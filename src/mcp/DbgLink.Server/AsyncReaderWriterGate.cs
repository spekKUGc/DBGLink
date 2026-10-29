namespace DbgLink.Server;

/// <summary>
/// Reader/writer gate with an async acquisition API. Read holders run
/// concurrently; a writer excludes every other holder, so read-only tool work
/// (decompilation, xrefs, strings, memory, register reads) never queues behind
/// another reader, while mutations (annotations, renames, debugger steps,
/// memory writes) keep exclusive access.
///
/// <para>Why this is not <see cref="System.Threading.ReaderWriterLockSlim"/>:
/// that type has managed thread affinity — the thread that enters must be the
/// thread that exits — but a tool call spends its whole critical section inside
/// awaited bridge round-trips, so the exit lands on whichever thread-pool
/// thread resumes the continuation and throws instead of serialising. The
/// counter/waiter scheme below gives the same one-writer/many-readers class of
/// exclusivity without pinning a thread.</para>
///
/// <para>Admission happens when a waiter is signalled, not when it wakes: the
/// signal performs the counter change, so a woken waiter returns straight away
/// and can never miss a wake-up by losing a race.</para>
///
/// <para>Writer preference: a queued writer holds new readers back, so a
/// continuous stream of reads cannot starve a mutation.</para>
/// </summary>
internal sealed class AsyncReaderWriterGate : IDisposable
{
    // Guards the counters and the waiter lists. Only ever held for bounded,
    // non-blocking bookkeeping plus waiter wake-ups (whose continuations run
    // asynchronously and never inline into the holder), so a synchronous Wait
    // is safe here; an async exit would resume on an unpredictable continuation.
    private readonly SemaphoreSlim _entry = new(1, 1);

    private readonly LinkedList<Waiter> _readWaiters = new();
    private readonly LinkedList<Waiter> _writeWaiters = new();
    private int _readers;
    private int _writersWaiting;
    private bool _writerActive;
    private int _disposed;

    /// <summary>Read holders currently inside the gate (diagnostics/tests).</summary>
    internal int CurrentReaders => Volatile.Read(ref _readers);

    /// <summary>Writers queued behind the current holder (diagnostics/tests).</summary>
    internal int WritersWaiting => Volatile.Read(ref _writersWaiting);

    /// <summary>True while a writer holds the gate (diagnostics/tests).</summary>
    internal bool WriterActive => Volatile.Read(ref _writerActive);

    public Task<GateLease> EnterReadAsync(CancellationToken cancellationToken)
        => EnterAsync(write: false, cancellationToken);

    public Task<GateLease> EnterWriteAsync(CancellationToken cancellationToken)
        => EnterAsync(write: true, cancellationToken);

    private async Task<GateLease> EnterAsync(bool write, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        // Queueing and the admission decision are one atomic step under _entry;
        // doing them separately would let a wake-up land on a waiter that is
        // not yet visible in the list.
        await _entry.WaitAsync(cancellationToken).ConfigureAwait(false);
        var waiter = new Waiter(this, write);
        var admitted = false;
        try
        {
            // Re-check under the entry lock: the gate may have been disposed
            // between the check above and the acquisition of _entry. Throw
            // directly: the finally below releases _entry, and handing back a
            // lease here would hand one out without admission.
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(AsyncReaderWriterGate));
            admitted = write
                ? !_writerActive && Volatile.Read(ref _readers) == 0
                : !_writerActive && Volatile.Read(ref _writersWaiting) == 0;
            if (admitted)
            {
                if (write)
                    _writerActive = true;
                else
                    _readers++;
            }
            else
            {
                // Registered in the list BEFORE the cancellation callback is
                // armed, so a cannot-race withdrawal always finds this node.
                waiter.Node = (write ? _writeWaiters : _readWaiters).AddLast(waiter);
                waiter.Queued = true;
                if (write)
                    _writersWaiting++;
            }
        }
        finally { _entry.Release(); }

        if (admitted)
            return new GateLease(this, write);

        // From here the waiters are only completed by Withdraw (queued and
        // cancelled), by Dispose (the gate was torn down) or by a
        // signal-generated Grant (admission counters already updated), so the
        // counters can never disagree.
        using var registration = cancellationToken.Register(
            static state => ((Waiter)state!).Cancel(), waiter);
        await waiter.Task.ConfigureAwait(false);
        return new GateLease(this, write);
    }

    private void Exit(bool write)
    {
        // Synchronous by design: see the _entry comment. The hold time is
        // bounded (counter updates plus TrySetResult wake-ups), so this cannot
        // block on the very state it protects.
        //
        // The entry semaphore is never disposed (see Dispose), so a holder
        // that leaves after the gate was torn down releases cleanly instead
        // of throwing ObjectDisposedException out of the caller's finally
        // block, where it would replace the real tool result.
        _entry.Wait();
        try
        {
            if (write)
                _writerActive = false;
            else
                _readers--;

            WakeLocked();
        }
        finally { _entry.Release(); }
    }

    /// <summary>Wake the next waiter(s) and admit them. Must be called with
    /// <see cref="_entry"/> held.</summary>
    private void WakeLocked()
    {
        // A writer goes first whenever nobody holds the gate.
        while (!_writerActive && Volatile.Read(ref _readers) == 0 && Volatile.Read(ref _writersWaiting) > 0)
        {
            var node = _writeWaiters.First;
            if (node is null)
                break;
            _writeWaiters.Remove(node);
            _writersWaiting--;
            if (!node.Value.TryClaim())
                continue; // Lost a cancellation race: already withdrawn, drop it and try the next waiter.
            // Admission (counter change) happens BEFORE the wake-up signal,
            // so the woken waiter always observes a consistent gate state.
            _writerActive = true;
            node.Value.Complete();
            return;
        }

        if (_writerActive || Volatile.Read(ref _writersWaiting) > 0 || _readWaiters.Count == 0)
            return;

        while (_readWaiters.First is { } first)
        {
            _readWaiters.Remove(first);
            if (!first.Value.TryClaim())
                continue;
            _readers++;
            first.Value.Complete();
        }
    }

    /// <summary>
    /// Dequeue a waiter that gave up while it was still queued. Runs on
    /// whatever thread the cancellation callback was invoked on; <see
    /// cref="_entry"/> is only ever held for bounded bookkeeping, so the
    /// synchronous Wait always completes.
    /// </summary>
    private void Withdraw(Waiter waiter)
    {
        _entry.Wait();
        try
        {
            if (!waiter.Queued)
                return; // Already signalled and dequeued; that grant stands.
            waiter.Queued = false;
            // A concurrent Dispose (FailQueuedWaitersLocked) or grant may have
            // already removed the node from its queue: LinkedList.Remove throws
            // when the node belongs nowhere, so only remove a listed node.
            // The counters stay consistent: Dispose zeroes them with the clear,
            // and a granted waiter already updated them before its removal.
            if (waiter.Node!.List is null)
                return;
            (waiter.Write ? _writeWaiters : _readWaiters).Remove(waiter.Node);
            if (waiter.Write)
                _writersWaiting--;
            WakeLocked();
        }
        finally { _entry.Release(); }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(AsyncReaderWriterGate));
    }

    /// <summary>
    /// RAII handle returned by the gate. Disposal releases exactly the mode
    /// that was acquired, from any thread, because the gate is not
    /// thread-affine.
    /// </summary>
    internal readonly struct GateLease : IDisposable
    {
        private readonly AsyncReaderWriterGate _gate;
        private readonly bool _write;

        internal GateLease(AsyncReaderWriterGate gate, bool write)
        {
            _gate = gate;
            _write = write;
        }

        public void Dispose()
        {
            if (_gate is not null)
                _gate.Exit(_write);
        }
    }

    private const int Waiting = 0;
    private const int Signalled = 1;
    private const int Withdrawn = 2;
    private const int Failed = 3;

    /// <summary>One queued acquirer. Exactly one of "signalled" and "withdrawn
    /// while queued" can win, both decided under <see cref="_entry"/>, so the
    /// counters and the queues never disagree.</summary>
    private sealed class Waiter
    {
        private readonly TaskCompletionSource _tcs =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly AsyncReaderWriterGate _gate;
        private int _state = Waiting;

        internal Waiter(AsyncReaderWriterGate gate, bool write)
        {
            _gate = gate;
            Write = write;
        }

        internal bool Write { get; }

        internal Task Task => _tcs.Task;

        internal LinkedListNode<Waiter>? Node { get; set; }

        /// <summary>True while this waiter is still in its queue. Flipped under
        /// <see cref="_entry"/> by both the signal and the withdrawal.</summary>
        internal bool Queued { get; set; }

        /// <summary>Claim the waiter for admission. Called with the entry lock
        /// held, after removal from its queue. Returns false when a concurrent
        /// cancel won first: the caller must drop the waiter without counting
        /// an admission, otherwise the gate wedges on a lease nobody holds.
        /// On true the caller must update the admission counters and then call
        /// <see cref="Complete"/> so the woken waiter observes them.
        /// </summary>
        internal bool TryClaim()
        {
            return Interlocked.CompareExchange(ref _state, Signalled, Waiting) == Waiting;
        }

        /// <summary>Wake the claimed waiter. Must follow a successful <see
        /// cref="TryClaim"/> after the admission counters were updated.
        /// </summary>
        internal void Complete()
        {
            Queued = false;
            _tcs.TrySetResult();
        }

        /// <summary>Give up while queued. Called from a cancellation callback,
        /// so it must be safe on any thread.</summary>
        internal void Cancel()
        {
            if (Interlocked.CompareExchange(ref _state, Withdrawn, Waiting) != Waiting)
                return; // Already signalled: that grant stands.
            _gate.Withdraw(this);
            _tcs.TrySetCanceled();
        }

        /// <summary>Fail the waiter because the gate was torn down while it was
        /// queued. Without this the waiter would wait forever: the gate no
        /// longer has anyone who could wake it.</summary>
        internal void Fail(Exception error)
        {
            if (Interlocked.CompareExchange(ref _state, Failed, Waiting) == Waiting)
            {
                Queued = false;
                _tcs.TrySetException(error);
            }
        }
    }

    /// <summary>
    /// Tears the gate down. Queued waiters are failed instead of being left
    /// to wait forever, and the entry semaphore is deliberately NOT disposed:
    /// a holder that leaves after the teardown still calls Exit, and disposing
    /// the semaphore would make that release throw ObjectDisposedException
    /// out of the caller's finally block.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        var error = new ObjectDisposedException(nameof(AsyncReaderWriterGate));
        _entry.Wait();
        try
        {
            FailQueuedWaitersLocked(error);
        }
        finally { _entry.Release(); }
        GC.SuppressFinalize(this);
    }

    /// <summary>Fails every queued waiter and clears the queues. Must be
    /// called with <see cref="_entry"/> held.</summary>
    private void FailQueuedWaitersLocked(Exception error)
    {
        foreach (var waiter in _readWaiters)
            waiter.Fail(error);
        foreach (var waiter in _writeWaiters)
            waiter.Fail(error);
        _readWaiters.Clear();
        _writeWaiters.Clear();
        _writersWaiting = 0;
    }

    /// <summary>True when the gate has no holder and no queued waiter, so it
    /// can be removed and disposed without stranding a caller. Used by the
    /// session registry to prune gates of closed sessions.</summary>
    internal bool IsIdle
    {
        get
        {
            _entry.Wait();
            try
            {
                return !_writerActive &&
                       Volatile.Read(ref _readers) == 0 &&
                       _readWaiters.Count == 0 &&
                       _writeWaiters.Count == 0;
            }
            finally { _entry.Release(); }
        }
    }
}
