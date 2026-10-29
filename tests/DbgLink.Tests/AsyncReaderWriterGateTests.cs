using System.Diagnostics;
using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// AsyncReaderWriterGate: read holders overlap, writers exclude everyone, a
/// waiting writer holds new readers back, and a cancelled waiter leaves the
/// gate usable. These are the invariants the server session gate depends on,
/// so every wait here carries a hard timeout: a regression must surface as a
/// failure, not as a hung test run.
/// </summary>
public sealed class AsyncReaderWriterGateTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Two_readers_are_inside_at_the_same_time()
    {
        using var gate = new AsyncReaderWriterGate();
        var first = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);
        var second = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);

        Assert.Equal(2, gate.CurrentReaders);
        Assert.False(gate.WriterActive);

        first.Dispose();
        Assert.Equal(1, gate.CurrentReaders);
        second.Dispose();
        Assert.Equal(0, gate.CurrentReaders);
    }

    [Fact]
    public async Task A_writer_excludes_readers_and_other_writers()
    {
        using var gate = new AsyncReaderWriterGate();
        var writeLease = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);
        Assert.True(gate.WriterActive);

        // Both requests queue behind the active writer and must not be admitted.
        var readerTask = gate.EnterReadAsync(CancellationToken.None);
        var writerTask = gate.EnterWriteAsync(CancellationToken.None);
        await Task.Delay(100);
        Assert.False(readerTask.IsCompleted);
        Assert.False(writerTask.IsCompleted);

        writeLease.Dispose();

        // Writer preference: the queued writer goes next, and while it holds
        // the gate the queued reader still waits.
        var writer = await writerTask.WaitAsync(Budget);
        Assert.True(gate.WriterActive);
        Assert.False(readerTask.IsCompleted);

        writer.Dispose();
        var reader = await readerTask.WaitAsync(Budget);
        using (reader)
        {
            Assert.False(gate.WriterActive);
            Assert.Equal(1, gate.CurrentReaders);
        }
    }

    [Fact]
    public async Task A_waiting_writer_holds_new_readers_back()
    {
        using var gate = new AsyncReaderWriterGate();
        var reader = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);

        var writerTask = gate.EnterWriteAsync(CancellationToken.None);
        await WaitUntilAsync(() => gate.WritersWaiting == 1);

        // A reader that arrives after the writer queued must be held back.
        var lateReader = gate.EnterReadAsync(CancellationToken.None);
        await Task.Delay(150);
        Assert.False(lateReader.IsCompleted, "a reader was admitted while a writer was queued");

        reader.Dispose();
        var writer = await writerTask.WaitAsync(Budget);
        using (writer)
        {
            Assert.True(gate.WriterActive);
            Assert.False(lateReader.IsCompleted);
            Assert.Equal(0, gate.CurrentReaders);
        }

        var late = await lateReader.WaitAsync(Budget);
        using (late)
        {
            Assert.Equal(1, gate.CurrentReaders);
            Assert.False(gate.WriterActive);
        }
    }

    [Fact]
    public async Task A_cancelled_reader_waiter_withdraws_without_the_writer_releasing()
    {
        using var gate = new AsyncReaderWriterGate();
        var writeLease = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);

        using var cancelling = new CancellationTokenSource();
        var readerTask = gate.EnterReadAsync(cancelling.Token);
        await Task.Delay(80);
        Assert.False(readerTask.IsCompleted);

        cancelling.Cancel();

        // The waiter withdraws itself; the writer never had to release.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await readerTask.WaitAsync(Budget));
        Assert.Equal(0, gate.CurrentReaders);
        Assert.Equal(0, gate.WritersWaiting);

        writeLease.Dispose();
        var after = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);
        using (after)
        {
            Assert.Equal(1, gate.CurrentReaders);
        }
    }

    [Fact]
    public async Task Cancelling_a_queued_writer_releases_the_reader_barrier()
    {
        using var gate = new AsyncReaderWriterGate();
        var reader = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);

        using var cancelling = new CancellationTokenSource();
        var writerTask = gate.EnterWriteAsync(cancelling.Token);
        await WaitUntilAsync(() => gate.WritersWaiting == 1);

        cancelling.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await writerTask.WaitAsync(Budget));

        // The barrier is gone, so a reader can be admitted without anyone
        // releasing a write lease.
        Assert.Equal(0, gate.WritersWaiting);
        var second = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);
        using (second)
        {
            Assert.Equal(2, gate.CurrentReaders);
        }
        reader.Dispose();
        Assert.Equal(0, gate.CurrentReaders);
    }

    [Fact]
    public async Task Readers_queued_behind_a_writer_are_all_admitted_when_it_exits()
    {
        using var gate = new AsyncReaderWriterGate();
        var first = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);

        var writerTask = gate.EnterWriteAsync(CancellationToken.None);
        await WaitUntilAsync(() => gate.WritersWaiting == 1);

        var queuedA = gate.EnterReadAsync(CancellationToken.None);
        var queuedB = gate.EnterReadAsync(CancellationToken.None);
        await Task.Delay(80);
        Assert.False(queuedA.IsCompleted);
        Assert.False(queuedB.IsCompleted);

        first.Dispose();
        var writer = await writerTask.WaitAsync(Budget);
        Assert.True(gate.WriterActive);
        Assert.Equal(0, gate.CurrentReaders);

        writer.Dispose();
        var a = await queuedA.WaitAsync(Budget);
        var b = await queuedB.WaitAsync(Budget);
        using (a)
        using (b)
        {
            Assert.Equal(2, gate.CurrentReaders);
            Assert.False(gate.WriterActive);
        }
    }

    [Fact]
    public async Task Writers_are_exclusive()
    {
        using var gate = new AsyncReaderWriterGate();
        var concurrentWriters = 0;
        var maxConcurrentWriters = 0;

        var writers = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(async () =>
            {
                for (var iteration = 0; iteration < 20; iteration++)
                {
                    using var lease = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);
                    Assert.True(gate.WriterActive);
                    Assert.Equal(0, gate.CurrentReaders);

                    var inside = Interlocked.Increment(ref concurrentWriters);
                    Interlocked.Exchange(ref maxConcurrentWriters,
                        Math.Max(Volatile.Read(ref maxConcurrentWriters), inside));
                    await Task.Delay(1);
                    Interlocked.Decrement(ref concurrentWriters);
                }
            }))
            .ToArray();

        await Task.WhenAll(writers).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal(0, concurrentWriters);
        Assert.Equal(1, maxConcurrentWriters);
        Assert.False(gate.WriterActive);
        Assert.Equal(0, gate.CurrentReaders);
    }

    [Fact]
    public async Task A_mixed_stampede_never_deadlocks_and_readers_overlap()
    {
        using var gate = new AsyncReaderWriterGate();
        var stopwatch = Stopwatch.StartNew();
        var writerEntries = 0;
        var readersObservedInParallel = 0;
        var maxReadersInParallel = 0;
        var concurrentHolders = 0;

        var tasks = new List<Task>();
        for (var worker = 0; worker < 32; worker++)
        {
            var isWriter = worker % 8 == 0;
            tasks.Add(Task.Run(async () =>
            {
                for (var iteration = 0; iteration < 50; iteration++)
                {
                    // Writers and readers alike come and go so a queued writer
                    // must keep blocking new readers while it waits.
                    if (isWriter)
                    {
                        using var lease = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);
                        Interlocked.Increment(ref writerEntries);
                        var inside = Interlocked.Increment(ref concurrentHolders);
                        Interlocked.Exchange(ref maxReadersInParallel,
                            Math.Max(Volatile.Read(ref maxReadersInParallel), inside));
                        await Task.Yield();
                        Interlocked.Decrement(ref concurrentHolders);
                    }
                    else
                    {
                        using var lease = await gate.EnterReadAsync(CancellationToken.None).WaitAsync(Budget);
                        Interlocked.Increment(ref readersObservedInParallel);
                        var inside = Interlocked.Increment(ref concurrentHolders);
                        Interlocked.Exchange(ref maxReadersInParallel,
                            Math.Max(Volatile.Read(ref maxReadersInParallel), inside));
                        // The hold counter must stay raised across the yield:
                        // releasing it before the yield left a window of a few
                        // instructions, so on a loaded runner two readers were
                        // never observed inside the gate at the same time and
                        // the assertion below failed at random.
                        await Task.Yield();
                        Interlocked.Decrement(ref concurrentHolders);
                    }
                }
            }));
        }

        var everything = Task.WhenAll(tasks);
        var finished = await Task.WhenAny(everything, Task.Delay(TimeSpan.FromSeconds(90)));
        Assert.Same(everything, finished);
        await everything.WaitAsync(Budget);

        Assert.True(writerEntries > 0);
        Assert.True(readersObservedInParallel > 0);
        Assert.Equal(0, gate.CurrentReaders);
        Assert.False(gate.WriterActive);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(85), $"the stampede took {stopwatch.Elapsed}");
        // Writers hold alone, so the observed parallelism comes from readers.
        Assert.True(maxReadersInParallel > 1, "readers were never observed running in parallel");
    }

    [Fact]
    public async Task Dispose_is_idempotent_and_blocks_later_entry()
    {
        var gate = new AsyncReaderWriterGate();
        gate.Dispose();
        gate.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await gate.EnterReadAsync(CancellationToken.None));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await gate.EnterWriteAsync(CancellationToken.None));
    }

    /// <summary>
    /// Disposing a gate while a writer waits must not strand the waiter: the
    /// old implementation disposed the entry semaphore, so the waiter's task
    /// was never completed and the call hung forever.
    /// </summary>
    [Fact]
    public async Task Dispose_fails_a_queued_waiter_instead_of_stranding_it()
    {
        var gate = new AsyncReaderWriterGate();
        var held = await gate.EnterWriteAsync(CancellationToken.None);

        var waiting = gate.EnterReadAsync(CancellationToken.None);
        await WaitUntilAsync(() => gate.WritersWaiting >= 0 && gate.CurrentReaders == 0);

        gate.Dispose();

        // The waiter must fail fast, not hang.
        var failure = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await waiting.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.IsType<ObjectDisposedException>(failure);

        // The holder can still leave cleanly: releasing after the teardown
        // must not throw out of the caller's finally block.
        held.Dispose();
    }

    /// <summary>
    /// A reader that leaves after the gate was torn down must not throw: the
    /// release runs from the caller's finally block, where an exception would
    /// replace the real tool result.
    /// </summary>
    [Fact]
    public async Task Release_after_dispose_does_not_throw()
    {
        var gate = new AsyncReaderWriterGate();
        var lease = await gate.EnterReadAsync(CancellationToken.None);
        gate.Dispose();

        var exception = Record.Exception(() => lease.Dispose());
        Assert.Null(exception);
        await Task.CompletedTask;
    }

    /// <summary>
    /// A gate with no holder and no waiter is idle and can be pruned; a gate
    /// with a live holder is not.
    /// </summary>
    [Fact]
    public async Task IsIdle_reflects_holders_and_waiters()
    {
        var gate = new AsyncReaderWriterGate();
        Assert.True(gate.IsIdle);

        var lease = await gate.EnterReadAsync(CancellationToken.None);
        Assert.False(gate.IsIdle);
        lease.Dispose();
        Assert.True(gate.IsIdle);

        var write = await gate.EnterWriteAsync(CancellationToken.None);
        var queuedTask = gate.EnterReadAsync(CancellationToken.None);
        Assert.False(gate.IsIdle);
        write.Dispose();
        var queued = await queuedTask;
        queued.Dispose();
        Assert.True(gate.IsIdle);

        gate.Dispose();
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition() && deadline.Elapsed < TimeSpan.FromSeconds(5))
            await Task.Delay(10);
        Assert.True(condition(), "condition did not become true within the timeout");
    }

    /// <summary>
    /// A waiter cancelled while queued must not wedge the gate: whichever of
    /// the grant and the withdrawal wins, the gate stays usable afterwards.
    /// </summary>
    [Fact]
    public async Task Cancelled_waiter_leaves_the_gate_usable()
    {
        using var gate = new AsyncReaderWriterGate();
        var held = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);

        using var cancelling = new CancellationTokenSource();
        var waiterTask = gate.EnterWriteAsync(cancelling.Token);
        await WaitUntilAsync(() => gate.WritersWaiting == 1);
        cancelling.Cancel();
        held.Dispose();

        // Either outcome is consistent (cancelled before the grant, or
        // granted before the cancel was observed), but the waiter must settle
        // and the gate must admit the next writer (no wedge on a lost race).
        await waiterTask.WaitAsync(Budget).ContinueWith(_ => { }, TaskScheduler.Default);
        var next = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);
        next.Dispose();
    }

    /// <summary>
    /// Disposing a gate concurrently with waiter cancellation must not throw:
    /// whichever wins (fail-and-clear or withdraw-and-remove), the waiter
    /// settles exactly once. Stress interleaves both orders across iterations;
    /// before the fix, the losing interleave crashed with InvalidOperationException
    /// out of the cancellation callback.
    /// </summary>
    [Fact]
    public async Task Dispose_racing_cancellation_never_throws()
    {
        const int iterations = 500;
        for (var iteration = 0; iteration < iterations; iteration++)
        {
            var gate = new AsyncReaderWriterGate();
            var held = await gate.EnterWriteAsync(CancellationToken.None).WaitAsync(Budget);
            using var cancelling = new CancellationTokenSource();
            var waiterTask = gate.EnterWriteAsync(cancelling.Token);
            await WaitUntilAsync(() => gate.WritersWaiting == 1);

            // Dispose and cancel race on purpose: the fail-and-clear path and
            // the withdraw path must agree on who owns the queued node.
            var disposer = Task.Run(() => gate.Dispose());
            var cancelError = Record.Exception(() => cancelling.Cancel());
            var disposeError = await Record.ExceptionAsync(() => disposer);
            Assert.Null(cancelError);
            Assert.Null(disposeError);

            // The waiter settles (cancelled or failed by the teardown), never hangs.
            var waiterError = await Record.ExceptionAsync(() => waiterTask.WaitAsync(Budget));
            Assert.True(waiterError is null or OperationCanceledException or ObjectDisposedException,
                $"Unexpected waiter outcome: {waiterError?.GetType().Name}");
            held.Dispose();
            gate.Dispose();
        }
        await Task.CompletedTask;
    }
}
