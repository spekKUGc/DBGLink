namespace DbgLink.Server;

/// <summary>
/// Per-analysis-session snapshot state: the register diff baseline and the
/// diffOnly fingerprint.
///
/// This state used to be process-wide, which made two things wrong once the
/// reader/writer gate let several read-only snapshot calls run concurrently on
/// one session:
/// <list type="bullet">
/// <item>a diffOnly snapshot on session B was compared against session A's
/// register baseline, so registers of a different target were reported as
/// changed;</item>
/// <item>the compare-then-write on the baseline was not atomic, so two
/// interleaved calls could leave a mixed baseline behind (half the registers
/// from one call, half from the other) and report changed registers as
/// unchanged.</item>
/// </list>
///
/// Keying the state by analysis id removes the cross-session leak; the lock
/// makes every compare-and-update atomic within a session.
/// </summary>
internal sealed class SessionSnapshotState
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _registers = new(StringComparer.OrdinalIgnoreCase);
    private string? _fingerprint;
    private bool? _batchedCapability;
    private long _lastUsedTicks = Environment.TickCount64;

    /// <summary>
    /// Native GetAnalysisSnapshot capability, learned once per session. Null
    /// until the first status probe; afterwards a snapshot call can skip the
    /// extra GetServerStatus round trip. A failed batched attempt falls back
    /// for that call but keeps the positive bit so a transient failure is
    /// retried on the next snapshot.
    /// </summary>
    internal bool? BatchedCapability
    {
        get
        {
            lock (_gate)
            {
                _lastUsedTicks = Environment.TickCount64;
                return _batchedCapability;
            }
        }
        set
        {
            lock (_gate)
            {
                _lastUsedTicks = Environment.TickCount64;
                _batchedCapability = value;
            }
        }
    }

    /// <summary>
    /// Atomically compares the stored value of <paramref name="key"/> with
    /// <paramref name="value"/> and stores it. Returns true when the value is
    /// new or changed.
    /// </summary>
    internal bool UpdateRegister(string key, string value)
    {
        lock (_gate)
        {
            _lastUsedTicks = Environment.TickCount64;
            if (_registers.TryGetValue(key, out var previous) &&
                string.Equals(previous, value, StringComparison.OrdinalIgnoreCase))
                return false;
            _registers[key] = value;
            return true;
        }
    }

    /// <summary>
    /// Replaces the whole baseline (used by the non-diff snapshot path, which
    /// records every register it saw).
    /// </summary>
    internal void ReplaceRegisters(IReadOnlyDictionary<string, string> values)
    {
        lock (_gate)
        {
            _lastUsedTicks = Environment.TickCount64;
            _registers.Clear();
            foreach (var pair in values)
                _registers[pair.Key] = pair.Value;
        }
    }

    /// <summary>
    /// Atomically reports whether <paramref name="fingerprint"/> repeats the
    /// previous one and records the new one. Returns true when the snapshot is
    /// unchanged since the previous diffOnly poll.
    /// </summary>
    internal bool TryConsumeFingerprint(string fingerprint)
    {
        lock (_gate)
        {
            _lastUsedTicks = Environment.TickCount64;
            if (_fingerprint is not null && string.Equals(_fingerprint, fingerprint, StringComparison.Ordinal))
                return true;
            _fingerprint = fingerprint;
            return false;
        }
    }

    /// <summary>Monotonic stamp of the last access, used to evict the least
    /// recently used state when the per-session table is over its cap.</summary>
    internal long LastUsedTicks
    {
        get { lock (_gate) return _lastUsedTicks; }
    }
}
