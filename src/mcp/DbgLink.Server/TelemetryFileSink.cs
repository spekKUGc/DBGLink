using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server
{

/// <summary>
/// Local append-only telemetry cache for LLM analysis. No commands needed:
/// every tool completion appends one compact line to the per-PID
/// events-&lt;pid&gt;.log, and a small digest.md is rewritten periodically.
/// digest.md is the LLM entry point (always tiny); events-&lt;pid&gt;.log is
/// for grep/drill-down.
/// </summary>
internal sealed class TelemetryFileSink : IDisposable
{
    internal const long MaxEventsBytes = 1024 * 1024;
    private const int MaxGenerations = 2;
    private const int MaxQueueLines = 2000;
    private const int MaxLineChars = 512;
    private const int RecentFailuresCap = 20;
    // T2 §8 retention caps (frozen numbers, ctor-override only for maxEventsBytes in tests).
    private const int DailyRetentionDays = 7;
    private const long TotalDirectoryBytesCap = 8L * 1024 * 1024;
    private const int GzMaxAgeDays = 30;
    private const int TmpMaxAgeMinutes = 60;
    private const int OrphanAgeHours = 24;
    private const int CleanupLockStaleMinutes = 10;
    private const int MaxBatchLines = 5000;
    private const int MaxCompressPerTick = 4;

    private readonly ServerMetrics _metrics;
    private readonly string _directory;
    private readonly string _eventsPath;
    private readonly string _digestPath;
    private readonly string _cleanupLockPath;
    private readonly int _pid;
    private readonly long _maxEventsBytes;
    private readonly ConcurrentQueue<string> _queue = new();
    private readonly object _recentLock = new();
    private readonly List<string> _recentFailures = new();
    private readonly Timer _flushTimer;
    private readonly Timer _digestTimer;
    private readonly Timer _compressTimer;
    private readonly object _flushLock = new();
    // UTF-8 without BOM for all telemetry file writes: Encoding.UTF8 emits
    // a preamble (EF BB BF), so the first line of events-<pid>.log was not
    // parseable by naive ^\d{4}- readers. Reads keep Encoding.UTF8 (BOM
    // detection still strips preambles from legacy files).
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);
    private long _toolLogs;
    private long _dropped;
    private long _flushErrors;
    private long _rotations;
    private long _compressions;
    private long _flushes;
    private int _disabled;
    private TelemetryDisableReason _disableReason;
    private int _disposed;
    // Swallowed failures. The sink must never throw into the tool path, but a
    // silent failure makes a broken sink invisible: every caught error is
    // counted here and surfaced through /metrics. The counters are static
    // because one of the failure sites (TryCreate) runs before the sink
    // instance exists, and a process runs a single sink.
    private static long _errors;
    private static string? _lastError;

    private TelemetryFileSink(ServerMetrics metrics, string directory, long maxEventsBytes)
    {
        _metrics = metrics;
        _directory = directory;
        _pid = Environment.ProcessId;
        _eventsPath = Path.Combine(directory, $"events-{_pid}.log");
        _digestPath = Path.Combine(directory, "digest.md");
        _cleanupLockPath = Path.Combine(directory, "cleanup.lock");
        _maxEventsBytes = maxEventsBytes;
        _flushTimer = new Timer(static state => ((TelemetryFileSink)state!).Flush(), this, 2000, 2000);
        _digestTimer = new Timer(static state => ((TelemetryFileSink)state!).WriteDigest(), this, 60_000, 60_000);
        // T2 §6: background .gz, first run 5 min after start, period 15 min.
        // Never in flush/digest timer, BelowNormal, TryEnter (never waits for flush).
        _compressTimer = new Timer(static state => ((TelemetryFileSink)state!).CompressAndRetainTick(), this, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15));
    }

    internal static TelemetryFileSink? TryCreate(ServerMetrics metrics, string? directory = null, Func<string, string?>? environment = null, long maxEventsBytes = MaxEventsBytes)
    {
        try
        {
            environment ??= Environment.GetEnvironmentVariable;
            if (IsDisabled(environment("DBGLINK_TELEMETRY")))
                return null;
            if (string.IsNullOrWhiteSpace(directory))
                directory = environment("DBGLINK_TELEMETRY_DIR");
            if (string.IsNullOrWhiteSpace(directory))
            {
                var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrWhiteSpace(localApplicationData))
                    return null;
                directory = Path.Combine(localApplicationData, "DBGLink", "telemetry");
            }
            directory = Path.GetFullPath(directory);
            // Check -> create -> re-check (matches ServerConfig.PersistConfig /
            // CheckpointStore.Save): a TOCTOU swap between the first check and
            // the create must not leave an unsafe directory in use.
            if (!LocalPathPolicy.IsSafeLocalPath(directory))
                return null;
            System.IO.Directory.CreateDirectory(directory);
            FileProtection.ProtectDirectory(directory, reason => ReportProtection("TryCreate", reason));
            if (!LocalPathPolicy.IsSafeLocalPath(directory))
                return null;
            var sink = new TelemetryFileSink(metrics, directory, maxEventsBytes);
            // T2 §5.2: orphan cleanup once at startup, under cleanup.lock.
            // Best-effort, never throws, never blocks startup on failure.
            try { sink.TryOrphanCleanup(); } catch (Exception caught) { NoteError("TryCreate", caught); }
            sink.WriteDigest();
            return sink;
        }
        catch
        {
            return null;
        }
    }

    internal static bool IsDisabled(string? raw)
        => raw?.Trim().ToLowerInvariant() is "0" or "false" or "off" or "no" or "disabled" or "disable";

    internal string EventsPath => _eventsPath;
    internal string DigestPath => _digestPath;
    internal string Directory => _directory;
    internal long DroppedLines => Interlocked.Read(ref _dropped);
    internal long FlushErrors => Interlocked.Read(ref _flushErrors);
    internal long Rotations => Interlocked.Read(ref _rotations);
    internal long Compressions => Interlocked.Read(ref _compressions);
    internal bool Enabled => Volatile.Read(ref _disabled) == 0;
    internal TelemetrySinkHealth Health => new(
        Volatile.Read(ref _disabled) == 0,
        _disableReason,
        _queue.Count,
        Interlocked.Read(ref _dropped),
        Interlocked.Read(ref _flushes),
        Interlocked.Read(ref _rotations),
        Interlocked.Read(ref _compressions),
        Interlocked.Read(ref _flushErrors),
        Interlocked.Read(ref _errors),
        _lastError);

    /// <summary>
    /// Records a swallowed failure. Never throws: the sink must not turn a
    /// housekeeping error into a tool failure. The counter and the last
    /// operation are surfaced through <see cref="Health"/> so a degraded sink
    /// is visible in /metrics instead of being silently ignored.
    /// </summary>
    internal static void NoteError(string operation, Exception? error = null)
    {
        try
        {
            Interlocked.Increment(ref _errors);
            Volatile.Write(ref _lastError, error is null
                ? operation
                : operation + ": " + error.GetType().Name);
        }
        catch { }
    }

    private static int _protectionReported;

    /// <summary>
    /// One-shot reporter for file-protection failures. FlushCore runs on a
    /// timer, so a persistent failure must not spam the error counter; the
    /// first occurrence lands in Health (visible in /metrics), the rest stay
    /// silent. Never throws. Not durable (in-memory Health only) — a durable
    /// protection-failure record would be a separate change.
    /// </summary>
    private static void ReportProtection(string operation, string reason)
    {
        if (Interlocked.Exchange(ref _protectionReported, 1) == 0)
            NoteError(operation + " protect: " + reason);
    }

    /// <param name="tokens">Real cl100k_base BPE count for the call, computed
    /// once by the caller (<see cref="ServerMetrics.RecordToolResult"/>) and
    /// passed in. The sink never re-counts: a second BPE pass would double
    /// the token cost of every call on the hot path.</param>
    internal void LogTool(string tool, string outcome, long elapsedMs, long requestBytes, long responseBytes, long tokens, string? errorCode = null, string? sessionId = null, string? detail = null)
    {
        try
        {
            // T2 §7: after Disable, Append is cheap no-op (only Dropped++).
            if (Volatile.Read(ref _disabled) != 0)
            {
                Interlocked.Increment(ref _dropped);
                return;
            }
            var safeTool = ServerMetrics.SanitizeToolName(tool);
            var safeOutcome = ServerMetrics.SanitizeErrorCode(outcome);
            var code = ServerMetrics.ResolveErrorCode(outcome, errorCode);
            var inBytes = Math.Max(0, requestBytes);
            var outBytes = Math.Max(0, responseBytes);
            var line = new StringBuilder(192)
                .Append(DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"))
                .Append(' ').Append(safeTool)
                .Append(' ').Append(safeOutcome)
                .Append(' ').Append(Math.Max(0, elapsedMs)).Append("ms")
                .Append(" in").Append(inBytes)
                .Append(" out").Append(outBytes)
                .Append(" tok").Append(tokens);
            if (code is not null && !string.Equals(safeOutcome, "ok", StringComparison.Ordinal))
                line.Append(" err=").Append(code);
            var session = ServerMetrics.SanitizeSessionId(sessionId);
            if (session != "-")
                line.Append(" sess=").Append(session);
            var mix = ServerMetrics.SanitizeBatchDetail(detail);
            if (mix.Length > 0)
                line.Append(" sub=").Append(mix);
            // Materialize once: the same text feeds the queue and the
            // recent-failure ring (previously built twice per failure).
            var text = line.ToString();
            Enqueue(text.Length > MaxLineChars ? text[..MaxLineChars] : text);
            if (!string.Equals(safeOutcome, "ok", StringComparison.Ordinal))
            {
                lock (_recentLock)
                {
                    _recentFailures.Add(text);
                    if (_recentFailures.Count > RecentFailuresCap)
                        _recentFailures.RemoveRange(0, _recentFailures.Count - RecentFailuresCap);
                }
            }
            if (Interlocked.Increment(ref _toolLogs) % 50 == 0)
                WriteDigest();
        }
        catch (Exception caught) { NoteError("LogTool", caught); }
    }

    internal void LogEvent(string message)
    {
        try
        {
            if (Volatile.Read(ref _disabled) != 0)
            {
                Interlocked.Increment(ref _dropped);
                return;
            }
            var safe = new string(message.Where(c => !char.IsControl(c)).Take(MaxLineChars - 24).ToArray());
            Enqueue(DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + " " + safe);
        }
        catch (Exception caught) { NoteError("LogEvent", caught); }
    }

    // T2 §2 adapter: Store AppendLine preserves LogTool/LogEvent calls without Recorder changes.
    // Hot path: never throws, never does I/O, never blocks (only Enqueue + cap-check + counters).
    internal void AppendLine(string line, DateTimeOffset timestampUtc)
    {
        try
        {
            if (Volatile.Read(ref _disabled) != 0)
            {
                Interlocked.Increment(ref _dropped);
                return;
            }
            if (line is null)
            {
                Interlocked.Increment(ref _dropped);
                return;
            }
            // Store-level 512 trim (duplicates T1, cheap). Timestamp already from Recorder.
            Enqueue(line.Length > MaxLineChars ? line[..MaxLineChars] : line);
        }
        catch (Exception caught) { NoteError("AppendLine", caught); }
    }

    private void Enqueue(string line)
    {
        if (Volatile.Read(ref _disabled) != 0)
        {
            Interlocked.Increment(ref _dropped);
            return;
        }
        if (_queue.Count >= MaxQueueLines)
        {
            Interlocked.Increment(ref _dropped);
            return;
        }
        _queue.Enqueue(line);
    }

    internal void Flush()
    {
        lock (_flushLock)
        {
            FlushCore();
        }
    }

    private void FlushCore()
    {
        try
        {
            if (Volatile.Read(ref _disabled) != 0)
                return;
            if (_queue.IsEmpty)
                return;
            RotateIfNeeded();
            var batch = new List<string>(512);
            while (batch.Count < MaxBatchLines && _queue.TryDequeue(out var line))
                batch.Add(line);
            if (batch.Count == 0)
                return;
            try
            {
                var builder = new StringBuilder(batch.Count * 128);
                foreach (var entry in batch)
                    builder.AppendLine(entry);
                File.AppendAllText(_eventsPath, builder.ToString(), Utf8NoBom);
                FileProtection.ProtectFile(_eventsPath, reason => ReportProtection("FlushCore", reason));
                Interlocked.Increment(ref _flushes);
            }
            catch (UnauthorizedAccessException)
            {
                Interlocked.Increment(ref _flushErrors);
                ReturnBatch(batch);
                Disable(TelemetryDisableReason.NoPermission);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                // T2 §7: one retry via CreateDirectory, then Disable(PathNotFound).
                try
                {
                    System.IO.Directory.CreateDirectory(_directory);
                    FileProtection.ProtectDirectory(_directory, reason => ReportProtection("FlushCore", reason));
                    var builder = new StringBuilder(batch.Count * 128);
                    foreach (var entry in batch)
                        builder.AppendLine(entry);
                    File.AppendAllText(_eventsPath, builder.ToString(), Utf8NoBom);
                    FileProtection.ProtectFile(_eventsPath, reason => ReportProtection("FlushCore", reason));
                    Interlocked.Increment(ref _flushes);
                }
                catch
                {
                    Interlocked.Increment(ref _flushErrors);
                    ReturnBatch(batch);
                    Disable(TelemetryDisableReason.PathNotFound);
                }
                return;
            }
            catch (IOException ex) when (IsDiskFull(ex))
            {
                Interlocked.Increment(ref _flushErrors);
                ReturnBatch(batch);
                Disable(TelemetryDisableReason.DiskFull);
                return;
            }
            catch (IOException)
            {
                // Transient (sharing, path too long, per-PID transition): keep existing
                // best-effort restore-order logic, FlushErrors++, retry next tick. No Disable.
                Interlocked.Increment(ref _flushErrors);
                ReturnBatch(batch);
                return;
            }
            catch
            {
                Interlocked.Increment(ref _flushErrors);
                ReturnBatch(batch);
                return;
            }
            // Queue overflow guard: after a successful write, shed only the
            // excess beyond one flush batch so lines enqueued concurrently
            // with the write are kept for the next flush. A failed flush
            // above returned its lines to the queue, so write errors still
            // lose nothing.
            while (_queue.Count > MaxQueueLines && _queue.TryDequeue(out _))
                Interlocked.Increment(ref _dropped);
        }
        catch (Exception caught) { NoteError("FlushCore", caught); }
    }

    private void ReturnBatch(List<string> batch)
    {
        try
        {
            // Best-effort restore order (as before): dequeued batch goes back first.
            var remainder = new List<string>();
            while (_queue.TryDequeue(out var rest))
                remainder.Add(rest);
            foreach (var entry in batch)
                _queue.Enqueue(entry);
            foreach (var entry in remainder)
                _queue.Enqueue(entry);
        }
        catch (Exception caught) { NoteError("ReturnBatch", caught); }
    }

    private static bool IsDiskFull(IOException ex)
    {
        try
        {
            const int ERROR_DISK_FULL = unchecked((int)0x80070070);
            const int ERROR_HANDLE_DISK_FULL = unchecked((int)0x80070027);
            if (ex.HResult == ERROR_DISK_FULL || ex.HResult == ERROR_HANDLE_DISK_FULL)
                return true;
            var msg = ex.Message ?? string.Empty;
            if (msg.Contains("not enough space", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("disk full", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }
        catch { return false; }
    }

    private void Disable(TelemetryDisableReason reason)
    {
        try
        {
            _disableReason = reason;
            if (Interlocked.Exchange(ref _disabled, 1) != 0)
                return;
            try { _flushTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Disable", caught); }
            try { _digestTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Disable", caught); }
            try { _compressTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Disable", caught); }
        }
        catch (Exception caught) { NoteError("Disable", caught); }
    }

    private void RotateIfNeeded()
    {
        try
        {
            if (Volatile.Read(ref _disabled) != 0)
                return;
            var nowUtc = DateTimeOffset.UtcNow;
            FileInfo active;
            try { active = new FileInfo(_eventsPath); }
            catch { return; }
            bool exists;
            try { exists = active.Exists; } catch { return; }
            if (!exists)
                return;
            DateTime activeDate;
            long activeLen;
            try
            {
                active.Refresh();
                activeDate = active.LastWriteTimeUtc.Date;
                activeLen = active.Length;
            }
            catch { return; }
            var nowDate = nowUtc.UtcDateTime.Date;
            try
            {
                if (activeDate != nowDate)
                {
                    // T2 §4.3 daily: target owns past date (active.LastWriteTimeUtc, not now).
                    RotateDaily(activeDate);
                    return;
                }
            }
            catch (Exception caught) { NoteError("RotateIfNeeded", caught); }
            try
            {
                if (activeLen < _maxEventsBytes)
                    return;
                RotateSize();
            }
            catch (Exception caught) { NoteError("RotateIfNeeded", caught); }
        }
        catch (Exception caught) { NoteError("RotateIfNeeded", caught); }
    }

    private void RotateDaily(DateTime activeDate)
    {
        try
        {
            var datePart = activeDate.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
            var baseName = $"events-{_pid}-{datePart}.log";
            var target = Path.Combine(_directory, baseName);
            try
            {
                if (!File.Exists(target))
                {
                    MoveViaTmp(_eventsPath, target);
                    Interlocked.Increment(ref _rotations);
                    return;
                }
            }
            catch (Exception caught) { NoteError("RotateDaily", caught); }
            // Collision (restart same day after rotation): -02, -03 … up to 99.
            for (var seq = 2; seq <= 99; seq++)
            {
                var seqName = $"events-{_pid}-{datePart}-{seq:D2}.log";
                var seqTarget = Path.Combine(_directory, seqName);
                try
                {
                    if (File.Exists(seqTarget))
                        continue;
                    MoveViaTmp(_eventsPath, seqTarget);
                    Interlocked.Increment(ref _rotations);
                    return;
                }
                catch (Exception caught) { NoteError("RotateDaily", caught); }
            }
            // Fallback when all seq taken: size-shift as last resort.
            try { RotateSize(); } catch (Exception caught) { NoteError("RotateDaily", caught); }
        }
        catch
        {
            Interlocked.Increment(ref _flushErrors);
        }
    }

    private void RotateSize()
    {
        try
        {
            FileInfo active;
            try
            {
                active = new FileInfo(_eventsPath);
                if (!active.Exists || active.Length < _maxEventsBytes)
                    return;
            }
            catch { return; }
            // T2 §4.3 size: shift top-down .1 → .2, active → .1 via tmp+rename, overwrite:false.
            // If .2 occupied, it is compression candidate; to keep bounded generations
            // (Rotation test: ≤4 files without background worker), delete .2 after
            // best-effort synchronous compress attempt (retention deletes .gz later).
            var gen2 = _eventsPath + ".2";
            var gen1 = _eventsPath + ".1";
            try
            {
                if (File.Exists(gen2))
                {
                    try { TryCompressOne(gen2); } catch (Exception caught) { NoteError("RotateSize", caught); }
                    try
                    {
                        if (File.Exists(gen2))
                            File.Delete(gen2);
                    }
                    catch (Exception caught) { NoteError("RotateSize", caught); }
                }
            }
            catch (Exception caught) { NoteError("RotateSize", caught); }
            try
            {
                if (File.Exists(gen1))
                    MoveViaTmp(gen1, gen2);
            }
            catch (Exception caught) { NoteError("RotateSize", caught); }
            try
            {
                if (File.Exists(_eventsPath))
                {
                    MoveViaTmp(_eventsPath, gen1);
                    Interlocked.Increment(ref _rotations);
                }
            }
            catch
            {
                Interlocked.Increment(ref _flushErrors);
            }
        }
        catch
        {
            Interlocked.Increment(ref _flushErrors);
        }
    }

    internal static void MoveViaTmp(string source, string target)
    {
        // T2 §4.1: tmp + atomic rename, overwrite:false (never clobber another generation).
        // Direct File.Move(active, target) on Windows fails/tears when second process
        // holds file open on append; move to tmp frees activePath name instantly.
        var tmp = source + "." + Guid.NewGuid().ToString("N") + ".tmp";
        bool movedToTmp = false;
        try
        {
            File.Move(source, tmp);
            movedToTmp = true;
            File.Move(tmp, target, overwrite: false);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (Exception caught) { NoteError("MoveViaTmp", caught); }
            // If first Move succeeded but second failed (target collision), try to restore?
            // Best-effort: if tmp gone and target exists, rotation is done or skipped;
            // if source gone and tmp deleted without target, data loss avoided by caller
            // catching and counting FlushErrors (file already in tmp, not lost until delete).
            _ = movedToTmp;
        }
    }

    internal void WriteDigest()
    {
        try
        {
            if (Volatile.Read(ref _disabled) != 0)
                return;
            JsonObject snapshot;
            try { snapshot = _metrics.Snapshot(); }
            catch { return; }
            var text = DigestFormatter.Format(snapshot, RecentFailures(), Interlocked.Read(ref _dropped), Interlocked.Read(ref _toolLogs), CountEventLines());
            if (text.Length > 32 * 1024)
                text = text[..(32 * 1024)];
            var temporary = _digestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporary, text, Utf8NoBom);
                FileProtection.ProtectFile(temporary, reason => ReportProtection("WriteDigest", reason));
                File.Move(temporary, _digestPath, overwrite: true);
                FileProtection.ProtectFile(_digestPath, reason => ReportProtection("WriteDigest", reason));
            }
            finally
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); } catch (Exception caught) { NoteError("WriteDigest", caught); }
            }
        }
        catch (Exception caught) { NoteError("WriteDigest", caught); }
    }

    private string[] RecentFailures()
    {
        lock (_recentLock)
            return _recentFailures.TakeLast(10).ToArray();
    }

    /// <summary>Actual per-PID events log line count on disk (may exceed this
    /// process's logged lines: the file is append-only across restarts and
    /// rotations). WriteDigest runs every 50 tool logs, so the count is
    /// cached by file size with a 60s TTL instead of re-reading up to 200k
    /// lines each time. Rotation shrinks the file, which invalidates the
    /// size key.</summary>
    private long _cachedEventLines = -1;
    private long _cachedEventLinesSize = -1;
    private long _cachedEventLinesTicks;
    private long CountEventLines()
    {
        try
        {
            var size = new FileInfo(_eventsPath) is { Exists: true } info ? info.Length : -1;
            if (_cachedEventLines >= 0 && size == _cachedEventLinesSize &&
                unchecked(Environment.TickCount64 - _cachedEventLinesTicks) < 60_000)
                return _cachedEventLines;
            long count = 0;
            foreach (var _ in File.ReadLines(_eventsPath, Encoding.UTF8))
            {
                if (++count >= 200_000) break;
            }
            _cachedEventLines = count;
            _cachedEventLinesSize = size;
            _cachedEventLinesTicks = Environment.TickCount64;
            return count;
        }
        catch { return -1; }
    }

    // T2 §5.2 orphan cleanup (once at startup, under cleanup.lock).
    // Orphan active files events-<deadpid>.log older than 24h without write,
    // pid not alive → rotate to daily name via MoveViaTmp, then retention as
    // usual. Never deletes another live active file.
    internal void TryOrphanCleanup()
    {
        FileStream? lockStream = null;
        bool ownsLock = false;
        try
        {
            ownsLock = TryAcquireCleanupLock(ref lockStream);
            if (!ownsLock)
                return;
            var nowUtc = DateTimeOffset.UtcNow;
            // Orphans: events-*.log (not daily dated, not .1/.2/.gz).
            // The candidates are listed BEFORE the live-process set is built:
            // enumerating the machine's process table is expensive, and it is
            // only needed when there is actually an orphan file to judge.
            string[] candidates;
            try { candidates = System.IO.Directory.GetFiles(_directory, "events-*.log"); }
            catch { candidates = Array.Empty<string>(); }
            if (candidates.Length == 0)
                return;
            HashSet<int> livePids;
            try
            {
                var processes = System.Diagnostics.Process.GetProcesses();
                try
                {
                    livePids = new HashSet<int>(processes.Select(p =>
                    {
                        try { return p.Id; } catch { return -1; }
                    }));
                }
                finally
                {
                    // Process objects own OS handles: release them
                    // synchronously instead of waiting for the finalizer.
                    foreach (var process in processes)
                    {
                        try { process.Dispose(); } catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
                    }
                }
            }
            catch { livePids = new HashSet<int> { _pid }; }
            foreach (var path in candidates)
            {
                try
                {
                    var name = Path.GetFileName(path);
                    // Skip daily dated files events-<pid>-YYYYMMDD*.log (already rotated).
                    // Active pattern is events-<pid>.log exactly.
                    if (!IsActivePerPidName(name))
                        continue;
                    int pid = ParsePid(name);
                    if (pid < 0)
                        continue;
                    if (pid == _pid)
                        continue;
                    if (livePids.Contains(pid))
                        continue;
                    FileInfo fi;
                    try
                    {
                        fi = new FileInfo(path);
                        if (!fi.Exists)
                            continue;
                        fi.Refresh();
                        if ((nowUtc - fi.LastWriteTimeUtc).TotalHours < OrphanAgeHours)
                            continue;
                    }
                    catch { continue; }
                    // Orphan: rotate to daily name by its LastWriteTimeUtc.
                    try
                    {
                        var datePart = fi.LastWriteTimeUtc.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
                        var target = Path.Combine(_directory, $"events-{pid}-{datePart}.log");
                        if (File.Exists(target))
                        {
                            for (var seq = 2; seq <= 99; seq++)
                            {
                                var seqTarget = Path.Combine(_directory, $"events-{pid}-{datePart}-{seq:D2}.log");
                                if (!File.Exists(seqTarget))
                                {
                                    target = seqTarget;
                                    break;
                                }
                            }
                            if (File.Exists(target))
                                continue;
                        }
                        MoveViaTmp(path, target);
                    }
                    catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
                }
                catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
            }
        }
        catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
        finally
        {
            try { lockStream?.Dispose(); } catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
            try
            {
                if (ownsLock && File.Exists(_cleanupLockPath))
                    File.Delete(_cleanupLockPath);
            }
            catch (Exception caught) { NoteError("TryOrphanCleanup", caught); }
        }
    }

    private static bool IsActivePerPidName(string fileName)
    {
        // events-<pid>.log exactly (not .1/.2/.gz, not dated).
        try
        {
            if (!fileName.StartsWith("events-", StringComparison.OrdinalIgnoreCase))
                return false;
            if (!fileName.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                return false;
            var middle = fileName.Substring("events-".Length, fileName.Length - "events-".Length - ".log".Length);
            // Active has no '-' (dated has events-<pid>-YYYYMMDD).
            if (middle.Contains('-'))
                return false;
            return int.TryParse(middle, out _);
        }
        catch { return false; }
    }

    private static int ParsePid(string fileName)
    {
        try
        {
            var middle = fileName.Substring("events-".Length, fileName.Length - "events-".Length - ".log".Length);
            if (int.TryParse(middle, out var pid) && pid > 0)
                return pid;
            return -1;
        }
        catch { return -1; }
    }

    private bool TryAcquireCleanupLock(ref FileStream? stream)
    {
        try
        {
            // Stale lock older than 10 min → delete.
            try
            {
                if (File.Exists(_cleanupLockPath))
                {
                    var age = DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(_cleanupLockPath);
                    if (age.TotalMinutes > CleanupLockStaleMinutes)
                    {
                        try { File.Delete(_cleanupLockPath); } catch (Exception caught) { NoteError("TryAcquireCleanupLock", caught); }
                    }
                }
            }
            catch (Exception caught) { NoteError("TryAcquireCleanupLock", caught); }
            stream = new FileStream(_cleanupLockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.DeleteOnClose);
            return true;
        }
        catch (IOException)
        {
            // Another process owns cleanup this tick → skip (not an error).
            try { stream?.Dispose(); } catch (Exception caught) { NoteError("TryAcquireCleanupLock", caught); }
            stream = null;
            return false;
        }
        catch
        {
            try { stream?.Dispose(); } catch (Exception caught) { NoteError("TryAcquireCleanupLock", caught); }
            stream = null;
            return false;
        }
    }

    // T2 §6 + §8: background .gz + retention, separate timer, BelowNormal, TryEnter (never waits).
    internal void CompressAndRetainTick()
    {
        // Never wait for flush: if flush in progress, skip tick.
        bool entered = false;
        try
        {
            entered = Monitor.TryEnter(_flushLock);
            if (!entered)
                return;
            if (Volatile.Read(ref _disabled) != 0)
                return;
            if (Volatile.Read(ref _disposed) != 0)
                return;
            try { System.Threading.Thread.CurrentThread.Priority = System.Threading.ThreadPriority.BelowNormal; }
            catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
            try { CompressOldGenerations(); } catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
            try { EnforceRetention(); } catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
        }
        catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
        finally
        {
            try
            {
                if (entered)
                    Monitor.Exit(_flushLock);
            }
            catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
            // Restore priority best-effort.
            try { System.Threading.Thread.CurrentThread.Priority = System.Threading.ThreadPriority.Normal; }
            catch (Exception caught) { NoteError("CompressAndRetainTick", caught); }
        }
    }

    private void CompressOldGenerations()
    {
        try
        {
            var nowUtc = DateTimeOffset.UtcNow;
            var candidates = new List<string>();
            string[] files;
            try { files = System.IO.Directory.GetFiles(_directory, "events*"); }
            catch { return; }
            foreach (var path in files)
            {
                try
                {
                    var name = Path.GetFileName(path);
                    if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (name.Equals("cleanup.lock", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (name.Equals("digest.md", StringComparison.OrdinalIgnoreCase))
                        continue;
                    // Never: active events-<pid>.log, .log.1 (fresh generation).
                    if (string.Equals(path, _eventsPath, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (string.Equals(path, _eventsPath + ".1", StringComparison.OrdinalIgnoreCase))
                        continue;
                    // Also never compress other live actives events-<otherpid>.log (only orphan via lock handles them).
                    if (IsActivePerPidName(name))
                        continue;
                    // What to compress: .log.2, dated daily older than 24h.
                    bool isGen2 = name.EndsWith(".log.2", StringComparison.OrdinalIgnoreCase);
                    bool isDatedDaily = IsDatedDailyName(name);
                    if (!isGen2 && !isDatedDaily)
                        continue;
                    FileInfo fi = new(path);
                    if (!fi.Exists)
                        continue;
                    fi.Refresh();
                    if ((nowUtc - fi.LastWriteTimeUtc).TotalHours < OrphanAgeHours)
                        continue;
                    var gzPath = path + ".gz";
                    if (File.Exists(gzPath))
                        continue;
                    candidates.Add(path);
                    if (candidates.Count >= MaxCompressPerTick)
                        break;
                }
                catch (Exception caught) { NoteError("CompressOldGenerations", caught); }
            }
            // Oldest first (stable retention).
            candidates.Sort((a, b) =>
            {
                try
                {
                    var ta = File.GetLastWriteTimeUtc(a);
                    var tb = File.GetLastWriteTimeUtc(b);
                    return ta.CompareTo(tb);
                }
                catch { return 0; }
            });
            int done = 0;
            foreach (var src in candidates)
            {
                if (done >= MaxCompressPerTick)
                    break;
                try
                {
                    if (TryCompressOne(src))
                        Interlocked.Increment(ref _compressions);
                    done++;
                }
                catch { done++; }
                if (Volatile.Read(ref _disposed) != 0)
                    break;
            }
        }
        catch (Exception caught) { NoteError("CompressOldGenerations", caught); }
    }

    private static bool IsDatedDailyName(string fileName)
    {
        // events-<pid>-YYYYMMDD.log or -seq (already rotated daily files).
        try
        {
            if (!fileName.StartsWith("events-", StringComparison.OrdinalIgnoreCase))
                return false;
            // Must contain 8-digit date.
            for (var i = 0; i + 8 <= fileName.Length; i++)
            {
                bool allDigits = true;
                for (var j = 0; j < 8; j++)
                {
                    if (!char.IsDigit(fileName[i + j]))
                    {
                        allDigits = false;
                        break;
                    }
                }
                if (allDigits)
                    return true;
            }
            return false;
        }
        catch { return false; }
    }

    internal static bool TryCompressOne(string sourcePath)
    {
        // T2 §6 algorithm: <name>.gz.tmp-Guid via GZipStream + SequentialScan,
        // verify .gz exists, Length>0, magic 0x1F 0x8B, then Delete(source).
        // Best-effort, never throws, no Disable (compression best-effort).
        var tmp = sourcePath + ".gz." + Guid.NewGuid().ToString("N") + ".tmp";
        var gz = sourcePath + ".gz";
        try
        {
            if (!File.Exists(sourcePath))
                return false;
            if (File.Exists(gz))
                return false;
            FileInfo srcInfo = new(sourcePath);
            srcInfo.Refresh();
            if (!srcInfo.Exists || srcInfo.Length == 0)
                return false;
            try
            {
                using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 8192, FileOptions.SequentialScan);
                using var tmpStream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 8192, FileOptions.SequentialScan);
                using var gzip = new GZipStream(tmpStream, CompressionLevel.SmallestSize);
                input.CopyTo(gzip);
            }
            catch { return false; }
            // Verify: exists, Length>0, magic 1F 8B.
            try
            {
                FileInfo gzInfo = new(tmp);
                gzInfo.Refresh();
                if (!gzInfo.Exists || gzInfo.Length <= 0)
                    return false;
                using var verify = new FileStream(tmp, FileMode.Open, FileAccess.Read, FileShare.Read, 4);
                int b0 = verify.ReadByte();
                int b1 = verify.ReadByte();
                if (b0 != 0x1F || b1 != 0x8B)
                    return false;
            }
            catch { return false; }
            try
            {
                File.Move(tmp, gz, overwrite: false);
                FileProtection.ProtectFile(gz, reason => ReportProtection("TryCompressOne", reason));
            }
            catch (IOException)
            {
                // .gz appeared concurrently (other process compressed) → treat as done, delete tmp.
                return File.Exists(gz);
            }
            try
            {
                File.Delete(sourcePath);
                return true;
            }
            catch { return File.Exists(gz); }
        }
        catch { return false; }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (Exception caught) { NoteError("TryCompressOne", caught); }
        }
    }

    private void EnforceRetention()
    {
        FileStream? lockStream = null;
        bool ownsLock = false;
        try
        {
            // T2 §8: deletion only via cleanup-lock (two processes must not split generations).
            ownsLock = TryAcquireCleanupLock(ref lockStream);
            if (!ownsLock)
                return;
            var nowUtc = DateTimeOffset.UtcNow;
            // Order: tmp garbage → total-size cap BEFORE age (leak P0: a
            // full directory must shed bytes even when nothing is old
            // enough for the age caps) → .gz older 30d → daily older 7d.
            try { DeleteTmpGarbage(nowUtc); } catch (Exception caught) { NoteError("EnforceRetention", caught); }
            try { EnforceTotalSize(); } catch (Exception caught) { NoteError("EnforceRetention", caught); }
            try { DeleteGzOlderThan(nowUtc); } catch (Exception caught) { NoteError("EnforceRetention", caught); }
            try { DeleteDailyOlderThan(nowUtc); } catch (Exception caught) { NoteError("EnforceRetention", caught); }
        }
        catch (Exception caught) { NoteError("EnforceRetention", caught); }
        finally
        {
            try { lockStream?.Dispose(); } catch (Exception caught) { NoteError("EnforceRetention", caught); }
            try
            {
                if (ownsLock && File.Exists(_cleanupLockPath))
                    File.Delete(_cleanupLockPath);
            }
            catch (Exception caught) { NoteError("EnforceRetention", caught); }
        }
    }

    private void DeleteTmpGarbage(DateTimeOffset nowUtc)
    {
        try
        {
            string[] files;
            try { files = System.IO.Directory.GetFiles(_directory, "*.tmp"); }
            catch { return; }
            foreach (var path in files)
            {
                try
                {
                    var name = Path.GetFileName(path);
                    bool ours = name.StartsWith("events", StringComparison.OrdinalIgnoreCase)
                        || name.StartsWith("digest", StringComparison.OrdinalIgnoreCase);
                    if (!ours)
                        continue;
                    var age = nowUtc - File.GetLastWriteTimeUtc(path);
                    if (age.TotalMinutes > TmpMaxAgeMinutes)
                    {
                        try { File.Delete(path); } catch (Exception caught) { NoteError("DeleteTmpGarbage", caught); }
                    }
                }
                catch (Exception caught) { NoteError("DeleteTmpGarbage", caught); }
            }
        }
        catch (Exception caught) { NoteError("DeleteTmpGarbage", caught); }
    }

    private void DeleteGzOlderThan(DateTimeOffset nowUtc)
    {
        try
        {
            string[] files;
            try { files = System.IO.Directory.GetFiles(_directory, "*.gz"); }
            catch { return; }
            foreach (var path in files)
            {
                try
                {
                    var age = nowUtc - File.GetLastWriteTimeUtc(path);
                    if (age.TotalDays > GzMaxAgeDays)
                    {
                        try { File.Delete(path); } catch (Exception caught) { NoteError("DeleteGzOlderThan", caught); }
                    }
                }
                catch (Exception caught) { NoteError("DeleteGzOlderThan", caught); }
            }
        }
        catch (Exception caught) { NoteError("DeleteGzOlderThan", caught); }
    }

    private void DeleteDailyOlderThan(DateTimeOffset nowUtc)
    {
        try
        {
            string[] files;
            try { files = System.IO.Directory.GetFiles(_directory, "events*"); }
            catch { return; }
            foreach (var path in files)
            {
                try
                {
                    var name = Path.GetFileName(path);
                    if (string.Equals(path, _eventsPath, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (string.Equals(path, _eventsPath + ".1", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                        continue; // handled by Gz age (30d), not daily (7d) — but .gz of daily older 7d stays until 30d per spec.
                    if (!IsDatedDailyName(name))
                        continue;
                    DateTime fileDate = ExtractDateOrLastWrite(path, name);
                    var ageDays = (nowUtc.UtcDateTime.Date - fileDate.Date).TotalDays;
                    if (ageDays > DailyRetentionDays)
                    {
                        try { File.Delete(path); } catch (Exception caught) { NoteError("DeleteDailyOlderThan", caught); }
                        // Delete paired .gz as well (daily + its .gz).
                        try
                        {
                            var gz = path + ".gz";
                            if (File.Exists(gz))
                                File.Delete(gz);
                        }
                        catch (Exception caught) { NoteError("DeleteDailyOlderThan", caught); }
                    }
                }
                catch (Exception caught) { NoteError("DeleteDailyOlderThan", caught); }
            }
        }
        catch (Exception caught) { NoteError("DeleteDailyOlderThan", caught); }
    }

    private static DateTime ExtractDateOrLastWrite(string path, string fileName)
    {
        try
        {
            // Prefer date in name (YYYYMMDD), else LastWriteTimeUtc.
            for (var i = 0; i + 8 <= fileName.Length; i++)
            {
                bool allDigits = true;
                for (var j = 0; j < 8; j++)
                {
                    if (!char.IsDigit(fileName[i + j]))
                    {
                        allDigits = false;
                        break;
                    }
                }
                if (allDigits)
                {
                    var part = fileName.Substring(i, 8);
                    if (DateTime.TryParseExact(part, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var dt))
                        return dt;
                }
            }
        }
        catch (Exception caught) { NoteError("ExtractDateOrLastWrite", caught); }
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.UtcNow; }
    }

    private void EnforceTotalSize()
    {
        try
        {
            string[] files;
            try { files = System.IO.Directory.GetFiles(_directory, "events*"); }
            catch { return; }
            long total = 0;
            var sized = new List<(string Path, DateTime Time, long Len, bool Protected)>();
            foreach (var path in files)
            {
                try
                {
                    FileInfo fi = new(path);
                    if (!fi.Exists)
                        continue;
                    fi.Refresh();
                    long len = fi.Length;
                    total += len;
                    bool isProtected = string.Equals(path, _eventsPath, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(path, _eventsPath + ".1", StringComparison.OrdinalIgnoreCase);
                    sized.Add((path, fi.LastWriteTimeUtc, len, isProtected));
                }
                catch (Exception caught) { NoteError("EnforceTotalSize", caught); }
            }
            // Include .gz in total (events* + *.gz per spec §8).
            try
            {
                foreach (var gz in System.IO.Directory.GetFiles(_directory, "*.gz"))
                {
                    try
                    {
                        FileInfo fi = new(gz);
                        if (!fi.Exists)
                            continue;
                        fi.Refresh();
                        total += fi.Length;
                        sized.Add((gz, fi.LastWriteTimeUtc, fi.Length, false));
                    }
                    catch (Exception caught) { NoteError("EnforceTotalSize", caught); }
                }
            }
            catch (Exception caught) { NoteError("EnforceTotalSize", caught); }
            if (total <= TotalDirectoryBytesCap)
                return;
            // Delete oldest unprotected (.gz/daily) first until under cap.
            sized.Sort((a, b) => a.Time.CompareTo(b.Time));
            foreach (var entry in sized)
            {
                if (total <= TotalDirectoryBytesCap)
                    break;
                if (entry.Protected)
                    continue;
                try
                {
                    File.Delete(entry.Path);
                    total -= entry.Len;
                }
                catch (Exception caught) { NoteError("EnforceTotalSize", caught); }
            }
        }
        catch (Exception caught) { NoteError("EnforceTotalSize", caught); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        try { _flushTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { _digestTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { _compressTimer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { _flushTimer.Dispose(); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { _digestTimer.Dispose(); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { _compressTimer.Dispose(); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { Flush(); } catch (Exception caught) { NoteError("Dispose", caught); }
        try { WriteDigest(); } catch (Exception caught) { NoteError("Dispose", caught); }
        GC.SuppressFinalize(this);
    }
}

internal static class DigestFormatter
{
    internal static string Format(JsonObject snapshot, string[] recentFailures, long dropped, long loggedLines, long fileLines = -1)
    {
        var builder = new StringBuilder(4096);
        try
        {
            var uptime = snapshot["uptimeSeconds"]?.GetValue<double>() ?? 0;
            var summary = snapshot["toolsSummary"] as JsonObject;
            var total = summary?["totalCalls"]?.GetValue<long>() ?? snapshot["toolCalls"]?.GetValue<long>() ?? 0;
            var ok = summary?["totalOk"]?.GetValue<long>() ?? 0;
            var bytesIn = snapshot["bytesReceived"]?.GetValue<long>() ?? 0;
            var bytesOut = snapshot["bytesSent"]?.GetValue<long>() ?? 0;
            builder.AppendLine("# DBGLink telemetry digest");
            builder.AppendLine($"updated: {DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ} | uptime: {FormatDuration(uptime)} | tool events: {total} (this process lines: {loggedLines}, file lines: {(fileLines < 0 ? "?" : fileLines.ToString(System.Globalization.CultureInfo.InvariantCulture))}, dropped: {dropped})");
            // The tok total is the sum of the real per-call BPE counts
            // already accumulated in the snapshot (0 for byte-only sides
            // without payload text). With no real-BPE aggregate the field
            // is omitted rather than estimated.
            var totalTokens = SumTotalTokens(snapshot);
            var totalLine = $"total: {total} calls, ok {ok} ({Rate(ok, total):P1}), in {FormatBytes(bytesIn)} out {FormatBytes(bytesOut)}";
            if (totalTokens > 0)
                totalLine += $" tok{FormatTokens(totalTokens)}";
            builder.AppendLine(totalLine);
            AppendTop(builder, summary?["topSlowest"] as JsonArray, "slow p95", row => $"{row?["tool"]} p95 {row?["p95Ms"]}ms avg {row?["avgMs"]}ms max {row?["maxMs"]}ms x{row?["calls"]}");
            AppendTop(builder, summary?["topLargest"] as JsonArray, "big avg-out", row => $"{row?["tool"]} {FormatBytes((long)(row?["avgBytesOut"]?.GetValue<double>() ?? 0))} x{row?["calls"]}");
            AppendBigTotal(builder, snapshot);
            AppendFunctionsTotal(builder, snapshot);
            AppendTop(builder, summary?["topErrors"] as JsonArray, "errors", row =>
            {
                var rate = Rate(row?["errors"]?.GetValue<long>() ?? 0, row?["calls"]?.GetValue<long>() ?? 0);
                var topCode = row?["topErrorCode"]?.GetValue<string>() ?? "-";
                var topCount = row?["topErrorCodeCount"]?.GetValue<long>() ?? 0;
                var top = string.Equals(topCode, "-", StringComparison.Ordinal) ? "" : $" top={topCode}x{topCount}";
                return $"{row?["tool"]} {row?["errors"]} ({rate:P0}){top}";
            });
            if (snapshot["backends"] is JsonObject backends)
            {
                var native = backends["native"] as JsonObject;
                var ghidra = backends["ghidra"] as JsonObject;
                builder.Append("backends:");
                if (native is not null)
                    builder.Append($" native {native["calls"]} ok {Rate(native["ok"]?.GetValue<long>() ?? 0, native["calls"]?.GetValue<long>() ?? 0):P0}{FormatTopBackendError(native["errors"] as JsonObject)}");
                if (ghidra is not null)
                {
                    var hits = ghidra["cacheHits"]?.GetValue<long>() ?? 0;
                    var miss = ghidra["cacheMisses"]?.GetValue<long>() ?? 0;
                    builder.Append($" | ghidra {ghidra["calls"]} ok {Rate(ghidra["ok"]?.GetValue<long>() ?? 0, ghidra["calls"]?.GetValue<long>() ?? 0):P0} cache {Rate(hits, hits + miss):P0}{FormatTopBackendError(ghidra["errors"] as JsonObject)}");
                }
                builder.AppendLine();
                // Pinned accounting: backends counts top-level bridge uses
                // (at most one per tool call), so native+ghidra <= total
                // below. Fan-out RPCs inside a tool call (batch items,
                // snapshot sections, enrichment lookups) are attributed to
                // their wrapper, not added here.
                long fanout = 0;
                try { fanout = backends["fanoutSubCalls"]?.GetValue<long>() ?? 0; } catch { fanout = 0; }
                if (fanout > 0)
                    builder.AppendLine($"fanout sub-calls: {fanout} (batch/snapshot/enrichment RPCs attributed to their wrapper tool call, not counted in backends)");
            }
            if (snapshot["httpStatus"] is JsonObject http)
                builder.AppendLine($"http: {string.Join(" ", http.Select(p => $"{p.Key}x{p.Value?.GetValue<long>() ?? 0}"))} | authFail {snapshot["authFailures"]} originReject {snapshot["originRejects"]}");
            if (snapshot["sessions"] is JsonObject sessions)
            {
                builder.Append($"sessions: registered {sessions["registeredTotal"]} closed {sessions["closedTotal"]} replaced {sessions["bridgeReplacedTotal"]}");
                if (sessions["bySession"] is JsonObject bySession && bySession.Count > 0)
                {
                    var topSessions = bySession.OrderByDescending(p => p.Value?.GetValue<long>() ?? 0).Take(3)
                        .Select(p => $"{p.Key}x{p.Value?.GetValue<long>() ?? 0}");
                    builder.Append($" top {string.Join(" ", topSessions)}");
                }
                if (sessions["active"] is not null)
                    builder.Append($" active {sessions["active"]}");
                builder.AppendLine();
            }
            builder.AppendLine("recent failures (up to 10):");
            if (recentFailures.Length == 0)
                builder.AppendLine("(none)");
            else
                foreach (var line in recentFailures)
                    builder.AppendLine(line);
            builder.AppendLine("---");
            builder.AppendLine("Accounting: total counts MCP tool calls (one per tools/call); backends counts top-level bridge uses (at most one per tool call, first RPC wins) so native+ghidra <= total; fan-out RPCs inside a tool call are attributed to their wrapper (see sub= mix, fanout line).");
            builder.AppendLine("Line fields: in/out payload bytes, tok=real cl100k_base BPE tokens (0 when payload text was unavailable), sess=analysis session, sub=batch sub-method mix.");
            builder.AppendLine("Lifecycle lines (_session ..., _open ...ms lifecycle, _server ...) carry kind+state only and never match the tool regex above.");
            builder.AppendLine("Agent rule: the same error twice in a row means change the inputs, not the call.");
            builder.AppendLine("Read this file first. Grep events-*.log for details (last 50 lines usually enough).");
            return builder.ToString();
        }
        catch
        {
            return "# DBGLink telemetry digest\n(unavailable)\n";
        }
    }

    /// <summary>Sum of the real per-call BPE token counts accumulated in the
    /// snapshot's per-tool rows (this process only). Saturates instead of
    /// wrapping.</summary>
    private static long SumTotalTokens(JsonObject snapshot)
    {
        try
        {
            long sum = 0;
            if (snapshot["tools"] is JsonObject tools)
            {
                foreach (var pair in tools)
                {
                    if (pair.Value is not JsonObject row) continue;
                    sum = AddSaturating(sum, Math.Max(0, row["totalTokens"]?.GetValue<long>() ?? 0));
                }
            }
            return sum;
        }
        catch { return 0; }
    }

    private static void AppendBigTotal(StringBuilder builder, JsonObject snapshot)
    {
        try
        {
            var merged = new Dictionary<string, (long Calls, long In, long Out, long Tokens)>(StringComparer.Ordinal);
            if (snapshot["tools"] is JsonObject tools)
            {
                foreach (var pair in tools)
                {
                    if (pair.Value is not JsonObject row) continue;
                    // Snapshot rows carry the real accumulated BPE count
                    // (totalTokens, 0 for byte-only sides without text).
                    merged[pair.Key] = (
                        row["calls"]?.GetValue<long>() ?? 0,
                        row["totalBytesIn"]?.GetValue<long>() ?? 0,
                        row["totalBytesOut"]?.GetValue<long>() ?? 0,
                        row["totalTokens"]?.GetValue<long>() ?? 0);
                }
            }
            var top = merged.OrderByDescending(p => p.Value.Out).Take(5).ToArray();
            if (top.Length == 0)
            {
                builder.AppendLine("big total: (none)");
                return;
            }
            builder.Append("big total: ");
            builder.AppendLine(string.Join(" | ", top.Select(p =>
                $"{p.Key} out{FormatBytes(p.Value.Out)} in{FormatBytes(p.Value.In)} tok{FormatTokens(p.Value.Tokens)} x{p.Value.Calls}")));
        }
        catch { builder.AppendLine("big total: (unavailable)"); }
    }

    /// <summary>w06: per-function top-5 by attributed real BPE tokens
    /// (this-process snapshot). Row: name xCalls tok<tokens> [errN].
    /// Missing/empty ⇒ "(none)".</summary>
    private static void AppendFunctionsTotal(StringBuilder builder, JsonObject snapshot)
    {
        try
        {
            var merged = new Dictionary<string, (long Calls, long Tokens, long Errors)>(StringComparer.Ordinal);
            if (snapshot["functions"] is JsonObject fns)
            {
                foreach (var pair in fns)
                {
                    if (pair.Value is not JsonObject row) continue;
                    merged[pair.Key] = (
                        row["calls"]?.GetValue<long>() ?? 0,
                        row["tokens"]?.GetValue<long>() ?? 0,
                        row["errors"]?.GetValue<long>() ?? 0);
                }
            }
            var top = merged.OrderByDescending(p => p.Value.Tokens).Take(5).ToArray();
            if (top.Length == 0)
            {
                builder.AppendLine("functions: top (none)");
                return;
            }
            builder.Append("functions: top ");
            builder.AppendLine(string.Join(" | ", top.Select(p =>
            {
                var err = p.Value.Errors > 0 ? $" err{p.Value.Errors}" : "";
                return $"{p.Key} x{p.Value.Calls} tok{FormatTokens(p.Value.Tokens)}{err}";
            })));
        }
        catch { builder.AppendLine("functions: top (unavailable)"); }
    }

    private static long AddSaturating(long a, long b)
    {
        var value = a + b;
        return value < 0 ? long.MaxValue : value;
    }

    private static void AppendTop(StringBuilder builder, JsonArray? rows, string label, Func<JsonObject?, string> format)
    {
        if (rows is null || rows.Count == 0)
        {
            builder.AppendLine($"{label}: (none)");
            return;
        }
        builder.Append(label).Append(": ");
        builder.AppendLine(string.Join(" | ", rows.OfType<JsonObject>().Take(5).Select(format)));
    }

    private static string FormatTopBackendError(JsonObject? errors)
    {
        try
        {
            if (errors is null || errors.Count == 0)
                return "";
            var top = errors.OrderByDescending(p => p.Value?.GetValue<long>() ?? 0).First();
            return $" err={top.Key}x{top.Value?.GetValue<long>() ?? 0}";
        }
        catch { return ""; }
    }

    private static double Rate(long part, long total) => total <= 0 ? 0 : (double)part / total;
    private static string FormatBytes(double bytes) => bytes switch
    {
        >= 1024 * 1024 => $"{bytes / (1024 * 1024):F1}MB",
        >= 1024 => $"{bytes / 1024:F1}KB",
        _ => $"{bytes:F0}B",
    };
    private static string FormatTokens(long tokens) => tokens switch
    {
        >= 1_000_000 => $"{tokens / 1_000_000d:F1}M",
        >= 1_000 => $"{tokens / 1_000d:F1}k",
        _ => $"{tokens}",
    };
    private static string FormatDuration(double seconds) => TimeSpan.FromSeconds(Math.Max(0, seconds)) switch
    {
        { TotalHours: >= 1 } span => $"{(int)span.TotalHours}h{span.Minutes}m",
        { TotalMinutes: >= 1 } span => $"{(int)span.TotalMinutes}m{span.Seconds}s",
        var span => $"{span.Seconds}s",
    };
}

} // end namespace DbgLink.Server
