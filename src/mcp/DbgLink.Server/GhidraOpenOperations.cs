using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed class GhidraOpenOperations(IGhidraControlClient? control, TimeSpan? importTimeout = null) : IDisposable
{
    internal const int MaxWaitMs = 30000;
    /// <summary>
    /// Default bound for one import operation (queue wait + active import).
    /// The launcher starts with a ten-minute analysis budget and then retries
    /// without analysis; two extra minutes here let that fallback finish and
    /// register instead of racing a terminal timeout. An uncompletable import
    /// (e.g. RAW/unknown format that Ghidra cannot import unattended) still
    /// becomes a terminal <c>ghidra_import_timeout</c> error instead of an
    /// infinite <c>pending</c>. Well above the 30s long-poll ceiling / 35s tool
    /// floor, so normal polling is unaffected. Overridable per process with
    /// <c>DBGLINK_GHIDRA_IMPORT_TIMEOUT_MS</c> (clamped to 60s..900s) or per
    /// instance via the constructor/property (used by tests for ms-scale
    /// deadlines). Wire keys unchanged.
    /// </summary>
    internal static readonly TimeSpan DefaultImportTimeout = TimeSpan.FromMinutes(12);
    internal const string ImportTimeoutEnvironmentVariable = "DBGLINK_GHIDRA_IMPORT_TIMEOUT_MS";
    private const int WaitStepMs = 50;
    private TimeSpan _importTimeout = importTimeout is null
        ? ResolveImportTimeout()
        : ValidateImportTimeout(importTimeout.Value);
    internal TimeSpan ImportTimeout
    {
        get => _importTimeout;
        set => _importTimeout = ValidateImportTimeout(value);
    }
    private readonly object _gate = new();
    private readonly Dictionary<string, Operation> _operations = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _lifetime = new();
    private Task _tail = Task.CompletedTask;
    private long _sequence;
    private int _disposed;
    internal ServerMetrics? Telemetry { get; set; }
    internal int PendingCount { get { lock (_gate) return _operations.Values.Count(o => o.Result is null); } }
    private sealed class Operation(long sequence, string path, bool analyze, CancellationTokenSource cancellation)
    {
        public long Sequence { get; } = sequence;
        public string Path { get; } = path;
        public bool Analyze { get; } = analyze;
        public CancellationTokenSource Cancellation { get; } = cancellation;
        public DateTimeOffset Created { get; } = DateTimeOffset.UtcNow;
        public string State { get; set; } = "queued";
        public string? Result { get; set; }
        public DateTimeOffset? Completed { get; set; }
    }

    internal async Task<string> BeginGhidraOpenAsync(string path, bool analyze = true, int waitMs = 0,
        CancellationToken cancellationToken = default)
    {
        string id;
        string queued;
        // Normalize before compare/store so "..\ " spellings of the same file
        // coalesce into one queue slot instead of occupying several.
        var normalizedPath = NormalizeOpenPath(path);
        lock (_gate)
        {
            Prune();
            if (control is null || _lifetime.IsCancellationRequested)
            {
                Telemetry?.RecordControlRejected();
                return BridgeEnvelope.Error("ghidra_unavailable", "Ghidra import control is unavailable.");
            }
            // Coalesce duplicate imports: the same target queued twice must share
            // one operation instead of occupying two import slots.
            foreach (var existing in _operations)
            {
                if (existing.Value.Result is null &&
                    existing.Value.Analyze == analyze &&
                    string.Equals(existing.Value.Path, normalizedPath, StringComparison.OrdinalIgnoreCase))
                {
                    queued = BridgeEnvelope.Success(Describe(existing.Key, existing.Value));
                    id = existing.Key;
                    goto AfterEnqueue;
                }
            }
            if (_operations.Values.Count(o => o.Completed is null) >= 8 || _operations.Count >= 64)
            {
                Telemetry?.RecordControlRejected();
                return BridgeEnvelope.Error("ghidra_operation_limit", "The bounded Ghidra import queue is full.");
            }
            id = "ghidra-open-" + Guid.NewGuid().ToString("N");
            var operation = new Operation(++_sequence, normalizedPath, analyze, CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token));
            _operations.Add(id, operation);
            var previous = _tail;
            _tail = RunAsync(previous, operation);
            Telemetry?.RecordControlBegun();
            queued = BridgeEnvelope.Success(Describe(id, operation));
        }
    AfterEnqueue:
        waitMs = Math.Clamp(waitMs, 0, MaxWaitMs);
        if (waitMs <= 0)
            return queued;
        return await WaitForOperationAsync(id, waitMs, cancellationToken, attachOperationId: true).ConfigureAwait(false);
    }

    private async Task RunAsync(Task previous, Operation operation)
    {
        string terminal = "failed";
        try
        {
            await previous.WaitAsync(operation.Cancellation.Token).ConfigureAwait(false);
            TimeSpan remaining;
            lock (_gate)
            {
                operation.Cancellation.Token.ThrowIfCancellationRequested();
                operation.State = "importing";
                // Total operation age (queue wait + active import) is bounded:
                // an operation that waited too long behind a slow head expires
                // without starting another launcher import.
                remaining = _importTimeout - (DateTimeOffset.UtcNow - operation.Created);
                if (remaining <= TimeSpan.Zero)
                {
                    if (operation.Result is null)
                    {
                        operation.State = "failed";
                        operation.Result = BuildImportTimeoutError(operation);
                    }
                    terminal = operation.State;
                    return;
                }
            }
            var importTask = control!.OpenFileAsync(operation.Path, operation.Analyze, operation.Cancellation.Token);
            // Race the import against the deadline (unlinked delay: cancelling
            // the operation must surface as cancelled, never as a timeout).
            // WhenAny bounds this method even if the control ignores
            // cancellation; the status path re-checks the same deadline.
            var completed = await Task.WhenAny(importTask, Task.Delay(remaining)).ConfigureAwait(false);
            if (!ReferenceEquals(completed, importTask))
            {
                lock (_gate)
                {
                    if (operation.Result is null)
                    {
                        if (string.Equals(operation.State, "cancelling", StringComparison.Ordinal))
                        {
                            // User cancel was already in flight: it wins over
                            // the deadline, and the hung import never answered.
                            operation.State = "cancelled";
                            operation.Result = BridgeEnvelope.Error("ghidra_open_cancelled", "The Ghidra import was cancelled. Re-issue OpenGhidraFile for a new operation; do not poll the cancelled operationId.");
                            terminal = "cancelled";
                        }
                        else
                        {
                            operation.State = "failed";
                            operation.Result = BuildImportTimeoutError(operation);
                            terminal = "failed";
                        }
                    }
                    else
                    {
                        terminal = operation.State;
                    }
                }
                try { operation.Cancellation.Cancel(); } catch { }
                // Observe the abandoned import so its exceptions never surface
                // as unobserved; the terminal result above is authoritative.
                _ = importTask.ContinueWith(static task => _ = task.Exception,
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                if (string.Equals(terminal, "cancelled", StringComparison.Ordinal))
                {
                    await previous.ConfigureAwait(false);
                }
                return;
            }
            var result = await importTask.ConfigureAwait(false);
            lock (_gate)
            {
                // A lazy status-path expiry may have already terminalized this
                // operation; never overwrite an existing terminal result.
                if (operation.Result is null)
                {
                    operation.Result = result;
                    operation.State = JsonNode.Parse(result)?["ok"]?.GetValue<bool>() == true ? "completed" : "failed";
                }
                terminal = operation.State;
            }
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
            {
                if (operation.Result is null)
                {
                    operation.State = "cancelled";
                    operation.Result = BridgeEnvelope.Error("ghidra_open_cancelled", "The Ghidra import was cancelled. Re-issue OpenGhidraFile for a new operation; do not poll the cancelled operationId.");
                    terminal = "cancelled";
                }
                else
                {
                    terminal = operation.State;
                }
            }
            // A cancelled queued item must not let its successor overtake the active import.
            await previous.ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            lock (_gate)
            {
                if (operation.Result is null)
                {
                    // Preserve the launcher's capacity code when the control
                    // throws it (e.g. pre-spawn table-full): callers must see
                    // session_capacity_reached, not a generic open failure.
                    if (exception is InvalidOperationException && IsSessionCapacity(exception.Message))
                    {
                        operation.State = "failed";
                        operation.Result = BridgeEnvelope.Error("session_capacity_reached",
                            "The maximum number of parallel analysis sessions has been reached. Close an unused session with CloseAnalysisSession, then retry.");
                    }
                    else
                    {
                        operation.State = "failed";
                        operation.Result = BridgeEnvelope.Error("ghidra_open_failed", "The Ghidra import failed. Re-issue OpenGhidraFile to retry as a new operation; track it via GetGhidraOpenStatus.");
                    }
                }
                terminal = operation.State;
            }
        }
        finally
        {
            long elapsedMs;
            lock (_gate)
            {
                operation.Completed = DateTimeOffset.UtcNow;
                elapsedMs = (long)(operation.Completed.Value - operation.Created).TotalMilliseconds;
            }
            try { Telemetry?.RecordControlTerminal(terminal, elapsedMs); } catch { }
        }
    }

    internal Task<string> GetGhidraOpenStatusAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        string id;
        int waitMs;
        lock (_gate)
        {
            Prune();
            if (arguments is not { ValueKind: JsonValueKind.Object } ||
                !arguments.Value.TryGetProperty("operationId", out var idElement) ||
                idElement.ValueKind != JsonValueKind.String ||
                string.IsNullOrEmpty(idElement.GetString()))
                return Task.FromResult(BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes: re-issue OpenGhidraFile for a new operationId instead of polling."));
            id = idElement.GetString()!;
            if (!_operations.ContainsKey(id))
                return Task.FromResult(BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes: re-issue OpenGhidraFile for a new operationId instead of polling."));
            waitMs = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "waitMs", 0), 0, MaxWaitMs);
            if (waitMs <= 0)
            {
                if (!_operations.TryGetValue(id, out var operation))
                    return Task.FromResult(BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes: re-issue OpenGhidraFile for a new operationId instead of polling."));
                ExpireIfImportTimedOutLocked(operation);
                return Task.FromResult(operation.Result ?? BridgeEnvelope.Success(Describe(id, operation)));
            }
        }
        return WaitForOperationAsync(id, waitMs, cancellationToken);
    }

    private async Task<string> WaitForOperationAsync(string id, int waitMs, CancellationToken cancellationToken, bool attachOperationId = false)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            lock (_gate)
            {
                Prune();
                if (!_operations.TryGetValue(id, out var operation))
                    return BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes: re-issue OpenGhidraFile for a new operationId instead of polling.");
                // Belt-and-braces with the RunAsync deadline: even if the
                // worker is starved, a poll past the import deadline observes
                // the same terminal timeout instead of an infinite pending.
                ExpireIfImportTimedOutLocked(operation);
                if (operation.Result is not null)
                    return attachOperationId ? AttachOperationId(operation.Result, id) : operation.Result;
                var remainingMs = waitMs - watch.ElapsedMilliseconds;
                if (remainingMs <= 0)
                {
                    var pending = Describe(id, operation);
                    pending["pending"] = true;
                    pending["waitedMs"] = watch.ElapsedMilliseconds;
                    return BridgeEnvelope.Success(pending);
                }
            }
            var delayMs = (int)Math.Min(WaitStepMs, waitMs - watch.ElapsedMilliseconds);
            if (delayMs > 0)
                await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
        }
    }

    internal Task<string> CancelAsync(JsonElement? arguments)
    {
        lock (_gate)
        {
            if (arguments is not { ValueKind: JsonValueKind.Object } ||
                !arguments.Value.TryGetProperty("operationId", out var idElement) ||
                idElement.ValueKind != JsonValueKind.String ||
                string.IsNullOrEmpty(idElement.GetString()))
                return Task.FromResult(BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes."));
            var id = idElement.GetString()!;
            if (!_operations.TryGetValue(id, out var operation))
                return Task.FromResult(BridgeEnvelope.Error("ghidra_operation_not_found", "The Ghidra open operation was not found. Completed operations expire after 5 minutes."));
            if (operation.Result is null)
            {
                operation.State = "cancelling";
                operation.Cancellation.Cancel();
            }
            return Task.FromResult(BridgeEnvelope.Success(Describe(id, operation)));
        }
    }

    internal JsonArray Queue()
    {
        lock (_gate)
            return new JsonArray(_operations.Where(p => p.Value.Result is null).OrderBy(p => p.Value.Sequence)
                .Select(p => (JsonNode?)Describe(p.Key, p.Value)).ToArray());
    }

    /// <summary>
    /// Best-effort operationId attach for the OPEN fast path only: when the
    /// in-budget import already completed, the stored launcher result has no
    /// operationId, breaking callers that parse it for later
    /// GetGhidraOpenStatus/Cancel. Parse-attach-serialize; on any parse
    /// failure return the raw result unchanged. Only attaches when the
    /// ok:true result object lacks operationId; pending and error shapes
    /// pass through untouched.
    /// </summary>
    private static string AttachOperationId(string raw, string id)
    {
        try
        {
            var root = JsonNode.Parse(raw)?.AsObject();
            if (root is null)
                return raw;
            if (root["ok"]?.GetValue<bool>() != true)
                return raw;
            if (root["result"] is not JsonObject result)
                return raw;
            if (result.ContainsKey("operationId"))
                return raw;
            result["operationId"] = id;
            return root.ToJsonString();
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
            return raw;
        }
    }

    /// <summary>
    /// Lazy deadline enforcement for status readers (caller holds
    /// <c>_gate</c>). If the operation is still actively importing past
    /// <see cref="ImportTimeout"/>, it becomes the same terminal
    /// <c>ghidra_import_timeout</c> failure the worker produces, the
    /// underlying import is signalled to abort, and the expiry is recorded
    /// via <c>Completed</c> (telemetry stays with the worker's terminal
    /// record to avoid double counting). User-cancelled
    /// (<c>cancelling</c>) operations are left for the cancel path.
    /// </summary>
    private void ExpireIfImportTimedOutLocked(Operation operation)
    {
        if (operation.Result is not null ||
            !string.Equals(operation.State, "importing", StringComparison.Ordinal) ||
            DateTimeOffset.UtcNow - operation.Created < _importTimeout)
            return;
        try { operation.Cancellation.Cancel(); } catch { }
        operation.State = "failed";
        operation.Result = BuildImportTimeoutError(operation);
        operation.Completed = DateTimeOffset.UtcNow;
    }

    private string BuildImportTimeoutError(Operation operation)
    {
        var seconds = Math.Max(1L, (long)Math.Ceiling(_importTimeout.TotalSeconds));
        return BridgeEnvelope.Error("ghidra_import_timeout",
            $"The Ghidra import of '{System.IO.Path.GetFileName(operation.Path)}' did not complete within {seconds} seconds. " +
            "The target may use an unsupported or raw format that Ghidra cannot import unattended. " +
            "Re-issue OpenGhidraFile with a supported executable format as a new operation; do not poll the timed-out operationId.");
    }

    /// <summary>Capacity-throw detector matching the launcher's pre-spawn
    /// session-table message; keeps session_capacity_reached distinct from a
    /// generic import failure.</summary>
    private static bool IsSessionCapacity(string? message)
        => message is not null &&
            message.Contains("maximum number of parallel analysis sessions", StringComparison.OrdinalIgnoreCase);

    private static TimeSpan ValidateImportTimeout(TimeSpan value)
        => value > TimeSpan.Zero
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value), "The Ghidra import timeout must be positive.");

    internal static TimeSpan ResolveImportTimeout(Func<string, string?>? environment = null)
    {
        try
        {
            environment ??= Environment.GetEnvironmentVariable;
            if (int.TryParse(environment(ImportTimeoutEnvironmentVariable)?.Trim(), out var milliseconds))
                return TimeSpan.FromMilliseconds(Math.Clamp(milliseconds, 60_000, 900_000));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
        }
        return DefaultImportTimeout;
    }

    private JsonObject Describe(string id, Operation operation)
    {
        var queuePosition = operation.State == "queued"
            ? _operations.Values.Count(o => o.Sequence < operation.Sequence && o.Result is null) : 0;
        // Back off deeper queue positions so N queued importers do not poll in
        // lockstep; the head of the queue keeps the historical 1000 ms hint.
        var retryAfterMs = operation.Result is null ? Math.Min(1000 * (1 + queuePosition), 8000) : (int?)null;
        return new JsonObject
        {
            ["status"] = operation.Result is null ? "pending" : operation.State,
            ["phase"] = operation.State, ["operationId"] = id,
            ["fileName"] = System.IO.Path.GetFileName(operation.Path),
            ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - operation.Created).TotalMilliseconds,
            ["queuePosition"] = queuePosition,
            ["progressPercent"] = operation.State switch
            {
                "completed" => JsonValue.Create(100),
                "importing" => JsonValue.Create(50),
                _ => null
            },
            ["etaMs"] = null, ["retryAfterMs"] = retryAfterMs is null ? null : JsonValue.Create(retryAfterMs.Value)
        };
    }
    private void Prune()
    {
        foreach (var pair in _operations.Where(p => p.Value.Completed < DateTimeOffset.UtcNow.AddMinutes(-5)).ToArray())
        {
            _operations.Remove(pair.Key);
            pair.Value.Cancellation.Dispose();
        }
    }

    private static string NormalizeOpenPath(string path)
    {
        try
        {
            var trimmed = (path ?? "").Trim();
            if (trimmed.Length == 0)
                return trimmed;
            return Path.GetFullPath(trimmed);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return (path ?? "").Trim();
        }
    }
    public void Stop()
    {
        lock (_gate) _lifetime.Cancel();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        Operation[] operations;
        lock (_gate)
        {
            try { _lifetime.Cancel(); } catch { }
            operations = _operations.Values.ToArray();
            _operations.Clear();
        }
        foreach (var operation in operations)
        {
            try { operation.Cancellation.Cancel(); } catch { }
            try { operation.Cancellation.Dispose(); } catch { }
        }
        try { _lifetime.Dispose(); } catch { }
        GC.SuppressFinalize(this);
    }
}
