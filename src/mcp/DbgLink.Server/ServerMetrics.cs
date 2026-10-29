using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Diagnostics;

namespace DbgLink.Server
{
internal sealed class ServerMetrics
{
    // Bounded FIFO for activity records: each tool call appends two entries
    // (running + completed/failed), so without a cap an AI-driven debugging
    // session would grow this list without limit (memory leak).
    private const int ActivityHistoryLimit = 128;
    private const int ActiveOperationsLimit = 16;
    private const int PerToolLimit = 64;
    private const int MethodLimit = 32;
    private const int ErrorCodeLimit = 32;
    private const int TopN = 8;
    // Per-function telemetry (w06): bounded selector -> counters map.
    private const int PerFunctionLimit = 256;
    private const int FunctionSelectorMaxLength = 128;
    private const int FunctionSelectorsPerCall = 16;
    private const int FunctionsSnapshotCap = 64;

    // Fixed latency buckets (ms) for p50/p95 estimation without storing samples.
    private static readonly long[] LatencyBuckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000];

    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private long _httpRequests;
    private long _roundTrips;
    private long _toolCalls;
    private long _bytesReceived;
    private long _bytesSent;
    private readonly object _activityLock = new();
    private readonly List<ActivityEntry> _activeOperations = new();
    private ActivityEntry? _lastOperation;
    private readonly List<JsonObject> _activityHistory = new();
    private long _operationId;
    private long _activitySequence;

    // --- Bulk telemetry aggregates (all bounded) ---
    private readonly ConcurrentDictionary<string, long> _mcpMethods = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _httpStatus = new(StringComparer.Ordinal);
    private long _authFailures;
    private long _originRejects;
    private readonly ConcurrentDictionary<string, ToolStats> _tools = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, FunctionStats> _functions = new(StringComparer.Ordinal);
    private readonly BackendStats _native = new();
    private readonly BackendStats _ghidra = new();
    private long _ghidraCacheHits;
    private long _ghidraCacheMisses;
    private long _sessionsRegistered;
    private long _sessionsClosed;
    private long _bridgeReplaced;
    private readonly ConcurrentDictionary<string, long> _sessionCalls = new(StringComparer.Ordinal);
    private const int SessionCallsLimit = 32;
    private long _controlBegun;
    private long _controlCompleted;
    private long _controlFailed;
    private long _controlCancelled;
    private long _controlRejected;
    // Fan-out sub-calls suppressed from backends by top-level attribution
    // (see BeginBackendAttribution): bridge RPCs issued inside a tool flow
    // after the first one (batch items, snapshot sections, enrichment and
    // candidates lookups, autoPause probes, cache-hit replays). Kept as one
    // honest counter so the collapsed volume stays visible in the digest.
    private long _backendFanoutSubCalls;
    // Top-level backend attribution scope (digest coherence). Pinned
    // definition: toolsSummary.totalCalls counts MCP tool completions (one
    // per tools/call, every outcome); backends.{native,ghidra}.calls counts
    // top-level bridge uses — at most ONE per tool execution, the first RPC
    // wins. Backend-free tool calls (validation/queue/session/local-only)
    // add to total without touching backends, hence
    // backends.native.calls + backends.ghidra.calls <= totalCalls.
    // Same AsyncLocal idiom as AnalysisContext: each dispatcher tool flow
    // gets its own attribution, concurrent tools do not interfere, and
    // direct RecordBackendCall use outside a tool flow (unit tests,
    // background probes) keeps counting every call.
    private static readonly AsyncLocal<BackendAttributionState?> _backendAttribution = new();
    private long _httpCurrent;
    private long _httpMax;
    private long _execCurrent;
    private long _execMax;

    internal TelemetryFileSink? FileSink { get; set; }

    public OperationScope BeginTool(string toolName)
    {
        var descriptor = DescribeTool(toolName);
        var safeName = SanitizeToolName(toolName);
        var entry = new ActivityEntry(safeName, descriptor.Target, descriptor.Phase, descriptor.DataFlow);
        lock (_activityLock)
        {
            if (_activeOperations.Count >= ActiveOperationsLimit)
                _activeOperations.RemoveAt(0);
            entry.Id = ++_operationId;
            _activeOperations.Add(entry);
            RecordActivity(entry);
        }
        return new OperationScope(this, entry);
    }

    public void RecordHttpRequest()
        => Interlocked.Increment(ref _httpRequests);

    public void RecordMcpRequest(string? method, long bodyBytes)
    {
        Interlocked.Increment(ref _roundTrips);
        AddBounded(ref _bytesReceived, bodyBytes);
        if (string.Equals(method, "tools/call", StringComparison.Ordinal))
            Interlocked.Increment(ref _toolCalls);
        var key = SanitizeMethod(method ?? "_unknown", 64);
        AddCapped(_mcpMethods, key, MethodLimit);
    }

    public void RecordBytesSent(long bytes)
        => AddBounded(ref _bytesSent, bytes);

    public void RecordHttpStatus(int status)
        => AddCapped(_httpStatus, status.ToString(System.Globalization.CultureInfo.InvariantCulture), 16);

    public void RecordAuthFailure() => Interlocked.Increment(ref _authFailures);
    public void RecordOriginRejected() => Interlocked.Increment(ref _originRejects);

    public void HttpEnter() => EnterGauge(ref _httpCurrent, ref _httpMax);
    public void HttpExit() => DecrementGaugeFloorZero(ref _httpCurrent);
    public void ExecEnter() => EnterGauge(ref _execCurrent, ref _execMax);
    public void ExecExit() => DecrementGaugeFloorZero(ref _execCurrent);

    public void RecordSessionRegistered(string? sessionId = null)
    {
        Interlocked.Increment(ref _sessionsRegistered);
        try
        {
            var session = SanitizeSessionId(sessionId);
            FileSink?.LogEvent(session != "-" ? $"_session registered sess={session}" : "_session registered");
        }
        catch { }
    }
    public void RecordSessionClosed(string? sessionId = null)
    {
        Interlocked.Increment(ref _sessionsClosed);
        try
        {
            var session = SanitizeSessionId(sessionId);
            FileSink?.LogEvent(session != "-" ? $"_session closed sess={session}" : "_session closed");
        }
        catch { }
    }
    public void RecordBridgeReplaced(string? sessionId = null)
    {
        Interlocked.Increment(ref _bridgeReplaced);
        try
        {
            var session = SanitizeSessionId(sessionId);
            FileSink?.LogEvent(session != "-" ? "_session bridge-replaced sess=" + session : "_session bridge-replaced");
        }
        catch { }
    }

    public void RecordControlBegun() => Interlocked.Increment(ref _controlBegun);
    public void RecordControlRejected() => Interlocked.Increment(ref _controlRejected);
    public void RecordControlTerminal(string state, long elapsedMs = 0)
    {
        switch (state)
        {
            case "completed": Interlocked.Increment(ref _controlCompleted); break;
            case "cancelled":
            case "cancelling": Interlocked.Increment(ref _controlCancelled); break;
            default: Interlocked.Increment(ref _controlFailed); break;
        }
        try
        {
            // Lifecycle line (a distinct kind from tool lines, which carry
            // ms/in/out/tok/err/sess/sub): timestamped, sanitized, bounded,
            // with the import lifetime elapsed so failures keep timing. No
            // path/session/secret is logged — the state is a closed
            // vocabulary (completed/failed/cancelled). The OpenGhidraFile
            // tool call itself is logged separately by the dispatcher with
            // the full tool fields.
            var safe = SanitizeErrorCode(state);
            FileSink?.LogEvent($"_open {safe} {Math.Max(0, elapsedMs)}ms lifecycle");
        }
        catch { }
    }

    public void RecordBackendCall(string backend, string method, bool ok, string? errorCode, long elapsedMs, bool cached = false)
    {
        try
        {
            // Top-level attribution: inside a dispatcher tool flow only the
            // first bridge RPC counts toward backends; later RPCs in the
            // same flow are fan-out sub-calls of that one tool call and are
            // tallied separately (see _backendFanoutSubCalls).
            var attribution = _backendAttribution.Value;
            if (attribution is not null && ReferenceEquals(attribution.Owner, this))
            {
                if (Interlocked.Exchange(ref attribution.Counted, 1) != 0)
                {
                    Interlocked.Increment(ref _backendFanoutSubCalls);
                    return;
                }
            }
            var stats = string.Equals(backend, "ghidra", StringComparison.Ordinal) ? _ghidra : _native;
            if (cached)
            {
                if (string.Equals(backend, "ghidra", StringComparison.Ordinal))
                {
                    if (ok) Interlocked.Increment(ref _ghidraCacheHits);
                    else Interlocked.Increment(ref _ghidraCacheMisses);
                }
            }
            else if (string.Equals(backend, "ghidra", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref _ghidraCacheMisses);
            }
            stats.Record(ok, SanitizeMethod(method, 64), SanitizeErrorCode(errorCode), elapsedMs);
        }
        catch { }
    }

    /// <summary>Opens top-level backend attribution for one tool execution
    /// (used by the dispatcher around the tool body): the first
    /// <see cref="RecordBackendCall"/> inside the scope counts toward
    /// backends, later ones are fan-out sub-calls. Restores any outer scope
    /// on dispose; never throws.</summary>
    internal BackendAttributionScope BeginBackendAttribution() => new(this);

    internal sealed class BackendAttributionScope : IDisposable
    {
        private readonly BackendAttributionState? _previous;
        private int _disposed;

        internal BackendAttributionScope(ServerMetrics owner)
        {
            _previous = _backendAttribution.Value;
            _backendAttribution.Value = new BackendAttributionState(owner);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _backendAttribution.Value = _previous;
        }
    }

    private sealed class BackendAttributionState(ServerMetrics owner)
    {
        public ServerMetrics Owner { get; } = owner;
        public int Counted;
    }

    internal void RecordToolResult(string tool, string outcome, long elapsedMs, long requestBytes, long responseBytes, string? errorCode = null, string? sessionId = null, string? detail = null, IReadOnlyList<string>? functions = null, string? requestText = null, string? responseText = null)
    {
        try
        {
            var key = SanitizeToolName(tool);
            if (!_tools.TryGetValue(key, out var stats))
            {
                if (_tools.Count >= PerToolLimit)
                    key = "_other";
                stats = _tools.GetOrAdd(key, static _ => new ToolStats());
            }
            var resolvedCode = ResolveErrorCode(outcome, errorCode);
            // Real cl100k_base BPE count for this call (TokenMeter): BPE
            // where the payload text was plumbed in, 0 for byte-only sides.
            // Computed once and shared by the tool aggregate, per-function
            // attribution and the tok column so one call pays BPE at most
            // once per side.
            var tokens = CountTokens(requestText, responseText, requestBytes, responseBytes);
            stats.Record(outcome, resolvedCode, elapsedMs, requestBytes, responseBytes, tokens);
            var session = SanitizeSessionId(sessionId);
            if (session != "-")
                AddCapped(_sessionCalls, session, SessionCallsLimit);
            try { RecordFunctions(functions, outcome, tokens); } catch { }
            try { FileSink?.LogTool(key, outcome, elapsedMs, requestBytes, responseBytes, tokens, resolvedCode, sessionId, detail); } catch { }
        }
        catch { }
    }

    public JsonObject Snapshot(long after = 0)
    {
        var bytesReceived = Interlocked.Read(ref _bytesReceived);
        var bytesSent = Interlocked.Read(ref _bytesSent);
        var uptimeSeconds = _uptime.Elapsed.TotalSeconds;
        var snapshot = new JsonObject
        {
            ["schemaVersion"] = 2,
            ["startedAtUtc"] = _startedUtc.ToString("O"),
            ["uptimeSeconds"] = Math.Round(uptimeSeconds, 3),
            ["httpRequests"] = Interlocked.Read(ref _httpRequests),
            ["roundTrips"] = Interlocked.Read(ref _roundTrips),
            ["toolCalls"] = Interlocked.Read(ref _toolCalls),
            ["bytesReceived"] = bytesReceived,
            ["bytesSent"] = bytesSent,
            ["receivedMegabytes"] = Math.Round(bytesReceived / (1024d * 1024d), 6),
            ["sentMegabytes"] = Math.Round(bytesSent / (1024d * 1024d), 6),
            ["activeOperations"] = ActiveOperationsJson(),
            ["lastOperation"] = LastOperationJson(),
            ["activityHistory"] = ActivityHistoryJson(after),
            ["mcpMethods"] = CappedDictJson(_mcpMethods),
            ["httpStatus"] = CappedDictJson(_httpStatus),
            ["authFailures"] = Interlocked.Read(ref _authFailures),
            ["originRejects"] = Interlocked.Read(ref _originRejects),
            ["tools"] = ToolsJson(),
            ["toolsSummary"] = ToolsSummaryJson(),
            ["functions"] = FunctionsJson(),
            ["backends"] = BackendsJson(),
            ["queues"] = new JsonObject
            {
                ["httpCurrent"] = Interlocked.Read(ref _httpCurrent),
                ["httpMax"] = Interlocked.Read(ref _httpMax),
                ["executionCurrent"] = Interlocked.Read(ref _execCurrent),
                ["executionMax"] = Interlocked.Read(ref _execMax),
            },
            ["sessions"] = new JsonObject
            {
                ["registeredTotal"] = Interlocked.Read(ref _sessionsRegistered),
                ["closedTotal"] = Interlocked.Read(ref _sessionsClosed),
                ["bridgeReplacedTotal"] = Interlocked.Read(ref _bridgeReplaced),
                ["bySession"] = CappedDictJson(_sessionCalls),
            },
            ["ghidraOpen"] = new JsonObject
            {
                ["begun"] = Interlocked.Read(ref _controlBegun),
                ["completed"] = Interlocked.Read(ref _controlCompleted),
                ["failed"] = Interlocked.Read(ref _controlFailed),
                ["cancelled"] = Interlocked.Read(ref _controlCancelled),
                ["rejected"] = Interlocked.Read(ref _controlRejected),
            },
            ["process"] = ProcessJson(uptimeSeconds),
        };
        return snapshot;
    }

    private void RecordActivity(ActivityEntry entry)
    {
        var item = entry.ToJson(entry.State);
        // Monotonic across ring-buffer trims, so the client cursor (the last
        // seen sequence) keeps working once entries start falling off.
        item["sequence"] = ++_activitySequence;
        item["timestamp"] = DateTimeOffset.UtcNow.ToString("O");
        _activityHistory.Add(item);
        if (_activityHistory.Count > ActivityHistoryLimit)
            _activityHistory.RemoveRange(0, _activityHistory.Count - ActivityHistoryLimit);
    }

    private JsonArray ActivityHistoryJson(long after)
    {
        // `after` is a sequence cursor, not a list index: after a trim the
        // first retained entry no longer sits at position zero.
        lock (_activityLock)
            return new JsonArray(_activityHistory
                .Where(item => (item["sequence"]?.GetValue<long>() ?? 0) > after)
                .Take(16)
                .Select(item => item.DeepClone()).ToArray());
    }

    private JsonArray ActiveOperationsJson()
    {
        lock (_activityLock)
        {
            return new JsonArray(_activeOperations
                .Take(16)
                .Select(entry => entry.ToJson("running"))
                .ToArray());
        }
    }

    private JsonNode? LastOperationJson()
    {
        lock (_activityLock)
            return _lastOperation?.ToJson(_lastOperation.State);
    }

    private void Complete(ActivityEntry entry, bool failed, string? outcome, long requestBytes, long responseBytes, string? errorCode = null, string? sessionId = null, string? detail = null, IReadOnlyList<string>? functions = null, string? requestText = null, string? responseText = null)
    {
        entry.Stopwatch.Stop();
        var elapsedMs = (long)Math.Round(entry.Stopwatch.Elapsed.TotalMilliseconds);
        lock (_activityLock)
        {
            _activeOperations.Remove(entry);
            entry.State = failed ? "failed" : "completed";
            _lastOperation = entry;
            RecordActivity(entry);
        }
        RecordToolResult(entry.Tool, outcome ?? (failed ? "backend_error" : "ok"), elapsedMs, requestBytes, responseBytes, errorCode, sessionId, detail, functions, requestText, responseText);
    }

    private JsonObject FunctionsJson()
    {
        var obj = new JsonObject();
        foreach (var pair in _functions.OrderByDescending(p => p.Value.Tokens).Take(FunctionsSnapshotCap))
        {
            var snap = pair.Value.Snapshot();
            obj[pair.Key] = new JsonObject
            {
                ["calls"] = snap.Calls,
                ["tokens"] = snap.Tokens,
                ["errors"] = snap.Errors,
            };
        }
        return obj;
    }

    /// <summary>Per-function counters (w06): one call attributes its tokens
    /// evenly across its distinct selectors so multi-function calls
    /// (AnalyzeFunctions/BatchAnnotate) divide the shared budget instead of
    /// multiplying it. The total is the call's real BPE token count,
    /// computed once by the caller. Never throws; selectors are
    /// re-sanitized (idempotent).</summary>
    private void RecordFunctions(IReadOnlyList<string>? selectors, string? outcome, long totalTokens)
    {
        try
        {
            if (selectors is null || selectors.Count == 0)
                return;
            var distinct = new List<string>(Math.Min(selectors.Count, FunctionSelectorsPerCall));
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var raw in selectors)
            {
                if (distinct.Count >= FunctionSelectorsPerCall)
                    break;
                var safe = SanitizeFunctionSelector(raw);
                if (safe is null || !seen.Add(safe))
                    continue;
                distinct.Add(safe);
            }
            if (distinct.Count == 0)
                return;
            totalTokens = Math.Max(0, totalTokens);
            var per = totalTokens / distinct.Count;
            var remainder = (int)(totalTokens % distinct.Count);
            var failed = !string.Equals(SanitizeErrorCode(outcome), "ok", StringComparison.Ordinal);
            for (var i = 0; i < distinct.Count; i++)
            {
                var key = distinct[i];
                if (!_functions.TryGetValue(key, out var stats))
                {
                    if (_functions.Count >= PerFunctionLimit)
                        key = "_other";
                    stats = _functions.GetOrAdd(key, static _ => new FunctionStats());
                }
                stats.Record(per + (i < remainder ? 1 : 0), failed);
            }
        }
        catch { }
    }

    /// <summary>Function selector for per-function telemetry (w06): control
    /// chars stripped, trimmed, capped at 128. Null when blank/empty after
    /// sanitizing. Case is preserved (symbols are case-sensitive).</summary>
    internal static string? SanitizeFunctionSelector(string? selector)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(selector))
                return null;
            var safe = new string(selector.Where(c => !char.IsControl(c)).Take(FunctionSelectorMaxLength).ToArray()).Trim();
            return string.IsNullOrEmpty(safe) ? null : safe;
        }
        catch { return null; }
    }

    /// <summary>Extract distinct function selectors from tool arguments (w06).
    /// Covers InspectFunction (.function),
    /// AnalyzeFunctions/GetInvestigationBrief (.functions[] + .start),
    /// BatchAnnotate (.operations[].function) and ProbeFunction (.address,
    /// .function and .probes[] rows). Always sanitized, order-preserving,
    /// capped at 16. Never throws.</summary>
    internal static IReadOnlyList<string> ExtractFunctionSelectors(string? tool, System.Text.Json.JsonElement? arguments)
    {
        try
        {
            if (string.IsNullOrEmpty(tool) || arguments is not { ValueKind: System.Text.Json.JsonValueKind.Object } args)
                return Array.Empty<string>();
            return tool switch
            {
                "InspectFunction" => SingleSelector(ToolSupport.ReadArgumentString(args, "function")),
                "AnalyzeFunctions" => AnalyzeSelectors(args),
                "GetInvestigationBrief" => BriefSelectors(args),
                "BatchAnnotate" or "SubmitAnnotations" => BatchSelectors(args),
                "ProbeFunction" => ProbeSelectors(args),
                _ => Array.Empty<string>(),
            };
        }
        catch { return Array.Empty<string>(); }
    }

    private static IReadOnlyList<string> SingleSelector(string? raw)
    {
        var safe = SanitizeFunctionSelector(raw);
        return safe is null ? Array.Empty<string>() : new[] { safe };
    }

    private static IReadOnlyList<string> AnalyzeSelectors(System.Text.Json.JsonElement args)
    {
        var out_ = new List<string>(9);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string? raw)
        {
            if (out_.Count >= FunctionSelectorsPerCall)
                return;
            var safe = SanitizeFunctionSelector(raw);
            if (safe is null || !seen.Add(safe))
                return;
            out_.Add(safe);
        }
        try
        {
            if (args.TryGetProperty("functions", out var fns) && fns.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var item in fns.EnumerateArray())
                {
                    if (out_.Count >= FunctionSelectorsPerCall)
                        break;
                    if (item.ValueKind != System.Text.Json.JsonValueKind.String)
                        continue;
                    Add(item.GetString());
                }
            }
            Add(ToolSupport.ReadArgumentString(args, "start"));
        }
        catch { }
        return out_;
    }

    private static IReadOnlyList<string> BriefSelectors(System.Text.Json.JsonElement args)
    {
        var batch = AnalyzeSelectors(args);
        return batch.Count > 0 ? batch : SingleSelector(ToolSupport.ReadArgumentString(args, "function"));
    }

    private static IReadOnlyList<string> BatchSelectors(System.Text.Json.JsonElement args)
    {
        var out_ = new List<string>(FunctionSelectorsPerCall);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            if (!args.TryGetProperty("operations", out var ops) || ops.ValueKind != System.Text.Json.JsonValueKind.Array)
                return out_;
            foreach (var op in ops.EnumerateArray())
            {
                if (out_.Count >= FunctionSelectorsPerCall)
                    break;
                if (op.ValueKind != System.Text.Json.JsonValueKind.Object)
                    continue;
                var fn = ToolSupport.ReadArgumentString(op, "function");
                var safe = SanitizeFunctionSelector(fn);
                if (safe is null || !seen.Add(safe))
                    continue;
                out_.Add(safe);
            }
        }
        catch { }
        return out_;
    }

    private static IReadOnlyList<string> ProbeSelectors(System.Text.Json.JsonElement args)
    {
        var out_ = new List<string>(FunctionSelectorsPerCall);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void AddRow(System.Text.Json.JsonElement row)
        {
            if (out_.Count >= FunctionSelectorsPerCall || row.ValueKind != System.Text.Json.JsonValueKind.Object)
                return;
            foreach (var key in new[] { "function", "address" })
            {
                var safe = SanitizeFunctionSelector(ToolSupport.ReadArgumentString(row, key));
                if (safe is not null && seen.Add(safe))
                {
                    out_.Add(safe);
                    return;
                }
            }
        }
        try
        {
            AddRow(args);
            if (args.TryGetProperty("probes", out var probes) && probes.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var probe in probes.EnumerateArray())
                    AddRow(probe);
        }
        catch { }
        return out_;
    }

    private JsonObject ToolsJson()
    {
        var obj = new JsonObject();
        foreach (var pair in _tools.OrderBy(p => p.Key).Take(PerToolLimit))
            obj[pair.Key] = pair.Value.ToJson();
        return obj;
    }

    private JsonObject ToolsSummaryJson()
    {
        long totalCalls = 0, totalOk = 0;
        var rows = new List<(string Tool, ToolStats Stats)>();
        foreach (var pair in _tools)
        {
            totalCalls += pair.Value.Calls;
            totalOk += pair.Value.Ok;
            rows.Add((pair.Key, pair.Value));
        }
        var summary = new JsonObject
        {
            ["totalCalls"] = totalCalls,
            ["totalOk"] = totalOk,
            ["totalError"] = Math.Max(0, totalCalls - totalOk),
            ["trackedTools"] = rows.Count,
        };
        try
        {
            var slowest = rows.OrderByDescending(r => r.Stats.P95Ms()).Take(TopN)
                .Select(r => (JsonNode)new JsonObject
                {
                    ["tool"] = r.Tool, ["calls"] = r.Stats.Calls,
                    ["avgMs"] = r.Stats.AvgMs(), ["p95Ms"] = r.Stats.P95Ms(), ["maxMs"] = r.Stats.MaxMs,
                }).ToArray();
            var largest = rows.OrderByDescending(r => r.Stats.AvgBytesOut()).Take(TopN)
                .Select(r => (JsonNode)new JsonObject
                {
                    ["tool"] = r.Tool, ["calls"] = r.Stats.Calls,
                    ["avgBytesOut"] = r.Stats.AvgBytesOut(), ["maxBytesOut"] = r.Stats.MaxBytesOut,
                }).ToArray();
            var largestTotal = rows.OrderByDescending(r => r.Stats.Totals().BytesOut).Take(TopN)
                .Select(r =>
                {
                    var totals = r.Stats.Totals();
                    return (JsonNode)new JsonObject
                    {
                        ["tool"] = r.Tool, ["calls"] = totals.Calls,
                        ["totalBytesOut"] = totals.BytesOut, ["totalBytesIn"] = totals.BytesIn,
                        ["totalTokens"] = totals.Tokens,
                    };
                }).ToArray();
            var errors = rows.Select(r => (r.Tool, r.Stats, Errors: r.Stats.Calls - r.Stats.Ok))
                .Where(r => r.Errors > 0).OrderByDescending(r => r.Errors).Take(TopN)
                .Select(r =>
                {
                    var top = r.Stats.TopErrorCode();
                    return (JsonNode)new JsonObject
                    {
                        ["tool"] = r.Tool, ["calls"] = r.Stats.Calls, ["errors"] = r.Errors,
                        ["errorRate"] = r.Stats.Calls == 0 ? 0 : Math.Round((double)r.Errors / r.Stats.Calls, 4),
                        ["topErrorCode"] = top.Code, ["topErrorCodeCount"] = top.Count,
                        ["errorsByCode"] = r.Stats.ErrorsByCodeJson(),
                        ["timeout"] = r.Stats.Timeout, ["queueFull"] = r.Stats.QueueFull,
                        ["validationError"] = r.Stats.ValidationError,
                        ["badSession"] = r.Stats.BadSession,
                        ["cancelled"] = r.Stats.Cancelled,
                        ["backendError"] = r.Stats.BackendError,
                        ["exception"] = r.Stats.Exception,
                        ["protocolError"] = r.Stats.ProtocolError,
                        ["disabledOrUnknown"] = r.Stats.DisabledOrUnknown,
                    };
                }).ToArray();
            summary["topSlowest"] = new JsonArray(slowest);
            summary["topLargest"] = new JsonArray(largest);
            summary["topLargestTotal"] = new JsonArray(largestTotal);
            summary["topErrors"] = new JsonArray(errors);
        }
        catch { }
        return summary;
    }

    private JsonObject BackendsJson()
    {
        return new JsonObject
        {
            ["native"] = _native.ToJson(),
            ["ghidra"] = new JsonObject
            {
                ["calls"] = _ghidra.Calls,
                ["ok"] = _ghidra.Ok,
                ["fail"] = Math.Max(0, _ghidra.Calls - _ghidra.Ok),
                ["avgMs"] = _ghidra.AvgMs(),
                ["maxMs"] = _ghidra.MaxMs,
                ["cacheHits"] = Interlocked.Read(ref _ghidraCacheHits),
                ["cacheMisses"] = Interlocked.Read(ref _ghidraCacheMisses),
                ["errors"] = _ghidra.ErrorsJson(),
            },
            // Fan-out sub-calls collapsed by top-level attribution (batch
            // items, snapshot sections, enrichment/candidates lookups,
            // autoPause probes): attributed to their wrapper tool call, not
            // counted in native/ghidra calls above.
            ["fanoutSubCalls"] = Interlocked.Read(ref _backendFanoutSubCalls),
        };
    }

    private static JsonObject ProcessJson(double uptimeSeconds)
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var workingSetMb = Math.Round(process.WorkingSet64 / (1024d * 1024d), 2);
            var gcMb = Math.Round(GC.GetTotalMemory(false) / (1024d * 1024d), 2);
            ThreadPool.GetAvailableThreads(out var workers, out var ports);
            return new JsonObject
            {
                ["workingSetMb"] = workingSetMb,
                ["gcHeapMb"] = gcMb,
                ["threadPoolWorkersAvailable"] = workers,
                ["threadPoolPortsAvailable"] = ports,
                ["gcGen0"] = GC.CollectionCount(0),
                ["gcGen1"] = GC.CollectionCount(1),
                ["gcGen2"] = GC.CollectionCount(2),
            };
        }
        catch
        {
            return new JsonObject();
        }
    }

    private static JsonObject CappedDictJson(ConcurrentDictionary<string, long> dict)
    {
        var obj = new JsonObject();
        foreach (var pair in dict.OrderByDescending(p => p.Value).Take(32))
            obj[pair.Key] = pair.Value;
        return obj;
    }

    private static (string Target, string Phase, string DataFlow) DescribeTool(string toolName)
        => toolName switch
        {
            "OpenGhidraFile" => ("Ghidra file import", "validate → import → open", "MCP → launcher control pipe → isolated Ghidra"),
            "InspectFunction" or "DecompileModule" or "BatchAnnotate" or "Xrefs" or "ListSymbols" =>
                ("Ghidra static program", "static analysis", "MCP → Ghidra loopback bridge"),
            "GetAnalysisSnapshot" or "GetInvestigationBrief" or "MapStaticFunctionToLive" =>
                ("static + dynamic evidence", "orchestrated analysis", "MCP → Ghidra + x64dbg native bridge"),
            _ => ("x64dbg dynamic session", "native analysis", "MCP → x64dbg native bridge")
        };

    internal static string SanitizeToolName(string toolName)
        => new string(toolName.Where(character => !char.IsControl(character)).Take(128).ToArray()) is { Length: > 0 } safe
            ? safe : "_unknown";

    internal static string SanitizeMethod(string? method, int maxLength)
    {
        if (string.IsNullOrEmpty(method)) return "_unknown";
        var safe = new string(method.Where(c => !char.IsControl(c)).Take(Math.Clamp(maxLength, 8, 128)).ToArray());
        return string.IsNullOrEmpty(safe) ? "_unknown" : safe;
    }

    internal static string SanitizeErrorCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return "unknown";
        var lowered = code.Trim().ToLowerInvariant();
        var safe = new string(lowered.Where(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.').Take(64).ToArray());
        return string.IsNullOrEmpty(safe) ? "unknown" : safe;
    }

    /// <summary>
    /// Clear error name for telemetry: prefer the backend error code, fall back
    /// to the outcome (e.g. timeout, validation_error) so the telemetry log always
    /// carries err= for failures. Returns null for ok with no code.
    /// </summary>
    internal static string? ResolveErrorCode(string? outcome, string? errorCode)
    {
        var safeOutcome = SanitizeErrorCode(outcome);
        if (!string.IsNullOrWhiteSpace(errorCode))
        {
            var code = SanitizeErrorCode(errorCode);
            // "unknown" means the backend gave no code: fall back to outcome.
            if (!string.Equals(code, "unknown", StringComparison.Ordinal))
                return code;
        }
        if (string.Equals(safeOutcome, "ok", StringComparison.Ordinal))
            return null;
        return safeOutcome;
    }

    /// <summary>
    /// Real cl100k_base BPE token count for one tool call (TokenMeter): BPE
    /// where the actual request/response text is available, 0 for sides
    /// without text. Never throws; safe on concurrent request paths.
    /// </summary>
    internal static long CountTokens(string? requestText, string? responseText, long requestBytes, long responseBytes)
        => TokenMeter.CountCall(requestText, responseText, requestBytes, responseBytes);

    /// <summary>Display-safe session id for telemetry. Valid ids (the shared
    /// <see cref="AnalysisSessionRegistry.IsValidAnalysisId"/> policy) pass
    /// through capped at 36 chars; anything else reads as "-".</summary>
    internal static string SanitizeSessionId(string? sessionId)
    {
        if (sessionId is null || !AnalysisSessionRegistry.IsValidAnalysisId(sessionId))
            return "-";
        return sessionId.Length <= 36 ? sessionId : sessionId.Substring(0, 36);
    }

    internal static string SanitizeBatchDetail(string? detail)
    {
        if (string.IsNullOrWhiteSpace(detail)) return "";
        return new string(detail.Trim().Where(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or '+' or 'x' or '*').Take(128).ToArray());
    }

    private static void AddCapped(ConcurrentDictionary<string, long> dict, string key, int limit)
    {
        while (true)
        {
            if (dict.TryGetValue(key, out var current))
            {
                if (dict.TryUpdate(key, current == long.MaxValue ? current : current + 1, current))
                    return;
                continue;
            }
            if (dict.Count >= limit)
            {
                key = "_other";
                if (dict.TryGetValue(key, out var other))
                {
                    if (dict.TryUpdate(key, other == long.MaxValue ? other : other + 1, other))
                        return;
                    continue;
                }
                if (dict.TryAdd(key, 1))
                    return;
                continue;
            }
            if (dict.TryAdd(key, 1))
                return;
        }
    }

    private static void EnterGauge(ref long current, ref long max)
    {
        var next = Interlocked.Increment(ref current);
        while (true)
        {
            var observed = Interlocked.Read(ref max);
            if (next <= observed) return;
            if (Interlocked.CompareExchange(ref max, next, observed) == observed)
                return;
        }
    }

    /// <summary>Stray exits (e.g. double-release on an error path) must not
    /// drive concurrency gauges negative and corrupt the queues snapshot.</summary>
    private static void DecrementGaugeFloorZero(ref long current)
    {
        while (true)
        {
            var observed = Interlocked.Read(ref current);
            if (observed <= 0) return;
            if (Interlocked.CompareExchange(ref current, observed - 1, observed) == observed)
                return;
        }
    }

    internal sealed class OperationScope : IDisposable
    {
        private readonly ServerMetrics _owner;
        private readonly ActivityEntry _entry;
        private int _disposed;

        internal OperationScope(ServerMetrics owner, ActivityEntry entry)
        {
            _owner = owner;
            _entry = entry;
        }

        public void Complete(bool failed = false)
            => Complete(failed, null, 0, 0);

        public void Complete(bool failed, string? outcome, long requestBytes = 0, long responseBytes = 0, string? errorCode = null, string? sessionId = null, string? detail = null, IReadOnlyList<string>? functions = null, string? requestText = null, string? responseText = null)
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _owner.Complete(_entry, failed, outcome, requestBytes, responseBytes, errorCode, sessionId, detail, functions, requestText, responseText);
        }

        public void Dispose() => Complete(failed: true, outcome: "exception");
    }

    internal sealed class ActivityEntry
    {
        public ActivityEntry(string tool, string target, string phase, string dataFlow)
        {
            Tool = tool;
            Target = target;
            Phase = phase;
            DataFlow = dataFlow;
        }

        public long Id { get; set; }
        public string Tool { get; }
        public string Target { get; }
        public string Phase { get; }
        public string DataFlow { get; }
        public string State { get; set; } = "running";
        public Stopwatch Stopwatch { get; } = Stopwatch.StartNew();

        public JsonObject ToJson(string state)
            => new()
            {
                ["operationId"] = Id,
                ["tool"] = Tool,
                ["target"] = Target,
                ["phase"] = Phase,
                ["dataFlow"] = DataFlow,
                ["state"] = state,
                ["elapsedMilliseconds"] = Math.Round(Stopwatch.Elapsed.TotalMilliseconds, 3)
            };
    }

    private sealed class ToolStats
    {
        private const int ErrorCodeCap = 16;
        private readonly object _lock = new();
        private readonly long[] _buckets = new long[LatencyBuckets.Length];
        private readonly Dictionary<string, long> _errorCodes = new(StringComparer.Ordinal);
        public long Calls;
        public long Ok;
        public long ValidationError;
        public long QueueFull;
        public long Timeout;
        public long Exception;
        public long Cancelled;
        public long BadSession;
        public long DisabledOrUnknown;
        public long BackendError;
        public long ProtocolError;
        private long _totalMs;
        public long MaxMs;
        private long _totalBytesOut;
        public long MaxBytesOut;
        private long _totalBytesIn;
        public long MaxBytesIn;
        // Real BPE tokens accumulated per call (0 for byte-only sides
        // without payload text). Unlike bytes this is never recomputed from
        // totals, so /metrics totalTokens and the digest big-total lines
        // report what was actually counted.
        private long _totalTokens;

        public void Record(string outcome, string? errorCode, long elapsedMs, long requestBytes, long responseBytes, long tokens)
        {
            elapsedMs = Math.Max(0, elapsedMs);
            requestBytes = Math.Max(0, requestBytes);
            responseBytes = Math.Max(0, responseBytes);
            tokens = Math.Max(0, tokens);
            var normalizedOutcome = SanitizeErrorCode(outcome);
            var normalizedCode = ResolveErrorCode(outcome, errorCode);
            lock (_lock)
            {
                Calls = Calls == long.MaxValue ? Calls : Calls + 1;
                switch (normalizedOutcome)
                {
                    case "ok": IncrementSaturating(ref Ok); break;
                    case "validation_error": IncrementSaturating(ref ValidationError); break;
                    case "queue_full": IncrementSaturating(ref QueueFull); break;
                    case "timeout": IncrementSaturating(ref Timeout); break;
                    case "exception": IncrementSaturating(ref Exception); break;
                    case "cancelled": IncrementSaturating(ref Cancelled); break;
                    case "bad_session":
                    case "bad_analysis_id": IncrementSaturating(ref BadSession); break;
                    case "unknown_tool":
                    case "disabled": IncrementSaturating(ref DisabledOrUnknown); break;
                    case "protocol_error": IncrementSaturating(ref ProtocolError); break;
                    default: IncrementSaturating(ref BackendError); break;
                }
                if (normalizedCode is not null)
                {
                    if (_errorCodes.TryGetValue(normalizedCode, out var count))
                        _errorCodes[normalizedCode] = count == long.MaxValue ? count : count + 1;
                    else if (_errorCodes.Count < ErrorCodeCap)
                        _errorCodes[normalizedCode] = 1;
                    else
                    {
                        if (_errorCodes.TryGetValue("_other", out var other))
                            _errorCodes["_other"] = other == long.MaxValue ? other : other + 1;
                        else
                            _errorCodes["_other"] = 1;
                    }
                }
                _totalMs = _totalMs > long.MaxValue - elapsedMs ? long.MaxValue : _totalMs + elapsedMs;
                if (elapsedMs > MaxMs) MaxMs = elapsedMs;
                for (var i = 0; i < LatencyBuckets.Length; i++)
                {
                    if (elapsedMs <= LatencyBuckets[i]) { _buckets[i]++; break; }
                    if (i == LatencyBuckets.Length - 1) _buckets[i]++;
                }
                _totalBytesOut = _totalBytesOut > long.MaxValue - responseBytes ? long.MaxValue : _totalBytesOut + responseBytes;
                if (responseBytes > MaxBytesOut) MaxBytesOut = responseBytes;
                _totalBytesIn = _totalBytesIn > long.MaxValue - requestBytes ? long.MaxValue : _totalBytesIn + requestBytes;
                if (requestBytes > MaxBytesIn) MaxBytesIn = requestBytes;
                _totalTokens = _totalTokens > long.MaxValue - tokens ? long.MaxValue : _totalTokens + tokens;
            }
        }

        public double AvgMs() => Calls == 0 ? 0 : Math.Round((double)_totalMs / Calls, 2);
        public double AvgBytesOut() => Calls == 0 ? 0 : Math.Round((double)_totalBytesOut / Calls, 1);

        // Outcome counters saturate like Calls: a wrapped counter would
        // corrupt error-rate math (Calls - Ok) in ToolsSummaryJson.
        private static void IncrementSaturating(ref long counter)
        {
            if (counter < long.MaxValue) counter++;
        }

        public long P50Ms() => Quantile(0.5);
        public long P95Ms() => Quantile(0.95);

        private long Quantile(double q)
        {
            if (Calls == 0) return 0;
            var target = (long)Math.Ceiling(Calls * q);
            long cumulative = 0;
            for (var i = 0; i < _buckets.Length; i++)
            {
                cumulative += _buckets[i];
                if (cumulative >= target) return LatencyBuckets[i];
            }
            return LatencyBuckets[^1];
        }

        public JsonObject ToJson()
        {
            lock (_lock)
            {
                var top = TopErrorCodeLocked();
                return new JsonObject
                {
                    ["calls"] = Calls,
                    ["ok"] = Ok,
                    ["errors"] = Math.Max(0, Calls - Ok),
                    ["backendError"] = BackendError,
                    ["validationError"] = ValidationError,
                    ["queueFull"] = QueueFull,
                    ["timeout"] = Timeout,
                    ["exception"] = Exception,
                    ["cancelled"] = Cancelled,
                    ["badSession"] = BadSession,
                    ["disabledOrUnknown"] = DisabledOrUnknown,
                    ["protocolError"] = ProtocolError,
                    ["topErrorCode"] = top.Code,
                    ["topErrorCodeCount"] = top.Count,
                    ["errorsByCode"] = ErrorsByCodeLocked(),
                    ["avgMs"] = AvgMs(),
                    ["maxMs"] = MaxMs,
                    ["p50Ms"] = P50Ms(),
                    ["p95Ms"] = P95Ms(),
                    ["avgBytesOut"] = AvgBytesOut(),
                    ["maxBytesOut"] = MaxBytesOut,
                    ["totalBytesOut"] = _totalBytesOut,
                    ["totalBytesIn"] = _totalBytesIn,
                    ["totalTokens"] = _totalTokens,
                    ["avgBytesIn"] = Calls == 0 ? 0 : Math.Round((double)_totalBytesIn / Calls, 1),
                    ["maxBytesIn"] = MaxBytesIn,
                };
            }
        }

        public (string Code, long Count) TopErrorCode()
        {
            lock (_lock)
                return TopErrorCodeLocked();
        }

        public JsonObject ErrorsByCodeJson()
        {
            lock (_lock)
                return ErrorsByCodeLocked();
        }

        private (string Code, long Count) TopErrorCodeLocked()
        {
            var top = _errorCodes.OrderByDescending(p => p.Value).FirstOrDefault();
            return top.Key is null ? ("-", 0) : (top.Key, top.Value);
        }

        private JsonObject ErrorsByCodeLocked()
        {
            var obj = new JsonObject();
            foreach (var pair in _errorCodes.OrderByDescending(p => p.Value).Take(8))
                obj[pair.Key] = pair.Value;
            return obj;
        }

        public (long Calls, long Ok, long BytesIn, long BytesOut, long Tokens) Totals()
        {
            lock (_lock)
                return (Calls, Ok, _totalBytesIn, _totalBytesOut, _totalTokens);
        }
    }

    /// <summary>Per-function counters (w06): calls, attributed tokens, errors.
    /// All counters saturate instead of wrapping.</summary>
    private sealed class FunctionStats
    {
        private readonly object _lock = new();
        public long Calls;
        public long Tokens;
        public long Errors;

        public void Record(long tokens, bool isError)
        {
            tokens = Math.Max(0, tokens);
            lock (_lock)
            {
                if (Calls < long.MaxValue) Calls++;
                Tokens = Tokens > long.MaxValue - tokens ? long.MaxValue : Tokens + tokens;
                if (isError && Errors < long.MaxValue) Errors++;
            }
        }

        public (long Calls, long Tokens, long Errors) Snapshot()
        {
            lock (_lock)
                return (Calls, Tokens, Errors);
        }
    }

    private sealed class BackendStats
    {
        private readonly object _lock = new();
        private readonly ConcurrentDictionary<string, long> _errors = new(StringComparer.Ordinal);
        public long Calls;
        public long Ok;
        private long _totalMs;
        public long MaxMs;

        public void Record(bool ok, string method, string errorCode, long elapsedMs)
        {
            elapsedMs = Math.Max(0, elapsedMs);
            Interlocked.Increment(ref Calls);
            if (ok) Interlocked.Increment(ref Ok);
            else AddCapped(_errors, errorCode, ErrorCodeLimit);
            while (true)
            {
                var current = Interlocked.Read(ref _totalMs);
                var next = elapsedMs > long.MaxValue - current ? long.MaxValue : current + elapsedMs;
                if (Interlocked.CompareExchange(ref _totalMs, next, current) == current) break;
            }
            while (true)
            {
                var observed = Interlocked.Read(ref MaxMs);
                if (elapsedMs <= observed) break;
                if (Interlocked.CompareExchange(ref MaxMs, elapsedMs, observed) == observed) break;
            }
        }

        public double AvgMs()
        {
            var calls = Interlocked.Read(ref Calls);
            return calls == 0 ? 0 : Math.Round((double)Interlocked.Read(ref _totalMs) / calls, 2);
        }

        public JsonObject ToJson()
            => new()
            {
                ["calls"] = Interlocked.Read(ref Calls),
                ["ok"] = Interlocked.Read(ref Ok),
                ["fail"] = Math.Max(0, Interlocked.Read(ref Calls) - Interlocked.Read(ref Ok)),
                ["avgMs"] = AvgMs(),
                ["maxMs"] = Interlocked.Read(ref MaxMs),
                ["errors"] = ErrorsJson(),
            };

        public JsonObject ErrorsJson()
        {
            var obj = new JsonObject();
            foreach (var pair in _errors.OrderByDescending(p => p.Value).Take(16))
                obj[pair.Key] = pair.Value;
            return obj;
        }
    }

    private static void AddBounded(ref long target, long value)
    {
        if (value <= 0)
            return;

        while (true)
        {
            var current = Interlocked.Read(ref target);
            var next = value > long.MaxValue - current ? long.MaxValue : current + value;
            if (Interlocked.CompareExchange(ref target, next, current) == current)
                return;
        }
    }
} // end ServerMetrics
} // end namespace DbgLink.Server
