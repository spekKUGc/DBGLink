using System.Collections.Concurrent;
using System.Text.Json;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed record AnalysisSessionDescriptor(
    string AnalysisId,
    string NativePipeName,
    string GhidraEndpointDirectory,
    string? NativePipeToken = null);

internal sealed record AnalysisSessionRuntime(
    string AnalysisId,
    IBridgeClient Bridge,
    IGhidraClient Ghidra,
    string NativePipeName,
    string GhidraEndpointDirectory,
    string? NativePipeToken = null)
{
    public bool OwnsBridge { get; init; }
    public bool OwnsGhidra { get; init; }
}

internal sealed class AnalysisSessionRegistry : IDisposable
{
    private readonly ConcurrentDictionary<string, AnalysisSessionRuntime> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AsyncReaderWriterGate> _gates = new(StringComparer.Ordinal);
    // Per-session read/write gate (see AsyncReaderWriterGate). Several
    // read-only tools may hold the same session at once; mutations, session
    // registration and lifecycle operations take it exclusively.
    public AsyncReaderWriterGate GetGate(string id) => _gates.GetOrAdd(id, _ => new AsyncReaderWriterGate());
    public AnalysisSessionRuntime? Find(string id) => _sessions.GetValueOrDefault(id);
    public int ActiveCount => _sessions.Count;
    internal int GateCount => _gates.Count;
    internal int ClosedCount { get { lock (_lifecycleLock) return _closed.Count; } }
    public IReadOnlyList<string> ActiveIds => _sessions.Keys.OrderBy(key => key, StringComparer.Ordinal).Take(16).ToList();
    internal ServerMetrics? Telemetry { get; set; }
    private readonly object _lifecycleLock = new();
    private int _disposed;
    private string _activeAnalysisId = "default";
    public string ActiveAnalysisId => Volatile.Read(ref _activeAnalysisId);
    private const int MaxClosedIds = 256;
    private readonly HashSet<string> _closed = new(StringComparer.Ordinal);
    private readonly Queue<string> _closedOrder = new();

    public bool IsClosed(string? id)
    {
        lock (_lifecycleLock) return id is not null && _closed.Contains(id);
    }

    /// <summary>
    /// Remember a closed id for the short "already closed" path, but keep the
    /// set bounded: a client can invent unlimited valid-looking ids.
    /// </summary>
    private void RememberClosed(string id)
    {
        if (id == "default" || !_closed.Add(id))
            return;
        _closedOrder.Enqueue(id);
        while (_closedOrder.Count > MaxClosedIds)
            _closed.Remove(_closedOrder.Dequeue());
    }

    // Called under the session's Gate, so no tool can still be using the old bridge.
    public void ReplaceBridge(string id, string pipe, string? pipeToken = null)
    {
        var barePipe = NativePipeNamePolicy.Normalize(pipe);
        var token = NormalizePipeToken(pipeToken);
        if (!IsValidPipeName(barePipe)) throw new InvalidOperationException("Invalid debugger pipe returned by launcher.");
        if (token is not null && !BridgeClient.IsValidPipeToken(token))
            throw new InvalidOperationException("Invalid debugger pipe token returned by launcher.");
        lock (_lifecycleLock)
        {
            var old = Resolve(id);
            if (old.NativePipeName == barePipe && string.Equals(old.NativePipeToken, token, StringComparison.Ordinal)) return;
            var replacement = new BridgeClient(barePipe!, token, requirePipeToken: token is not null);
            var telemetry = Telemetry;
            if (telemetry is not null && replacement is BridgeClient concrete)
                concrete.Telemetry = telemetry;
            _sessions[id] = old with { Bridge = replacement, NativePipeName = barePipe!, NativePipeToken = token, OwnsBridge = true };
            if (old.OwnsBridge && old.Bridge is IDisposable disposable) disposable.Dispose();
        }
        Telemetry?.RecordBridgeReplaced(id);
    }

    public void Close(string id)
    {
        var removed = false;
        lock (_lifecycleLock)
        {
            if (!_sessions.TryGetValue(id, out var old))
            {
                RememberClosed(id);
                return;
            }
            RememberClosed(id);
            if (id == "default")
                _sessions[id] = old with { Bridge = new ClosedDebuggerClient(), NativePipeName = "", OwnsBridge = false };
            else
            {
                _sessions.TryRemove(id, out _);
                removed = true;
                // The per-session gate is NOT removed here: in-flight holders
                // still own it, and a late GetGate(id) must see the SAME gate.
                // Dropping it here would let a new writer run concurrently
                // with an old holder. Idle gates are pruned below instead.
            }
            if (_activeAnalysisId == id) Volatile.Write(ref _activeAnalysisId, "default");
            if (old.OwnsBridge && old.Bridge is IDisposable disposable) disposable.Dispose();
            if (old.OwnsGhidra && old.Ghidra is IDisposable ghidraDisposable) ghidraDisposable.Dispose();
        }
        if (removed)
        {
            PruneIdleGates();
            Telemetry?.RecordSessionClosed(id);
        }
    }

    /// <summary>
    /// Removes and disposes the gates of sessions that no longer exist, but
    /// only once they are idle (no holder, no waiter). A gate with a live
    /// holder stays until the last holder leaves, so the exclusivity of that
    /// session is never silently lost.
    /// </summary>
    private void PruneIdleGates()
    {
        List<string>? stale = null;
        foreach (var pair in _gates)
        {
            if (_sessions.ContainsKey(pair.Key))
                continue;
            if (!pair.Value.IsIdle)
                continue;
            (stale ??= new List<string>()).Add(pair.Key);
        }
        if (stale is null)
            return;
        foreach (var id in stale)
        {
            if (_gates.TryRemove(id, out var gate))
            {
                try { gate.Dispose(); } catch { }
            }
        }
    }

    public AnalysisSessionRegistry(IBridgeClient defaultBridge, IGhidraClient defaultGhidra)
    {
        _sessions["default"] = new AnalysisSessionRuntime(
            "default",
            defaultBridge,
            defaultGhidra,
            "",
            "");
    }

    public AnalysisSessionRuntime Resolve(string? analysisId)
    {
        var key = string.IsNullOrWhiteSpace(analysisId) ? Volatile.Read(ref _activeAnalysisId) : analysisId.Trim();
        if (!_sessions.TryGetValue(key, out var session))
            throw new AnalysisSessionNotFoundException(key);
        return session;
    }

    /// <summary>
    /// Resolve a session id, tolerating exactly one failure mode: an id that
    /// died (replaced/closed by a previous call) while one other session is
    /// live. Falling back keeps read-only tools working across a session
    /// restart instead of failing every later call; zero or several live
    /// sessions stay a hard error so an ambiguous request is never answered
    /// against the wrong target. Mutating/annotation callers must NOT use
    /// this: the dispatcher scopes the fallback to read-only tools only, so
    /// a bogus id on a mutating tool fails closed via Resolve instead of
    /// silently retargeting the live session.
    /// </summary>
    public bool TryResolveWithFallback(string? analysisId, out AnalysisSessionRuntime? session, out string? note)
    {
        session = null;
        note = null;
        var key = string.IsNullOrWhiteSpace(analysisId) ? Volatile.Read(ref _activeAnalysisId) : analysisId.Trim();
        if (_sessions.TryGetValue(key, out var exact))
        {
            session = exact;
            return true;
        }

        var live = _sessions.Keys.Where(id => id != "default").OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (live.Count != 1 || !_sessions.TryGetValue(live[0], out var sole))
            return false;
        session = sole;
        note = $"Unknown session '{key}'; using '{sole.AnalysisId}'.";
        return true;
    }

    public bool TryRegister(AnalysisSessionDescriptor descriptor)
    {
        var barePipe = NativePipeNamePolicy.Normalize(descriptor?.NativePipeName);
        var pipeToken = NormalizePipeToken(descriptor?.NativePipeToken);
        if (descriptor is null ||
            !IsValidAnalysisId(descriptor.AnalysisId) ||
            !IsValidPipeName(barePipe) ||
            (pipeToken is not null && !BridgeClient.IsValidPipeToken(pipeToken)) ||
            !IsValidEndpointDirectory(descriptor.GhidraEndpointDirectory))
            return false;

        try
        {
            var bridge = new BridgeClient(barePipe!, pipeToken, requirePipeToken: pipeToken is not null);
            var telemetry = Telemetry;
            if (telemetry is not null)
                bridge.Telemetry = telemetry;
            var ghidra = new GhidraClient(descriptor.GhidraEndpointDirectory);
            if (telemetry is not null)
                ghidra.Telemetry = telemetry;
            var runtime = new AnalysisSessionRuntime(
                descriptor.AnalysisId,
                bridge,
                ghidra,
                barePipe!,
                descriptor.GhidraEndpointDirectory,
                pipeToken) { OwnsBridge = true, OwnsGhidra = true };
            lock (_lifecycleLock)
            {
                if (Volatile.Read(ref _disposed) != 0 || _closed.Contains(descriptor.AnalysisId))
                {
                    bridge.Dispose();
                    try { ghidra.Dispose(); } catch { }
                    return false;
                }

                if (_sessions.TryAdd(descriptor.AnalysisId, runtime))
                {
                    Volatile.Write(ref _activeAnalysisId, descriptor.AnalysisId);
                    telemetry?.RecordSessionRegistered(descriptor.AnalysisId);
                    return true;
                }
            }

            bridge.Dispose();
            try { ghidra.Dispose(); } catch { }
            var idempotent = _sessions.TryGetValue(descriptor.AnalysisId, out var existing) &&
                string.Equals(existing.NativePipeName, barePipe, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(existing.NativePipeToken, pipeToken, StringComparison.Ordinal) &&
                string.Equals(existing.GhidraEndpointDirectory, descriptor.GhidraEndpointDirectory, StringComparison.OrdinalIgnoreCase);
            return idempotent;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        AnalysisSessionRuntime[] sessions;
        AsyncReaderWriterGate[] gates;
        lock (_lifecycleLock)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            sessions = _sessions
                .Where(pair => pair.Value.OwnsBridge || pair.Value.OwnsGhidra)
                .Select(pair => pair.Value)
                .ToArray();
            _sessions.Clear();
            gates = _gates.Values.ToArray();
            _gates.Clear();
        }

        foreach (var session in sessions)
        {
            if (session.OwnsBridge && session.Bridge is IDisposable disposable)
                try { disposable.Dispose(); } catch { }
            if (session.OwnsGhidra && session.Ghidra is IDisposable ghidraDisposable)
                try { ghidraDisposable.Dispose(); } catch { }
        }

        // The gates are owned by this table alone (AnalysisSessionRuntime no
        // longer carries its own copy), so every gate is disposed exactly once.
        foreach (var gate in gates)
        {
            try { gate.Dispose(); } catch { }
        }

        GC.SuppressFinalize(this);
    }

    internal static IReadOnlyCollection<string> ReservedDosNames => LocalPathPolicy.ReservedDeviceNames;

    /// <summary>Canonical analysisId policy shared by ToolSupport.ReadAnalysisId,
    /// McpToolDispatcher.TryReadSessionId and ServerMetrics.SanitizeSessionId:
    /// bounded, identifier-only, and never a reserved DOS device name.</summary>
    internal static bool IsValidAnalysisId(string value)
        => !string.IsNullOrWhiteSpace(value) &&
            value.Length <= 128 &&
            !LocalPathPolicy.ReservedDeviceNames.Contains(value) &&
            value.All(character => char.IsLetterOrDigit(character) || character is '-' or '_');

    private static bool IsValidPipeName(string? value)
        => value is not null &&
            NativePipeNamePolicy.IsValid(value) &&
            !value.Equals("DbgLink.Control", StringComparison.Ordinal);

    /// <summary>Blank tokens are the legacy path (no token); anything else
    /// rides to <see cref="BridgeClient"/>, whose constructor validates it.</summary>
    private static string? NormalizePipeToken(string? token)
        => string.IsNullOrWhiteSpace(token) ? null : token;

    private static bool IsValidEndpointDirectory(string value)
        => !string.IsNullOrWhiteSpace(value) &&
            value.Length <= 32_760 &&
            Path.IsPathFullyQualified(value) &&
            !value.Any(char.IsControl) &&
            Directory.Exists(value) &&
            LocalPathPolicy.IsSafeLocalPath(value);
}

internal sealed class ClosedDebuggerClient : IBridgeClient
{
    public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(false);
    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        => Task.FromResult(BridgeEnvelope.Error("debugger_closed", "The debugger is closed. Use OpenDebugTarget to start it again."));
}

internal static class AnalysisSessionResponse
{
    public static bool TryRead(string response, out AnalysisSessionDescriptor? descriptor)
    {
        descriptor = null;
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object)
                return false;

            var analysisId = TryReadString(result, "analysisId");
            var nativePipe = TryReadString(result, "nativePipeName");
            // The N1 per-session native pipe token rides alongside the pipe
            // name. Absent on the legacy path; a present-but-non-string token
            // is a protocol violation.
            string? nativePipeToken = null;
            if (result.TryGetProperty("nativePipeToken", out var tokenElement))
            {
                if (tokenElement.ValueKind != JsonValueKind.String)
                    return false;
                nativePipeToken = tokenElement.GetString();
            }
            var endpointDirectory = result.TryGetProperty("ghidraEndpointDirectory", out var endpoint)
                ? endpoint.ValueKind == JsonValueKind.String ? endpoint.GetString() : null
                : null;
            if (analysisId is null || nativePipe is null || endpointDirectory is null)
                return false;

            descriptor = new AnalysisSessionDescriptor(analysisId, nativePipe, endpointDirectory, nativePipeToken);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? TryReadString(JsonElement objectElement, string propertyName)
    {
        return objectElement.TryGetProperty(propertyName, out var property) &&
            property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

}
