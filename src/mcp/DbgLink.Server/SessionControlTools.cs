using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed class SessionControlTools(IGhidraControlClient? control, AnalysisSessionRegistry sessions, AnalysisContext context)
{
    public bool Available => control?.SupportsSessionControl == true;

    /// <summary>
    /// Checkpoint store hook for ReopenAnalysisSession summary embedding.
    /// Set in tests; null in production wiring, where Reopen resolves the
    /// default checkpoint path best-effort (never failing the reopen).
    /// </summary>
    internal CheckpointStore? CheckpointStoreOverride { get; set; }

    public async Task<string> ListAsync(JsonElement? arguments, CancellationToken token)
    {
        // Forward the caller's closed-session preference; the launcher
        // filters at render time (live only by default) and never prunes
        // the persisted manifest. Omitted when false so the default payload
        // stays byte-identical.
        var payload = new JsonObject();
        if (ToolSupport.ReadArgumentBool(arguments, "includeClosed", false))
            payload["includeClosed"] = true;
        var response = await SendAsync("ListAnalysisSessions", payload, token).ConfigureAwait(false);
        var root = TryParseObject(response);
        if (root is null)
            return BridgeEnvelope.Error("session_control_protocol",
                "The launcher returned a malformed session list response. Retry ListAnalysisSessions.");
        if (IsOk(root) && root["result"] is JsonObject result)
        {
            result["activeAnalysisId"] = sessions.ActiveAnalysisId;
            AddRestoreHint(result);
            return root.ToJsonString();
        }
        return response;
    }

    public async Task<string> SwitchAsync(JsonElement? arguments, CancellationToken token)
    {
        JsonObject payload;
        try
        {
            payload = arguments is null ? new JsonObject() : JsonNode.Parse(arguments.Value.GetRawText())!.AsObject();
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return BridgeEnvelope.Error("invalid_argument", "SwitchDebugger arguments must be a JSON object.");
        }
        // Host-scope gate: validate an explicit path with the same policy as
        // OpenDebugTarget (absolute local drive path, .exe/.dll, exists, size
        // cap, reparse-free, no quote/control, no UNC/ADS/device) before any
        // pipe traffic. Missing path with architecture=auto also fails: auto
        // requires a target. Same-arch switches without a path pass through.
        var architecture = payload["architecture"] is JsonValue archValue &&
            archValue.TryGetValue<string>(out var archText) ? archText : "auto";
        var isAuto = string.IsNullOrWhiteSpace(architecture) ||
            string.Equals(architecture.Trim(), "auto", StringComparison.OrdinalIgnoreCase);
        string? switchPath = payload["path"] is JsonValue pathValue &&
            pathValue.TryGetValue<string>(out var pathText) ? pathText : null;
        if (!string.IsNullOrWhiteSpace(switchPath))
        {
            if (LiveAnalysisTools.ValidateDebugTarget(switchPath, null, null) is null)
                return BridgeEnvelope.Error("invalid_argument",
                    "SwitchDebugger path failed validation: it must be an absolute local .exe/.dll path that exists. Do not repeat the same path.");
        }
        else if (isAuto)
        {
            return BridgeEnvelope.Error("invalid_argument",
                "SwitchDebugger with architecture=auto requires a valid path to an existing .exe/.dll target.");
        }
        var analysisId = context.AnalysisId;
        if (string.IsNullOrWhiteSpace(analysisId))
            return BridgeEnvelope.Error("session_control_protocol",
                "The current session has no analysis id. Call ListAnalysisSessions for live ids.");
        payload["analysisId"] = analysisId;
        var response = await SendAsync("SwitchDebugger", payload, token).ConfigureAwait(false);
        var root = TryParseObject(response);
        if (root is null)
            return BridgeEnvelope.Error("session_control_protocol",
                "The launcher returned a malformed SwitchDebugger response. Retry with the same analysisId.");
        if (IsOk(root) && root["result"] is JsonObject result)
        {
            if (!TryReadString(result["analysisId"], out var echoedId) || echoedId != analysisId ||
                !TryReadString(result["nativePipeName"], out var pipeName))
                return BridgeEnvelope.Error("session_control_protocol", "The launcher did not return the selected debugger session.");
            // The N1 native pipe token is per-session: without it the replaced
            // bridge cannot authenticate. Absent on the legacy path.
            TryReadString(result["nativePipeToken"], out var pipeToken);
            sessions.ReplaceBridge(analysisId, pipeName, string.IsNullOrWhiteSpace(pipeToken) ? null : pipeToken);
            result["sessionNote"] = $"Session '{analysisId}' valid; bridge replaced.";
            return root.ToJsonString();
        }
        return response;
    }

    public async Task<string> CloseAsync(string? analysisId, CancellationToken token)
    {
        var id = analysisId ?? context.AnalysisId;
        if (string.IsNullOrWhiteSpace(id))
            return BridgeEnvelope.Error("invalid_argument", "CloseAnalysisSession needs a non-blank analysis id.");
        if (sessions.IsClosed(id))
            return new JsonObject { ["ok"] = true, ["result"] = new JsonObject
                { ["analysisId"] = id, ["closed"] = true, ["alreadyClosed"] = true,
                  ["sessionNote"] = $"Session '{id}' closed; id no longer valid.",
                  ["remainingSessions"] = RemainingSessions(), ["remainingSessionCount"] = sessions.ActiveCount } }.ToJsonString();
        var response = await SendAsync("CloseAnalysisSession", new JsonObject { ["analysisId"] = id }, token).ConfigureAwait(false);
        var root = TryParseObject(response);
        if (root is null)
            return BridgeEnvelope.Error("session_control_protocol",
                $"The launcher returned a malformed CloseAnalysisSession response for '{id}'. The session may still be open; call ListAnalysisSessions to confirm.");
        if (IsOk(root) && root["result"] is JsonObject result)
        {
            if (!TryReadString(result["analysisId"], out var echoedId) || echoedId != id ||
                !TryReadBool(result["closed"]))
                return BridgeEnvelope.Error("session_control_protocol", "The launcher did not confirm session shutdown.");
            sessions.Close(id);
            result["sessionNote"] = $"Session '{id}' closed; id no longer valid.";
            result["remainingSessions"] = RemainingSessions();
            result["remainingSessionCount"] = sessions.ActiveCount;
            return root.ToJsonString();
        }
        return response;
    }

    public async Task<string> ReopenAsync(string? analysisId, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(analysisId))
            return BridgeEnvelope.Error("invalid_argument", "ReopenAnalysisSession needs a non-blank analysis id.");
        var id = analysisId;
        var response = await SendAsync("ReopenAnalysisSession", new JsonObject { ["analysisId"] = id }, token).ConfigureAwait(false);
        var root = TryParseObject(response);
        if (root is null)
            return BridgeEnvelope.Error("session_control_protocol",
                $"The launcher returned a malformed ReopenAnalysisSession response for '{id}'. The target may still have reopened; call ListAnalysisSessions to confirm.");
        if (IsOk(root) && root["result"] is JsonObject result)
        {
            if (TryReadBool(result["reopened"]))
            {
                // The dispatcher auto-registers the new session from these
                // fields; reject a descriptor-less success so a half-open
                // session never looks live.
                if (!TryReadString(result["analysisId"], out var renewed) || renewed == id ||
                    !TryReadString(result["nativePipeName"], out _) ||
                    !TryReadString(result["ghidraEndpointDirectory"], out _))
                    return BridgeEnvelope.Error("session_control_protocol", "The launcher did not return the reopened analysis session.");
                // The reopened session usually has a handoff checkpoint: embed
                // its summary so the follow-up Checkpoint restore is not forced.
                // Best-effort decoration only; the reopen itself already succeeded.
                EmbedCheckpointSummary(result);
                return root.ToJsonString();
            }
            return response;
        }
        return response;
    }

    /// <summary>
    /// Live session ids (plus count) for CloseAnalysisSession responses, so
    /// the caller picks the next live id from the close reply instead of a
    /// follow-up ListAnalysisSessions call. Additive; capped at the
    /// registry's 16-id window, with the exact count alongside.
    /// </summary>
    private JsonArray RemainingSessions()
        => new(sessions.ActiveIds.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());

    /// <summary>
    /// Best-effort checkpoint-summary decoration for a successful reopen: when
    /// the launcher reports the reopened binary's sha256, the stored handoff
    /// summary (same shape as Checkpoint action=restore fields=summary) rides along
    /// in the reopen reply. Any store absence, parse failure, or missing hash
    /// leaves the reopen response untouched — the reopen itself succeeded.
    /// </summary>
    private void EmbedCheckpointSummary(JsonObject result)
    {
        try
        {
            if (result["sha256"] is not JsonValue shaValue ||
                !shaValue.TryGetValue<string>(out var raw) ||
                AddressMapping.NormalizeSha256(raw) is not string sha256)
                return;
            var store = CheckpointStoreOverride ?? new CheckpointStore(DbgLinkConfigPath.GetCheckpointPath());
            var (checkpoint, _) = store.LoadSnapshot(sha256);
            if (checkpoint is null)
            {
                result["checkpointFound"] = false;
                return;
            }
            result["checkpointFound"] = true;
            result["checkpointSummary"] = CheckpointTools.BuildCheckpointSummary(
                checkpoint, CheckpointTools.ComputeCheckpointHash(checkpoint), 2000, null);
            result["checkpointNote"] = "Checkpoint summary embedded; Checkpoint action=restore for full text.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            JsonException or TimeoutException or ArgumentException or InvalidOperationException or FormatException)
        {
        }
    }

    public async Task<string> OpenDebugTargetAsync(JsonObject payload, string architecture, CancellationToken token)
    {
        var selection = JsonSerializer.SerializeToElement(new { architecture = SanitizeArchitecture(architecture), path = payload["path"]!.GetValue<string>() });
        var selected = await SwitchAsync(selection, token).ConfigureAwait(false);
        var debugger = ReadSuccess(selected);
        if (debugger is null) return selected;
        var response = await sessions.Resolve(context.AnalysisId).Bridge.RequestAsync(
            "OpenDebugTarget", JsonSerializer.SerializeToElement(payload), token).ConfigureAwait(false);
        var root = TryParseObject(response);
        if (root is null)
            return BridgeEnvelope.Error("session_control_protocol",
                "The debugger returned a malformed OpenDebugTarget response. The target may still have opened; poll GetAnalysisSnapshot to confirm.");
        if (IsOk(root) && root["result"] is JsonObject result)
        {
            // A reopened target gets a fresh module table (and usually a new
            // base). Never answer the next map from the pre-reopen cache.
            SessionCaches.InvalidateModuleCaches();
            result["analysisId"] = context.AnalysisId;
            result["architecture"] = debugger["architecture"]?.DeepClone();
            result["debuggerPid"] = debugger["debuggerPid"]?.DeepClone();
            result["debuggerChanged"] = debugger["changed"]?.DeepClone();
            return root.ToJsonString();
        }
        return response;
    }

    private Task<string> SendAsync(string method, JsonObject payload, CancellationToken token)
        => control is null
            ? Task.FromResult(BridgeEnvelope.Error("session_control_unavailable", "The launcher does not support session control."))
            : control.SessionControlAsync(method, JsonSerializer.SerializeToElement(payload), token);

    /// <summary>
    /// Sessions that died with the previous launcher run are re-advertised by
    /// the launcher as restored/needsReopen entries. Their old analysisIds are
    /// invalid, so a top-level hint tells the caller to reopen each target via
    /// OpenGhidraFile instead of retrying the dead id. Absent without restored
    /// entries, so the default list bytes are unchanged.
    /// </summary>
    private static void AddRestoreHint(JsonObject result)
    {
        try
        {
            if (result["sessions"] is not JsonArray items)
                return;
            var restored = 0;
            foreach (var item in items)
            {
                if (item is JsonObject session &&
                    session["restored"] is JsonValue flag &&
                    flag.TryGetValue<bool>(out var isRestored) && isRestored)
                    restored++;
            }
            if (restored > 0)
                result["restoreHint"] = $"{restored} previous analysis session(s) ended with the last launcher run " +
                    "(restored:true, needsReopen:true). Those analysisIds are invalid: call ReopenAnalysisSession " +
                    "with the dead analysisId for a one-step reopen (or reopen each target via OpenGhidraFile), " +
                    "then restore context with Checkpoint (action=create/restore) and the annotation journal.";
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
        }
    }

    private static JsonObject? ReadSuccess(string response)
    {
        var root = TryParseObject(response);
        return root is not null && IsOk(root) ? root["result"] as JsonObject : null;
    }

    /// <summary>
    /// The launcher is an external process: its control responses must never
    /// crash session handling with a parse exception. Malformed payloads
    /// surface as protocol errors with a retry hint instead. Depth-bounded
    /// (MaxDepth 8, like SlimMutationAck) so a hostile nested payload cannot
    /// blow the stack via unbounded JsonNode.Parse.
    /// </summary>
    private static JsonObject? TryParseObject(string response)
    {
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return null;
            return JsonNode.Parse(document.RootElement.GetRawText())?.AsObject();
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool IsOk(JsonObject root)
    {
        try
        {
            return root["ok"]?.GetValue<bool>() == true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    private static bool TryReadString(JsonNode? node, out string value)
    {
        value = "";
        try
        {
            if (node is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text) &&
                !string.IsNullOrWhiteSpace(text))
            {
                value = text;
                return true;
            }
            return false;
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    private static bool TryReadBool(JsonNode? node)
    {
        try
        {
            return node is JsonValue jsonValue && jsonValue.TryGetValue<bool>(out var value) && value;
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Architecture is a launcher token (auto/x64/x86): blank, oversized, or
    /// control-char values fall back to auto instead of travelling the pipe.
    /// </summary>
    private static string SanitizeArchitecture(string? architecture)
    {
        if (string.IsNullOrWhiteSpace(architecture))
            return "auto";
        var clean = architecture.Trim();
        return clean.Length is < 1 or > 16 || clean.Any(char.IsControl) ? "auto" : clean;
    }
}
