using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal enum ToolCapability { ReadOnly, Annotation, Mutation }

/// <summary>Which analysis session a tool operates on: its own session, no session
/// (launcher-global operations), or a session that is being closed.</summary>
internal enum ToolSessionScope { Session, Global, Closing }

internal sealed record ToolInvocation(string Name, JsonElement? Arguments, string? AnalysisId, CancellationToken CancellationToken)
{
    /// <summary>Telemetry detail set by executors (e.g. batch sub-method mix).
    /// Read by the dispatcher after Execute completes; never sent to backends.</summary>
    public string? Detail { get; set; }
}
internal sealed record ToolDefinition(JsonObject Metadata, Func<ToolInvocation, Task<string>> Execute,
    ToolCapability Capability, bool RequiresControl, bool Advertised, bool Lean = false,
    int MinimumTimeoutMs = 1_000,
    ToolSessionScope SessionScope = ToolSessionScope.Session,
    bool RegistersCompletedSession = false,
    bool RawResponse = false,
    Func<ToolInvocation, bool>? RequiresExclusiveLease = null)
{
    public string Name { get; } = Metadata["name"]!.GetValue<string>();
    /// <summary>Cached input schema reference: avoids a per-dispatch
    /// dictionary lookup plus cast on the tools/call hot path.</summary>
    public JsonObject InputSchema { get; } = (JsonObject)Metadata["inputSchema"]!;
    public bool IsEnabled(ServerConfig config, bool hasControl) =>
        (!RequiresControl || hasControl) && Capability switch
        {
            ToolCapability.Mutation => config.AllowMutation,
            ToolCapability.Annotation => config.AllowAnnotation,
            _ => true
        };

    /// <summary>
    /// True when this call must hold the session's exclusive (write) lease.
    /// Read-only tools normally share the session with concurrent readers, but
    /// a tool that changes the target's state despite its ReadOnly capability
    /// (GetAnalysisSnapshot with autoPause pauses and resumes the debugger)
    /// must take the write lease: otherwise a concurrent reader can observe a
    /// target paused by another call, and one call's resume can undo another
    /// call's pause.
    /// </summary>
    public bool NeedsExclusiveLease(ToolInvocation invocation) =>
        RequiresExclusiveLease?.Invoke(invocation) ?? Capability != ToolCapability.ReadOnly;

    public bool IsAdvertisedFor(ServerConfig config, bool hasControl) =>
        Advertised &&
        IsEnabled(config, hasControl);
}

internal sealed partial class ToolRegistry
{
    private readonly Dictionary<string, ToolDefinition> _tools = new(StringComparer.Ordinal);
    public IEnumerable<ToolDefinition> Definitions => _tools.Values;
    public int Count => _tools.Count;
    public bool TryGet(string? name, [NotNullWhen(true)] out ToolDefinition? definition)
    {
        // Null/empty names miss instead of throwing from the dictionary:
        // the dispatcher maps a miss to an unknown_tool protocol error.
        if (string.IsNullOrEmpty(name))
        {
            definition = null;
            return false;
        }
        return _tools.TryGetValue(name, out definition);
    }

    private readonly Dictionary<ListCacheKey, JsonArray> _listTemplates = new();
    private sealed record ListCacheKey(bool AllowMutation, bool AllowAnnotation, bool HasControl);

    private void Register(JsonObject metadata, Func<ToolInvocation, Task<string>> execute,
        ToolCapability capability = ToolCapability.ReadOnly, bool requiresControl = false, bool advertised = true, bool lean = false,
        int minimumTimeoutMs = 1_000,
        ToolSessionScope sessionScope = ToolSessionScope.Session,
        bool registersCompletedSession = false,
        bool rawResponse = false,
        Func<ToolInvocation, bool>? requiresExclusiveLease = null)
    {
        var registeredName = metadata["name"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(registeredName))
            throw new InvalidOperationException("Tool metadata must include a non-blank name.");
        if (_tools.ContainsKey(registeredName))
            throw new InvalidOperationException($"Duplicate tool registration: '{registeredName}'.");
        if (minimumTimeoutMs < 1 || minimumTimeoutMs > 120_000)
            throw new ArgumentOutOfRangeException(nameof(minimumTimeoutMs), minimumTimeoutMs,
                "Tool minimum timeout must be within [1, 120000]ms so the dispatcher clamp stays well-formed.");
        var schema = (JsonObject)metadata["inputSchema"]!;
        if (schema["properties"] is not JsonObject properties)
            schema["properties"] = properties = new JsonObject();
        // The session routing key: present on every tool so calls can pin a
        // session, but documented once here instead of once per tool. The
        // dispatcher falls back to the active session when it is omitted, and
        // ListAnalysisSessions reports the activeAnalysisId to pin explicitly.
        properties["analysisId"] = new JsonObject
        {
            ["type"] = "string", ["maxLength"] = 128
        };
        var definition = new ToolDefinition(metadata, execute, capability, requiresControl, advertised, lean,
            minimumTimeoutMs, sessionScope, registersCompletedSession, rawResponse, requiresExclusiveLease);
        _tools.Add(definition.Name, definition);
    }

    /// <summary>
    /// Lease predicate for read-only tools that pause and resume the target when
    /// <c>autoPause</c> is set. Such a call changes debugger state despite its
    /// ReadOnly capability, so it must hold the session's exclusive lease;
    /// otherwise a concurrent reader can observe a pause it did not ask for and
    /// one call's resume can undo another call's pause.
    /// </summary>
    internal static bool AutoPauseRequiresExclusiveLease(ToolInvocation call)
        => ToolSupport.ReadArgumentBool(call.Arguments, "autoPause", false);

    /// <summary>Builds every advertised template once. Register only runs in
    /// the constructor, so the set is fixed afterwards and List needs no
    /// lock or invalidation: it clones the matching prebuilt template.</summary>
    private void BuildListTemplates()
    {
        foreach (var mutation in new[] { false, true })
            foreach (var annotation in new[] { false, true })
                foreach (var control in new[] { false, true })
                {
                    var key = new ListCacheKey(mutation, annotation, control);
                    _listTemplates[key] = BuildListTemplate(key);
                }
    }

    private JsonArray BuildListTemplate(ListCacheKey key)
    {
        var config = new ServerConfig { Profile = ToolProfile.Comprehensive, AllowMutation = key.AllowMutation, AllowAnnotation = key.AllowAnnotation };
        return new JsonArray(
            Definitions.Where(tool => tool.IsAdvertisedFor(config, key.HasControl))
                .Select(tool => ToolPresentation.Advertise(tool.Metadata, ToolProfile.Comprehensive)).ToArray());
    }

    public JsonArray List(ServerConfig config, bool hasControl)
    {
        // tools/list is served from a prebuilt per-flag template: advertisement
        // depends only on (AllowMutation, AllowAnnotation, hasControl).
        // Single standard catalog; config.Profile is ignored.
        // Callers receive a fresh clone; wire bytes are unchanged. The fallback
        // build covers future flag values without mutating shared state.
        var key = new ListCacheKey(config.AllowMutation, config.AllowAnnotation, hasControl);
        if (!_listTemplates.TryGetValue(key, out var template))
            template = BuildListTemplate(key);
        return (JsonArray)template.DeepClone()!;
    }
}
