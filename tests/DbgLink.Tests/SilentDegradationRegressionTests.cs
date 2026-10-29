using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;

namespace DbgLink.Tests;

/// <summary>
/// Regression tests for bugs that returned a confident but wrong answer, or
/// that quietly re-broke a lease the dispatcher was supposed to enforce:
/// a degraded string triage reported as "clean", a counter read from a field
/// that is never emitted, a batch injecting arguments no schema declares, and
/// autoPause read tools escaping the exclusive lease.
/// </summary>
public sealed class SilentDegradationRegressionTests
{
    private readonly ITestOutputHelper _out;
    public SilentDegradationRegressionTests(ITestOutputHelper output) => _out = output;

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static McpToolDispatcher BuildDispatcher(IBridgeClient bridge, IGhidraClient ghidra, out AnalysisSessionRegistry sessions)
    {
        var config = new ServerConfig { Port = 50397 };
        sessions = new AnalysisSessionRegistry(bridge, ghidra);
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(null, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(
            Path.Combine(Path.GetTempPath(), "dbglink-degraded-" + Guid.NewGuid().ToString("N"))));
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), new GhidraOpenOperations(null), sessionControl);
        return new McpToolDispatcher(config, registry, context, sessions, new ServerMetrics(),
            hasControl: false, NullLogger.Instance);
    }

    // ---------------------------------------------------------------- 1

    /// <summary>
    /// DumpStrings failing and the native fallback answering with a text report
    /// used to produce ok:true with an empty IOC array and no marker, i.e. the
    /// tool claimed the target was clean. It must report the degradation and
    /// echo the fallback text instead.
    /// </summary>
    [Fact]
    public async Task TriageStrings_fallback_text_is_reported_as_degraded_not_as_clean()
    {
        const string fallback = "[FindInterestingStrings] matches=1 module=\"t.exe\" scannedBytes=4096 needles=12\n" +
            "[needle=\"http://\"] matches=1\n[0] address=0x140003000 module=t.exe encoding=ascii text=\"http://evil.test/a\"";
        var bridge = new ScriptedBridge()
            .On("FindInterestingStrings", ScriptedBridge.Ok(JsonSerializer.Serialize(fallback)));
        var ghidra = new ScriptedGhidra
        {
            ["DumpStrings"] = ScriptedBridge.Error("section_not_found", "no such section"),
        };
        // P3: TriageStrings alias purged; the fallback logic lives in
        // TriageImportsTools.TriageStringsAsync (reached via Triage).
        var context = new AnalysisContext(bridge, ghidra);
        var raw = await new TriageImportsTools(context).TriageStringsAsync(
            Args("{\"section\":\".rdata\"}"), CancellationToken.None);
        var rawText = raw;
        _out.WriteLine(rawText);
        var node = AnalysisFormatting.ReadBridgeResultNode(rawText)!;
        Assert.True(node["degraded"]?.GetValue<bool>(), "a text-only fallback must never read as a clean scan");
        Assert.Equal(0, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal("FindInterestingStrings", node["fallback"]!.GetValue<string>());
        Assert.Contains("FindInterestingStrings", node["fallbackText"]!.GetValue<string>());
        Assert.Contains("NOT evidence", node["warning"]!.GetValue<string>());
    }

    // ---------------------------------------------------------------- 2

    /// <summary>
    /// readyForAnalysis was dropped from the snapshot summary; the brief read
    /// the missing key and always reported liveReady=false. It is derived now.
    /// </summary>
    [Fact]
    public void Brief_summary_derives_live_ready_from_paused_unchanged_state()
    {
        var ready = InvestigationTools.BuildBriefSummary(
            "main", null, null, null,
            JsonNode.Parse("{\"summary\":{\"running\":false,\"consistency\":\"unchanged\",\"moduleCount\":3}}"),
            null, includeLive: true, new JsonObject(), errorCount: 0, truncated: false);
        Assert.True(ready["liveReady"]!.GetValue<bool>());

        var running = InvestigationTools.BuildBriefSummary(
            "main", null, null, null,
            JsonNode.Parse("{\"summary\":{\"running\":true,\"consistency\":\"running\",\"moduleCount\":3}}"),
            null, includeLive: true, new JsonObject(), errorCount: 0, truncated: false);
        Assert.False(running["liveReady"]!.GetValue<bool>());

        // Default brief does not request the module table. The snapshot then
        // omits moduleCount entirely; absence is not evidence that the target
        // is unready.
        var noModuleTable = InvestigationTools.BuildBriefSummary(
            "main", null, null, null,
            JsonNode.Parse("{\"summary\":{\"running\":false,\"consistency\":\"unchanged\"}}"),
            null, includeLive: true, new JsonObject(), errorCount: 0, truncated: false);
        Assert.True(noModuleTable["liveReady"]!.GetValue<bool>());
    }

    // ---------------------------------------------------------------- 4

    /// <summary>
    /// The batch budget added both maxItems and maxFrames to a shared case.
    /// Each of these four tools declares only one of the two and sets
    /// additionalProperties=false, so every injected extra argument failed
    /// validation and killed the row (or the whole batch).
    /// </summary>
    [Theory]
    [InlineData("GetMemoryMap")]
    [InlineData("ListThreads")]
    [InlineData("ListBreakpoints")]
    [InlineData("GetBacktrace")]
    public async Task Batch_budget_only_adds_arguments_the_tool_declares(string method)
    {
        var bridge = new ScriptedBridge();
        var dispatcher = BuildDispatcher(bridge, new NullGhidra(), out var sessions);
        using var scope = sessions;

        var result = await dispatcher.CallAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = Args($"[{{\"method\":\"{method}\",\"arguments\":{{}}}}]"),
            },
        }, CancellationToken.None);

        var text = TextOf(result);
        _out.WriteLine(text);
        Assert.DoesNotContain("Unsupported argument", text);
        var rows = JsonNode.Parse(text)!["results"]!.AsArray();
        Assert.Single(rows);
        Assert.True(rows[0]!["response"]!["ok"]!.GetValue<bool>(), $"{method} row failed: {text}");
    }

    // ---------------------------------------------------------------- 5

    /// <summary>
    /// Read-only tools that pause/resume the target on autoPause must take the
    /// session's exclusive lease, exactly like GetAnalysisSnapshot.
    /// </summary>
    [Theory]
    [InlineData("ListThreads")]
    [InlineData("GetBacktrace")]
    [InlineData("ReadMemAtAddress")]
    public void Auto_pause_read_tools_require_the_exclusive_lease(string name)
    {
        var bridge = new RecordingBridge();
        var ghidra = new NullGhidra();
        var sessions = new AnalysisSessionRegistry(bridge, ghidra);
        using var scope = sessions;
        var context = new AnalysisContext(bridge, ghidra);
        var live = new LiveAnalysisTools(context);
        var registry = new ToolRegistry(
            context,
            new CheckpointTools(new CheckpointStore(
                Path.Combine(Path.GetTempPath(), "dbglink-lease-" + Guid.NewGuid().ToString("N")))),
            live,
            new InvestigationTools(context, live),
            new AddressMapping(context),
            new GhidraOpenOperations(null),
            new SessionControlTools(null, sessions, context));

        Assert.True(registry.TryGet(name, out var tool));
        Assert.True(tool!.NeedsExclusiveLease(new ToolInvocation(name, Args("{\"autoPause\":true}"), null, CancellationToken.None)));
        Assert.False(tool.NeedsExclusiveLease(new ToolInvocation(name, Args("{\"autoPause\":false}"), null, CancellationToken.None)));
    }

    // ---------------------------------------------------------------- 6

    /// <summary>
    /// The single-live-session fallback is read-only-only. An autoPause read
    /// changes debugger state, so a dead session id on it must fail closed
    /// instead of pausing/resuming somebody else's live target.
    /// </summary>
    [Fact]
    public async Task Auto_pause_with_a_dead_session_id_does_not_fall_back()
    {
        var dispatcher = BuildDispatcher(new ScriptedBridge(), new NullGhidra(), out var sessions);
        using var scope = sessions;
        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));

        var error = await Assert.ThrowsAsync<McpProtocolException>(() => dispatcher.CallAsync(new CallToolRequestParams
        {
            Name = "ListThreads",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["analysisId"] = Args("\"replaced-session\""),
                ["autoPause"] = Args("true"),
            },
        }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
    }

    /// <summary>Scripted Ghidra endpoint: method -> raw envelope.</summary>
    private sealed class ScriptedGhidra : IGhidraClient
    {
        private readonly Dictionary<string, string> _responses = new(StringComparer.Ordinal);

        public string this[string method]
        {
            set => _responses[method] = value;
        }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult(_responses.TryGetValue(method, out var response)
                ? response
                : "{\"id\":1,\"ok\":true,\"result\":{}}");
    }
}
