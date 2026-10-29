using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Direct LiveAnalysisTools tests for the pause-wait robustness (OD-1 follow-up):
// the wait distinguishes paused / still-running / bridge-unusable, a verdict is
// only emitted after a real observed pause, and the probe waitMs budget is
// bounded and configurable. Direct calls bypass MCP schema validation; one
// wire-level test pins the dispatcher path end to end, and one pins that the
// waitMs knob is advertised in the ProbeFunction schema.
public sealed class ProbePauseWaitTests
{
    private const string CallOk =
        "{\"action\":\"callFunction\",\"target\":\"0x0000000140001000\"," +
        "\"oldCip\":\"0x0000000140002000\",\"running\":true}";

    private const string PausedState =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true," +
        "\"returnValue\":\"0x0000000000000005\"," +
        "\"registersAfter\":{\"rip\":\"0x0000000140002000\",\"rsp\":\"0x0000000000000000\",\"rax\":\"0x0000000000000005\"}}";
    private const string RunningState = "{\"debugging\":true,\"running\":true,\"stableRead\":true}";

    private const string EvalFive =
        "{\"expression\":\"rax\",\"valueHex\":\"0x0000000000000005\"," +
        "\"valueUnsigned\":\"5\",\"valueSigned\":\"5\"}";

    private sealed class ProbeSequenceBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        private readonly HashSet<string> _throwing = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];

        public ProbeSequenceBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
            return this;
        }

        public ProbeSequenceBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public ProbeSequenceBridge Throws(string method)
        {
            _throwing.Add(method);
            return this;
        }

        public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

        public static string BridgeError(string code, string message) =>
            "{\"id\":1,\"ok\":false,\"error\":{\"code\":" + JsonSerializer.Serialize(code) +
            ",\"message\":" + JsonSerializer.Serialize(message) + "}}";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (_throwing.Contains(method))
                return Task.FromException<string>(new IOException("test transport failure"));
            if (_scripts.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            if (_sticky.TryGetValue(method, out var response))
                return Task.FromResult(response);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }

        public int PollCount(string method) => Calls.Count(call => call == method);
    }

    private static LiveAnalysisTools Live(ProbeSequenceBridge bridge)
        => new(new AnalysisContext(bridge, new NullGhidra()));

    private static JsonElement Args(string json)
        => JsonSerializer.Deserialize<JsonElement>(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    [Fact]
    public async Task PauseWait_PausedState_EmitsVerdict()
    {
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.Ok(PausedState))
            .Sticky("EvaluateExpression", ProbeSequenceBridge.Ok(EvalFive));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"expected\":\"0x5\"}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.GetProperty("matched").GetBoolean());
        Assert.True(result.TryGetProperty("returnValue", out _));
        Assert.Equal(1, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_StillRunning_NoVerdict_TimeoutWithoutRegisterRead()
    {
        // waitMs=200 -> 4 polls at a 50ms interval; all report usable running
        // states, so the budget exhausts as still-running, not bridge noise.
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.Ok(RunningState));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"expected\":\"0x5\",\"waitMs\":200}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        var error = root.GetProperty("error");
        Assert.Equal("debugger_running_timeout", error.GetProperty("code").GetString());
        Assert.Contains("did not pause", error.GetProperty("message").GetString());
        Assert.DoesNotContain("matched", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("returnValue", raw, StringComparison.Ordinal);
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
        Assert.Equal(4, bridge.PollCount("GetSnapshotState"));
    }

    [Fact]
    public async Task PauseWait_BridgeThrows_NoVerdict_DistinctBridgeMessage()
    {
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Throws("GetSnapshotState");

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"expected\":\"0x5\",\"waitMs\":200}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        var error = root.GetProperty("error");
        Assert.Equal("debugger_running_timeout", error.GetProperty("code").GetString());
        var message = error.GetProperty("message").GetString() ?? "";
        Assert.Contains("usable", message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("did not pause", message, StringComparison.Ordinal);
        Assert.DoesNotContain("matched", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("returnValue", raw, StringComparison.Ordinal);
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_ErrorEnvelopeState_NoVerdict_BridgeMessage()
    {
        // An ok:false state response is unusable: it says nothing about the
        // target, so it must not be mistaken for "still running".
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.BridgeError("transport_error", "pipe hiccup"));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"waitMs\":150}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_running_timeout",
            root.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("usable", root.GetProperty("error").GetProperty("message").GetString(),
            StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
        Assert.Equal(3, bridge.PollCount("GetSnapshotState"));
    }

    [Fact]
    public async Task PauseWait_EmptyResultState_IsUnusable_NotStillRunning()
    {
        // An ok:true envelope with an empty result carries no paused/running
        // fields: unusable, not evidence the target is running.
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.Ok("{}"));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"waitMs\":150}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Contains("usable", root.GetProperty("error").GetProperty("message").GetString(),
            StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_TransientHiccupThenPaused_StillVerdict()
    {
        // One unreadable poll and one running poll must not poison the wait:
        // the later real pause still yields a verdict.
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Script("GetSnapshotState",
                "not-json-at-all",
                ProbeSequenceBridge.Ok(RunningState),
                ProbeSequenceBridge.Ok(PausedState))
            .Sticky("EvaluateExpression", ProbeSequenceBridge.Ok(EvalFive));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"expected\":\"0x5\",\"waitMs\":500}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        Assert.True(root.GetProperty("result").GetProperty("matched").GetBoolean());
        Assert.Equal(1, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_UnusableThenRunning_ReportsStillRunning()
    {
        // A single usable running sample flips the classification from
        // bridge-unusable to still-running even when earlier polls were noise.
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Script("GetSnapshotState",
                "not-json-at-all",
                ProbeSequenceBridge.Ok(RunningState),
                ProbeSequenceBridge.Ok(RunningState),
                ProbeSequenceBridge.Ok(RunningState));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"waitMs\":200}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Contains("did not pause", root.GetProperty("error").GetProperty("message").GetString(),
            StringComparison.Ordinal);
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_WaitMsZero_SinglePollThenTimeout()
    {
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.Ok(RunningState));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"waitMs\":0}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(1, bridge.PollCount("GetSnapshotState"));
        Assert.Equal(0, bridge.PollCount("EvaluateExpression"));
    }

    [Fact]
    public async Task PauseWait_NegativeWaitMs_ClampedToSinglePoll()
    {
        var bridge = new ProbeSequenceBridge()
            .Sticky("CallFunction", ProbeSequenceBridge.Ok(CallOk))
            .Sticky("GetSnapshotState", ProbeSequenceBridge.Ok(RunningState));

        var raw = await Live(bridge).ProbeFunctionAsync(
            Args("{\"address\":\"cip\",\"waitMs\":-100}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(1, bridge.PollCount("GetSnapshotState"));
    }

    [Fact]
    public void PauseWait_BudgetConstants_DocumentTheClamp()
    {
        // Default preserves the historical 60x50ms behavior; the max keeps an
        // opt-in longer wait bounded.
        Assert.Equal(3000, LiveAnalysisTools.DefaultProbeWaitMs);
        Assert.Equal(30000, LiveAnalysisTools.MaxProbeWaitMs);
        Assert.Equal(50, LiveAnalysisTools.PausePollIntervalMs);
        Assert.Equal(60, LiveAnalysisTools.DefaultProbeWaitMs / LiveAnalysisTools.PausePollIntervalMs);
    }

    [Fact]
    public async Task PauseWait_Wire_BridgeUnusable_HonestMessageEndToEnd()
    {
        // Dispatcher path with the default budget: an unusable bridge must
        // surface the bridge-side message, never a verdict.
        var bridge = new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(CallOk))
            .On("GetSnapshotState", ScriptedBridge.Error("transport_error", "pipe hiccup"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("{\"address\":\"cip\"}"),
        }, CancellationToken.None);

        Assert.True(result.IsError == true);
        // The dispatcher unwraps error envelopes to "[code] message" text.
        var text = TextOf(result);
        Assert.Contains("debugger_running_timeout", text, StringComparison.Ordinal);
        Assert.Contains("usable", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("matched", text, StringComparison.Ordinal);
        Assert.DoesNotContain("returnValue", text, StringComparison.Ordinal);
        Assert.DoesNotContain("EvaluateExpression", bridge.Calls.Select(c => c.Method));
    }

    [Fact]
    public void ProbeFunction_Advertises_Bounded_WaitMs_Knob()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "ProbeFunction");
        var waitMs = tool["inputSchema"]!["properties"]!["waitMs"] as JsonObject;
        Assert.NotNull(waitMs);
        Assert.Equal("integer", waitMs!["type"]!.GetValue<string>());
        Assert.Equal(LiveAnalysisTools.MaxProbeWaitMs, waitMs["maximum"]!.GetValue<int>());
        // Boundaries ride server-side: omitted still validates.
        Assert.Null(server.ValidateArguments("ProbeFunction",
            JsonSerializer.Deserialize<JsonElement>("{\"address\":\"cip\"}")));
    }
}
