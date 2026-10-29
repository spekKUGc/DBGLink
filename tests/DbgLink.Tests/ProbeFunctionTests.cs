using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Wire tests for ProbeFunction: one tool call stages a CallFunction, runs it,
// waits for the target to pause (GetSnapshotState), then reads the return
// register via EvaluateExpression, with an optional numeric verdict against
// expected. runAfter=false stages only and reports no verdict. Same production
// path as live traffic (validation -> mutation gate -> bridge -> response mapping).
public sealed class ProbeFunctionTests
{
    private static LocalMcpServer CreateServer(IBridgeClient bridge, bool allowMutation = true)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = allowMutation }, bridge);

    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private const string CallOk =
        "{\"action\":\"callFunction\",\"target\":\"0x0000000140001000\"," +
        "\"oldCip\":\"0x0000000140002000\",\"running\":true}";

    private const string PausedState =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true," +
        "\"returnValue\":\"0x0000000000000005\"," +
        "\"registersAfter\":{\"rip\":\"0x0000000140002000\",\"rsp\":\"0x0000000000000000\",\"rax\":\"0x0000000000000005\"}}";

    private static ScriptedBridge ProbeBridge(string evalResult)
        => new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(CallOk))
            .On("GetSnapshotState", ScriptedBridge.Ok(PausedState))
            .On("EvaluateExpression", ScriptedBridge.Ok(evalResult));

    private const string EvalFive =
        "{\"expression\":\"rax\",\"valueHex\":\"0x0000000000000005\"," +
        "\"valueUnsigned\":\"5\",\"valueSigned\":\"5\"}";

    [Fact]
    public async Task Probe01_Matched_HexExpected_ComparesNumerically()
    {
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"expected\":\"0x5\"}"),
        }, CancellationToken.None);

        Assert.Equal(3, bridge.RequestCount);
        Assert.Equal("CallFunction", bridge.Calls[0].Method);
        Assert.Contains("\"runAfter\":true", bridge.Calls[0].ArgsJson);
        Assert.Equal("GetSnapshotState", bridge.Calls[1].Method);
        Assert.Equal("EvaluateExpression", bridge.Calls[2].Method);
        Assert.Contains("rax", bridge.Calls[2].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.True(doc.RootElement.GetProperty("matched").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal("0x5", doc.RootElement.GetProperty("expected").GetString());
    }

    [Fact]
    public async Task Probe02_Mismatch_ReportsFalse_WithoutError()
    {
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"expected\":\"0x6\"}"),
        }, CancellationToken.None);

        Assert.Equal(3, bridge.RequestCount);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.False(doc.RootElement.GetProperty("matched").GetBoolean());
    }

    [Fact]
    public async Task Probe03_NoExpected_OmitsVerdict_ButReturnsValue()
    {
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\"}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        var text = TextOf(result);
        Assert.DoesNotContain("matched", text);
        Assert.Contains("returnValue", text);
        Assert.Contains("0x0000000000000005", text);
        Assert.Contains("\"executed\":true", text);
    }

    [Fact]
    public async Task Probe04_CallError_PassesThrough_WithOneBridgeCall()
    {
        var bridge = new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Error("native_error", "Target is running. Pause it before injecting a call."));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"expected\":\"0x5\"}"),
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("running", TextOf(result));
    }

    [Fact]
    public async Task Probe05_EvalError_PassesThrough_AfterPause()
    {
        // Explicit return expressions never retry: one EvaluateExpression,
        // and the bridge error passes through untouched.
        var bridge = new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(CallOk))
            .On("GetSnapshotState", ScriptedBridge.Ok(PausedState))
            .On("EvaluateExpression", ScriptedBridge.Error("native_error", "Could not evaluate expression: rax"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"returnExpression\":\"rax\"}"),
        }, CancellationToken.None);

        Assert.Equal(3, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("Could not evaluate", TextOf(result));
    }

    // x86 target: the default 64-bit return register does not exist, so the
    // probe retries once with eax and reports returnExpression=eax.
    private sealed class ArchAwareBridge : IBridgeClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        private readonly Func<string, string?, string> _respond;

        public ArchAwareBridge(Func<string, string?, string> respond) => _respond = respond;
        public int RequestCount => Calls.Count;
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            var argsJson = arguments?.GetRawText();
            Calls.Add((method, argsJson));
            return Task.FromResult(_respond(method, argsJson));
        }
    }

    private static ArchAwareBridge X86ProbeBridge() => new((method, argsJson) => method switch
    {
        "CallFunction" => ScriptedBridge.Ok(CallOk),
        "GetSnapshotState" => ScriptedBridge.Ok(PausedState),
        // x86 knows eax but not rax.
        "EvaluateExpression" when (argsJson?.Contains("eax") ?? false) =>
            ScriptedBridge.Ok("{\"expression\":\"eax\",\"valueHex\":\"0x00000001\",\"valueUnsigned\":\"1\",\"valueSigned\":\"1\"}"),
        "EvaluateExpression" =>
            ScriptedBridge.Error("native_error", "Could not evaluate expression: rax"),
        _ => ScriptedBridge.Ok("{}"),
    });

    [Fact]
    public async Task Probe12_DefaultReturn_FallsBack_ToEax_OnX86()
    {
        var bridge = X86ProbeBridge();
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\"}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        // rax tried first, then exactly one eax retry.
        Assert.Equal(4, bridge.RequestCount);
        Assert.Equal("EvaluateExpression", bridge.Calls[2].Method);
        Assert.Contains("rax", bridge.Calls[2].ArgsJson);
        Assert.Equal("EvaluateExpression", bridge.Calls[3].Method);
        Assert.Contains("eax", bridge.Calls[3].ArgsJson);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal("eax", doc.RootElement.GetProperty("returnExpression").GetString());
        Assert.Contains("0x00000001", TextOf(result));
    }

    [Fact]
    public async Task Probe13_ExplicitRax_OnX86_DoesNotRetry_PassesErrorThrough()
    {
        var bridge = X86ProbeBridge();
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"returnExpression\":\"rax\"}"),
        }, CancellationToken.None);

        Assert.Equal(3, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("Could not evaluate expression: rax", TextOf(result));
        Assert.DoesNotContain("eax", string.Join(";", bridge.Calls.Select(c => c.ArgsJson)));
    }

    [Fact]
    public async Task Probe10_StagedOnly_NoVerdict_AndNoRegisterRead()
    {
        // runAfter=false: the call has not executed, so no register read and no
        // matched verdict are emitted; only the staged CallFunction runs.
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"runAfter\":false,\"expected\":\"0x5\"}"),
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("CallFunction", bridge.Calls[0].Method);
        Assert.Contains("\"runAfter\":false", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.True(doc.RootElement.GetProperty("staged").GetBoolean());
        Assert.False(doc.RootElement.TryGetProperty("matched", out _));
        Assert.False(doc.RootElement.TryGetProperty("returnValue", out _));
    }

    [Fact]
    public async Task Probe11_TargetNeverPauses_RefusesToReadRacingRegister()
    {
        var bridge = new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(CallOk))
            .On("GetSnapshotState", ScriptedBridge.Ok("{\"debugging\":true,\"running\":true,\"stableRead\":true}"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"expected\":\"0x5\"}"),
        }, CancellationToken.None);

        Assert.True(result.IsError == true);
        Assert.Contains("did not pause", TextOf(result));
        Assert.DoesNotContain("EvaluateExpression", bridge.Calls.Select(c => c.Method));
    }

    [Fact]
    public async Task Probe14_PausedWithoutReturnCapture_RefusesStaleRegister()
    {
        // The target paused, but the pause was not the injected call landing
        // on its return breakpoint (no native returnValue capture: the call
        // faulted or the pause came from elsewhere). Reporting rax anyway
        // would present a stale register as a call result.
        var bridge = new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(CallOk))
            .On("GetSnapshotState", ScriptedBridge.Ok("{\"debugging\":true,\"running\":false,\"stableRead\":true}"))
            .On("EvaluateExpression", ScriptedBridge.Ok(EvalFive));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"expected\":\"0x5\"}"),
        }, CancellationToken.None);

        Assert.True(result.IsError == true);
        Assert.Contains("did not land", TestWire.RawText(result));
        Assert.DoesNotContain("EvaluateExpression", bridge.Calls.Select(c => c.Method));
        Assert.DoesNotContain("returnValue", TestWire.RawText(result));
    }

    [Fact]
    public async Task Probe15_LandedCall_MarksExecutedTrue()
    {
        // A genuine landing (native returnValue capture on the paused state)
        // is reported with an explicit executed marker so a caller can never
        // mistake a stale register for a call result.
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\"}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.True(doc.RootElement.GetProperty("executed").GetBoolean());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"address\":\" \"}")]
    [InlineData("{\"address\":\"cip\",\"returnExpression\":\" \"}")]
    [InlineData("{\"address\":\"cip\",\"expected\":5}")]
    public async Task Probe06_InvalidArguments_RejectedBeforeBridge(string json)
    {
        var bridge = ProbeBridge(EvalFive);
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "ProbeFunction",
                Arguments = Args(json),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Probe07_MutationGate_HidesAndBlocksWithoutCapability()
    {
        var bridge = ProbeBridge(EvalFive);
        using var gated = CreateServer(bridge, allowMutation: false);
        var names = gated.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("ProbeFunction", names);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            gated.CallToolAsync(new CallToolRequestParams
            {
                Name = "ProbeFunction",
                Arguments = Args("{\"address\":\"cip\"}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("capability", error.Message);
        Assert.Equal(0, bridge.RequestCount);

        using var open = CreateServer(new ScriptedBridge(), allowMutation: true);
        Assert.Contains("ProbeFunction", open.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Probe08_ForwardsArgsRunAfterAndCustomReturn()
    {
        var bridge = ProbeBridge(
            "{\"expression\":\"eax\",\"valueHex\":\"0x0000000000000001\"," +
            "\"valueUnsigned\":\"1\",\"valueSigned\":\"1\"}");
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"address\":\"cip\",\"arg1\":\"0x10\",\"runAfter\":true,\"returnExpression\":\"eax\",\"expected\":\"1\"}"),
        }, CancellationToken.None);

        Assert.Equal(3, bridge.RequestCount);
        Assert.Contains("0x10", bridge.Calls[0].ArgsJson);
        Assert.Contains("runAfter", bridge.Calls[0].ArgsJson);
        Assert.Contains("eax", bridge.Calls[2].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.True(doc.RootElement.GetProperty("matched").GetBoolean());
    }

    [Fact]
    public void Probe09_AdvertisedInBothProfiles()
    {
        using var comp = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var lean = new LocalMcpServer(
            new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        foreach (var server in new[] { comp, lean })
            Assert.Contains("ProbeFunction", server.ListTools().OfType<JsonObject>()
                .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal));
    }
}
