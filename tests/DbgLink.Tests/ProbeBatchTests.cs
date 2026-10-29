using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Wire tests for ProbeFunction batch mode (probes[1..4]): server-resolved
// addresses, slim per-row verdicts, hard-stop on a faulted probe, shared
// wait budget. Single-probe behavior is pinned by ProbeFunctionTests.
public sealed class ProbeBatchTests
{
    private static LocalMcpServer CreateServer(IBridgeClient bridge, bool allowMutation = true)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = allowMutation }, bridge);

    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private const string PausedWithReturn =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true," +
        "\"returnValue\":{\"valueHex\":\"0x5\",\"valueUnsigned\":\"5\",\"valueSigned\":\"5\"}," +
        "\"registersAfter\":{\"rip\":\"0x140001000\",\"rax\":\"0x5\"}}";

    private const string PausedNoReturn =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true}";

    private static ScriptedBridge ProbeBatchBridge(string evalResult, bool withReturn = true) =>
        new ScriptedBridge()
            .On("CallFunction", ScriptedBridge.Ok(
                "{\"address\":\"0x140001000\",\"returnBreakpoint\":\"0x140002000\",\"running\":true}"))
            .On("GetSnapshotState", ScriptedBridge.Ok(withReturn ? PausedWithReturn : PausedNoReturn))
            .On("EvaluateExpression", ScriptedBridge.Ok(evalResult));

    private const string EvalFive =
        "{\"expression\":\"rax\",\"valueHex\":\"0x5\"," +
        "\"valueUnsigned\":\"5\",\"valueSigned\":\"5\"}";

    private sealed class StubGhidra : IGhidraClient
    {
        private readonly string _inspectResult;
        public StubGhidra(string inspectResult) => _inspectResult = inspectResult;
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
            => Task.FromResult("{\"id\":1,\"ok\":true,\"result\":" + _inspectResult + "}");
    }

    private const string IdentityMain =
        "{\"function\":{\"name\":\"main\",\"entry\":\"0x140001000\",\"rva\":\"0x1000\"," +
        "\"module\":{\"path\":\"C:\\\\test.exe\",\"sha256\":\"abc123\"}}}";

    private const string IdentityOther =
        "{\"function\":{\"name\":\"other\",\"entry\":\"0x140002000\",\"rva\":\"0x2000\"," +
        "\"module\":{\"path\":\"C:\\\\other.dll\"}}}";

    private static LocalMcpServer CreateServerWithGhidra(IBridgeClient bridge, string inspectResult)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge, new StubGhidra(inspectResult));

    private static ScriptedBridge LiveModuleBridge(ScriptedBridge bridge)
        => bridge.On("GetModuleRecords", ScriptedBridge.Ok(
            "{\"modules\":[{\"name\":\"test.exe\",\"base\":\"0x140000000\",\"end\":\"0x140050000\"," +
            "\"path\":\"C:\\\\test.exe\"}],\"truncated\":false}"));

    [Theory]
    [InlineData("{\"probes\":[]}")]
    [InlineData("{\"probes\":[{},{},{},{},{},{},{},{},{}]}")]
    [InlineData("{\"probes\":\"x\"}")]
    public async Task Batch_MalformedEnvelope_RejectedBeforeBackend(string json)
    {
        var bridge = ProbeBatchBridge(EvalFive);
        using var server = CreateServer(bridge);

        // Schema-level violations throw before any backend call.
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "ProbeFunction",
                Arguments = Args(json),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"probes\":[{\"address\":\"cip\",\"function\":\"main\"}]}")]
    [InlineData("{\"probes\":[{}]}")]
    public async Task Batch_MalformedRow_RejectedBeforeBackend(string json)
    {
        var bridge = ProbeBatchBridge(EvalFive);
        using var server = CreateServer(bridge);

        // Row-shape violations (not exactly one of address/function) fail the
        // row validation with an error result, touching no backend.
        var error = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args(json),
        }, CancellationToken.None);

        Assert.True(error.IsError == true);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Batch_RunAfterFalse_WithSeveralProbes_RejectedBeforeBackend()
    {
        var bridge = ProbeBatchBridge(EvalFive);
        using var server = CreateServer(bridge);

        var error = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"runAfter\":false,\"probes\":[{\"address\":\"cip\"},{\"address\":\"cip\"}]}"),
        }, CancellationToken.None);

        Assert.True(error.IsError == true);
        Assert.Contains("runAfter", TestWire.RawText(error));
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Batch_TwoAddressProbes_SlimVerdicts_NoCallEcho()
    {
        var bridge = ProbeBatchBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"probes\":[{\"address\":\"cip\",\"expected\":\"0x5\"}," +
                "{\"address\":\"cip\",\"expected\":\"0x6\"}],\"waitMs\":1000}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        var root = doc.RootElement;
        Assert.Equal(2, root.GetProperty("probes").GetInt32());
        Assert.Equal(1, root.GetProperty("matched").GetInt32());
        Assert.Equal(2, root.GetProperty("executed").GetInt32());
        var rows = root.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.True(rows[0].GetProperty("matched").GetBoolean());
        Assert.False(rows[1].GetProperty("matched").GetBoolean());
        foreach (var row in rows)
        {
            Assert.False(row.TryGetProperty("call", out _));
            Assert.Equal("cip", row.GetProperty("selector").GetString());
        }
        // Two full single-probe sequences, no mapping calls.
        Assert.Equal(6, bridge.RequestCount);
    }

    [Fact]
    public async Task Batch_FunctionRow_ResolvesLiveAddress_AndMatches()
    {
        var bridge = LiveModuleBridge(ProbeBatchBridge(EvalFive));
        using var server = CreateServerWithGhidra(bridge, IdentityMain);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"probes\":[{\"function\":\"main\",\"expected\":\"5\"}],\"waitMs\":1000}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        var row = Assert.Single(doc.RootElement.GetProperty("results").EnumerateArray());
        Assert.Equal("main", row.GetProperty("selector").GetString());
        Assert.Equal("0x140001000", row.GetProperty("liveAddress").GetString());
        Assert.True(row.GetProperty("mapping").GetProperty("match").GetBoolean());
        Assert.True(row.GetProperty("matched").GetBoolean());
    }

    [Fact]
    public async Task Batch_MappingMiss_FailsRow_AndContinues()
    {
        var bridge = LiveModuleBridge(ProbeBatchBridge(EvalFive));
        using var server = CreateServerWithGhidra(bridge, IdentityOther);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"probes\":[{\"function\":\"other\"},{\"address\":\"cip\",\"expected\":\"0x5\"}],\"waitMs\":1000}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        var rows = doc.RootElement.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.False(rows[0].GetProperty("ok").GetBoolean());
        Assert.True(rows[1].GetProperty("matched").GetBoolean());
        Assert.False(doc.RootElement.TryGetProperty("stoppedEarly", out _));
    }

    [Fact]
    public async Task Batch_NotLanded_HardStops_RestSkipped()
    {
        var bridge = ProbeBatchBridge(EvalFive, withReturn: false);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"probes\":[{\"address\":\"cip\"},{\"address\":\"cip\"}],\"waitMs\":1000}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        var root = doc.RootElement;
        var rows = root.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.Equal("probe_call_did_not_return", rows[0].GetProperty("code").GetString());
        Assert.True(rows[1].GetProperty("skipped").GetBoolean());
        Assert.True(root.GetProperty("stoppedEarly").GetBoolean());
        // First probe staged + polled once; the second never ran a backend call.
        Assert.Equal(2, bridge.RequestCount);
    }

    [Fact]
    public void Metrics_ExtractProbeSelectors_CoversBatchRows()
    {
        var args = JsonSerializer.Deserialize<JsonElement>(
            "{\"address\":\"cip\",\"probes\":[{\"function\":\"main\"},{\"address\":\"rax\"}]}");
        Assert.Equal(new[] { "cip", "main", "rax" },
            ServerMetrics.ExtractFunctionSelectors("ProbeFunction", args));
    }

    [Fact]
    public async Task Batch_SingleStagedRow_ReportsStaged_WithoutVerdict()
    {
        var bridge = ProbeBatchBridge(EvalFive);
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ProbeFunction",
            Arguments = Args("{\"runAfter\":false,\"probes\":[{\"address\":\"cip\"}]}"),
        }, CancellationToken.None);

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        var row = Assert.Single(doc.RootElement.GetProperty("results").EnumerateArray());
        Assert.True(row.GetProperty("staged").GetBoolean());
        Assert.False(row.TryGetProperty("matched", out _));
        Assert.Equal(1, bridge.RequestCount);
    }
}
