extern alias Server;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit.Abstractions;
using BridgeEnvelope = Server::DbgLink.Shared.BridgeEnvelope;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// Strict token regression caps: absolute wire budgets for tools/list and
/// per-tool responses. Fails on growth, not just relative lean-vs-full.
/// </summary>
public sealed class TokenRegressionTests
{
    private readonly ITestOutputHelper _output;
    public TokenRegressionTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void ToolsList_AbsoluteCaps()
    {
        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var lean = new LocalMcpServer(new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        var compJson = comp.ListTools().ToJsonString();
        var leanJson = lean.ListTools().ToJsonString();
        _output.WriteLine($"comp chars={compJson.Length} tok~{Tok(compJson)}; lean chars={leanJson.Length} tok~{Tok(leanJson)}");
        // Single standard catalog: both profiles advertise the same payload.
        Assert.Equal(compJson, leanJson);
        // Absolute caps with generous headroom over 2026-10 measurements
        // (real cl100k_base: comp ~10.6k tok).
        // Update only when deliberate schema growth lands.
        Assert.True(compJson.Length <= 65_000, $"standard tools/list grew: {compJson.Length}");
        Assert.True(Tok(compJson) <= 17_600, $"standard tok cap breached: {Tok(compJson)}");
    }

    [Fact]
    public void Standard_Strips_Examples_For_Every_Tool_Except_One()
    {
        using var lean = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Lean }, new RecordingBridge());
        var tools = lean.ListTools().OfType<JsonObject>().ToList();
        Assert.True(tools.Count >= 15, $"standard tools/list unexpectedly small: {tools.Count}");
        foreach (var tool in tools)
        {
            var name = tool["name"]!.GetValue<string>();
            var examples = tool["inputSchema"]!["examples"] as JsonArray;
            if (examples is not null)
                Assert.True(string.Equals(name, "SetBreakpoint", StringComparison.Ordinal) && examples.Count == 1,
                    $"{name}: only SetBreakpoint may keep one example");
        }
    }

    [Fact]
    public void Standard_Keeps_PropertyDescriptions_For_Snapshots()
    {
        using var lean = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Lean }, new RecordingBridge());
        foreach (var name in new[] { "GetAnalysisSnapshot", "TraceUntil", "SetBreakpoint" })
        {
            var tool = lean.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == name);
            Assert.NotNull(tool["description"]);
        }
    }

    [Fact]
    public void Comprehensive_Keeps_AtMost_One_Example_And_No_Empty_Arrays()
    {
        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        foreach (var tool in comp.ListTools().OfType<JsonObject>())
        {
            var examples = tool["inputSchema"]?["examples"] as JsonArray;
            if (examples is not null)
            {
                Assert.True(examples.Count == 1, $"{tool["name"]} must keep at most 1 example, got {examples.Count}");
            }
        }
    }

    [Fact]
    public async Task Batch_ClampApplies_TriageBudgets_And_Dedups()
    {
        // Batch fan-out is triage, not a deep dive: heavy reads without an
        // explicit budget are clamped, explicit per-item budgets are honored,
        // and identical items share one backend call.
        var backend = new CapturingGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(new ModelContextProtocol.Protocol.CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""
                {"requests":[
                  {"method":"InspectFunction","arguments":{"function":"main"}},
                  {"method":"InspectFunction","arguments":{"function":"main","maxChars":20000}},
                  {"method":"DumpStrings","arguments":{}},
                  {"method":"ReadStaticBytes","arguments":{"address":"0x140001000"}},
                  {"method":"ListFunctions","arguments":{}},
                  {"method":"ListFunctions","arguments":{}}]}
                """)!,
        }, CancellationToken.None);
        Assert.False(result.IsError == true);
        var text = ((ModelContextProtocol.Protocol.TextContentBlock)result.Content[0]).Text;

        // Omitted InspectFunction budget clamped to the triage level; the
        // explicit per-item budget passes through untouched.
        var inspect = backend.Calls.Where(c => c.Method == "InspectFunction").ToList();
        Assert.Equal(2, inspect.Count);
        Assert.Contains("\"maxChars\":6000", inspect[0].ArgsJson);
        Assert.Contains("\"maxChars\":20000", inspect[1].ArgsJson);

        // Omitted paging/byte budgets clamped so 16-way fan-outs cannot blow
        // the shared output limit.
        Assert.Contains("\"maxItems\":32", Assert.Single(backend.Calls.Where(c => c.Method == "DumpStrings")).ArgsJson);
        Assert.Contains("\"length\":512", Assert.Single(backend.Calls.Where(c => c.Method == "ReadStaticBytes")).ArgsJson);

        // Identical items collapse to one backend call; both ordered rows
        // are still present in the envelope.
        Assert.Single(backend.Calls.Where(c => c.Method == "ListFunctions"));
        Assert.Contains("\"index\":0", text);
        Assert.Contains("\"index\":1", text);
    }

    private sealed class CapturingGhidra : DbgLink.Server.IGhidraClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}");
        }
    }

    [Fact]
    public async Task Batch_Dedup_Saves_BackendCalls()
    {
        var bridge = new CountingBatchBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var args = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"expressions":["rax","rax"]}""")!;
        var result = await server.CallToolAsync(new ModelContextProtocol.Protocol.CallToolRequestParams { Name = "EvaluateExpressions", Arguments = args }, CancellationToken.None);
        var text = ((ModelContextProtocol.Protocol.TextContentBlock)result.Content[0]).Text;
        // Backend must be hit once for two identical items.
        Assert.Equal(1, bridge.RequestCount);
        Assert.Contains("0x1", text);
        // Both items present in ordered array (index 0 and 1 may be in envelope or unwrapped).
        Assert.Contains("\"index\":0", text);
        Assert.Contains("\"index\":1", text);
    }

    [Fact]
    public async Task Batch_Dedup_Normalizes_Expression_Case_And_Spaces()
    {
        var bridge = new CountingBatchBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var args = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"expressions":["rax"," RAX "]}""")!;
        var result = await server.CallToolAsync(new ModelContextProtocol.Protocol.CallToolRequestParams { Name = "EvaluateExpressions", Arguments = args }, CancellationToken.None);
        var text = ((ModelContextProtocol.Protocol.TextContentBlock)result.Content[0]).Text;
        Assert.Equal(1, bridge.RequestCount);
        Assert.Contains("\"index\":0", text);
        Assert.Contains("\"index\":1", text);
    }

    private sealed class CountingBatchBridge : DbgLink.Server.IBridgeClient
    {
        private int _count;
        public int RequestCount => Volatile.Read(ref _count);
        public Task<bool> PingAsync(CancellationToken t) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken t)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"valueHex\":\"0x1\"}}");
        }
    }

    [Fact]
    public async Task Checkpoint_Summary_Is_Smaller_Than_Full_And_Supports_Hash()
    {
        using var dir = TempDir.Create("dbglink-tok-");
        var store = new CheckpointStore(Path.Combine(dir, "checkpoints.json"));
        var tools = new CheckpointTools(store);
        var sha = new string('a', 64);
        var big = new string('x', 5000);
        await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
        {
            sha256 = sha,
            findings = big,
            hypotheses = big,
            verified = big,
            nextStep = "step",
            context = big,
            liveValues = big
        }), null);
        var full = await tools.GetLastCheckpointAsync(JsonSerializer.SerializeToElement(new { sha256 = sha }));
        var summary = await tools.GetLastCheckpointAsync(JsonSerializer.SerializeToElement(new { sha256 = sha, fields = "summary", maxChars = 200 }));
        Assert.True(summary.Length < full.Length / 2, $"summary {summary.Length} should be < half of full {full.Length}");
        var fullNode = JsonNode.Parse(full)!.AsObject();
        var hash = fullNode["result"]?["contentHash"]?.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(hash));
        var unchanged = await tools.GetLastCheckpointAsync(JsonSerializer.SerializeToElement(new { sha256 = sha, fields = "summary", ifNoneMatch = hash }));
        Assert.Contains("\"unchanged\":true", unchanged);
    }

    [Fact]
    public void Consistency_Unchanged_Omits_BeforeAfter()
    {
        var state = JsonNode.Parse("""{"debuggerPid":123,"generation":"1","debugging":true,"running":false,"threadId":42,"stableRead":true}""")!;
        var result = AnalysisSnapshotSummary.AssessConsistency(state, state.DeepClone());
        Assert.Equal("unchanged", result["status"]!.GetValue<string>());
        Assert.Null(result["before"]);
        Assert.Null(result["after"]);
        Assert.NotNull(result["generation"]);
    }

    [Fact]
    public void Consistency_Changed_Uses_Delta_Not_Clones()
    {
        var before = JsonNode.Parse("""{"debuggerPid":123,"generation":"1","debugging":true,"running":false,"threadId":42,"stableRead":true}""")!;
        var after = JsonNode.Parse("""{"debuggerPid":123,"generation":"2","debugging":true,"running":false,"threadId":42,"stableRead":true}""")!;
        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("changed", result["status"]!.GetValue<string>());
        Assert.Null(result["before"]);
        Assert.NotNull(result["after"]);
        Assert.NotNull(result["changedFields"]);
        Assert.Contains("generation", result["changedFields"]!.AsArray().Select(n => n!.GetValue<string>()));
    }

    [Fact]
    public void BridgeEnvelope_Error_Clips_Long_Message()
    {
        var msg = new string('x', 2000);
        var json = BridgeEnvelope.Error("boom", msg);
        var node = JsonNode.Parse(json)!.AsObject();
        var clipped = node["error"]!["message"]!.GetValue<string>();
        Assert.True(clipped.Length <= 512 + 32, $"clipped len {clipped.Length}");
        Assert.Contains("[truncated", clipped);
    }

    [Fact]
    public void Advertised_Metadata_Keeps_Validation_Annotations()
    {
        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        var json = comp.ListTools().ToJsonString();
        // direction/kind selectors carry pattern validation annotations
        // (WS2 extended both with a both fan-in alternative).
        Assert.Contains("^(?i)(to|from|both)$", json);
        Assert.Contains("^(?i)(imports|exports|both)$", json);
        // DecompileModule no longer takes a single-function selector: use InspectFunction.
        var module = comp.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == "DecompileModule");
        Assert.Null(module["inputSchema"]!["properties"]!["function"]);
        Assert.Null(module["inputSchema"]!["x-exclusiveSelectors"]);
    }
}
