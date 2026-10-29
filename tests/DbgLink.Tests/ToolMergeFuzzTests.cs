using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Big post-merge fuzz + stability cycle for the canonical tools:
// ControlDebuggerExecution, Xrefs, ListSymbols, BatchAnnotate,
// TraceUntil(count/kind) and GetGhidraOpenStatus(cancel).
//
// RB rewrite notes:
// - The private RaceBridge/RaceGhidra/StubControl copies (:15-43) were
//   verbatim duplicates of the Perf/Phase3 copies; all three suites now
//   share Support/TestDoubles.cs (MergeRaceBridge/MergeRaceGhidra/
//   MergeStubControl). No behavior change: same counting, same payloads.
// - Ghidra-fan-out uniques absorbed from ToolMergePerfTests (RB-owned):
//   removed XrefsTo is rejected inside BatchStaticQueries with zero Ghidra
//   calls, and the case-insensitive Xrefs/ListSymbols routing pins live
//   here (the validation-flavored copies; Perf keeps the count-flavored
//   ones). P3: single-op UpdateVariable is purged (use BatchAnnotate;
//   hostile/race/fan-out pins for it deleted with the tool).
// - x64dbg-native bulk/step assertions are intentionally untouched:
//   they belong to the RA track (real-pipe migration lives in Perf).
public sealed class ToolMergeFuzzTests
{
    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private static async Task<McpProtocolException> CallThrowsAsync(LocalMcpServer server, string name, string json)
        => await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = Args(json) }, CancellationToken.None));

    // ---- ControlDebuggerExecution hostile ----

    [Theory]
    [InlineData("{\"action\":\"bogus\"}")]
    [InlineData("{\"action\":\"\"}")]
    [InlineData("{\"action\":\"run run\"}")]
    [InlineData("{\"action\":\"RUN; DROP TABLE\"}")]
    [InlineData("{}")]
    [InlineData("{\"action\":123}")]
    public async Task ControlDebuggerExecution_rejects_hostile_action_before_bridge(string json)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var error = await CallThrowsAsync(server, "ControlDebuggerExecution", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("run", "RunDebugger")]
    [InlineData("pause", "PauseDebugger")]
    public async Task ControlDebuggerExecution_routes_action_to_legacy_bridge_method(string action, string expectedBridge)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "ControlDebuggerExecution", Arguments = Args($"{{\"action\":\"{action}\"}}") },
            CancellationToken.None);
        Assert.Equal(new[] { expectedBridge }, bridge.Methods);
    }

    [Fact]
    public async Task ControlDebuggerExecution_run_pause_storm_is_race_free()
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "ControlDebuggerExecution",
                Arguments = Args(i % 2 == 0 ? "{\"action\":\"run\"}" : "{\"action\":\"pause\"}")
            },
            CancellationToken.None)));
        Assert.Equal(40, bridge.RequestCount);
        Assert.Equal(20, bridge.Methods.Count(m => m == "RunDebugger"));
        Assert.Equal(20, bridge.Methods.Count(m => m == "PauseDebugger"));
    }

    // ---- Xrefs / ListSymbols hostile ----

    [Theory]
    [InlineData("{\"address\":\"0x1000\",\"direction\":\"sideways\"}")]
    [InlineData("{\"address\":\"0x1000\",\"direction\":\"\"}")]
    [InlineData("{\"address\":\"0x1000\"}")]
    [InlineData("{\"address\":\"\",\"direction\":\"to\"}")]
    public async Task Xrefs_rejects_hostile_direction_or_address_before_bridge(string json)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var error = await CallThrowsAsync(server, "Xrefs", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, ghidra.RequestCount);
    }

    [Fact]
    public async Task Xrefs_malformed_address_reaches_bridge_for_backend_diagnosis()
    {
        // Address shape is a backend concern (Ghidra VA vs live addr): MCP
        // validation passes it through and the backend reports invalid_address.
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "Xrefs", Arguments = Args("{\"address\":\"0xZZZ\",\"direction\":\"from\"}") },
            CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal(1, ghidra.RequestCount);
    }

    [Theory]
    [InlineData("{\"kind\":\"maybe\"}")]
    [InlineData("{\"kind\":\"\"}")]
    [InlineData("{}")]
    [InlineData("{\"kind\":\"imports\",\"filter\":\"AIL_*\",\"maxItems\":0}")]
    public async Task ListSymbols_rejects_hostile_kind_before_bridge(string json)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var error = await CallThrowsAsync(server, "ListSymbols", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, ghidra.RequestCount);
    }

    [Fact]
    public async Task Xrefs_canonical_directions_route_to_legacy_bridge_methods()
    {
        // Lowercase canonical spellings (the batch path trims + folds case the
        // same way via SendStaticAsync): "to" -> XrefsTo, "from" -> XrefsFrom.
        foreach (var (direction, expected) in new[] { ("to", "XrefsTo"), ("from", "XrefsFrom") })
        {
            var ghidra = new MergeRaceGhidra();
            using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
            var result = await server.CallToolAsync(
                new CallToolRequestParams { Name = "Xrefs", Arguments = Args($"{{\"address\":\"0x1000\",\"direction\":\"{direction}\"}}") },
                CancellationToken.None);
            Assert.False(result.IsError);
            Assert.Equal(new[] { expected }, ghidra.Methods);
        }
    }

    [Fact]
    public async Task ListSymbols_canonical_kinds_route_to_legacy_bridge_methods()
    {
        foreach (var (kind, expected) in new[] { ("imports", "ListImports"), ("exports", "ListExports") })
        {
            var ghidra = new MergeRaceGhidra();
            using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
            var result = await server.CallToolAsync(
                new CallToolRequestParams { Name = "ListSymbols", Arguments = Args($"{{\"kind\":\"{kind}\"}}") },
                CancellationToken.None);
            Assert.False(result.IsError);
            Assert.Equal(new[] { expected }, ghidra.Methods);
        }
    }

    [Fact]
    public async Task BatchStaticQueries_rejects_nested_analysisId_with_index()
    {
        // Session pinning belongs on the batch envelope: a nested analysisId
        // is a validation error naming the request index, with zero backend
        // calls (ExecuteBatchAsync validates the whole batch first).
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = Args("{\"requests\":[{\"method\":\"Xrefs\",\"arguments\":{\"address\":\"0x1000\",\"direction\":\"to\",\"analysisId\":\"analysis-x\"}}]}")
        }, CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Contains("invalid_batch", TextOf(result));
        Assert.Contains("0", TextOf(result));
        Assert.Contains("analysisId", TextOf(result));
        Assert.Equal(0, ghidra.RequestCount);
    }

    [Fact]
    public async Task BatchStaticQueries_isolates_bad_canonical_method_with_index()
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = Args("{\"requests\":[{\"method\":\"Xrefs\",\"arguments\":{\"address\":\"0x1000\",\"direction\":\"to\"}},{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"bogus\"}}]}")
        }, CancellationToken.None);
        // Per-row validation (localDispatch wired): the valid row executes, the
        // bad row is isolated with its index; the batch itself is not an error.
        Assert.False(result.IsError);
        var text = TextOf(result);
        Assert.Contains("invalid_batch", text, StringComparison.Ordinal);
        Assert.Contains("Request #1", text, StringComparison.Ordinal);
        Assert.Equal(1, ghidra.RequestCount);
    }

    // ---- TraceUntil count/kind hostile ----

    [Theory]
    [InlineData("{\"count\":0}")]
    [InlineData("{\"count\":-5}")]
    [InlineData("{\"count\":101}")]
    [InlineData("{\"count\":\"three\"}")]
    [InlineData("{\"count\":1,\"kind\":\"sideways\"}")]
    [InlineData("{\"count\":1,\"kind\":\"\"}")]
    public async Task TraceUntil_rejects_hostile_count_or_kind_before_bridge(string json)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var error = await CallThrowsAsync(server, "TraceUntil", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task TraceUntil_count_uses_a_single_bulk_step_call()
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":3,\"kind\":\"into\"}") },
            CancellationToken.None);
        var steps = bridge.Calls.Where(c => c.Method == "StepInto").ToArray();
        Assert.Single(steps);
        Assert.Contains("\"count\":3", steps[0].ArgsJson);
    }

    [Fact]
    public async Task EvaluateExpressions_forwards_single_expression_to_bridge()
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "EvaluateExpressions", Arguments = Args("{\"expressions\":[\"rax\"]}") },
            CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal(new[] { "EvaluateExpression" }, bridge.Methods);
        Assert.Contains("rax", bridge.Calls[0].ArgsJson);
    }

    [Fact]
    public async Task TraceUntil_count_with_stop_criteria_keeps_the_predicate_loop()
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":50,\"stopAt\":\"call\",\"maxSteps\":5}") },
            CancellationToken.None);
        // count is ignored when stop criteria are set: only single-step loop calls.
        var steps = bridge.Calls.Where(c => c.Method == "StepInto").ToArray();
        Assert.NotEmpty(steps);
        foreach (var step in steps)
            Assert.Contains("\"count\":1", step.ArgsJson);
    }

    // ---- GetGhidraOpenStatus cancel hostile + storm ----

    [Theory]
    [InlineData("{\"operationId\":\"\"}")]
    [InlineData("{\"operationId\":\"nope\",\"cancel\":\"yes\"}")]
    [InlineData("{}")]
    public async Task GetGhidraOpenStatus_rejects_hostile_arguments(string json)
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidraControl: new MergeStubControl());
        var error = await CallThrowsAsync(server, "GetGhidraOpenStatus", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
    }

    [Fact]
    public async Task GetGhidraOpenStatus_traversal_id_is_a_plain_miss_not_a_path()
    {
        // Operation ids are dictionary keys, never filesystem paths.
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidraControl: new MergeStubControl());
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "GetGhidraOpenStatus", Arguments = Args("{\"operationId\":\"../../../etc/passwd\",\"cancel\":true}") },
            CancellationToken.None);
        Assert.Contains("ghidra_operation_not_found", TextOf(result));
    }

    [Fact]
    public async Task GetGhidraOpenStatus_unknown_id_storm_is_stable()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidraControl: new MergeStubControl());
        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(i => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "GetGhidraOpenStatus",
                Arguments = Args(i % 2 == 0 ? "{\"operationId\":\"nope\"}" : "{\"operationId\":\"nope\",\"cancel\":true}")
            },
            CancellationToken.None)));
        foreach (var result in results)
            Assert.Contains("ghidra_operation_not_found", TextOf(result));
    }

    // ---- Hidden tools stay callable ----

    [Fact]
    public void Phase4_hidden_tools_absent_from_discovery()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true },
            new RecordingBridge(), new MergeRaceGhidra(), ghidraControl: new MergeStubControl());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        foreach (var hidden in new[] { "MapStaticFunctionToLive" })
            Assert.DoesNotContain(hidden, names);
        // Discovery replacements stay advertised.
        foreach (var canonical in new[] { "GetInvestigationBrief", "Triage", "OpenDebugTarget", "ListAnalysisSessions" })
            Assert.Contains(canonical, names);
    }

    [Theory]
    [InlineData("MapStaticFunctionToLive", "{\"function\":\"main\"}")]
    public async Task Hidden_expert_tools_remain_callable_but_unadvertised(string name, string json)
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true },
            new RecordingBridge(), new MergeRaceGhidra(), ghidraControl: new MergeStubControl());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain(name, names);
        // Callable: must not throw Unknown tool (backend may report its own error).
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = Args(json) },
            CancellationToken.None);
        Assert.NotNull(result);
    }
}