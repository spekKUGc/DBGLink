using System.Runtime.Versioning;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Perf-regression guard for the legacy-removal merge: bulk stepping stays a
// single step call per TraceUntil, single-op BatchAnnotate stays one
// Ghidra call, removed sub-methods/tools are rejected without backend calls,
// and the canonical storm stays race-free.
//
// RB rewrite notes:
// - The old suite counted RequestCount/Calls on managed mocks: a green
//   counter proved the dispatcher called a mock once, not that the native
//   bridge saw one call. All bulk-stepping and storm assertions now measure
//   at the native-bridge boundary through RealNativePipeServer (a real
//   Win32 message-mode pipe + BridgeClient): NativeStepHarness records the
//   StepInto/StepOver/StepOut requests that actually crossed the pipe.
//   A TraceUntil still performs snapshot-section reads after the step, so
//   the pin is "exactly one Step* at the native boundary", never
//   "total pipe requests == 1".
// - BatchAnnotate batching stays mock-measured on purpose: the Ghidra
//   static path is a TCP wire owned by the Ghidra track, and the 1-call
//   contract is a dispatcher property, not a transport property. P3:
//   single-op UpdateVariable (and its 1-call/2-call fan-out contract)
//   is purged; BatchAnnotate ops ride one bridge call. See
//   ToolMergeFuzzTests for the validation-flavored copies.
// - The private RaceBridge/RaceGhidra/StubControl copies are deleted: the
//   suite consumes Support/TestDoubles.cs (MergeRaceBridge/MergeRaceGhidra/
//   MergeStubControl).
// - The 60s wall-clock ceiling test is dropped: completion itself is the
//   anti-hang guard (xunit fails a hung test), and wall-clock asserts only
//   measure CI jitter, not a product contract.
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ToolMergePerfTests
{
    /// <summary>
    /// LocalMcpServer over a REAL message-mode named pipe. Step* requests
    /// crossing the native boundary are recorded with their args payload;
    /// every other method keeps the RealNativePipeServer default handler.
    /// </summary>
    private sealed class NativeStepHarness : IAsyncDisposable
    {
        private readonly object _gate;
        private readonly List<(string Method, string? ArgsJson)> _steps;

        public RealNativePipeServer Pipe { get; }
        public LocalMcpServer Server { get; }
        public IReadOnlyList<(string Method, string? ArgsJson)> Steps
        {
            get { lock (_gate) return _steps.ToArray(); }
        }

        private NativeStepHarness(
            RealNativePipeServer pipe,
            LocalMcpServer server,
            object gate,
            List<(string Method, string? ArgsJson)> steps)
        {
            Pipe = pipe;
            Server = server;
            _gate = gate;
            _steps = steps;
        }

        public static async Task<NativeStepHarness> StartAsync()
        {
            // The step handlers are registered before the server exists, so
            // they close over this shared (gate, list) pair; the harness
            // takes ownership of the same pair below.
            var gate = new object();
            var steps = new List<(string Method, string? ArgsJson)>();
            var pipe = new RealNativePipeServer();
            foreach (var (method, action) in new[]
            {
                ("StepInto", "stepInto"), ("StepOver", "stepOver"), ("StepOut", "stepOut"),
            })
            {
                var capturedMethod = method;
                var capturedAction = action;
                pipe.RegisterHandler(capturedMethod, (id, args) =>
                {
                    lock (gate) steps.Add((capturedMethod, args?.GetRawText()));
                    return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"{capturedAction}\",\"status\":\"paused\"}}}}";
                });
            }
            await Task.Yield();
            var server = new LocalMcpServer(
                new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true, MaxConcurrentRequests = 64, MaxQueuedOperations = 256 },
                new BridgeClient(pipe.PipeName));
            return new NativeStepHarness(pipe, server, gate, steps);
        }

        public async ValueTask DisposeAsync()
        {
            Server.Dispose();
            await Pipe.DisposeAsync();
        }
    }

    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private static async Task<McpProtocolException> CallThrowsAsync(LocalMcpServer server, string name, string json)
        => await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = Args(json) }, CancellationToken.None));

    private static IReadOnlyList<(string Method, string? ArgsJson)> StepsOf(
        NativeStepHarness harness, string method)
        => harness.Steps.Where(c => c.Method == method).ToArray();

    // ---- 1. TraceUntil bulk kinds: one step call each at the native boundary ----

    [Fact]
    public async Task TraceUntil_count5_kind_over_uses_single_StepOver_call()
    {
        await using var harness = await NativeStepHarness.StartAsync();
        var result = await harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":5,\"kind\":\"over\"}") },
            CancellationToken.None);
        Assert.False(result.IsError);
        var steps = StepsOf(harness, "StepOver");
        var only = Assert.Single(steps);
        Assert.Contains("\"count\":5", only.ArgsJson);
        // The bulk fast path may still read snapshot sections after the
        // step: the contract is one StepOver at the boundary, not one pipe
        // request total.
        Assert.True(harness.Pipe.RequestCount >= 1);
    }

    [Fact]
    public async Task TraceUntil_count3_kind_out_uses_single_StepOut_call()
    {
        await using var harness = await NativeStepHarness.StartAsync();
        var result = await harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":3,\"kind\":\"out\"}") },
            CancellationToken.None);
        Assert.False(result.IsError);
        var steps = StepsOf(harness, "StepOut");
        var only = Assert.Single(steps);
        Assert.Contains("\"count\":3", only.ArgsJson);
        Assert.True(harness.Pipe.RequestCount >= 1);
    }

    [Fact]
    public async Task TraceUntil_count100_upper_bound_uses_single_call()
    {
        await using var harness = await NativeStepHarness.StartAsync();
        var result = await harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":100}") },
            CancellationToken.None);
        Assert.False(result.IsError);
        var steps = harness.Steps.Where(c => c.Method is "StepInto" or "StepOver" or "StepOut").ToArray();
        var only = Assert.Single(steps);
        Assert.Contains("\"count\":100", only.ArgsJson);
        Assert.True(harness.Pipe.RequestCount >= 1);
    }

    // ---- 2. BatchAnnotate single-op: exactly one Ghidra call (RB-owned) ----
    // (P3: single-op UpdateVariable purged; one batch op is one bridge call.)

    [Theory]
    [InlineData("{\"operations\":[{\"kind\":\"rename_variable\",\"function\":\"f\",\"variable\":\"v\",\"name\":\"n\"}]}")]
    [InlineData("{\"operations\":[{\"kind\":\"set_variable_type\",\"function\":\"f\",\"variable\":\"v\",\"type\":\"int\"}]}")]
    public async Task BatchAnnotate_single_op_costs_exactly_one_ghidra_call(string json)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "BatchAnnotate", Arguments = Args(json) },
            CancellationToken.None);
        Assert.False(result.IsError);
        Assert.Equal(new[] { "BatchAnnotate" }, ghidra.Methods);
        Assert.Equal(1, ghidra.RequestCount);
    }

    // ---- 3. Removed sub-methods rejected inside batches, zero backend calls ----

    [Fact]
    public async Task BatchDebuggerOperations_rejects_nested_analysisId_with_index()
    {
        // Mirror of the static-batch pin: session pinning belongs on the
        // batch envelope. Zero backend calls; the error names index 0 and
        // the offending analysisId key.
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = Args("{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"analysisId\":\"analysis-x\"}}]}")
        }, CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Contains("invalid_batch", TextOf(result));
        Assert.Contains("0", TextOf(result));
        Assert.Contains("analysisId", TextOf(result));
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task BatchDebuggerOperations_rejects_removed_EvaluateExpression_with_hint()
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = Args("{\"requests\":[{\"method\":\"EvaluateExpression\",\"arguments\":{\"expression\":\"rax\"}}]}")
        }, CancellationToken.None);
        Assert.Contains("invalid_batch", TextOf(result));
        Assert.Contains("EvaluateExpressions", TextOf(result));
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task BatchStaticQueries_rejects_removed_XrefsTo()
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = Args("{\"requests\":[{\"method\":\"XrefsTo\",\"arguments\":{\"address\":\"0x1000\"}}]}")
        }, CancellationToken.None);
        Assert.Contains("invalid_batch", TextOf(result));
        Assert.Equal(0, ghidra.RequestCount);
    }

    // ---- 4. Removed tools are unknown, zero bridge calls ----

    [Theory]
    [InlineData("StepAndInspect", "{\"count\":1}")]
    [InlineData("CancelGhidraOpen", "{\"operationId\":\"nope\"}")]
    [InlineData("RunDebugger", "{}")]
    public async Task Removed_tools_are_unknown_without_bridge_calls(string name, string json)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge, new MergeRaceGhidra(), ghidraControl: new MergeStubControl());
        var error = await CallThrowsAsync(server, name, json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("Unknown tool", error.Message);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task TraceUntil_count1_lower_bound_uses_single_StepInto_call()
    {
        // count=1 is the schema minimum (0 is rejected): it still takes the
        // bulk fast path — exactly one StepInto carrying count 1 at the
        // native boundary, never a degenerate loop or a zero-call no-op.
        await using var harness = await NativeStepHarness.StartAsync();
        var result = await harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":1}") },
            CancellationToken.None);
        Assert.NotNull(result);
        Assert.False(result.IsError);
        var steps = StepsOf(harness, "StepInto");
        var only = Assert.Single(steps);
        Assert.Contains("\"count\":1", only.ArgsJson);
        Assert.True(harness.Pipe.RequestCount >= 1);
    }

    [Fact]
    public async Task BatchAnnotate_two_ops_costs_exactly_one_ghidra_call()
    {
        // P3: the UpdateVariable rename+retype fan-out (2 bridge calls) is
        // gone with the tool; two batch ops ride one BatchAnnotate call.
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "BatchAnnotate", Arguments = Args("{\"operations\":[{\"kind\":\"rename_variable\",\"function\":\"f\",\"variable\":\"v\",\"name\":\"n\"},{\"kind\":\"set_variable_type\",\"function\":\"f\",\"variable\":\"n\",\"type\":\"int\"}]}") },
            CancellationToken.None);
        Assert.False(result.IsError);
        Assert.Equal(new[] { "BatchAnnotate" }, ghidra.Methods);
        Assert.Equal(1, ghidra.RequestCount);
    }

    // ---- 5. Canonical storm: 30x TraceUntil + 30x EvaluateExpressions over the real pipe ----

    [Fact]
    public async Task Canonical_storm_60_parallel_calls_is_stable()
    {
        // Dispatch stability under concurrency, measured at the native
        // boundary: each TraceUntil count=2 collapses to exactly one
        // StepInto at the pipe; each EvaluateExpressions fans out to at
        // least one EvaluateExpression (snapshot-section reads may add
        // more pipe traffic, so the total is a lower bound, not exact).
        // Completion is the anti-hang guard: a dispatch deadlock fails the
        // test via the framework timeout instead of a jitter-sensitive
        // wall-clock assert.
        await using var harness = await NativeStepHarness.StartAsync();
        var traces = Enumerable.Range(0, 30).Select(_ => harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "TraceUntil", Arguments = Args("{\"count\":2}") },
            CancellationToken.None));
        var evals = Enumerable.Range(0, 30).Select(_ => harness.Server.CallToolAsync(
            new CallToolRequestParams { Name = "EvaluateExpressions", Arguments = Args("{\"expressions\":[\"rax\"]}") },
            CancellationToken.None));
        var results = await Task.WhenAll(traces.Concat(evals));
        Assert.Equal(60, results.Length);
        foreach (var result in results)
            Assert.NotNull(result);
        Assert.Equal(30, harness.Steps.Count(c => c.Method == "StepInto"));
        Assert.True(harness.Pipe.RequestCount >= 60);
    }

    // ---- 6. Fuzz gaps from stability review ----

    [Theory]
    [InlineData("{\"expressions\":[]}")]
    [InlineData("{\"expressions\":[\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\",\"rax\"]}")]
    [InlineData("{\"expressions\":[123]}")]
    [InlineData("{\"expressions\":[null]}")]
    [InlineData("{\"expressions\":\"rax\"}")]
    public async Task EvaluateExpressions_rejects_malformed_batches_before_bridge(string json)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var error = await CallThrowsAsync(server, "EvaluateExpressions", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"expressions\":[\"rax\",\"RAX\",\"rax \"]}", 1)]
    [InlineData("{\"expressions\":[\"rax\",\"rbx\"]}", 2)]
    public async Task EvaluateExpressions_dedups_case_and_whitespace_variants(string json, int expectedCalls)
    {
        // Dispatcher-level dedup pin (not a perf signal): identical register
        // spellings collapse before the bridge is touched.
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "EvaluateExpressions", Arguments = Args(json) },
            CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal(expectedCalls, bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"address\":\"0x1000\",\"direction\":\"FROM\"}", "XrefsFrom")]
    [InlineData("{\"address\":\"0x1000\",\"direction\":\"To\"}", "XrefsTo")]
    public async Task Xrefs_direction_is_case_insensitive(string json, string expectedBridge)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "Xrefs", Arguments = Args(json) },
            CancellationToken.None);
        Assert.Equal(new[] { expectedBridge }, ghidra.Methods);
    }

    [Theory]
    [InlineData("{\"kind\":\"IMPORTS\"}", "ListImports")]
    [InlineData("{\"kind\":\"EXPORTS\"}", "ListExports")]
    public async Task ListSymbols_kind_is_case_insensitive(string json, string expectedBridge)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "ListSymbols", Arguments = Args(json) },
            CancellationToken.None);
        Assert.Equal(new[] { expectedBridge }, ghidra.Methods);
    }

    [Theory]
    [InlineData("{\"method\":\"Xrefs\",\"arguments\":{\"address\":\"0x1000\"}}")]
    [InlineData("{\"method\":\"Xrefs\",\"arguments\":{\"address\":\"0x1000\",\"direction\":\"bogus\"}}")]
    [InlineData("{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"bogus\"}}")]
    public async Task BatchStaticQueries_rejects_canonical_misuse_with_index(string requestJson)
    {
        var ghidra = new MergeRaceGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = Args($"{{\"requests\":[{requestJson}]}}")
        }, CancellationToken.None);
        Assert.False(result.IsError);
        var text = TextOf(result);
        Assert.Contains("invalid_batch", text, StringComparison.Ordinal);
        Assert.Contains("Request #0", text, StringComparison.Ordinal);
        Assert.Equal(0, ghidra.RequestCount);
    }

    [Theory]
    [InlineData("{\"action\":\"RUN\"}")]
    [InlineData("{\"action\":\" run\"}")]
    public async Task ControlDebuggerExecution_action_is_case_sensitive(string json)
    {
        var bridge = new MergeRaceBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var error = await CallThrowsAsync(server, "ControlDebuggerExecution", json);
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }
}
