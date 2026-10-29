using System.Text.Json;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// End-to-end tool calls through the REAL C# server stack
/// (LocalMcpServer + dispatcher + argument validation) backed by REAL
/// loopback transports: a message-mode named pipe instead of x64dbg and a
/// TCP endpoint directory instead of Ghidra. No mocks for the transports.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ServerEndToEndTests
{
    private static ServerConfig TestConfig(string? checkpointPath = null) => new()
    {
        Port = ServerConfig.DefaultPort,
        MaxConcurrentRequests = 16,
        MaxQueuedOperations = 32,
        DefaultToolTimeoutMs = 5_000,
    };

    private sealed class Harness : IAsyncDisposable
    {
        public RealNativePipeServer Pipe { get; }
        public RealGhidraServers Ghidra { get; }
        public LocalMcpServer Server { get; }

        private Harness(RealNativePipeServer pipe, RealGhidraServers ghidra, LocalMcpServer server)
        {
            Pipe = pipe;
            Ghidra = ghidra;
            Server = server;
        }

        public static async Task<Harness> StartAsync(string? checkpointPath = null)
        {
            var pipe = new RealNativePipeServer();
            var ghidra = new RealGhidraServers(pipe.PipeName);
            await Task.Yield();
            var server = new LocalMcpServer(
                TestConfig(checkpointPath),
                new BridgeClient(pipe.PipeName),
                new GhidraClient(ghidra.EndpointDirectory),
                new GhidraControlClient(ghidra.PipeName, ghidra.Token),
                checkpointPath);
            return new Harness(pipe, ghidra, server);
        }

        public async ValueTask DisposeAsync()
        {
            Server.Dispose();
            await Ghidra.DisposeAsync();
            await Pipe.DisposeAsync();
        }
    }

    private static async Task<(bool IsError, string Text)> CallAsync(LocalMcpServer server, string name, string argsJson)
    {
        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\""
            + name + "\",\"arguments\":" + argsJson + "}}";
        var raw = await server.ExecuteTestRequestAsync(body, CancellationToken.None, "2025-06-18");
        Assert.NotNull(raw);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var protocolError))
            return (true, "protocol:" + protocolError.GetRawText());
        var result = root.GetProperty("result");
        if (result.TryGetProperty("error", out _))
            return (true, result.GetRawText());
        if (!result.TryGetProperty("content", out var content))
            return (true, "no-content:" + result.GetRawText());
        var isError = result.TryGetProperty("isError", out var flag) && flag.GetBoolean();
        var text = content[0].GetProperty("text").GetString() ?? "";
        return (isError, text);
    }

    // ========================================================================================
    // Debugger tools through the real stack
    // ========================================================================================

    [Fact]
    public async Task Snapshot_FlowsThroughDispatcherAndValidation()
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "GetAnalysisSnapshot", "{}");
        Assert.False(isError);
        Assert.Contains("0x140001000", text);
    }

    [Fact]
    public async Task StepAndTrace_FlowThroughDispatcher()
    {
        await using var harness = await Harness.StartAsync();
        var (stepError, stepText) = await CallAsync(harness.Server, "TraceUntil", "{\"count\":1,\"kind\":\"into\"}");
        Assert.False(stepError);
        Assert.Contains("0x140001000", stepText);
        var (traceError, _) = await CallAsync(harness.Server, "TraceUntil", "{\"maxSteps\":5}");
        Assert.False(traceError);
        var (bulkError, bulkText) = await CallAsync(harness.Server, "TraceUntil", "{\"count\":1,\"kind\":\"into\"}");
        Assert.False(bulkError);
        Assert.Contains("count_reached", bulkText);
    }

    [Theory]
    [InlineData("ReadMemAtAddress", "{\"address\":\"0x140001000\"}", "48895C24")]
    [InlineData("EvaluateExpressions", "{\"expressions\":[\"cip\"]}", "0x140001000")]
    [InlineData("ListThreads", "{}", "threadId")]
    [InlineData("GetBacktrace", "{}", "0x140001000")]
    [InlineData("GetMemoryMap", "{}", "PAGE_READONLY")]
    [InlineData("InspectAddressStructure", "{\"address\":\"cip\"}", "magic")]
    public async Task DebuggerReads_ReturnPayloads(string tool, string args, string expected)
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, tool, args);
        Assert.False(isError);
        Assert.Contains(expected, text);
    }

    [Theory]
    [InlineData("SetBreakpoint", "{\"address\":\"cip\"}", "setBreakpoint")]
    [InlineData("ClearBreakpoint", "{\"address\":\"cip\"}", "clearBreakpoint")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"run\"}", "runDebugger")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"pause\"}", "pauseDebugger")]
    [InlineData("SetRegister", "{\"register\":\"rax\",\"value\":\"0x0\"}", "rax")]
    [InlineData("WriteMemory", "{\"address\":\"csp\",\"hexBytes\":\"90 90\"}", "bytesWritten")]
    public async Task DebuggerMutations_Execute(string tool, string args, string expected)
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, tool, args);
        Assert.False(isError);
        Assert.Contains(expected, text);
    }

    [Fact]
    public async Task BatchDebugger_Works()
    {
        await using var harness = await Harness.StartAsync();
        // Bulk expression eval lives in top-level EvaluateExpressions, not in
        // batches: the batch mixes plain debugger ops in one round trip.
        var (isError, text) = await CallAsync(harness.Server, "BatchDebuggerOperations",
            "{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"cip\"}},{\"method\":\"ListBreakpoints\",\"arguments\":{}}]}");
        Assert.False(isError);
        Assert.Contains("48895C24", text);
    }

    [Fact]
    public async Task InvalidArguments_RejectedByDispatcherValidation()
    {
        await using var harness = await Harness.StartAsync();
        // Both surface as JSON-RPC errors (McpProtocolException -> error
        // envelope), with messages that name the problem for the agent.
        var (isError, invalidText) = await CallAsync(harness.Server, "ReadMemAtAddress", "{}");
        Assert.True(isError);
        Assert.StartsWith("protocol:", invalidText);
        Assert.Contains("ReadMemAtAddress", invalidText);
        var (unknownError, unknownText) = await CallAsync(harness.Server, "NoSuchTool", "{}");
        Assert.True(unknownError);
        Assert.StartsWith("protocol:", unknownText);
        Assert.Contains("Unknown tool", unknownText);
    }

    // ========================================================================================
    // Static (Ghidra-side) tools through the real stack
    // ========================================================================================

    [Theory]
    [InlineData("InspectFunction", "{\"function\":\"main\"}", "main")]
    [InlineData("DecompileModule", "{\"maxFunctions\":8}", "main")]
    [InlineData("Triage", "{\"kind\":\"strings\"}", "totalExamined")]
    [InlineData("Xrefs", "{\"address\":\"0x140001000\",\"direction\":\"to\"}", "xrefs")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\"}", "KERNEL32")]
    [InlineData("ListSymbols", "{\"kind\":\"exports\"}", "main")]
    [InlineData("ListFunctions", "{}", "main")]
    [InlineData("ReadStaticBytes", "{\"address\":\"0x140001000\",\"length\":4}", "48895C24")]
    public async Task StaticReads_ReturnPayloads(string tool, string args, string expected)
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, tool, args);
        Assert.False(isError);
        Assert.Contains(expected, text);
    }

    [Fact]
    public async Task BatchStatic_Works()
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "BatchStaticQueries",
            "{\"requests\":[{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"imports\"}}]}");
        Assert.False(isError);
        Assert.Contains("KERNEL32", text);
    }

    [Theory]
    [InlineData("BatchAnnotate", "{\"operations\":[{\"kind\":\"rename_function\",\"function\":\"main\",\"name\":\"my_main\"},{\"kind\":\"set_function_comment\",\"function\":\"main\",\"comment\":\"entry\"}]}")]
    [InlineData("SubmitAnnotations", "{\"operations\":[{\"kind\":\"rename_variable\",\"function\":\"main\",\"variable\":\"local_1\",\"name\":\"counter\"}]}")]
    public async Task GhidraMutations_Execute(string tool, string args)
    {
        await using var harness = await Harness.StartAsync();
        // P3: single-op mutate/annotate tools are purged; the batch superset
        // is the only annotation surface. Fat bridge rows come back slim.
        string batchAck(int id, JsonElement? _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"applied\":2,\"failed\":0,\"results\":[{{\"index\":0,\"kind\":\"rename_function\",\"function\":\"main\",\"name\":\"my_main\",\"committed\":true,\"journaled\":true}},{{\"index\":1,\"kind\":\"set_function_comment\",\"function\":\"main\",\"commentChars\":5,\"committed\":true,\"journaled\":true}}]}}}}";
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", batchAck);
        harness.Ghidra.RegisterTcpHandler("SubmitAnnotations", batchAck);
        var (isError, text) = await CallAsync(harness.Server, tool, args);
        Assert.False(isError);
        Assert.Contains("applied", text);
    }

    [Fact]
    public async Task InvestigationBrief_FlowsThrough()
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "GetInvestigationBrief", "{\"function\":\"main\"}");
        Assert.False(isError);
        Assert.Contains("main", text);
    }

    [Fact]
    public async Task StaticToTargetMapping_ResolvesAddress()
    {
        await using var harness = await Harness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, _) =>
            "{\"id\":" + id + ",\"ok\":true,\"result\":{\"function\":{\"name\":\"main\",\"entry\":\"0x140001000\",\"rva\":\"0x1000\",\"module\":{\"path\":\"C:\\\\test.exe\"}}}}");
        var (isError, text) = await CallAsync(harness.Server, "MapStaticFunctionToLive", "{\"function\":\"main\"}");
        Assert.False(isError);
        Assert.Contains("0x140001000", text);
    }

    // ========================================================================================
    // Checkpoints + sessions through the real stack
    // ========================================================================================

    [Fact]
    public async Task Checkpoints_RoundTripOnDiskFiles()
    {
        using var dir = TempDir.Create("dbglink-e2e-");
        var checkpointPath = Path.Combine(dir, "latest.json");
        await using var harness = await Harness.StartAsync(checkpointPath);
        var sha = new string('a', 64);
        var (createError, _) = await CallAsync(harness.Server, "Checkpoint",
            "{\"action\":\"create\",\"sha256\":\"" + sha + "\",\"title\":\"t\",\"findings\":\"f\",\"hypotheses\":\"h\",\"verified\":\"v\",\"nextStep\":\"n\"}");
        Assert.False(createError);
        Assert.True(File.Exists(checkpointPath));
        var (getError, getText) = await CallAsync(harness.Server, "Checkpoint",
            "{\"action\":\"restore\",\"sha256\":\"" + sha + "\"}");
        Assert.False(getError);
        Assert.Contains(sha, getText);
    }

    [Fact]
    public async Task SessionTools_FlowThroughDispatcher()
    {
        await using var harness = await Harness.StartAsync();
        var (listError, listText) = await CallAsync(harness.Server, "ListAnalysisSessions", "{}");
        Assert.False(listError, listText);
        Assert.Contains("default", listText);
    }

    [Fact]
    public async Task OpenDebugTarget_FlowsThroughSwitchAndBridge()
    {
        using var dir = TempDir.Create("dbglink-e2e-");
        var target = Path.Combine(dir, "target.exe");
        File.WriteAllBytes(target, new byte[4096]);
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "OpenDebugTarget",
            "{\"path\":" + JsonSerializer.Serialize(target) + ",\"architecture\":\"x64\"}");
        Assert.False(isError, text);
        Assert.Contains("default", text);
    }

    [Fact]
    public async Task ServerStatus_ReportsBridgeState()
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "GetServerStatus", "{}");
        Assert.False(isError);
        Assert.Contains(harness.Pipe.ProcessId.ToString(), text);
    }
}
