using System.Runtime.Versioning;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Verifies every debugger, inspection, search, control, checkpoint, and session command
/// against REALLY OPENED SERVERS:
/// 1. Live Kestrel HTTP MCP Server over loopback TCP (http://127.0.0.1:{port}/mcp)
/// 2. Live Win32 Message-Mode Named Pipe Server (\\.\pipe\DbgLink.Control.{pid})
/// 3. Live Ghidra Control Pipe Server and Live Ghidra TCP Endpoint Server
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class RealOpenedServerCommandTests
{
    private static string ExtractText(CallToolResult result)
    {
        Assert.NotNull(result);
        Assert.False(result.IsError == true, $"Tool returned an error: {JsonSerializer.Serialize(result)}");
        var content = Assert.Single(result.Content);
        return Assert.IsType<TextContentBlock>(content).Text;
    }

    // =========================================================================
    // 1. STATUS & INSPECTION COMMANDS OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_GetServerStatus_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("GetServerStatus");
        var text = ExtractText(result);

        Assert.Contains("DBGLink", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_GetAnalysisSnapshot_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("GetAnalysisSnapshot", new
        {
            maxFrames = 8,
            instructionBytes = 64,
            stackBytes = 64
        });
        var text = ExtractText(result);

        Assert.Contains("schemaVersion", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_TraceUntilWithCount_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("TraceUntil", new
        {
            count = 1,
            kind = "into",
            includeModules = false
        });
        var text = ExtractText(result);

        Assert.Contains("schemaVersion", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_TraceUntil_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("TraceUntil", new
        {
            kind = "into",
            maxSteps = 5
        });
        var text = ExtractText(result);

        Assert.Contains("schemaVersion", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    // =========================================================================
    // 2. MEMORY & REGISTERS OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_ReadMemAtAddress_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("ReadMemAtAddress", new
        {
            address = "0x140001000",
            byteCount = 10
        });
        var text = ExtractText(result);

        Assert.Contains("48895C240848896C2410", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_InspectAddressStructure_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("InspectAddressStructure", new
        {
            address = "0x140001000",
            pointerCount = 4
        });
        var text = ExtractText(result);

        Assert.Contains("magic", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_GetMemoryMap_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("GetMemoryMap");
        var text = ExtractText(result);

        Assert.Contains("PAGE_EXECUTE_READ", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_EvaluateExpressions_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("EvaluateExpressions", new
        {
            expressions = new[] { "cip" }
        });
        var text = ExtractText(result);

        Assert.Contains("0x140001000", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_Threads_and_Backtrace_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var threadsRes = await harness.CallToolOverWireAsync("ListThreads");
        var threadsText = ExtractText(threadsRes);
        Assert.Contains("threadId", threadsText);

        var backtraceRes = await harness.CallToolOverWireAsync("GetBacktrace");
        var backtraceText = ExtractText(backtraceRes);
        Assert.Contains("0x140001000", backtraceText);

        Assert.True(harness.NativePipeServer.RequestCount >= 2);
    }

    // =========================================================================
    // 3. SEARCH & STRING COMMANDS OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_FindBytePatternInModule_executes_over_wire_via_batch()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // Top-level single is purged (P3): the pattern search lives in
        // BatchDebuggerOperations; the bridge handler is unchanged.
        var result = await harness.CallToolOverWireAsync("BatchDebuggerOperations", new
        {
            requests = new object[]
            {
                new { method = "FindBytePatternInModule", arguments = new { module = "test.exe", pattern = "48 89 5C 24" } },
            }
        });
        var text = ExtractText(result);

        Assert.Contains("0x140001000", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_Triage_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // P3: TriageStrings alias purged; Triage(kind=strings) is the cover.
        var result = await harness.CallToolOverWireAsync("Triage", new
        {
            kind = "strings",
            section = ".rdata"
        });
        var text = ExtractText(result);

        Assert.Contains("totalExamined", text);
    }

    // =========================================================================
    // 4. DEBUGGER CONTROL COMMANDS OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_Breakpoints_lifecycle_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // 1. SetBreakpoint
        var setRes = await harness.CallToolOverWireAsync("SetBreakpoint", new
        {
            address = "0x140001000",
            kind = "soft"
        });
        Assert.Contains("setBreakpoint", ExtractText(setRes));

        // 2. ListBreakpoints (batch-only single since the P3 cut)
        var listRes = await harness.CallToolOverWireAsync("BatchDebuggerOperations", new
        {
            requests = new object[]
            {
                new { method = "ListBreakpoints", arguments = new { } }
            }
        });
        Assert.Contains("0x140001000", ExtractText(listRes));

        // 3. ClearBreakpoint
        var clearRes = await harness.CallToolOverWireAsync("ClearBreakpoint", new
        {
            address = "0x140001000"
        });
        Assert.Contains("clearBreakpoint", ExtractText(clearRes));

        Assert.True(harness.NativePipeServer.RequestCount >= 3);
    }

    [Fact]
    public async Task RealServer_ControlDebuggerExecution_run_and_pause_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var run = await harness.CallToolOverWireAsync("ControlDebuggerExecution", new { action = "run" });
        Assert.Contains("runDebugger", ExtractText(run));

        var pause = await harness.CallToolOverWireAsync("ControlDebuggerExecution", new { action = "pause" });
        Assert.Contains("pauseDebugger", ExtractText(pause));

        Assert.True(harness.NativePipeServer.RequestCount >= 2);
    }

    [Fact]
    public async Task RealServer_State_Mutation_commands_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var regRes = await harness.CallToolOverWireAsync("SetRegister", new
        {
            register = "rax",
            value = "0x42"
        });
        Assert.Contains("rax", ExtractText(regRes));

        var memRes = await harness.CallToolOverWireAsync("WriteMemory", new
        {
            address = "0x140001000",
            hexBytes = "90 90 90 90"
        });
        Assert.Contains("bytesWritten", ExtractText(memRes));

        Assert.True(harness.NativePipeServer.RequestCount >= 2);
    }

    [Fact]
    public async Task RealServer_BatchDebuggerOperations_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // Bulk expression eval lives in top-level EvaluateExpressions, not in
        // batches: the batch mixes plain debugger ops in one round trip.
        var batchRes = await harness.CallToolOverWireAsync("BatchDebuggerOperations", new
        {
            requests = new object[]
            {
                new { method = "ReadMemAtAddress", arguments = new { address = "cip" } },
                new { method = "ListBreakpoints", arguments = new { } }
            }
        });
        var text = ExtractText(batchRes);

        using var doc = JsonDocument.Parse(text);
        var node = doc.RootElement.TryGetProperty("result", out var result) ? result : doc.RootElement;
        var rows = node.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.Equal(0, rows[0].GetProperty("index").GetInt32());
        Assert.Equal(1, rows[1].GetProperty("index").GetInt32());
        Assert.True(harness.NativePipeServer.RequestCount >= 2);
    }

    // =========================================================================
    // 5. CHECKPOINT & HIGH-LEVEL INVESTIGATION OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_Checkpoints_create_and_retrieve_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        const string sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        var createRes = await harness.CallToolOverWireAsync("Checkpoint", new
        {
            action = "create",
            sha256,
            title = "Test Session",
            findings = "Discovered key function",
            hypotheses = "Suspected buffer check",
            verified = "Verified address",
            nextStep = "Step over",
            context = "CIP=0x140001000"
        });
        Assert.Contains("saved", ExtractText(createRes));

        var getRes = await harness.CallToolOverWireAsync("Checkpoint", new
        {
            action = "restore",
            sha256
        });
        var text = ExtractText(getRes);
        Assert.Contains("Test Session", text);
        Assert.Contains("Discovered key function", text);
    }

    [Fact]
    public async Task RealServer_GetInvestigationBrief_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var result = await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "main"
        });
        var text = ExtractText(result);

        Assert.Contains("schemaVersion", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    // =========================================================================
    // 6. GHIDRA & SESSION CONTROL OVER REAL OPENED SERVERS
    // =========================================================================

    [Fact]
    public async Task RealServer_Ghidra_Static_Commands_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var inspectRes = await harness.CallToolOverWireAsync("InspectFunction", new
        {
            function = "main"
        });
        var inspectText = ExtractText(inspectRes);
        Assert.Contains("int main()", inspectText);

        var decompileRes = await harness.CallToolOverWireAsync("DecompileModule", new
        {
            maxFunctions = 2
        });
        var decompileText = ExtractText(decompileRes);
        Assert.Contains("int main()", decompileText);

        var listFuncs = await harness.CallToolOverWireAsync("ListFunctions");
        Assert.Contains("main", ExtractText(listFuncs));

        var listImports = await harness.CallToolOverWireAsync("ListSymbols", new { kind = "imports" });
        Assert.Contains("KERNEL32", ExtractText(listImports));

        var listExports = await harness.CallToolOverWireAsync("ListSymbols", new { kind = "exports" });
        Assert.Contains("main", ExtractText(listExports));

        var stringsRes = await harness.CallToolOverWireAsync("Triage", new
        {
            kind = "strings",
            section = ".rdata"
        });
        Assert.Contains("totalExamined", ExtractText(stringsRes));

        var bytesRes = await harness.CallToolOverWireAsync("ReadStaticBytes", new
        {
            address = "0x140001000",
            length = 16
        });
        Assert.Contains("48895C2408", ExtractText(bytesRes));

        var xrefsRes = await harness.CallToolOverWireAsync("Xrefs", new
        {
            address = "0x140001000",
            direction = "to"
        });
        Assert.Contains("xrefs", ExtractText(xrefsRes));
    }

    [Fact]
    public async Task RealServer_Ghidra_Mutations_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // P3: single-op RenameFunction/UpdateVariable purged; one
        // BatchAnnotate transaction covers rename + vartype.
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"applied\":3,\"failed\":0,\"results\":[{{\"index\":0,\"kind\":\"rename_function\",\"function\":\"main\",\"name\":\"my_main\",\"committed\":true,\"journaled\":true}},{{\"index\":1,\"kind\":\"rename_variable\",\"function\":\"main\",\"variable\":\"local_1\",\"name\":\"counter\",\"committed\":true,\"journaled\":true}},{{\"index\":2,\"kind\":\"set_variable_type\",\"function\":\"main\",\"variable\":\"counter\",\"type\":\"int\",\"committed\":true,\"journaled\":true}}]}}}}");

        var batch = await harness.CallToolOverWireAsync("BatchAnnotate", new
        {
            operations = new object[]
            {
                new { kind = "rename_function", function = "main", name = "my_main" },
                new { kind = "rename_variable", function = "main", variable = "local_1", name = "counter" },
                new { kind = "set_variable_type", function = "main", variable = "counter", type = "int" },
            },
        });
        var text = ExtractText(batch);
        Assert.Contains("applied", text);
        Assert.Contains("my_main", text);
    }

    [Fact]
    public async Task RealServer_Session_Control_Commands_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var listRes = await harness.CallToolOverWireAsync("ListAnalysisSessions");
        var listText = ExtractText(listRes);
        Assert.Contains("default", listText);
        Assert.Contains("activeAnalysisId", listText);
    }

    [Fact]
    public async Task RealServer_OpenDebugTarget_executes_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var targetPath = GetFixturePath("HardenedStressTarget.exe");

        var result = await harness.CallToolOverWireAsync("OpenDebugTarget", new
        {
            path = targetPath
        });
        var text = ExtractText(result);

        Assert.Contains("openDebugTarget", text);
        Assert.True(harness.NativePipeServer.RequestCount >= 1);
    }

    [Fact]
    public async Task RealServer_OpenGhidraFile_and_GetGhidraOpenStatus_execute_over_wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var targetPath = GetFixturePath("HardenedStressTarget.exe");

        var openRes = await harness.CallToolOverWireAsync("OpenGhidraFile", new
        {
            path = targetPath,
            waitMs = 0
        });
        var openText = ExtractText(openRes);
        Assert.Contains("operationId", openText);

        using var doc = JsonDocument.Parse(openText);
        var opId = doc.RootElement.GetProperty("operationId").GetString();
        Assert.NotNull(opId);

        // Long-poll: a zero-wait status read races the async import completion
        // under load (returns pending/importing), so wait for the terminal state
        // instead of asserting on a single immediate poll.
        var statusRes = await harness.CallToolOverWireAsync("GetGhidraOpenStatus", new
        {
            operationId = opId,
            waitMs = 15000
        });
        var statusText = ExtractText(statusRes);
        Assert.Contains("\"opened\":true", statusText);
    }

    private static string GetFixturePath(string filename)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "artifacts", "fixtures", "x64", filename);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException($"Compiled fixture binary was not found: {filename}");
    }

    // =========================================================================
    // 7. ERROR PATHS OVER REAL OPENED SERVERS (WIRE RESILIENCE)
    // =========================================================================

    [Fact]
    public async Task RealServer_Unknown_Tool_Returns_Protocol_Error_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("NoSuchTool", new { }));
        Assert.NotEmpty(error.Message);
    }

    [Fact]
    public async Task RealServer_Schema_Violations_Rejected_Over_Wire_Before_Bridge()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var before = harness.NativePipeServer.RequestCount;

        // Invalid hex never reaches the native pipe.
        await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("WriteMemory", new { address = "0x140001000", hexBytes = "ZZ" }));

        // byteCount minimum is 1.
        await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ReadMemAtAddress", new { address = "0x140001000", byteCount = 0 }));

        // Unknown debugger action is not forwarded.
        await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ControlDebuggerExecution", new { action = "bogus" }));

        Assert.Equal(before, harness.NativePipeServer.RequestCount);
    }

    [Fact]
    public async Task RealServer_Invalid_Batch_Surfaces_InvalidBatch_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        using var doc = await harness.CallToolRawAsync("BatchDebuggerOperations", new
        {
            requests = new object[]
            {
                new { method = "ReadMemAtAddress", arguments = new { address = "cip" } },
                new { method = "DropDatabase", arguments = new { } },
            }
        });
        var root = doc.RootElement;
        Assert.False(root.TryGetProperty("error", out _));
        var result = root.GetProperty("result");
        Assert.True(result.GetProperty("isError").GetBoolean());
        var text = result.GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        Assert.Contains("invalid_batch", text);
        Assert.Contains("DropDatabase", text);
    }

    [Fact]
    public async Task RealServer_ToolsList_Advertises_Core_Commands_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var tools = await harness.ListToolsOverWireAsync();
        var names = tools.Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var expected in new[]
        {
            "GetServerStatus", "GetAnalysisSnapshot", "ReadMemAtAddress",
            "EvaluateExpressions", "SetBreakpoint", "BatchDebuggerOperations",
            "Checkpoint", "ListAnalysisSessions",
        })
            Assert.Contains(expected, names);
    }

    [Fact]
    public async Task RealServer_ListThreads_Pagination_And_Filtered_MemoryMap_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var threads = await harness.CallToolOverWireAsync("ListThreads", new
        {
            offset = 0,
            maxItems = 1
        });
        Assert.Contains("threadId", ExtractText(threads));

        var filtered = await harness.CallToolOverWireAsync("GetMemoryMap", new
        {
            executableOnly = true,
            rwxOnly = true,
            maxItems = 8
        });
        Assert.Contains("PAGE_", ExtractText(filtered));
        Assert.True(harness.NativePipeServer.RequestCount >= 2);
    }

    [Fact]
    public async Task RealServer_Checkpoint_Bad_Sha_Rejected_Before_Bridge()
    {
        await using var harness = await RealServerHarness.StartAsync();

        foreach (var badSha in new[] { "not-hex", new string('0', 63), new string('0', 65), "" })
        {
            await Assert.ThrowsAsync<McpProtocolException>(() =>
                harness.CallToolOverWireAsync("Checkpoint", new
                {
                    action = "create",
                    sha256 = badSha,
                    title = "t",
                    findings = "f",
                    hypotheses = "h",
                    verified = "v",
                    nextStep = "n",
                }));
        }
    }
}

