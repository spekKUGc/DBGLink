using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Live dispatcher tests for the debugger-control tools: every test goes through
// LocalMcpServer.CallToolAsync (validation -> capability gate -> queue ->
// bridge -> response mapping) with a scripted native bridge, i.e. the same
// path production MCP traffic takes, minus the real x64dbg process.
public sealed class LiveDebuggerControlTests
{
    private static LocalMcpServer CreateServer(ScriptedBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);

    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private static async Task<CallToolResult> CallAsync(
        LocalMcpServer server, ScriptedBridge bridge, string name, string json)
    {
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = Args(json) },
            CancellationToken.None);
        return result;
    }

    [Fact]
    public async Task Live01_SetBreakpoint_forwards_address_and_kind_to_bridge()
    {
        var bridge = new ScriptedBridge().On("SetBreakpoint",
            ScriptedBridge.Ok("{\"action\":\"setBreakpoint\",\"kind\":\"soft\",\"address\":\"0x0000000140001000\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "SetBreakpoint", "{\"address\":\"cip\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("SetBreakpoint", bridge.Calls[0].Method);
        Assert.Contains("cip", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        Assert.Contains("setBreakpoint", TextOf(result));
    }

    [Fact]
    public async Task Live02_SetBreakpoint_rejects_blank_address_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "SetBreakpoint",
                Arguments = Args("{\"address\":\" \"}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live03_SetBreakpoint_closed_sets_rejected_before_bridge()
    {
        // hwSize allows only 1/2/4/8 (x-allowedInts) and kind/hwType/memType are
        // pattern-locked: invalid values fail fast with InvalidParams, no bridge call.
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        foreach (var json in new[]
        {
            "{\"address\":\"cip\",\"kind\":\"hw\",\"hwType\":\"x\",\"hwSize\":3}",
            "{\"address\":\"cip\",\"kind\":\"bogus\"}",
            "{\"address\":\"cip\",\"kind\":\"hw\",\"hwType\":\"z\"}",
            "{\"address\":\"cip\",\"kind\":\"mem\",\"memType\":\"q\"}",
        })
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
                server.CallToolAsync(new CallToolRequestParams
                {
                    Name = "SetBreakpoint",
                    Arguments = Args(json),
                }, CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }
        Assert.Equal(0, bridge.RequestCount);

        // The closed set still admits every legal combination.
        foreach (var json in new[]
        {
            "{\"address\":\"cip\",\"kind\":\"hw\",\"hwType\":\"x\",\"hwSize\":4}",
            "{\"address\":\"cip\",\"kind\":\"mem\",\"memType\":\"r\"}",
        })
        {
            var result = await CallAsync(server, bridge, "SetBreakpoint", json);
            Assert.False(result.IsError == true);
        }
        Assert.Equal(2, bridge.RequestCount);
    }

    [Fact]
    public async Task Live04_ClearBreakpoint_all_without_address_reaches_bridge()
    {
        var bridge = new ScriptedBridge().On("ClearBreakpoint",
            ScriptedBridge.Ok("{\"action\":\"clearBreakpoint\",\"cleared\":\"all\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ClearBreakpoint", "{\"all\":true}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.False(result.IsError == true);
        Assert.Contains("clearBreakpoint", TextOf(result));
    }

    [Fact]
    public async Task Live05_ClearBreakpoint_neither_address_nor_all_returns_readable_tool_error()
    {
        var bridge = new ScriptedBridge().On("ClearBreakpoint",
            ScriptedBridge.Error("native_error", "ClearBreakpoint requires address or all=true."));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ClearBreakpoint", "{}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("address or all", TextOf(result));
    }

    [Fact]
    public async Task Live07_ClearBreakpoint_with_address_forwards_to_bridge()
    {
        var bridge = new ScriptedBridge().On("ClearBreakpoint",
            ScriptedBridge.Ok("{\"action\":\"clearBreakpoint\",\"cleared\":1}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ClearBreakpoint", "{\"address\":\"cip\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("ClearBreakpoint", bridge.Calls[0].Method);
        Assert.Contains("cip", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        Assert.Contains("clearBreakpoint", TextOf(result));
    }

    [Fact]
    public async Task Live08_ControlDebuggerExecution_bogus_action_rejected_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "ControlDebuggerExecution",
                Arguments = Args("{\"action\":\"step\"}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live10_ControlDebuggerExecution_run_routes_to_bridge_run()
    {
        var bridge = new ScriptedBridge().On("RunDebugger",
            ScriptedBridge.Ok("{\"action\":\"run\",\"alreadyRunning\":true}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ControlDebuggerExecution", "{\"action\":\"run\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("RunDebugger", bridge.Calls[0].Method);
        Assert.False(result.IsError == true);
        Assert.Contains("alreadyRunning", TextOf(result));
    }

    [Fact]
    public async Task Live11_ControlDebuggerExecution_pause_carries_poll_followup_hint()
    {
        var bridge = new ScriptedBridge().On("PauseDebugger", ScriptedBridge.Ok(
            "{\"action\":\"pause\",\"requested\":true," +
            "\"followUp\":\"Poll GetAnalysisSnapshot until consistency==unchanged.\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ControlDebuggerExecution", "{\"action\":\"pause\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("PauseDebugger", bridge.Calls[0].Method);
        Assert.False(result.IsError == true);
        Assert.Contains("GetAnalysisSnapshot", TextOf(result));
    }


    [Fact]
    public async Task Live13_SetRegister_roundtrip_reports_old_and_new_values()
    {
        var bridge = new ScriptedBridge().On("SetRegister", ScriptedBridge.Ok(
            "{\"action\":\"setRegister\",\"register\":\"rax\"," +
            "\"oldValue\":\"0x0000000000000000\",\"newValue\":\"0x0000000140001000\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "SetRegister",
            "{\"register\":\"rax\",\"value\":\"0x140001000\"}");

        Assert.Equal(1, bridge.RequestCount);
        var text = TextOf(result);
        Assert.Contains("oldValue", text);
        Assert.Contains("0x0000000140001000", text);
    }

    [Fact]
    public async Task Live14_SetRegister_rejects_bad_pattern_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "SetRegister",
                Arguments = Args("{\"register\":\"rax!\",\"value\":\"0x0\"}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live15_WriteMemory_forwards_hex_and_reports_next_address()
    {
        var bridge = new ScriptedBridge().On("WriteMemory", ScriptedBridge.Ok(
            "{\"action\":\"writeMemory\",\"address\":\"0x0000000000001000\"," +
            "\"bytesWritten\":2,\"nextAddress\":\"0x0000000000001002\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "WriteMemory",
            "{\"address\":\"csp\",\"hexBytes\":\"90 90\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Contains("90 90", bridge.Calls[0].ArgsJson);
        Assert.Contains("nextAddress", TextOf(result));
    }

    [Fact]
    public async Task Live16_WriteMemory_oversized_native_error_is_tool_error()
    {
        var bridge = new ScriptedBridge().On("WriteMemory",
            ScriptedBridge.Error("native_error", "WriteMemory Too many bytes (max 4096 per call; page large patches)."));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "WriteMemory",
            "{\"address\":\"csp\",\"hexBytes\":\"90 90\"}");

        Assert.True(result.IsError == true);
        Assert.Contains("4096", TextOf(result));
    }

    [Fact]
    public async Task Live19_ListThreads_surfaces_current_thread()
    {
        var bridge = new ScriptedBridge().On("ListThreads", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"totalCount\":2,\"returnedCount\":2,\"currentThread\":0," +
            "\"truncated\":false,\"threads\":[]}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ListThreads", "{\"maxItems\":128}");

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal(0, doc.RootElement.GetProperty("currentThread").GetInt32());
        Assert.Equal(2, doc.RootElement.GetProperty("totalCount").GetInt32());
    }

    [Fact]
    public async Task Live21_GetBacktrace_paging_contract_roundtrips()
    {
        var bridge = new ScriptedBridge().On("GetBacktrace", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"startFrame\":0,\"returnedCount\":8,\"walkedFrames\":20," +
            "\"truncated\":true,\"nextFrame\":8,\"frames\":[]}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "GetBacktrace", "{\"maxFrames\":8}");

        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal(8, doc.RootElement.GetProperty("nextFrame").GetInt32());
    }


    [Fact]
    public async Task Live22_EvaluateExpressions_duplicate_expressions_share_one_bridge_call()
    {
        var bridge = new ScriptedBridge().On("EvaluateExpression",
            ScriptedBridge.Ok("{\"expression\":\"cip\",\"valueHex\":\"0x0000000140001000\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "EvaluateExpressions", "{\"expressions\":[\"cip\",\"cip\"]}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.False(result.IsError == true);
        var text = TextOf(result);
        Assert.Contains("\"index\":0", text);
        Assert.Contains("\"index\":1", text);
    }

    [Fact]
    public async Task Live23_WriteMemory_nonhex_rejected_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        foreach (var json in new[]
        {
            "{\"address\":\"csp\",\"hexBytes\":\"zz\"}",
            "{\"address\":\"csp\",\"hexBytes\":\"9\"}",
        })
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
                server.CallToolAsync(new CallToolRequestParams
                {
                    Name = "WriteMemory",
                    Arguments = Args(json),
                }, CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live24_Bridge_throw_becomes_tool_error_not_crash()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new ThrowingBridge());

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = Args("{\"address\":\"cip\"}"),
        }, CancellationToken.None);

        // Backend failures are reported inside the result (isError=true)
        // instead of surfacing as a protocol-level internal error.
        Assert.True(result.IsError);
        Assert.Contains("backend component failed",
            Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content)).Text);
    }

    [Fact]
    public async Task Live25_Unknown_argument_is_rejected_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "SetBreakpoint",
                Arguments = Args("{\"address\":\"cip\",\"bogus\":1}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("bogus", error.Message);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live26_EvaluateExpressions_forwards_single_expression_to_bridge()
    {
        var bridge = new ScriptedBridge().On("EvaluateExpression",
            ScriptedBridge.Ok("{\"expression\":\"[rsp+8]\",\"valueHex\":\"0x0000000140001000\",\"valueUnsigned\":\"5368713216\",\"valueSigned\":\"5368713216\",\"dereference\":\"0x0000000000000000\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "EvaluateExpressions", "{\"expressions\":[\"[rsp+8]\"]}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("EvaluateExpression", bridge.Calls[0].Method);
        Assert.Contains("rsp", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        Assert.Contains("0x0000000140001000", TextOf(result));
    }

    [Fact]
    public async Task Live27_GetMemoryMap_forwards_rwx_and_executable_flags()
    {
        var bridge = new ScriptedBridge().On("GetMemoryMap",
            ScriptedBridge.Ok("{\"pages\":[{\"baseAddress\":\"0x0000000140000000\",\"isRwx\":true}],\"totalMatched\":1,\"truncated\":false}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "GetMemoryMap", "{\"rwxOnly\":true,\"executableOnly\":true}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("GetMemoryMap", bridge.Calls[0].Method);
        Assert.Contains("\"rwxOnly\":true", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        Assert.Contains("0x0000000140000000", TextOf(result));
    }


    [Fact]
    public async Task Live28_GetMemoryMap_invalid_type_rejected_before_bridge()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetMemoryMap",
                Arguments = Args("{\"type\":\"bogus\"}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live29_ListThreads_offset_paging_forwards_to_bridge()
    {
        var bridge = new ScriptedBridge().On("ListThreads", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"totalCount\":10,\"returnedCount\":2,\"currentThread\":0," +
            "\"truncated\":true,\"threads\":[]}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "ListThreads", "{\"maxItems\":2,\"offset\":4}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Contains("4", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal(10, doc.RootElement.GetProperty("totalCount").GetInt32());
    }

    [Fact]
    public async Task Live30_GetBacktrace_startFrame_paging_forwards_to_bridge()
    {
        var bridge = new ScriptedBridge().On("GetBacktrace", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"startFrame\":8,\"returnedCount\":8,\"walkedFrames\":20," +
            "\"truncated\":true,\"nextFrame\":16,\"frames\":[]}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "GetBacktrace", "{\"maxFrames\":8,\"startFrame\":8}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Contains("8", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal(16, doc.RootElement.GetProperty("nextFrame").GetInt32());
    }

    [Fact]
    public async Task Live30b_Memory_opt_ins_forward_to_bridge()
    {
        // ReadMemAtAddress includeAscii/spacedHex, InspectAddressStructure
        // includeAscii/spacedHex, and GetMemoryMap fullProtect are additive
        // opt-ins: absent stays the historical call, explicit true forwards.
        var bridge = new ScriptedBridge()
            .On("ReadMemAtAddress", ScriptedBridge.Ok("{\"bytes\":\"90\"}"))
            .On("InspectAddressStructure", ScriptedBridge.Ok("{\"address\":\"cip\"}"))
            .On("GetMemoryMap", ScriptedBridge.Ok("{\"pages\":[],\"totalMatched\":0,\"truncated\":false}"));
        using var server = CreateServer(bridge);

        var read = await CallAsync(server, bridge, "ReadMemAtAddress",
            "{\"address\":\"cip\",\"includeAscii\":true,\"spacedHex\":true}");
        Assert.False(read.IsError == true);
        Assert.Contains("includeAscii", bridge.Calls[0].ArgsJson);
        Assert.Contains("spacedHex", bridge.Calls[0].ArgsJson);

        var inspect = await CallAsync(server, bridge, "InspectAddressStructure",
            "{\"address\":\"cip\",\"includeAscii\":true,\"spacedHex\":true}");
        Assert.False(inspect.IsError == true);
        Assert.Contains("includeAscii", bridge.Calls[1].ArgsJson);
        Assert.Contains("spacedHex", bridge.Calls[1].ArgsJson);

        var map = await CallAsync(server, bridge, "GetMemoryMap", "{\"fullProtect\":true}");
        Assert.False(map.IsError == true);
        Assert.Contains("fullProtect", bridge.Calls[2].ArgsJson);

        // Wrong types never reach a backend.
        foreach (var (tool, json) in new[]
        {
            ("ReadMemAtAddress", "{\"address\":\"cip\",\"includeAscii\":\"yes\"}"),
            ("ReadMemAtAddress", "{\"address\":\"cip\",\"spacedHex\":1}"),
            ("InspectAddressStructure", "{\"address\":\"cip\",\"includeAscii\":1}"),
            ("GetMemoryMap", "{\"fullProtect\":\"yes\"}"),
        })
        {
            var before = bridge.RequestCount;
            await Assert.ThrowsAsync<McpProtocolException>(() =>
                server.CallToolAsync(new CallToolRequestParams
                {
                    Name = tool,
                    Arguments = Args(json),
                }, CancellationToken.None));
            Assert.Equal(before, bridge.RequestCount);
        }
    }

    [Fact]
    public async Task Live31_SetBreakpoint_accepts_condition_and_logText()
    {
        var bridge = new ScriptedBridge().On("SetBreakpoint",
            ScriptedBridge.Ok("{\"action\":\"setBreakpoint\",\"kind\":\"soft\",\"address\":\"0x0000000140001000\",\"condition\":\"eax==1\",\"logText\":\"eax={eax}\"}"));
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "SetBreakpoint", "{\"address\":\"cip\",\"condition\":\"eax==1\",\"logText\":\"eax={eax}\"}");

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("SetBreakpoint", bridge.Calls[0].Method);
        Assert.Contains("eax==1", bridge.Calls[0].ArgsJson);
        Assert.Contains("eax={eax}", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        Assert.Contains("eax==1", TextOf(result));
    }

    [Fact]
    public async Task Live32_SetBreakpoint_without_address_or_module_rva_rejected()
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "SetBreakpoint",
                Arguments = Args("{}"),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"expressions\":[]}")]
    [InlineData("{\"expressions\":[\"\"]}")]
    public async Task Live34_EvaluateExpressions_empty_or_blank_item_rejected_before_bridge(string json)
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "EvaluateExpressions",
                Arguments = Args(json),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Live35_EvaluateExpressions_whitespace_item_is_tool_error_without_bridge_call()
    {
        // A whitespace-only item passes the string schema (minLength 1) but
        // the executor rejects it as a per-call error result, not a throw,
        // and no backend request goes out.
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var result = await CallAsync(server, bridge, "EvaluateExpressions", "{\"expressions\":[\" \"]}");

        Assert.Equal(0, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("non-blank", TextOf(result));
    }
}
