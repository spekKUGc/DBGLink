using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Wire-mock tests for ListLiveFunctions: every test goes through
// LocalMcpServer.CallToolAsync with a scripted native bridge answering
// GetModuleFunctions, i.e. the same path production MCP traffic takes.
public sealed class ListLiveFunctionsTests
{
    private static LocalMcpServer CreateServer(ScriptedBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

    private static Dictionary<string, JsonElement> Args(string json) => TestWire.Args(json);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    [Fact]
    public async Task ListLiveFunctions_forwards_module_and_maxItems_to_bridge()
    {
        var bridge = new ScriptedBridge().On("GetModuleFunctions", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"module\":{\"name\":\"app.exe\",\"base\":\"0x0000000140000000\"}," +
            "\"source\":\"x64dbg\",\"functions\":[{\"entry\":\"0x0000000140001000\",\"rva\":\"0x1000\"," +
            "\"name\":\"main\",\"end\":\"0x0000000140001080\"}],\"returnedCount\":1,\"truncated\":false}"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ListLiveFunctions",
            Arguments = Args("{\"module\":\"app.exe\",\"maxItems\":10}"),
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
        Assert.Equal("GetModuleFunctions", bridge.Calls[0].Method);
        Assert.Contains("app.exe", bridge.Calls[0].ArgsJson);
        Assert.Contains("10", bridge.Calls[0].ArgsJson);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal("x64dbg", doc.RootElement.GetProperty("source").GetString());
        var functions = doc.RootElement.GetProperty("functions");
        Assert.Equal(1, functions.GetArrayLength());
        Assert.Equal("0x0000000140001000", functions[0].GetProperty("entry").GetString());
        Assert.Equal("0x1000", functions[0].GetProperty("rva").GetString());
        Assert.Equal("main", functions[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task ListLiveFunctions_exports_fallback_reports_honest_source()
    {
        var bridge = new ScriptedBridge().On("GetModuleFunctions", ScriptedBridge.Ok(
            "{\"schemaVersion\":1,\"source\":\"exports\",\"functions\":[{\"entry\":\"0x0000000140002000\"," +
            "\"rva\":\"0x2000\",\"name\":\"ExportedFn\"}],\"returnedCount\":1,\"truncated\":false}"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ListLiveFunctions",
            Arguments = Args("{\"module\":\"app.exe\"}"),
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
        Assert.False(result.IsError == true);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.Equal("exports", doc.RootElement.GetProperty("source").GetString());
    }

    [Theory]
    [InlineData("{\"module\":\"app.exe\",\"maxItems\":0}")]
    [InlineData("{\"module\":\"app.exe\",\"maxItems\":4097}")]
    public async Task ListLiveFunctions_rejects_out_of_range_maxItems_before_bridge(string json)
    {
        var bridge = new ScriptedBridge();
        using var server = CreateServer(bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            server.CallToolAsync(new CallToolRequestParams
            {
                Name = "ListLiveFunctions",
                Arguments = Args(json),
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task ListLiveFunctions_bridge_error_returns_readable_tool_error()
    {
        var bridge = new ScriptedBridge().On("GetModuleFunctions",
            ScriptedBridge.Error("native_error", "GetModuleFunctions: no loaded module matches 'nope.exe'."));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ListLiveFunctions",
            Arguments = Args("{\"module\":\"nope.exe\"}"),
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
        Assert.True(result.IsError == true);
        Assert.Contains("no loaded module", TextOf(result));
    }

    [Fact]
    public void ListLiveFunctions_schema_caps_maxItems_at_4096()
    {
        using var server = CreateServer(new ScriptedBridge());
        // The tool is a hidden alias now (callable, not advertised): the cap is
        // still enforced by validation against its own schema.
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), x => x["name"]!.GetValue<string>() == "ListLiveFunctions");
        // Schema caps are still enforced for direct calls; the tool is just not advertised.
    }
}
