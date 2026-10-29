using System.Text.Json;
using DbgLink.Server;
using Xunit;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// Blind-agent friction: a wrong argument name cost a round trip with a bare
/// "Unsupported argument" message, and reading a wide string meant hand-decoding
/// UTF-16LE hex. The error now names the accepted keys and ReadMemAtAddress can
/// decode the bytes itself.
/// </summary>
public sealed class ArgumentHintAndUtf16Tests
{
    [Fact]
    public void Unsupported_argument_names_the_accepted_keys()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<System.Text.Json.Nodes.JsonObject>()
            .Single(x => x["name"]!.GetValue<string>() == "ReadMemAtAddress");
        var error = ToolArgumentRules.Validate(
            tool["inputSchema"]!.AsObject(),
            JsonSerializer.SerializeToElement(new { address = "cip", length = 32 }));
        Assert.NotNull(error);
        Assert.Contains("Unsupported argument: length", error);
        Assert.Contains("accepted: address, byteCount", error);
    }

    [Fact]
    public async Task Read_memory_decodes_utf16_on_request_and_strips_the_flag()
    {
        // "Hi" as UTF-16LE then a NUL terminator.
        var bridge = new ScriptedBridge().On("ReadMemAtAddress",
            ScriptedBridge.Ok("{\"address\":\"0x140003000\",\"bytes\":\"480069000000\",\"bytesRead\":6}"));
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

        var text = TextOf(await server.CallToolAsync(new ModelContextProtocol.Protocol.CallToolRequestParams
        {
            Name = "ReadMemAtAddress",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                "{\"address\":\"0x140003000\",\"includeUtf16\":true}")!,
        }, CancellationToken.None));

        Assert.Contains("\"utf16\":\"Hi\"", text);
        // The MCP-only flag never reaches the bridge (it rejects unknown fields).
        Assert.DoesNotContain("includeUtf16", bridge.Calls.Single().ArgsJson);
        // The hex payload is preserved.
        Assert.Contains("480069000000", text);
    }

    [Fact]
    public async Task Read_memory_without_the_flag_is_unchanged()
    {
        var bridge = new ScriptedBridge().On("ReadMemAtAddress",
            ScriptedBridge.Ok("{\"address\":\"0x140003000\",\"bytes\":\"48006900\",\"bytesRead\":4}"));
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

        var text = TextOf(await server.CallToolAsync(new ModelContextProtocol.Protocol.CallToolRequestParams
        {
            Name = "ReadMemAtAddress",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                "{\"address\":\"0x140003000\"}")!,
        }, CancellationToken.None));

        Assert.DoesNotContain("utf16", text);
    }
}
