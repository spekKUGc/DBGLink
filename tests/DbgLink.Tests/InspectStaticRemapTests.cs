using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Defect 1: InspectAddressStructure on a static image-base VA (e.g.
// 0x140003000, the FixtureUnicodePointer slot) reported read=false because
// the static address is not mapped under ASLR. The tool now retries once
// as live = moduleBase + (staticVA - imageBase) and returns the live bytes
// plus the pointer slot with a one-line [StaticRemap] note.
public sealed class InspectStaticRemapTests
{
    private const string UnreadableText =
        "[InspectAddressStructure] address=0x140003000 expression=\"0x140003000\" pointerSize=8\n" +
        "[Address] 0x140003000\n" +
        "[Xrefs] included=false\n" +
        "[Bytes] byteCount=128 read=false\n" +
        "[Pointers] count=8 read=false";

    private const string ReadableText =
        "[InspectAddressStructure] address=0x7FF799BA3000 expression=\"0x7FF799BA3000\" pointerSize=8\n" +
        "[Address] 0x7FF799BA3000 module=analysistarget label=FixtureUnicodePointer\n" +
        "[Xrefs] included=false\n" +
        "[Bytes] byteCount=128 read=true\n" +
        "0x7FF799BA3000 (128 bytes)\n1020ba99f77f0000\n" +
        "[Pointers] count=8 read=true\n" +
        "[0] +0x0 value=0x7FF799BA2010 module=analysistarget utf16=\"DBGLink\"";

    private static string TextEnvelope(string text) =>
        "{\"id\":1,\"ok\":true,\"method\":\"InspectAddressStructure\",\"text\":" + JsonSerializer.Serialize(text) + "}";

    private sealed class RemapBridge : IBridgeClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public Task<bool> PingAsync(CancellationToken t) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            var args = arguments?.GetRawText() ?? "";
            return Task.FromResult(method switch
            {
                "InspectAddressStructure" when args.Contains("140003000", StringComparison.Ordinal) => TextEnvelope(UnreadableText),
                "InspectAddressStructure" => TextEnvelope(ReadableText),
                "GetModuleRecords" => ScriptedBridge.Ok("{\"modules\":[{\"name\":\"AnalysisTarget.exe\",\"base\":\"0x7FF799BA0000\",\"end\":\"0x7FF799BB0000\",\"path\":\"C:\\\\fixture\\\\AnalysisTarget.exe\"}],\"truncated\":false}"),
                _ => ScriptedBridge.Ok("{}"),
            });
        }
    }

    private sealed class StatusGhidra(string fileName) : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
            => Task.FromResult(ScriptedBridge.Ok("{\"program\":{\"fileName\":" + JsonSerializer.Serialize(fileName) + ",\"imageBase\":\"140000000\"}}"));
    }

    private static LocalMcpServer CreateServer(RemapBridge bridge, string fileName)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge, new StatusGhidra(fileName));

    [Fact]
    public async Task StaticAddress_RemapsToLive_ReturnsBytesAndPointer()
    {
        var bridge = new RemapBridge();
        using var server = CreateServer(bridge, "AnalysisTarget.exe");

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = TestWire.Args("{\"address\":\"0x140003000\",\"includeXrefs\":false}"),
        }, CancellationToken.None);

        var text = TestWire.TextOf(result);
        Assert.Contains("read=true", text);
        Assert.Contains("0x7FF799BA2010", text);
        Assert.Contains("[StaticRemap]", text);
        // The retry must target live = moduleBase + RVA(0x3000).
        var retry = bridge.Calls.Where(c => c.Method == "InspectAddressStructure").ToList();
        Assert.Equal(2, retry.Count);
        Assert.Contains("7FF799BA3000", retry[1].ArgsJson);
    }

    [Fact]
    public async Task LiveAddress_PassesThrough_WithoutExtraCalls()
    {
        var bridge = new RemapBridge();
        using var server = CreateServer(bridge, "AnalysisTarget.exe");

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = TestWire.Args("{\"address\":\"0x7FF799BA3000\",\"includeXrefs\":false}"),
        }, CancellationToken.None);

        var text = TestWire.TextOf(result);
        Assert.Contains("read=true", text);
        Assert.DoesNotContain("[StaticRemap]", text);
        Assert.Single(bridge.Calls);
        Assert.Equal("InspectAddressStructure", bridge.Calls[0].Method);
    }

    [Fact]
    public async Task UnmatchedModule_ReturnsOriginalResponse()
    {
        var bridge = new RemapBridge();
        using var server = CreateServer(bridge, "Other.exe");

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = TestWire.Args("{\"address\":\"0x140003000\",\"includeXrefs\":false}"),
        }, CancellationToken.None);

        var text = TestWire.TextOf(result);
        Assert.Contains("read=false", text);
        Assert.DoesNotContain("[StaticRemap]", text);
        // No retry when no live module matches the Ghidra program.
        Assert.Single(bridge.Calls.Where(c => c.Method == "InspectAddressStructure"));
    }

    [Fact]
    public async Task NonTextResponse_PassesThrough_Unchanged()
    {
        // Token-baseline shaped mock (JSON result object, no text envelope):
        // the wrapper must not invent calls or rewrite the payload.
        var bridge = new ScriptedBridge()
            .On("InspectAddressStructure", ScriptedBridge.Ok("{\"address\":\"0x1\",\"fields\":[]}"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, bridge, new StatusGhidra("AnalysisTarget.exe"));

        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = TestWire.Args("{\"address\":\"0x1\"}"),
        }, CancellationToken.None);

        Assert.Single(bridge.Calls);
        Assert.Contains("0x1", TestWire.RawText(result));
    }
}
