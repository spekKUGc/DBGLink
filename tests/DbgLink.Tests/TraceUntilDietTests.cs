using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// TraceUntil token diet: compact path (short address + mnemonic),
/// 512-entry cap, 8KB default snapshot budget.
/// </summary>
[Collection("LiveWire")]
public sealed class TraceUntilDietTests
{
    private readonly ITestOutputHelper _output;

    public TraceUntilDietTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void TraceUntil_CompactAddress_StripsPadding()
    {
        Assert.Equal("0x140001000", LiveAnalysisTools.CompactTraceAddress("0x0000000140001000"));
        Assert.Equal("0x7ff810001040", LiveAnalysisTools.CompactTraceAddress("0x00007FF810001040"));
        Assert.Equal("0x0", LiveAnalysisTools.CompactTraceAddress("0x00000000"));
        Assert.Equal(string.Empty, LiveAnalysisTools.CompactTraceAddress(null));
    }

    [Fact]
    public void TraceUntil_Mnemonic_KeepsFirstToken()
    {
        Assert.Equal("mov", LiveAnalysisTools.ExtractTraceMnemonic("mov rax, qword ptr [rsp+0x28]"));
        Assert.Equal("sub", LiveAnalysisTools.ExtractTraceMnemonic("sub rsp, 28h"));
        Assert.Equal("ret", LiveAnalysisTools.ExtractTraceMnemonic("ret"));
        Assert.Equal(string.Empty, LiveAnalysisTools.ExtractTraceMnemonic(null));
    }

    [Fact]
    public void TraceUntil_CompactEntry_IsSmallerThanFull()
    {
        var address = "0x0000000140001000";
        var instruction = "mov rax, qword ptr [rsp+0x28]";
        var full = new JsonArray();
        var compact = new JsonArray();
        for (var i = 0; i < 10; i++)
        {
            full.Add(LiveAnalysisTools.FormatTracePathEntry(i, address, instruction, compact: false));
            compact.Add(LiveAnalysisTools.FormatTracePathEntry(i, address, instruction, compact: true));
        }
        var fullLen = full.ToJsonString().Length;
        var compactLen = compact.ToJsonString().Length;
        _output.WriteLine($"path full={fullLen}B compact={compactLen}B");
        Assert.True(compactLen < fullLen, $"compact {compactLen} should be smaller than full {fullLen}");
        Assert.IsAssignableFrom<JsonValue>(compact[0]);
        Assert.IsType<JsonObject>(full[0]);
        Assert.Contains("0x140001000 mov", compact[0]!.GetValue<string>());
    }

    [Fact]
    public void TraceUntil_PathCap_StopsAt512()
    {
        var path = new JsonArray();
        var truncated = false;
        for (var i = 0; i < 600; i++)
            LiveAnalysisTools.TryAddTracePathEntry(path,
                LiveAnalysisTools.FormatTracePathEntry(i, "0x140001000", "mov rax, rbx", compact: true),
                ref truncated);
        Assert.Equal(LiveAnalysisTools.MaxTracePathEntries, path.Count);
        Assert.True(truncated);
        Assert.Equal(512, LiveAnalysisTools.MaxTracePathEntries);
    }

    [Fact]
    public void TraceUntil_Schema_DefaultsAreDiet()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var trace = server.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == "TraceUntil");
        var props = (JsonObject)trace["inputSchema"]!["properties"]!;
        // Diet budgets ride server-side; the advertised caps stay.
        Assert.Equal(60000, props["maxChars"]!["maximum"]!.GetValue<int>());
        Assert.Null(server.ValidateArguments("TraceUntil",
            JsonSerializer.Deserialize<JsonElement>("{\"maxSteps\":3,\"includePath\":true}")));
        var allowed = props["pathFormat"]!["enum"]!.AsArray().Select(n => n!.GetValue<string>()).ToHashSet();
        Assert.Contains("compact", allowed);
        Assert.Contains("full", allowed);
        var snapshot = server.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == "GetAnalysisSnapshot");
        var snapshotProps = (JsonObject)snapshot["inputSchema"]!["properties"]!;
        Assert.Equal(60000, snapshotProps["maxChars"]!["maximum"]!.GetValue<int>());
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task TraceUntil_Wire_CompactSmallerThanFull()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.NativePipeServer.RegisterHandler("ReadDisassemblyChunk", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"cip\",\"instructions\":[{{\"address\":\"0x0000000140001000\",\"instruction\":\"mov rax, qword ptr [rsp+0x28]\",\"size\":4}}]}}}}");

        var compactText = TextOf(await harness.CallToolOverWireAsync("TraceUntil",
            new { maxSteps = 5, includePath = true, pathFormat = "compact" }));
        var fullText = TextOf(await harness.CallToolOverWireAsync("TraceUntil",
            new { maxSteps = 5, includePath = true, pathFormat = "full" }));

        var compactPath = JsonNode.Parse(compactText)!["trace"]!["path"]!.AsArray();
        var fullPath = JsonNode.Parse(fullText)!["trace"]!["path"]!.AsArray();
        Assert.Equal(fullPath.Count, compactPath.Count);
        Assert.True(compactPath.Count > 0);
        var compactLen = compactPath.ToJsonString().Length;
        var fullLen = fullPath.ToJsonString().Length;
        _output.WriteLine($"wire path compact={compactLen}B full={fullLen}B entries={compactPath.Count}");
        Assert.True(compactLen < fullLen, $"compact {compactLen} should be smaller than full {fullLen}");
        Assert.Equal("compact", JsonNode.Parse(compactText)!["trace"]!["pathFormat"]!.GetValue<string>());
        Assert.Equal("full", JsonNode.Parse(fullText)!["trace"]!["pathFormat"]!.GetValue<string>());
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task TraceUntil_Wire_DefaultIsCompactAndMaxCharsDiet()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var defaultText = TextOf(await harness.CallToolOverWireAsync("TraceUntil",
            new { maxSteps = 3, includePath = true }));
        var defaultNode = JsonNode.Parse(defaultText)!;
        Assert.Equal("compact", defaultNode["trace"]!["pathFormat"]!.GetValue<string>());
        Assert.True(defaultNode["usedChars"]!.GetValue<int>() <= 8000);
        var path = defaultNode["trace"]!["path"]!.AsArray();
        Assert.True(path.Count <= 512);
        Assert.True(path.Count <= LiveAnalysisTools.MaxTracePathEntries);

        var explicitText = TextOf(await harness.CallToolOverWireAsync("TraceUntil",
            new { maxSteps = 3, includePath = true, pathFormat = "full", maxChars = 12000 }));
        var explicitNode = JsonNode.Parse(explicitText)!;
        Assert.Equal("full", explicitNode["trace"]!["pathFormat"]!.GetValue<string>());
        Assert.True(explicitNode["usedChars"]!.GetValue<int>() <= 12000);
    }
}
