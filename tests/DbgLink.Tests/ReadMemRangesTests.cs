using System.Runtime.Versioning;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// ReadMemAtAddress multi-range mode: up to 8 {address, byteCount} entries in
/// one call over the real wire stack (Kestrel HTTP + named pipe), with
/// per-index errors that never fail the sibling chunks.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ReadMemRangesTests
{
    private readonly ITestOutputHelper _output;

    public ReadMemRangesTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void Schema_Advertises_Ranges_Up_To_Eight()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<System.Text.Json.Nodes.JsonObject>()
            .Single(x => x["name"]!.GetValue<string>() == "ReadMemAtAddress");
        var schema = (System.Text.Json.Nodes.JsonObject)tool["inputSchema"]!;
        var ranges = (System.Text.Json.Nodes.JsonObject)schema["properties"]!["ranges"]!;
        Assert.Equal(1, ranges["minItems"]!.GetValue<int>());
        Assert.Equal(8, ranges["maxItems"]!.GetValue<int>());
        var itemByteCount = (System.Text.Json.Nodes.JsonObject)
            ((System.Text.Json.Nodes.JsonObject)ranges["items"]!)["properties"]!["byteCount"]!;
        Assert.Equal(4096, itemByteCount["maximum"]!.GetValue<int>());
        // Ranges-only call validates; empty call names the missing selector.
        Assert.Null(ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(
            new { ranges = new[] { new { address = "0x140001000", byteCount = 16 } } })));
        var missing = ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { }));
        Assert.Contains("ranges", missing);
    }

    [Fact]
    public async Task Ranges_Mode_Forwards_All_Entries_In_One_Wire_Call()
    {
        await using var harness = await RealServerHarness.StartAsync();
        JsonElement? seenArgs = null;
        var before = harness.NativePipeServer.RequestCount;
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, args) =>
        {
            seenArgs = args;
            return $"{{\"id\":{id},\"ok\":true,\"method\":\"ReadMemAtAddress\"," +
                $"\"text\":\"[ReadMemAtAddress] ranges=2\\n[0] address=0x140001000 byteCount=4\\n" +
                $"AA BB CC DD\\n[1] address=0x140002000 byteCount=4\\n11 22 33 44\"}}";
        });

        var text = TextOf(await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new
            {
                ranges = new[]
                {
                    new { address = "0x140001000", byteCount = 4 },
                    new { address = "0x140002000", byteCount = 4 }
                }
            }));
        _output.WriteLine(text);
        Assert.Equal(before + 1, harness.NativePipeServer.RequestCount);
        Assert.Equal(2, seenArgs!.Value.GetProperty("ranges").GetArrayLength());
        Assert.Contains("[0]", text);
        Assert.Contains("[1]", text);
        Assert.Contains("0x140001000", text);
        Assert.Contains("0x140002000", text);
    }

    [Fact]
    public async Task Ranges_Mode_One_Bad_Entry_Does_Not_Fail_Others()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"method\":\"ReadMemAtAddress\"," +
            $"\"text\":\"[ReadMemAtAddress] ranges=2\\n[0] address=0x140001000 byteCount=4\\n" +
            $"AA BB CC DD\\n[1] error=Failed to read memory at 0x600000\"}}");

        var text = TextOf(await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new
            {
                ranges = new[]
                {
                    new { address = "0x140001000", byteCount = 4 },
                    new { address = "0x600000", byteCount = 4 }
                }
            }));
        Assert.Contains("[0] address=0x140001000", text);
        Assert.Contains("[1] error=", text);
    }

    [Fact]
    public async Task Ranges_Mode_TotalCap_Is_Enforced_By_Backend()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, _) =>
            $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":\"native_error\"," +
            $"\"message\":\"ReadMemAtAddress total byteCount across ranges must not exceed 16384.\"}}}}");

        var result = await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new
            {
                ranges = new[]
                {
                    new { address = "0x140001000", byteCount = 4096 },
                    new { address = "0x140002000", byteCount = 4096 },
                    new { address = "0x140003000", byteCount = 4096 },
                    new { address = "0x140004000", byteCount = 4096 },
                    new { address = "0x140005000", byteCount = 4096 }
                }
            });
        Assert.True(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("16384", text);
    }

    [Theory]
    [InlineData(9)]
    public async Task Ranges_Mode_Nine_Entries_Rejected_Before_Backend(int count)
    {
        await using var harness = await RealServerHarness.StartAsync();
        var before = harness.NativePipeServer.RequestCount;
        var ranges = Enumerable.Range(0, count)
            .Select(i => new { address = "0x140001000", byteCount = 16 }).ToArray();
        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ReadMemAtAddress", new { ranges }));
        Assert.Contains("ranges", error.Message);
        Assert.Equal(before, harness.NativePipeServer.RequestCount);
    }

    [Fact]
    public async Task Ranges_Mode_Oversize_ByteCount_Rejected_Before_Backend()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var before = harness.NativePipeServer.RequestCount;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ReadMemAtAddress",
                new { ranges = new[] { new { address = "0x140001000", byteCount = 4097 } } }));
        Assert.Contains("ranges", error.Message);
        Assert.Equal(before, harness.NativePipeServer.RequestCount);
    }

    [Fact]
    public async Task Ranges_Mode_Missing_Address_And_Ranges_Rejected()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var before = harness.NativePipeServer.RequestCount;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ReadMemAtAddress", new { }));
        Assert.Contains("ReadMemAtAddress", error.Message);
        Assert.Equal(before, harness.NativePipeServer.RequestCount);
    }

    [Fact]
    public async Task Single_Mode_Still_Works_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"method\":\"ReadMemAtAddress\",\"text\":\"[ReadMemAtAddress] 0x140001000  AA BB\"}}");

        var text = TextOf(await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new { address = "0x140001000", byteCount = 2 }));
        Assert.Contains("0x140001000", text);
    }
}
