using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Token guard for TriageStrings: overlong IOC values are preview-truncated
/// to <see cref="TriageImportsTools.MaxIocValueChars"/> while classification
/// still runs on the full value. Prevents a single 20k blob from costing
/// thousands of tokens per triage response.
/// </summary>
public sealed class TriageIocTruncationTests
{
    private sealed class StubGhidra : IGhidraClient
    {
        private readonly string _payload;
        public StubGhidra(string payload) => _payload = payload;
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
            => Task.FromResult(_payload);
    }

    private sealed class NullBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken t) => Task.FromResult(true);
        public Task<string> RequestAsync(string m, JsonElement? a, CancellationToken t)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"y\"}}");
    }

    private static string Payload(params object[] strings)
        => JsonSerializer.Serialize(new { id = 1, ok = true, result = new { strings } });

    private static async Task<JsonNode> TriageAsync(string payloadJson)
    {
        var ctx = new AnalysisContext(new NullBridge(), new StubGhidra(payloadJson));
        var inv = new TriageImportsTools(ctx);
        var raw = await inv.TriageStringsAsync(null, CancellationToken.None);
        return AnalysisFormatting.ReadBridgeResultNode(raw)!;
    }

    [Fact]
    public async Task GiantUrl_IsTruncated_ButStillDetected()
    {
        var giant = "https://" + new string('a', 5000) + ".example.com/beacon";
        var node = await TriageAsync(Payload(
            new { address = "0x140002000", value = giant, length = giant.Length }));
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal(1, node["truncatedValues"]!.GetValue<int>());
        var ioc = Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!);
        Assert.Equal("C2_URL", ioc["type"]!.GetValue<string>());
        Assert.Equal("0x140002000", ioc["address"]!.GetValue<string>());
        var preview = ioc["value"]!.GetValue<string>();
        Assert.True(preview.Length <= TriageImportsTools.MaxIocValueChars);
        Assert.True(ioc["fullLength"]!.GetValue<int>() > 0);
        Assert.Equal(giant.Length, ioc["fullLength"]!.GetValue<int>());
        Assert.EndsWith("\n...[truncated]", preview);
        Assert.DoesNotContain(giant, preview);
    }

    [Fact]
    public async Task ShortValues_AreNotTruncated()
    {
        var node = await TriageAsync(Payload(
            new { address = "0x140002000", value = "http://evil.example/command", length = 24 },
            new { address = "0x140002020", value = "hello", length = 5 }));
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal(0, node["truncatedValues"]!.GetValue<int>());
        var ioc = Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!);
        Assert.Equal("http://evil.example/command", ioc["value"]!.GetValue<string>());
        Assert.Null(ioc["truncated"]);
        Assert.Null(ioc["fullLength"]);
    }

    [Fact]
    public async Task EmptyIocs_CarryOneActionableNote()
    {
        // Zero IOCs is expected (triage only reports URL/IP/cmd/registry/
        // security-API/crypto matches), so the response must say why in one
        // short field instead of reading as "nothing found".
        var node = await TriageAsync(Payload(
            new { address = "0x140002010", value = "DBGLink ", length = 8 },
            new { address = "0x140002020", value = "hello", length = 5 }));
        Assert.Equal(0, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal(2, node["totalExamined"]!.GetValue<int>());
        Assert.Contains("DumpStrings", node["note"]!.GetValue<string>());
    }

    [Fact]
    public async Task NonEmptyIocs_CarryNoNote()
    {
        var node = await TriageAsync(Payload(
            new { address = "0x140002000", value = "http://evil.example/command", length = 24 }));
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.Null(node["note"]);
    }

    [Theory]
    [InlineData(505, false)] // 7 + 505 = 512 -> fits exactly
    [InlineData(506, true)]  // 7 + 506 = 513 -> over budget
    public async Task Boundary512_TruncatesOnlyWhenOver(int tail, bool expectTruncated)
    {
        var val = "http://" + new string('a', tail);
        var node = await TriageAsync(Payload(new { address = "0x1", value = val, length = val.Length }));
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        var ioc = Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!);
        if (expectTruncated)
        {
            Assert.True(ioc["fullLength"]!.GetValue<int>() > 0);
            Assert.Equal(val.Length, ioc["fullLength"]!.GetValue<int>());
            Assert.Equal(1, node["truncatedValues"]!.GetValue<int>());
        }
        else
        {
            Assert.Null(ioc["truncated"]);
            Assert.Equal(val, ioc["value"]!.GetValue<string>());
            Assert.Equal(0, node["truncatedValues"]!.GetValue<int>());
        }
    }

    [Fact]
    public async Task Classification_UsesFullValue_NotPreview()
    {
        // IOC marker sits past the 512-char preview window: it must still be
        // detected because matching runs before truncation.
        var val = new string('a', 600) + " https://hidden-evil.example.com/beacon";
        var node = await TriageAsync(Payload(new { address = "0x1", value = val, length = val.Length }));
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal("C2_URL", Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!)["type"]!.GetValue<string>());
    }

    [Fact]
    public async Task TextField_And_ByteLength_Variants_AreTruncated()
    {
        var giant = "https://evil.example.com/" + new string('b', 2000);
        var payload = JsonSerializer.Serialize(new
        {
            id = 1,
            ok = true,
            result = new
            {
                strings = new[] { new { address = "0x2", text = giant, byteLength = giant.Length } }
            }
        });
        var node = await TriageAsync(payload);
        var ioc = Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!);
        Assert.True(ioc["value"]!.GetValue<string>().Length <= TriageImportsTools.MaxIocValueChars);
        Assert.True(ioc["fullLength"]!.GetValue<int>() > 0);
    }

    [Fact]
    public async Task Truncation_NeverLeavesDanglingSurrogate()
    {
        var val = "https://evil.example.com/" + new string('x', 480) + "😀" + new string('y', 2000);
        var node = await TriageAsync(Payload(new { address = "0x1", value = val, length = val.Length }));
        var preview = Assert.IsType<JsonObject>(Assert.IsType<JsonArray>(node["iocs"]!)[0]!)["value"]!.GetValue<string>();
        foreach (var ch in preview)
            Assert.False(char.IsSurrogate(ch) && preview.Length == 1);
        // Well-formed: round-trips through UTF-8 without replacement.
        var bytes = System.Text.Encoding.UTF8.GetBytes(preview);
        Assert.Equal(preview, System.Text.Encoding.UTF8.GetString(bytes));
    }

    private sealed class RoutingGhidra : IGhidraClient
    {
        private readonly Queue<string> _pages = new();
        public readonly List<string?> Calls = [];
        public RoutingGhidra(string first) => _pages.Enqueue(first);
        public void Enqueue(string payload) => _pages.Enqueue(payload);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add(arguments?.GetRawText());
            return Task.FromResult(_pages.Count > 0 ? _pages.Dequeue()
                : "{\"id\":1,\"ok\":true,\"result\":{\"strings\":[],\"truncated\":false}}");
        }
    }

    private static string StringPage(object[] strings, bool truncated, string? nextAddress)
    {
        var result = new JsonObject
        {
            ["strings"] = JsonSerializer.SerializeToNode(strings),
            ["truncated"] = truncated,
        };
        if (nextAddress is not null)
            result["nextAddress"] = nextAddress;
        return JsonSerializer.Serialize(new JsonObject { ["id"] = 1, ["ok"] = true, ["result"] = result });
    }

    private static object IocRow(string address, string text)
        => new { address, text, byteLength = text.Length };

    private static async Task<(JsonNode Node, RoutingGhidra Ghidra)> TriagePagedAsync(
        string firstPage, object? args = null, Action<RoutingGhidra>? setup = null)
    {
        var ghidra = new RoutingGhidra(firstPage);
        setup?.Invoke(ghidra);
        var ctx = new AnalysisContext(new NullBridge(), ghidra);
        var inv = new TriageImportsTools(ctx);
        var element = args is null ? (JsonElement?)null : JsonSerializer.SerializeToElement(args);
        var raw = await inv.TriageStringsAsync(element, CancellationToken.None);
        return (AnalysisFormatting.ReadBridgeResultNode(raw)!, ghidra);
    }

    [Fact]
    public async Task Filter_Start_MaxScanBytes_Pass_Through_To_DumpStrings()
    {
        var (node, ghidra) = await TriagePagedAsync(
            StringPage([IocRow("0x140002000", "http://evil.example/command")], truncated: false, nextAddress: null),
            new { filter = "evil*", start = "0x140002000", maxScanBytes = 65536, section = ".rdata" });
        Assert.Single(ghidra.Calls);
        Assert.Contains("\"filter\":\"evil*\"", ghidra.Calls[0]);
        Assert.Contains("\"start\":\"0x140002000\"", ghidra.Calls[0]);
        Assert.Contains("\"maxScanBytes\":65536", ghidra.Calls[0]);
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.False(node["truncated"]!.GetValue<bool>());
        Assert.Null(node["nextAddress"]);
    }

    [Fact]
    public async Task Paging_Args_Omitted_By_Default()
    {
        var (_, ghidra) = await TriagePagedAsync(
            StringPage([IocRow("0x1", "http://evil.example/command")], truncated: false, nextAddress: null));
        Assert.Single(ghidra.Calls);
        Assert.DoesNotContain("maxScanBytes", ghidra.Calls[0]);
        Assert.DoesNotContain("\"filter\"", ghidra.Calls[0]);
        Assert.DoesNotContain("\"start\"", ghidra.Calls[0]);
    }

    [Fact]
    public async Task Single_Page_Truncation_Surfaces_NextAddress()
    {
        // Default maxPages=1: one fetch, honest continuation, no re-call.
        var (node, ghidra) = await TriagePagedAsync(
            StringPage([IocRow("0x1", "http://evil.example/command")], truncated: true, nextAddress: "0x2"));
        Assert.Single(ghidra.Calls);
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.Equal("0x2", node["nextAddress"]!.GetValue<string>());
    }

    [Fact]
    public async Task MaxPages_AutoFollows_NextAddress()
    {
        var (node, ghidra) = await TriagePagedAsync(
            StringPage([IocRow("0x1", "http://a.example/command")], truncated: true, nextAddress: "0x2"),
            new { maxPages = 2 },
            g => g.Enqueue(StringPage(
                [IocRow("0x2", "http://b.example/command")], truncated: false, nextAddress: null)));
        Assert.Equal(2, ghidra.Calls.Count);
        Assert.Contains("\"start\":\"0x2\"", ghidra.Calls[1]);
        Assert.Equal(2, node["suspiciousCount"]!.GetValue<int>());
        Assert.Equal(2, node["totalExamined"]!.GetValue<int>());
        Assert.False(node["truncated"]!.GetValue<bool>());
        Assert.Null(node["nextAddress"]);
    }

    [Fact]
    public async Task Page_Cap_Stays_Honest()
    {
        var (node, ghidra) = await TriagePagedAsync(
            StringPage([IocRow("0x1", "http://a.example/command")], truncated: true, nextAddress: "0x2"),
            new { maxPages = 2 },
            g =>
            {
                g.Enqueue(StringPage(
                    [IocRow("0x2", "http://b.example/command")], truncated: true, nextAddress: "0x3"));
                g.Enqueue(StringPage(
                    [IocRow("0x3", "http://c.example/command")], truncated: true, nextAddress: "0x4"));
            });
        Assert.Equal(2, ghidra.Calls.Count);
        Assert.Equal(2, node["suspiciousCount"]!.GetValue<int>());
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.Equal("0x3", node["nextAddress"]!.GetValue<string>());
    }
}
