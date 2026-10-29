using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace DbgLink.Tests;

/// <summary>
/// P5: large row lists stay readable by default, but an explicit
/// <c>compact:true</c> switches repeated keys to one column legend plus
/// positional rows. The wire shape is pinned here, together with the token
/// win and the "never forward the client-only flag to Ghidra" rule.
/// </summary>
public sealed class CompactRowsTests
{
    private readonly ITestOutputHelper _output;

    public CompactRowsTests(ITestOutputHelper output) => _output = output;

    private const string FunctionsJson = """
        {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","functions":[
        {"name":"fn0","entry":"0x140001000","size":16,"instructionCount":4,"branchCount":1},
        {"name":"fn1","entry":"0x140001100","size":32,"instructionCount":8,"branchCount":2},
        {"name":"fn2","entry":"0x140001200","size":64,"instructionCount":16,"branchCount":3},
        {"name":"fn3","entry":"0x140001300","size":80,"instructionCount":20,"branchCount":4},
        {"name":"fn4","entry":"0x140001400","size":96,"instructionCount":24,"branchCount":5},
        {"name":"fn5","entry":"0x140001500","size":112,"instructionCount":28,"branchCount":6},
        {"name":"fn6","entry":"0x140001600","size":128,"instructionCount":32,"branchCount":7},
        {"name":"fn7","entry":"0x140001700","size":144,"instructionCount":36,"branchCount":8}],
        "truncated":false,"nextOffset":8}}
        """;

    private const string SymbolsJson = """
        {"ok":true,"result":{
        "imports":[
        {"name":"CreateFileW","library":"kernel32.dll","refCount":3},
        {"name":"connect","library":"ws2_32.dll","refCount":2},
        {"name":"memcpy","library":"msvcrt.dll","refCount":9}],
        "exports":[
        {"name":"main","address":"0x140001000"},
        {"name":"DllMain","address":"0x140001100"}],
        "importsTruncated":false,"exportsTruncated":false}}
        """;

    private const string SectionsJson = """
        {"ok":true,"result":{"sections":[
        {"name":".text","start":"0x140001000","end":"0x140002000","permissions":"r-x"},
        {"name":".rdata","start":"0x140002000","end":"0x140003000","permissions":"r--"}],
        "entryPoint":"0x140001000","truncated":false}}
        """;

    private const string StatusJson = """
        {"ok":true,"result":{"program":{"fileName":"app.exe","functionCount":8,"imageBase":"0x140000000"}}}
        """;

    private const string StringsJson = """
        {"ok":true,"result":{"strings":[
        {"address":"0x140002000","text":"https://c2.example/a","length":20},
        {"address":"0x140002100","text":"hello world","length":11}],"truncated":false}}
        """;

    private sealed class RowsBackend : IGhidraClient
    {
        private readonly Func<JsonElement?, string> _strings;
        public List<(string Method, string? Args)> Calls { get; } = [];

        public RowsBackend(Func<JsonElement?, string>? strings = null)
            => _strings = strings ?? (_ => StringsJson);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult(method switch
            {
                "status" => StatusJson,
                "ListSections" => SectionsJson,
                "ListSymbolsBoth" => SymbolsJson,
                "ListFunctions" => FunctionsJson,
                "DumpStrings" => _strings(arguments),
                _ => "{\"ok\":true,\"result\":{}}",
            });
        }
    }

    private static async Task<string> CallAsync(LocalMcpServer server, string name, string args)
    {
        var response = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = name,
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(args)!,
        }, CancellationToken.None);
        Assert.False(response.IsError);
        return Assert.IsType<TextContentBlock>(Assert.Single(response.Content)).Text;
    }

    private static JsonObject Payload(string text)
    {
        var root = JsonNode.Parse(text)!.AsObject();
        return root["result"] as JsonObject ?? root;
    }

    [Fact]
    public async Task ListFunctions_compact_uses_columns_rows_and_saves_tokens()
    {
        var backend = new RowsBackend();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);

        var plain = await CallAsync(server, "ListFunctions", "{\"maxItems\":8}");
        var compact = await CallAsync(server, "ListFunctions", "{\"maxItems\":8,\"compact\":true}");

        Assert.IsType<JsonArray>(Payload(plain)["functions"]);
        var functions = Payload(compact)["functions"]!.AsObject();
        Assert.Equal(
            new[] { "name", "entry", "size", "instructionCount", "branchCount" },
            functions["columns"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray());
        var rows = functions["rows"]!.AsArray();
        Assert.Equal(8, rows.Count);
        Assert.Equal("fn0", rows[0]![0]!.GetValue<string>());
        Assert.Equal(16, rows[0]![2]!.GetValue<int>());
        Assert.Equal(4, rows[0]![3]!.GetValue<int>());

        Assert.All(backend.Calls.Where(call => call.Method == "ListFunctions"),
            call => Assert.DoesNotContain("\"compact\"", call.Args ?? string.Empty));
        var plainTokens = TokenCounter.Count(plain);
        var compactTokens = TokenCounter.Count(compact);
        _output.WriteLine($"ListFunctions tokens: plain={plainTokens} compact={compactTokens} saved={plainTokens - compactTokens} ({(plainTokens - compactTokens) * 100.0 / plainTokens:F1}%)");
        Assert.True(compactTokens < plainTokens * 0.85,
            $"compact={compactTokens} plain={plainTokens}");
    }

    [Fact]
    public async Task ListSymbols_both_compact_codes_each_side_and_keeps_plain_shape()
    {
        var backend = new RowsBackend();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);

        var plain = Payload(await CallAsync(server, "ListSymbols", "{\"kind\":\"both\"}"));
        Assert.IsType<JsonArray>(plain["imports"]);
        Assert.IsType<JsonArray>(plain["exports"]);

        var compact = Payload(await CallAsync(server, "ListSymbols",
            "{\"kind\":\"both\",\"compact\":true}"));
        foreach (var side in new[] { "imports", "exports" })
        {
            var table = compact[side]!.AsObject();
            Assert.NotEmpty(table["columns"]!.AsArray());
            Assert.NotEmpty(table["rows"]!.AsArray());
        }
        Assert.Equal("CreateFileW",
            compact["imports"]!["rows"]![0]![0]!.GetValue<string>());
        Assert.Equal("main", compact["exports"]!["rows"]![0]![0]!.GetValue<string>());
        Assert.All(backend.Calls.Where(call => call.Method == "ListSymbolsBoth"),
            call => Assert.DoesNotContain("\"compact\"", call.Args ?? string.Empty));
    }

    [Fact]
    public async Task ModuleMap_compact_tables_keep_the_map_readable_and_smaller()
    {
        var backend = new RowsBackend();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);

        var plain = await CallAsync(server, "GetModuleMap",
            "{\"maxFunctions\":8,\"maxSymbols\":4,\"maxStrings\":3}");
        var compact = await CallAsync(server, "GetModuleMap",
            "{\"maxFunctions\":8,\"maxSymbols\":4,\"maxStrings\":3,\"compact\":true}");

        var plainMap = Payload(plain);
        Assert.IsType<JsonArray>(plainMap["functions"]!["sample"]);
        var map = Payload(compact);
        Assert.IsType<JsonObject>(map["functions"]!["sample"]);
        Assert.NotEmpty(map["functions"]!["sample"]!["columns"]!.AsArray());
        Assert.NotEmpty(map["imports"]!["top"]!["columns"]!.AsArray());
        Assert.NotEmpty(map["exports"]!["top"]!["columns"]!.AsArray());
        Assert.NotEmpty(map["strings"]!["top"]!["columns"]!.AsArray());
        var plainTokens = TokenCounter.Count(plain);
        var compactTokens = TokenCounter.Count(compact);
        _output.WriteLine($"GetModuleMap tokens: plain={plainTokens} compact={compactTokens} saved={plainTokens - compactTokens} ({(plainTokens - compactTokens) * 100.0 / plainTokens:F1}%)");
        Assert.True(compactTokens < plainTokens * 0.9,
            $"compact={compactTokens} plain={plainTokens}");
    }

    [Fact]
    public async Task ModuleMap_walks_rdata_pages_and_reports_the_real_continuation()
    {
        var page = 0;
        var backend = new RowsBackend(_ =>
        {
            page++;
            var next = $"0x14000{0x3000 + page * 0x1000:X4}";
            return $"{{\"ok\":true,\"result\":{{\"strings\":[{{\"address\":\"{next}\",\"text\":\"page{page}\",\"length\":5}}],\"truncated\":true,\"nextAddress\":\"{next}\"}}}}";
        });
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);

        var map = Payload(await CallAsync(server, "GetModuleMap", "{}"));
        var dumps = backend.Calls.Where(call => call.Method == "DumpStrings").ToList();

        Assert.Equal(2, dumps.Count);
        Assert.DoesNotContain("\"start\"", dumps[0].Args ?? string.Empty);
        Assert.Contains("\"start\":\"0x140004000\"", dumps[1].Args ?? string.Empty);
        Assert.Contains("\"maxItems\":256", dumps[0].Args ?? string.Empty);
        Assert.Equal(2, map["strings"]!["examined"]!.GetValue<int>());
        Assert.True(map["strings"]!["truncated"]!.GetValue<bool>());
        Assert.Equal("0x140005000", map["strings"]!["nextAddress"]!.GetValue<string>());
    }
}
