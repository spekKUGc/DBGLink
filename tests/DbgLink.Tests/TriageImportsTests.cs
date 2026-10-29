using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class TriageImportsTests
{
    private sealed class StubGhidra : IGhidraClient
    {
        private readonly string _payload;
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public StubGhidra(string payload) => _payload = payload;
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult(_payload);
        }
    }

    private sealed class NullBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken t) => Task.FromResult(true);
        public Task<string> RequestAsync(string m, JsonElement? a, CancellationToken t)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"y\"}}");
    }

    private static string Payload(IEnumerable<object> imports, bool truncated = false)
        => JsonSerializer.Serialize(new { id = 1, ok = true, result = new { imports, truncated } });

    private static object Import(string library, string name, int sites, string address = "0x140001000")
        => new
        {
            name,
            library,
            address,
            refCount = sites,
        };

    private static async Task<(JsonNode Node, StubGhidra Ghidra)> TriageAsync(string payloadJson, object? args = null)
    {
        var ghidra = new StubGhidra(payloadJson);
        var ctx = new AnalysisContext(new NullBridge(), ghidra);
        var tools = new TriageImportsTools(ctx);
        var element = args is null ? (JsonElement?)null : JsonSerializer.SerializeToElement(args);
        var raw = await tools.TriageImportsAsync(element, CancellationToken.None);
        return (AnalysisFormatting.ReadBridgeResultNode(raw)!, ghidra);
    }

    private static string MixedPayload() => Payload([
        Import("ws2_32.dll", "connect", 5),
        Import("crypt32.dll", "CryptEncrypt", 1),
        Import("kernel32.dll", "IsDebuggerPresent", 3),
        Import("advapi32.dll", "RegOpenKeyExW", 2),
        Import("kernel32.dll", "CreateProcessW", 4),
        Import("kernel32.dll", "WriteProcessMemory", 6),
        Import("msvcrt.dll", "strlen", 9),
    ]);

    [Fact]
    public async Task Classifies_Each_Risk_Category()
    {
        var (node, ghidra) = await TriageAsync(MixedPayload());
        Assert.Equal("ListImports", ghidra.Calls.Single().Method);
        // RefCount-by-default: triage relies on the bridge refCount and never
        // forces a site payload.
        Assert.DoesNotContain("maxSites", ghidra.Calls.Single().ArgsJson);
        Assert.DoesNotContain("includeSites", ghidra.Calls.Single().ArgsJson);
        Assert.Equal(7, node["totalExamined"]!.GetValue<int>());
        Assert.Equal(6, node["suspiciousCount"]!.GetValue<int>());
        // benignFiltered was totalExamined - suspiciousCount; derive it.
        Assert.Equal(1, node["totalExamined"]!.GetValue<int>() - node["suspiciousCount"]!.GetValue<int>());
        var byName = node["imports"]!.AsArray()
            .Select(n => n!.AsObject())
            .ToDictionary(o => o["name"]!.GetValue<string>(), o => o, StringComparer.Ordinal);
        Assert.Contains("network", byName["connect"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("crypto", byName["CryptEncrypt"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("anti-debug", byName["IsDebuggerPresent"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("registry", byName["RegOpenKeyExW"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("exec", byName["CreateProcessW"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("injection", byName["WriteProcessMemory"]["categories"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.DoesNotContain("strlen", byName.Keys);
        Assert.Equal(5, byName["connect"]["refCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Prefers_RefCount_Over_Legacy_Sites()
    {
        // Bridge refCount-by-default: when both shapes travel, the count wins;
        // legacy referenceSites-only rows still fall back to the array length.
        var payload = Payload([
            new { name = "connect", library = "ws2_32.dll", address = "0x140001000", refCount = 7, referenceSites = new[] { "0x140002000", "0x140002001" } },
            new { name = "socket", library = "ws2_32.dll", address = "0x140001001", referenceSites = new[] { "0x140002002", "0x140002003", "0x140002004" } },
        ]);
        var (node, _) = await TriageAsync(payload);
        var byName = node["imports"]!.AsArray()
            .Select(n => n!.AsObject())
            .ToDictionary(o => o["name"]!.GetValue<string>(), o => o, StringComparer.Ordinal);
        Assert.Equal(7, byName["connect"]["refCount"]!.GetValue<int>());
        Assert.Equal(3, byName["socket"]["refCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Defaults_return_a_compact_risk_slice()
    {
        var many = Enumerable.Range(0, 40)
            .Select(i => Import("ws2_32.dll", "connect" + i, 40 - i))
            .ToArray();
        var ghidra = new StubGhidra(Payload(many));
        var tools = new TriageImportsTools(new AnalysisContext(new NullBridge(), ghidra));

        var defaultRaw = await tools.TriageImportsAsync(null, CancellationToken.None);
        var explicitRaw = await tools.TriageImportsAsync(
            JsonSerializer.SerializeToElement(new { top = 32 }), CancellationToken.None);
        var defaultNode = AnalysisFormatting.ReadBridgeResultNode(defaultRaw)!;
        var explicitNode = AnalysisFormatting.ReadBridgeResultNode(explicitRaw)!;

        Assert.Equal(16, defaultNode["imports"]!.AsArray().Count);
        Assert.Equal(32, explicitNode["imports"]!.AsArray().Count);
        Assert.True(defaultRaw.Length < explicitRaw.Length,
            $"default {defaultRaw.Length} should be smaller than top=32 {explicitRaw.Length}");
        Assert.True(defaultNode["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public void Schema_defaults_are_compact()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort },
            new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "Triage");
        var props = (JsonObject)tool["inputSchema"]!["properties"]!;

        // Diet budgets ride server-side; the advertised caps stay.
        Assert.Equal(128, props["top"]!["maximum"]!.GetValue<int>());
        Assert.Equal(512, props["maxItems"]!["maximum"]!.GetValue<int>());
        Assert.Equal(30000, props["maxChars"]!["maximum"]!.GetValue<int>());
        Assert.Null(server.ValidateArguments("Triage",
            JsonSerializer.Deserialize<JsonElement>("{}")));
    }

    [Fact]
    public async Task Sorts_By_RefCount_And_Respects_Top()
    {
        var (node, _) = await TriageAsync(MixedPayload(), new { top = 2 });
        var names = node["imports"]!.AsArray().Select(n => n!["name"]!.GetValue<string>()).ToArray();
        Assert.Equal(new[] { "WriteProcessMemory", "connect" }, names);
        Assert.True(node["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task MaxChars_Budget_Drops_Lowest_Ranked_Rows()
    {
        var many = Enumerable.Range(0, 20)
            .Select(i => Import("ws2_32.dll", "connect" + i, 20 - i))
            .ToArray();
        var (node, _) = await TriageAsync(Payload(many), new { top = 32, maxChars = 1000 });
        var raw = node.ToJsonString();
        Assert.True(raw.Length <= 1000);
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.True(node["imports"]!.AsArray().Count < 20);
    }

    [Fact]
    public async Task Limits_Are_Clamped()
    {
        // top=0 clamps to 1, huge maxItems clamps to the 512 backend bound.
        var (node, ghidra) = await TriageAsync(MixedPayload(), new { top = 0, maxItems = 999999 });
        Assert.Single(node["imports"]!.AsArray());
        Assert.Contains("\"maxItems\":512", ghidra.Calls.Single().ArgsJson);
    }

    [Fact]
    public async Task Legacy_Function_Field_And_Malformed_Rows()
    {
        var payload = JsonSerializer.Serialize(new
        {
            id = 1,
            ok = true,
            result = new
            {
                imports = new object[]
                {
                    new { library = "kernel32.dll", function = "CreateProcessW", address = "0x1", referenceSites = new[] { "0x2" }, referencesTruncated = false },
                    new { library = "x.dll", name = 42, address = "0x3" },
                    new { library = "y.dll", address = "0x4" },
                },
            },
        });
        var (node, _) = await TriageAsync(payload);
        Assert.Equal(1, node["totalExamined"]!.GetValue<int>());
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Wire_Triage_Is_Advertised_And_Cuts_Tokens()
    {
        var payload = Payload([Import("ws2_32.dll", "connect", 2), Import("msvcrt.dll", "strlen", 1)]);
        var ghidra = new StubGhidra(payload);
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        Assert.Contains(server.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == "Triage");
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "Triage",
            Arguments = new Dictionary<string, JsonElement> { ["top"] = JsonSerializer.SerializeToElement(32) },
        }, CancellationToken.None);
        Assert.False(result.IsError == true);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.Contains("suspiciousCount", text);
        // Counts, not full site arrays: no per-site address list on the wire.
        Assert.DoesNotContain("referenceSites", text);
        Assert.Contains("ListImports", ghidra.Calls.Single().Method);
    }

    [Fact]
    public async Task Purged_aliases_are_gone_from_discovery_and_calls()
    {
        // P3: the pre-merge TriageImports/TriageStrings aliases are physically
        // purged; Triage(kind=...) is the only triage surface (direct calls,
        // batches and map internals all go through it).
        var payload = Payload([Import("ws2_32.dll", "connect", 2)]);
        var ghidra = new StubGhidra(payload);
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == "TriageImports");
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == "TriageStrings");
        foreach (var alias in new[] { "TriageImports", "TriageStrings" })
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
            {
                Name = alias,
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
            Assert.StartsWith("Unknown tool", error.Message);
        }
        Assert.Empty(ghidra.Calls);
    }

    [Fact]
    public async Task Unified_Triage_Advertised_And_Callable()
    {
        // Single standard catalog: Triage is advertised everywhere and
        // callable (the dispatcher resolves all enabled tools).
        var payload = Payload([Import("ws2_32.dll", "connect", 2)]);
        using var lean = new LocalMcpServer(
            new ServerConfig { Port = 50302, Profile = ToolProfile.Lean },
            new RecordingBridge(), new StubGhidra(payload));
        Assert.Contains(lean.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == "Triage");
        var result = await lean.CallToolAsync(new CallToolRequestParams
        {
            Name = "Triage",
            Arguments = new Dictionary<string, JsonElement>(),
        }, CancellationToken.None);
        Assert.False(result.IsError == true);
        Assert.Contains("suspiciousCount", Assert.IsType<TextContentBlock>(result.Content[0]).Text);
    }

    private sealed class RoutingGhidra : IGhidraClient
    {
        private readonly Dictionary<string, Queue<string>> _pages = new(StringComparer.Ordinal);
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public void Enqueue(string method, string payload)
        {
            if (!_pages.TryGetValue(method, out var queue))
                _pages[method] = queue = new Queue<string>();
            queue.Enqueue(payload);
        }
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            if (_pages.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            return Task.FromResult(Payload([]));
        }
    }

    private static string ImportPage(object[] imports, bool truncated, int? nextOffset)
    {
        var result = new JsonObject
        {
            ["imports"] = JsonSerializer.SerializeToNode(imports),
            ["truncated"] = truncated,
        };
        if (nextOffset.HasValue)
            result["nextOffset"] = nextOffset.Value;
        return JsonSerializer.Serialize(new JsonObject { ["id"] = 1, ["ok"] = true, ["result"] = result });
    }

    private static string ExportPage(object[] exports, bool truncated, int? nextOffset)
    {
        var result = new JsonObject
        {
            ["exports"] = JsonSerializer.SerializeToNode(exports),
            ["truncated"] = truncated,
        };
        if (nextOffset.HasValue)
            result["nextOffset"] = nextOffset.Value;
        return JsonSerializer.Serialize(new JsonObject { ["id"] = 1, ["ok"] = true, ["result"] = result });
    }

    private static string BothPage(object[] imports, object[] exports, int? nextImports, int? nextExports)
    {
        var result = new JsonObject
        {
            ["imports"] = JsonSerializer.SerializeToNode(imports),
            ["exports"] = JsonSerializer.SerializeToNode(exports),
        };
        if (nextImports.HasValue)
            result["nextOffsetImports"] = nextImports.Value;
        if (nextExports.HasValue)
            result["nextOffsetExports"] = nextExports.Value;
        result["truncated"] = nextImports.HasValue || nextExports.HasValue;
        return JsonSerializer.Serialize(new JsonObject { ["id"] = 1, ["ok"] = true, ["result"] = result });
    }

    private static async Task<(JsonNode Node, RoutingGhidra Ghidra)> TriagePagedAsync(
        Action<RoutingGhidra> setup, object? args = null)
    {
        var ghidra = new RoutingGhidra();
        setup(ghidra);
        var ctx = new AnalysisContext(new NullBridge(), ghidra);
        var tools = new TriageImportsTools(ctx);
        var element = args is null ? (JsonElement?)null : JsonSerializer.SerializeToElement(args);
        var raw = await tools.TriageImportsAsync(element, CancellationToken.None);
        return (AnalysisFormatting.ReadBridgeResultNode(raw)!, ghidra);
    }

    [Fact]
    public async Task AutoPages_Across_ListImports_Pages_In_One_Call()
    {
        // Two ListImports pages behind one triage call with opt-in
        // maxPages>1: no manual filter/offset re-call needed. Default
        // maxPages=1 stays a single ListImports fetch.
        var (node, ghidra) = await TriagePagedAsync(g =>
        {
            g.Enqueue("ListImports", ImportPage(
                [Import("ws2_32.dll", "connect", 5), Import("kernel32.dll", "WriteProcessMemory", 6)],
                truncated: true, nextOffset: 2));
            g.Enqueue("ListImports", ImportPage(
                [Import("crypt32.dll", "CryptEncrypt", 1)],
                truncated: false, nextOffset: null));
        }, new { maxPages = 2 });
        Assert.Equal(2, ghidra.Calls.Count);
        Assert.All(ghidra.Calls, c => Assert.Equal("ListImports", c.Method));
        Assert.Contains("\"offset\":0", ghidra.Calls[0].ArgsJson);
        Assert.Contains("\"offset\":2", ghidra.Calls[1].ArgsJson);
        Assert.Equal(3, node["totalExamined"]!.GetValue<int>());
        Assert.Equal(3, node["suspiciousCount"]!.GetValue<int>());
        Assert.False(node["truncated"]!.GetValue<bool>());
        Assert.Null(node["nextOffset"]);
        var names = node["imports"]!.AsArray().Select(n => n!["name"]!.GetValue<string>()).ToArray();
        Assert.Equal(new[] { "WriteProcessMemory", "connect", "CryptEncrypt" }, names);
    }

    [Fact]
    public async Task Surfaces_NextOffset_When_More_Data_Remains()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
            g.Enqueue("ListImports", ImportPage(
                [Import("ws2_32.dll", "connect", 5), Import("kernel32.dll", "WriteProcessMemory", 6)],
                truncated: true, nextOffset: 2)),
            new { maxItems = 2 });
        Assert.Single(ghidra.Calls);
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.Equal(2, node["nextOffset"]!.GetValue<int>());
    }

    [Fact]
    public async Task Offset_Resumes_From_Prior_Continuation()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
            g.Enqueue("ListImports", ImportPage(
                [Import("ws2_32.dll", "connect", 5)],
                truncated: false, nextOffset: null)),
            new { offset = 5 });
        Assert.Contains("\"offset\":5", ghidra.Calls.Single().ArgsJson);
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.False(node["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task IncludeExports_Returns_Summary_In_One_Call()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
        {
            g.Enqueue("ListSymbolsBoth", BothPage(
                [Import("ws2_32.dll", "connect", 5)],
                [new { name = "ExportFunc", address = "0x140001000" }],
                nextImports: null, nextExports: null));
        }, new { includeExports = true });

        // One combined call carries both sides: no second Ghidra round trip.
        Assert.Single(ghidra.Calls);
        Assert.Equal("ListSymbolsBoth", ghidra.Calls[0].Method);
        Assert.Contains("\"maxItemsImports\":256", ghidra.Calls[0].ArgsJson);
        Assert.Contains("\"maxItemsExports\":16", ghidra.Calls[0].ArgsJson);
        var exports = node["exports"]!.AsArray();
        Assert.Single(exports);
        Assert.Equal("ExportFunc", exports[0]!["name"]!.GetValue<string>());
        Assert.Equal("0x140001000", exports[0]!["address"]!.GetValue<string>());
        Assert.Null(node["exportsTruncated"]);
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task IncludeExports_Falls_Back_When_The_Combined_Call_Fails()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
        {
            g.Enqueue("ListSymbolsBoth",
                "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"x\"}}");
            g.Enqueue("ListImports", ImportPage(
                [Import("ws2_32.dll", "connect", 5)], truncated: false, nextOffset: null));
            g.Enqueue("ListExports", ExportPage(
                [new { name = "ExportFunc", address = "0x140001000" }], truncated: false, nextOffset: null));
        }, new { includeExports = true });

        Assert.Equal(3, ghidra.Calls.Count);
        Assert.Equal("ListSymbolsBoth", ghidra.Calls[0].Method);
        Assert.Equal("ListImports", ghidra.Calls[1].Method);
        Assert.Equal("ListExports", ghidra.Calls[2].Method);
        Assert.Single(node["exports"]!.AsArray());
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Import_rows_drop_bridge_external_pseudo_addresses()
    {
        var payload = Payload([
            Import("kernel32.dll", "WriteProcessMemory", 6, "EXTERNAL:00000003"),
            Import("ws2_32.dll", "connect", 5, "0x140002000"),
        ]);
        var (node, _) = await TriageAsync(payload);

        var rows = node["imports"]!.AsArray()
            .ToDictionary(row => row!["name"]!.GetValue<string>());
        // The bridge EXTERNAL: counter is not an address the caller can use;
        // real mapped addresses stay.
        Assert.Null(rows["WriteProcessMemory"]!["address"]);
        Assert.Equal("0x140002000", rows["connect"]!["address"]!.GetValue<string>());
    }

    [Fact]
    public async Task Exports_Omitted_By_Default_For_Compat()
    {
        var (node, ghidra) = await TriageAsync(MixedPayload());
        Assert.Null(node["exports"]);
        Assert.Null(node["exportsTruncated"]);
        Assert.DoesNotContain(ghidra.Calls, c => c.Method == "ListExports");
    }

    [Fact]
    public async Task Later_Page_Failure_Keeps_Rows_And_Reports_Truncated()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
        {
            g.Enqueue("ListImports", ImportPage(
                [Import("ws2_32.dll", "connect", 5)],
                truncated: true, nextOffset: 1));
            g.Enqueue("ListImports",
                "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"y\"}}");
        }, new { maxPages = 2 });
        Assert.Equal(2, ghidra.Calls.Count);
        Assert.Equal(1, node["suspiciousCount"]!.GetValue<int>());
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.Equal(1, node["nextOffset"]!.GetValue<int>());
    }

    [Fact]
    public async Task Page_Iteration_Is_Bounded()
    {
        var (node, ghidra) = await TriagePagedAsync(g =>
        {
            for (var i = 0; i < 10; i++)
                g.Enqueue("ListImports", ImportPage(
                    [Import("ws2_32.dll", "connect" + i, 1)],
                    truncated: true, nextOffset: i + 1));
        }, new { maxItems = 512, maxPages = 8 });
        Assert.True(ghidra.Calls.Count <= 8);
        Assert.True(node["truncated"]!.GetValue<bool>());
        Assert.NotNull(node["nextOffset"]);
    }
}
