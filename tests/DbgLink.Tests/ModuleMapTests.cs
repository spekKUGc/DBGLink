using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// GetModuleMap is the map-first entry point: one bounded call that fans out
/// over already-tested static reads (status/ListSections/ListSymbolsBoth/
/// ListFunctions/TriageStrings) and never decompiles. These tests pin the
/// composition, the caps, honest degradation and the no-decompiler contract.
/// </summary>
public sealed class ModuleMapTests
{
    private sealed class MapBackend : IGhidraClient
    {
        private const string DefaultFunctions = """
            {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","sha256":"abc123",
            "functions":[{"name":"entry","entry":"0x140001000","size":64},
            {"name":"main","entry":"0x140001040","size":128}],"truncated":false}}
            """;
        private readonly object _gate = new();
        private readonly Dictionary<string, string> _failures = new(StringComparer.Ordinal);
        private readonly string _functions;
        public List<(string Method, string? Args)> Calls { get; } = [];

        public MapBackend(string? functions = null) => _functions = functions ?? DefaultFunctions;

        public MapBackend Fail(string method, string code = "ghidra_timeout")
        {
            _failures[method] = $"{{\"ok\":false,\"error\":{{\"code\":\"{code}\",\"message\":\"boom\"}}}}";
            return this;
        }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            lock (_gate) Calls.Add((method, arguments?.GetRawText()));
            if (_failures.TryGetValue(method, out var failure))
                return Task.FromResult(failure);
            return Task.FromResult(method switch
            {
                "status" => """
                    {"ok":true,"result":{"available":true,"sha256":"abc123","minAddress":"0x140000000","maxAddress":"0x140010000",
                    "program":{"fileName":"app.exe","format":"PE","sha256":"abc123","imageBase":"0x140000000",
                    "minAddress":"0x140000000","maxAddress":"0x140010000","architecture":"x86",
                    "language":"x86:LE:64:default","languageId":"x86:LE:64:default","compiler":"windows",
                    "compilerSpec":"windows","functionCount":42}}}
                    """,
                "ListSections" => """
                    {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","sha256":"abc123",
                    "entryPoint":"0x140001000","entryFunction":{"name":"entry","entry":"0x140001000"},
                    "sections":[
                    {"name":".text","start":"0x140001000","end":"0x140001fff","size":4096,"permissions":"r-x","initialized":true},
                    {"name":".rdata","start":"0x140002000","end":"0x140002fff","size":4096,"permissions":"r--","initialized":true},
                    {"name":".data","start":"0x140003000","end":"0x140003fff","size":4096,"permissions":"rw-","initialized":true}],
                    "truncated":false}}
                    """,
                "ListSymbolsBoth" => """
                    {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","sha256":"abc123",
                    "imports":[
                    {"name":"CreateFileW","library":"kernel32.dll","address":"EXTERNAL:1","refCount":2},
                    {"name":"connect","library":"ws2_32.dll","address":"EXTERNAL:2","refCount":5},
                    {"name":"strlen","library":"msvcrt.dll","address":"EXTERNAL:3","refCount":9}],
                    "exports":[{"name":"DllMain","address":"0x140001000"}],
                    "importsTruncated":false,"exportsTruncated":false,"truncated":false}}
                    """,
                "ListFunctions" => _functions,
                "DumpStrings" => """
                    {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","sha256":"abc123",
                    "strings":[
                    {"address":"0x140002010","text":"http://evil.example/c2","length":24},
                    {"address":"0x140002040","text":"192.168.1.10","length":12},
                    {"address":"0x140002060","text":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","length":48}],
                    "truncated":false}}
                    """,
                "InspectFunction" => """
                    {"ok":true,"result":{"decompilation":{"status":"ok","code":"int entry(){return 0;}"}}}
                    """,
                _ => "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"unexpected\"}}",
            });
        }
    }

    private static async Task<(JsonObject Map, MapBackend Backend)> MapAsync(
        string args = "{}", MapBackend? backend = null)
    {
        backend ??= new MapBackend();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var response = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetModuleMap",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(args)!
        }, CancellationToken.None);
        Assert.False(response.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(response.Content)).Text;
        // Non-raw tools are unwrapped by the dispatcher: the wire text is the
        // result object itself, not the {ok,result} envelope.
        var node = JsonNode.Parse(text);
        Assert.NotNull(node);
        Assert.True(node is JsonObject, text);
        return ((JsonObject)node!, backend);
    }

    [Fact]
    public async Task Map_composes_module_sections_entry_symbols_strings_functions_without_decompiling()
    {
        var (map, backend) = await MapAsync();

        Assert.Equal("app.exe", map["module"]!["fileName"]!.GetValue<string>());
        Assert.Equal(42, map["module"]!["functionCount"]!.GetValue<int>());
        Assert.Equal("0x140001000", Assert.Single(map["entryPoints"]!.AsArray())!["address"]!.GetValue<string>());
        Assert.Equal("entry", map["entryPoints"]![0]!["name"]!.GetValue<string>());
        Assert.Equal(3, map["sections"]!.AsArray().Count);
        Assert.Equal("r-x", map["sections"]![0]!["permissions"]!.GetValue<string>());

        var imports = map["imports"]!;
        Assert.Equal(3, imports["returned"]!.GetValue<int>());
        // Absence means "not truncated": the wire omits negative optional flags.
        Assert.Null(imports["truncated"]);
        // Highest refCount first: the map answers "what does this binary use most".
        Assert.Equal("strlen", imports["top"]![0]!["name"]!.GetValue<string>());
        Assert.Equal(new[] { "kernel32.dll", "msvcrt.dll", "ws2_32.dll" },
            imports["libraries"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray());

        Assert.Equal(1, map["exports"]!["returned"]!.GetValue<int>());
        Assert.Equal("DllMain", map["exports"]!["top"]![0]!["name"]!.GetValue<string>());

        Assert.Equal(2, map["functions"]!["sample"]!.AsArray().Count);
        Assert.Equal(42, map["functions"]!["total"]!.GetValue<int>());

        var strings = map["strings"]!;
        Assert.Equal(3, strings["examined"]!.GetValue<int>());
        Assert.Equal(3, strings["suspicious"]!.GetValue<int>());
        Assert.Equal(1, strings["byType"]!["C2_URL"]!.GetValue<int>());
        Assert.Equal(1, strings["byType"]!["IP_Address"]!.GetValue<int>());

        Assert.Null(map["degraded"]);
        Assert.Contains("includeDecomp:false", map["nextAction"]!.GetValue<string>());

        // The map must stay decompiler-free: it is the substitute for
        // "decompile everything first", not another entry into it.
        Assert.DoesNotContain(backend.Calls, call =>
            call.Method is "InspectFunction" or "AnalyzeFunctions" or "DecompileModule");
        Assert.Single(backend.Calls, call => call.Method == "ListSections");
        Assert.Single(backend.Calls, call => call.Method == "ListSymbolsBoth");
        Assert.Single(backend.Calls, call => call.Method == "ListFunctions");
        Assert.Contains("\"includeCounts\":true",
            backend.Calls.Single(call => call.Method == "ListFunctions").Args);
        Assert.Single(backend.Calls, call => call.Method == "DumpStrings");
    }

    [Fact]
    public async Task Map_compact_diet_drops_derived_fields_and_keeps_decisions()
    {
        var (full, _) = await MapAsync(
            "{\"maxSections\":12,\"maxSymbols\":20,\"maxFunctions\":8,\"maxStrings\":8}");
        var (compact, _) = await MapAsync(
            "{\"maxSections\":12,\"maxSymbols\":20,\"maxFunctions\":8,\"maxStrings\":8,\"compact\":true}");

        Assert.True(compact.ToJsonString().Length < full.ToJsonString().Length - 300,
            $"compact {compact.ToJsonString().Length} vs full {full.ToJsonString().Length}");
        // Derived echoes are gone; decision data stays.
        Assert.False(compact["module"]!.AsObject().ContainsKey("language"));
        Assert.True(compact["module"]!.AsObject().Count <= 5);
        Assert.False(compact["imports"]!.AsObject().ContainsKey("libraries"));
        Assert.False(compact["functions"]!.AsObject().ContainsKey("total"));
        Assert.NotNull(compact["imports"]!["top"]);
        Assert.NotNull(compact["functions"]!["sample"]);
        Assert.NotNull(compact["sections"]);
        Assert.True(compact["nextAction"]!.GetValue<string>().Length < 180);

        // The default shape keeps the convenience fields.
        Assert.True(full["imports"]!.AsObject().ContainsKey("libraries"));
        Assert.True(full["functions"]!.AsObject().ContainsKey("total"));
    }

    private sealed class StringPagingBackend : IGhidraClient
    {
        private readonly MapBackend _inner = new();
        private readonly List<(string Method, string? Args)> _calls = [];

        public List<(string Method, string? Args)> Calls => _calls;

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            lock (_calls) _calls.Add((method, arguments?.GetRawText()));
            if (method != "DumpStrings")
                return _inner.RequestAsync(method, arguments, token);
            return Task.FromResult(
                "{\"ok\":true,\"result\":{\"source\":\"ghidra-static\",\"imageBase\":\"0x140000000\"," +
                "\"strings\":[{\"address\":\"0x140002010\",\"text\":\"http://evil.example/c2\",\"length\":24}]," +
                "\"truncated\":true,\"nextAddress\":\"0x140002040\"}}");
        }
    }

    [Fact]
    public async Task Map_bounds_string_paging_to_two_pages()
    {
        var backend = new StringPagingBackend();
        var map = await MapWithClientAsync(backend);

        Assert.Equal(2, backend.Calls.Count(call => call.Method == "DumpStrings"));
        Assert.True(map["strings"]!["truncated"]!.GetValue<bool>());
        Assert.NotNull(map["strings"]!["nextAddress"]);
    }

    private sealed class ImportPagingBackend : IGhidraClient
    {
        private readonly MapBackend _inner = new();

        public List<(string Method, string? Args)> Calls => _inner.Calls;

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            if (method != "ListSymbolsBoth")
                return _inner.RequestAsync(method, arguments, token);
            var offset = 0;
            if (arguments is { ValueKind: JsonValueKind.Object } args &&
                args.TryGetProperty("offsetImports", out var offsetNode))
                offset = offsetNode.GetInt32();
            // Simulate a bridge page smaller than the total so the map must
            // follow nextOffsetImports; imp25 lives on the second page.
            const int pageSize = 20;
            var rows = Enumerable.Range(offset, Math.Min(pageSize, 30 - offset)).Select(index =>
                $"{{\"name\":\"imp{index:00}\",\"library\":\"lib.dll\",\"address\":\"EXTERNAL:{index}\",\"refCount\":{index}}}");
            var next = offset + pageSize < 30 ? offset + pageSize : (int?)null;
            var cursor = next is null ? "" : ",\"nextOffsetImports\":" + next.Value;
            return Task.FromResult(
                "{\"ok\":true,\"result\":{\"source\":\"ghidra-static\",\"imageBase\":\"0x140000000\",\"sha256\":\"abc123\"," +
                "\"imports\":[" + string.Join(',', rows) + "],\"exports\":[],\"importsTruncated\":" +
                (next is null ? "false" : "true") + cursor +
                ",\"exportsTruncated\":false,\"truncated\":true}}");
        }
    }

    private static async Task<JsonObject> MapWithClientAsync(IGhidraClient backend)
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var response = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetModuleMap",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("{}")!
        }, CancellationToken.None);
        Assert.False(response.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(response.Content)).Text;
        return (JsonObject)JsonNode.Parse(text)!;
    }

    [Fact]
    public async Task Map_ranks_imports_beyond_the_first_symbol_page()
    {
        var backend = new ImportPagingBackend();
        var map = await MapWithClientAsync(backend);

        var top = map["imports"]!["top"]!.AsArray()
            .Select(node => node!["name"]!.GetValue<string>()).ToArray();
        // imp25 has refCount 25 and lies beyond the old 20-row first page.
        Assert.Contains("imp25", top);
        Assert.Contains("imp29", top);
        Assert.True(map["imports"]!["truncated"]!.GetValue<bool>());
        Assert.True(backend.Calls.Count(call => call.Method == "ListSymbolsBoth") <= 2);
    }

    [Fact]
    public async Task Map_caps_every_list_and_reports_truncation()
    {
        var (map, _) = await MapAsync(
            "{\"maxSections\":2,\"maxSymbols\":2,\"maxFunctions\":1,\"maxStrings\":1}");

        Assert.Equal(new[] { ".text", ".rdata" },
            map["sections"]!.AsArray().Select(n => n!["name"]!.GetValue<string>()).ToArray());
        Assert.True(map["sectionsTruncated"]!.GetValue<bool>());
        Assert.Equal(new[] { "strlen", "connect" },
            map["imports"]!["top"]!.AsArray().Select(n => n!["name"]!.GetValue<string>()).ToArray());
        Assert.True(map["imports"]!["truncated"]!.GetValue<bool>());
        Assert.Single(map["functions"]!["sample"]!.AsArray());
        Assert.True(map["functions"]!["truncated"]!.GetValue<bool>());
        Assert.Single(map["strings"]!["top"]!.AsArray());
        Assert.Equal("C2_URL", map["strings"]!["top"]![0]!["type"]!.GetValue<string>());
        Assert.True(map["strings"]!["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Map_degrades_honestly_when_a_read_fails()
    {
        var (map, backend) = await MapAsync(backend: new MapBackend().Fail("ListSections"));

        // Empty containers are omitted on the wire: an absent slice means the
        // same as an empty one, and the degraded list still names the failure.
        Assert.Null(map["sections"]);
        // The failed slice is named; the rest of the map still answers.
        Assert.Contains(map["degraded"]!.AsArray(),
            node => node!.GetValue<string>().StartsWith("ListSections:", StringComparison.Ordinal));
        Assert.Equal("app.exe", map["module"]!["fileName"]!.GetValue<string>());
        Assert.Single(backend.Calls, call => call.Method == "ListSections");
    }

    [Fact]
    public async Task Map_skips_string_scan_when_disabled()
    {
        var (map, backend) = await MapAsync("{\"includeStrings\":false}");

        Assert.DoesNotContain(backend.Calls, call => call.Method == "DumpStrings");
        Assert.Null(map["strings"]);
        Assert.Equal("app.exe", map["module"]!["fileName"]!.GetValue<string>());
    }

    [Fact]
    public async Task Map_ranks_functions_by_risk_and_explains_why()
    {
        var backend = new MapBackend("""
            {"ok":true,"result":{"source":"ghidra-static","imageBase":"0x140000000","sha256":"abc123",
            "functions":[
            {"name":"FUN_140001000","entry":"0x140001000","size":32,"instructionCount":12,"branchCount":2},
            {"name":"FUN_140001100","entry":"0x140001100","size":400,"instructionCount":120,"branchCount":18},
            {"name":"main","entry":"0x140001200","size":200,"instructionCount":60,"branchCount":9},
            {"name":"thunk_FUN_140001300","entry":"0x140001300","size":8,"thunk":true}],
            "truncated":false}}
            """);

        var (map, _) = await MapAsync("{\"maxFunctions\":4}", backend);
        var functions = map["functions"]!;
        var sample = functions["sample"]!.AsArray();

        Assert.Equal("risk", functions["order"]!.GetValue<string>());
        Assert.Equal(4, sample.Count);
        Assert.Equal("main", sample[0]!["name"]!.GetValue<string>());
        Assert.Equal("FUN_140001100", sample[1]!["name"]!.GetValue<string>());
        Assert.Equal("thunk_FUN_140001300", sample[3]!["name"]!.GetValue<string>());
        Assert.True(sample[0]!["risk"]!.GetValue<int>() > sample[1]!["risk"]!.GetValue<int>());
        Assert.Contains("entry-like", sample[0]!["why"]!.GetValue<string>());
        Assert.Contains("thunk", sample[3]!["why"]!.GetValue<string>());
        Assert.Null(functions["truncated"]);
    }

    [Fact]
    public async Task Map_entry_decomp_opt_in_attaches_bounded_entry_decompilation()
    {
        var (map, backend) = await MapAsync("{\"includeEntryDecomp\":true}");

        // One bounded InspectFunction answers "what does entry do" in the
        // same call; the rest of the map stays decompiler-free.
        Assert.Equal("int entry(){return 0;}", map["entryDecomp"]!["code"]!.GetValue<string>());
        var inspect = Assert.Single(backend.Calls, call => call.Method == "InspectFunction");
        Assert.Contains("\"function\":\"0x140001000\"", inspect.Args);
        Assert.Contains("\"maxChars\":4000", inspect.Args);
        Assert.Contains("\"includeReferences\":false", inspect.Args);

        // Opt-out (default) keeps the historical decompiler-free map.
        var (plain, plainBackend) = await MapAsync("{}");
        Assert.Null(plain["entryDecomp"]);
        Assert.DoesNotContain(plainBackend.Calls, call => call.Method == "InspectFunction");
    }

    [Fact]
    public async Task Map_entry_decomp_failure_degrades_honestly()
    {
        var (map, _) = await MapAsync(
            "{\"includeEntryDecomp\":true}", new MapBackend().Fail("InspectFunction"));

        Assert.Null(map["entryDecomp"]);
        Assert.Contains(map["degraded"]!.AsArray(),
            node => node!.GetValue<string>().StartsWith("InspectFunction(entry):", StringComparison.Ordinal));
        Assert.Equal("app.exe", map["module"]!["fileName"]!.GetValue<string>());
    }

    [Fact]
    public void Schema_entry_decomp_is_opt_in_bool()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), new MapBackend());

        Assert.Null(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"includeEntryDecomp\":true}")));
        Assert.NotNull(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"includeEntryDecomp\":\"yes\"}")));
    }

    [Fact]
    public void Schema_is_bounded_and_string_scan_is_opt_out()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), new MapBackend());

        Assert.Null(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>("{}")));
        Assert.Null(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"maxSections\":64,\"maxSymbols\":64,\"maxFunctions\":64,\"maxStrings\":32,\"includeStrings\":false}")));
        Assert.NotNull(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"maxSections\":65}")));
        Assert.NotNull(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"maxStrings\":33}")));
        Assert.NotNull(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"includeStrings\":\"no\"}")));
        Assert.NotNull(server.ValidateArguments("GetModuleMap", JsonSerializer.Deserialize<JsonElement>(
            "{\"unexpected\":1}")));
    }
}
