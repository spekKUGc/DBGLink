using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class StaticQueryTests
{
    private sealed class StaticBackend : IGhidraClient
    {
        public List<string> Calls { get; } = [];
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add(method);
            return Task.FromResult(method == "XrefsTo"
                ? "{\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"bad address\"}}"
                : "{\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}");
        }
    }

    private sealed class TriageBackend : IGhidraClient
    {
        public List<(string Method, string? ArgsJson)> Calls { get; } = [];
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult(method switch
            {
                "ListImports" => "{\"ok\":true,\"result\":{\"imports\":[{\"name\":\"CreateRemoteThread\",\"library\":\"kernel32\",\"address\":\"EXTERNAL:0\",\"refCount\":1}],\"truncated\":false}}",
                "ListExports" => "{\"ok\":true,\"result\":{\"exports\":[{\"name\":\"main\",\"address\":\"0x140001000\"}],\"truncated\":false}}",
                "DumpStrings" => "{\"ok\":true,\"result\":{\"strings\":[{\"address\":\"0x140003000\",\"text\":\"hello\",\"length\":5}],\"truncated\":false}}",
                "ListFunctions" => "{\"ok\":true,\"result\":{\"functions\":[],\"truncated\":false}}",
                "GetAnalysisQueue" => "{\"ok\":true,\"result\":{\"schemaVersion\":2,\"queue\":[{\"name\":\"fn0\",\"entry\":\"0x140001000\",\"rva\":\"0x1000\",\"instructionCount\":4,\"named\":false,\"calleeCount\":0}],\"totalFunctions\":1,\"returned\":1,\"limit\":8,\"doneCount\":0,\"remainingCount\":1,\"truncated\":false}}",
                "AnalyzeFunctions" => "{\"ok\":true,\"result\":{\"schemaVersion\":2,\"functions\":[{\"index\":0,\"selector\":\"0x140001000\",\"ok\":true}],\"truncated\":false,\"truncatedSections\":[]}}",
                _ => "{\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}",
            });
        }
    }

    private static CallToolRequestParams Request(string name, string args) => new()
    { Name = name, Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(args)! };

    [Theory]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"filter\":\"AIL_*\"}")]
    [InlineData("ListSymbols", "{\"kind\":\"exports\"}")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"includeSites\":true}")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"includeSites\":false,\"maxSites\":0}")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"maxSites\":32}")]
    [InlineData("ListFunctions", "{\"start\":\"1000\",\"end\":\"2000\"}")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"to\"}")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"from\"}")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"both\"}")]
    [InlineData("ListSymbols", "{\"kind\":\"both\"}")]
    [InlineData("ListSymbols", "{\"kind\":\"both\",\"includeSites\":true}")]
    [InlineData("ReadStaticBytes", "{\"address\":\"1000\",\"length\":32}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[{\"address\":\"1000\",\"length\":32}]}")]
    public async Task Static_tools_are_advertised_and_use_Ghidra_without_native_or_control(string method, string args)
    {
        var backend = new StaticBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        Assert.Contains(server.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == method);
        await server.CallToolAsync(Request(method, args), CancellationToken.None);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public async Task DumpStrings_survives_only_inside_batch_queries()
    {
        // P3: the top-level DumpStrings single is purged (covered by Triage
        // kind=strings); the batch row keeps working with identical rules.
        var backend = new TriageBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), t => t["name"]!.GetValue<string>() == "DumpStrings");
        var result = await server.CallToolAsync(Request("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"DumpStrings\",\"arguments\":{\"section\":\".rdata\",\"maxItems\":16}}]}"), CancellationToken.None);
        Assert.False(result.IsError == true);
        Assert.Single(backend.Calls, call => call.Method == "DumpStrings");
        Assert.Equal(0, live.RequestCount);
    }

    [Theory]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"to\"}", "XrefsTo")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"from\"}", "XrefsFrom")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"both\"}", "XrefsBoth")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"BOTH\"}", "XrefsBoth")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"both\",\"maxItemsTo\":4}", "XrefsBoth")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\"}", "ListImports")]
    [InlineData("ListSymbols", "{\"kind\":\"exports\"}", "ListExports")]
    [InlineData("ListSymbols", "{\"kind\":\"both\"}", "ListSymbolsBoth")]
    [InlineData("ListSymbols", "{\"kind\":\"BOTH\"}", "ListSymbolsBoth")]
    public async Task Canonical_static_tools_fan_out_to_legacy_bridge_methods(string method, string args, string expectedBridge)
    {
        var backend = new StaticBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        await server.CallToolAsync(Request(method, args), CancellationToken.None);
        Assert.Equal(new[] { expectedBridge }, backend.Calls);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public async Task Both_modes_strip_the_selector_and_forward_paging_keys()
    {
        var backend = new TriageBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        await server.CallToolAsync(Request("Xrefs",
            "{\"address\":\"1000\",\"direction\":\"both\",\"maxItemsTo\":4,\"offsetFrom\":2}"), CancellationToken.None);
        var xrefs = Assert.Single(backend.Calls.Where(c => c.Method == "XrefsBoth"));
        Assert.DoesNotContain("direction", xrefs.ArgsJson);
        Assert.Contains("\"maxItemsTo\":4", xrefs.ArgsJson);
        Assert.Contains("\"offsetFrom\":2", xrefs.ArgsJson);
        await server.CallToolAsync(Request("ListSymbols",
            "{\"kind\":\"both\",\"maxItemsImports\":8}"), CancellationToken.None);
        var symbols = Assert.Single(backend.Calls.Where(c => c.Method == "ListSymbolsBoth"));
        Assert.DoesNotContain("\"kind\"", symbols.ArgsJson);
        Assert.Contains("\"maxItemsImports\":8", symbols.ArgsJson);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public async Task ListSymbols_exports_strips_site_opts_and_imports_forwards_them()
    {
        var backend = new TriageBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        await server.CallToolAsync(Request("ListSymbols",
            "{\"kind\":\"exports\",\"includeSites\":true,\"maxSites\":8}"), CancellationToken.None);
        var exports = Assert.Single(backend.Calls.Where(c => c.Method == "ListExports"));
        Assert.DoesNotContain("includeSites", exports.ArgsJson);
        Assert.DoesNotContain("maxSites", exports.ArgsJson);
        await server.CallToolAsync(Request("ListSymbols",
            "{\"kind\":\"imports\",\"includeSites\":true,\"maxSites\":4}"), CancellationToken.None);
        var imports = Assert.Single(backend.Calls.Where(c => c.Method == "ListImports"));
        Assert.Contains("includeSites", imports.ArgsJson);
        Assert.Contains("\"maxSites\":4", imports.ArgsJson);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public async Task Status_reports_missing_Ghidra_even_when_native_is_healthy()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort },
            new FixedResponseBridge("{\"ok\":true,\"debugging\":false}"), new NullGhidra());
        var result = await server.CallToolAsync(Request("GetServerStatus", "{}"), CancellationToken.None);
        var status = JsonNode.Parse(Assert.IsType<TextContentBlock>(result.Content[0]).Text)!;
        Assert.True(status["ok"]!.GetValue<bool>());
        Assert.False(status["ghidra"]!["ready"]!.GetValue<bool>());
        // The attached echo is omitted when it matches the root debugging flag.
        Assert.False(status["debugging"]!.GetValue<bool>());
        Assert.Null(status["debugger"]);
        Assert.Empty(status["ghidra"]!["queue"]!.AsArray());
        // Derived counters and null error literals are not paid for.
        var telemetry = status["telemetry"]!;
        Assert.Null(telemetry["total"]?["error"]);
        Assert.Null(telemetry["total"]?["okRate"]);
        Assert.Null(telemetry["backends"]?["native"]?["fail"]);
        Assert.Null(telemetry["backends"]?["native"]?["topError"]);
    }

    [Fact]
    public async Task Status_sections_without_readiness_skip_the_ghidra_probe()
    {
        var ghidra = new StatusCountingGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort },
            new FixedResponseBridge("{\"ok\":true,\"debugging\":false}"), ghidra);

        var httpOnly = await server.CallToolAsync(Request("GetServerStatus", "{\"sections\":[\"http\"]}"), CancellationToken.None);
        var httpStatus = JsonNode.Parse(Assert.IsType<TextContentBlock>(httpOnly.Content[0]).Text)!;
        // A filtered view that excludes summary/backends does not pay the
        // Ghidra readiness probe.
        Assert.Equal(0, ghidra.Calls);
        Assert.Null(httpStatus["ghidra"]);
        Assert.NotNull(httpStatus["telemetry"]!["http"]);

        var backends = await server.CallToolAsync(Request("GetServerStatus", "{\"sections\":[\"backends\"]}"), CancellationToken.None);
        Assert.Equal(1, ghidra.Calls);
        Assert.NotNull(JsonNode.Parse(Assert.IsType<TextContentBlock>(backends.Content[0]).Text)!["ghidra"]);
    }

    [Fact]
    public async Task Batch_preserves_order_and_individual_errors()
    {
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"ListSymbols","arguments":{"kind":"imports","filter":"AIL_*"}},
            {"method":"Xrefs","arguments":{"address":"bad","direction":"to"}},
            {"method":"ListFunctions","arguments":{}}]}
            """), CancellationToken.None);
        Assert.Equal(new[] { "ListImports", "XrefsTo", "ListFunctions" }, backend.Calls);
        Assert.Contains("invalid_address", Assert.IsType<TextContentBlock>(result.Content[0]).Text);
        Assert.True(JsonNode.Parse(Assert.IsType<TextContentBlock>(result.Content[0]).Text)!["partial"]!.GetValue<bool>());
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task Batch_accepts_DecompileModule()
    {
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"DecompileModule","arguments":{"start":"1000","maxFunctions":2}}]}
            """), CancellationToken.None);
        Assert.Equal(new[] { "DecompileModule" }, backend.Calls);
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task DecompileModule_invalid_row_is_isolated_per_row()
    {
        // P0-1 contract: the static batch runs a local dispatcher, so a
        // schema-level row failure becomes a per-row invalid_batch error, not
        // a whole-batch abort. Family mismatch stays a hard error (pinned by
        // Batch_with_nonstatic_method_reports_invalid_batch_without_work).
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"DecompileModule","arguments":{"function":"1000","maxFunctions":2}}]}
            """), CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.Contains("invalid_batch", text);
        Assert.Contains("Request #0", text);
        Assert.True(JsonNode.Parse(text)!["partial"]!.GetValue<bool>());
        Assert.Empty(backend.Calls);
    }

    [Theory]
    [InlineData("ReadStaticBytes", "{\"address\":\"1000\",\"length\":0}")]
    [InlineData("ReadStaticBytes", "{\"address\":\"1000\",\"length\":32769}")]
    [InlineData("ReadStaticBytes", "{}")]
    [InlineData("Xrefs", "{\"address\":\"1000\"}")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"sideways\"}")]
    [InlineData("ListSymbols", "{}")]
    [InlineData("ListSymbols", "{\"kind\":\"bogus\"}")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"maxSites\":33}")]
    [InlineData("ListSymbols", "{\"kind\":\"imports\",\"includeSites\":\"yes\"}")]
    [InlineData("ListFunctions", "{\"maxItems\":0}")]
    [InlineData("ListFunctions", "{\"maxItems\":129}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[]}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[{\"length\":8}]}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[{\"address\":\"1000\",\"length\":0}]}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[{\"address\":\"1000\",\"length\":4097}]}")]
    [InlineData("ReadStaticBytes", "{\"ranges\":[{\"address\":\"1000\",\"length\":8,\"extra\":1}]}")]
    [InlineData("Xrefs", "{\"address\":\"1000\",\"direction\":\"both\",\"maxItemsTo\":0}")]
    [InlineData("ListSymbols", "{\"kind\":\"both\",\"maxItemsImports\":129}")]
    public async Task Invalid_static_arguments_never_reach_Ghidra(string method, string args)
    {
        var backend = new StaticBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() =>
            server.CallToolAsync(Request(method, args), CancellationToken.None));
        Assert.Empty(backend.Calls);
        Assert.Equal(0, live.RequestCount);
    }

    [Theory]
    [InlineData("{\"maxItems\":513}")]
    [InlineData("{\"maxItems\":0}")]
    [InlineData("{\"maxScanBytes\":1024}")]
    [InlineData("{\"minLength\":1}")]
    [InlineData("{\"minLength\":257}")]
    [InlineData("{\"includeHex\":\"yes\"}")]
    public async Task Invalid_batch_DumpStrings_row_never_reaches_Ghidra(string args)
    {
        // P3: DumpStrings validates only as a batch row now; a bad row is
        // isolated per-row with no backend call (static batches fan out).
        var backend = new TriageBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"DumpStrings\",\"arguments\":" + args + "}]}"), CancellationToken.None);
        Assert.False(result.IsError == true);
        Assert.Contains("invalid_batch", TestWire.RawText(result));
        Assert.Empty(backend.Calls);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public async Task Oversized_batch_of_valid_items_is_rejected_before_any_work()
    {
        // 17 individually valid items: only the 16-item batch cap rejects them.
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var items = string.Join(",", Enumerable.Repeat(
            "{\"method\":\"ListFunctions\",\"arguments\":{}}", 17));
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() =>
            server.CallToolAsync(Request("BatchStaticQueries",
                "{\"requests\":[" + items + "]}"), CancellationToken.None));
        Assert.Empty(backend.Calls);
    }

    [Theory]
    [InlineData("{\"requests\":[]}")]
    [InlineData("{\"requests\":[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]}")]
    public async Task Malformed_batch_shape_is_rejected_before_any_work(string json)
    {
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() =>
            server.CallToolAsync(Request("BatchStaticQueries", json), CancellationToken.None));
        Assert.Empty(backend.Calls);
    }

    [Theory]
    [InlineData("NoSuchMethod")]
    [InlineData("RenameFunction")]
    [InlineData("SetBreakpoint")]
    public async Task Batch_with_nonstatic_method_reports_invalid_batch_without_work(string method)
    {
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"" + method + "\",\"arguments\":{}}]}"), CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Contains("invalid_batch", Assert.IsType<TextContentBlock>(result.Content[0]).Text);
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public async Task Batch_duplicate_static_items_share_one_backend_call()
    {
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"ListFunctions","arguments":{}},
            {"method":"ListFunctions","arguments":{}}]}
            """), CancellationToken.None);
        Assert.False(result.IsError);
        Assert.Single(backend.Calls);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.Contains("\"index\":0", text);
        Assert.Contains("\"index\":1", text);
    }

    [Theory]
    [InlineData("{\"method\":\"RenameFunction\",\"arguments\":{\"function\":\"1000\",\"name\":\"Mixer\"}}")]
    [InlineData("{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"imports\",\"analysisId\":\"other\"}}")]
    [InlineData("{\"method\":\"XrefsTo\",\"arguments\":{\"address\":\"1000\"}}")]
    public async Task Invalid_batch_is_rejected_before_any_work(string invalid)
    {
        // Family mismatch and nested analysisId stay hard whole-batch errors
        // with zero backend calls. Schema-level row failures are per-row now
        // (Batch_schema_failure_is_isolated_per_row): they no longer abort.
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"imports\"}}," + invalid + "]}"), CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public async Task Batch_schema_failure_is_isolated_per_row()
    {
        // P0-1 contract: one schema-bad row fails only its index; the valid
        // prefix row still runs exactly once.
        var backend = new StaticBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"ListSymbols\",\"arguments\":{\"kind\":\"imports\"}}," +
            "{\"method\":\"ReadStaticBytes\",\"arguments\":{\"address\":\"1000\",\"length\":32769}}," +
            "{\"method\":\"ListFunctions\",\"arguments\":{}}]}"), CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        using var document = JsonDocument.Parse(text);
        Assert.True(document.RootElement.GetProperty("partial").GetBoolean());
        var rows = document.RootElement.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(3, rows.Length);
        Assert.True(rows[0].GetProperty("response").GetProperty("ok").GetBoolean());
        var bad = rows[1].GetProperty("response");
        Assert.False(bad.GetProperty("ok").GetBoolean());
        Assert.Equal("invalid_batch", bad.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("Request #1", bad.GetProperty("error").GetProperty("message").GetString());
        Assert.True(rows[2].GetProperty("response").GetProperty("ok").GetBoolean());
        Assert.Equal(new[] { "ListImports", "ListFunctions" }, backend.Calls);
    }

    [Fact]
    public async Task Batch_triage_module_runs_six_reads_in_one_call()
    {
        // P0-1 win: ListSymbols-imports + ListSymbols-exports + Triage(strings)
        // + Triage(imports) + GetAnalysisQueue + ListFunctions in ONE batch call.
        // (P3: TriageStrings/TriageImports aliases purged; unified Triage rows.)
        var backend = new TriageBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"ListSymbols","arguments":{"kind":"imports"}},
            {"method":"ListSymbols","arguments":{"kind":"exports"}},
            {"method":"Triage","arguments":{"kind":"strings","section":".rdata"}},
            {"method":"Triage","arguments":{"kind":"imports"}},
            {"method":"GetAnalysisQueue","arguments":{}},
            {"method":"ListFunctions","arguments":{}}]}
            """), CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        using var document = JsonDocument.Parse(text);
        var envelope = document.RootElement;
        Assert.False(envelope.TryGetProperty("partial", out var batchPartial) && batchPartial.GetBoolean());
        var rows = envelope.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(6, rows.Length);
        Assert.Equal(
            new[] { 0, 1, 2, 3, 4, 5 },
            rows.Select(row => row.GetProperty("index").GetInt32()).ToArray());
        Assert.All(rows, row => Assert.True(row.GetProperty("response").GetProperty("ok").GetBoolean()));
        // Local composites fan out on the bridge; batch triage budgets clamp
        // omitted heavy knobs (maxItems 32, queue limit 8).
        var methods = backend.Calls.Select(call => call.Method).ToArray();
        Assert.Equal(
            new[] { "ListImports", "ListExports", "DumpStrings", "ListImports", "GetAnalysisQueue", "ListFunctions" },
            methods);
        Assert.Contains("\"maxItems\":32", Assert.Single(backend.Calls.Where(call => call.Method == "DumpStrings")).ArgsJson);
        Assert.Contains("\"limit\":8", Assert.Single(backend.Calls.Where(call => call.Method == "GetAnalysisQueue")).ArgsJson);
        var triageImports = backend.Calls.Where(call => call.Method == "ListImports").ToArray()[1];
        Assert.Contains("\"maxItems\":32", triageImports.ArgsJson);
    }

    [Fact]
    public async Task Batch_queue_row_with_digests_composes_inside_batch()
    {
        // P0-1 + P2-10 combined: a GetAnalysisQueue row with withDigests=true
        // runs its digest fan-out locally; the batch still costs one MCP call.
        var backend = new TriageBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("BatchStaticQueries", """
            {"requests":[{"method":"GetAnalysisQueue","arguments":{"withDigests":true}},
            {"method":"ListFunctions","arguments":{}}]}
            """), CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        using var document = JsonDocument.Parse(text);
        var rows = document.RootElement.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        var queue = rows[0].GetProperty("response").GetProperty("result");
        Assert.Equal(1, queue.GetProperty("digestedCount").GetInt32());
        Assert.True(queue.GetProperty("queue")[0].TryGetProperty("digest", out _));
        Assert.Equal(new[] { "GetAnalysisQueue", "AnalyzeFunctions", "ListFunctions" },
            backend.Calls.Select(call => call.Method).ToArray());
    }

    [Fact]
    public async Task ReadStaticBytes_ranges_reaches_backend_verbatim()
    {
        // The C# layer forwards ranges untouched; the total cap and per-index
        // errors are enforced by the bridge (pinned in GhidraStaticQueryChecks).
        var backend = new TriageBackend();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(Request("ReadStaticBytes",
            "{\"address\":\"1000\",\"length\":8}"), CancellationToken.None);
        Assert.False(result.IsError);
        result = await server.CallToolAsync(Request("ReadStaticBytes",
            "{\"ranges\":[{\"address\":\"1000\",\"length\":8},{\"address\":\"2000\"}]}"), CancellationToken.None);
        Assert.False(result.IsError);
        var ranged = backend.Calls.Where(call => call.Method == "ReadStaticBytes").ToArray()[1];
        Assert.Contains("\"ranges\"", ranged.ArgsJson);
        // address/length vs ranges is mutually exclusive at the MCP layer:
        // the ambiguous shape fails validation before any bridge call.
        Assert.NotNull(server.ValidateArguments("ReadStaticBytes",
            JsonSerializer.Deserialize<JsonElement>("{\"address\":\"1000\",\"ranges\":[{\"address\":\"1000\"}]}")));
        Assert.NotNull(server.ValidateArguments("ReadStaticBytes",
            JsonSerializer.Deserialize<JsonElement>("{\"length\":8,\"ranges\":[{\"address\":\"1000\"}]}")));
        // Nine chunks exceed the fan-out cap before any backend call.
        var nine = string.Join(",", Enumerable.Repeat("{\"address\":\"1000\"}", 9));
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() =>
            server.CallToolAsync(Request("ReadStaticBytes", "{\"ranges\":[" + nine + "]}"), CancellationToken.None));
        Assert.Equal(2, backend.Calls.Count(call => call.Method == "ReadStaticBytes"));
    }

    [Theory]
    [InlineData("{\"address\":\"EXTERNAL:00000001\",\"direction\":\"to\"}", "XrefsTo")]
    [InlineData("{\"address\":\"EXTERNAL:00000001\",\"direction\":\"both\"}", "XrefsBoth")]
    public async Task Xrefs_external_literal_reaches_bridge_verbatim(string args, string expectedBridge)
    {
        // Schema promises Xrefs(direction=to) accepts the EXTERNAL:<offset>
        // literals ListSymbols emits; the MCP layer must not reject or rewrite
        // them (Java address() resolves them to the same EXTERNAL-space Address).
        var backend = new StaticBackend(); var live = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, live, backend);
        Assert.Null(server.ValidateArguments("Xrefs",
            JsonSerializer.Deserialize<JsonElement>(args)));
        await server.CallToolAsync(Request("Xrefs", args), CancellationToken.None);
        Assert.Equal(new[] { expectedBridge }, backend.Calls);
        Assert.Equal(0, live.RequestCount);
    }

    [Fact]
    public void ListSymbols_schema_documents_explicit_zero_refCount_only()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>().Single(x => x["name"]!.GetValue<string>() == "ListSymbols");
        var props = (JsonObject)tool["inputSchema"]!["properties"]!;
        Assert.Contains("explicit 0 is refCount-only", props["maxSites"]!["description"]!.GetValue<string>());
        Assert.Contains("explicit maxSites:0", props["includeSites"]!["description"]!.GetValue<string>());
        var xrefs = server.ListTools().OfType<JsonObject>().Single(x => x["name"]!.GetValue<string>() == "Xrefs");
        var xrefsProps = (JsonObject)xrefs["inputSchema"]!["properties"]!;
        Assert.Contains("EXTERNAL", xrefsProps["address"]!["description"]!.GetValue<string>());
    }

    [Fact]
    public void Triage_description_references_real_tools_only()
    {
        // Stale names (ListImports/ListExports/DumpStrings/ListDataTypes) are
        // bridge internals or hidden tools, never advertised MCP tools: the
        // user-facing descriptions must name ListSymbols (or no tool at all).
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tools = server.ListTools().OfType<JsonObject>().ToDictionary(x => x["name"]!.GetValue<string>());
        var triageDesc = tools["Triage"]["description"]!.GetValue<string>();
        Assert.Contains("ListSymbols", triageDesc);
        foreach (var stale in new[] { "ListImports", "ListExports", "DumpStrings", "ListDataTypes" })
        {
            Assert.DoesNotContain(stale, triageDesc);
        }
        var triageProps = (JsonObject)tools["Triage"]["inputSchema"]!["properties"]!;
        foreach (var key in new[] { "filter", "maxItems", "maxPages" })
            foreach (var stale in new[] { "ListImports", "ListExports", "ListDataTypes" })
                Assert.DoesNotContain(stale, triageProps[key]!["description"]?.GetValue<string>() ?? string.Empty);
        Assert.DoesNotContain("DumpStrings", triageProps["filter"]!["description"]!.GetValue<string>());
    }
}



internal sealed class StatusCountingGhidra : IGhidraClient
{
    private int _calls;
    public int Calls => Volatile.Read(ref _calls);

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
    {
        Interlocked.Increment(ref _calls);
        return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"available\":true}}");
    }
}
