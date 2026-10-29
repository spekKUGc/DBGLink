using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// I-03 AnalyzeFunctions: schema/gate pins, the wire contract of the
/// multi-function digest (per-entry indexed not_found, forwarded budgets,
/// transparent static read), and the new InspectFunction card flags.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class AnalyzeFunctionsTests
{
    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static LocalMcpServer CreateServer(bool allowMutation = false)
        => new(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = allowMutation },
            new RecordingBridge(),
            new NullGhidra());

    private sealed class CapturingGhidra : IGhidraClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}");
        }
    }

    [Fact]
    public async Task AnalyzeFunctions_omitted_flags_forward_untouched()
    {
        // Diet budgets ride server-side: omission forwards untouched and the
        // bridge defaults apply (C-free digest, 4-item sections).
        var backend = new CapturingGhidra();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "AnalyzeFunctions",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"functions":["main"]}"""),
        }, CancellationToken.None);
        var (_, argsJson) = Assert.Single(backend.Calls);
        Assert.DoesNotContain("includeDecomp", argsJson, StringComparison.Ordinal);
        Assert.DoesNotContain("maxItems", argsJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Schema_accepts_selector_forms_and_rejects_malformed_envelopes()
    {
        using var server = CreateServer();

        // Explicit selectors (1..8) or an ordered start slice.
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["FixtureCaller"]}""")));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["a","b","c","d","e","f","g","h"]}""")));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"start":"0x140001000"}""")));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"start":"main","maxFunctions":8,"maxChars":24000,"maxItems":32}""")));

        // 1..8 selectors: an empty array or a ninth selector fails before the bridge.
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"functions":[]}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["a","b","c","d","e","f","g","h","i"]}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"functions":"main"}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"functions":[1]}""")));
        // Blank selectors fail dispatcher validation before any backend call.
        var blankServer = CreateServer();
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() => blankServer.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "AnalyzeFunctions",
                Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>( """{"functions":[" "]}"""),
            }, CancellationToken.None));

        // The envelope is closed and the numeric knobs stay bounded.
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"extra":1}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"start":"main","maxFunctions":9}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"start":"main","maxFunctions":0}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"start":"main","maxItems":33}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args("""{"start":"main","maxChars":999}""")));
    }

    [Fact]
    public void Schema_accepts_inspect_string_and_constant_flags()
    {
        using var server = CreateServer();
        Assert.Null(server.ValidateArguments("InspectFunction", Args(
            """{"function":"main","includeStrings":true,"includeConstants":true}""")));
        Assert.Null(server.ValidateArguments("InspectFunction", Args(
            """{"function":"main","includeStrings":false}""")));
        Assert.NotNull(server.ValidateArguments("InspectFunction", Args(
            """{"function":"main","includeStrings":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("InspectFunction", Args(
            """{"function":"main","includeConstants":1}""")));
    }

    [Fact]
    public void Schema_accepts_analyze_comment_and_prototype_opts()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeComments":true,"includePrototype":true}""")));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeComments":false}""")));
        Assert.Null(server.ValidateArguments("DecompileModule", Args(
            """{"maxFunctions":8,"includePrototype":true}""")));
        Assert.Null(server.ValidateArguments("DecompileModule", Args(
            """{"maxFunctions":8,"includePrototype":false}""")));

        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeDecomp":false}""")));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeDecomp":true}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeDecomp":"no"}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includeComments":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", Args(
            """{"functions":["main"],"includePrototype":1}""")));
        Assert.NotNull(server.ValidateArguments("DecompileModule", Args(
            """{"maxFunctions":8,"includePrototype":"yes"}""")));
    }

    [Fact]
    public async Task Read_only_capability_executes_without_mutation_gates()
    {
        var backend = new CapturingGhidra();
        using var server = new LocalMcpServer(
            new ServerConfig
            {
                Port = ServerConfig.DefaultPort,
                Profile = ToolProfile.Lean,
                AllowMutation = false,
                AllowAnnotation = false,
            },
            new RecordingBridge(),
            backend);

        var tools = server.ListTools().OfType<JsonObject>().ToList();
        Assert.Contains(tools, tool => tool["name"]!.GetValue<string>() == "AnalyzeFunctions");
        // Single standard catalog: schema keeps its descriptions.
        var analyze = tools.Single(tool => tool["name"]!.GetValue<string>() == "AnalyzeFunctions");
        Assert.NotNull(analyze["inputSchema"]!["properties"]!["maxItems"]!["description"]);

        await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "AnalyzeFunctions",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"functions":["main"]}""")!,
        }, CancellationToken.None);
        Assert.Equal("AnalyzeFunctions", Assert.Single(backend.Calls).Method);
    }

    [Fact]
    public async Task BatchStaticQueries_accepts_analyze_functions_with_triage_budget()
    {
        var backend = new CapturingGhidra();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"requests":[{"method":"AnalyzeFunctions","arguments":{"functions":["main"]}}]}""")!,
        }, CancellationToken.None);
        Assert.False(result.IsError);
        var call = Assert.Single(backend.Calls);
        Assert.Equal("AnalyzeFunctions", call.Method);
        Assert.Contains("\"maxChars\":8000", call.ArgsJson);
    }

    [Fact]
    public async Task Wire_digest_indexes_not_found_and_forwards_budgets()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var captured = "";
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            captured = args?.GetRawText() ?? "";
            var maxChars = args?.TryGetProperty("maxChars", out var chars) == true ? chars.GetInt32() : -1;
            var maxItems = args?.TryGetProperty("maxItems", out var items) == true ? items.GetInt32() : -1;
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    functions = new object[]
                    {
                        new
                        {
                            index = 0, selector = "FixtureCaller", ok = true, bridgeMarker = "keep-me",
                            function = new { name = "FixtureCaller", entry = "0x140001000" },
                            strings = new[] { new { address = "0x140003000", value = "hello", length = 5 } },
                            constants = new[] { new { value = "0x2a", count = 3, firstAddress = "0x140001010" } },
                        },
                        new
                        {
                            index = 1, selector = "FixtureCallee", ok = true,
                            function = new { name = "FixtureCallee", entry = "0x140001040" },
                            references = new { callers = Array.Empty<object>(), callees = Array.Empty<object>() },
                        },
                        new
                        {
                            index = 2, selector = "missing", ok = false, code = "not_found",
                            message = "matched no global function name",
                        },
                    },
                    truncated = false,
                    truncatedSections = Array.Empty<string>(),
                    maxChars,
                    maxItems,
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("AnalyzeFunctions", new
        {
            functions = new[] { "FixtureCaller", "FixtureCallee", "missing" },
            maxChars = 12_000,
            maxItems = 6,
        }));

        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
        var entries = root.GetProperty("functions").EnumerateArray().ToArray();
        Assert.Equal(3, entries.Length);
        Assert.Equal(new[] { 0, 1, 2 }, entries.Select(entry => entry.GetProperty("index").GetInt32()).ToArray());
        Assert.Equal("FixtureCaller", entries[0].GetProperty("selector").GetString());
        Assert.True(entries[0].GetProperty("ok").GetBoolean());
        Assert.True(entries[1].GetProperty("ok").GetBoolean());
        Assert.False(entries[2].GetProperty("ok").GetBoolean());
        Assert.Equal("not_found", entries[2].GetProperty("code").GetString());
        Assert.Equal("matched no global function name", entries[2].GetProperty("message").GetString());
        // Static reads are transparent: bridge-only fields survive the wire.
        Assert.Equal("keep-me", entries[0].GetProperty("bridgeMarker").GetString());

        // The digest budget knobs reach Ghidra unchanged.
        using var capturedDocument = JsonDocument.Parse(captured);
        Assert.Equal(12000, capturedDocument.RootElement.GetProperty("maxChars").GetInt32());
        Assert.Equal(6, capturedDocument.RootElement.GetProperty("maxItems").GetInt32());
    }

    [Fact]
    public async Task Wire_inspect_function_forwards_new_flags()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var includeStrings = args?.TryGetProperty("includeStrings", out var strings) == true && strings.GetBoolean();
            var includeConstants = args?.TryGetProperty("includeConstants", out var constants) == true && constants.GetBoolean();
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { function = "main", includeStrings, includeConstants },
            });
        });

        // Omitted flags stay false (backward-compatible default)...
        var off = TextOf(await harness.CallToolOverWireAsync("InspectFunction", new { function = "main" }));
        Assert.Contains("\"includeStrings\":false", off);
        Assert.Contains("\"includeConstants\":false", off);

        // ...and explicit flags reach the Ghidra bridge.
        var on = TextOf(await harness.CallToolOverWireAsync("InspectFunction",
            new { function = "main", includeStrings = true, includeConstants = true }));
        Assert.Contains("\"includeStrings\":true", on);
        Assert.Contains("\"includeConstants\":true", on);
    }

    [Fact]
    public async Task Wire_analyze_forwards_comment_and_prototype_opts()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var captured = "";
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            captured = args?.GetRawText() ?? "";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    functions = Array.Empty<object>(),
                    truncated = false,
                    truncatedSections = Array.Empty<string>(),
                },
            });
        });

        _ = TextOf(await harness.CallToolOverWireAsync("AnalyzeFunctions",
            new { functions = new[] { "main" }, includeComments = true, includePrototype = true }));
        Assert.Contains("includeComments", captured);
        Assert.Contains("includePrototype", captured);

        _ = TextOf(await harness.CallToolOverWireAsync("DecompileModule",
            new { maxFunctions = 2, includePrototype = true }));
        // DecompileModule shares the bridge: the flag must not be rejected.
    }

    [Fact]
    public async Task Wire_provenance_keys_survive_to_the_model()
    {
        // FID provenance is transparent: bridge-only nameSource/libraryMatched
        // keys reach the model untouched, so triage can skip library code.
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    functions = new object[]
                    {
                        new { function = new { name = "memcpy", entry = "0x140002000", nameSource = "ANALYSIS" } },
                        new { function = new { name = "FUN_140003000", entry = "0x140003000", nameSource = "DEFAULT" } },
                    },
                    libraryMatched = 1,
                    truncated = false,
                    truncatedSections = Array.Empty<string>(),
                },
            }));

        var text = TextOf(await harness.CallToolOverWireAsync("AnalyzeFunctions",
            new { functions = new[] { "memcpy", "FUN_140003000" } }));
        Assert.Contains("\"nameSource\":\"ANALYSIS\"", text);
        Assert.Contains("\"nameSource\":\"DEFAULT\"", text);
        Assert.Contains("\"libraryMatched\":1", text);
    }
}
