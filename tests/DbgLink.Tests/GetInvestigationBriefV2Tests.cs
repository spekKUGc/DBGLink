using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// w14 GetInvestigationBrief v2: one call digests up to 4 functions
/// (sections.static packet, aggregated summary) with strings on by default
/// and constants opt-in; single-function mode keeps its wire shape.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class GetInvestigationBriefV2Tests
{
    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static LocalMcpServer CreateServer()
        => new(
            new ServerConfig { Port = ServerConfig.DefaultPort },
            new RecordingBridge(),
            new NullGhidra());

    private static JsonElement BriefOf(string text)
        => JsonDocument.Parse(text).RootElement;

    [Fact]
    public async Task Schema_accepts_single_or_batch_selectors_and_bounded_flags()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main"}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["a"]}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["a","b","c","d"]}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["main"],"includeStrings":true,"includeConstants":false}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","maxTokens":0}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","maxTokens":500}""")));

        // 1..4 selectors: empty, overlong, non-string and blank entries fail.
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":[]}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["a","b","c","d","e"]}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":"main"}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":[1]}""")));
        // Blank selectors fail dispatcher validation before any backend call.
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() => server.CallToolAsync(
            new ModelContextProtocol.Protocol.CallToolRequestParams
            {
                Name = "GetInvestigationBrief",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["functions"] = Args("""[" "]"""),
                },
            }, CancellationToken.None));

        // Closed envelope and bounded knobs stay enforced.
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","extra":1}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeStrings":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["main"],"maxChars":3999}""")));
        // Below-floor maxTokens passes the advertised schema but fails dispatcher validation.
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() => server.CallToolAsync(
            new ModelContextProtocol.Protocol.CallToolRequestParams
            {
                Name = "GetInvestigationBrief",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["function"] = JsonSerializer.SerializeToElement("main"),
                    ["maxTokens"] = Args("""-1"""),
                },
            }, CancellationToken.None));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","maxTokens":30001}""")));
    }

    [Fact]
    public async Task Wire_token_ceiling_cuts_the_payload_and_tokens()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new { name = "main", entry = "0x140001000", rva = "0x1000" },
                    decompilation = new string('A', 12_000),
                    strings = new[] { new { address = "0x140003000", value = "saved-token-budget" } },
                },
            }));

        var uncapped = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "main",
            includeLive = false,
        }));
        var capped = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "main",
            includeLive = false,
            maxTokens = 500,
        }));

        var uncappedTokens = TokenCounter.Count(uncapped);
        var cappedTokens = TokenCounter.Count(capped);
        Console.WriteLine(
            $"Brief tokens: uncapped={uncappedTokens} capped={cappedTokens} saved={uncappedTokens - cappedTokens} ({(uncappedTokens - cappedTokens) * 100.0 / uncappedTokens:F1}%)");
        Assert.True(cappedTokens * 2 < uncappedTokens,
            $"Token guard must at least halve the payload (uncapped={uncappedTokens}, capped={cappedTokens})");
    }

    [Fact]
    public async Task Wire_token_ceiling_omits_sections_and_returns_continuation()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new { name = "main", entry = "0x140001000", rva = "0x1000" },
                    decompilation = new string('B', 3_000),
                    strings = new[] { new { address = "0x140003000", value = "hello-token-budget" } },
                },
            }));

        var text = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "main",
            includeLive = false,
            maxTokens = 500,
        }));
        var brief = BriefOf(text);

        Assert.Equal(500, brief.GetProperty("maxTokens").GetInt32());
        Assert.True(brief.GetProperty("truncated").GetBoolean());
        Assert.True(brief.GetProperty("usedChars").GetInt32() <= 2000);
        var section = brief.GetProperty("sections").GetProperty("static");
        Assert.True(section.GetProperty("omitted").GetBoolean());
        Assert.Equal("response_budget", section.GetProperty("reason").GetString());
        Assert.Contains("maxTokens", brief.GetProperty("continuation").GetString());
    }

    [Fact]
    public async Task Wire_multi_function_returns_one_packet_with_strings_and_constants()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var seen = new List<(string? Function, bool Strings, bool Constants)>();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var selector = args?.TryGetProperty("function", out var f) == true ? f.GetString() : "unknown";
            var strings = args?.TryGetProperty("includeStrings", out var s) == true && s.GetBoolean();
            var constants = args?.TryGetProperty("includeConstants", out var c) == true && c.GetBoolean();
            lock (seen)
                seen.Add((selector, strings, constants));
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path = "C:\\target.dll", sha256 = "" },
                    },
                    decompilation = $"int {selector}() {{ return 0; }}",
                    strings = new[] { new { address = "0x140003000", value = "hello-brief", length = 11 } },
                    constants = new[] { new { value = "0x2a", count = 3, firstAddress = "0x140001010" } },
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            functions = new[] { "fn0", "fn1", "fn2", "fn3" },
            includeLive = false,
            includeConstants = true,
            maxChars = 16000,
        }));
        var brief = BriefOf(text);

        // One call served all four functions.
        Assert.Equal(4, seen.Count);
        // The four static reads are issued concurrently; the packet order is
        // still selector order, which the entry assertions below pin.
        Assert.Equal(new[] { "fn0", "fn1", "fn2", "fn3" },
            seen.Select(call => call.Function).OrderBy(selector => selector).ToArray());
        Assert.Equal(4, brief.GetProperty("bridgeCalls").GetProperty("ghidra").GetInt32());

        // Strings default on; constants are explicit here and reach Ghidra
        // for every selector.
        Assert.All(seen, call => Assert.True(call.Strings && call.Constants));

        // sections.static is a per-function packet carrying strings/constants.
        var packet = brief.GetProperty("sections").GetProperty("static");
        Assert.Equal(4, packet.GetProperty("count").GetInt32());
        var entries = packet.GetProperty("functions").EnumerateArray().ToArray();
        Assert.Equal(4, entries.Length);
        for (var index = 0; index < entries.Length; index++)
        {
            Assert.Equal(index, entries[index].GetProperty("index").GetInt32());
            Assert.Equal($"fn{index}", entries[index].GetProperty("selector").GetString());
            Assert.True(entries[index].GetProperty("ok").GetBoolean());
            Assert.Equal("hello-brief",
                entries[index].GetProperty("strings").EnumerateArray().First()
                    .GetProperty("value").GetString());
            Assert.Equal("0x2a",
                entries[index].GetProperty("constants").EnumerateArray().First()
                    .GetProperty("value").GetString());
        }

        // Summary aggregates the packet.
        var summary = brief.GetProperty("summary");
        Assert.Equal(4, summary.GetProperty("functionCount").GetInt32());
        Assert.Equal(4, summary.GetProperty("staticReadyCount").GetInt32());
        Assert.True(summary.GetProperty("staticReady").GetBoolean());

        // The shared budget holds: bounded response, no truncation (a negative
        // optional flag is omitted, so absence is the "not truncated" signal).
        Assert.True(brief.GetProperty("usedChars").GetInt32() <= 16000);
        Assert.False(brief.TryGetProperty("truncated", out _));
        Assert.True(text.Length <= 20_000, $"multi brief exceeded budget: {text.Length}");

        // A one-element batch is still a packet, not the legacy single shape.
        var solo = BriefOf(TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            functions = new[] { "fn0" },
            includeLive = false,
        })));
        Assert.Equal(1, solo.GetProperty("sections").GetProperty("static").GetProperty("count").GetInt32());
        Assert.Equal("fn0", solo.GetProperty("functions").EnumerateArray().First().GetString());
    }

    [Fact]
    public async Task Wire_single_mode_keeps_shape_and_forwards_explicit_opt_out()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var seen = new List<(bool Strings, bool Constants)>();
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var selector = args?.TryGetProperty("function", out var f) == true ? f.GetString() : "unknown";
            var strings = args?.TryGetProperty("includeStrings", out var s) == true && s.GetBoolean();
            var constants = args?.TryGetProperty("includeConstants", out var c) == true && c.GetBoolean();
            lock (seen)
                seen.Add((strings, constants));
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path = "C:\\target.dll", sha256 = "" },
                    },
                    decompilation = "int solo() { return 0; }",
                    strings = new[] { new { address = "0x140003000", value = "hello-brief", length = 11 } },
                    constants = new[] { new { value = "0x2a", count = 3, firstAddress = "0x140001010" } },
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "solo",
            includeLive = false,
            includeConstants = true,
        }));
        var brief = BriefOf(text);

        Assert.False(brief.TryGetProperty("functions", out _));
        Assert.Equal(1, brief.GetProperty("bridgeCalls").GetProperty("ghidra").GetInt32());
        var staticSection = brief.GetProperty("sections").GetProperty("static");
        Assert.Equal("solo", staticSection.GetProperty("function").GetProperty("name").GetString());
        Assert.Contains("hello-brief", staticSection.GetProperty("strings").GetRawText());
        Assert.True(brief.GetProperty("summary").GetProperty("staticReady").GetBoolean());
        Assert.True(Assert.Single(seen).Strings && Assert.Single(seen).Constants);

        // Explicit flags still reach Ghidra.
        TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "solo",
            includeLive = false,
            includeStrings = false,
            includeConstants = false,
        }));
        Assert.Equal(2, seen.Count);
        Assert.False(seen[1].Strings || seen[1].Constants);
    }

    [Fact]
    public async Task Wire_function_and_functions_together_is_rejected()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var both = await harness.CallToolOverWireAsync("GetInvestigationBrief", new
        {
            function = "a",
            functions = new[] { "b" },
        });
        Assert.Contains("invalid_argument",
            Assert.IsType<TextContentBlock>(Assert.Single(both.Content)).Text);

        var neither = await harness.CallToolOverWireAsync("GetInvestigationBrief", new { });
        Assert.Contains("invalid_argument",
            Assert.IsType<TextContentBlock>(Assert.Single(neither.Content)).Text);
    }

    [Fact]
    public void Schema_accepts_includeLiveBytes_opt_in_and_rejects_wrong_type()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeLiveBytes":true}""")));
        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"functions":["a","b"],"includeLiveBytes":false}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeLiveBytes":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeLiveBytes":1}""")));
    }

    [Fact]
    public async Task Multi_mode_issues_static_reads_concurrently()
    {
        var ghidra = new ConcurrentGhidra(expected: 4);
        var context = new AnalysisContext(new RecordingBridge(), ghidra);
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));

        var raw = await tools.GetInvestigationBriefAsync(
            Args("""{"functions":["a","b","c","d"],"includeLive":false}"""),
            CancellationToken.None);

        Assert.NotNull(ReadBriefResultNode(raw));
        Assert.Equal(4, ghidra.Started);
        Assert.True(ghidra.AllReached, "the brief started static reads serially instead of fanning them out");
    }

    // =====================================================================
    // P1-7: one brief maps ALL N selectors over ONE module table, with
    // opt-in per-function liveBytes. Direct-impl fakes keep the tests
    // deterministic (no pipe/TCP timing).
    // =====================================================================

    private sealed class MultiMapBridge : IBridgeClient
    {
        public List<string> Calls { get; } = [];
        public List<string> ReadAddresses { get; } = [];
        public List<string> ReadArgs { get; } = [];
        public string LastSnapshotArgs { get; private set; } = "";
        public bool TruncateSnapshotModules { get; set; }

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (method == "GetServerStatus")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":123,\"debugging\":true,\"capabilities\":{\"analysisSnapshot\":true}}");
            if (method == "GetAnalysisSnapshot")
            {
                LastSnapshotArgs = arguments?.GetRawText() ?? "";
                var modules = JsonSerializer.SerializeToNode(new
                {
                    modules = new[]
                    {
                        new { @base = "0x140000000", end = "0x140050000", name = "test.exe", path = "C:\\test.exe" }
                    },
                    truncated = TruncateSnapshotModules,
                });
                var result = new JsonObject
                {
                    ["stateBefore"] = SnapshotState(),
                    ["stateAfter"] = SnapshotState(),
                    ["sections"] = new JsonObject
                    {
                        ["status"] = new JsonObject { ["pid"] = 123, ["telemetry"] = "large" },
                        ["context"] = "context",
                        ["callStack"] = "stack",
                        ["modules"] = modules,
                    },
                };
                return Task.FromResult(JsonSerializer.Serialize(new { id = 1, ok = true, result }));
            }
            if (method == "GetModuleRecords")
            {
                return Task.FromResult(JsonSerializer.Serialize(new
                {
                    id = 1,
                    ok = true,
                    result = new
                    {
                        modules = new[]
                        {
                            new { @base = "0x140000000", end = "0x140050000", name = "test.exe", path = "C:\\test.exe" }
                        },
                        truncated = false,
                    },
                }));
            }
            if (method == "ReadMemAtAddress")
            {
                var address = arguments?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "" : "";
                ReadAddresses.Add(address);
                ReadArgs.Add(arguments?.GetRawText() ?? "");
                return Task.FromResult(JsonSerializer.Serialize(new
                {
                    id = 1,
                    ok = true,
                    result = new { address, bytes = "AA BB CC", bytesRead = 3 },
                }));
            }
            return Task.FromResult(
                "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unexpected\",\"message\":\"" + method + "\"}}");
        }

        private static JsonNode SnapshotState() => JsonNode.Parse(
            """{"debuggerPid":123,"generation":"1","debugging":true,"running":false,"threadId":42,"stableRead":true}""")!;
    }

    private sealed class ConcurrentGhidra : IGhidraClient
    {
        private readonly int _expected;
        private readonly TaskCompletionSource _allStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _started;

        public ConcurrentGhidra(int expected) => _expected = expected;

        public int Started => Volatile.Read(ref _started);
        public bool AllReached => _allStarted.Task.IsCompleted;

        public async Task<string> RequestAsync(
            string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method != "InspectFunction")
                return "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unexpected\",\"message\":\"test\"}}";

            if (Interlocked.Increment(ref _started) == _expected)
                _allStarted.TrySetResult();
            // A sequential caller deadlocks here until the timeout, making the
            // regression deterministic instead of a load-sensitive stopwatch.
            await _allStarted.Task.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken);
            var selector = arguments?.TryGetProperty("function", out var value) == true
                ? value.GetString() ?? ""
                : "";
            return JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path = "C:\\target.dll", sha256 = "" },
                    },
                },
            });
        }
    }

    private sealed class MultiMapGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method != "InspectFunction")
                return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unknown\",\"message\":\"test\"}}");
            var selector = arguments?.TryGetProperty("function", out var f) == true ? f.GetString() ?? "" : "";
            // fn0..fn2 share the live test.exe module; oob exceeds it;
            // missing points at an unloaded module. RVAs stay in-bounds otherwise.
            var (rva, path) = selector switch
            {
                "fn1" => ("0x1040", "C:\\test.exe"),
                "fn2" => ("0x1080", "C:\\test.exe"),
                "oob" => ("0x90000", "C:\\test.exe"),
                "missing" => ("0x1000", "C:\\missing.dll"),
                _ => ("0x1000", "C:\\test.exe"),
            };
            var entry = selector == "oob" ? "0x140090000" : "0x140001000";
            return Task.FromResult(JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry,
                        rva,
                        module = new { path, sha256 = "" },
                    },
                },
            }));
        }
    }

    private sealed class SummaryGhidra : IGhidraClient
    {
        public bool Constants { get; private set; }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method != "InspectFunction")
                return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unknown\",\"message\":\"test\"}}");
            var includeConstants = arguments?.TryGetProperty("includeConstants", out var c) == true && c.GetBoolean();
            Constants = includeConstants;
            var result = new JsonObject
            {
                ["function"] = new JsonObject
                {
                    ["name"] = "fn0",
                    ["entry"] = "0x140001000",
                    ["rva"] = "0x1000",
                    ["module"] = new JsonObject
                    {
                        ["path"] = "C:\\app.exe",
                        ["sha256"] = "abc",
                        ["imageBase"] = "0x140000000",
                        // The full program summary that Ghidra echoes per function.
                        ["summary"] = new JsonObject
                        {
                            ["fileName"] = "app.exe",
                            ["format"] = "PE",
                            ["architecture"] = "x86",
                            ["functionCount"] = 42,
                            ["language"] = "x86:LE:32:default",
                            ["compiler"] = "windows",
                        },
                    },
                },
                ["references"] = new JsonObject
                {
                    ["callers"] = new JsonArray(new JsonObject { ["name"] = "main", ["entry"] = "0x1400010A0" }),
                    ["callees"] = new JsonArray(new JsonObject { ["name"] = "helper", ["entry"] = "0x140001040" }),
                    ["xrefsTo"] = new JsonArray(new JsonObject { ["from"] = "0x1400010A0", ["to"] = "0x140001000", ["type"] = "CALL" }),
                    ["xrefsFrom"] = new JsonArray(new JsonObject { ["from"] = "0x140001010", ["to"] = "0x140003000", ["type"] = "READ" }),
                },
            };
            if (includeConstants)
                result["constants"] = new JsonArray(new JsonObject
                {
                    ["value"] = "0x2a",
                    ["count"] = 3,
                    ["firstAddress"] = "0x140001010",
                });
            return Task.FromResult(JsonSerializer.Serialize(new { id = 1, ok = true, result }));
        }
    }

    private static async Task<JsonObject> BriefAsync(
        MultiMapBridge bridge, object arguments)
    {
        var context = new AnalysisContext(bridge, new MultiMapGhidra());
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));
        var raw = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(arguments), CancellationToken.None);
        var node = ReadBriefResultNode(raw);
        Assert.True(node is JsonObject, $"Brief envelope was not ok:true: {raw[..Math.Min(2000, raw.Length)]}");
        return (JsonObject)node!;
    }

    // AnalysisFormatting.ReadBridgeResultNode caps MaxDepth at 8, which a
    // 3-function brief (static packet + mapping packet + live snapshot) can
    // exceed. The MCP wire carries the full string; only this helper needs a
    // deeper parse.
    private static JsonNode? ReadBriefResultNode(string raw)
    {
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 64 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("ok", out var ok) ||
                ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) ||
                result.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                return null;
            return JsonNode.Parse(result.GetRawText());
        }
        catch (JsonException)
        {
            return null;
        }
    }

    [Fact]
    public async Task Brief_default_omits_the_embedded_status_section()
    {
        var bridge = new MultiMapBridge();
        var brief = await BriefAsync(bridge, new { function = "fn0" });

        Assert.False(brief["sections"]!["live"]!["sections"]!.AsObject().ContainsKey("status"));
        Assert.Contains("\"instructionBytes\":16", bridge.LastSnapshotArgs, StringComparison.Ordinal);
        Assert.Contains("\"stackBytes\":32", bridge.LastSnapshotArgs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Brief_default_maps_from_the_snapshot_without_shipping_modules()
    {
        var bridge = new MultiMapBridge();
        var brief = await BriefAsync(bridge, new { function = "fn0", verifyHash = false });

        // The snapshot carries the module table internally, so mapping no
        // longer needs a targeted GetModuleRecords round trip.
        Assert.Contains("\"includeModules\":true", bridge.LastSnapshotArgs, StringComparison.Ordinal);
        Assert.DoesNotContain("GetModuleRecords", bridge.Calls);
        Assert.Equal("snapshot_modules", brief["mappingSource"]!.GetValue<string>());
        Assert.True(brief["sections"]!["mapping"]!["match"]!.GetValue<bool>());
        Assert.Equal(1, brief["bridgeCalls"]!["native"]!.GetValue<int>());

        // The caller did not ask for the table, so the live section keeps its
        // old compact shape and the internal fetch stays invisible.
        Assert.False(brief["sections"]!["live"]!["sections"]!.AsObject().ContainsKey("modules"));
        var liveSummary = brief["sections"]!["live"]!["summary"]!.AsObject();
        Assert.False(liveSummary.ContainsKey("moduleStatus"));
        Assert.False(liveSummary.ContainsKey("moduleCount"));

        // An explicit opt-in for the full clone still delivers it.
        var optedIn = await BriefAsync(new MultiMapBridge(),
            new { function = "fn0", verifyHash = false, includeModules = true, includeLiveDetail = true });
        Assert.True(optedIn["sections"]!["live"]!["sections"]!.AsObject().ContainsKey("modules"));
        Assert.True(optedIn["sections"]!["live"]!["summary"]!.AsObject().ContainsKey("moduleCount"));
    }

    [Fact]
    public async Task Brief_hoists_one_module_summary_and_leaves_constants_opt_in()
    {
        var ghidra = new SummaryGhidra();
        var context = new AnalysisContext(new MultiMapBridge(), ghidra);
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));

        var raw = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(new { function = "fn0", includeLive = false, verifyHash = false }),
            CancellationToken.None);
        var brief = ReadBriefResultNode(raw)!.AsObject();

        // One compact hoist remains; the per-function copy is duplication.
        var function = brief["sections"]!["static"]!["function"]!.AsObject();
        Assert.False(function["module"]!.AsObject().ContainsKey("summary"));
        Assert.False(function["module"]!.AsObject().ContainsKey("sha256"));
        Assert.True(function["module"]!.AsObject().ContainsKey("path"));
        var references = brief["sections"]!["static"]!["references"]!.AsObject();
        Assert.True(references.ContainsKey("callers"));
        Assert.True(references.ContainsKey("callees"));
        Assert.False(references.ContainsKey("xrefsTo"));
        Assert.False(references.ContainsKey("xrefsFrom"));
        Assert.Equal("Xrefs(address)", references["xrefsOmitted"]!.GetValue<string>());
        var hoisted = brief["summary"]!["module"]!.AsObject();
        Assert.Equal("app.exe", hoisted["fileName"]!.GetValue<string>());
        Assert.Equal("x86", hoisted["architecture"]!.GetValue<string>());
        Assert.False(hoisted.ContainsKey("language"));
        Assert.False(hoisted.ContainsKey("compiler"));

        // Constants are no longer paid for by default.
        Assert.False(ghidra.Constants);
        Assert.Null(brief["sections"]!["static"]!["constants"]);

        var withConstants = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(
                new { function = "fn0", includeLive = false, verifyHash = false, includeConstants = true }),
            CancellationToken.None);
        Assert.True(ghidra.Constants);
        Assert.NotNull(ReadBriefResultNode(withConstants)!["sections"]!["static"]!["constants"]);
    }

    [Fact]
    public async Task Brief_maps_all_selectors_from_one_snapshot_table()
    {
        var bridge = new MultiMapBridge();
        var brief = await BriefAsync(bridge,
            new { functions = new[] { "fn0", "fn1", "fn2" }, verifyHash = false, includeModules = true });

        // One shared table: no targeted module fetch for any selector.
        Assert.DoesNotContain("GetModuleRecords", bridge.Calls);
        Assert.Equal(1, brief["bridgeCalls"]!["native"]!.GetValue<int>());

        var mapping = brief["sections"]!["mapping"]!.AsObject();
        Assert.Equal(3, mapping["count"]!.GetValue<int>());
        var entries = mapping["mappings"]!.AsArray();
        Assert.Equal(3, entries.Count);
        var expectedLive = new[] { "0x140001000", "0x140001040", "0x140001080" };
        for (var index = 0; index < 3; index++)
        {
            var entry = entries[index]!.AsObject();
            Assert.Equal(index, entry["index"]!.GetValue<int>());
            var entryMapping = entry["mapping"]!.AsObject();
            Assert.True(entryMapping["match"]!.GetValue<bool>());
            Assert.Equal(expectedLive[index], entryMapping["liveAddress"]!.GetValue<string>());
            // Default OFF: no byte enrichment. The module table is hoisted
            // once and referenced by index; the breakpoint address is
            // liveAddress + rva.
            Assert.Null(entryMapping["liveBytes"]);
            Assert.False(entryMapping.ContainsKey("breakpointHint"));
            var moduleIndex = entryMapping["moduleIndex"]!.GetValue<int>();
            var moduleRow = mapping["modules"]![moduleIndex]!.AsObject();
            Assert.Equal("test.exe", moduleRow["name"]!.GetValue<string>());
            Assert.NotNull(moduleRow["base"]);
            Assert.NotNull(entryMapping["rva"]);
        }

        // N mappings from one snapshot save N targeted fetches, on top of the
        // snapshot's own batched savings (4: batched snapshot + modules).
        Assert.Equal(7, brief["roundTripsSaved"]!.GetValue<int>());
        Assert.Equal("snapshot_modules", brief["mappingSource"]!.GetValue<string>());
        var summary = brief["summary"]!.AsObject();
        Assert.Equal("matched", summary["mapping"]!.GetValue<string>());
        Assert.Equal(3, summary["mappingReadyCount"]!.GetValue<int>());
        Assert.Null(summary["roundTripsSaved"]);
    }

    [Fact]
    public async Task Brief_live_bytes_opt_in_reads_each_match()
    {
        var bridge = new MultiMapBridge();
        var brief = await BriefAsync(bridge,
            new { functions = new[] { "fn0", "fn1" }, verifyHash = false, includeModules = true, includeLiveBytes = true });

        // One bounded live read per matched function, at the mapped address.
        Assert.Equal(new[] { "0x140001000", "0x140001040" }, bridge.ReadAddresses);
        Assert.All(bridge.ReadArgs, args => Assert.Contains("32", args));
        Assert.Equal(1 + 2, brief["bridgeCalls"]!["native"]!.GetValue<int>());

        var entries = brief["sections"]!["mapping"]!["mappings"]!.AsArray();
        Assert.Equal(2, entries.Count);
        foreach (var entry in entries)
        {
            var entryMapping = entry!["mapping"]!.AsObject();
            Assert.True(entryMapping["match"]!.GetValue<bool>());
            Assert.Equal("AA BB CC", entryMapping["liveBytes"]!["bytes"]!.GetValue<string>());
            Assert.NotNull(entryMapping["moduleIndex"]);
        }
    }

    [Fact]
    public async Task Brief_multi_keeps_honest_reasons_and_never_drops_selectors()
    {
        var bridge = new MultiMapBridge();
        var brief = await BriefAsync(bridge,
            new { functions = new[] { "fn0", "oob", "missing" }, verifyHash = false, includeModules = true });

        var entries = brief["sections"]!["mapping"]!["mappings"]!.AsArray();
        Assert.Equal(3, entries.Count);
        Assert.True(entries[0]!["mapping"]!["match"]!.GetValue<bool>());
        Assert.False(entries[1]!["mapping"]!["match"]!.GetValue<bool>());
        Assert.Equal("rva_out_of_module", entries[1]!["mapping"]!["reason"]!.GetValue<string>());
        Assert.False(entries[2]!["mapping"]!["match"]!.GetValue<bool>());
        Assert.Equal("module_identity_not_found", entries[2]!["mapping"]!["reason"]!.GetValue<string>());

        var summary = brief["summary"]!.AsObject();
        Assert.Equal("partial", summary["mapping"]!.GetValue<string>());
        Assert.Equal(1, summary["mappingReadyCount"]!.GetValue<int>());
    }

    [Fact]
    public async Task Brief_single_default_carries_no_byte_enrichment()
    {
        var bridge = new MultiMapBridge();
        var context = new AnalysisContext(bridge, new MultiMapGhidra());
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));
        var raw = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(new { function = "fn0", verifyHash = false, includeModules = true }),
            CancellationToken.None);

        // Default single-function mapping keeps its historical shape.
        Assert.DoesNotContain("liveBytes", raw);
        Assert.DoesNotContain("breakpointHint", raw);
        var brief = ReadBriefResultNode(raw)!.AsObject();
        Assert.True(brief["sections"]!["mapping"]!["match"]!.GetValue<bool>());
        // Batched snapshot (4: snapshot + modules) plus this single mapping.
        Assert.Equal(5, brief["roundTripsSaved"]!.GetValue<int>());
    }

    [Fact]
    public async Task Brief_default_slims_live_to_correlation_view_with_detail_opt_in()
    {
        var slim = await BriefAsync(new MultiMapBridge(),
            new { function = "fn0", verifyHash = false });
        var slimSections = slim["sections"]!["live"]!["sections"]!.AsObject();
        Assert.True(slimSections.ContainsKey("context"));
        Assert.True(slimSections.ContainsKey("callStack"));
        Assert.False(slimSections.ContainsKey("modules"));
        Assert.False(slimSections.ContainsKey("status"));
        var slimSummary = slim["sections"]!["live"]!["summary"]!.AsObject();
        Assert.False(slimSummary.ContainsKey("moduleStatus"));
        Assert.False(slimSummary.ContainsKey("moduleCount"));
        // Mapping still comes from the internal snapshot table.
        Assert.Equal("snapshot_modules", slim["mappingSource"]!.GetValue<string>());
        Assert.True(slim["sections"]!["mapping"]!["match"]!.GetValue<bool>());

        // The opt-in restores the old full clone, including the module table
        // the mapping rode in on (with includeModules=true).
        var full = await BriefAsync(new MultiMapBridge(),
            new { function = "fn0", verifyHash = false, includeModules = true, includeLiveDetail = true });
        var fullSections = full["sections"]!["live"]!["sections"]!.AsObject();
        Assert.True(fullSections.ContainsKey("modules"));
        Assert.True(full["sections"]!["live"]!["summary"]!.AsObject().ContainsKey("moduleCount"));
    }

    [Fact]
    public void Schema_accepts_includeLiveDetail_opt_in()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeLiveDetail":true}""")));
        Assert.NotNull(server.ValidateArguments("GetInvestigationBrief", Args(
            """{"function":"main","includeLiveDetail":"yes"}""")));
    }

    [Fact]
    public void SlimBriefContextText_keeps_registers_and_cuts_disassembly_and_stack()
    {
        var slim = AnalysisFormatting.SlimBriefContextText(
            "[GetCurrentContext]\n0x70000100 module=test instruction=ret\n\n[Registers]\nrax : 0x0\nrcx : 0x44\nrip : 0x70000100\n\n[Disassembly]\n0x70000100 C3 ret\n\n[Stack]\n0x11 (8 bytes)\nAABBCCDD\n");
        Assert.Contains("0x70000100 module=test", slim, StringComparison.Ordinal);
        Assert.Contains("rcx : 0x44", slim, StringComparison.Ordinal);
        Assert.Contains("rip : 0x70000100", slim, StringComparison.Ordinal);
        Assert.DoesNotContain("rax : 0x0", slim, StringComparison.Ordinal);
        Assert.DoesNotContain("[Disassembly]", slim, StringComparison.Ordinal);
        Assert.DoesNotContain("[Stack]", slim, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Brief_truncated_snapshot_falls_back_to_one_shared_fetch()
    {
        var bridge = new MultiMapBridge { TruncateSnapshotModules = true };
        var brief = await BriefAsync(bridge,
            new { functions = new[] { "fn0", "fn1" }, verifyHash = false, includeModules = true });

        Assert.Equal(1, bridge.Calls.Count(call => call == "GetModuleRecords"));
        Assert.Equal("targeted_module_request", brief["mappingSource"]!.GetValue<string>());
        var entries = brief["sections"]!["mapping"]!["mappings"]!.AsArray();
        Assert.Equal(2, entries.Count);
        Assert.All(entries, entry => Assert.True(entry!["mapping"]!["match"]!.GetValue<bool>()));
    }
}

