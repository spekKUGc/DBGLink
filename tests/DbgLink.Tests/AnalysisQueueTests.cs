using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// I-06a GetAnalysisQueue: schema/limit pins, read-only lean execution, and
/// the wire contract of the leaves-first worklist (order preserved, limit
/// forwarded, transparent static read).
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class AnalysisQueueTests
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
    public void Schema_pins_limit_to_1_to_64_and_keeps_the_envelope_closed()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":1}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":64}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":8,"module":"target.exe"}""")));

        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":0}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":65}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":"8"}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":8,"extra":1}""")));
    }

    [Fact]
    public void Schema_accepts_digestLimit_and_rejects_wrong_types()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":4,"withDigests":false}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":1}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true,"digestLimit":1}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true,"digestLimit":24}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true,"digestLimit":0}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true,"digestLimit":25}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"withDigests":true,"digestLimit":"8"}""")));
    }

    [Fact]
    public void Schema_accepts_includeRva_flag_and_rejects_wrong_types()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"includeRva":true}""")));
        Assert.Null(server.ValidateArguments("GetAnalysisQueue", Args("""{"limit":4,"includeRva":false}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"includeRva":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisQueue", Args("""{"includeRva":1}""")));
    }

    private sealed class QueueDigestGhidra : IGhidraClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        private readonly int _rows;
        private readonly bool _failDigests;

        public QueueDigestGhidra(int rows = 2, bool failDigests = false)
        {
            _rows = rows;
            _failDigests = failDigests;
        }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            if (method == "GetAnalysisQueue")
            {
                var rows = string.Join(",", Enumerable.Range(0, _rows).Select(index =>
                    $"{{\"name\":\"fn{index}\",\"entry\":\"0x1400010{index:X}0\",\"rva\":\"0x10{index:X}0\",\"instructionCount\":4,\"named\":false,\"calleeCount\":{index}}}"));
                return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"schemaVersion\":2,\"queue\":[" + rows +
                    "],\"totalFunctions\":" + _rows + ",\"returned\":" + _rows + ",\"limit\":8,\"doneCount\":0,\"remainingCount\":" + _rows + ",\"truncated\":false}}");
            }
            if (method == "AnalyzeFunctions")
            {
                if (_failDigests)
                    return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"ghidra_timeout\",\"message\":\"slow\"}}");
                var count = arguments?.TryGetProperty("functions", out var functions) == true
                    ? functions.GetArrayLength() : 0;
                var entries = string.Join(",", Enumerable.Range(0, count).Select(index =>
                    $"{{\"index\":{index},\"selector\":\"s{index}\",\"ok\":true," +
                    $"\"function\":{{\"name\":\"fn{index}\",\"entry\":\"0x1400010{index:X}0\",\"rva\":\"0x10{index:X}0\"," +
                    "\"analysis\":{\"nameKind\":\"generated\",\"hasUsefulName\":false}}," +
                    "\"references\":{\"callers\":[{\"name\":\"main\",\"entry\":\"0x140000000\"}],\"callees\":[]}," +
                    "\"strings\":[],\"constants\":[]}"));
                return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"schemaVersion\":2,\"functions\":[" + entries + "],\"truncated\":false,\"truncatedSections\":[]}}");
            }
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    private static string QueueTextOf(CallToolResult result)
    {
        Assert.False(result.IsError == true, $"Tool error: {JsonSerializer.Serialize(result)}");
        return Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
    }

    [Fact]
    public async Task Queue_without_digests_is_a_byte_stable_passthrough()
    {
        // Opted out (absent or false): the bridge bytes pass through
        // untouched and no digest fan-out runs.
        foreach (var args in new[] { """{"limit":2}""", """{"limit":2,"withDigests":false}""" })
        {
            var backend = new QueueDigestGhidra();
            using var server = new LocalMcpServer(
                new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
            var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetAnalysisQueue",
                Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(args)!,
            }, CancellationToken.None));
            Assert.DoesNotContain("withDigests", text);
            Assert.DoesNotContain("digest", text);
            Assert.Single(backend.Calls);
            Assert.Equal("GetAnalysisQueue", backend.Calls[0].Method);
        }
    }

    [Fact]
    public async Task Queue_with_digests_embeds_analyze_entries_in_one_call()
    {
        // P2-10 win: queue + N analyze collapses to one MCP call (two bridge
        // calls: the queue plus one capped digest fan-out).
        var backend = new QueueDigestGhidra(rows: 2);
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"limit":2,"withDigests":true}""")!,
        }, CancellationToken.None));
        Assert.Equal(new[] { "GetAnalysisQueue", "AnalyzeFunctions" }, backend.Calls.Select(call => call.Method).ToArray());
        // The MCP-only flags never reach the bridge; triage digest budgets do.
        Assert.DoesNotContain("withDigests", backend.Calls[0].ArgsJson);
        Assert.DoesNotContain("digestLimit", backend.Calls[0].ArgsJson);
        Assert.Contains("\"maxChars\":8000", backend.Calls[1].ArgsJson);
        Assert.Contains("\"maxItems\":8", backend.Calls[1].ArgsJson);
        using var document = JsonDocument.Parse(text);
        var result = document.RootElement;
        Assert.True(result.GetProperty("withDigests").GetBoolean());
        Assert.Equal(2, result.GetProperty("digestedCount").GetInt32());
        // Negative optional flags are omitted on the wire: absence == false.
        Assert.False(result.TryGetProperty("digestsTruncated", out _));
        var queue = result.GetProperty("queue").EnumerateArray().ToArray();
        Assert.Equal(2, queue.Length);
        foreach (var row in queue)
            Assert.True(row.TryGetProperty("digest", out var digest) &&
                digest.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task Queue_digests_repeat_no_row_identity_or_empty_sections()
    {
        var backend = new QueueDigestGhidra(rows: 1);
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"limit":1,"withDigests":true}""")!,
        }, CancellationToken.None));

        using var document = JsonDocument.Parse(text);
        var row = document.RootElement.GetProperty("queue")[0];
        Assert.Equal("fn0", row.GetProperty("name").GetString());
        var digest = row.GetProperty("digest");
        var function = digest.GetProperty("function");
        // Row keeps name+entry; the digest keeps only the join key.
        Assert.False(function.TryGetProperty("name", out _));
        Assert.False(function.TryGetProperty("rva", out _));
        Assert.False(function.TryGetProperty("entry", out _));
        Assert.True(function.GetProperty("analysis").TryGetProperty("hasUsefulName", out _));
        // Empty sections are absence, populated ones stay.
        var references = digest.GetProperty("references");
        Assert.False(references.TryGetProperty("callees", out _));
        Assert.Single(references.GetProperty("callers").EnumerateArray());
        Assert.False(digest.TryGetProperty("strings", out _));
        Assert.False(digest.TryGetProperty("constants", out _));
        // Digests stay C-free by construction.
        Assert.Contains("\"includeDecomp\":false", backend.Calls[1].ArgsJson);
    }

    [Fact]
    public async Task Queue_with_digests_caps_at_sixteen_rows_and_flags_truncation()
    {
        var backend = new QueueDigestGhidra(rows: 20);
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"limit":20,"withDigests":true}""")!,
        }, CancellationToken.None));
        var digestCalls = backend.Calls.Where(call => call.Method == "AnalyzeFunctions").ToArray();
        Assert.Equal(2, digestCalls.Length);
        // Two batches share the 8000-char budget instead of multiplying it.
        foreach (var digestCall in digestCalls)
        {
            using var digestArgs = JsonDocument.Parse(digestCall.ArgsJson!);
            Assert.Equal(4000, digestArgs.RootElement.GetProperty("maxChars").GetInt32());
        }
        using var firstArgs = JsonDocument.Parse(digestCalls[0].ArgsJson!);
        Assert.Equal(8, firstArgs.RootElement.GetProperty("functions").GetArrayLength());
        using var document = JsonDocument.Parse(text);
        var result = document.RootElement;
        Assert.Equal(16, result.GetProperty("digestedCount").GetInt32());
        Assert.True(result.GetProperty("digestsTruncated").GetBoolean());
        var queue = result.GetProperty("queue").EnumerateArray().ToArray();
        Assert.Equal(20, queue.Length);
        Assert.True(queue.Take(16).All(row => row.TryGetProperty("digest", out _)));
        Assert.All(queue.Skip(16), row => Assert.False(row.TryGetProperty("digest", out _)));
    }

    [Fact]
    public async Task Queue_with_digests_honors_digestLimit_up_to_twenty_four()
    {
        var backend = new QueueDigestGhidra(rows: 24);
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"limit":24,"withDigests":true,"digestLimit":24}""")!,
        }, CancellationToken.None));
        Assert.Equal(3, backend.Calls.Count(call => call.Method == "AnalyzeFunctions"));
        using var document = JsonDocument.Parse(text);
        var result = document.RootElement;
        Assert.Equal(24, result.GetProperty("digestedCount").GetInt32());
        Assert.False(result.TryGetProperty("digestsTruncated", out _));
    }

    [Fact]
    public async Task Queue_with_digests_survives_digest_failure_honestly()
    {
        var backend = new QueueDigestGhidra(rows: 2, failDigests: true);
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var text = QueueTextOf(await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""{"withDigests":true}""")!,
        }, CancellationToken.None));
        using var document = JsonDocument.Parse(text);
        var result = document.RootElement;
        Assert.True(result.GetProperty("digestsTruncated").GetBoolean());
        Assert.Equal("ghidra_timeout", result.GetProperty("digestError").GetString());
        Assert.All(result.GetProperty("queue").EnumerateArray(),
            row => Assert.False(row.TryGetProperty("digest", out _)));
    }

    [Fact]
    public async Task Read_only_capability_executes_without_mutation_gates_and_stays_in_lean()
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
        Assert.Contains(tools, tool => tool["name"]!.GetValue<string>() == "GetAnalysisQueue");

        await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "GetAnalysisQueue",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"limit":3}""")!,
        }, CancellationToken.None);
        Assert.Equal("GetAnalysisQueue", Assert.Single(backend.Calls).Method);
    }

    [Fact]
    public async Task Wire_queue_stays_leaves_first_and_forwards_limit()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var captured = "";
        harness.Ghidra.RegisterTcpHandler("GetAnalysisQueue", (id, args) =>
        {
            captured = args?.GetRawText() ?? "";
            var limit = args?.TryGetProperty("limit", out var value) == true ? value.GetInt32() : -1;
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    queue = new object[]
                    {
                        new { name = "leaf", entry = "0x140001040", instructionCount = 4, named = false, calleeCount = 0 },
                        new { name = "mid", entry = "0x140001020", instructionCount = 9, named = true, calleeCount = 1 },
                        new { name = "root", entry = "0x140001000", instructionCount = 12, named = true, calleeCount = 2 },
                    },
                    limit,
                    truncated = false,
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("GetAnalysisQueue", new { limit = 3 }));

        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
        var names = root.GetProperty("queue").EnumerateArray()
            .Select(entry => entry.GetProperty("name").GetString()).ToArray();
        Assert.Equal(new[] { "leaf", "mid", "root" }, names);
        var callees = root.GetProperty("queue").EnumerateArray()
            .Select(entry => entry.GetProperty("calleeCount").GetInt32()).ToArray();
        Assert.Equal(callees.OrderBy(count => count).ToArray(), callees);

        using var capturedDocument = JsonDocument.Parse(captured);
        Assert.Equal(3, capturedDocument.RootElement.GetProperty("limit").GetInt32());
    }

    [Fact]
    public async Task Wire_queue_forwards_includeRva_opt_in()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var captured = "";
        harness.Ghidra.RegisterTcpHandler("GetAnalysisQueue", (id, args) =>
        {
            captured = args?.GetRawText() ?? "";
            var includeRva = args?.TryGetProperty("includeRva", out var flag) == true && flag.GetBoolean();
            object[] queue = includeRva
                ? [new { name = "leaf", entry = "0x140001040", rva = "0x1040", instructionCount = 4, named = false, calleeCount = 0 }]
                : [new { name = "leaf", entry = "0x140001040", instructionCount = 4, named = false, calleeCount = 0 }];
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    queue,
                    truncated = false,
                },
            });
        });

        // Default omits rva.
        var @default = TextOf(await harness.CallToolOverWireAsync("GetAnalysisQueue", new { limit = 1 }));
        using (var doc = JsonDocument.Parse(@default))
            Assert.False(doc.RootElement.GetProperty("queue").EnumerateArray().First().TryGetProperty("rva", out _));
        Assert.DoesNotContain("includeRva", captured);

        // Opt-in forwards and attaches rva.
        var opted = TextOf(await harness.CallToolOverWireAsync("GetAnalysisQueue", new { limit = 1, includeRva = true }));
        using (var doc = JsonDocument.Parse(opted))
            Assert.True(doc.RootElement.GetProperty("queue").EnumerateArray().First().TryGetProperty("rva", out _));
        Assert.Contains("includeRva", captured);
    }
}
