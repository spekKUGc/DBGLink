using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// w16 CallGraph: schema/limit pins, the read-only wire contract of the
/// aggregated caller-to-callee graph (node shape, edge counts, nextStart
/// continuation), and the transparent static-read passthrough.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class CallGraphTests
{
    private readonly ITestOutputHelper _output;

    public CallGraphTests(ITestOutputHelper output) => _output = output;

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
    public void Schema_accepts_ranges_and_rejects_malformed_envelopes()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("CallGraph", Args("{}")));
        Assert.Null(server.ValidateArguments("CallGraph", Args(
            """{"start":"0x140001000","end":"0x140002000","maxNodes":256,"maxEdges":1024}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args(
            """{"module":"target.dll","maxNodes":1,"maxEdges":1}""")));

        // The envelope is closed and the node/edge caps stay bounded.
        Assert.NotNull(server.ValidateArguments("CallGraph", Args(
            """{"maxNodes":2,"extra":1}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"maxNodes":0}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"maxNodes":257}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"maxEdges":0}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"maxEdges":1025}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"start":123}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"maxNodes":2.5}""")));
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
        Assert.Contains(tools, tool => tool["name"]!.GetValue<string>() == "CallGraph");

        await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "CallGraph",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"maxNodes":16}""")!,
        }, CancellationToken.None);
        Assert.Equal("CallGraph", Assert.Single(backend.Calls).Method);
    }

    [Fact]
    public async Task BatchStaticQueries_accepts_call_graph_with_triage_budget()
    {
        var backend = new CapturingGhidra();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), backend);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"requests":[{"method":"CallGraph","arguments":{}}]}""")!,
        }, CancellationToken.None);
        Assert.False(result.IsError);
        var call = Assert.Single(backend.Calls);
        Assert.Equal("CallGraph", call.Method);
        Assert.Contains("\"maxNodes\":32", call.ArgsJson);
        Assert.Contains("\"maxEdges\":128", call.ArgsJson);
    }

    [Fact]
    public void Schema_accepts_neighborhood_seed_depth_direction()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("CallGraph", Args(
            """{"function":"0x140001000","depth":2,"direction":"both"}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args(
            """{"function":"main","depth":1,"direction":"callers"}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args(
            """{"function":"main","direction":"callees"}""")));

        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"function":1}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"depth":0}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"depth":3}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"direction":"sideways"}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"direction":1}""")));
    }

    [Fact]
    public async Task Wire_neighborhood_passes_through_nextBest_and_frontier()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("CallGraph", (id, args) =>
        {
            Assert.Equal("main", args?.GetProperty("function").GetString());
            Assert.Equal(2, args?.GetProperty("depth").GetInt32());
            Assert.Equal("both", args?.GetProperty("direction").GetString());
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 4,
                    mode = "neighborhood",
                    seed = new { name = "main", entry = "0x140001000", rva = "0x1000" },
                    nodes = new[]
                    {
                        new { name = "main", entry = "0x140001000", rva = "0x1000" },
                        new { name = "DecryptPayload", entry = "0x140001100", rva = "0x1100" },
                    },
                    edges = new[] { new { s = 0, t = 1, n = 2 } },
                    totalCalls = 2,
                    truncated = true,
                    nextBest = new[]
                    {
                        new { name = "DecryptPayload", entry = "0x140001100", rva = "0x1100", depth = 1, risk = 27, why = "sensitive-name,degree=2" },
                    },
                    frontier = new[] { new { name = "FIXTURE_Helper", entry = "0x140001200", rva = "0x1200", depth = 1 } },
                    summary = new { nodeCount = 2, edgeCount = 1, totalCalls = 2, truncated = true, nextAction = "InspectFunction 0x140001100" },
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("CallGraph", new
        {
            function = "main",
            depth = 2,
            direction = "both",
        }));

        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(4, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("neighborhood", root.GetProperty("mode").GetString());
        Assert.Equal("main", root.GetProperty("seed").GetProperty("name").GetString());
        var best = Assert.Single(root.GetProperty("nextBest").EnumerateArray());
        Assert.Equal("DecryptPayload", best.GetProperty("name").GetString());
        Assert.Equal(27, best.GetProperty("risk").GetInt32());
        Assert.Equal("FIXTURE_Helper", Assert.Single(root.GetProperty("frontier").EnumerateArray()).GetProperty("name").GetString());
    }

    [Fact]
    public void Neighborhood_fixture_is_cheaper_than_full_graph()
    {
        // Representative 64-node module slice versus the 8-node neighborhood a
        // caller actually needs to choose the next function. Both shapes are
        // produced by the same bridge; this guards the token win from drifting.
        var nodes = Enumerable.Range(0, 64)
            .Select(i => new
            {
                name = i == 7 ? "DecryptPayload" : $"FUN_140{i:X4}",
                entry = $"0x14000{i:X4}",
                rva = $"{i:X4}",
            })
            .ToArray();
        var edges = Enumerable.Range(0, 192)
            .Select(i => new { s = i % 64, t = (i * 7 + 1) % 64, n = (i % 4) + 1 })
            .ToArray();
        var full = JsonSerializer.Serialize(new
        {
            schemaVersion = 3,
            nodes,
            edges,
            totalCalls = edges.Sum(edge => edge.n),
            truncated = false,
        });

        var neighborhoodNodes = nodes.Take(8).ToArray();
        var neighborhoodEdges = new[]
        {
            new { s = 0, t = 1, n = 2 }, new { s = 0, t = 7, n = 1 },
            new { s = 1, t = 2, n = 1 }, new { s = 2, t = 3, n = 1 },
            new { s = 3, t = 4, n = 1 }, new { s = 4, t = 5, n = 1 },
            new { s = 5, t = 6, n = 1 },
        };
        var nextBest = new[]
        {
            new { name = "DecryptPayload", entry = "0x140000007", rva = "0007", depth = 1, risk = 27, why = "sensitive-name,degree=3" },
            new { name = "FUN_140000000", entry = "0x140000000", rva = "0000", depth = 1, risk = 4, why = "degree=4" },
            new { name = "FUN_140000002", entry = "0x140000002", rva = "0002", depth = 1, risk = 2, why = "degree=2" },
            new { name = "FUN_140000003", entry = "0x140000003", rva = "0003", depth = 2, risk = -28, why = "degree=2" },
            new { name = "FUN_140000004", entry = "0x140000004", rva = "0004", depth = 2, risk = -28, why = "degree=2" },
        };
        var neighborhood = JsonSerializer.Serialize(new
        {
            schemaVersion = 4,
            mode = "neighborhood",
            seed = neighborhoodNodes[0],
            nodes = neighborhoodNodes,
            edges = neighborhoodEdges,
            totalCalls = neighborhoodEdges.Sum(edge => edge.n),
            truncated = false,
            nextBest,
            summary = new
            {
                nodeCount = neighborhoodNodes.Length,
                edgeCount = neighborhoodEdges.Length,
                totalCalls = neighborhoodEdges.Sum(edge => edge.n),
                truncated = false,
                nextAction = "InspectFunction 0x140000007 with includeDecomp:false, or use it as the next CallGraph seed.",
            },
        });

        var fullTokens = TokenCounter.Count(full);
        var neighborhoodTokens = TokenCounter.Count(neighborhood);
        _output.WriteLine(
            $"CallGraph tokens: full64={fullTokens} neighborhood8={neighborhoodTokens} saved={fullTokens - neighborhoodTokens} ({(fullTokens - neighborhoodTokens) * 100.0 / fullTokens:F1}%)");
        Assert.True(neighborhoodTokens < fullTokens,
            $"Neighborhood must stay cheaper than the full slice (full={fullTokens}, neighborhood={neighborhoodTokens})");
    }

    [Fact]
    public void Schema_accepts_instruction_count_and_edge_format_opts()
    {
        using var server = CreateServer();

        Assert.Null(server.ValidateArguments("CallGraph", Args("""{"includeInstructionCount":true}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args("""{"includeInstructionCount":false}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args("""{"edgeFormat":"indexed"}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args("""{"edgeFormat":"full"}""")));
        Assert.Null(server.ValidateArguments("CallGraph", Args("""{"maxNodes":2,"includeInstructionCount":true,"edgeFormat":"indexed"}""")));

        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"includeInstructionCount":"yes"}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"includeInstructionCount":1}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"edgeFormat":"sparse"}""")));
        Assert.NotNull(server.ValidateArguments("CallGraph", Args("""{"edgeFormat":1}""")));
    }

    [Fact]
    public void CallGraph_V3_And_V2_Edge_Shapes_Parse()
    {
        // .NET CallGraph is a transparent passthrough, so this pins both wire
        // shapes at the test level: v3 integer-indexed {s,t,n} (current) and
        // the canned v2 {caller,callee,count} (backward compat for CI gap).
        const string v3 = """{"schemaVersion":3,"nodes":[{"name":"a","entry":"0x140001000","rva":"0x1000"}],"edges":[{"s":0,"t":0,"n":2}],"totalCalls":2,"truncated":false}""";
        using (var v3Doc = JsonDocument.Parse(v3))
        {
            var root = v3Doc.RootElement;
            Assert.Equal(3, root.GetProperty("schemaVersion").GetInt32());
            var edge = Assert.Single(root.GetProperty("edges").EnumerateArray());
            Assert.Equal(0, edge.GetProperty("s").GetInt32());
            Assert.Equal(0, edge.GetProperty("t").GetInt32());
            Assert.Equal(2, edge.GetProperty("n").GetInt32());
        }

        const string v2 = """{"schemaVersion":2,"nodes":[{"name":"a","entry":"0x140001000","rva":"0x1000","instructionCount":12}],"edges":[{"caller":"0x140001000","callee":"0x140001040","count":2}],"nodeCount":1,"edgeCount":1,"totalCalls":2,"truncated":false}""";
        using (var v2Doc = JsonDocument.Parse(v2))
        {
            var root = v2Doc.RootElement;
            Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
            var edge = Assert.Single(root.GetProperty("edges").EnumerateArray());
            Assert.Equal("0x140001000", edge.GetProperty("caller").GetString());
            Assert.Equal("0x140001040", edge.GetProperty("callee").GetString());
            Assert.Equal(2, edge.GetProperty("count").GetInt32());
        }
    }

    [Fact]
    public async Task Wire_graph_v3_indexed_edges_pass_through()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("CallGraph", (id, args) =>
        {
            var includeCounts = args?.TryGetProperty("includeInstructionCount", out var flag) == true && flag.GetBoolean();
            object[] nodes = includeCounts
                ? [new { name = "FixtureCaller", entry = "0x140001000", rva = "0x1000", instructionCount = 12 },
                   new { name = "FixtureCallee", entry = "0x140001040", rva = "0x1040", instructionCount = 4 }]
                : [new { name = "FixtureCaller", entry = "0x140001000", rva = "0x1000" },
                   new { name = "FixtureCallee", entry = "0x140001040", rva = "0x1040" }];
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 3,
                    nodes,
                    edges = new[] { new { s = 0, t = 1, n = 2 } },
                    totalCalls = 2,
                    truncated = false,
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("CallGraph", new { maxNodes = 2, includeInstructionCount = true }));
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(3, root.GetProperty("schemaVersion").GetInt32());
        var edge = Assert.Single(root.GetProperty("edges").EnumerateArray());
        Assert.Equal(0, edge.GetProperty("s").GetInt32());
        Assert.Equal(1, edge.GetProperty("t").GetInt32());
        Assert.Equal(2, edge.GetProperty("n").GetInt32());
    }

    [Fact]
    public async Task Wire_graph_reports_aggregated_counts_and_continuation()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("CallGraph", (id, args) =>
        {
            var maxNodes = args?.TryGetProperty("maxNodes", out var nodes) == true ? nodes.GetInt32() : -1;
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    nodes = new[]
                    {
                        new { name = "FixtureCaller", entry = "0x140001000", rva = "0x1000", instructionCount = 12 },
                        new { name = "FixtureCallee", entry = "0x140001040", rva = "0x1040", instructionCount = 4 },
                    },
                    edges = new[]
                    {
                        new { caller = "0x140001000", callee = "0x140001040", count = 2 },
                    },
                    nodeCount = 2,
                    edgeCount = 1,
                    totalCalls = 2,
                    truncated = true,
                    nextStart = "0x140001080",
                    continuation = "Repeat CallGraph with start set to nextStart.",
                    maxNodes,
                    bridgeMarker = "keep-me",
                },
            });
        });

        var text = TextOf(await harness.CallToolOverWireAsync("CallGraph", new { maxNodes = 2 }));

        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
        var nodes = root.GetProperty("nodes").EnumerateArray().ToArray();
        Assert.Equal(2, nodes.Length);
        Assert.Equal("FixtureCaller", nodes[0].GetProperty("name").GetString());
        Assert.Equal("0x140001000", nodes[0].GetProperty("entry").GetString());
        Assert.Equal(12, nodes[0].GetProperty("instructionCount").GetInt32());
        var edge = Assert.Single(root.GetProperty("edges").EnumerateArray());
        Assert.Equal("0x140001000", edge.GetProperty("caller").GetString());
        Assert.Equal("0x140001040", edge.GetProperty("callee").GetString());
        Assert.Equal(2, edge.GetProperty("count").GetInt32());
        Assert.Equal(2, root.GetProperty("totalCalls").GetInt32());
        Assert.True(root.GetProperty("truncated").GetBoolean());
        Assert.Equal("0x140001080", root.GetProperty("nextStart").GetString());
        // Static reads are transparent: bridge-only fields survive the wire.
        Assert.Equal("keep-me", root.GetProperty("bridgeMarker").GetString());
    }
}
