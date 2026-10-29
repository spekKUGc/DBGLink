using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// Pins the Triage merge: the advertised <c>Triage(kind)</c> tool dispatches
/// to the existing implementations, every kind answers a stable payload,
/// and the pre-merge <c>TriageImports</c>/<c>TriageStrings</c> aliases are
/// purged (P3: unknown to discovery and to calls).
/// </summary>
public sealed class TriageMergeTests
{
    private sealed class RoutingGhidra : IGhidraClient
    {
        public readonly List<(string Method, string? ArgsJson)> Calls = [];
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Calls.Add((method, arguments?.GetRawText()));
            return Task.FromResult(method switch
            {
                "ListImports" =>
                    "{\"id\":1,\"ok\":true,\"result\":{\"imports\":[" +
                    "{\"name\":\"connect\",\"library\":\"ws2_32.dll\",\"address\":\"0x140001000\",\"refCount\":5}," +
                    "{\"name\":\"WriteProcessMemory\",\"library\":\"kernel32.dll\",\"address\":\"0x140001001\",\"refCount\":6}],\"truncated\":false}}",
                "DumpStrings" =>
                    "{\"id\":1,\"ok\":true,\"result\":{\"strings\":[" +
                    "{\"address\":\"0x140003000\",\"text\":\"http://evil.example/c2\",\"length\":24}],\"truncated\":false}}",
                _ => "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"unexpected\"}}",
            });
        }
    }

    private sealed class NullBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken t) => Task.FromResult(true);
        public Task<string> RequestAsync(string m, JsonElement? a, CancellationToken t)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"y\"}}");
    }

    private static LocalMcpServer Server(RoutingGhidra ghidra) => new(
        new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), ghidra);

    private static CallToolRequestParams Req(string name, string argsJson) => new()
    {
        Name = name,
        Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(argsJson)!,
    };

    private static string Text(CallToolResult result)
    {
        Assert.False(result.IsError);
        return Assert.IsType<TextContentBlock>(result.Content[0]).Text;
    }

    [Fact]
    public async Task Triage_kind_defaults_to_imports()
    {
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        var unified = Text(await server.CallToolAsync(Req("Triage", "{\"kind\":\"imports\",\"top\":2}"), CancellationToken.None));
        // Omitted kind defaults to imports with identical bytes.
        ghidra.Calls.Clear();
        var defaulted = Text(await server.CallToolAsync(Req("Triage", "{\"top\":2}"), CancellationToken.None));
        Assert.Equal(unified, defaulted);
    }

    [Fact]
    public async Task Triage_kind_strings_returns_ioc_payload()
    {
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        var unified = Text(await server.CallToolAsync(Req("Triage", "{\"kind\":\"strings\"}"), CancellationToken.None));
        Assert.Contains("suspiciousCount", unified);
    }

    [Fact]
    public async Task Triage_kind_both_merges_both_sides()
    {
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        var both = JsonNode.Parse(Text(await server.CallToolAsync(
            Req("Triage", "{\"kind\":\"both\",\"top\":2}"), CancellationToken.None)))!.AsObject();
        var imports = JsonNode.Parse(Text(await server.CallToolAsync(
            Req("Triage", "{\"kind\":\"imports\",\"top\":2}"), CancellationToken.None)))!.AsObject();
        var strings = JsonNode.Parse(Text(await server.CallToolAsync(
            Req("Triage", "{\"kind\":\"strings\"}"), CancellationToken.None)))!.AsObject();
        Assert.Equal(imports.ToJsonString(), both["imports"]!.ToJsonString());
        Assert.Equal(strings.ToJsonString(), both["strings"]!.ToJsonString());
    }

    [Fact]
    public void Triage_aliases_are_hidden_but_the_unified_tool_is_advertised()
    {
        using var server = Server(new RoutingGhidra());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(tool => tool["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.Contains("Triage", names);
        Assert.DoesNotContain("TriageImports", names);
        Assert.DoesNotContain("TriageStrings", names);
    }

    [Fact]
    public async Task Triage_forwards_only_each_side_keys()
    {
        // The union schema admits both sides' knobs, but each implementation
        // receives only its own: foreign keys neither change defaults nor
        // leak into bridge payloads.
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        await server.CallToolAsync(
            Req("Triage", "{\"kind\":\"strings\",\"top\":32,\"section\":\".rdata\"}"), CancellationToken.None);
        var dump = Assert.Single(ghidra.Calls, call => call.Method == "DumpStrings");
        Assert.DoesNotContain("\"top\"", dump.ArgsJson);
        ghidra.Calls.Clear();
        await server.CallToolAsync(
            Req("Triage", "{\"kind\":\"imports\",\"section\":\".rdata\",\"start\":\"0x140002000\",\"top\":2}"),
            CancellationToken.None);
        var list = Assert.Single(ghidra.Calls, call => call.Method == "ListImports");
        Assert.DoesNotContain("\"section\"", list.ArgsJson);
        Assert.DoesNotContain("\"start\"", list.ArgsJson);
    }

    [Fact]
    public async Task Triage_invalid_kind_rejected_before_any_backend_call()
    {
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            Req("Triage", "{\"kind\":\"bogus\"}"), CancellationToken.None));
        Assert.Empty(ghidra.Calls);
    }

    [Fact]
    public async Task Triage_batch_admits_unified_tool_kinds_together()
    {
        // Local batch dispatch serves Triage through the same kind routing as
        // the direct tool (P3: the pre-merge aliases are purged, not batched).
        var ghidra = new RoutingGhidra();
        using var server = Server(ghidra);
        var result = await server.CallToolAsync(Req("BatchStaticQueries",
            "{\"requests\":[{\"method\":\"Triage\",\"arguments\":{\"kind\":\"imports\",\"top\":2}}," +
            "{\"method\":\"Triage\",\"arguments\":{\"kind\":\"strings\"}}]}"), CancellationToken.None);
        var text = Text(result);
        using var document = JsonDocument.Parse(text);
        var rows = document.RootElement.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.All(rows, row => Assert.True(row.GetProperty("response").GetProperty("ok").GetBoolean()));
        Assert.Contains(ghidra.Calls, call => call.Method == "ListImports");
        Assert.Contains(ghidra.Calls, call => call.Method == "DumpStrings");
    }
}
