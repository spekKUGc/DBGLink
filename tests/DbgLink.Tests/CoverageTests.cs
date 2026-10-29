using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class CoverageTests
{
    private static LocalMcpServer CreateServer(IBridgeClient bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

    [Fact]
    public void SampleCallStacks_is_hidden_but_bounded_and_callable()
    {
        // Hidden from discovery (BatchDebuggerOperations is the strict
        // superset), still callable with the same bounded sampling limits.
        using var server = CreateServer(new RecordingBridge());
        var compNames = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("SampleCallStacks", compNames);
        Assert.Contains("BatchDebuggerOperations", compNames);
        using var lean = new LocalMcpServer(
            new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        Assert.DoesNotContain(lean.ListTools().OfType<JsonObject>(),
            x => x["name"]!.GetValue<string>() == "SampleCallStacks");
    }

    [Fact]
    public void SampleCallStacks_stays_out_of_the_lean_prompt_but_remains_callable()
    {
        using var lean = new LocalMcpServer(
            new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        Assert.DoesNotContain(lean.ListTools().OfType<JsonObject>(),
            x => x["name"]!.GetValue<string>() == "SampleCallStacks");
    }

    [Theory]
    [InlineData("{\"intervalMs\":49}")]
    [InlineData("{\"intervalMs\":5001}")]
    [InlineData("{\"durationMs\":15001}")]
    [InlineData("{\"maxSamples\":0}")]
    [InlineData("{\"maxSamples\":101}")]
    [InlineData("{\"maxFrames\":0}")]
    [InlineData("{\"maxFrames\":129}")]
    [InlineData("{\"topN\":0}")]
    [InlineData("{\"topN\":129}")]
    [InlineData("{\"autoPause\":\"yes\"}")]
    public async Task Invalid_coverage_arguments_never_reach_a_backend(string json)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = "SampleCallStacks", Arguments = arguments }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task Valid_coverage_call_reaches_the_bridge_with_sampling_arguments()
    {
        var bridge = new CoverageBridge();
        using var server = CreateServer(bridge);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            "{\"intervalMs\":100,\"durationMs\":500,\"maxSamples\":5,\"topN\":10}")!;
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = "SampleCallStacks", Arguments = arguments }, CancellationToken.None);
        Assert.Equal("SampleCallStacks", bridge.LastMethod);
        Assert.Contains("\"maxSamples\":5", bridge.LastArgsJson);
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task Aggregated_coverage_payload_passes_through_with_hit_counts()
    {
        var bridge = new CoverageBridge();
        using var server = CreateServer(bridge);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "SampleCallStacks",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("{\"maxSamples\":2}")!,
        }, CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        using var payload = JsonDocument.Parse(text);
        var frames = payload.RootElement.GetProperty("frames").EnumerateArray().ToArray();
        Assert.Equal(2, payload.RootElement.GetProperty("samples").GetInt32());
        Assert.Equal("app.exe", frames[0].GetProperty("module").GetString());
        Assert.Equal(2, frames[0].GetProperty("hits").GetInt32());
    }

    private sealed class CoverageBridge : IBridgeClient
    {
        public string? LastMethod;
        public string? LastArgsJson;
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            LastMethod = method;
            LastArgsJson = arguments?.GetRawText();
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{" +
                "\"samples\":2,\"uniqueFrames\":1,\"truncated\":false," +
                "\"frames\":[{\"module\":\"app.exe\",\"rva\":\"0x1000\",\"hits\":2}]}}");
        }
    }
}
