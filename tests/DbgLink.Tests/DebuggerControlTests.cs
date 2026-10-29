using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class DebuggerControlTests
{
    private static readonly string[] MutationControlTools =
    [
        "SetBreakpoint", "ClearBreakpoint",
        "ControlDebuggerExecution",
        "SetRegister", "WriteMemory",
    ];

    // Expert tools: hidden from discovery to reduce confusion, still callable.
    // SampleCallStacks hides behind BatchDebuggerOperations. The old
    // single-op annotate/mutate tools were physically removed (P3 cull);
    // BatchAnnotate/SubmitAnnotations are their strict superset.
    private static readonly string[] HiddenExpertTools =
    [
        "SampleCallStacks",
    ];

    private static readonly string[] ReadOnlyControlTools =
    [
        "ListThreads", "GetBacktrace",
    ];

    private static LocalMcpServer CreateServer(IBridgeClient bridge, bool allowMutation)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = allowMutation }, bridge);

    [Fact]
    public void Mutation_control_tools_are_hidden_without_allow_mutation()
    {
        using var server = CreateServer(new RecordingBridge(), allowMutation: false);
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        foreach (var tool in MutationControlTools)
            Assert.DoesNotContain(tool, names);
        foreach (var tool in HiddenExpertTools)
            Assert.DoesNotContain(tool, names);
        foreach (var tool in ReadOnlyControlTools)
            Assert.Contains(tool, names);
    }

    [Fact]
    public void Mutation_control_tools_and_annotations_are_advertised_by_default()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        foreach (var tool in MutationControlTools.Concat(ReadOnlyControlTools))
            Assert.Contains(tool, names);
        foreach (var hidden in HiddenExpertTools)
            Assert.DoesNotContain(hidden, names);
        // The batch supersets stay advertised: single ops hide behind them.
        Assert.Contains("BatchAnnotate", names);
        Assert.Contains("BatchDebuggerOperations", names);
    }

    [Theory]
    [InlineData("SetBreakpoint", "{}")]
    [InlineData("SetBreakpoint", "{\"address\":\" \"}")]
    [InlineData("ClearBreakpoint", "{\"address\":\" \"}")]
    [InlineData("SetRegister", "{\"register\":\"!!\",\"value\":\"0x0\"}")]
    [InlineData("SetRegister", "{\"register\":\"rax\"}")]
    [InlineData("WriteMemory", "{\"address\":\"cip\",\"hexBytes\":\" \"}")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"bogus\"}")]
    [InlineData("ControlDebuggerExecution", "{}")]
    [InlineData("ListThreads", "{\"maxItems\":513}")]
    [InlineData("GetBacktrace", "{\"maxFrames\":0}")]
    public async Task Invalid_control_arguments_never_reach_a_backend(string name, string json)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge, allowMutation: true);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = arguments }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("SetBreakpoint", "{\"address\":\"cip\"}")]
    [InlineData("ClearBreakpoint", "{\"address\":\"cip\"}")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"run\"}")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"pause\"}")]
    [InlineData("SetRegister", "{\"register\":\"rax\",\"value\":\"0x0\"}")]
    [InlineData("WriteMemory", "{\"address\":\"csp\",\"hexBytes\":\"90 90\"}")]
    public async Task Valid_mutation_control_calls_reach_the_bridge(string name, string json)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge, allowMutation: true);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        // RecordingBridge returns ok:true without a payload, which the dispatcher
        // reports as a tool error — but the bridge must have been called once.
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = arguments }, CancellationToken.None);
        Assert.Equal(1, bridge.RequestCount);
        // RecordingBridge answers ok:true with no payload, which the
        // dispatcher reports as a tool error: pin the contract instead of a
        // NotNull tautology (CallToolAsync never returns null).
        Assert.True(result.IsError);
    }

    [Theory]
    [InlineData("ListThreads", "{\"maxItems\":16}")]
    [InlineData("GetBacktrace", "{\"maxFrames\":8}")]
    public async Task Valid_readonly_control_calls_reach_the_bridge(string name, string json)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge, allowMutation: false);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        var result = await server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = arguments }, CancellationToken.None);
        Assert.Equal(1, bridge.RequestCount);
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Mutation_control_calls_require_the_mutation_capability()
    {
        using var server = CreateServer(new RecordingBridge(), allowMutation: false);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "SetBreakpoint",
                Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("{\"address\":\"cip\"}")!,
            }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("capability", error.Message);
    }

    [Theory]
    [InlineData("SetBreakpoint", "{\"address\":\"cip\"}")]
    [InlineData("ClearBreakpoint", "{\"address\":\"cip\"}")]
    [InlineData("ClearBreakpoint", "{\"all\":true}")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"run\"}")]
    [InlineData("ControlDebuggerExecution", "{\"action\":\"pause\"}")]
    [InlineData("SetRegister", "{\"register\":\"rax\",\"value\":\"0x0\"}")]
    [InlineData("WriteMemory", "{\"address\":\"csp\",\"hexBytes\":\"90 90\"}")]
    public async Task Every_mutation_control_call_requires_the_mutation_capability(string name, string json)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge, allowMutation: false);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = arguments }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("capability", error.Message);
        Assert.Equal(0, bridge.RequestCount);
    }
}
