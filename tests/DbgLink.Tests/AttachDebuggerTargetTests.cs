using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class AttachDebuggerTargetTests
{
    private const string CurrentProtocol = "2025-06-18";

    private sealed class CapturingBridge : IBridgeClient
    {
        public int RequestCount;
        public Task<bool> PingAsync(CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref RequestCount);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"attached\":true}}");
        }
    }

    private static (LocalMcpServer server, CapturingBridge bridge) CreateServer()
    {
        var bridge = new CapturingBridge();
        var server = new LocalMcpServer(
            new ServerConfig
            {
                Port = ServerConfig.DefaultPort,
                MaxConcurrentRequests = 16,
                MaxQueuedOperations = 32,
                DefaultToolTimeoutMs = 5_000,
                AllowMutation = true,
            },
            bridge,
            new NullGhidra(),
            new CompletedGhidraControl("{}"),
            null);
        return (server, bridge);
    }

    private static CallToolRequestParams ToolCall(string name, object arguments) => new()
    {
        Name = name,
        Arguments = new Dictionary<string, JsonElement>(
            JsonSerializer.SerializeToElement(arguments).EnumerateObject().ToDictionary(
                property => property.Name,
                property => property.Value.Clone())),
    };

    private static string ResponseText(CallToolResult result)
        => string.Join("", result.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));

    [Fact]
    public async Task Attach_rejects_missing_pid_at_schema()
    {
        var (server, bridge) = CreateServer();
        try
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
                ToolCall("AttachDebuggerTarget", new { }), CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
            Assert.Equal(0, bridge.RequestCount);
        }
        finally
        {
            server.Stop();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-7)]
    public async Task Attach_rejects_nonpositive_pid_at_schema(int pid)
    {
        var (server, bridge) = CreateServer();
        try
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
                ToolCall("AttachDebuggerTarget", new { pid }), CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
            Assert.Equal(0, bridge.RequestCount);
        }
        finally
        {
            server.Stop();
        }
    }

    [Fact]
    public async Task Attach_rejects_unopenable_pid_without_bridge_traffic()
    {
        // int.MaxValue can never be a live pid: OpenProcess fails, so the
        // bitness probe fails closed before any pipe traffic.
        var (server, bridge) = CreateServer();
        try
        {
            var result = await server.CallToolAsync(
                ToolCall("AttachDebuggerTarget", new { pid = 2147483647 }), CancellationToken.None);
            Assert.True(result.IsError);
            Assert.Contains("architecture", ResponseText(result), StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, bridge.RequestCount);
        }
        finally
        {
            server.Stop();
        }
    }

    [Fact]
    public async Task Attach_is_listed_with_pid_schema()
    {
        var (server, bridge) = CreateServer();
        _ = bridge;
        try
        {
            var response = await server.ExecuteTestRequestAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                CancellationToken.None, CurrentProtocol);
            using var document = JsonDocument.Parse(Assert.IsType<string>(response));
            var tools = document.RootElement.GetProperty("result").GetProperty("tools");
            var attach = tools.EnumerateArray().FirstOrDefault(
                t => t.GetProperty("name").GetString() == "AttachDebuggerTarget");
            Assert.True(attach.ValueKind == JsonValueKind.Object, "AttachDebuggerTarget is not listed.");
            var schema = attach.GetProperty("inputSchema");
            Assert.Contains("pid", schema.GetProperty("required").EnumerateArray().Select(e => e.GetString()));
        }
        finally
        {
            server.Stop();
        }
    }
}
