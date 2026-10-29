using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class DebugTargetOperationsTests
{
    private const string CurrentProtocol = "2025-06-18";

    private sealed class CapturingBridge : IBridgeClient
    {
        public string Response = "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true}}";
        public int RequestCount;
        public string? LastMethod;
        public string? LastArguments;
        public Task<bool> PingAsync(CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref RequestCount);
            LastMethod = method;
            LastArguments = arguments?.GetRawText();
            return Task.FromResult(Response);
        }
    }

    private static LocalMcpServer CreateServer(
        IBridgeClient bridge, bool allowMutation, bool control) => new(
            new ServerConfig
            {
                Port = ServerConfig.DefaultPort,
                MaxConcurrentRequests = 16,
                MaxQueuedOperations = 32,
                DefaultToolTimeoutMs = 5_000,
                AllowMutation = allowMutation,
            },
            bridge,
            new NullGhidra(),
            control ? new CompletedGhidraControl("{}") : null,
            null);

    private static string OpenBody(int id, string argumentsJson) =>
        $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"OpenDebugTarget\",\"arguments\":{argumentsJson}}}}}";

    private static string MissingExe() => Path.Combine(
        Path.GetTempPath(), "dbglink-no-such-target-" + Guid.NewGuid().ToString("N"), "app.exe");

    private static async Task<(bool isError, string text)> CallAsync(
        LocalMcpServer server, string body)
    {
        var response = await server.ExecuteTestRequestAsync(
            body, CancellationToken.None, CurrentProtocol);
        using var document = JsonDocument.Parse(Assert.IsType<string>(response));
        var result = document.RootElement.GetProperty("result");
        return (
            result.GetProperty("isError").GetBoolean(),
            result.GetProperty("content")[0].GetProperty("text").GetString() ?? "");
    }

    [Fact]
    public async Task Unknown_without_control()
    {
        var server = CreateServer(new RecordingBridge(), allowMutation: true, control: false);
        try
        {
            var response = await server.ExecuteTestRequestAsync(
                OpenBody(1, "{\"path\":\"C:\\\\x.exe\"}"), CancellationToken.None, CurrentProtocol);
            using var document = JsonDocument.Parse(Assert.IsType<string>(response));
            Assert.True(document.RootElement.TryGetProperty("error", out _));
        }
        finally
        {
            server.Stop();
        }
    }

    [Fact]
    public async Task Hidden_without_mutation_capability()
    {
        var server = CreateServer(new RecordingBridge(), allowMutation: false, control: true);
        try
        {
            Assert.DoesNotContain(
                server.ListTools().OfType<System.Text.Json.Nodes.JsonObject>(),
                x => x["name"]!.GetValue<string>() == "OpenDebugTarget");
            var response = await server.ExecuteTestRequestAsync(
                OpenBody(1, "{\"path\":\"C:\\\\x.exe\"}"), CancellationToken.None, CurrentProtocol);
            using var document = JsonDocument.Parse(Assert.IsType<string>(response));
            Assert.True(document.RootElement.TryGetProperty("error", out var error));
            Assert.Contains("capability", error.GetProperty("message").GetString());
        }
        finally
        {
            server.Stop();
        }
    }

    [Theory]
    [InlineData("{\"path\":\"relative\\\\app.exe\"}")]
    [InlineData("{\"path\":\"C:\\\\dbglink-no-such-target\\\\app.exe\"}")]
    [InlineData("{\"path\":\"C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts\"}")]
    [InlineData("{\"path\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\"arguments\":\"/c \\\"dir\\\"\"}")]
    [InlineData("{\"path\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\"workDir\":\"relative\\\\dir\"}")]
    public async Task Invalid_arguments_never_reach_the_backend(string argumentsJson)
    {
        var bridge = new RecordingBridge();
        var server = CreateServer(bridge, allowMutation: true, control: true);
        try
        {
            var (isError, _) = await CallAsync(server, OpenBody(1, argumentsJson));
            Assert.True(isError);
            Assert.Equal(0, bridge.RequestCount);
        }
        finally
        {
            server.Stop();
        }
    }

    [Fact]
    public async Task Backend_open_failure_is_reported_as_a_tool_error()
    {
        var bridge = new CapturingBridge
        {
            Response = "{\"id\":1,\"ok\":false,\"error\":{\"message\":\"The debugger could not open the target.\"}}",
        };
        using var server = CreateServer(bridge, allowMutation: true, control: true);
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var exe = Path.Combine(directory, "app.exe");
            File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });
            var (isError, text) = await CallAsync(server, OpenBody(1, JsonSerializer.Serialize(new { path = exe })));
            Assert.True(isError);
            Assert.Contains("could not open", text);
            Assert.Equal(1, bridge.RequestCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Valid_call_forwards_path_arguments_and_workdir_to_the_bridge()
    {
        var bridge = new CapturingBridge();
        var server = CreateServer(bridge, allowMutation: true, control: true);
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var exe = Path.Combine(directory, "app.exe");
            File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });
            var argumentsJson = JsonSerializer.Serialize(new
            {
                path = exe,
                arguments = "-a 1",
                workDir = directory,
            });
            var (isError, text) = await CallAsync(server, OpenBody(1, argumentsJson));
            Assert.False(isError);
            Assert.Equal(1, bridge.RequestCount);
            Assert.Equal("OpenDebugTarget", bridge.LastMethod);
            using var payload = JsonDocument.Parse(bridge.LastArguments!);
            Assert.Equal(exe, payload.RootElement.GetProperty("path").GetString());
            Assert.Equal("-a 1", payload.RootElement.GetProperty("arguments").GetString());
            Assert.Equal(
                directory,
                payload.RootElement.GetProperty("workDir").GetString(),
                ignoreCase: true);
            Assert.Contains("opened", text);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
        server.Stop();
    }
}
