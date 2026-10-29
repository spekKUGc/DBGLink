using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// HTTP/error-surface pins for the live-confirmed defects:
/// 1. Missing/empty Content-Type on POST /mcp must be 400/415 with a
///    JSON-RPC error body (never an empty-body 500). Auth keeps precedence.
/// 2. Tool-layer deserialization/validation faults (e.g. a lone surrogate)
///    must surface as -32602 with a safe message, never opaque -32603.
/// </summary>
[Collection("LiveWire")]
public sealed class HttpErrorSurfaceTests
{
    private static readonly string Token = new('a', 40);

    // --- Content-Type helpers (unit) ---

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("text/plain", false)]
    [InlineData("text/plain; charset=utf-8", false)]
    [InlineData("application/json", true)]
    [InlineData("application/json; charset=utf-8", true)]
    [InlineData("Application/JSON", true)]
    [InlineData("application/json ; charset=utf-8", true)]
    public void IsJsonContentType_Classifies_Missing_Empty_Wrong_And_Json(string? contentType, bool expected)
    {
        Assert.Equal(expected, McpRequestPolicy.IsJsonContentType(contentType));
    }

    // --- Live wire: missing/empty Content-Type ---

    [Fact]
    public async Task Post_Without_ContentType_Returns_JsonRpc_Error_Never_500()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        var rpc = """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""";
        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes(rpc));
        content.Headers.Clear(); // no Content-Type
        using var response = await host.Client.PostAsync("mcp", content);
        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.UnsupportedMediaType,
            $"expected 400/415, got {(int)response.StatusCode}");
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("2.0", doc.RootElement.GetProperty("jsonrpc").GetString());
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Post_With_Empty_ContentType_Header_Returns_JsonRpc_Error_Never_500()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        var (status, media, body) = await host.RawPostAsync(
            """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""",
            sendContentTypeHeader: true, contentTypeValue: "");
        Assert.True(status is 400 or 415, $"expected 400/415, got {status}");
        Assert.NotEqual(500, status);
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        Assert.True(doc.RootElement.TryGetProperty("error", out var error));
        Assert.True(error.TryGetProperty("code", out _));
        Assert.True(error.TryGetProperty("message", out _));
        Assert.Equal("application/json", media);
    }

    [Fact]
    public async Task Post_With_TextPlain_ContentType_Is_415_With_JsonRpc_Body()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        using var content = new StringContent("""{"jsonrpc":"2.0","id":3,"method":"tools/list"}""", Encoding.UTF8, "text/plain");
        using var response = await host.Client.PostAsync("mcp", content);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Wrong_Token_With_Missing_ContentType_Keeps_401_Precedence()
    {
        await using var host = await ErrorSurfaceHost.StartAsync(requireAuth: true);
        using var anonymous = new HttpClient { BaseAddress = host.Client.BaseAddress, Timeout = TimeSpan.FromSeconds(5) };
        anonymous.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", new string('b', 40));
        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes("""{"jsonrpc":"2.0","id":4,"method":"tools/list"}"""));
        content.Headers.Clear();
        using var response = await anonymous.PostAsync("mcp", content);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Empty_Body_With_Json_ContentType_Stays_400()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        using var content = new StringContent("", Encoding.UTF8, "application/json");
        using var response = await host.Client.PostAsync("mcp", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Theory]
    [InlineData("{bad")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"tools/list\"}")]
    public async Task Invalid_Json_And_Duplicate_Keys_Keep_Returning_400(string payload)
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        using var response = await host.Client.PostAsync("mcp",
            new StringContent(payload, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    // --- Live wire: lone surrogate -> -32602 ---

    [Fact]
    public async Task Lone_Surrogate_Argument_Returns_InvalidParams_Not_Opaque_InternalError()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        var rpc = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"GetServerStatus\",\"arguments\":{\"bogus\":\"\\ud800\"}}}";
        using var response = await host.Client.PostAsync("mcp",
            new StringContent(rpc, Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        // Policy short-circuits undecodable input as HTTP 400 with -32602.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var doc = JsonDocument.Parse(body);
        var error = doc.RootElement.GetProperty("error");
        Assert.Equal((int)McpErrorCode.InvalidParams, error.GetProperty("code").GetInt32());
        var message = error.GetProperty("message").GetString() ?? "";
        Assert.False(string.IsNullOrWhiteSpace(message));
        Assert.DoesNotContain("An error occurred.", message);
        Assert.True(message.Length <= 512);
    }

    // --- Dispatcher: surrogate/validation exceptions map properly ---

    [Fact]
    public async Task Dispatcher_Surrogate_In_Known_String_Field_Throws_InvalidParams()
    {
        using var server = new LocalMcpServer(new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            MaxConcurrentRequests = 16,
            MaxQueuedOperations = 32,
            DefaultToolTimeoutMs = 5_000,
        }, new RecordingBridge());
        // The \ud800 escape parses but cannot be decoded: GetString throws
        // InvalidOperationException. The dispatcher must map it to -32602,
        // never let it escape as an opaque -32603.
        using var parsed = JsonDocument.Parse("{\"function\":\"\\ud800\"}");
        var request = new CallToolRequestParams
        {
            Name = "InspectFunction",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["function"] = parsed.RootElement.GetProperty("function").Clone(),
            },
        };
        var exception = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(request, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, exception.ErrorCode);
        Assert.Contains("Invalid arguments", exception.Message);
        Assert.DoesNotContain("An error occurred.", exception.Message);
        Assert.True(exception.Message.Length <= 512);
    }

    [Fact]
    public async Task Dispatcher_Undecodable_Arguments_Throw_InvalidParams_Not_Silent_Success()
    {
        using var server = new LocalMcpServer(new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            MaxConcurrentRequests = 16,
            MaxQueuedOperations = 32,
            DefaultToolTimeoutMs = 5_000,
        }, new RecordingBridge());
        // JsonDocument parses the escape but the element cannot round-trip
        // through SerializeToElement (JsonException -> null). GetServerStatus
        // has no required fields, so without the explicit guard this would
        // silently succeed with dropped arguments.
        using var parsed = JsonDocument.Parse("{\"bogus\":\"\\ud800\"}");
        var request = new CallToolRequestParams
        {
            Name = "GetServerStatus",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["bogus"] = parsed.RootElement.GetProperty("bogus").Clone(),
            },
        };
        var exception = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(request, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, exception.ErrorCode);
    }

    [Fact]
    public async Task Dispatcher_Ordinary_Validation_Error_Stays_InvalidParams()
    {
        using var server = new LocalMcpServer(new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            MaxConcurrentRequests = 16,
            MaxQueuedOperations = 32,
            DefaultToolTimeoutMs = 5_000,
        }, new RecordingBridge());
        var exception = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "InspectFunction",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, exception.ErrorCode);
    }

    // --- #1: surrogate in JSON-RPC id -> well-formed body, never empty ---

    [Fact]
    public async Task Surrogate_In_Id_Returns_WellFormed_Error_With_Null_Id()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        // The \ud800 escape is ASCII on the wire; it parses but cannot be
        // decoded, so the policy reports -32602 echoing id:null.
        var rpc = "{\"jsonrpc\":\"2.0\",\"id\":\"\\ud800\",\"method\":\"tools/list\",\"params\":{}}";
        using var response = await host.Client.PostAsync("mcp",
            new StringContent(rpc, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        Assert.Equal("2.0", root.GetProperty("jsonrpc").GetString());
        Assert.True(root.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.Null);
        var error = root.GetProperty("error");
        Assert.Equal((int)McpErrorCode.InvalidParams, error.GetProperty("code").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(error.GetProperty("message").GetString()));
    }

    [Fact]
    public async Task Surrogate_In_Id_RawSocket_Returns_WellFormed_Error()
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        var rpc = "{\"jsonrpc\":\"2.0\",\"id\":\"\\ud800\",\"method\":\"tools/list\",\"params\":{}}";
        var (status, media, body) = await host.RawPostAsync(rpc,
            sendContentTypeHeader: true, contentTypeValue: "application/json");
        Assert.Equal(400, status);
        Assert.Equal("application/json", media);
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(body);
        Assert.Equal((int)McpErrorCode.InvalidParams,
            doc.RootElement.GetProperty("error").GetProperty("code").GetInt32());
    }

    // --- #2: envelope-shape faults -> -32602, never opaque -32603 ---

    [Theory]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\",\"params\":[]}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":102,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\",\"arguments\":\"nope\"}}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":103,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\",\"arguments\":[]}}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":104,\"method\":\"tools/call\",\"params\":{\"name\":123,\"arguments\":{}}}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":105,\"method\":\"tools/call\"}")]
    public async Task Envelope_Shape_Faults_Return_InvalidParams_Not_Opaque(string rpc)
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        using var response = await host.Client.PostAsync("mcp",
            new StringContent(rpc, Encoding.UTF8, "application/json"));
        // Shape faults are JSON-RPC InvalidParams: transport stays 200 like
        // the dispatcher's own -32602, only the code/message change.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(ReadPayload(body));
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("error", out var error));
        Assert.Equal((int)McpErrorCode.InvalidParams, error.GetProperty("code").GetInt32());
        var message = error.GetProperty("message").GetString() ?? "";
        Assert.False(string.IsNullOrWhiteSpace(message));
        Assert.DoesNotContain("An error occurred.", message);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":106,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\",\"arguments\":null}}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":107,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\"}}")]
    public async Task Null_Or_Missing_Arguments_Stay_InvalidParams(string rpc)
    {
        await using var host = await ErrorSurfaceHost.StartAsync();
        using var response = await host.Client.PostAsync("mcp",
            new StringContent(rpc, Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(body));
        using var doc = JsonDocument.Parse(ReadPayload(body));
        Assert.True(doc.RootElement.TryGetProperty("error", out var error));
        Assert.Equal((int)McpErrorCode.InvalidParams, error.GetProperty("code").GetInt32());
        Assert.DoesNotContain("An error occurred.", error.GetProperty("message").GetString() ?? "");
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Theory]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":[]}", "params must be an object")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"X\",\"arguments\":\"nope\"}}", "arguments must be an object")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"X\",\"arguments\":[]}}", "arguments must be an object")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":1}}", "params.name")]
    public void ValidateToolsCallEnvelope_Maps_Shapes_To_InvalidParams(string json, string fragment)
    {
        using var doc = JsonDocument.Parse(json);
        var message = McpRequestPolicy.ValidateToolsCallEnvelope(doc.RootElement);
        Assert.NotNull(message);
        Assert.Contains(fragment, message);
    }

    [Fact]
    public void ValidateToolsCallEnvelope_Passes_Valid_And_NonCall_Through()
    {
        using var valid = JsonDocument.Parse(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\",\"arguments\":{}}}");
        Assert.Null(McpRequestPolicy.ValidateToolsCallEnvelope(valid.RootElement));
        using var missingArgs = JsonDocument.Parse(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"Xrefs\"}}");
        Assert.Null(McpRequestPolicy.ValidateToolsCallEnvelope(missingArgs.RootElement));
        using var other = JsonDocument.Parse(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":[]}");
        Assert.Null(McpRequestPolicy.ValidateToolsCallEnvelope(other.RootElement));
    }

    // --- #3: dead debugger -> debugger_unreachable, not generic catch-all ---

    [Fact]
    public async Task GetServerStatus_Dead_Debugger_Returns_DebuggerUnreachable_With_Id_And_Hint()
    {
        using var server = new LocalMcpServer(new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            MaxConcurrentRequests = 16,
            MaxQueuedOperations = 32,
            DefaultToolTimeoutMs = 5_000,
        }, new DeadDebuggerBridge());
        var result = await server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None);
        Assert.True(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("debugger_unreachable", text);
        Assert.Contains("default", text);
        Assert.Contains("ListAnalysisSessions", text);
        Assert.Contains("CloseAnalysisSession", text);
        Assert.DoesNotContain("backend component failed", text);
    }

    private static string ReadPayload(string body)
    {
        // Policy shape errors are plain JSON; the SDK may answer dispatcher
        // -32602 over SSE. Accept both so the pin survives transport tweaks.
        var start = body.IndexOf('{');
        var end = body.LastIndexOf('}');
        if (body.Contains("data: ", StringComparison.Ordinal))
        {
            var line = body.Split('\n').FirstOrDefault(l => l.StartsWith("data: ", StringComparison.Ordinal));
            if (line is not null) return line["data: ".Length..].Trim();
        }
        return start >= 0 && end > start ? body[start..(end + 1)] : body.Trim();
    }

    private sealed class DeadDebuggerBridge : DbgLink.Server.IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(false);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromException<string>(new IOException("The debugger pipe is dead."));
    }

    private sealed class ErrorSurfaceHost : IAsyncDisposable
    {
        private static readonly string HostBearerToken = Token;
        public RecordingBridge Bridge { get; } = new();
        public HttpClient Client { get; }
        public int Port { get; }
        private readonly LocalMcpServer _server;
        private readonly Task _run;

        private ErrorSurfaceHost(int port, bool requireAuth)
        {
            Port = port;
            Client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/"), Timeout = TimeSpan.FromSeconds(10) };
            Client.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
            Client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", HostBearerToken);
            _server = new LocalMcpServer(new ServerConfig
            {
                Port = port,
                AuthToken = HostBearerToken,
                MaxRequestBodyBytes = 4096,
                RequireAuthToken = requireAuth,
            }, Bridge);
            _run = _server.RunAsync(CancellationToken.None);
        }

        public static Task<ErrorSurfaceHost> StartAsync(bool requireAuth = false)
            => StartAsync(requireAuth, 0);

        private static async Task<ErrorSurfaceHost> StartAsync(bool requireAuth, int _)
        {
            const int maxAttempts = 5;
            for (var attempt = 1; ; attempt++)
            {
                var port = TestPortAllocator.GetFreePort();
                var host = new ErrorSurfaceHost(port, requireAuth);
                try
                {
                    for (var wait = 0; wait < 100; wait++)
                    {
                        if (host._run.IsCompleted) await host._run;
                        try { using var response = await host.Client.GetAsync("metrics"); if (response.IsSuccessStatusCode) return host; }
                        catch (HttpRequestException) { }
                        await Task.Delay(25);
                    }
                }
                catch (IOException) when (attempt < maxAttempts)
                {
                    try { await host.DisposeAsync(); } catch { }
                    continue;
                }
                catch { await host.DisposeAsync(); throw; }
                await host.DisposeAsync();
                throw new TimeoutException("The error-surface HTTP host did not start.");
            }
        }

        /// <summary>Raw-socket POST for header shapes HttpClient cannot emit
        /// (e.g. a present-but-empty Content-Type value).</summary>
        public async Task<(int status, string? mediaType, string body)> RawPostAsync(
            string body, bool sendContentTypeHeader, string? contentTypeValue)
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", Port);
            using var stream = tcp.GetStream();
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var head = new StringBuilder();
            head.Append("POST /mcp HTTP/1.1\r\n");
            head.Append("Host: 127.0.0.1\r\n");
            head.Append($"Authorization: Bearer {HostBearerToken}\r\n");
            head.Append("Accept: application/json, text/event-stream\r\n");
            head.Append("MCP-Protocol-Version: 2025-06-18\r\n");
            if (sendContentTypeHeader)
                head.Append($"Content-Type:{(string.IsNullOrEmpty(contentTypeValue) ? "" : " " + contentTypeValue)}\r\n");
            head.Append($"Content-Length: {bodyBytes.Length}\r\n");
            head.Append("Connection: close\r\n\r\n");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()));
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
            using var ms = new MemoryStream();
            var buf = new byte[8192];
            int n;
            try { while ((n = await stream.ReadAsync(buf)) != 0) ms.Write(buf, 0, n); } catch { }
            var response = Encoding.UTF8.GetString(ms.ToArray());
            var status = int.Parse(response.Split("\r\n")[0].Split(' ')[1]);
            string? media = null;
            foreach (var line in response.Split("\r\n"))
            {
                if (line.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = line["Content-Type:".Length..].Trim();
                    var semi = value.IndexOf(';');
                    media = (semi < 0 ? value : value[..semi]).Trim();
                }
            }
            var sep = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            // The error payload is a small JSON object; de-chunk if needed.
            var rawBody = sep >= 0 ? response[(sep + 4)..] : "";
            var payload = ExtractJsonPayload(rawBody);
            return (status, media, payload);
        }

        private static string ExtractJsonPayload(string raw)
        {
            var start = raw.IndexOf('{');
            var end = raw.LastIndexOf('}');
            return start >= 0 && end > start ? raw[start..(end + 1)] : raw.Trim();
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            _server.Stop();
            await _run.WaitAsync(TimeSpan.FromSeconds(10));
            _server.Dispose();
        }
    }
}
