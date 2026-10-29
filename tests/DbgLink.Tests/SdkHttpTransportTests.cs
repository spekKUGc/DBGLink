using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

[Collection("LiveWire")]
public sealed class SdkHttpTransportTests
{
    [Fact]
    public async Task Initialize_list_and_call_use_the_sdk_without_a_session()
    {
        const string protocol = "2025-06-18";
        await using var host = await TestHost.StartAsync();
        using var init = await host.Post(Initialize(protocol));
        Assert.Equal(HttpStatusCode.OK, init.StatusCode);
        using var result = await ReadRpc(init);
        Assert.Equal(protocol, result.RootElement.GetProperty("result").GetProperty("protocolVersion").GetString());
        Assert.Equal("DBGLink", result.RootElement.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString());
        host.Client.DefaultRequestHeaders.Add("MCP-Protocol-Version", protocol);
        using var initialized = await host.Post("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
        Assert.True(initialized.IsSuccessStatusCode);
        using var list = await host.Post("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        using var tools = await ReadRpc(list);
        Assert.Contains(tools.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray(),
            tool => tool.GetProperty("name").GetString() == "GetServerStatus");
        using var call = await host.Post("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"GetServerStatus","arguments":{}}}""");
        using var called = await ReadRpc(call);
        Assert.False(called.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal(1, host.Bridge.RequestCount);
        using var metrics = JsonDocument.Parse(await host.Client.GetStringAsync("metrics"));
        Assert.True(metrics.RootElement.GetProperty("bytesReceived").GetInt64() > 0);
        Assert.True(metrics.RootElement.GetProperty("bytesSent").GetInt64() > 0);
    }

    [Fact]
    public async Task Metrics_rejects_requests_without_a_bearer_token()
    {
        await using var host = await TestHost.StartAsync();
        using var anonymous = new HttpClient
        {
            BaseAddress = host.Client.BaseAddress,
            Timeout = TimeSpan.FromSeconds(5)
        };

        using var denied = await anonymous.GetAsync("metrics");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Contains(denied.Headers.WwwAuthenticate, value => value.Scheme == "Bearer");

        using var authorized = await host.Client.GetAsync("metrics");
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
    }

    [Fact]
    public async Task Mcp_endpoint_enforces_the_token_only_when_configured_to()
    {
        await using var host = await TestHost.StartAsync(ToolProfile.Comprehensive, requireAuth: true);
        using var anonymous = new HttpClient
        {
            BaseAddress = host.Client.BaseAddress,
            Timeout = TimeSpan.FromSeconds(5)
        };

        using var denied = await anonymous.PostAsync("mcp",
            new StringContent(Initialize("2025-06-18"), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);

        // The configured client (with the bearer header) keeps working.
        using var allowed = await host.Post(Initialize("2025-06-18"));
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task Single_catalog_is_identical_on_the_wire()
    {
        await using var comprehensive = await TestHost.StartAsync(ToolProfile.Comprehensive);
        await using var lean = await TestHost.StartAsync(ToolProfile.Lean);
        var comprehensiveList = await ReadToolList(comprehensive);
        var leanList = await ReadToolList(lean);

        Assert.Equal(comprehensiveList.GetRawText(), leanList.GetRawText());
    }

    private static async Task<JsonElement> ReadToolList(TestHost host)
    {
        using var init = await host.Post(Initialize("2025-06-18"));
        Assert.True(init.IsSuccessStatusCode);
        using var list = await host.Post("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        using var result = await ReadRpc(list);
        return result.RootElement.GetProperty("result").GetProperty("tools").Clone();
    }

    [Fact]
    public async Task Stateless_transport_allows_another_initialize_without_session_limits()
    {
        await using var host = await TestHost.StartAsync();
        using var first = await host.Post(Initialize("2025-06-18"));
        Assert.True(first.IsSuccessStatusCode);
        using var second = await host.Post(Initialize("2025-06-18"));
        Assert.True(second.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Stateless_transport_does_not_issue_or_require_session_ids()
    {
        await using var host = await TestHost.StartAsync();
        using var init = await host.Post(Initialize("2025-06-18"));
        Assert.Equal(HttpStatusCode.OK, init.StatusCode);
        Assert.False(init.Headers.Contains("Mcp-Session-Id"));
        host.Client.DefaultRequestHeaders.Add("MCP-Protocol-Version", "2025-06-18");
        host.Client.DefaultRequestHeaders.Add("Mcp-Session-Id", "obsolete-session-from-previous-launch");
        using var list = await host.Post("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        using var result = await ReadRpc(list);
        Assert.True(result.RootElement.GetProperty("result").GetProperty("tools").GetArrayLength() > 0);
    }

    [Theory]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"initialize\"}")]
    [InlineData("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"arguments\":{\"n\":1,\"n\":2}}}")]
    [InlineData("{bad")]
    public async Task Invalid_json_is_rejected_before_dispatch(string json)
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Post(json);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Foreign_origins_and_oversized_requests_are_rejected()
    {
        await using var host = await TestHost.StartAsync();
        host.Client.DefaultRequestHeaders.Add("Origin", "https://example.org");
        using var foreign = await host.Post(Initialize("2025-06-18"));
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        host.Client.DefaultRequestHeaders.Remove("Origin");
        using var oversized = await host.Post(new string('x', 4097));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Unknown_jsonrpc_method_never_reaches_dispatch()
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Post("""{"jsonrpc":"2.0","id":9,"method":"tools/bogus"}""");
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("error", body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Unknown_tool_returns_an_error_without_touching_the_bridge()
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Post(
            """{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"NoSuchTool","arguments":{}}}""");
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("error", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"isError\":false", body);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Tool_call_without_params_is_rejected_before_dispatch()
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Post("""{"jsonrpc":"2.0","id":11,"method":"tools/call"}""");
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("error", body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Get_on_mcp_never_dispatches_to_tools()
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Client.GetAsync("mcp");
        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Wrong_content_type_is_rejected_before_dispatch()
    {
        await using var host = await TestHost.StartAsync();
        using var content = new StringContent(Initialize("2025-06-18"), Encoding.UTF8, "text/plain");
        using var response = await host.Client.PostAsync("mcp", content);
        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Concurrent_burst_of_tool_lists_all_answered_without_bridge_load()
    {
        await using var host = await TestHost.StartAsync();
        var tasks = Enumerable.Range(100, 20).Select(id =>
            host.Post($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/list\"}}"));
        var responses = await Task.WhenAll(tasks);
        try
        {
            foreach (var response in responses)
            {
                using (response)
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadAsStringAsync();
                    Assert.Contains("tools", body);
                }
            }
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Wrong_bearer_tokens_are_rejected_with_a_challenge()
    {
        await using var host = await TestHost.StartAsync();
        using var wrong = new HttpClient { BaseAddress = host.Client.BaseAddress, Timeout = TimeSpan.FromSeconds(5) };
        wrong.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", new string('b', 40));
        using var denied = await wrong.GetAsync("metrics");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Contains(denied.Headers.WwwAuthenticate, value => value.Scheme == "Bearer");
        Assert.Equal(0, host.Bridge.RequestCount);

        await using var guarded = await TestHost.StartAsync(ToolProfile.Comprehensive, requireAuth: true);
        using var shortToken = new HttpClient { BaseAddress = guarded.Client.BaseAddress, Timeout = TimeSpan.FromSeconds(5) };
        shortToken.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "short");
        using var deniedMcp = await shortToken.PostAsync("mcp",
            new StringContent(Initialize("2025-06-18"), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, deniedMcp.StatusCode);
        Assert.Equal(0, guarded.Bridge.RequestCount);
    }

    [Fact]
    public async Task Lean_profile_call_succeeds_over_http_and_hits_the_bridge_once()
    {
        await using var host = await TestHost.StartAsync(ToolProfile.Lean);
        using var call = await host.Post(
            """{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"GetServerStatus","arguments":{}}}""");
        using var result = await ReadRpc(call);
        Assert.False(result.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal(1, host.Bridge.RequestCount);
    }

    [Fact]
    public async Task Post_on_metrics_is_not_routed_to_tools()
    {
        await using var host = await TestHost.StartAsync();
        using var response = await host.Client.PostAsync("metrics",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(0, host.Bridge.RequestCount);
    }

    internal static string Initialize(string protocol) => JsonSerializer.Serialize(new
    {
        jsonrpc = "2.0", id = 1, method = "initialize",
        @params = new { protocolVersion = protocol, capabilities = new { }, clientInfo = new { name = "DBGLink tests", version = "1" } }
    });

    private static async Task<JsonDocument> ReadRpc(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync();
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
            body = body.Split('\n').First(line => line.StartsWith("data: ", StringComparison.Ordinal))[6..];
        return JsonDocument.Parse(body);
    }

    private sealed class TestHost : IAsyncDisposable
    {
        // Valid token68 payload; independent of the Windows-only harness.
        private static readonly string HostBearerToken = new('a', 40);
        public RecordingBridge Bridge { get; } = new();
        public HttpClient Client { get; }
        private readonly LocalMcpServer _server;
        private readonly Task _run;
        private TestHost(int port, ToolProfile profile, bool requireAuth)
        {
            Client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/"), Timeout = TimeSpan.FromSeconds(10) };
            Client.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
            Client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", HostBearerToken);
            _server = new LocalMcpServer(new ServerConfig
            {
                Port = port,
                AuthToken = HostBearerToken,
                MaxRequestBodyBytes = 4096,
                Profile = profile,
                RequireAuthToken = requireAuth,
            }, Bridge);
            _run = _server.RunAsync(CancellationToken.None);
        }
        public static Task<TestHost> StartAsync() => StartAsync(ToolProfile.Comprehensive);

        public static Task<TestHost> StartAsync(ToolProfile profile) => StartAsync(profile, requireAuth: false);

        public static async Task<TestHost> StartAsync(ToolProfile profile, bool requireAuth)
        {
            // Each host binds a real Kestrel socket: take a free port from the
            // allocator and retry on the small probe-to-bind race instead of
            // pinning the contractual default port.
            const int maxAttempts = 5;
            for (var attempt = 1; ; attempt++)
            {
                var port = TestPortAllocator.GetFreePort();
                var host = new TestHost(port, profile, requireAuth);
                try
                {
                    for (var wait = 0; wait < 100; wait++)
                    {
                        if (host._run.IsCompleted) await host._run; // Rethrows bind failures for the retry below.
                        try { using var response = await host.Client.GetAsync("metrics"); if (response.IsSuccessStatusCode) return host; }
                        catch (HttpRequestException) { }
                        await Task.Delay(25);
                    }
                }
                catch (IOException) when (attempt < maxAttempts)
                {
                    // Probe-to-bind race: dispose and retry on a fresh port.
                    // DisposeAsync may rethrow the faulted run task, so guard it here.
                    try { await host.DisposeAsync(); } catch { }
                    continue;
                }
                catch { await host.DisposeAsync(); throw; }
                await host.DisposeAsync();
                throw new TimeoutException("The SDK HTTP host did not start.");
            }
        }
        public Task<HttpResponseMessage> Post(string body) => Client.PostAsync("mcp", new StringContent(body, Encoding.UTF8, "application/json"));
        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            _server.Stop();
            await _run.WaitAsync(TimeSpan.FromSeconds(10));
            _server.Dispose();
        }
    }
}
