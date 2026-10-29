using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// Orchestrates a fully live test cluster where:
/// 1. A real Win32 message-mode Named Pipe server runs the native bridge.
/// 2. A real Ghidra control pipe server and real Ghidra TCP server run.
/// 3. A real Kestrel HTTP LocalMcpServer runs on a real TCP port.
/// 4. An HttpClient executes actual HTTP JSON-RPC POST requests to /mcp.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RealServerHarness : IAsyncDisposable
{
    // Valid token68 payload (32..512 chars) required by the /metrics gate.
    internal static readonly string TestBearerToken = new('a', 40);
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);
    private readonly string _checkpointDir;
    private readonly string _checkpointPath;
    private readonly Task _serverRunTask;
    private readonly LocalMcpServer _mcpServer;
    private readonly BridgeClient _bridgeClient;
    private int _rpcId;

    public RealNativePipeServer NativePipeServer { get; }
    public RealGhidraServers Ghidra { get; }
    public HttpClient Client { get; }
    public int Port { get; }

    private RealServerHarness(
        int port,
        RealNativePipeServer nativePipeServer,
        RealGhidraServers ghidra,
        string checkpointDir,
        string checkpointPath,
        BridgeClient bridgeClient,
        LocalMcpServer mcpServer,
        HttpClient client,
        Task serverRunTask)
    {
        Port = port;
        NativePipeServer = nativePipeServer;
        Ghidra = ghidra;
        _checkpointDir = checkpointDir;
        _checkpointPath = checkpointPath;
        _bridgeClient = bridgeClient;
        _mcpServer = mcpServer;
        Client = client;
        _serverRunTask = serverRunTask;
    }

    public static async Task<RealServerHarness> StartAsync(bool allowMutation = true)
    {
        // Each host binds a real Kestrel socket: take a free port from the
        // allocator and retry on the small probe-to-bind race instead of
        // pinning the contractual default port.
        const int maxAttempts = 5;
        for (var attempt = 1; ; attempt++)
        {
            var port = TestPortAllocator.GetFreePort();

            // 2. Start real Win32 Named Pipe server
            var nativePipe = new RealNativePipeServer();

            // 3. Start real Ghidra servers (Named Pipe + TCP)
            var ghidra = new RealGhidraServers(nativePipe.PipeName);

        // 4. Create clients
        var bridgeClient = new BridgeClient(nativePipe.PipeName);
        var ghidraControlClient = new GhidraControlClient(ghidra.PipeName, ghidra.Token);
        var ghidraClient = new GhidraClient(ghidra.EndpointDirectory);

        var checkpointDir = Path.Combine(Path.GetTempPath(), "dbglink_harness_chkpt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(checkpointDir);
        var checkpointPath = Path.Combine(checkpointDir, "checkpoint.json");

        var config = new ServerConfig
        {
            Port = port,
            // /metrics requires this token; the harness client sends it too.
            AuthToken = TestBearerToken,
            AllowMutation = allowMutation,
            GhidraControlPipeName = ghidra.PipeName,
            GhidraControlToken = ghidra.Token,
            DefaultToolTimeoutMs = 15_000,
            MaxConcurrentRequests = 16,
            MaxQueuedOperations = 32
        };

        var mcpServer = new LocalMcpServer(
            config,
            bridgeClient,
            ghidraClient,
            ghidraControlClient,
            checkpointPath);

        var serverRunTask = mcpServer.RunAsync(CancellationToken.None);

        var client = new HttpClient
        {
            BaseAddress = new Uri($"http://127.0.0.1:{port}/"),
            Timeout = TimeSpan.FromSeconds(15)
        };
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
        client.DefaultRequestHeaders.Add("MCP-Protocol-Version", "2025-06-18");
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", TestBearerToken);

        var harness = new RealServerHarness(
            port,
            nativePipe,
            ghidra,
            checkpointDir,
            checkpointPath,
            bridgeClient,
            mcpServer,
            client,
            serverRunTask);

        // Wait for Kestrel server to be up and running via /metrics endpoint
        try
        {
            for (var attemptLoop = 0; attemptLoop < 100; attemptLoop++)
            {
                if (serverRunTask.IsCompleted)
                    await serverRunTask; // Rethrows startup (e.g. bind) failures for the retry below.

                try
                {
                    using var response = await client.GetAsync("metrics");
                    if (response.IsSuccessStatusCode)
                        return harness;
                }
                catch (HttpRequestException) { }

                await Task.Delay(25);
            }
        }
        catch (IOException) when (attempt < maxAttempts)
        {
            // Probe-to-bind race: Kestrel lost the port between allocation and
            // listen. Dispose this host and retry on a fresh port.
            await harness.DisposeAsync();
            continue;
        }

        await harness.DisposeAsync();
        throw new TimeoutException($"The real Kestrel MCP server on port {port} failed to start within the timeout.");
        }
    }

    public async Task<JsonDocument> PostRpcAsync(string jsonRpc)
    {
        using var content = new StringContent(jsonRpc, Encoding.UTF8, "application/json");
        using var response = await Client.PostAsync("mcp", content);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync();
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
        {
            var dataLine = body.Split('\n').First(l => l.StartsWith("data: ", StringComparison.Ordinal));
            body = dataLine[6..];
        }

        return JsonDocument.Parse(body);
    }

    public async Task<JsonDocument> CallToolRawAsync(string toolName, object? arguments = null)
    {
        var id = Interlocked.Increment(ref _rpcId);
        var rpc = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id,
            method = "tools/call",
            @params = new
            {
                name = toolName,
                arguments = arguments ?? new { }
            }
        });

        return await PostRpcAsync(rpc);
    }

    public async Task<CallToolResult> CallToolOverWireAsync(string toolName, object? arguments = null)
    {
        using var doc = await CallToolRawAsync(toolName, arguments);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var error))
        {
            var code = error.GetProperty("code").GetInt32();
            var msg = error.GetProperty("message").GetString() ?? "";
            throw new McpProtocolException(msg, (McpErrorCode)code);
        }

        var resultElement = root.GetProperty("result");
        return JsonSerializer.Deserialize<CallToolResult>(resultElement.GetRawText(), JsonWeb)!;
    }

    public async Task<List<Tool>> ListToolsOverWireAsync()
    {
        var id = Interlocked.Increment(ref _rpcId);
        var rpc = $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/list\"}}";
        using var doc = await PostRpcAsync(rpc);
        var toolsElement = doc.RootElement.GetProperty("result").GetProperty("tools");
        return JsonSerializer.Deserialize<List<Tool>>(toolsElement.GetRawText(), JsonWeb)!;
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        _mcpServer.Stop();
        try { await _serverRunTask.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        _mcpServer.Dispose();
        _bridgeClient.Dispose();
        await Ghidra.DisposeAsync();
        await NativePipeServer.DisposeAsync();

        try
        {
            if (Directory.Exists(_checkpointDir))
                Directory.Delete(_checkpointDir, true);
        }
        catch { }
    }
}
