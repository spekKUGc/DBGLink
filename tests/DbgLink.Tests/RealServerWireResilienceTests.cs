using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;
using ModelContextProtocol;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Tests real-wire resilience, OS-level concurrency, and fault handling with really opened servers:
/// - Real TCP socket limits and connection behavior
/// - Real Win32 Named Pipe message boundaries and connection drops
/// - Concurrency stress over real HTTP sockets and real Win32 Named Pipes
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class RealServerWireResilienceTests
{
    [Fact]
    public async Task RealServer_Handles_10_Concurrent_Clients_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // Fire 10 simultaneous requests from different tasks
        var tasks = Enumerable.Range(0, 10).Select(async i =>
        {
            var res = await harness.CallToolOverWireAsync("ReadMemAtAddress", new
            {
                address = $"0x{0x140001000 + (i * 0x10):X}",
                byteCount = 8
            });
            Assert.False(res.IsError == true);
            Assert.NotNull(res.Content);
        });

        await Task.WhenAll(tasks);

        Assert.True(harness.NativePipeServer.RequestCount >= 10);
    }

    [Fact]
    public async Task RealServer_Propagates_Bridge_Error_Object_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // Configure the real native pipe server to return an error envelope
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, _) =>
            $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":404,\"message\":\"Memory unmapped or inaccessible.\"}}}}");

        var result = await harness.CallToolOverWireAsync("ReadMemAtAddress", new
        {
            address = "0xDEADBEEF",
            byteCount = 4
        });

        // MCP tool should safely return isError = true with error text
        Assert.True(result.IsError == true);
        var text = Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("Memory unmapped", text);
    }

    [Fact]
    public async Task RealServer_Handles_Abrupt_Pipe_Drop_Gracefully()
    {
        await using var harness = await RealServerHarness.StartAsync();

        // Inject fault that abruptly closes the pipe stream upon connection
        harness.NativePipeServer.InjectFault(pipe =>
        {
            pipe.Disconnect();
        });

        // The tool call should fail safely as a tool error without crashing the MCP server
        var result = await harness.CallToolOverWireAsync("ReadMemAtAddress", new
        {
            address = "0x140001000",
            byteCount = 4
        });
        Assert.True(result.IsError == true);
        var text = Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("backend component failed", text);

        // Next request after the fault should work normally over the pipe
        var nextRes = await harness.CallToolOverWireAsync("GetServerStatus");
        Assert.False(nextRes.IsError == true);
    }

    [Fact]
    public async Task RealServer_HTTP_Rejects_Bad_JSON_RPC_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        using var response = await harness.Client.PostAsync("mcp", new StringContent("NOT_VALID_JSON", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RealServer_HTTP_Rejects_Oversized_Request_Over_Wire()
    {
        await using var harness = await RealServerHarness.StartAsync();

        var hugeString = new string('A', 5 * 1024 * 1024); // 5 MB
        using var response = await harness.Client.PostAsync("mcp", new StringContent(hugeString, System.Text.Encoding.UTF8, "application/json"));

        Assert.True(response.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.BadRequest or HttpStatusCode.InternalServerError);
    }
}
