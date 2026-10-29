using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

[Collection("LiveWire")]
public sealed class ServerLifetimeTests
{
    [Fact]
    public async Task Http_endpoint_survives_loss_of_startup_debugger_and_bridge_can_reconnect()
    {
        if (!OperatingSystem.IsWindows()) return;

        // A dead PID models the initial debugger after an architecture switch.
        using var exited = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0")
        {
            UseShellExecute = false, CreateNoWindow = true
        })!;
        await exited.WaitForExitAsync();
        var pipeName = "DbgLink.Control." + exited.Id;
        // Generous deadline: this spawns a real server + pipe and reconnects;
        // a loaded parallel test host must not trip a tight 25s budget.
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        var configPath = Path.Combine(Path.GetTempPath(), "dbglink-lifetime-" + Guid.NewGuid() + ".json");
        var port = TestPortAllocator.GetFreePort();
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/"), Timeout = TimeSpan.FromSeconds(5) };
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
        Task<int>? run = null;
        try
        {
            var handshake = ReplyOnce(pipeName, "ping", deadline.Token);
            run = Program.RunAsync(["--pipe-name", pipeName, "--port", port.ToString(), "--config-path", configPath], stop.Token);
            await handshake;
            await WaitForHttp(http, run, configPath, deadline.Token);

            // The former watchdog exited after 2 seconds plus a 1.5 second pipe timeout.
            await Task.Delay(TimeSpan.FromSeconds(5), deadline.Token);
            Assert.False(run.IsCompleted, "Losing the startup debugger must not terminate the MCP host.");
            using var list = await Post(http, "tools/list", null, deadline.Token);
            Assert.True(list.RootElement.GetProperty("result").GetProperty("tools").GetArrayLength() > 0);
            using var unavailable = await Post(http, "tools/call", new { name = "GetServerStatus", arguments = new { } }, deadline.Token);
            Assert.True(unavailable.RootElement.TryGetProperty("error", out _) ||
                unavailable.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());

            var recovered = ReplyOnce(pipeName, "GetServerStatus", deadline.Token);
            using var status = await Post(http, "tools/call", new { name = "GetServerStatus", arguments = new { } }, deadline.Token);
            await recovered;
            Assert.False(status.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
            Assert.False(run.IsCompleted);
        }
        finally
        {
            stop.Cancel();
            if (run is not null) await run.WaitAsync(TimeSpan.FromSeconds(10));
            File.Delete(configPath);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task ReplyOnce(string pipeName, string method, CancellationToken token)
    {
        await using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        await pipe.WaitForConnectionAsync(token);
        var bytes = new byte[4096];
        var length = await pipe.ReadAsync(bytes, token);
        using var request = JsonDocument.Parse(bytes.AsMemory(0, length));
        Assert.Equal(method, request.RootElement.GetProperty("method").GetString());
        var response = JsonSerializer.Serialize(new
        {
            id = request.RootElement.GetProperty("id").GetInt32(), ok = true,
            plugin = "DBGLink", bridge = "native", pid = Environment.ProcessId, debugging = false
        }) + "\n";
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(response), token);
        await pipe.FlushAsync(token);
    }

    private static async Task WaitForHttp(HttpClient http, Task run, string configPath, CancellationToken token)
    {
        while (true)
        {
            Assert.False(run.IsCompleted);
            try
            {
                // The server persists its config (including the bearer token)
                // before it starts listening; /metrics requires the header.
                if (http.DefaultRequestHeaders.Authorization is null && File.Exists(configPath))
                {
                    var document = JsonDocument.Parse(await File.ReadAllTextAsync(configPath, token));
                    var authToken = document.RootElement.GetProperty("AuthToken").GetString();
                    http.DefaultRequestHeaders.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);
                }
                using var response = await http.GetAsync("metrics", token);
                if (response.IsSuccessStatusCode) return;
            }
            catch (Exception exception) when (exception is HttpRequestException or JsonException
                or KeyNotFoundException or IOException or InvalidOperationException)
            {
                // The config file may still be mid-write; retry.
            }
            await Task.Delay(25, token);
        }
    }

    private static async Task<JsonDocument> Post(HttpClient http, string method, object? args, CancellationToken token)
    {
        using var content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method, @params = args }), Encoding.UTF8, "application/json");
        using var response = await http.PostAsync("mcp", content, token);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(token);
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
            body = body.Split('\n').First(line => line.StartsWith("data: ", StringComparison.Ordinal))[6..];
        return JsonDocument.Parse(body);
    }
}
