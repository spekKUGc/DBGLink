using DbgLink.Server;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace DbgLink.Tests;

/// <summary>
/// N1 native pipe authentication (.NET server side): the launcher passes
/// <c>--pipe-token</c>, and <see cref="BridgeClient"/> sends it as a
/// top-level <c>"token"</c> on every request envelope. Omitting the token is
/// tolerated only on the explicit legacy/test path (no token configured and
/// no token required).
/// </summary>
[Collection("LiveWire")]
public sealed class NativePipeAuthTests
{
    private const string TestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void ParseCommandLine_defaults_pipe_token_to_null()
    {
        using var scope = PipeTokenEnvironment.Scope(null);

        var options = Program.ParseCommandLine(Array.Empty<string>());

        Assert.Null(options.PipeToken);
    }

    /// <summary>
    /// The pipe token travels in the child's environment, not on the command
    /// line: argv is readable by every local process through
    /// Win32_Process.CommandLine.
    /// </summary>
    [Fact]
    public void ParseCommandLine_reads_pipe_token_from_the_environment()
    {
        using var scope = PipeTokenEnvironment.Scope(TestToken);

        var options = Program.ParseCommandLine(Array.Empty<string>());

        Assert.Equal(TestToken, options.PipeToken);
    }

    /// <summary>
    /// An explicit --pipe-token still wins over the environment, so a manual
    /// run can override the inherited value.
    /// </summary>
    [Fact]
    public void ParseCommandLine_prefers_the_command_line_token_over_the_environment()
    {
        const string other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        using var scope = PipeTokenEnvironment.Scope(TestToken);

        var options = Program.ParseCommandLine(["--pipe-token", other]);

        Assert.Equal(other, options.PipeToken);
    }

    /// <summary>
    /// A blank environment value must not silently disable the token
    /// requirement.
    /// </summary>
    [Fact]
    public void ParseCommandLine_ignores_a_blank_environment_token()
    {
        using var scope = PipeTokenEnvironment.Scope("   ");

        var options = Program.ParseCommandLine(Array.Empty<string>());

        Assert.Null(options.PipeToken);
    }

    [Fact]
    public void ParseCommandLine_reads_pipe_token()
    {
        var options = Program.ParseCommandLine(
            ["--pipe-name", "DbgLink.Control.42", "--pipe-token", TestToken]);

        Assert.Equal("DbgLink.Control.42", options.PipeName);
        Assert.Equal(TestToken, options.PipeToken);
    }

    [Fact]
    public void ParseCommandLine_rejects_duplicate_pipe_token()
    {
        Assert.Throws<ArgumentException>(() =>
            Program.ParseCommandLine(["--pipe-token", TestToken, "--pipe-token", TestToken]));
    }

    [Fact]
    public void ParseCommandLine_rejects_missing_pipe_token_value()
    {
        Assert.Throws<ArgumentException>(() => Program.ParseCommandLine(["--pipe-token"]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("has\0control")]
    public void BridgeClient_rejects_invalid_pipe_tokens(string token)
    {
        Assert.Throws<ArgumentException>(() => new BridgeClient("DbgLink.Control.42", token));
    }

    [Fact]
    public void BridgeClient_rejects_oversized_pipe_token()
    {
        Assert.Throws<ArgumentException>(() => new BridgeClient("DbgLink.Control.42", new string('a', 257)));
    }

    [Fact]
    public void BridgeClient_exposes_the_configured_token()
    {
        using var client = new BridgeClient("DbgLink.Control.42", TestToken, requirePipeToken: true);

        Assert.Equal(TestToken, client.PipeToken);
        Assert.True(client.RequiresPipeToken);
    }

    [Fact]
    public async Task Request_envelope_contains_the_configured_token()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, int.MaxValue);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        using var client = new BridgeClient(pipeName, TestToken);
        var requestTask = client.RequestAsync(
            "ReadMemAtAddress",
            JsonSerializer.SerializeToElement(new { address = "0x140001000" }),
            timeout.Token);
        await server.WaitForConnectionAsync(timeout.Token);
        using var request = JsonDocument.Parse(await ReadMessageAsync(server, timeout.Token));
        var id = request.RootElement.GetProperty("id").GetInt32();
        await WriteLineAsync(server, $"{{\"id\":{id},\"ok\":true,\"result\":{{}}}}", timeout.Token);
        await requestTask;

        Assert.Equal("ReadMemAtAddress", request.RootElement.GetProperty("method").GetString());
        Assert.Equal(TestToken, request.RootElement.GetProperty("token").GetString());
        Assert.Equal("0x140001000", request.RootElement.GetProperty("params").GetProperty("address").GetString());
    }

    [Fact]
    public async Task Request_envelope_omits_the_token_on_the_legacy_path()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, int.MaxValue);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        using var client = new BridgeClient(pipeName);
        var requestTask = client.RequestAsync("ping", timeout.Token);
        await server.WaitForConnectionAsync(timeout.Token);
        using var request = JsonDocument.Parse(await ReadMessageAsync(server, timeout.Token));
        var id = request.RootElement.GetProperty("id").GetInt32();
        await WriteLineAsync(
            server,
            $"{{\"id\":{id},\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":{Environment.ProcessId},\"debugging\":false}}",
            timeout.Token);
        var response = await requestTask;

        Assert.Contains("\"ok\":true", response);
        Assert.False(request.RootElement.TryGetProperty("token", out _));
    }

    [Fact]
    public async Task Request_without_a_required_token_fails_closed_before_pipe_io()
    {
        // No pipe server listens here: failing closed must happen before any
        // transport attempt, so a transport error would mean the gate moved.
        using var client = new BridgeClient(
            "DbgLink.Control." + Random.Shared.Next(1, int.MaxValue),
            requirePipeToken: true);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.RequestAsync("ping", CancellationToken.None));

        Assert.Contains("--pipe-token", exception.Message);
    }

    [Fact]
    public async Task Server_sends_the_cli_token_to_the_native_bridge()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, int.MaxValue);
        var configPath = Path.Combine(Path.GetTempPath(), "dbglink-pipeauth-" + Guid.NewGuid().ToString("N") + ".json");
        var port = TestPortAllocator.GetFreePort();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        Task<int>? run = null;
        try
        {
            await using var pipe = new NamedPipeServerStream(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            run = Program.RunAsync(
                ["--pipe-name", pipeName, "--pipe-token", TestToken, "--port", port.ToString(), "--config-path", configPath],
                stop.Token);
            await pipe.WaitForConnectionAsync(deadline.Token);
            using var request = JsonDocument.Parse(await ReadMessageAsync(pipe, deadline.Token));

            Assert.Equal("ping", request.RootElement.GetProperty("method").GetString());
            Assert.Equal(TestToken, request.RootElement.GetProperty("token").GetString());

            var id = request.RootElement.GetProperty("id").GetInt32();
            await WriteLineAsync(
                pipe,
                $"{{\"id\":{id},\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":{Environment.ProcessId},\"debugging\":false}}",
                deadline.Token);
            // The startup ping above already proved CLI -> BridgeClient
            // plumbing; shut down before serving further bridge traffic.
            stop.Cancel();
            Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(10), deadline.Token));
        }
        finally
        {
            stop.Cancel();
            if (run is not null)
            {
                try { await run.WaitAsync(TimeSpan.FromSeconds(10)); } catch { }
            }
            try { File.Delete(configPath); } catch { }
        }
    }

    [Theory]
    [InlineData("DbgLink.Control.1234.abcdef12", true)]
    [InlineData("DbgLink.Control.1.00000000", true)]
    [InlineData("DbgLink.Control.42.ABCDEF12", true)]
    [InlineData("DbgLink.Control.1234.abc", true)]
    [InlineData("DbgLink.Control.1234.", false)]
    [InlineData("DbgLink.Control.1234.xyz", false)]
    [InlineData("DbgLink.Control..abcdef12", false)]
    [InlineData("DbgLink.Control.0.abcdef12", false)]
    [InlineData("DbgLink.Control.01.abcdef12", false)]
    [InlineData("DbgLink.Control.1.2.3", false)]
    public void NativePipeNamePolicy_accepts_the_n1_suffixed_form(string? pipeName, bool expectedValid)
    {
        Assert.Equal(expectedValid, NativePipeNamePolicy.IsValid(pipeName));
    }

    private static async Task<string> ReadMessageAsync(NamedPipeServerStream server, CancellationToken token)
    {
        var buffer = new byte[65536];
        using var message = new MemoryStream();
        int read;
        do
        {
            read = await server.ReadAsync(buffer, token);
            if (read == 0)
                break;
            message.Write(buffer, 0, read);
        }
        while (!server.IsMessageComplete);
        return Encoding.UTF8.GetString(message.ToArray()).Trim();
    }

    private static async Task WriteLineAsync(NamedPipeServerStream server, string text, CancellationToken token)
    {
        var bytes = Encoding.UTF8.GetBytes(text + "\n");
        await server.WriteAsync(bytes, token);
        await server.FlushAsync(token);
    }
}
