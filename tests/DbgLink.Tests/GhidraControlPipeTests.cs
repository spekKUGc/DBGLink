using System.ComponentModel;
using System.Text;
using System.Runtime.Versioning;
using DbgLink.Launcher.Core;

namespace DbgLink.Tests;

[SupportedOSPlatform("windows")]
public sealed class GhidraControlPipeTests
{
    [Theory]
    [InlineData("DbgLink.GhidraControl.")]
    [InlineData("DbgLink.GhidraControl.\0session")]
    public void Constructor_rejects_an_invalid_control_pipe_name(string pipeName)
    {
        Assert.Throws<ArgumentException>(() =>
            new GhidraControlPipeServer(
                pipeName,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                (_, _) => Task.FromResult(new GhidraOpenResult(true, "target.dll", true))));
    }

    [Fact]
    public async Task ReadBoundedLine_requires_a_newline_terminator()
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"id\":1}"));

        var result = await GhidraControlPipeServer.ReadBoundedLineAsync(stream, CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task ReadBoundedLine_rejects_data_after_the_first_frame()
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"id\":1}\nextra"));

        var result = await GhidraControlPipeServer.ReadBoundedLineAsync(stream, CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task ReadBoundedLine_accepts_one_complete_frame()
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"id\":1}\r\n"));

        var result = await GhidraControlPipeServer.ReadBoundedLineAsync(stream, CancellationToken.None);

        Assert.Equal("{\"id\":1}", result);
    }

    [Fact]
    public async Task DisposeAsync_is_idempotent()
    {
        var server = CreateServer((_, _) =>
            Task.FromResult(new GhidraOpenResult(true, "target.dll", true)));

        await server.DisposeAsync();
        await server.DisposeAsync();

        // A disposed server must stay disposed: starting again is rejected
        // instead of silently reviving the pipe.
        Assert.Throws<ObjectDisposedException>(server.Start);
    }

    [Fact]
    public async Task Start_after_dispose_is_rejected()
    {
        var server = CreateServer((_, _) =>
            Task.FromResult(new GhidraOpenResult(true, "target.dll", true)));

        await server.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(server.Start);
    }

    [Fact]
    public async Task Start_surfaces_a_pipe_creation_failure()
    {
        var pipeName = "DbgLink.GhidraControl." + Guid.NewGuid().ToString("N");
        var first = CreateServer(
            (_, _) => Task.FromResult(new GhidraOpenResult(true, "target.dll", true)),
            pipeName);
        var second = CreateServer(
            (_, _) => Task.FromResult(new GhidraOpenResult(true, "target.dll", true)),
            pipeName);
        try
        {
            first.Start();

            var exception = Record.Exception(second.Start);
            Assert.NotNull(exception);
            Assert.True(exception is IOException or UnauthorizedAccessException);
        }
        finally
        {
            await second.DisposeAsync();
            await first.DisposeAsync();
        }
    }

    [Fact]
    public async Task Dispatch_rejects_duplicate_properties_without_invoking_handler()
    {
        var invocationCount = 0;
        await using var server = CreateServer((_, _) =>
        {
            Interlocked.Increment(ref invocationCount);
            return Task.FromResult(new GhidraOpenResult(true, "target.dll", true));
        });

        var response = await server.DispatchAsync(
            "{\"id\":1,\"id\":2,\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}",
            CancellationToken.None);

        Assert.Contains("duplicate properties", response);
        Assert.Equal(0, invocationCount);
    }

    [Theory]
    [InlineData("{\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}")]
    [InlineData("{\"id\":\"1\",\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}")]
    public async Task Dispatch_rejects_missing_or_non_integer_id(string request)
    {
        var invocationCount = 0;
        await using var server = CreateServer((_, _) =>
        {
            Interlocked.Increment(ref invocationCount);
            return Task.FromResult(new GhidraOpenResult(true, "target.dll", true));
        });

        var response = await server.DispatchAsync(request, CancellationToken.None);

        Assert.Contains("integer id", response);
        Assert.Equal(0, invocationCount);
    }

    [Fact]
    public async Task Dispatch_converts_win32_open_failures_to_an_error_response()
    {
        await using var server = CreateServer((_, _) =>
            Task.FromException<GhidraOpenResult>(new Win32Exception(5)));

        var response = await server.DispatchAsync(
            "{\"id\":1,\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}",
            CancellationToken.None);

        Assert.Contains("ghidra_open_failed", response);
    }

    [Fact]
    public async Task Dispatch_converts_unexpected_open_failures_to_an_error_response()
    {
        await using var server = CreateServer((_, _) =>
            Task.FromException<GhidraOpenResult>(new Exception("unexpected")));

        var response = await server.DispatchAsync(
            "{\"id\":7,\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}",
            CancellationToken.None);

        Assert.Contains("\"id\":7", response);
        Assert.Contains("ghidra_open_failed", response);
    }

    [Fact]
    public async Task Dispatch_surfaces_session_capacity_as_a_specific_error()
    {
        await using var server = CreateServer((_, _) =>
            Task.FromException<GhidraOpenResult>(new InvalidOperationException(
                "The maximum number of parallel analysis sessions has been reached.")));

        var response = await server.DispatchAsync(
            "{\"id\":1,\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}",
            CancellationToken.None);

        Assert.Contains("session_capacity_reached", response);
        Assert.DoesNotContain("ghidra_open_failed", response);
    }

    [Fact]
    public async Task Dispatch_keeps_generic_open_failure_for_other_invalid_operations()
    {
        await using var server = CreateServer((_, _) =>
            Task.FromException<GhidraOpenResult>(new InvalidOperationException("boom")));

        var response = await server.DispatchAsync(
            "{\"id\":1,\"method\":\"OpenGhidraFile\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"C:\\\\target.dll\"}",
            CancellationToken.None);

        Assert.Contains("ghidra_open_failed", response);
        Assert.DoesNotContain("session_capacity_reached", response);
    }

    [Fact]
    public async Task Fast_import_mode_reaches_handler()
    {
        bool? received = null;
        await using var server = new GhidraControlPipeServer(
            "DbgLink.GhidraControl.test", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            (_, _) => throw new InvalidOperationException("Wrong handler"))
        {
            OpenWithAnalysisMode = (_, analyze, _) =>
            {
                received = analyze;
                return Task.FromResult(new GhidraOpenResult(true, "target.dll", true));
            }
        };
        var response = await server.DispatchAsync(System.Text.Json.JsonSerializer.Serialize(new
        {
            id = 1, method = "OpenGhidraFile", token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            path = "C:/target.dll", analyze = false
        }), CancellationToken.None);
        Assert.False(received);
        Assert.Contains("\"ok\":true", response);
    }

    [Fact]
    public async Task Disconnect_cancels_active_import()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = CreateServer(async (_, token) =>
        {
            started.SetResult();
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { if (token.IsCancellationRequested) cancelled.TrySetResult(); }
            return new GhidraOpenResult(true, "target.dll", true);
        }, "DbgLink.GhidraControl." + Guid.NewGuid().ToString("N"));
        server.Start();
        using var timeout = new CancellationTokenSource(5000);
        await using (var client = new System.IO.Pipes.NamedPipeClientStream(".", server.PipeName,
            System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(timeout.Token);
            var request = System.Text.Json.JsonSerializer.Serialize(new
            {
                id = 1, method = "OpenGhidraFile", token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", path = "C:/target.dll"
            }) + "\n";
            await client.WriteAsync(Encoding.UTF8.GetBytes(request), timeout.Token);
            await client.FlushAsync(timeout.Token);
            await started.Task.WaitAsync(timeout.Token);
        }
        await cancelled.Task.WaitAsync(timeout.Token);
    }

    private static GhidraControlPipeServer CreateServer(
        Func<string, CancellationToken, Task<GhidraOpenResult>> handler,
        string pipeName = "DbgLink.GhidraControl.test")
        => new(
            pipeName,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            handler);
}
