using DbgLink.Server;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace DbgLink.Tests;

[Collection("LiveWire")]
public sealed class BridgeClientTests
{
    [Fact]
    public async Task Request_sends_json_and_delimiter_in_one_pipe_message()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, int.MaxValue);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        using var client = new BridgeClient(pipeName);
        var requestTask = client.RequestAsync("ping", timeout.Token);
        var connectionTask = server.WaitForConnectionAsync(timeout.Token);
        // Surface an early client failure instead of masking it with the server timeout.
        if (await Task.WhenAny(requestTask, connectionTask) == requestTask)
            await requestTask;
        await connectionTask;
        var bytes = new byte[4096];
        var count = await server.ReadAsync(bytes, timeout.Token);
        var request = Encoding.UTF8.GetString(bytes, 0, count);
        var completeMessage = server.IsMessageComplete;
        using var document = JsonDocument.Parse(request);
        var id = document.RootElement.GetProperty("id").GetInt32();
        await server.WriteAsync(Encoding.UTF8.GetBytes($"{{\"id\":{id},\"ok\":true}}\n"), timeout.Token);
        await requestTask;

        Assert.True(completeMessage);
        Assert.EndsWith("\n", request);
        Assert.Equal("ping", document.RootElement.GetProperty("method").GetString());
    }

    [Fact]
    public void IsHealthyPingResponse_accepts_the_native_contract()
    {
        Assert.True(BridgeClient.IsHealthyPingResponse(
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":42,\"debugging\":false}"));
    }

    [Fact]
    public void IsHealthyPingResponse_rejects_duplicate_properties()
    {
        Assert.False(BridgeClient.IsHealthyPingResponse(
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"plugin\":\"other\",\"bridge\":\"native\",\"pid\":42,\"debugging\":false}"));
    }

    [Fact]
    public void IsHealthyPingResponse_rejects_a_string_pid()
    {
        Assert.False(BridgeClient.IsHealthyPingResponse(
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":\"42\",\"debugging\":false}"));
    }

    [Fact]
    public void ValidateResponse_rejects_a_non_object_error()
    {
        Assert.Throws<InvalidDataException>(() => BridgeClient.ValidateResponse(
            "{\"id\":7,\"ok\":false,\"error\":null}",
            expectedId: 7));
    }
}
