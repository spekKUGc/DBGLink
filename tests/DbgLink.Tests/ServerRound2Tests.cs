using System.Text.Json;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Lean real-loopback remainder: LiveAnalysis/static/checkpoint tool paths
/// over a private Harness (own wiring of the shared RealNativePipeServer +
/// RealGhidraServers transports) that have no other owner.
/// Moved out (owners hold the contracts now):
/// - call-stack folding (4 tests) -> AnalysisFormattingAndTruncationTests
/// - GhidraClient status caching -> GhidraClientTests
/// Deleted as duplicates: SessionFallback x2 (owned by SessionFallbackTests).
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ServerRound2Tests
{
    private static ServerConfig TestConfig(string? checkpointPath = null) => new()
    {
        Port = ServerConfig.DefaultPort,
        MaxConcurrentRequests = 16,
        MaxQueuedOperations = 32,
        DefaultToolTimeoutMs = 5_000,
    };

    private sealed class Harness : IAsyncDisposable
    {
        public RealNativePipeServer Pipe { get; }
        public RealGhidraServers Ghidra { get; }
        public LocalMcpServer Server { get; }

        private Harness(RealNativePipeServer pipe, RealGhidraServers ghidra, LocalMcpServer server)
        {
            Pipe = pipe;
            Ghidra = ghidra;
            Server = server;
        }

        public static async Task<Harness> StartAsync(string? checkpointPath = null)
        {
            var pipe = new RealNativePipeServer();
            var ghidra = new RealGhidraServers(pipe.PipeName);
            await Task.Yield();
            var server = new LocalMcpServer(
                TestConfig(checkpointPath),
                new BridgeClient(pipe.PipeName),
                new GhidraClient(ghidra.EndpointDirectory),
                new GhidraControlClient(ghidra.PipeName, ghidra.Token),
                checkpointPath);
            return new Harness(pipe, ghidra, server);
        }

        public async ValueTask DisposeAsync()
        {
            Server.Dispose();
            await Ghidra.DisposeAsync();
            await Pipe.DisposeAsync();
        }
    }

    private static async Task<(bool IsError, string Text)> CallAsync(LocalMcpServer server, string name, string argsJson)
    {
        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\""
            + name + "\",\"arguments\":" + argsJson + "}}";
        var raw = await server.ExecuteTestRequestAsync(body, CancellationToken.None, "2025-06-18");
        Assert.NotNull(raw);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var protocolError))
            return (true, "protocol:" + protocolError.GetRawText());
        var result = root.GetProperty("result");
        if (result.TryGetProperty("error", out _))
            return (true, result.GetRawText());
        if (!result.TryGetProperty("content", out var content))
            return (true, "no-content:" + result.GetRawText());
        var isError = result.TryGetProperty("isError", out var flag) && flag.GetBoolean();
        var text = content[0].GetProperty("text").GetString() ?? "";
        return (isError, text);
    }

    [Fact]
    public async Task TraceUntil_StopAddress_Finishes()
    {
        await using var harness = await Harness.StartAsync();
        var (isError, text) = await CallAsync(harness.Server, "TraceUntil",
            "{\"maxSteps\":10,\"stopAddress\":\"0x140001000\"}");
        Assert.False(isError, text);
        Assert.Contains("0x140001000", text);
    }

    [Fact]
    public async Task Xrefs_ReturnsPayload()
    {
        await using var harness = await Harness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("XrefsFrom", (id, _) =>
            "{\"id\":" + id + ",\"ok\":true,\"result\":{\"xrefs\":[{\"to\":\"0x140002000\",\"type\":\"CALL\"}]}}");
        var (isError, text) = await CallAsync(harness.Server, "Xrefs", "{\"address\":\"0x140001000\",\"direction\":\"from\"}");
        Assert.False(isError, text);
        Assert.Contains("0x140002000", text);
    }

    [Fact]
    public async Task Triage_ClassifiesPayload()
    {
        await using var harness = await Harness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("DumpStrings", (id, _) =>
            "{\"id\":" + id + ",\"ok\":true,\"result\":{\"strings\":[{\"address\":\"0x140002000\",\"value\":\"http://evil.example/command\",\"length\":24},{\"address\":\"0x140002020\",\"value\":\"hello\",\"length\":5}]}}");
        // P3: TriageStrings alias purged; Triage(kind=strings) is the cover.
        var (isError, text) = await CallAsync(harness.Server, "Triage", "{\"kind\":\"strings\",\"section\":\".rdata\"}");
        Assert.False(isError, text);
        Assert.Contains("C2_URL", text);
    }

    [Fact]
    public async Task Checkpoint_ValidationErrors_AreToolErrors()
    {
        await using var harness = await Harness.StartAsync();
        var (missingError, missingText) = await CallAsync(harness.Server, "Checkpoint", "{}");
        Assert.True(missingError);
        Assert.Contains("Checkpoint", missingText);
        var (unknownError, unknownText) = await CallAsync(harness.Server, "Checkpoint",
            "{\"action\":\"restore\",\"sha256\":\"" + new string('b', 64) + "\"}");
        Assert.False(unknownError, unknownText);
        // Unknown sha is a found:false payload, not an error: agents can
        // distinguish "no checkpoint yet" from a failure without parsing text.
        using var checkpoint = JsonDocument.Parse(unknownText);
        Assert.False(checkpoint.RootElement.GetProperty("found").GetBoolean());
    }
}
