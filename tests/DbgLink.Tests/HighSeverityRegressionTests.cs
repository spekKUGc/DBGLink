using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Regression tests for the three HIGH-severity defects found in the code
/// review: the /metrics/ bearer-token bypass, the double BPE token count and
/// the process-wide diff baseline that the reader/writer gate exposed.
/// </summary>
public sealed class HighSeverityRegressionTests
{
    // ---------------------------------------------------------------- H1

    /// <summary>
    /// The token gate used an exact PathString comparison, so "/metrics/"
    /// escaped it while ASP.NET routing still served the endpoint.
    /// </summary>
    [Theory]
    [InlineData("/metrics")]
    [InlineData("/metrics/")]
    public void Metrics_TrailingSlashVariant_RequiresToken(string path)
    {
        var (context, invoked) = Invoke(path, authHeader: null);
        Assert.False(invoked);
        Assert.Equal(401, context.Response.StatusCode);
    }

    // ---------------------------------------------------------------- H2

    /// <summary>
    /// The token count must be computed once per tool call. The sink used to
    /// re-run the BPE pass over the payload, doubling the token cost of every
    /// call on the hot path.
    /// </summary>
    [Fact]
    public void TelemetrySink_LogsTheTokenCountComputedByTheCaller()
    {
        using var dir = TempDir.Create("dbglink-h2-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);

        sink!.LogTool("EvaluateExpressions", "ok", 5, 100, 200, 4242);
        sink.Flush();

        var line = TestFileIO.ReadAllTextRetry(sink.EventsPath).Trim();
        Assert.Contains("tok4242", line);
    }

    /// <summary>
    /// The metrics aggregate and the telemetry line must report the same
    /// token count for one call: the sink no longer counts on its own.
    /// </summary>
    [Fact]
    public void ToolResult_CountsTokensExactlyOnce()
    {
        using var dir = TempDir.Create("dbglink-h2-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;

        const string request = """{"function":"main","maxChars":6000}""";
        const string response = """{"ok":true,"result":{"source":"ghidra-static"}}""";
        var expected = ServerMetrics.CountTokens(request, response, request.Length, response.Length);
        Assert.True(expected > 0, "The payload must produce a non-zero BPE count.");

        metrics.RecordToolResult(
            "EvaluateExpressions", "ok", 5, request.Length, response.Length,
            requestText: request, responseText: response);
        sink.Flush();

        var line = TestFileIO.ReadAllTextRetry(sink.EventsPath).Trim();
        Assert.Contains($"tok{expected}", line);
    }

    // ---------------------------------------------------------------- H3

    /// <summary>
    /// The register diff baseline was process-wide, so a diffOnly snapshot on
    /// one session was compared against another session's baseline and
    /// reported registers of a different target as changed.
    /// </summary>
    [Fact]
    public async Task DiffBaseline_IsIsolatedPerAnalysisSession()
    {
        var bridgeA = new RegisterBridge { Context = "CIP=0x140001000 | RAX=0x111 RBX=0x222 | DISASM: nop | STACK: [00]=0x0" };
        var bridgeB = new RegisterBridge { Context = "CIP=0x140002000 | RAX=0xAAA RBX=0xBBB | DISASM: nop | STACK: [00]=0x0" };
        var context = new AnalysisContext(bridgeA, new NullGhidra());
        var live = new LiveAnalysisTools(context);

        var sessionA = new AnalysisSessionRuntime("session-a", bridgeA, new NullGhidra(), "pipe-a", "C:\\g");
        var sessionB = new AnalysisSessionRuntime("session-b", bridgeB, new NullGhidra(), "pipe-b", "C:\\g");

        var baseline = JsonSerializer.SerializeToElement(new { diffOnly = false, sparseRegisters = false });

        // Both sessions take their first (baseline) snapshot.
        await context.ExecuteAsync(sessionA, () => live.GetAnalysisSnapshotAsync(baseline, CancellationToken.None));
        await context.ExecuteAsync(sessionB, () => live.GetAnalysisSnapshotAsync(baseline, CancellationToken.None));

        // Now diff-only on session B: its registers did not change, so none of
        // them may show up as changed. A shared baseline would have compared
        // session B against session A's values and reported both as changed.
        var diff = JsonSerializer.SerializeToElement(new { diffOnly = true, sparseRegisters = false });
        var responseB = await context.ExecuteAsync(sessionB, () => live.GetAnalysisSnapshotAsync(diff, CancellationToken.None));
        var contextB = AnalysisFormatting.ReadBridgeResultNode(responseB)?["sections"]?["context"]?.GetValue<string>();

        Assert.NotNull(contextB);
        Assert.DoesNotContain("RAX=0xAAA", contextB);
        Assert.DoesNotContain("RBX=0xBBB", contextB);

        // Session A still diffs against its own baseline: unchanged there too.
        var responseA = await context.ExecuteAsync(sessionA, () => live.GetAnalysisSnapshotAsync(diff, CancellationToken.None));
        var contextA = AnalysisFormatting.ReadBridgeResultNode(responseA)?["sections"]?["context"]?.GetValue<string>();

        Assert.NotNull(contextA);
        Assert.DoesNotContain("RAX=0x111", contextA);
        Assert.DoesNotContain("RBX=0x222", contextA);
    }

    /// <summary>
    /// The baseline compare-and-update must be atomic: concurrent diff-only
    /// calls on one session must not interleave and leave a baseline that
    /// mixes registers from different calls.
    /// </summary>
    [Fact]
    public async Task DiffBaseline_ConcurrentCalls_KeepTheBaselineConsistent()
    {
        var bridge = new RegisterBridge { Context = "CIP=0x140001000 | RAX=0x111 RBX=0x222 RCX=0x333 | DISASM: nop | STACK: [00]=0x0" };
        var context = new AnalysisContext(bridge, new NullGhidra());
        var live = new LiveAnalysisTools(context);
        var session = new AnalysisSessionRuntime("session-c", bridge, new NullGhidra(), "pipe-c", "C:\\g");

        var baseline = JsonSerializer.SerializeToElement(new { diffOnly = false, sparseRegisters = false });
        await context.ExecuteAsync(session, () => live.GetAnalysisSnapshotAsync(baseline, CancellationToken.None));

        // Twenty concurrent diff-only polls over the same unchanged state.
        var diff = JsonSerializer.SerializeToElement(new { diffOnly = true, sparseRegisters = false });
        var tasks = Enumerable.Range(0, 20)
            .Select(_ => context.ExecuteAsync(session, () => live.GetAnalysisSnapshotAsync(diff, CancellationToken.None)))
            .ToArray();
        var responses = await Task.WhenAll(tasks);

        // Every poll must agree that nothing changed: a torn baseline would
        // make some of them report a register as changed.
        foreach (var response in responses)
        {
            var node = AnalysisFormatting.ReadBridgeResultNode(response);
            var contextText = node?["sections"]?["context"]?.GetValue<string>();
            Assert.NotNull(contextText);
            Assert.DoesNotContain("RAX=0x111", contextText);
            Assert.DoesNotContain("RBX=0x222", contextText);
            Assert.DoesNotContain("RCX=0x333", contextText);
        }
    }

    // ------------------------------------------------------------ helpers

    private static (DefaultHttpContext Context, bool Invoked) Invoke(string path, string? authHeader)
    {
        var invoked = false;
        var config = new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            AuthToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            RequireAuthToken = true,
        };
        var policy = new McpRequestPolicy(
            next: _ => { invoked = true; return Task.CompletedTask; },
            config,
            new ServerMetrics());
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Host = new HostString("127.0.0.1", ServerConfig.DefaultPort);
        context.Request.Path = new PathString(path);
        if (authHeader is not null)
            context.Request.Headers.Authorization = authHeader;
        policy.InvokeAsync(context).GetAwaiter().GetResult();
        return (context, invoked);
    }

    private sealed class RegisterBridge : IBridgeClient
    {
        public string Context { get; set; } = "CIP=0x140001000 | RAX=0x123 RBX=0x456 | DISASM: nop | STACK: [00]=0x0";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            switch (method)
            {
                case "GetServerStatus":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
                case "GetSnapshotState":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"debugging\":true,\"running\":false,\"stableRead\":true}}");
                case "GetCurrentContext":
                    return Task.FromResult($"{{\"id\":1,\"ok\":true,\"result\":{{\"text\":\"{Context}\"}}}}");
                case "GetCallStack":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"text\":\"Frame 0: 0x140001000 target.exe!main\"}}");
                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }
}
