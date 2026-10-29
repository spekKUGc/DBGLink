using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// Real cl100k_base telemetry tokens only: every tok number comes from the
/// BPE path (TokenMeter); sides without payload text contribute 0 — there
/// is no heuristic fallback. Expected BPE values below are hard-pinned
/// (same encoding as the test-side TokenCounter).
/// </summary>
public sealed class TelemetryTokenMeterTests
{
    // Small realistic payloads. cl100k_base: req 11 tok (heu 10),
    // resp 14 tok (heu 13), total BPE 25 vs heuristic 22.
    private const string Req = """{"function":"main","maxChars":6000}""";
    private const string Resp = """{"ok":true,"result":{"source":"ghidra-static"}}""";

    [Fact]
    public void BpePath_UsesRealTokenizerWhenTextPresent()
    {
        // Hard pins: these exact cl100k_base counts prove the BPE path.
        Assert.Equal(11, TokenCounter.Count(Req));
        Assert.Equal(14, TokenCounter.Count(Resp));
        Assert.Equal(2, TokenCounter.Count("hello world"));

        var got = TokenMeter.CountCall(Req, Resp, Req.Length, Resp.Length);
        Assert.Equal(25, got);
        // Same seam the production call sites use.
        Assert.Equal(got, ServerMetrics.CountTokens(Req, Resp, Req.Length, Resp.Length));
    }

    [Fact]
    public void NoText_NoTokens_NoHeuristic()
    {
        // Byte-only callers contribute 0 per side without text: no estimation.
        Assert.Equal(0, TokenMeter.CountCall(null, null, 100, 274));
        Assert.Equal(0, TokenMeter.CountCall(null, null, 0, 0));
        Assert.Equal(0, TokenMeter.CountCall("", "", 0, 0));
        // Empty text means "unavailable" for that side.
        Assert.Equal(0, TokenMeter.CountCall("", null, 100, 274));
        // One-sided: BPE for the available side, 0 for the other.
        Assert.Equal(11, TokenMeter.CountCall(Req, null, Req.Length, 274));
        Assert.Equal(14, TokenMeter.CountCall(null, Resp, 100, Resp.Length));
    }

    [Fact]
    public void Cap_HugePayloadDropsTailInsteadOfEstimating()
    {
        var big = new string('x', 300_000);
        var got = TokenMeter.CountCall(big, null, big.Length, 0);
        // Over the cap only the BPE prefix counts; the tail is dropped.
        var expect = TokenCounter.Count(big.Substring(0, TokenMeter.MaxCharsToTokenize));
        Assert.Equal(expect, got);
        // The cap keeps it far below a full BPE run's cost yet above zero.
        Assert.True(got > 0);
    }

    [Fact]
    public void Concurrent_CountCallIsThreadSafe()
    {
        var results = new long[64];
        Parallel.For(0, results.Length, i =>
            results[i] = TokenMeter.CountCall(Req, Resp, Req.Length, Resp.Length));
        Assert.All(results, r => Assert.Equal(25, r));
    }

    [Fact]
    public void ToolMetrics_RealTokensPerToolAndSummary()
    {
        var metrics = new ServerMetrics();
        metrics.RecordToolResult("ProbeTool", "ok", 1, Req.Length, Resp.Length,
            requestText: Req, responseText: Resp);
        var tools = metrics.Snapshot()["tools"] as JsonObject;
        Assert.Equal(25L, (tools!["ProbeTool"] as JsonObject)!["totalTokens"]?.GetValue<long>());

        var summary = metrics.Snapshot()["toolsSummary"] as JsonObject;
        var top = summary!["topLargestTotal"] as JsonArray;
        var row = top!.OfType<JsonObject>().Single(r => r["tool"]?.GetValue<string>() == "ProbeTool");
        Assert.Equal(25L, row["totalTokens"]?.GetValue<long>());

        // Byte-only callers (no payload text) accumulate 0 — never an estimate.
        metrics.RecordToolResult("ByteTool", "ok", 1, 100, 274);
        tools = metrics.Snapshot()["tools"] as JsonObject;
        Assert.Equal(0L,
            (tools!["ByteTool"] as JsonObject)!["totalTokens"]?.GetValue<long>());
    }

    [Fact]
    public void Functions_RealTokensSplitEvenly()
    {
        var metrics = new ServerMetrics();
        metrics.RecordToolResult("AnalyzeFunctions", "ok", 5, Req.Length, Resp.Length,
            functions: ["a", "b"], requestText: Req, responseText: Resp);
        var fns = metrics.Snapshot()["functions"] as JsonObject;
        Assert.NotNull(fns);
        var a = (fns!["a"] as JsonObject)!["tokens"]?.GetValue<long>() ?? -1;
        var b = (fns["b"] as JsonObject)!["tokens"]?.GetValue<long>() ?? -1;
        Assert.Equal(25, a + b);
    }

    [Fact]
    public void Digest_BigTotalPrefersRealTokens()
    {
        using var dir = TempDir.Create("dbglink-tokmeter-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        metrics.RecordToolResult("ProbeTool", "ok", 1, Req.Length, Resp.Length,
            requestText: Req, responseText: Resp);
        metrics.RecordToolResult("ProbeTool", "ok", 1, Req.Length, Resp.Length,
            requestText: Req, responseText: Resp);
        sink!.Flush();
        sink.WriteDigest();

        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        // 2 x 25 real tokens.
        Assert.Contains($"ProbeTool out{Resp.Length * 2}B in{Req.Length * 2}B tok50 x2", digest);
        // No cross-process lifetime line: the digest is per-process only.
        Assert.DoesNotContain("lifetime:", digest);
        Assert.DoesNotContain("cumulative.json", digest);
    }
}
