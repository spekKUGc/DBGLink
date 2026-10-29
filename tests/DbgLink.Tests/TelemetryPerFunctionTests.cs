using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>w06: per-function telemetry — selector extraction, sanitizing,
/// counters (calls/tokens/errors) and digest top-5.</summary>
public sealed class TelemetryPerFunctionTests
{
    private static JsonElement? Elem(string json)
        => JsonSerializer.SerializeToElement(JsonNode.Parse(json)!.AsObject());

    [Fact]
    public void Extract_Inspect_SingleSelector()
    {
        var inspect = ServerMetrics.ExtractFunctionSelectors("InspectFunction", Elem("""{"function":"main"}"""));
        Assert.Equal(["main"], inspect);
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("InspectFunction", Elem("""{}""")));
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("ListFunctions", Elem("""{"function":"main"}""")));
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("InspectFunction", null));
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors(null, Elem("""{"function":"main"}""")));
    }

    [Fact]
    public void Extract_InvestigationBrief_FunctionOrFunctions()
    {
        var solo = ServerMetrics.ExtractFunctionSelectors("GetInvestigationBrief", Elem("""{"function":"main"}"""));
        Assert.Equal(["main"], solo);
        var batch = ServerMetrics.ExtractFunctionSelectors("GetInvestigationBrief", Elem("""{"functions":["main","helper"]}"""));
        Assert.Equal(["main", "helper"], batch);
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("GetInvestigationBrief", Elem("""{}""")));
    }

    [Fact]
    public void Extract_Analyze_ArrayPlusStart_DedupAndCap()
    {
        var args = Elem("""{"functions":["main","0x140001040","main"],"start":"helper"}""");
        Assert.Equal(["main", "0x140001040", "helper"],
            ServerMetrics.ExtractFunctionSelectors("AnalyzeFunctions", args));
        // start-only slice mode.
        Assert.Equal(["entry"],
            ServerMetrics.ExtractFunctionSelectors("AnalyzeFunctions", Elem("""{"start":"entry"}""")));
        // Cap at 16 selectors per call.
        var many = "[" + string.Join(",", Enumerable.Range(0, 20).Select(i => $"\"f{i}\"")) + "]";
        var capped = ServerMetrics.ExtractFunctionSelectors("AnalyzeFunctions", Elem($"{{\"functions\":{many}}}"));
        Assert.Equal(16, capped.Count);
    }

    [Fact]
    public void Extract_BatchAnnotate_OperationFunctions()
    {
        var args = Elem("""{"operations":[{"kind":"rename_function","function":"main","name":"x"},{"kind":"set_function_comment","function":"helper","comment":"c"},{"kind":"rename_function","function":"main","name":"y"}]}""");
        Assert.Equal(["main", "helper"],
            ServerMetrics.ExtractFunctionSelectors("BatchAnnotate", args));
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("BatchAnnotate", Elem("""{"operations":[]}""")));
        Assert.Empty(ServerMetrics.ExtractFunctionSelectors("BatchAnnotate", Elem("""{}""")));
    }

    [Fact]
    public void Sanitize_StripsControls_Caps128_BlankNull()
    {
        Assert.Equal("ab", ServerMetrics.SanitizeFunctionSelector("a\u0001\u007Fb"));
        Assert.Null(ServerMetrics.SanitizeFunctionSelector("  "));
        Assert.Null(ServerMetrics.SanitizeFunctionSelector(null));
        Assert.Null(ServerMetrics.SanitizeFunctionSelector("\x01\x02"));
        var long_ = new string('m', 200);
        Assert.Equal(128, ServerMetrics.SanitizeFunctionSelector(long_)!.Length);
        // Case and address chars preserved (symbols are case-sensitive).
        Assert.Equal("Foo::Bar<0x1400>", ServerMetrics.SanitizeFunctionSelector("Foo::Bar<0x1400>"));
    }

    [Fact]
    public void Counters_CallsTokensErrors_PerFunction()
    {
        var metrics = new ServerMetrics();
        metrics.RecordToolResult("InspectFunction", "ok", 5, 100, 274, functions: ["main"]);
        metrics.RecordToolResult("InspectFunction", "backend_error", 5, 100, 274, errorCode: "not_found", functions: ["main"]);
        var fns = metrics.Snapshot()["functions"] as JsonObject;
        Assert.NotNull(fns);
        var main = fns!["main"] as JsonObject;
        Assert.NotNull(main);
        Assert.Equal(2L, main!["calls"]?.GetValue<long>());
        Assert.Equal(1L, main["errors"]?.GetValue<long>());
        // Byte-only sides without payload text contribute 0 real BPE tokens.
        Assert.Equal(0L, main["tokens"]?.GetValue<long>());
        // Non-function tools leave the map untouched.
        metrics.RecordToolResult("ListFunctions", "ok", 1, 10, 100);
        Assert.Equal(2L, (metrics.Snapshot()["functions"] as JsonObject)!.Count == 1 ? 2L : -1L);
    }

    [Fact]
    public void Counters_MultiFunction_SplitsTokensEvenly()
    {
        var metrics = new ServerMetrics();
        const string req = """{"function":"main"}""";
        const string resp = """{"ok":true}""";
        var total = TokenCounter.Count(req) + TokenCounter.Count(resp);
        Assert.True(total > 0);
        metrics.RecordToolResult("AnalyzeFunctions", "ok", 5, req.Length, resp.Length,
            functions: ["a", "b"], requestText: req, responseText: resp);
        var fns = metrics.Snapshot()["functions"] as JsonObject;
        Assert.Equal(total, (fns!["a"] as JsonObject)!["tokens"]?.GetValue<long>()
            + (fns["b"] as JsonObject)!["tokens"]?.GetValue<long>());
        Assert.Equal(1L, (fns["a"] as JsonObject)!["calls"]?.GetValue<long>());
        Assert.Equal(1L, (fns["b"] as JsonObject)!["calls"]?.GetValue<long>());
    }

    [Fact]
    public void Digest_ContainsFunctionsTop5()
    {
        using var dir = TempDir.Create("dbglink-fn-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        for (var i = 0; i < 7; i++)
            metrics.RecordToolResult("InspectFunction", "ok", 1, 100, 1000, functions: ["fn" + i]);
        sink!.Flush();
        sink.WriteDigest();
        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.Contains("functions: top ", digest);
        // Top-5 cap: 7 tracked, 5 shown.
        var line = digest.Split('\n').First(l => l.StartsWith("functions: top", StringComparison.Ordinal));
        Assert.Equal(5, line.Split('|').Length);
        Assert.Contains("fn0", line);
    }

    [Fact]
    public void Digest_EmptyFunctions_ShowsNone()
    {
        var metrics = new ServerMetrics();
        var snapshot = metrics.Snapshot();
        var text = DigestFormatter.Format(snapshot, [], 0, 0);
        Assert.Contains("functions: top (none)", text);
        // Existing anchors intact.
        Assert.Contains("# DBGLink telemetry digest", text);
        Assert.Contains("big total:", text);
    }

    /// <summary>
    /// Function selectors are sanitized before they reach the per-function
    /// aggregate: control chars stripped, trimmed, capped at 128 chars, and
    /// blank selectors dropped. The dead TelemetryRecorder channel used to
    /// carry this test; the live path is ServerMetrics.
    /// </summary>
    [Fact]
    public void FunctionSelectors_AreSanitized_NoControlsOrOverflow()
    {
        var metrics = new ServerMetrics();
        metrics.RecordToolResult("InspectFunction", "ok", 5, 0, 100,
            functions: ["a\u0001b", new string('m', 200), "  ", "ok-name"]);

        var functions = metrics.Snapshot()["functions"] as JsonObject;
        Assert.NotNull(functions);
        var names = functions!.Select(pair => pair.Key).ToArray();

        // Control chars stripped, the 200-char name capped at 128, the blank
        // selector dropped, the clean name kept.
        Assert.Contains(names, name => name.Contains("ab"));
        Assert.Contains(names, name => name.StartsWith("ok-name", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.Length > 128);
        Assert.All(names, name => Assert.All(name, c => Assert.False(char.IsControl(c))));

        // Null functions => empty, never null-throws.
        var metrics2 = new ServerMetrics();
        metrics2.RecordToolResult("ListFunctions", "ok", 1, 0, 1);
        Assert.NotNull(metrics2.Snapshot()["functions"]);
    }

    [Fact]
    public void Snapshot_FunctionsBounded_ToolsIntact()
    {
        var metrics = new ServerMetrics();
        for (var i = 0; i < 300; i++)
            metrics.RecordToolResult("InspectFunction", "ok", 1, 10, 100, functions: ["fn" + i]);
        var snapshot = metrics.Snapshot();
        var fns = snapshot["functions"] as JsonObject;
        Assert.NotNull(fns);
        Assert.True(fns!.Count <= 256);
        Assert.NotNull(fns["_other"]);
        Assert.NotNull(snapshot["tools"] as JsonObject);
        Assert.NotNull(snapshot["toolsSummary"] as JsonObject);
    }
}
