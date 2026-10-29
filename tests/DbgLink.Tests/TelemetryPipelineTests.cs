using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DbgLink.Launcher.Core;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// IMPL-4 Tests slice (TELEMETRY-T5 §5.2 N1-N7 + View T4 checks).
/// All tests hermetic: fresh temp dirs + lambda env, no network, no
/// process-env mutation. Existing telemetry test files are untouched.
/// </summary>
public sealed class TelemetryPipelineTests
{
    private static string NewMissingDir()
    {
        // Deliberately NOT created: opt-out must not create it.
        return Path.Combine(Path.GetTempPath(), "dbglink-pipeline-" + Guid.NewGuid().ToString("N"));
    }

    // N1. Privacy: payload content never reaches the log; hostile metachars
    // cannot inject new fields via sess=/sub=.
    [Fact]
    public void Privacy_NoRawPayloadLeak()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);

        // Secrets exist nearby but are NEVER passed to the API (by-design).
        _ = "rax+1";
        _ = @"C:\secret\x.pdb";
        _ = "Bearer abc";
        _ = "poi(0x1234)";

        sink!.LogTool("EvaluateExpressions", "ok", 5, 100, 200, 0, null, "sess-1", "InspectFunction");
        sink.LogTool("X\x01Y", "backend_error", 7, 10, 20, 0, "debugger_closed", "sess-1\nerr=hacked", "../../etc/passwd {{$secret}}");
        sink.Flush();

        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        Assert.DoesNotContain("rax+1", events);
        Assert.DoesNotContain(".pdb", events);
        Assert.DoesNotContain("Bearer", events);
        Assert.DoesNotContain("poi(", events);
        Assert.DoesNotContain("../", events);
        Assert.DoesNotContain("$", events);
        Assert.DoesNotContain("{", events);
        Assert.DoesNotContain("}", events);
        // Injection via newline/= is impossible: a non-conforming session id
        // sanitizes to "-" under the shared analysisId policy and the sess
        // field is omitted from the line, so no crafted value can add fields.
        var hostileLine = events.Split('\n').First(l => l.Contains("backend_error"));
        Assert.DoesNotContain("sess=", hostileLine);
        Assert.DoesNotContain("err=hacked", events);
        Assert.DoesNotContain("err=", events.Split('\n').First(l => l.Contains("EvaluateExpressions")));
        foreach (var line in events.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')))
            Assert.True(line.All(c => !char.IsControl(c)), $"control char leaked: {line}");
    }

    // N2. Fuzz the frozen sanitizers: no controls, hard caps, pinned edges.
    [Fact]
    public void Privacy_SanitizeFuzz_NoControlsOrOverflow()
    {
        for (var i = 0; i < 200; i++)
        {
            var hostile = BuildHostile(i);
            // Spec-vs-code note (T5 §1.4 assumed totality): SanitizeToolName
            // is total over non-null inputs only — null tools are coalesced
            // to "Unknown tool" by the caller (McpToolDispatcher
            // `request.Name ?? "Unknown tool"`), never sanitized. The other
            // sanitizers below are null-tolerant and take null directly.
            var toolInput = hostile ?? "Unknown tool";
            Assert.True(ServerMetrics.SanitizeToolName(toolInput).All(c => !char.IsControl(c)));
            Assert.True(ServerMetrics.SanitizeToolName(toolInput).Length <= 128);
            Assert.True(ServerMetrics.SanitizeMethod(hostile, 64).All(c => !char.IsControl(c)));
            Assert.True(ServerMetrics.SanitizeMethod(hostile, 64).Length <= 64);
            Assert.True(ServerMetrics.SanitizeErrorCode(hostile).All(c => !char.IsControl(c)));
            Assert.True(ServerMetrics.SanitizeErrorCode(hostile).Length <= 64);
            Assert.True(ServerMetrics.SanitizeSessionId(hostile).All(c => !char.IsControl(c)));
            Assert.True(ServerMetrics.SanitizeSessionId(hostile).Length <= 36);
            Assert.True(ServerMetrics.SanitizeBatchDetail(hostile).All(c => !char.IsControl(c)));
            Assert.True(ServerMetrics.SanitizeBatchDetail(hostile).Length <= 128);
            var resolved = ServerMetrics.ResolveErrorCode(hostile, hostile);
            Assert.True(resolved is null || (resolved.All(c => !char.IsControl(c)) && resolved.Length <= 64));
        }

        // Pinned edges (ServerMetrics.cs:473-531, frozen by T5 §1.2).
        Assert.Equal("-", ServerMetrics.SanitizeSessionId("!!!"));
        Assert.Equal("", ServerMetrics.SanitizeBatchDetail(null));
        Assert.Null(ServerMetrics.ResolveErrorCode("ok", null));
        Assert.Null(ServerMetrics.ResolveErrorCode("ok", "unknown"));
        Assert.Equal("timeout", ServerMetrics.ResolveErrorCode("timeout", null));
        Assert.Equal("_unknown", ServerMetrics.SanitizeToolName("\x01\x02"));
    }

    private static string? BuildHostile(int i)
    {
        if (i % 25 == 0) return null;
        if (i % 25 == 1) return "   ";
        if (i % 25 == 2) return "!!!";
        var controls = new string(Enumerable.Range(0, 32).Select(n => (char)n).ToArray()) + "\x7F";
        return "pre" + i + controls + new string('m', i * 3) + " !!! " + new string('s', 500);
    }

    // N3. Opt-out: files off, aggregates on. Enabled by default.
    [Theory]
    [InlineData("disabled")]
    [InlineData("disable")]
    [InlineData("OFF")]
    [InlineData("No")]
    [InlineData("0")]
    [InlineData("false")]
    [InlineData("off")]
    [InlineData("no")]
    public void Policy_OptOut_WritesNothing_AndMetricsStayAlive(string flag)
    {
        var metrics = new ServerMetrics();
        var missing = NewMissingDir();
        Assert.Null(TelemetryFileSink.TryCreate(metrics, missing, _ => flag));
        Assert.False(Directory.Exists(missing));
        // ServerConfig kill-switch agrees with the sink (single source).
        Assert.True(ServerConfig.IsTelemetryDisabled(flag));

        metrics.FileSink = null;
        metrics.RecordToolResult("X", "ok", 1, 1, 1);
        var snapshot = metrics.Snapshot();
        Assert.Equal(1L, (snapshot["tools"] as JsonObject)!["X"]!["calls"]?.GetValue<long>());
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("1")]
    [InlineData("n")]
    [InlineData("none")]
    [InlineData("verbose")]
    public void Policy_EnabledByDefault_ForAnythingElse(string? flag)
    {
        var metrics = new ServerMetrics();
        using var tmp = TempDir.Create("dbglink-pipeline-");
        using var sink = TelemetryFileSink.TryCreate(metrics, tmp, _ => flag);
        Assert.NotNull(sink);
        Assert.False(ServerConfig.IsTelemetryDisabled(flag));
    }

    // N4. Retention bounds: rotation, queue drops surfaced, digest cap.
    [Fact]
    public void Retention_BoundsEnforced_QueueDigest()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null, maxEventsBytes: 200);
        Assert.NotNull(sink);
        for (var i = 0; i < 50; i++)
            sink!.LogTool("EvaluateExpressions", "ok", 1, 10, 100, 0);
        sink!.Flush();
        sink.Flush();
        Assert.True(new FileInfo(sink.EventsPath).Length < 4096);
        // ≤4: per-PID active events file + up to 2 generations + digest.md.
        Assert.True(Directory.GetFiles(dir).Length <= 4);

        // Overflow the 2000-line queue without flushing: drops are counted,
        // and the digest surfaces the exact counter (not silent loss).
        for (var i = 0; i < 3000; i++)
            sink.LogTool("EvaluateExpressions", "ok", 1, 10, 100, 0);
        sink.WriteDigest();
        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.True(new FileInfo(sink.DigestPath).Length <= 32 * 1024);
        var marker = "dropped: ";
        var at = digest.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(at >= 0);
        var number = new string(digest.Substring(at + marker.Length)
            .TakeWhile(char.IsDigit).ToArray());
        Assert.True(long.TryParse(number, out var dropped) && dropped > 0);
    }

    // N5. Digest/file backward-compat: frozen anchors and line format.
    [Fact]
    public void Migration_DigestBackwardCompat_GoldenAnchors()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        using (var scope = metrics.BeginTool("InspectFunction"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 100, responseBytes: 1000);
        using (var scope = metrics.BeginTool("ReadMemAtAddress"))
            scope.Complete(failed: true, outcome: "backend_error", requestBytes: 30, responseBytes: 0, errorCode: "debugger_closed");
        sink!.Flush();
        sink.WriteDigest();

        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        foreach (var anchor in new[]
        {
            "# DBGLink telemetry digest", "tool events:", "total:",
            "slow p95", "big avg-out", "big total:", "errors", "recent failures",
            "Line fields:", "Agent rule:", "Read this file first.",
        })
            Assert.Contains(anchor, digest);
        // Per-process digest only: no cross-process lifetime line.
        Assert.DoesNotContain("lifetime:", digest);
        Assert.DoesNotContain("cumulative.json", digest);

        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        Assert.True(Regex.IsMatch(events, @"^\d{4}-\d{2}-\d{2}T\S+ \S+ \S+ \d+ms in\d+ out\d+ tok\d+", RegexOptions.Multiline));
    }

    // N6. Hot path does no file I/O: 40 calls (below the 50-call digest
    // trigger) leave the per-PID events file untouched until an explicit Flush.
    [Fact]
    public void Pipeline_NoFileIoOnHotPath()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;

        var before = Directory.GetFiles(dir).OrderBy(f => f).ToArray();
        for (var i = 0; i < 40; i++)
            metrics.RecordToolResult("HotTool", "ok", 1, 10, 100);
        Assert.Equal(before, Directory.GetFiles(dir).OrderBy(f => f).ToArray());
        Assert.False(File.Exists(sink!.EventsPath));

        sink.Flush();
        var lines = TestFileIO.ReadAllTextRetry(sink.EventsPath)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(l => l.Contains("HotTool ok"));
        Assert.Equal(40, lines);
    }

    // N7. Stale artifacts from old versions (cumulative.json, legacy
    // events.log / events-legacy-*) are ignored: startup stays best-effort
    // and the per-process digest carries no lifetime line.
    [Fact]
    public void Migration_LegacyArtifacts_IgnoredOnStartup()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        File.WriteAllText(Path.Combine(dir, "cumulative.json"),
            """{"tools":{"InspectFunction":{"calls":5,"ok":4,"in":50,"out":500}},"bytesReceived":60,"bytesSent":600,"processes":3}""");
        File.WriteAllText(Path.Combine(dir, "events.log"), "stale legacy\n");
        File.WriteAllText(Path.Combine(dir, "events-legacy-20200101.log"), "stale legacy\n");

        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        using (var scope = metrics.BeginTool("InspectFunction"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 100, responseBytes: 1000);
        sink!.Flush();
        sink.WriteDigest();

        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.Contains("total: 1 calls", digest);
        Assert.DoesNotContain("lifetime:", digest);
        Assert.DoesNotContain("cumulative.json", digest);
    }

    // View (T4 §3.2): JSON node schema, render caps, no input mutation.
    // w10 diet: tops of 3, no "bytes"/topLargestAvgOut/errorsByCode dupes,
    // 5 recent failures, 8 http codes — default node stays ≤8KB.
    [Fact]
    public void View_StatusRenderer_JsonSchemaAndBudgets()
    {
        var metrics = new ServerMetrics();
        for (var t = 0; t < 8; t++)
        {
            for (var i = 0; i < 2; i++)
            {
                using var scope = metrics.BeginTool("ViewTool_" + t);
                scope.Complete(failed: t % 2 == 0, outcome: t % 2 == 0 ? "backend_error" : "ok",
                    requestBytes: 10 + t, responseBytes: 100 + t * 10,
                    errorCode: t % 2 == 0 ? "err_" + t : null);
            }
        }
        metrics.RecordBackendCall("native", "EvaluateExpression", true, null, 12);
        metrics.RecordBackendCall("native", "ReadMemAtAddress", false, "debugger_closed", 3);
        metrics.RecordBackendCall("ghidra", "InspectFunction", true, null, 40, cached: true);
        metrics.RecordMcpRequest("tools/call", 100);
        metrics.RecordHttpStatus(200);
        metrics.RecordSessionRegistered("sess-1");
        metrics.HttpEnter();
        var snapshot = metrics.Snapshot();
        var frozen = snapshot.ToJsonString();

        var failures = Enumerable.Range(0, 12).Select(i => new string('f', 600) + i).ToArray();
        var updated = new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);
        var renderer = new StatusRenderer();
        var node = renderer.RenderJson(snapshot, failures, 7, 16, -1, updated);

        Assert.Equal(2L, node["schemaVersion"]?.GetValue<long>());
        Assert.Equal(16L, node["total"]!["calls"]?.GetValue<long>());
        Assert.Equal(8L, node["total"]!["ok"]?.GetValue<long>());
        // No lifetime node: per-process totals live in "total".
        Assert.Null(node["lifetime"]);
        // w10 diet: duplicate markdown/aggregator projections are gone.
        Assert.Null(node["bytes"]);
        Assert.Null(node["topLargestAvgOut"]);
        Assert.True((node["topSlowest"] as JsonArray)!.Count <= 3);
        Assert.True((node["topLargestTotal"] as JsonArray)!.Count <= 3);
        Assert.True((node["topErrors"] as JsonArray)!.Count <= 3);
        foreach (var row in (node["topErrors"] as JsonArray)!.OfType<JsonObject>())
        {
            Assert.Null(row["errorsByCode"]);
            Assert.NotNull(row["topErrorCode"]);
        }
        Assert.True((node["sessions"]!["topSessions"] as JsonArray)!.Count <= 3);
        // fileLines -1 ⇒ null, never 0.
        Assert.True(node["dropped"]!["fileLines"] is null || node["dropped"]!["fileLines"]!.GetValueKind() == JsonValueKind.Null);
        Assert.Equal(7L, node["dropped"]!["queueDropped"]?.GetValue<long>());
        var rendered = node["recentFailures"] as JsonArray;
        Assert.Equal(5, rendered!.Count);
        Assert.True(rendered.OfType<JsonNode>().All(n => n.GetValue<string>().Length <= 512));
        Assert.NotNull(node["queues"]);
        Assert.NotNull(node["backends"]!["native"]);
        Assert.NotNull(node["backends"]!["ghidra"]);
        Assert.True(node.ToJsonString().Length <= 8 * 1024);
        Assert.True(node.ToJsonString().Length <= 64 * 1024);
        // Input snapshot is never mutated.
        Assert.Equal(frozen, snapshot.ToJsonString());
        // Deterministic for the same input.
        Assert.Equal(node.ToJsonString(), renderer.RenderJson(snapshot, failures, 7, 16, -1, updated).ToJsonString());
    }

    // View (T4 §3.1): markdown deterministic, fileLines -1 ⇒ '?', B1 cap.
    [Fact]
    public void View_StatusRenderer_MarkdownDeterministicAndCapped()
    {
        var metrics = new ServerMetrics();
        using (var scope = metrics.BeginTool("ViewTool"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 10, responseBytes: 100);
        var snapshot = metrics.Snapshot();
        var renderer = new StatusRenderer();
        var updated = new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);

        var first = renderer.RenderMarkdown(snapshot, [], 0, 1, -1, updated);
        var second = renderer.RenderMarkdown(snapshot, [], 0, 1, -1, updated);
        Assert.Equal(first, second);
        Assert.Contains("file lines: ?", first);
        Assert.Contains("(none)", first);
        Assert.True(first.Length <= 32 * 1024);
        // updatedUtc is caller-supplied: different clocks ⇒ different stamp.
        var later = renderer.RenderMarkdown(snapshot, [], 0, 1, -1, updated.AddHours(1));
        Assert.Contains("updated: 2026-10-08T13:00:00Z", later);
    }

    // View seam: the renderer never throws on hostile shapes.
    [Fact]
    public void View_StatusRenderer_NeverThrows_OnHostileInput()
    {
        var renderer = new StatusRenderer();
        var garbage = new JsonObject { ["toolsSummary"] = new JsonArray(), ["backends"] = new JsonObject() };
        var node = renderer.RenderJson(garbage, null!, -5, -5, -5, default);
        Assert.NotNull(node["total"]);
        var text = renderer.RenderMarkdown(garbage, null!, 0, 0, -1, default);
        Assert.StartsWith("# DBGLink telemetry digest", text);
    }

    // View integration (T4 §5 path B): GetServerStatus carries telemetry from
    // the in-memory snapshot; the call itself performs no file I/O.
    [Fact]
    public async Task View_StatusTelemetryNode_OnDemand_WithoutFileIo()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, TelemetryDirectory = dir },
            new StatusFakeBridge(), new StatusFakeGhidra());
        try
        {
            await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "EvaluateExpressions",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax+1" }),
                },
            }, CancellationToken.None);

            var before = Directory.GetFiles(dir).OrderBy(f => f).ToArray();
            var digestBefore = File.GetLastWriteTimeUtc(Path.Combine(dir, "digest.md"));

            var result = await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None);

            Assert.Equal(before, Directory.GetFiles(dir).OrderBy(f => f).ToArray());
            Assert.Equal(digestBefore, File.GetLastWriteTimeUtc(Path.Combine(dir, "digest.md")));

            var text = Assert.Single(result.Content.OfType<TextContentBlock>()).Text;
            var response = JsonNode.Parse(text)!.AsObject();
            // Pre-existing fields byte-identical in shape.
            Assert.NotNull(response["analysisId"]);
            Assert.NotNull(response["ghidra"]);
            Assert.NotNull(response["debugger"]);
            var telemetry = Assert.IsType<JsonObject>(response["telemetry"]);
            Assert.Equal(2L, telemetry["schemaVersion"]?.GetValue<long>());
            Assert.True(telemetry["total"]!["calls"]?.GetValue<long>() >= 1);
            Assert.NotNull(telemetry["queues"]);
            Assert.NotNull(telemetry["dropped"]);
            Assert.True(telemetry["dropped"]!["fileLines"] is null
                || telemetry["dropped"]!["fileLines"]!.GetValueKind() == JsonValueKind.Null);

            // Store-seam: provider extras flow into the node additively.
            ToolRegistry.TelemetryExtrasProvider = _ => new TelemetryStatusExtras(["boom err=x"], 7, 100, 42);
            var wired = await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None);
            var wiredTelemetry = JsonNode.Parse(Assert.Single(wired.Content.OfType<TextContentBlock>()).Text)!.AsObject()["telemetry"]!.AsObject();
            Assert.Equal(7L, wiredTelemetry["dropped"]!["queueDropped"]?.GetValue<long>());
            Assert.Equal(42L, wiredTelemetry["dropped"]!["fileLines"]?.GetValue<long>());
            Assert.Single((wiredTelemetry["recentFailures"] as JsonArray)!);
            Assert.Null(wiredTelemetry["lifetime"]);

            // T4 §6 single enrichment point: a provided snapshot wins over
            // the raw one (e.g. sessions.active from the server).
            ToolRegistry.TelemetrySnapshotProvider = () =>
            {
                var enriched = new ServerMetrics().Snapshot();
                (enriched["sessions"] as JsonObject)!["active"] = 5L;
                return enriched;
            };
            var enrichedResult = await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None);
            var enrichedTelemetry = JsonNode.Parse(Assert.Single(enrichedResult.Content.OfType<TextContentBlock>()).Text)!.AsObject()["telemetry"]!.AsObject();
            Assert.Equal(5L, enrichedTelemetry["sessions"]!["active"]?.GetValue<long>());
        }
        finally
        {
            ToolRegistry.TelemetrySnapshotProvider = null;
            ToolRegistry.TelemetryExtrasProvider = null;
            ToolRegistry.TelemetryRenderer = StatusRenderer.Shared;
        }
    }

    // Merged from TelemetryBulkTests (cleanup/C DELETE): bulk snapshot sections
    // stay parseable by the launcher client, maps stay bounded, gauges track max.
    [Fact]
    public void Merged_Bulk_SnapshotBoundsGaugesAndClientParse()
    {
        var metrics = new ServerMetrics();
        using (var scope = metrics.BeginTool("InspectFunction"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 120, responseBytes: 2048);
        using (var scope = metrics.BeginTool("TraceUntil"))
            scope.Complete(failed: true, outcome: "timeout", requestBytes: 80, responseBytes: 0);
        metrics.RecordMcpRequest("tools/call", 512);
        metrics.RecordMcpRequest("tools/list", 128);
        metrics.RecordHttpRequest();
        metrics.RecordHttpStatus(200);
        metrics.RecordBackendCall("native", "EvaluateExpression", true, null, 12);
        metrics.RecordBackendCall("ghidra", "InspectFunction", true, null, 40, cached: true);
        metrics.RecordSessionRegistered();
        metrics.RecordSessionClosed();
        metrics.HttpEnter();
        metrics.HttpEnter();
        metrics.HttpExit();
        metrics.ExecEnter();
        metrics.ExecExit();

        var snapshot = metrics.Snapshot();
        Assert.NotNull(snapshot["mcpMethods"] as JsonObject);
        Assert.NotNull(snapshot["tools"] as JsonObject);
        Assert.NotNull(snapshot["toolsSummary"] as JsonObject);
        Assert.NotNull(snapshot["backends"] as JsonObject);
        Assert.NotNull(snapshot["queues"] as JsonObject);
        Assert.NotNull(snapshot["sessions"] as JsonObject);
        Assert.Equal(1L, snapshot["mcpMethods"]!["tools/call"]?.GetValue<long>());
        Assert.Equal(1L, snapshot["tools"]!["InspectFunction"]!["ok"]?.GetValue<long>());
        var queues = snapshot["queues"] as JsonObject;
        Assert.Equal(1L, queues!["httpCurrent"]?.GetValue<long>());
        Assert.Equal(2L, queues["httpMax"]?.GetValue<long>());
        Assert.Equal(1L, queues["executionMax"]?.GetValue<long>());

        // Bounded maps (64 tools, 32 methods) keep the snapshot a cheap
        // GetServerStatus section even under hostile cardinality.
        for (var i = 0; i < 200; i++)
        {
            using var scope = metrics.BeginTool("BulkTool_" + i);
            scope.Complete(failed: true, outcome: "validation_error", requestBytes: 10, responseBytes: 100);
        }
        for (var i = 0; i < 100; i++)
            metrics.RecordMcpRequest("method_" + i, 10);
        var bounded = metrics.Snapshot();
        Assert.True((bounded["mcpMethods"] as JsonObject)!.Count <= 32);
        var json = bounded.ToJsonString();
        Assert.True(json.Length < 128 * 1024, $"snapshot grew: {json.Length}");
        using var document = JsonDocument.Parse(json);
        Assert.True(SessionMetricsClient.TryParse(document.RootElement, out _));
    }

    // Merged from TelemetryBulkTests: per-tool latency quantiles plus the
    // hostile-name sanitizer pins and the top-list caps.
    [Fact]
    public void Merged_Bulk_PerToolHistogramSanitizeAndTopLists()
    {
        var metrics = new ServerMetrics();
        for (var i = 0; i < 10; i++)
        {
            using var scope = metrics.BeginTool("EvaluateExpressions");
            scope.Complete(failed: false, outcome: "ok", requestBytes: 10, responseBytes: 100);
        }
        for (var i = 0; i < 200; i++)
        {
            using var scope = metrics.BeginTool("EvilTool_" + i);
            scope.Complete(failed: true, outcome: "validation_error");
        }
        var tools = metrics.Snapshot()["tools"] as JsonObject;
        Assert.NotNull(tools);
        Assert.True(tools!.Count <= 64);
        Assert.NotNull(tools["EvaluateExpressions"]);
        Assert.NotNull(tools["_other"]);
        var stats = tools["EvaluateExpressions"] as JsonObject;
        Assert.Equal(10L, stats!["calls"]?.GetValue<long>());
        // Instant calls land in the first latency bucket (<=5ms).
        Assert.Equal(5L, stats["p50Ms"]?.GetValue<long>());
        Assert.Equal(5L, stats["p95Ms"]?.GetValue<long>());

        var summary = metrics.Snapshot()["toolsSummary"] as JsonObject;
        Assert.True((summary!["topSlowest"] as JsonArray)!.Count <= 8);
        Assert.True((summary["topLargest"] as JsonArray)!.Count <= 8);
        Assert.True((summary["topLargestTotal"] as JsonArray)!.Count <= 8);
        Assert.True((summary["topErrors"] as JsonArray)!.Count <= 8);

        // Hostile method names stay sanitized and control-free.
        var hostile = new ServerMetrics();
        hostile.RecordMcpRequest("tools/call", 10);
        hostile.RecordMcpRequest("evil\nmethod\x01", 10);
        hostile.RecordMcpRequest(new string('m', 200), 10);
        hostile.RecordMcpRequest(null, 10);
        var methods = hostile.Snapshot()["mcpMethods"] as JsonObject;
        Assert.NotNull(methods);
        Assert.Equal(1L, methods!["tools/call"]?.GetValue<long>());
        Assert.Equal(1L, methods["evilmethod"]?.GetValue<long>());
        Assert.Equal(1L, methods[new string('m', 64)]?.GetValue<long>());
        Assert.Equal(1L, methods["_unknown"]?.GetValue<long>());
        foreach (var pair in methods!)
            Assert.True(pair.Key.All(c => !char.IsControl(c)), $"unsanitized key: {pair.Key}");
    }

    // Merged from TelemetryBulkTests: the dispatcher classifies per-tool
    // outcomes (ok vs validationError) into the snapshot.
    [Fact]
    public async Task Merged_Bulk_DispatcherPerToolStatsAndSnapshotContext()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new MergedBulkFakeBridge(), new MergedBulkFakeGhidra());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ok = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax+1" }),
            },
        }, cts.Token);
        Assert.False(ok.IsError);

        var rejected = false;
        try
        {
            await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "EvaluateExpressions",
                Arguments = new Dictionary<string, JsonElement>(),
            }, cts.Token);
        }
        catch (ModelContextProtocol.McpProtocolException) { rejected = true; }
        Assert.True(rejected);

        var snapshot = server.GetMetricsSnapshot();
        var tools = snapshot["tools"] as JsonObject;
        Assert.NotNull(tools);
        var stats = tools!["EvaluateExpressions"] as JsonObject;
        Assert.NotNull(stats);
        Assert.Equal(2L, stats!["calls"]?.GetValue<long>());
        Assert.Equal(1L, stats["ok"]?.GetValue<long>());
        Assert.Equal(1L, stats["validationError"]?.GetValue<long>());
        Assert.NotNull(snapshot["config"] as JsonObject);
        Assert.NotNull(snapshot["sessions"] as JsonObject);
    }

    private sealed class MergedBulkFakeBridge : DbgLink.Server.IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"expression\":\"rax\",\"value\":\"0x1\",\"valueDecimal\":1}}");
    }

    private sealed class MergedBulkFakeGhidra : DbgLink.Server.IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
    }

    // Merged from TelemetryEfficiencyTests (cleanup/C DELETE): tok-column pins.
    // Real cl100k_base BPE only: byte-only callers (no payload text) log
    // tok0, never an estimate. Where the actual payload text is plumbed in,
    // the column carries the real BPE count (25).
    [Fact]
    public void Merged_TokColumn_RealBpeOnly()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        sink!.LogTool("BatchStaticQueries", "ok", 41, 1242, 14439, 0, null, "sess-42", "InspectFunctionx2+ListSymbols");
        sink.Flush();

        var line = TestFileIO.ReadAllTextRetry(sink.EventsPath).Trim();
        Assert.Contains("in1242 out14439 tok0", line);
        Assert.Contains("sess=sess-42", line);
        Assert.Contains("sub=InspectFunctionx2+ListSymbols", line);
        // Back-compat: in/out parsers keep working.
        var match = Regex.Match(line, @"in(\d+) out(\d+)");
        Assert.True(match.Success);
        Assert.Equal("1242", match.Groups[1].Value);
        Assert.Equal("14439", match.Groups[2].Value);

        // BPE path: same sink, but with the payload text available the tok
        // column reports the real count.
        const string req = """{"function":"main","maxChars":6000}""";
        const string resp = """{"ok":true,"result":{"source":"ghidra-static"}}""";
        var real = TokenCounter.Count(req) + TokenCounter.Count(resp);
        Assert.Equal(25, real);
        sink.LogTool("BatchStaticQueries", "ok", 41, req.Length, resp.Length, real, null, "sess-42", null);
        sink.Flush();

        var lines = TestFileIO.ReadAllTextRetry(sink.EventsPath)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains($"in{req.Length} out{resp.Length} tok{real}", lines[^1].Trim());

        using var dir2 = TempDir.Create("dbglink-pipeline-");
        var metrics2 = new ServerMetrics();
        using var sink2 = TelemetryFileSink.TryCreate(metrics2, dir2, _ => null);
        Assert.NotNull(sink2);
        sink2!.LogTool("ListFunctions", "ok", 0, 15, 353, 0);
        sink2.Flush();

        var line2 = TestFileIO.ReadAllTextRetry(sink2.EventsPath).Trim();
        Assert.Contains("tok0", line2);
        Assert.DoesNotContain("sess=", line2);
        Assert.DoesNotContain("sub=", line2);
    }

    // Merged from TelemetryEfficiencyTests: batch sub-method mix logging.
    [Fact]
    public async Task Merged_BatchMix_SubMethodMix()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, TelemetryDirectory = dir }, new RecordingBridge(), new MergedMixBackend());
        await server.CallToolAsync(MergedRequest("BatchStaticQueries", """
            {"requests":[{"method":"ListSymbols","arguments":{"kind":"imports","filter":"AIL_*"}},
            {"method":"Xrefs","arguments":{"address":"bad","direction":"to"}},
            {"method":"ListFunctions","arguments":{}},
            {"method":"ListSymbols","arguments":{"kind":"imports"}}]}
            """), CancellationToken.None);
        server.Dispose();
        var events = TestFileIO.ReadAllTextRetry(ActiveEventsFile(dir));
        var batchLine = events.Split('\n').FirstOrDefault(l => l.Contains("BatchStaticQueries ok"));
        Assert.NotNull(batchLine);
        Assert.Contains("sub=ListSymbolsx2+Xrefs+ListFunctions", batchLine);
        Assert.Contains("tok", batchLine);
    }

    // Merged from TelemetryEfficiencyTests: bad-session batch logs sess without sub.
    [Fact]
    public async Task Merged_BatchMix_BadSessionLogsSessWithoutSub()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, TelemetryDirectory = dir }, new RecordingBridge(), new MergedMixBackend());
        await Assert.ThrowsAnyAsync<Exception>(() => server.CallToolAsync(MergedRequest("BatchStaticQueries",
            """{"analysisId":"sess-42","requests":[{"method":"ListSymbols","arguments":{"kind":"imports"}}]}"""),
            CancellationToken.None));
        server.Dispose();
        var events = TestFileIO.ReadAllTextRetry(ActiveEventsFile(dir));
        var line = events.Split('\n').FirstOrDefault(l => l.Contains("BatchStaticQueries") && l.Contains("bad_session"));
        Assert.NotNull(line);
        Assert.Contains("sess=sess-42", line);
        Assert.DoesNotContain("sub=", line);
    }

    private sealed class MergedMixBackend : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
            => Task.FromResult(method == "XrefsTo"
                ? "{\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"bad address\"}}"
                : "{\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}");
    }

    private static CallToolRequestParams MergedRequest(string name, string args) => new()
    { Name = name, Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(args)! };

    // Merged from TelemetryEfficiencyTests: per-tool byte totals that feed
    // the digest "big total" section (this-process snapshot only).
    [Fact]
    public void Merged_DigestTotals_FromSnapshot()
    {
        using var dir = TempDir.Create("dbglink-pipeline-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        using (var scope = metrics.BeginTool("BatchStaticQueries"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 1242, responseBytes: 14439);
        sink!.Flush();
        sink.WriteDigest();

        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.Contains("big total:", digest);
        Assert.Contains("BatchStaticQueries", digest);
        // Byte-only call: no payload text, so the real BPE count is 0 —
        // never an estimate (the old heuristic printed tok~4.2k here).
        Assert.Contains("tok0 x1", digest);
        var tools = metrics.Snapshot()["tools"] as JsonObject;
        Assert.Equal(14439L, tools!["BatchStaticQueries"]!["totalBytesOut"]!.GetValue<long>());
        Assert.Equal(1242L, tools["BatchStaticQueries"]!["totalBytesIn"]!.GetValue<long>());
        Assert.Equal(0L, tools["BatchStaticQueries"]!["totalTokens"]!.GetValue<long>());
    }

    /// <summary>The server's active per-PID telemetry file (single match in
    /// these hermetic dirs).</summary>
    private static string ActiveEventsFile(TempDir dir)
        => Assert.Single(Directory.GetFiles(dir, "events-*.log"));

    private sealed class StatusFakeBridge : DbgLink.Server.IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{\"debugging\":false}}");
    }

    private sealed class StatusFakeGhidra : DbgLink.Server.IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{\"available\":true}}");
    }
}

/// <summary>
/// Telemetry accounting coherence: total counts MCP tool calls, backends
/// counts top-level bridge uses (at most one per tool execution), so
/// backends.native + backends.ghidra &lt;= total. Covers the batch fan-out
/// collapse, the BOM-free events log, and the timed _open lifecycle line.
/// </summary>
public sealed class TelemetryAccountingTests
{
    private sealed class AttributedFakeBridge(ServerMetrics metrics) : DbgLink.Server.IBridgeClient
    {
        private int _requestCount;
        public int RequestCount => Volatile.Read(ref _requestCount);
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            // Mirror the production BridgeClient: every RPC records a backend call.
            metrics.RecordBackendCall("native", method, true, null, 1);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    private static McpToolDispatcher BuildDispatcher(
        ServerMetrics metrics, DbgLink.Server.IBridgeClient bridge, string checkpointPath, out AnalysisSessionRegistry sessions)
    {
        var config = new ServerConfig { Port = 50399 };
        var ghidra = new NullGhidra();
        sessions = new AnalysisSessionRegistry(bridge, ghidra);
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(null, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(checkpointPath));
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), new GhidraOpenOperations(null), sessionControl);
        return new McpToolDispatcher(config, registry, context, sessions, metrics,
            hasControl: false, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
    }

    private sealed class AvailableGhidraClient : DbgLink.Server.IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{\"available\":true}}");
    }

    private static McpToolDispatcher BuildStatusDispatcher(
        ServerMetrics metrics, DbgLink.Server.IBridgeClient bridge, DbgLink.Server.IGhidraClient ghidra,
        string checkpointPath, out AnalysisSessionRegistry sessions)
    {
        var config = new ServerConfig { Port = 50399 };
        sessions = new AnalysisSessionRegistry(bridge, ghidra);
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(null, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(checkpointPath));
        var open = new GhidraOpenOperations(null) { Telemetry = metrics };
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), open, sessionControl);
        return new McpToolDispatcher(config, registry, context, sessions, metrics,
            hasControl: false, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
    }

    [Fact]
    public async Task Accounting_FreshServerStatus_IncludesInflightCall_BackendsSumBelowTotal()
    {
        // Degenerate case: the very first tool call on a fresh server is
        // GetServerStatus. Its own backend RPC is already counted when the
        // telemetry node renders, but its tool completion lands only after
        // the response is built — the reported node must still satisfy
        // native+ghidra <= total.
        var metrics = new ServerMetrics();
        var bridge = new AttributedFakeBridge(metrics);
        using var ckpt = TempDir.Create("dbglink-acct-");
        using var dispatcher = BuildStatusDispatcher(metrics, bridge,
            new AvailableGhidraClient(), Path.Combine(ckpt, "checkpoints.json"), out var sessions);
        using var _ = sessions;

        var result = await dispatcher.CallAsync(new CallToolRequestParams
        {
            Name = "GetServerStatus",
            Arguments = new Dictionary<string, JsonElement>(),
        }, CancellationToken.None);
        Assert.False(result.IsError);

        var telemetry = (JsonNode.Parse(TestWire.RawText(result))!["telemetry"]!).AsObject();
        var total = telemetry["total"]!["calls"]!.GetValue<long>();
        var backends = telemetry["backends"]!.AsObject();
        var native = backends["native"]!["calls"]!.GetValue<long>();
        var ghidra = backends["ghidra"]!["calls"]!.GetValue<long>();
        Assert.True(native + ghidra <= total,
            $"fresh-server status node violates accounting: backends {native}+{ghidra} must not exceed total {total}");

        // Steady state converges right after: the completion is recorded.
        var steady = metrics.Snapshot();
        var steadyTotal = (steady["toolsSummary"] as JsonObject)!["totalCalls"]!.GetValue<long>();
        var steadyBackends = steady["backends"] as JsonObject;
        var steadyNative = (steadyBackends!["native"] as JsonObject)!["calls"]!.GetValue<long>();
        var steadyGhidra = (steadyBackends["ghidra"] as JsonObject)!["calls"]!.GetValue<long>();
        Assert.True(steadyNative + steadyGhidra <= steadyTotal,
            $"steady state violates accounting: backends {steadyNative}+{steadyGhidra} must not exceed total {steadyTotal}");
    }

    [Fact]
    public async Task Accounting_BatchFanoutCollapses_BackendsSumBelowTotal()
    {
        var metrics = new ServerMetrics();
        var bridge = new AttributedFakeBridge(metrics);
        using var ckpt = TempDir.Create("dbglink-acct-");
        using var dispatcher = BuildDispatcher(metrics, bridge, Path.Combine(ckpt, "checkpoints.json"), out var sessions);
        using var _ = sessions;

        var result = await dispatcher.CallAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"requests":[{"method":"ListThreads","arguments":{}},{"method":"GetBacktrace","arguments":{}},{"method":"GetMemoryMap","arguments":{}},{"method":"ListBreakpoints","arguments":{}}]}""")!,
        }, CancellationToken.None);
        Assert.False(result.IsError);

        // The bridge really served all four sub-calls; only the accounting collapses.
        Assert.Equal(4, bridge.RequestCount);
        var snapshot = metrics.Snapshot();
        var total = (snapshot["toolsSummary"] as JsonObject)!["totalCalls"]!.GetValue<long>();
        var backends = snapshot["backends"] as JsonObject;
        var native = (backends!["native"] as JsonObject)!["calls"]!.GetValue<long>();
        var ghidra = (backends["ghidra"] as JsonObject)!["calls"]!.GetValue<long>();
        var fanout = backends["fanoutSubCalls"]!.GetValue<long>();
        Assert.Equal(1, total);
        Assert.Equal(1, native);
        Assert.Equal(0, ghidra);
        Assert.Equal(3, fanout);
        Assert.True(native + ghidra <= total, $"backends {native}+{ghidra} must not exceed total {total}");

        var digest = DigestFormatter.Format(snapshot, [], 0, 1);
        Assert.Contains("backends:", digest);
        Assert.Contains("fanout sub-calls: 3", digest);
        Assert.DoesNotContain("lifetime:", digest);
    }

    [Fact]
    public void Accounting_TopLevelScope_FirstRpcWins_RestAreFanout()
    {
        var metrics = new ServerMetrics();
        using (metrics.BeginBackendAttribution())
        {
            metrics.RecordBackendCall("native", "EvaluateExpression", true, null, 2);
            metrics.RecordBackendCall("native", "ReadMemAtAddress", true, null, 3);
            metrics.RecordBackendCall("ghidra", "InspectFunction", true, null, 40);
        }
        // Outside a tool flow every call still counts (backward compat).
        metrics.RecordBackendCall("ghidra", "ListFunctions", true, null, 5);
        metrics.RecordToolResult("BatchDebuggerOperations", "ok", 10, 100, 500);
        metrics.RecordToolResult("ListFunctions", "ok", 5, 50, 200);

        var snapshot = metrics.Snapshot();
        var total = (snapshot["toolsSummary"] as JsonObject)!["totalCalls"]!.GetValue<long>();
        var backends = snapshot["backends"] as JsonObject;
        var native = (backends!["native"] as JsonObject)!["calls"]!.GetValue<long>();
        var ghidra = (backends["ghidra"] as JsonObject)!["calls"]!.GetValue<long>();
        var fanout = backends["fanoutSubCalls"]!.GetValue<long>();
        Assert.Equal(2, total);
        Assert.Equal(1, native);
        Assert.Equal(1, ghidra);
        Assert.Equal(2, fanout);
        Assert.True(native + ghidra <= total, $"backends {native}+{ghidra} must not exceed total {total}");
    }

    [Fact]
    public void EventsLog_HasNoBom_FirstLineMatchesToolRegex()
    {
        using var dir = TempDir.Create("dbglink-acct-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        using (var scope = metrics.BeginTool("InspectFunction"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 100, responseBytes: 1000);
        sink!.Flush();
        using (var scope = metrics.BeginTool("ReadMemAtAddress"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 10, responseBytes: 100);
        sink.Flush();
        sink.WriteDigest();

        var bytes = File.ReadAllBytes(sink.EventsPath);
        Assert.True(bytes.Length > 3);
        Assert.False(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            "events log must not start with a UTF-8 BOM");
        // Every non-empty line starts with a timestamp: naive ^\d{4}- readers work.
        foreach (var line in System.Text.Encoding.UTF8.GetString(bytes)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries))
            Assert.True(Regex.IsMatch(line, @"^\d{4}-\d{2}-\d{2}T"), $"line without timestamp: {line}");
        var digestBytes = File.ReadAllBytes(sink.DigestPath);
        Assert.True(digestBytes.Length > 3);
        Assert.False(digestBytes[0] == 0xEF && digestBytes[1] == 0xBB && digestBytes[2] == 0xBF,
            "digest must not start with a UTF-8 BOM");
    }

    [Fact]
    public void OpenTerminal_FailedImport_EmitsTimedLifecycleLine_WithoutSecrets()
    {
        using var dir = TempDir.Create("dbglink-acct-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        metrics.RecordControlBegun();
        metrics.RecordControlTerminal("failed", 45230);
        metrics.RecordControlTerminal("../../etc/passwd {{$secret}}", 7);
        sink!.Flush();

        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        Assert.Contains("_open failed 45230ms lifecycle", events);
        Assert.DoesNotContain("../", events);
        Assert.DoesNotContain("$", events);
        Assert.DoesNotContain("{", events);
        // Completed terminals share the shape and stay out of recent failures.
        metrics.RecordControlTerminal("completed", 100);
        sink.WriteDigest();
        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.Contains("recent failures (up to 10):", digest);
        Assert.Contains("(none)", digest);
    }

    [Fact]
    public async Task OpenTerminal_FailingImport_LogsTimedLifecycleLine_WithoutPath()
    {
        using var dir = TempDir.Create("dbglink-acct-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;
        using var open = new GhidraOpenOperations(new FailingGhidraControl()) { Telemetry = metrics };

        var raw = await open.BeginGhidraOpenAsync(@"C:\test\target.exe", analyze: true, waitMs: 10000, CancellationToken.None);
        Assert.Contains("ghidra_open_failed", raw);
        sink!.Flush();
        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        var line = events.Split('\n').FirstOrDefault(l => l.Contains("_open failed"));
        Assert.NotNull(line);
        Assert.True(Regex.IsMatch(line, @"_open failed \d+ms lifecycle"), $"unexpected _open line: {line}");
        Assert.DoesNotContain("target.exe", events);
    }
}

[CollectionDefinition("HandleStability", DisableParallelization = true)]
public sealed class HandleStabilityCollection;

/// <summary>
/// Handle-leak guards for the soak finding (process handles 550 -&gt; 738
/// under load -&gt; 658 after idle, +108 net): undisposed IDisposables that
/// own OS handles (Process, WindowsIdentity) grow the handle table on the
/// request path and only settle when the finalizer catches up. Each test
/// loops the suspect with no GC in between and pins zero synchronous growth
/// via the raw kernel32 handle count (no Process object of our own, so the
/// measurement itself cannot leak). Windows-only.
/// Own non-parallel collection: a process-wide handle count is sensitive to
/// any concurrent test's transient handles, so these never run beside
/// other suites (same pattern as RoundTripBaseline/TokenBaseline).
/// </summary>
[Collection("HandleStability")]
public sealed class ServerHandleStabilityTests
{
    [DllImport("kernel32.dll")]
    private static extern bool GetProcessHandleCount(nint processHandle, out uint handleCount);

    private static uint CurrentHandleCount()
    {
        Assert.True(GetProcessHandleCount(new nint(-1), out var count));
        return count;
    }

    [Fact]
    public void Snapshot_DoesNotGrowProcessHandleCount()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var metrics = new ServerMetrics();
        metrics.Snapshot();
        var before = CurrentHandleCount();
        for (var i = 0; i < 200; i++)
            metrics.Snapshot();
        var after = CurrentHandleCount();
        Assert.True(after <= before + 16,
            $"ServerMetrics.Snapshot leaked handles: {before} -> {after}");
    }

    [Fact]
    public void ProtectFile_DoesNotGrowProcessHandleCount()
    {
        if (!OperatingSystem.IsWindows())
            return;
        using var dir = TempDir.Create("dbglink-handle-");
        var path = Path.Combine(dir, "probe.txt");
        File.WriteAllText(path, "x");
        FileProtection.ProtectFile(path);
        var before = CurrentHandleCount();
        for (var i = 0; i < 100; i++)
            FileProtection.ProtectFile(path);
        var after = CurrentHandleCount();
        Assert.True(after <= before + 8,
            $"FileProtection.ProtectFile leaked handles: {before} -> {after}");
    }

    [Fact]
    public async Task GhidraEndpointOwnershipCheck_DoesNotGrowProcessHandleCount()
    {
        if (!OperatingSystem.IsWindows())
            return;
        using var warmup = TempDir.Create("dbglink-handle-");
        File.WriteAllText(Path.Combine(warmup, "ghidra-bridge-test.json"), "x");
        using (var client = new GhidraClient(warmup))
            _ = await client.RequestAsync("status", null, CancellationToken.None);
        var before = CurrentHandleCount();
        for (var i = 0; i < 50; i++)
        {
            using var dir = TempDir.Create("dbglink-handle-");
            // 1-byte body: passes the length gate, hits the file-owner
            // check, then fails JSON parsing (no network involved).
            File.WriteAllText(Path.Combine(dir, "ghidra-bridge-test.json"), "x");
            using var client = new GhidraClient(dir);
            _ = await client.RequestAsync("status", null, CancellationToken.None);
        }
        var after = CurrentHandleCount();
        Assert.True(after <= before + 8,
            $"GhidraClient endpoint ownership check leaked handles: {before} -> {after}");
    }

    [Fact]
    public void OrphanCleanup_DisposesEnumeratedProcesses()
    {
        if (!OperatingSystem.IsWindows())
            return;
        using var dir = TempDir.Create("dbglink-handle-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        sink!.TryOrphanCleanup();
        var before = CurrentHandleCount();
        for (var i = 0; i < 5; i++)
            sink.TryOrphanCleanup();
        var after = CurrentHandleCount();
        Assert.True(after <= before + 16,
            $"TelemetryFileSink.TryOrphanCleanup leaked handles: {before} -> {after}");
    }
}
