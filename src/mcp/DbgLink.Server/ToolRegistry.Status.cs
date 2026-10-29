using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;
namespace DbgLink.Server;

/// <summary>IMPL-4 View slice (TELEMETRY-T4 §2): pure status/telemetry renderer.
/// Pure function: snapshot -&gt; text/JSON. Forbidden: file I/O, timers,
/// ServerMetrics/TelemetryFileSink state access, await, long locks.
/// The timestamp comes in via <paramref name="updatedUtc"/> from the caller.
/// Markdown delegates to DigestFormatter (IMPL-2's file, read-only use,
/// byte-compat with today's digest) with the clock spliced for determinism;
/// the JSON projection is native here (T4 §3.2).</summary>
internal interface IStatusRenderer
{
    /// <summary>Markdown for digest.md and the status text section.
    /// Deterministic from the arguments + <paramref name="updatedUtc"/>.</summary>
    string RenderMarkdown(
        JsonObject snapshot,
        string[] recentFailures,
        long dropped,
        long loggedLines,
        long fileLines,
        DateTimeOffset updatedUtc);

    /// <summary>JSON "telemetry" node for GetServerStatus. Returns a new
    /// JsonObject; the input snapshot is never mutated. When
    /// <paramref name="sections"/> is null or empty the default diet node is
    /// returned (all groups, capped); otherwise only the requested groups
    /// plus schemaVersion/updated are kept.</summary>
    JsonObject RenderJson(
        JsonObject snapshot,
        string[] recentFailures,
        long dropped,
        long loggedLines,
        long fileLines,
        DateTimeOffset updatedUtc,
        IReadOnlySet<string>? sections = null);
}

/// <summary>On-demand extras for the status path (T4 §5 path B: no file I/O).
/// File-backed values (recent failures ring, drop counter, cached line count)
/// live in the Store slice; until it exposes them,
/// <see cref="FromSnapshot"/> supplies honest in-memory defaults
/// (fileLines -1 ⇒ JSON null).
/// The Store slice may later set
/// <see cref="ToolRegistry.TelemetryExtrasProvider"/> additively.</summary>
internal sealed record TelemetryStatusExtras(
    string[] RecentFailures,
    long Dropped,
    long LoggedLines,
    long FileLines)
{
    internal static TelemetryStatusExtras FromSnapshot(JsonObject snapshot)
    {
        var total = StatusRenderer.GetLong((snapshot["toolsSummary"] as JsonObject), "totalCalls", 0);
        return new TelemetryStatusExtras([], 0, total, -1);
    }
}

internal sealed class StatusRenderer : IStatusRenderer
{
    // Budgets (T4 §4): B1 markdown cap, B9 status-node cap, B7 render tops.
    // The JSON diet (w10): no "bytes" node, no topLargestAvgOut (dup of
    // topLargestTotal), no errorsByCode map (topErrorCode suffices), tops of
    // 3, 5 recent failures, 8 http codes — worst case stays ≤8KB so the
    // default status call is model-cheap.
    // Token diet (t2nt): per-process real-BPE totals live in
    // topLargestTotal; uptimeSeconds is dropped in favor of
    // the pinned updated clock; topSlowest rows drop avgMs (p95/max plus
    // counts stay). The raw ServerMetrics snapshot (launcher /metrics shape
    // + digest input) is untouched.
    internal const int MarkdownCapChars = 32 * 1024;
    internal const int TelemetryNodeCapChars = 64 * 1024;
    internal const int RenderTopN = 3;
    internal const int RenderSessionTopN = 3;
    internal const int RenderFailuresCap = 5;
    internal const int RenderLineChars = 512;
    internal const int RenderHttpStatusCap = 8;

    internal static readonly StatusRenderer Shared = new();

    public string RenderMarkdown(
        JsonObject snapshot,
        string[] recentFailures,
        long dropped,
        long loggedLines,
        long fileLines,
        DateTimeOffset updatedUtc)
    {
        try
        {
            // T4 rule 2: input is already cut to ≤10 by the caller; Take(10)
            // is a guard, not logic.
            var failures = (recentFailures ?? []).Take(RenderFailuresCap).ToArray();
            // Byte-compat with today's digest: the body is DigestFormatter's.
            // Its only impurity (UtcNow for "updated:") is spliced below so
            // the same input ⇒ the same output (T4 rule 1).
            var text = DigestFormatter.Format(snapshot, failures, dropped, loggedLines, fileLines);
            text = SpliceUpdatedTimestamp(text, updatedUtc);
            // B1: hard cap, enforced in code, not by agreement.
            if (text.Length > MarkdownCapChars)
                text = text[..MarkdownCapChars];
            return text;
        }
        catch
        {
            // T4 rule 3: render errors never escape.
            return "# DBGLink telemetry digest\n(unavailable)\n";
        }
    }

    public JsonObject RenderJson(
        JsonObject snapshot,
        string[] recentFailures,
        long dropped,
        long loggedLines,
        long fileLines,
        DateTimeOffset updatedUtc,
        IReadOnlySet<string>? sections = null)
    {
        try
        {
            var node = RenderJsonCore(snapshot, recentFailures, dropped, fileLines, updatedUtc);
            ApplySections(node, sections);
            // B9: ≤64KB serialized. Tops are already capped (B7), so only the
            // failure tail can overflow: trim from the end, keep counters exact.
            var failures = node["recentFailures"] as JsonArray ?? new JsonArray();
            var inputCount = (recentFailures ?? []).Take(RenderFailuresCap).Count();
            while (node.ToJsonString().Length > TelemetryNodeCapChars && failures.Count > 0)
                failures.RemoveAt(failures.Count - 1);
            if (node.ContainsKey("recentFailures") && failures.Count < inputCount)
                node["recentFailuresTruncated"] = true;
            return node;
        }
        catch
        {
            return new JsonObject { ["unavailable"] = true };
        }
    }

    /// <summary>Parse the GetServerStatus "sections" argument into the
    /// requested group set. Null/empty = default (all groups). Never throws:
    /// unreadable input falls back to the default. Unknown names are dropped
    /// (the MCP schema enum already rejects them at the gate).</summary>
    internal static HashSet<string>? ParseStatusSections(JsonElement? arguments)
    {
        try
        {
            if (arguments is not { ValueKind: JsonValueKind.Object } ||
                !arguments.Value.TryGetProperty("sections", out var value))
                return null;
            if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                return null;
            if (value.ValueKind != JsonValueKind.Array)
                return null;
            HashSet<string>? set = null;
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                    continue;
                var name = item.GetString()?.Trim().ToLowerInvariant();
                if (name is "summary" or "telemetry" or "backends" or "sessions" or "http")
                    (set ??= new HashSet<string>(StringComparer.Ordinal)).Add(name);
            }
            return set;
        }
        catch
        {
            return null;
        }
    }

    private static void ApplySections(JsonObject node, IReadOnlySet<string>? sections)
    {
        // Null/empty = default diet node: every group stays.
        if (sections is null || sections.Count == 0)
            return;
        // schemaVersion + updated always stay: they identify the payload.
        if (!sections.Contains("summary"))
        {
            node.Remove("uptimeSeconds");
            node.Remove("total");
            node.Remove("queues");
            node.Remove("dropped");
        }
        if (!sections.Contains("telemetry"))
        {
            node.Remove("topSlowest");
            node.Remove("topLargestTotal");
            node.Remove("topErrors");
            node.Remove("recentFailures");
            node.Remove("recentFailuresTruncated");
        }
        if (!sections.Contains("backends"))
            node.Remove("backends");
        if (!sections.Contains("sessions"))
            node.Remove("sessions");
        if (!sections.Contains("http"))
            node.Remove("http");
    }

    private static JsonObject RenderJsonCore(
        JsonObject snapshot,
        string[] recentFailures,
        long dropped,
        long fileLines,
        DateTimeOffset updatedUtc)
    {
        var summary = snapshot["toolsSummary"] as JsonObject;
        var totalCalls = GetLong(summary, "totalCalls", 0);
        var totalOk = GetLong(summary, "totalOk", 0);

        var failures = (recentFailures ?? [])
            .Take(RenderFailuresCap)
            .Select(line => line.Length > RenderLineChars ? line[..RenderLineChars] : line)
            .ToArray();

        return new JsonObject
        {
            ["schemaVersion"] = GetLong(snapshot, "schemaVersion", 2),
            ["updated"] = updatedUtc.ToString("O", CultureInfo.InvariantCulture),
            ["total"] = new JsonObject
            {
                ["calls"] = totalCalls,
                ["ok"] = totalOk,
            },
            ["topSlowest"] = ProjectTopSlowest(summary),
            ["topLargestTotal"] = ProjectTopLargestTotal(summary),
            ["topErrors"] = ProjectTopErrors(summary),
            ["backends"] = ProjectBackends(snapshot["backends"] as JsonObject),
            ["http"] = ProjectHttp(snapshot),
            ["sessions"] = ProjectSessions(snapshot["sessions"] as JsonObject),
            ["queues"] = ProjectQueues(snapshot["queues"] as JsonObject),
            ["dropped"] = ProjectDropped(dropped, fileLines),
            ["recentFailures"] = new JsonArray(failures.Select(f => (JsonNode)JsonValue.Create(f)!).ToArray()),
        };
    }

    private static JsonObject ProjectDropped(long dropped, long fileLines)
    {
        var node = new JsonObject
        {
            ["queueDropped"] = Math.Max(0, dropped),
            // toolLines repeated total.calls by construction (one line per
            // completed call): dropped instead of exported twice.
        };
        // T4 §3.2: -1 (unknown without a disk scan) ⇒ explicit JSON null,
        // never 0 and never a missing key. (Assigning null would remove the
        // key, so parse the null literal instead.)
        node["fileLines"] = fileLines < 0 ? JsonNode.Parse("null") : JsonValue.Create(Math.Max(0, fileLines));
        return node;
    }

    private static JsonArray ProjectTopSlowest(JsonObject? summary)
    {
        // Input is p95 desc from the Aggregator; View only re-sorts ties by
        // maxMs desc (T4 §3.2) and cuts to RenderTopN (B7 diet). Token diet:
        // avgMs is dropped (p95/max plus counts stay); the digest line that
        // prints avg reads the raw snapshot summary, not this node.
        var rows = (summary?["topSlowest"] as JsonArray)?.OfType<JsonObject>() ?? [];
        return new JsonArray(rows
            .Select(row => new
            {
                Tool = GetString(row, "tool", "_unknown"),
                Calls = GetLong(row, "calls", 0),
                P95Ms = GetLong(row, "p95Ms", 0),
                MaxMs = GetLong(row, "maxMs", 0),
            })
            .OrderByDescending(r => r.P95Ms)
            .ThenByDescending(r => r.MaxMs)
            .Take(RenderTopN)
            .Select(r => (JsonNode)new JsonObject
            {
                ["tool"] = r.Tool,
                ["calls"] = r.Calls,
                ["p95Ms"] = r.P95Ms,
                ["maxMs"] = r.MaxMs,
            }).ToArray());
    }

    private static JsonArray ProjectTopLargestTotal(JsonObject? summary)
    {
        var rows = (summary?["topLargestTotal"] as JsonArray)?.OfType<JsonObject>() ?? [];
        return new JsonArray(rows
            .Take(RenderTopN)
            .Select(row => (JsonNode)new JsonObject
            {
                ["tool"] = GetString(row, "tool", "_unknown"),
                ["calls"] = GetLong(row, "calls", 0),
                ["totalBytesIn"] = GetLong(row, "totalBytesIn", 0),
                ["totalBytesOut"] = GetLong(row, "totalBytesOut", 0),
                ["totalTokens"] = GetLong(row, "totalTokens", 0),
            }).ToArray());
    }

    private static JsonArray ProjectTopErrors(JsonObject? summary)
    {
        var rows = (summary?["topErrors"] as JsonArray)?.OfType<JsonObject>() ?? [];
        return new JsonArray(rows
            .Take(RenderTopN)
            .Select(row => (JsonNode)new JsonObject
            {
                ["tool"] = GetString(row, "tool", "_unknown"),
                ["calls"] = GetLong(row, "calls", 0),
                ["errors"] = GetLong(row, "errors", 0),
                ["errorRate"] = GetDouble(row, "errorRate", 0),
                ["topErrorCode"] = GetString(row, "topErrorCode", "-"),
                ["topErrorCodeCount"] = GetLong(row, "topErrorCodeCount", 0),
            }).ToArray());
    }

    private static JsonObject ProjectBackends(JsonObject? backends)
    {
        return new JsonObject
        {
            ["native"] = ProjectBackend(backends?["native"] as JsonObject, null, null),
            ["ghidra"] = ProjectBackend(
                backends?["ghidra"] as JsonObject,
                GetLong(backends?["ghidra"] as JsonObject, "cacheHits", 0),
                GetLong(backends?["ghidra"] as JsonObject, "cacheMisses", 0)),
            ["fanoutSubCalls"] = GetLong(backends, "fanoutSubCalls", 0),
        };
    }

    private static JsonObject ProjectBackend(JsonObject? backend, long? cacheHits, long? cacheMisses)
    {
        var calls = GetLong(backend, "calls", 0);
        var ok = GetLong(backend, "ok", 0);
        var node = new JsonObject
        {
            ["calls"] = calls,
            ["ok"] = ok,
            ["avgMs"] = GetDouble(backend, "avgMs", 0),
            ["maxMs"] = GetLong(backend, "maxMs", 0),
            // Absence means no errors: do not spend bytes on a null literal.
        };
        if (TopError(backend?["errors"] as JsonObject) is JsonNode topError)
            node["topError"] = topError;
        if (cacheHits.HasValue) node["cacheHits"] = cacheHits.Value;
        if (cacheMisses.HasValue) node["cacheMisses"] = cacheMisses.Value;
        return node;
    }

    private static JsonNode? TopError(JsonObject? errors)
    {
        try
        {
            if (errors is null || errors.Count == 0) return null;
            var top = errors.OrderByDescending(p => SafeLong(p.Value)).First();
            return new JsonObject
            {
                ["code"] = top.Key,
                ["count"] = SafeLong(top.Value),
            };
        }
        catch { return null; }
    }

    private static JsonObject ProjectHttp(JsonObject snapshot)
    {
        return new JsonObject
        {
            ["status"] = CopyDictLong(snapshot["httpStatus"] as JsonObject, RenderHttpStatusCap),
            ["authFailures"] = GetLong(snapshot, "authFailures", 0),
            ["originRejects"] = GetLong(snapshot, "originRejects", 0),
        };
    }

    private static JsonObject ProjectSessions(JsonObject? sessions)
    {
        var bySession = sessions?["bySession"] as JsonObject;
        var top = new JsonArray();
        try
        {
            if (bySession is not null)
            {
                foreach (var pair in bySession
                    .OrderByDescending(p => SafeLong(p.Value))
                    .Take(RenderSessionTopN))
                {
                    top.Add(new JsonObject
                    {
                        ["id"] = pair.Key,
                        ["calls"] = SafeLong(pair.Value),
                    });
                }
            }
        }
        catch { }
        return new JsonObject
        {
            // Lifecycle totals (registered/closed/replaced) are process
            // diagnostics: a caller acts on the active count and the busiest
            // sessions, not on counters since startup.
            ["topSessions"] = top,
            // Enriched by LocalMcpServer.GetMetricsSnapshot; 0 on the raw path.
            ["active"] = GetLong(sessions, "active", 0),
        };
    }

    private static JsonObject ProjectQueues(JsonObject? queues)
    {
        return new JsonObject
        {
            ["httpCurrent"] = GetLong(queues, "httpCurrent", 0),
            ["httpMax"] = GetLong(queues, "httpMax", 0),
            ["executionCurrent"] = GetLong(queues, "executionCurrent", 0),
            ["executionMax"] = GetLong(queues, "executionMax", 0),
        };
    }

    private static JsonObject CopyDictLong(JsonObject? source, int cap)
    {
        var node = new JsonObject();
        try
        {
            if (source is null) return node;
            foreach (var pair in source.OrderByDescending(p => SafeLong(p.Value)).Take(cap))
                node[pair.Key] = SafeLong(pair.Value);
        }
        catch { }
        return node;
    }

    private static string SpliceUpdatedTimestamp(string text, DateTimeOffset updatedUtc)
    {
        // DigestFormatter stamps "updated: <wall-clock> | uptime: …"; replace
        // just the clock so the render is a pure function of its arguments.
        const string marker = "updated: ";
        var start = text.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0) return text;
        start += marker.Length;
        var end = text.IndexOf(" | ", start, StringComparison.Ordinal);
        if (end < 0) return text;
        return string.Concat(
            text.AsSpan(0, start),
            updatedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            text.AsSpan(end));
    }

    internal static long GetLong(JsonObject? obj, string name, long fallback)
    {
        try { return obj?[name]?.GetValue<long>() ?? fallback; }
        catch { return fallback; }
    }

    internal static double GetDouble(JsonObject? obj, string name, double fallback)
    {
        try { return obj?[name]?.GetValue<double>() ?? fallback; }
        catch { return fallback; }
    }

    internal static string GetString(JsonObject? obj, string name, string fallback)
    {
        try { return obj?[name]?.GetValue<string>() ?? fallback; }
        catch { return fallback; }
    }

    private static long SafeLong(JsonNode? node)
    {
        try { return node?.GetValue<long>() ?? 0; }
        catch { return 0; }
    }
}

internal sealed partial class ToolRegistry
{
    /// <summary>View seam (T4 §6): in-memory snapshot source is
    /// <see cref="GhidraOpenOperations.Telemetry"/> (already wired by the
    /// server); file-backed extras default via
    /// <see cref="TelemetryStatusExtras.FromSnapshot"/>. The Store slice may
    /// set this provider additively to supply the real drop counter and cached
    /// file-line count — no edits needed here.</summary>
    internal static Func<JsonObject, TelemetryStatusExtras>? TelemetryExtrasProvider { get; set; }

    /// <summary>Renderer override for tests; defaults to the shared pure
    /// <see cref="StatusRenderer"/>.</summary>
    internal static IStatusRenderer TelemetryRenderer { get; set; } = StatusRenderer.Shared;

    /// <summary>View seam (T4 §6): single enrichment point. When set, the
    /// status node renders from this snapshot (e.g.
    /// LocalMcpServer.GetMetricsSnapshot with sessions.active + config)
    /// instead of the raw <see cref="GhidraOpenOperations.Telemetry"/>
    /// snapshot. Falls back to the raw in-memory snapshot when null, so the
    /// node works with zero cross-file wiring. Never does file I/O itself:
    /// the provider must hand back an already-built JsonObject.</summary>
    internal static Func<JsonObject>? TelemetrySnapshotProvider { get; set; }

    private static async Task<string> ReadServerStatusAsync(AnalysisContext context, GhidraOpenOperations open, ToolInvocation call)
    {
        using var probe = CancellationTokenSource.CreateLinkedTokenSource(call.CancellationToken);
        probe.CancelAfter(1500);
        var sections = StatusRenderer.ParseStatusSections(call.Arguments);
        // The Ghidra readiness probe feeds the ghidra node, which belongs to
        // the summary/backends view. A caller that explicitly filters those
        // away does not need the extra probe (2 wire calls -> 1).
        var probeGhidra = sections is null || sections.Count == 0 ||
            sections.Contains("summary") || sections.Contains("backends");
        // Native status and the Ghidra readiness probe are independent. Start
        // both together so the common case costs one round trip, not two.
        var nativeTask = context.Bridge.RequestAsync("GetServerStatus", call.Arguments, call.CancellationToken);
        var ghidraTask = probeGhidra
            ? context.Ghidra.RequestAsync("status", null, probe.Token)
            : null;
        string nativeRaw;
        try
        {
            nativeRaw = await nativeTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (call.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // A dead debugger pipe (process exited) must not surface as the
            // dispatcher's generic catch-all. Mirror the Ghidra probe below:
            // return a specific envelope naming the dead analysisId with a
            // close/reopen hint so the model can recover.
            probe.Cancel();
            var analysisId = context.AnalysisId;
            return BridgeEnvelope.Error("debugger_unreachable",
                $"Debugger for analysis session '{analysisId}' is unreachable. The debugger process may have exited; " +
                "call ListAnalysisSessions to confirm live sessions, then CloseAnalysisSession/ReopenAnalysisSession or OpenDebugTarget to restart. Do not poll.");
        }
        var native = JsonNode.Parse(nativeRaw)!.AsObject();
        JsonNode? ghidra = null;
        if (ghidraTask is not null)
        {
            try { ghidra = JsonNode.Parse(await ghidraTask.ConfigureAwait(false)); }
            catch (OperationCanceledException) when (!call.CancellationToken.IsCancellationRequested)
            {
                ghidra = JsonNode.Parse(BridgeEnvelope.Error("ghidra_status_timeout", "Ghidra readiness probe timed out. The Ghidra process may have exited; check ListAnalysisSessions (ghidraRunning:false means exited) and CloseAnalysisSession/ReopenAnalysisSession to restart. If still running, back off, then retry once."));
            }
        }
        // The Ghidra program summary repeats path/hash/image bounds; when a
        // program is open, keep the structured copy and drop the flat echoes.
        if (ghidra?["result"] is JsonObject ghidraResult &&
            ghidraResult["program"] is JsonObject)
        {
            ghidraResult.Remove("executablePath");
            ghidraResult.Remove("sha256");
            ghidraResult.Remove("minAddress");
            ghidraResult.Remove("maxAddress");
        }
        var queue = open.Queue();
        native["analysisId"] = context.AnalysisId;
        // Brevity: the import queue is a readiness signal, not a log dump.
        // Cap inline entries; totals stay exact so pollers can detect drain.
        const int maxQueueEntries = 8;
        var queued = queue.Take(maxQueueEntries).ToArray();
        if (ghidraTask is not null)
        {
            var queueArray = new JsonArray(queued.Select(entry => entry?.DeepClone()).ToArray());
            native["ghidra"] = new JsonObject
            {
                ["ready"] = ghidra?["ok"]?.GetValue<bool>() == true && ghidra?["result"]?["available"]?.GetValue<bool>() == true,
                ["importing"] = queue.Any(q => q?["phase"]?.GetValue<string>() == "importing"),
                ["queue"] = queueArray,
                ["queueTotal"] = queue.Count,
                ["queueTruncated"] = queue.Count > queued.Length,
                ["status"] = ghidra
            };
        }
        // attached mirrors the root debugging/ok fields; module was always
        // null and available duplicated ok, so neither earned a key. Repeat
        // it only when the nested value actually disagrees with the root.
        var nestedDebugging = native["result"]?["debugging"];
        var rootDebugging = native["debugging"];
        var attached = nestedDebugging ?? rootDebugging;
        if (attached is not null && !JsonNode.DeepEquals(attached, rootDebugging))
            native["debugger"] = new JsonObject { ["attached"] = attached.DeepClone() };
        // T4 §3.2 path B (on-demand): exactly one new top-level node. Pure
        // CPU after the probe above (<1ms under B7 caps); no File.*, no
        // CountEventLines, no timer waits — a slow disk cannot stall the
        // readiness probe (B11). Existing fields are untouched. The optional
        // "sections" argument filters the telemetry groups (w10 token diet);
        // it is forwarded to the native bridge untouched, which ignores
        // GetServerStatus params (NativePipeServer returns a fixed payload).
        native["telemetry"] = BuildTelemetryNode(open, sections);
        return native.ToJsonString();
    }

    private static JsonNode BuildTelemetryNode(GhidraOpenOperations open, HashSet<string>? sections)
    {
        try
        {
            JsonObject? snapshot = null;
            try { snapshot = TelemetrySnapshotProvider?.Invoke(); }
            catch { snapshot = null; }
            if (snapshot is null)
            {
                var telemetry = open.Telemetry;
                if (telemetry is null)
                    return new JsonObject { ["unavailable"] = true };
                try { snapshot = telemetry.Snapshot(); }
                catch { return new JsonObject { ["unavailable"] = true }; }
            }
            TelemetryStatusExtras extras;
            try { extras = TelemetryExtrasProvider?.Invoke(snapshot) ?? TelemetryStatusExtras.FromSnapshot(snapshot); }
            catch { extras = TelemetryStatusExtras.FromSnapshot(snapshot); }
            // The snapshot above was taken mid-flight: this GetServerStatus
            // call's own backend RPC is already counted in backends
            // (first-wins attribution records it before we render), but its
            // tool completion lands only after we return. On a fresh server
            // that reads as native(1)+ghidra(0) > total(0), so count the
            // in-flight call (assumed ok; the completion corrects the split
            // right after) and keep backends<=total true in the degenerate
            // case. Steady state is unaffected: it was already coherent and
            // stays so with the same +1 on both sides.
            IncludeInflightStatusCall(snapshot);
            try
            {
                return TelemetryRenderer.RenderJson(
                    snapshot,
                    extras.RecentFailures ?? [],
                    extras.Dropped,
                    extras.LoggedLines,
                    extras.FileLines,
                    DateTimeOffset.UtcNow,
                    sections);
            }
            catch { return new JsonObject { ["unavailable"] = true }; }
        }
        catch { return new JsonObject { ["unavailable"] = true }; }
    }

    /// <summary>Counts the in-flight GetServerStatus call in the snapshot it
    /// reports (see BuildTelemetryNode): +1 totalCalls and +1 totalOk, so the
    /// error split is untouched and backends&lt;=total holds even when this
    /// status call is the first tool call on a fresh server. Saturating,
    /// never throws; mutates only the toolsSummary node.</summary>
    private static void IncludeInflightStatusCall(JsonObject snapshot)
    {
        try
        {
            if (snapshot["toolsSummary"] is not JsonObject summary)
                return;
            var total = StatusRenderer.GetLong(summary, "totalCalls", 0);
            var ok = StatusRenderer.GetLong(summary, "totalOk", 0);
            if (total < long.MaxValue)
                summary["totalCalls"] = total + 1;
            if (ok < long.MaxValue)
                summary["totalOk"] = ok + 1;
        }
        catch { }
    }
}
