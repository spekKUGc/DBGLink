using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>
    /// Static-read fan-out width for BatchStaticQueries. Matches
    /// GhidraClient.MaxConcurrentBridgeRequests, which matches the bridge's
    /// MAX_CONNECTION_WORKERS: more would only queue in the bridge, fewer would
    /// leave its decompiler workers idle.
    /// </summary>
    private const int MaxConcurrentStaticReads = 4;

    private static JsonObject BatchInputSchema(string methodDescription) => new()
    {
        ["type"] = "object",
        ["additionalProperties"] = false,
        ["required"] = new JsonArray("requests"),
        ["properties"] = new JsonObject
        {
            ["requests"] = new JsonObject
            {
                ["type"] = "array",
                ["minItems"] = 1,
                ["maxItems"] = 16,
                ["items"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray("method", "arguments"),
                    ["properties"] = new JsonObject
                    {
                        ["method"] = TextRule(methodDescription, 64),
                        ["arguments"] = new JsonObject { ["type"] = "object" }
                    }
                }
            },
            ["autoPause"] = BoolRule(false, AutoPauseBatchDescription),
        }
    };

    /// <summary>
    /// Batch-local dispatch allowlist (C2): methods served in-process by a
    /// caller-supplied local dispatcher instead of a bridge pipe. Bridge-only
    /// batches (localDispatch null) never consult this set. Admission to a
    /// batch's allowedMethods stays with the owning workstream; this set only
    /// picks the sender once a method is admitted.
    /// </summary>
    internal static readonly HashSet<string> LocalBatchMethods = new(StringComparer.Ordinal)
    {
        "TriageStrings", "TriageImports", "Triage", "GetAnalysisQueue", "EvaluateExpressions", "GetAnalysisSnapshot",
    };

    /// <summary>Echo-safe method name for errors: control chars stripped, capped at 64.</summary>
    private static string DisplayMethod(string method)
    {
        var clean = new string(method.Where(character => !char.IsControl(character)).ToArray());
        return clean.Length > 64 ? clean[..64] + "...[truncated]" : clean;
    }

    /// <summary>Compact first-seen-order histogram: InspectFunctionx3+ListSymbolsx1.</summary>
    private static string DescribeBatchMix(IEnumerable<string> methods)
    {
        var counts = new List<(string Method, int Count)>();
        foreach (var method in methods)
        {
            var index = counts.FindIndex(entry => entry.Method == method);
            if (index < 0) counts.Add((method, 1));
            else counts[index] = (method, counts[index].Count + 1);
        }
        return string.Join("+", counts.Select(entry => entry.Count == 1 ? entry.Method : $"{entry.Method}x{entry.Count}"));
    }

    /// <summary>
    /// Shared executor for BatchDebuggerOperations and BatchStaticQueries:
    /// validate the batch up front, resolve batch-level autoPause once, then
    /// run requests under one deadline with a byte-bounded, order-preserving
    /// result list.
    /// localDispatch (C2) is null on the historical bridge-only path: every
    /// admitted method goes to send and a schema-validation failure aborts the
    /// whole batch. When provided, methods in LocalBatchMethods are dispatched
    /// locally, everything else still goes to send, and schema-validation
    /// failures become per-row errors. Family mismatch stays a hard error with
    /// index in both modes, and no hard error ever runs a backend call first.
    /// </summary>
    internal async Task<string> ExecuteBatchAsync(
        ToolInvocation call,
        Func<string, JsonElement?, CancellationToken, Task<string>> send,
        HashSet<string> allowedMethods,
        Func<string, string> unsupportedMessage,
        int deadlineMilliseconds,
        bool rejectNestedAnalysisId,
        Func<string, JsonElement?, CancellationToken, Task<string>>? localDispatch = null,
        bool parallelReads = false)
    {
        var requests = call.Arguments!.Value.GetProperty("requests").EnumerateArray().ToArray();
        // Validate the entire batch before any backend request, including disallowed nested session switches.
        // Errors name the offending index: one batch holds one family (static reads here,
        // debugger ops in BatchDebuggerOperations) — mixing them is rejected, not executed.
        var localFanOut = localDispatch is not null;
        var rowErrors = localFanOut ? new Dictionary<int, string>() : null;
        for (var validateIndex = 0; validateIndex < requests.Length; validateIndex++)
        {
            var request = requests[validateIndex];
            var method = request.GetProperty("method").GetString()!;
            var args = request.GetProperty("arguments");
            if (!IsValidToolMethodName(method))
                return BridgeEnvelope.Error("invalid_batch", $"Request #{validateIndex} ('{DisplayMethod(method)}'): method name is not a valid tool name.");
            _tools.TryGetValue(method, out var tool);
            BatchOnlySchemas.TryGetValue(method, out var batchSchema);
            if (!allowedMethods.Contains(method) || (tool is null && batchSchema is null))
                return BridgeEnvelope.Error("invalid_batch", $"Request #{validateIndex} ('{method}'): {unsupportedMessage(method)}");
            // P3 batch-only singles (no top-level registration) validate
            // against the BatchOnlySchemas table; registered tools use their
            // advertised schema. Either way the row sees the same rules.
            var error = ToolArgumentRules.Validate(
                tool is not null ? (JsonObject)tool.Metadata["inputSchema"]! : batchSchema!, args);
            if (error is not null)
            {
                // Bridge-only batches keep the historical whole-batch abort;
                // fan-out batches isolate the schema failure to its row.
                if (!localFanOut)
                    return BridgeEnvelope.Error("invalid_batch", $"Request #{validateIndex} ('{method}'): {error}");
                rowErrors![validateIndex] = error;
            }
            // autoPause is a top-level-tool-only flag: the batch forwards sub-args
            // straight to the bridge, which would both leak an unknown property and
            // skip the pause/resume the caller asked for. Make the caller use the
            // direct tool instead of silently stripping a safety flag.
            if (method is "WriteMemory" or "SetRegister" &&
                args.ValueKind == JsonValueKind.Object && args.TryGetProperty("autoPause", out _))
                return BridgeEnvelope.Error("invalid_batch", $"Request #{validateIndex} ('{method}'): autoPause is not supported inside a batch; call {method} directly with autoPause:true.");
            if (rejectNestedAnalysisId && args.TryGetProperty("analysisId", out _))
                return BridgeEnvelope.Error("invalid_batch", $"Request #{validateIndex} ('{method}'): set analysisId on the batch, not individual requests.");
        }
        // Telemetry: sub-method mix (first-seen order) so batch-heavy traffic
        // can be attributed without dumping the whole request list.
        call.Detail = DescribeBatchMix(requests.Select(r => r.GetProperty("method").GetString()!));

        // Batch-level autoPause (C3): resolved ONCE here, never per item.
        var wePaused = false;
        if (ToolSupport.ReadArgumentBool(call.Arguments, "autoPause", false))
        {
            // Static batches hit Ghidra only: pausing the live target is
            // meaningless there, so reject before any backend call instead of
            // burning a Ghidra round trip on a pause that can never apply.
            if (!ReferenceEquals(allowedMethods, DebuggerBatchMethods))
                return BridgeEnvelope.Error("invalid_batch",
                    "autoPause is only supported by BatchDebuggerOperations; static reads never touch the live target, so retry without autoPause.");
            var (paused, pauseError) = await PauseBatchTargetAsync(send, call.CancellationToken).ConfigureAwait(false);
            if (pauseError is not null)
                return pauseError;
            wePaused = paused;
        }

        var results = new JsonArray();
        var used = 0;
        var index = 0;
        var reason = "";
        var failed = false;
        var dedup = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        // Leave time to return partial results before the outer MCP deadline.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(call.CancellationToken);
        deadline.CancelAfter(deadlineMilliseconds);
        var resumed = true;
        // Static reads are independent, so the distinct ones are dispatched up
        // front (bounded by the bridge's own worker count) and replayed in
        // request order below. A sequential loop leaves three of the four
        // Ghidra bridge slots idle for the whole batch.
        using var prefetchGate = new SemaphoreSlim(MaxConcurrentStaticReads, MaxConcurrentStaticReads);
        Dictionary<string, string>? prefetched = null;
        HashSet<string>? prefetchCancelled = null;
        try
        {
            if (parallelReads && requests.Length > 1)
            {
                var distinct = new Dictionary<string, (int Index, string Method, JsonElement Args,
                    Func<string, JsonElement?, CancellationToken, Task<string>> Send)>(StringComparer.Ordinal);
                for (var prefetchIndex = 0; prefetchIndex < requests.Length; prefetchIndex++)
                {
                    if (rowErrors is not null && rowErrors.ContainsKey(prefetchIndex))
                        continue;
                    var request = requests[prefetchIndex];
                    var method = request.GetProperty("method").GetString()!;
                    var args = ClampBatchBudget(method, request.GetProperty("arguments"));
                    var key = CanonicalBatchKey(method, args);
                    if (distinct.ContainsKey(key))
                        continue;
                    // Same sender choice as the replay loop: local composites
                    // (triage) stay on the local dispatcher.
                    var itemSender = localDispatch is not null && LocalBatchMethods.Contains(method)
                        ? localDispatch : send;
                    distinct[key] = (prefetchIndex, method, args, itemSender);
                }

                async Task<(string Key, string? Raw, bool Cancelled)> FetchAsync(
                    string key, (int Index, string Method, JsonElement Args,
                        Func<string, JsonElement?, CancellationToken, Task<string>> Send) item)
                {
                    try
                    {
                        await prefetchGate.WaitAsync(deadline.Token).ConfigureAwait(false);
                        try
                        {
                            return (key, await item.Send(item.Method, item.Args, deadline.Token).ConfigureAwait(false), false);
                        }
                        finally { prefetchGate.Release(); }
                    }
                    catch (OperationCanceledException) when (!call.CancellationToken.IsCancellationRequested)
                    {
                        return (key, null, true);
                    }
                    catch (ModelContextProtocol.McpException exception)
                    {
                        var message = exception.Message;
                        if (message.Length > 256) message = message[..256] + "...[truncated]";
                        return (key, BridgeEnvelope.Error("batch_item_error",
                            $"Request #{item.Index} ('{item.Method}'): {message}"), false);
                    }
                }

                var outcomes = await Task.WhenAll(
                    distinct.Select(entry => FetchAsync(entry.Key, entry.Value))).ConfigureAwait(false);
                prefetched = new Dictionary<string, string>(StringComparer.Ordinal);
                prefetchCancelled = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (key, raw, cancelled) in outcomes)
                {
                    if (cancelled) prefetchCancelled.Add(key);
                    else prefetched[key] = raw!;
                }
            }
            for (; index < requests.Length; index++)
            {
                var request = requests[index];
                var method = request.GetProperty("method").GetString()!;
                JsonNode? parsed;
                if (rowErrors is not null && rowErrors.TryGetValue(index, out var rowError))
                {
                    // Schema failure isolated to its row: no backend call, but
                    // the index+method envelope is preserved so the caller can
                    // fix that row and resume the rest.
                    parsed = JsonNode.Parse(BridgeEnvelope.Error("invalid_batch",
                        $"Request #{index} ('{method}'): {rowError}"));
                }
                else
                {
                    var args = ClampBatchBudget(method, request.GetProperty("arguments"));
                    var key = CanonicalBatchKey(method, args);
                    if (dedup.TryGetValue(key, out var cached))
                    {
                        parsed = cached?.DeepClone();
                    }
                    else
                    {
                        // Local-capable methods go to the local dispatcher when
                        // one is supplied; everything else keeps the sender.
                        string raw;
                        if (prefetched is not null)
                        {
                            var prefetchedKey = CanonicalBatchKey(method, args);
                            if (prefetchCancelled!.Contains(prefetchedKey))
                            {
                                reason = "deadline";
                                break;
                            }
                            raw = prefetched[prefetchedKey];
                        }
                        else
                        {
                            var sender = localDispatch is not null && LocalBatchMethods.Contains(method)
                                ? localDispatch : send;
                            try
                            {
                                raw = await sender(method, args, deadline.Token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (!call.CancellationToken.IsCancellationRequested)
                            {
                                reason = "deadline";
                                break;
                            }
                            catch (ModelContextProtocol.McpException exception)
                            {
                                // Executor-level rejections (e.g. SetBreakpoint without an
                                // addressable target) become per-item errors, not batch killers.
                                // Clip to 256 chars: index+method are already in the row envelope.
                                var msg = exception.Message;
                                if (msg.Length > 256) msg = msg[..256] + "...[truncated]";
                                raw = BridgeEnvelope.Error("batch_item_error",
                                    $"Request #{index} ('{method}'): {msg}");
                            }
                        }
                        try
                        {
                            parsed = JsonNode.Parse(raw);
                        }
                        catch (JsonException)
                        {
                            parsed = JsonValue.Create(raw);
                        }
                        dedup[key] = parsed?.DeepClone();
                    }
                }
                var row = new JsonObject
                {
                    ["index"] = index,
                    ["response"] = parsed
                };
                // The bridge request id is a constant correlator; the batch
                // already keys rows by index. Drop it from successful rows.
                if (parsed is JsonObject parsedRow &&
                    parsedRow["ok"] is JsonValue parsedOk &&
                    parsedOk.TryGetValue<bool>(out var parsedOkFlag) && parsedOkFlag)
                    parsedRow.Remove("id");
                var size = Encoding.UTF8.GetByteCount(row.ToJsonString());
                if (used + size > 200_000)
                {
                    reason = "output_limit";
                    break;
                }
                failed |= row["response"]?["ok"]?.GetValue<bool>() != true;
                results.Add(row);
                used += size;
            }
        }
        finally
        {
            // One resume per batch, even when an item transport failure or
            // cancellation unwinds the loop: a target we paused must have its
            // prior running state restored on every path. Never throws, so the
            // resume cannot mask the batch outcome already in flight.
            if (wePaused)
                resumed = await TryResumeBatchAsync(send).ConfigureAwait(false);
        }
        // A failed resume surfaces as an honest error, never as item results
        // that would imply the target is running again.
        if (wePaused && !resumed)
            return BridgeEnvelope.Error("debugger_resume_failed",
                "autoPause=true: the batch ran while paused, but resuming the target failed; " +
                "it may still be paused. Resume it (ControlDebuggerExecution action=run) before continuing.");
        var complete = index >= requests.Length;
        var partial = failed || !complete;
        // Complete batches omit the flags: absence means false, saving the
        // fixed envelope bytes on every all-success call.
        var envelope = new JsonObject
        {
            ["results"] = results,
        };
        if (partial)
            envelope["partial"] = true;
        if (!complete)
            envelope["truncated"] = true;
        if (!complete)
            envelope["nextIndex"] = index;
        if (!string.IsNullOrEmpty(reason))
            envelope["stopReason"] = reason;
        if (wePaused)
            envelope["autoPause"] = new JsonObject
            {
                ["resumed"] = true,
            };
        return new JsonObject
        {
            ["ok"] = true,
            ["result"] = envelope
        }.ToJsonString();
    }

    /// <summary>
    /// Batch-level autoPause pre-phase: read the live target state once, pause
    /// a running target, and wait for a stable pause before any item runs.
    /// Returns the pause ownership plus a terminal error: a non-null error
    /// stops the batch with zero item calls. Mirrors the LiveAnalysisTools
    /// autoPause honesty semantics (no-op when already paused, honest errors
    /// on pause/wait failures, best-effort resume when we paused but the
    /// target never stabilized).
    /// </summary>
    private static async Task<(bool WePaused, string? Error)> PauseBatchTargetAsync(
        Func<string, JsonElement?, CancellationToken, Task<string>> send,
        CancellationToken cancellationToken)
    {
        JsonNode? initial;
        try
        {
            initial = AnalysisFormatting.ReadBridgeResultNode(
                await send("GetSnapshotState", null, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { initial = null; }
        if (!IsUsableBatchStateNode(initial))
            return (false, BridgeEnvelope.Error("snapshot_state_unreadable",
                "autoPause=true needs the current paused/running state, but GetSnapshotState was unreadable. " +
                "The debugger was not paused or resumed. Pause the target (ControlDebuggerExecution action=pause) " +
                "and retry without autoPause."));
        if (!AnalysisFormatting.ReadNodeBool(initial, "debugging"))
        {
            // No live session to pause; the items report not_debugging themselves.
            return (false, null);
        }
        // Resume only when WE paused a RUNNING target. A paused (even
        // not-yet-stable) target must stay paused: autoPause must never flip a
        // paused debuggee to running.
        var wasRunning = AnalysisFormatting.ReadNodeBool(initial, "running");
        if (!wasRunning && AnalysisFormatting.ReadNodeBool(initial, "stableRead"))
        {
            // Already stably paused: the flag is a no-op.
            return (false, null);
        }

        if (wasRunning)
        {
            string pauseRaw;
            try
            {
                pauseRaw = await send("PauseDebugger", null, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                return (false, BridgeEnvelope.Error("debugger_pause_failed",
                    ToolSupport.AutoPausePauseFailure(exception)));
            }
            if (ToolSupport.AnalyzeBridgeResponse(pauseRaw).IsError)
                return (false, BridgeEnvelope.Error("debugger_pause_failed",
                    "autoPause=true: the debugger refused the pause request; the target was left running. " +
                    "Pause it (ControlDebuggerExecution action=pause) and retry without autoPause."));
        }

        if (!await WaitForBatchPauseAsync(send, cancellationToken).ConfigureAwait(false))
        {
            if (wasRunning)
            {
                // Best-effort restore only when we paused a running target; a
                // target that was already paused is left paused either way.
                await TryResumeBatchAsync(send).ConfigureAwait(false);
                return (false, BridgeEnvelope.Error("debugger_running_timeout",
                    "autoPause=true: the target did not reach a stable pause within the polling budget; " +
                    "a best-effort resume was attempted. Verify the state with GetAnalysisSnapshot before continuing."));
            }
            return (false, BridgeEnvelope.Error("debugger_running_timeout",
                "autoPause=true: the target did not reach a stable pause within the polling budget; " +
                "the target was already paused and was left paused. Verify the state with GetAnalysisSnapshot before continuing."));
        }
        return (wasRunning, null);
    }

    /// <summary>
    /// Batch-scope twin of the LiveAnalysisTools state check: a state response
    /// is usable when it carries at least one recognizable paused/running
    /// field. Kept next to its only caller so the batch pause contract stays
    /// explicit.
    /// </summary>
    private static bool IsUsableBatchStateNode(JsonNode? node)
    {
        if (node is not JsonObject obj)
            return false;
        foreach (var name in new[] { "debugging", "running", "stableRead" })
        {
            try
            {
                if (obj[name] is JsonValue value && value.TryGetValue<bool>(out _))
                    return true;
            }
            catch (Exception exception) when (exception is FormatException or InvalidOperationException)
            {
            }
        }
        return false;
    }

    /// <summary>
    /// Poll GetSnapshotState for a stable pause before any batch item runs.
    /// Same ~3s budget as the LiveAnalysisTools autoPause path
    /// (AutoPauseWaitAttempts x PausePollIntervalMs); only a real observed
    /// pause counts. Caller cancellation always rethrows.
    /// </summary>
    private static async Task<bool> WaitForBatchPauseAsync(
        Func<string, JsonElement?, CancellationToken, Task<string>> send,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < LiveAnalysisTools.AutoPauseWaitAttempts; attempt++)
        {
            try
            {
                var stateRaw = await send("GetSnapshotState", null, cancellationToken).ConfigureAwait(false);
                var stateNode = AnalysisFormatting.ReadBridgeResultNode(stateRaw);
                if (stateNode is JsonObject obj &&
                    AnalysisFormatting.ReadNodeBool(obj, "debugging") &&
                    !AnalysisFormatting.ReadNodeBool(obj, "running") &&
                    AnalysisFormatting.ReadNodeBool(obj, "stableRead"))
                    return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
            }
            try
            {
                await Task.Delay(LiveAnalysisTools.PausePollIntervalMs, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
        }
        return false;
    }

    /// <summary>
    /// Best-effort RunDebugger for batch autoPause: never throws, so a
    /// finally-stage resume cannot mask the batch outcome already in flight.
    /// CancellationToken.None: the restore must be attempted even when the
    /// caller went away, and a paused target is the safe direction anyway.
    /// </summary>
    private static async Task<bool> TryResumeBatchAsync(
        Func<string, JsonElement?, CancellationToken, Task<string>> send)
    {
        try
        {
            var raw = await send("RunDebugger", null, CancellationToken.None).ConfigureAwait(false);
            return !ToolSupport.AnalyzeBridgeResponse(raw).IsError;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Tightens budgets for heavy static reads inside batches when the caller
    /// omits them: a batch is a triage fan-out, not a deep dive. Single-tool
    /// calls keep their wider defaults. Explicit per-item values are honored.
    /// </summary>
    private static JsonElement ClampBatchBudget(string method, JsonElement args)
    {
        // Triage defaults for batch fan-out: heavy reads get small caps unless
        // the caller overrides per item. Prevents 16x4096B blowing output_limit.
        if (args.ValueKind != JsonValueKind.Object)
            return args;
        var node = JsonNode.Parse(args.GetRawText())!.AsObject();
        var changed = false;
        void SetInt(string name, int cap)
        {
            if (!node.ContainsKey(name))
            {
                node[name] = cap;
                changed = true;
            }
        }
        switch (method)
        {
            case "InspectFunction":
                SetInt("maxChars", 6_000);
                break;
            case "AnalyzeFunctions":
                // One digest entry already holds up to 8 functions: 16x24KB
                // would blow the shared batch output limit. Triage cap unless
                // the caller passes an explicit budget.
                SetInt("maxChars", 8_000);
                break;
            case "DecompileModule":
                SetInt("maxChars", 8_000);
                break;
            case "CallGraph":
                SetInt("maxNodes", 32);
                SetInt("maxEdges", 128);
                break;
            case "DumpStrings":
                SetInt("maxItems", 32);
                break;
            case "ListSymbols":
            case "ListFunctions":
                SetInt("maxItems", 32);
                break;
            case "Xrefs":
                SetInt("maxItems", 32);
                break;
            case "ReadMemAtAddress":
            case "ReadStaticBytes":
            case "InspectAddressStructure":
                // byteCount/length caps: batch of 16x4096 would hit output_limit.
                if (method == "ReadStaticBytes") SetInt("length", 512);
                else SetInt("byteCount", 512);
                if (method == "InspectAddressStructure")
                {
                    SetInt("maxXrefs", 16);
                }
                break;
            case "GetMemoryMap":
            case "ListThreads":
            case "ListBreakpoints":
                // These three are paged by offset/maxItems and declare no
                // maxFrames. additionalProperties=false on their schemas means
                // an injected maxFrames made every batch item fail validation.
                SetInt("maxItems", 32);
                break;
            case "GetBacktrace":
                // GetBacktrace is paged by startFrame/maxFrames and declares no
                // maxItems; the reverse injection failed it the same way.
                SetInt("maxFrames", 8);
                break;
            case "FindBytePatternInModule":
                // Unbounded whole-module scans fan out badly: 16 items x 32MB
                // would blow the 60s debugger-batch deadline. Triage caps here;
                // explicit per-item values are still honored.
                SetInt("maxResults", 16);
                SetInt("maxScanBytes", 4_194_304);
                break;
            case "TriageStrings":
            case "TriageImports":
            case "Triage":
                // P0-1 fan-out budgets (round-trip plan §5.2): heavy composites
                // get triage caps in batches unless the caller overrides per
                // item. Dormant until the owning WS admits these methods to a
                // batch allowlist; all values sit inside the tool schemas.
                SetInt("maxItems", 32);
                break;
            case "GetAnalysisQueue":
                SetInt("limit", 8);
                break;
            case "GetAnalysisSnapshot":
                SetInt("maxChars", 8000);
                break;
        }
        if (!changed)
            return args;
        return JsonSerializer.SerializeToElement(node);
    }

    /// <summary>
    /// Batch dedup key: canonical JSON (sorted object keys), so key-order or
    /// whitespace variants of the same arguments share one backend call.
    /// Expression-level dedup lives in ExecuteExpressionsAsync
    /// (NormalizeExpression), not here.
    /// </summary>
    private static string CanonicalBatchKey(string method, JsonElement args)
    {
        try
        {
            return method + "\n" + CanonicalJson(JsonNode.Parse(args.GetRawText()));
        }
        catch (JsonException)
        {
            return method + "\n" + args.GetRawText();
        }
    }

    private static string CanonicalJson(JsonNode? node) => node switch
    {
        JsonObject obj => "{" + string.Join(",",
            obj.OrderBy(property => property.Key, StringComparer.Ordinal).Select(property =>
                JsonSerializer.Serialize(property.Key) + ":" + CanonicalJson(property.Value))) + "}",
        JsonArray array => "[" + string.Join(",", array.Select(CanonicalJson)) + "]",
        _ => node?.ToJsonString() ?? "null",
    };
}
