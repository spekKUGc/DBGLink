using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Microsoft.Extensions.Logging;
namespace DbgLink.Server;

internal sealed class McpToolDispatcher(ServerConfig config, ToolRegistry registry, AnalysisContext context,
    AnalysisSessionRegistry sessions, ServerMetrics metrics, bool hasControl, ILogger logger) : IDisposable
{
    private readonly SemaphoreSlim _execution = new(Math.Clamp(config.MaxConcurrentRequests, 1, 64));
    private readonly SemaphoreSlim _admission = new(Math.Clamp(config.MaxConcurrentRequests, 1, 64) + Math.Clamp(config.MaxQueuedOperations, 0, 256));
    private readonly int _maxExecution = Math.Clamp(config.MaxConcurrentRequests, 1, 64);
    private readonly int _maxAdmission = Math.Clamp(config.MaxConcurrentRequests, 1, 64) + Math.Clamp(config.MaxQueuedOperations, 0, 256);
    private const int QueueFullRetryAfterMs = 2000;
    private int _disposed;

    /// <summary>Queue-full refusal with occupancy numbers and a retry hint,
    /// so agents back off instead of hammering the same call.</summary>
    internal static string QueueFullMessage(int running, int queued)
        => $"Queue full ({running} running, {queued} queued, retryAfterMs={QueueFullRetryAfterMs}). Await or use BatchDebuggerOperations/EvaluateExpressions.";
    public async Task<CallToolResult> CallAsync(CallToolRequestParams request, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new McpProtocolException("The server is shutting down.", McpErrorCode.InternalError);
        using var activity = metrics.BeginTool(request.Name ?? "Unknown tool");
        // Tool lookup precedes argument serialization: unknown-tool calls
        // never pay (or trigger backend traffic via) argument serialization.
        if (request.Name is null || !registry.TryGet(request.Name, out var tool) || (tool.RequiresControl && !hasControl))
        {
            var hint = request.Name is null ? null : FindToolSuggestion(request.Name);
            var message = hint is null ? "Unknown tool." : $"Unknown tool. Did you mean '{hint}'?";
            activity.Complete(failed: true, outcome: "unknown_tool", errorCode: "unknown_tool", sessionId: TryReadSessionId(request.Arguments));
            throw new McpProtocolException(message, McpErrorCode.InvalidParams);
        }
        JsonElement? earlyArguments = request.Arguments is null ? null : TrySerializeArguments(request.Arguments);
        string? earlySessionId = TryReadSessionId(earlyArguments);
        if (!tool.IsEnabled(config, hasControl))
        {
            activity.Complete(failed: true, outcome: "disabled", errorCode: "disabled", sessionId: earlySessionId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, earlyArguments));
            throw new McpProtocolException($"{tool.Name} is disabled: it requires the {tool.Capability} capability (check server AllowMutation/AllowAnnotation settings).", McpErrorCode.InvalidParams);
        }
        // Argument serialization itself can fail on malformed Unicode (e.g. a
        // lone surrogate): the raw JsonElements cannot round-trip. That is an
        // input fault (-32602), not a silent empty-arguments call.
        if (request.Arguments is not null && earlyArguments is null)
        {
            activity.Complete(failed: true, outcome: "validation_error", errorCode: "validation_error", sessionId: earlySessionId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, earlyArguments));
            throw new McpProtocolException(
                $"{tool.Name}: Invalid arguments (the request could not be decoded).",
                McpErrorCode.InvalidParams);
        }
        JsonElement? arguments = earlyArguments;
        string? analysisId;
        try { analysisId = ToolSupport.ReadAnalysisId(arguments); }
        catch (InvalidOperationException exception)
        {
            var badText = SafeRawText(arguments);
            var badBytes = badText?.Length ?? 0;
            activity.Complete(failed: true, outcome: "bad_analysis_id", requestBytes: badBytes, errorCode: "bad_analysis_id", sessionId: earlySessionId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, arguments), requestText: badText);
            throw new McpProtocolException(
                $"{exception.Message} Active sessions: [{FormatActiveSessions()}]. Use a live id.",
                McpErrorCode.InvalidParams);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // ReadAnalysisId only decodes bounded identifiers; anything else
            // here is unexpected: distinct -32603, real code in telemetry.
            var badText = SafeRawText(arguments);
            activity.Complete(failed: true, outcome: "exception", requestBytes: badText?.Length ?? 0, errorCode: "exception", sessionId: earlySessionId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, arguments), requestText: badText);
            logger.LogError("Tool {Tool} argument decode failed {Type}: {Msg}", tool.Name, exception.GetType().Name, SanitizeOneLine(exception.Message));
            throw new McpProtocolException(
                "The tool arguments could not be processed because of an internal error.",
                McpErrorCode.InternalError);
        }
        JsonElement? toolArguments;
        string? requestText;
        int requestBytes;
        string? error;
        try
        {
            toolArguments = ToolSupport.RemoveAnalysisId(arguments);
            // Single serialization: the raw argument JSON feeds both the byte
            // count and the real (BPE) token count in telemetry.
            requestText = SafeRawText(toolArguments);
            requestBytes = requestText?.Length ?? 0;
            error = ToolArgumentRules.Validate(tool.InputSchema, arguments);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (IsInputFault(exception))
        {
            // Decoding/validation faults (lone surrogates, bad UTF-8/UTF-16,
            // malformed shapes) are invalid params (-32602) with a safe,
            // bounded message that never echoes raw values (no secret/path
            // leak). The real exception type travels in telemetry.
            var badText = SafeRawText(arguments);
            activity.Complete(failed: true, outcome: "validation_error", requestBytes: badText?.Length ?? 0, errorCode: "validation_error", sessionId: analysisId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, arguments), requestText: badText);
            throw new McpProtocolException(
                $"{tool.Name}: Invalid arguments ({SanitizeOneLine(exception.Message)}).",
                McpErrorCode.InvalidParams);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var badText = SafeRawText(arguments);
            logger.LogError("Tool {Tool} argument validation failed {Type}: {Msg}", tool.Name, exception.GetType().Name, SanitizeOneLine(exception.Message));
            activity.Complete(failed: true, outcome: "exception", requestBytes: badText?.Length ?? 0, errorCode: "exception", sessionId: analysisId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, arguments), requestText: badText);
            throw new McpProtocolException(
                "The tool arguments could not be processed because of an internal error.",
                McpErrorCode.InternalError);
        }
        if (error is not null)
        {
            activity.Complete(failed: true, outcome: "validation_error", requestBytes: requestBytes, errorCode: "validation_error", sessionId: analysisId, detail: null, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            // The tool name stays in the message: a JSON-RPC error reaches the
            // caller without tool context, so the name is the only pointer.
            throw new McpProtocolException($"{tool.Name}: {error}", McpErrorCode.InvalidParams);
        }
        if (!_admission.Wait(0))
        {
            var running = Math.Max(0, _maxExecution - _execution.CurrentCount);
            var queued = Math.Max(0, (_maxAdmission - _admission.CurrentCount) - running);
            activity.Complete(failed: true, outcome: "queue_full", requestBytes: requestBytes, errorCode: "queue_full", sessionId: analysisId, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            throw new McpProtocolException(QueueFullMessage(running, queued), McpErrorCode.InternalError);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var acquired = false;
        AsyncReaderWriterGate.GateLease? sessionGate = null;
        var invocation = new ToolInvocation(tool.Name, toolArguments, analysisId, deadline.Token);
        try
        {
            await _execution.WaitAsync(deadline.Token).ConfigureAwait(false);
            acquired = true;
            metrics.ExecEnter();
            // The tool timeout counts execution only: queue waits above run on
            // the client token, so a queued request is never killed by a
            // timeout that expired before it started.
            using var toolDeadline = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            toolDeadline.CancelAfter(Math.Clamp(config.DefaultToolTimeoutMs, tool.MinimumTimeoutMs, 120_000));
            invocation = invocation with { CancellationToken = toolDeadline.Token };
            var closing = tool.SessionScope == ToolSessionScope.Closing;
            AnalysisSessionRuntime? session;
            string? fallbackNote = null;
            // Single-live-session fallback is read-only only. The check uses
            // the same predicate the lease uses: a read-only tool with
            // autoPause=true pauses/resumes the target, so a bogus id on it
            // must fail closed instead of silently driving the one live
            // session. SwitchDebugger retargeted this way would reset/kill the
            // live debuggee, and WriteMemory/SetRegister/SetBreakpoint/
            // OpenDebugTarget would mutate the wrong target. Closing-scope
            // tools never fall back (Find, not Resolve) so Close/Reopen fail
            // as not-found.
            var allowFallback = !tool.NeedsExclusiveLease(invocation) &&
                tool.SessionScope == ToolSessionScope.Session;
            if (tool.SessionScope == ToolSessionScope.Session)
            {
                if (allowFallback)
                {
                    // A dead id falls back to the single live session (with a
                    // visible note) so one replaced session does not brick every
                    // later read; zero or several live sessions keep the strict
                    // bad_session error.
                    if (!sessions.TryResolveWithFallback(analysisId, out session, out fallbackNote))
                        session = sessions.Resolve(analysisId);
                }
                else
                {
                    session = sessions.Resolve(analysisId);
                }
            }
            else
            {
                session = tool.SessionScope switch
                {
                    ToolSessionScope.Global => null,
                    ToolSessionScope.Closing => sessions.Find(analysisId!),
                    _ => sessions.Resolve(analysisId)
                };
            }
            // Closing an unknown id is a safe no-op at the launcher; do not
            // allocate a gate for it. Unbounded ghost ids must not grow the
            // registry.
            if (session is not null)
            {
                var id = session.AnalysisId;
                var gate = sessions.GetGate(id);
                // Read-only tools take a read lease so several of them run
                // concurrently against one session. Mutations, annotations and
                // session-level lifecycle operations take the exclusive write
                // lease. A read-only tool that still changes the target's
                // state (GetAnalysisSnapshot with autoPause pauses and resumes
                // the debugger) asks for the write lease explicitly.
                var exclusive = closing || tool.NeedsExclusiveLease(invocation);
                sessionGate = exclusive
                    ? await gate.EnterWriteAsync(toolDeadline.Token).ConfigureAwait(false)
                    : await gate.EnterReadAsync(toolDeadline.Token).ConfigureAwait(false);
                // A preceding close/switch may have replaced the runtime while this request waited.
                if (closing) session = sessions.Find(id);
                else if (allowFallback)
                {
                    if (sessions.TryResolveWithFallback(id, out session, out var refreshedNote))
                        fallbackNote = refreshedNote ?? fallbackNote;
                    else session = sessions.Resolve(id);
                }
                else session = sessions.Resolve(id);
            }
            string? rawResult;
            // Backend top-level attribution: the first bridge RPC in this
            // tool flow counts toward backends; fan-out sub-calls collapse
            // into fanoutSubCalls so backends stays a breakdown of total.
            using (metrics.BeginBackendAttribution())
            {
                rawResult = await context.ExecuteAsync(session, () => tool.Execute(invocation)).ConfigureAwait(false);
            }
            var raw = rawResult;
            if (tool.RegistersCompletedSession && AnalysisSessionResponse.TryRead(raw, out var descriptor) && descriptor is not null)
            {
                var gate = sessions.GetGate(descriptor.AnalysisId);
                using var registration = await gate.EnterWriteAsync(toolDeadline.Token).ConfigureAwait(false);
                if (!sessions.TryRegister(descriptor))
                    raw = BridgeEnvelope.Error("analysis_session_unavailable", "The completed analysis session is closed or could not be registered.");
                else
                    // Registering flips the active session to the newest
                    // import (the omit=active contract). Annotate the flip
                    // so unqualified dynamic calls driving a new debugger
                    // are never silent; additive keys only. Decision: keep
                    // the flip (existing omitted-id test depends on it) and
                    // make it visible here and via ListAnalysisSessions.
                    raw = AnnotateActiveSession(raw, sessions.ActiveAnalysisId, descriptor.AnalysisId);
            }
            // The registry has already consumed the per-session token above;
            // never expose that native-pipe credential in a tool result.
            raw = ToolSupport.RedactSessionSecrets(raw);
            var result = ToolSupport.AnalyzeBridgeResponse(raw, !tool.RawResponse);
            var responseBytes = raw?.Length ?? 0;
            var parsedCode = result.IsError ? BridgeClient.TryParseErrorCode(raw ?? "") : null;
            var errorCode = result.IsError ? (parsedCode ?? "backend_error") : null;
            activity.Complete(result.IsError, result.IsError ? "backend_error" : "ok", requestBytes, responseBytes, errorCode,
                sessionId: session?.AnalysisId ?? analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText, responseText: raw);
            var text = tool.RawResponse ? raw! : ToolSupport.NestJsonText(result.Text);
            if (result.IsError && text.Length > 2048)
                text = text[..2048] + "...[truncated]";
            if (fallbackNote is not null)
                return FallbackNotedResult(text, fallbackNote, session?.AnalysisId, result.IsError);
            return new CallToolResult { Content = [new TextContentBlock { Text = text }], IsError = result.IsError };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            activity.Complete(failed: true, outcome: "cancelled", requestBytes: requestBytes, errorCode: "cancelled", sessionId: analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            throw;
        }
        catch (OperationCanceledException)
        {
            // Per the MCP spec, tool execution failures (deadline, backend
            // crash) must be reported inside the CallToolResult with
            // isError=true; a JSON-RPC error here makes clients drop the
            // session instead of letting the model adjust and retry.
            activity.Complete(failed: true, outcome: "timeout", requestBytes: requestBytes, errorCode: "timeout", sessionId: analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            return ToolErrorResult("The tool execution exceeded its bounded deadline.");
        }
        catch (AnalysisSessionNotFoundException exception)
        {
            activity.Complete(failed: true, outcome: "bad_session", requestBytes: requestBytes, errorCode: "bad_session", sessionId: analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            throw new McpProtocolException(
                $"{exception.Message} Active sessions: [{FormatActiveSessions()}]. Use a live id.",
                McpErrorCode.InvalidParams);
        }
        catch (McpException)
        {
            activity.Complete(failed: true, outcome: "protocol_error", requestBytes: requestBytes, errorCode: "protocol_error", sessionId: analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            throw;
        }
        catch (Exception exception)
        {
            var oneLine = (exception.Message ?? "").Replace('\r', ' ').Replace('\n', ' ');
            if (oneLine.Length > 256) oneLine = oneLine[..256] + "...[truncated]";
            logger.LogError("Tool {Tool} failed {Type}: {Msg}", tool.Name, exception.GetType().Name, oneLine);
            activity.Complete(failed: true, outcome: "exception", requestBytes: requestBytes, errorCode: "exception", sessionId: analysisId, detail: invocation.Detail, functions: ServerMetrics.ExtractFunctionSelectors(tool.Name, toolArguments), requestText: requestText);
            return ToolErrorResult("The tool could not be completed because a backend component failed.");
        }
        finally { sessionGate?.Dispose(); if (acquired) { _execution.Release(); metrics.ExecExit(); } _admission.Release(); }
    }

    private string? FindToolSuggestion(string requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
            return null;
        string? prefixMatch = null;
        string? closest = null;
        var closestDistance = int.MaxValue;
        foreach (var candidate in registry.Definitions)
        {
            var name = candidate.Name;
            if (string.Equals(name, requested, StringComparison.OrdinalIgnoreCase))
                return name;
            if (prefixMatch is null && name.Length >= 3 && requested.Length >= 3 &&
                (name.StartsWith(requested, StringComparison.OrdinalIgnoreCase) ||
                 requested.StartsWith(name, StringComparison.OrdinalIgnoreCase)))
                prefixMatch = name;
            var distance = CappedEditDistance(requested, name, 2);
            if (distance < closestDistance)
            {
                closestDistance = distance;
                closest = name;
            }
        }
        if (closestDistance <= 2)
            return closest;
        return prefixMatch;
    }

    private static int CappedEditDistance(string first, string second, int cap)
    {
        // Case-insensitive Levenshtein with early exit past cap; tool names
        // are short and the registry is small, so this stays sub-microsecond.
        if (Math.Abs(first.Length - second.Length) > cap)
            return cap + 1;
        var previous = new int[second.Length + 1];
        var current = new int[second.Length + 1];
        for (var j = 0; j <= second.Length; j++)
            previous[j] = j;
        for (var i = 1; i <= first.Length; i++)
        {
            current[0] = i;
            var rowMinimum = current[0];
            for (var j = 1; j <= second.Length; j++)
            {
                var cost = char.ToUpperInvariant(first[i - 1]) == char.ToUpperInvariant(second[j - 1]) ? 0 : 1;
                current[j] = Math.Min(Math.Min(previous[j] + 1, current[j - 1] + 1), previous[j - 1] + cost);
                if (current[j] < rowMinimum)
                    rowMinimum = current[j];
            }
            if (rowMinimum > cap)
                return cap + 1;
            (previous, current) = (current, previous);
        }
        return previous[second.Length];
    }

    private static JsonElement? TrySerializeArguments(System.Collections.Generic.IDictionary<string, JsonElement> arguments)
    {
        try { return JsonSerializer.SerializeToElement(arguments); }
        catch { return null; }
    }

    private static string? TryReadSessionId(JsonElement? arguments)
    {
        try { return ToolSupport.ReadAnalysisId(arguments); }
        catch { return null; }
    }

    /// <summary>Best-effort session id straight from the request dictionary,
    /// so unknown-tool telemetry needs no argument serialization. Uses the
    /// shared analysisId policy; invalid ids read as null.</summary>
    private static string? TryReadSessionId(System.Collections.Generic.IDictionary<string, JsonElement>? arguments)
    {
        try
        {
            if (arguments is null || !arguments.TryGetValue("analysisId", out var value) ||
                value.ValueKind != JsonValueKind.String)
                return null;
            var text = value.GetString();
            return text is not null && AnalysisSessionRegistry.IsValidAnalysisId(text) ? text : null;
        }
        catch { return null; }
    }

    /// <summary>Best-effort raw argument JSON for telemetry token counting.
    /// Null when unavailable so the caller falls back to the byte heuristic. Never throws.</summary>
    private static string? SafeRawText(JsonElement? element)
    {
        try { return element?.GetRawText(); }
        catch { return null; }
    }

    /// <summary>Input-decode faults (bad JSON shape, lone surrogates, bad
    /// UTF-16/UTF-8, malformed values) map to InvalidParams (-32602).
    /// Everything else in argument prep is unexpected (-32603).</summary>
    private static bool IsInputFault(Exception exception)
        => exception is JsonException or ArgumentException or InvalidOperationException or FormatException;

    /// <summary>Safe, bounded, non-leaking one-liner for client-facing
    /// messages. Shared with the request policy via
    /// <see cref="ToolSupport.SanitizeOneLine"/>.</summary>
    private static string SanitizeOneLine(string? message)
        => ToolSupport.SanitizeOneLine(message, "the request could not be decoded");

    private string FormatActiveSessions()
    {
        try
        {
            var ids = sessions.ActiveIds;
            if (ids.Count == 0)
                return "(none)";
            // Session ids are opaque and only the first few are ever useful in
            // an error: an unbounded list is re-sent on every failed retry.
            const int shown = 8;
            var listed = string.Join(", ", ids.Take(shown));
            return ids.Count <= shown ? listed : $"{listed} (+{ids.Count - shown} more, see ListAnalysisSessions)";
        }
        catch { return "(unknown)"; }
    }

    /// <summary>
    /// Additive active-session annotation for completed imports: the raw
    /// launcher envelope keeps its keys; result gains activeAnalysisId plus a
    /// sessionNote naming the flip. Parse failures return the raw unchanged.
    /// </summary>
    internal static string AnnotateActiveSession(string? raw, string activeId, string completedId)
    {
        if (string.IsNullOrEmpty(raw))
            return raw ?? "";
        try
        {
            var root = JsonNode.Parse(raw)?.AsObject();
            if (root is null || root["ok"]?.GetValue<bool>() != true)
                return raw;
            if (root["result"] is not JsonObject result)
                return raw;
            result["activeAnalysisId"] = activeId;
            if (!result.ContainsKey("sessionNote"))
                result["sessionNote"] = $"Session '{completedId}' registered; active session is now '{activeId}'. Omit analysisId to use the active session, or pass a live id explicitly.";
            return root.ToJsonString();
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
            return raw;
        }
    }

    /// <summary>
    /// JSON-safe fallback note: when the unwrapped text is a JSON object the
    /// note rides as additive sessionNote/resolvedAnalysisId fields so strict
    /// parsers keep working; a top-level JSON array rides as a second text
    /// block to preserve its shape; plain text keeps the historical prefix.
    /// </summary>
    internal static CallToolResult FallbackNotedResult(string text, string fallbackNote, string? resolvedId, bool isError)
    {
        try
        {
            var node = JsonNode.Parse(text);
            if (node is JsonObject obj)
            {
                if (!obj.ContainsKey("sessionNote"))
                    obj["sessionNote"] = fallbackNote;
                else if (!obj.ContainsKey("fallbackNote"))
                    obj["fallbackNote"] = fallbackNote;
                if (resolvedId is not null && !obj.ContainsKey("resolvedAnalysisId"))
                    obj["resolvedAnalysisId"] = resolvedId;
                return new CallToolResult { Content = [new TextContentBlock { Text = obj.ToJsonString() }], IsError = isError };
            }
            if (node is JsonArray)
                return new CallToolResult
                {
                    Content = [new TextContentBlock { Text = fallbackNote }, new TextContentBlock { Text = text }],
                    IsError = isError
                };
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
        }
        return new CallToolResult { Content = [new TextContentBlock { Text = fallbackNote + "\n" + text }], IsError = isError };
    }

    private static CallToolResult ToolErrorResult(string message)
        => new()
        {
            Content = [new TextContentBlock { Text = message }],
            IsError = true
        };

    /// <summary>
    /// Tears the dispatcher down. The admission and execution semaphores are
    /// deliberately NOT disposed: a call that is in flight releases them in its
    /// finally block, and disposing them under it would throw
    /// ObjectDisposedException out of the finally and replace the real tool
    /// result with an exception. New calls are refused instead.
    /// </summary>
    public void Dispose()
    {
        Interlocked.Exchange(ref _disposed, 1);
        GC.SuppressFinalize(this);
    }
}
