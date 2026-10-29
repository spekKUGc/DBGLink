using DbgLink.Shared;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed class LiveAnalysisTools
{
    private readonly AnalysisContext _context;
    private IBridgeClient ActiveBridge => _context.Bridge;
    private IGhidraClient ActiveGhidra => _context.Ghidra;
    private readonly SessionControlTools? _sessions;
    // Per-analysis-session snapshot state (register diff baseline + diffOnly
    // fingerprint). Keyed by analysis id: a process-wide baseline made a
    // diffOnly snapshot on one session report another session's registers as
    // changed, and the old unsynchronized compare-then-write could leave a
    // mixed baseline behind when read-only calls overlapped.
    private readonly ConcurrentDictionary<string, SessionSnapshotState> _snapshotStates = new(StringComparer.Ordinal);
    private const int SnapshotStateLimit = SessionCaches.SnapshotStateLimit;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _rejectedTargets = new(StringComparer.OrdinalIgnoreCase);
    private const int RejectedTargetLimit = SessionCaches.RejectedTargetLimit;
    private static readonly TimeSpan RejectedTargetTtl = SessionCaches.RejectedTargetTtl;
    public LiveAnalysisTools(AnalysisContext context, SessionControlTools? sessions = null)
    {
        _context = context;
        _sessions = sessions;
    }

    internal sealed record ValidatedDebugTarget(string FullPath, string? WorkDir);

    /// <summary>
    /// Snapshot state for the currently active analysis session. The table is
    /// capped: the least recently used entry is evicted once the cap is hit,
    /// so a long-lived server cannot accumulate one baseline per closed
    /// session.
    /// </summary>
    private SessionSnapshotState SnapshotState()
    {
        var analysisId = _context.AnalysisId;
        var state = _snapshotStates.GetOrAdd(analysisId, static _ => new SessionSnapshotState());
        if (_snapshotStates.Count > SnapshotStateLimit)
            EvictLeastRecentlyUsedSnapshotState(analysisId);
        return state;
    }

    private void EvictLeastRecentlyUsedSnapshotState(string currentAnalysisId)
    {
        string? oldestKey = null;
        long oldestTicks = long.MaxValue;
        foreach (var pair in _snapshotStates)
        {
            if (string.Equals(pair.Key, currentAnalysisId, StringComparison.Ordinal))
                continue;
            var ticks = pair.Value.LastUsedTicks;
            if (ticks < oldestTicks)
            {
                oldestTicks = ticks;
                oldestKey = pair.Key;
            }
        }
        if (oldestKey is not null)
            _snapshotStates.TryRemove(oldestKey, out _);
    }

    internal static ValidatedDebugTarget? ValidateDebugTarget(
        string? path, string? commandLine, string? workDir)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0 ||
            path.Length > 32_760)
            return null;
        var trimmedPath = path.Trim();
        if (!Path.IsPathFullyQualified(trimmedPath))
            return null;
        // Host-scope escapes: UNC (\\server\share, Uri.IsUnc), non-drive
        // roots, and DOS device segments (CON/NUL/COM1/...) fail closed here
        // so no pipe traffic follows. ADS (:) is covered by IsSafeLocalPath
        // via DbgLinkConfigPath.IsSafePath; the quote/control gate below
        // covers x64dbg init quoting.
        if (!LocalPathPolicy.IsSafeLocalPath(trimmedPath))
            return null;
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(trimmedPath);
        }
        catch (Exception exception) when (exception is ArgumentException or
            NotSupportedException or PathTooLongException)
        {
            return null;
        }
        if (!LocalPathPolicy.IsSafeLocalPath(fullPath))
            return null;
        var extension = Path.GetExtension(fullPath);
        if (!extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            return null;
        FileInfo info;
        try
        {
            info = new FileInfo(fullPath);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory))
                return null;
            if (info.Length <= 0 || info.Length > 512L * 1024 * 1024)
                return null;
            // Mirror the Ghidra-target policy: reject targets reachable
            // through a reparse point (symlink/junction/mount) so a link
            // named *.exe cannot smuggle a different binary or DLL-plant
            // via the working directory. IsSafeLocalPath also rejects UNC,
            // ADS and DOS device spellings (fail-closed, no pipe traffic).
            if (!LocalPathPolicy.IsSafeLocalPath(fullPath))
                return null;
        }
        catch (Exception exception) when (exception is ArgumentException or
            NotSupportedException or PathTooLongException or IOException or
            UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
        string? resolvedWorkDir = null;
        if (!string.IsNullOrEmpty(workDir))
        {
            if (workDir.IndexOf('\0') >= 0 || workDir.Length > 32_760)
                return null;
            var trimmedWorkDir = workDir.Trim();
            if (!Path.IsPathFullyQualified(trimmedWorkDir))
                return null;
            if (!LocalPathPolicy.IsSafeLocalPath(trimmedWorkDir))
                return null;
            DirectoryInfo? directory;
            try
            {
                directory = new DirectoryInfo(trimmedWorkDir);
                if (!directory.Exists)
                    return null;
                resolvedWorkDir = directory.FullName;
                if (!LocalPathPolicy.IsSafeLocalPath(resolvedWorkDir))
                    return null;
            }
            catch (Exception exception) when (exception is ArgumentException or
                NotSupportedException or PathTooLongException or IOException or
                UnauthorizedAccessException or System.Security.SecurityException)
            {
                return null;
            }
        }
        if (commandLine is not null && commandLine.Length > 4_096)
            return null;
        // The values are interpolated into an x64dbg `init` command line,
        // whose quoting cannot embed a literal quote: reject instead of
        // escaping, on both ends of the bridge.
        foreach (var text in new[] { fullPath, commandLine ?? "", resolvedWorkDir ?? "" })
        {
            if (text.IndexOf('"') >= 0 || text.Any(char.IsControl))
                return null;
        }
        return new ValidatedDebugTarget(fullPath, resolvedWorkDir);
    }

    internal async Task<string> OpenDebugTargetAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var path = ToolSupport.ReadArgumentString(arguments, "path");
        var commandLine = ToolSupport.ReadArgumentString(arguments, "arguments");
        var workDir = ToolSupport.ReadArgumentString(arguments, "workDir");
        var validated = ValidateDebugTarget(path, commandLine, workDir);
        if (validated is null)
        {
            var key = TruncateTargetForError(path);
            if (!string.IsNullOrEmpty(key) && _rejectedTargets.TryGetValue(key, out var rejectedAt) &&
                DateTimeOffset.UtcNow - rejectedAt < RejectedTargetTtl)
                return BridgeEnvelope.Error("debug_target_invalid",
                    $"The same target path was already rejected: '{key}'. Do not repeat it — verify the path exists or ask the user for a different one.");
            if (!string.IsNullOrEmpty(key))
            {
                _rejectedTargets[key] = DateTimeOffset.UtcNow;
                while (_rejectedTargets.Count > RejectedTargetLimit)
                {
                    var oldest = _rejectedTargets.OrderBy(pair => pair.Value).FirstOrDefault();
                    if (oldest.Key is null || !_rejectedTargets.TryRemove(oldest.Key, out _)) break;
                }
            }
            return BridgeEnvelope.Error("debug_target_invalid",
                $"The debug target path, arguments, or working directory failed validation: '{key}'. " +
                "Do not repeat the same path — verify the file exists or ask the user for a different one.");
        }
        var payload = new JsonObject { ["path"] = validated.FullPath };
        if (commandLine is not null)
            payload["arguments"] = commandLine;
        if (workDir is not null)
            payload["workDir"] = validated.WorkDir;
        if (_sessions?.Available == true)
            return await _sessions.OpenDebugTargetAsync(payload,
                ToolSupport.ReadArgumentString(arguments, "architecture") ?? "auto", cancellationToken).ConfigureAwait(false);
        return await ActiveBridge.RequestAsync(
            "OpenDebugTarget",
            JsonSerializer.SerializeToElement(payload),
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<string> GetAnalysisSnapshotAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // Opt-in auto-pause: absent/false takes the historical path untouched.
        if (!ToolSupport.ReadArgumentBool(arguments, "autoPause", false))
            return await GetAnalysisSnapshotCoreAsync(arguments, cancellationToken).ConfigureAwait(false);
        return await GetAnalysisSnapshotWithAutoPauseAsync(arguments, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<string> GetAnalysisSnapshotCoreAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // One state object per analysis session, resolved once so every
        // section of this snapshot shares the same register baseline.
        var snapshotState = SnapshotState();
        var maxFrames = ToolSupport.ReadArgumentInt(arguments, "maxFrames", 8);
        var beforeBytes = ToolSupport.ReadArgumentInt(arguments, "beforeBytes", 16);
        var instructionBytes = ToolSupport.ReadArgumentInt(arguments, "instructionBytes", 16);
        var stackBytes = ToolSupport.ReadArgumentInt(arguments, "stackBytes", 64);
        var maxChars = ToolSupport.ReadResponseBudget(arguments, 16_000, 200, 60_000, out var maxTokens);
        var includeThreads = ToolSupport.ReadArgumentBool(arguments, "includeThreads", false);
        var includeModules = ToolSupport.ReadArgumentBool(arguments, "includeModules", false);
        var compactModules = ToolSupport.ReadArgumentBool(arguments, "compactModules", true);
        // Name+base+end identify a module for correlation; the full local
        // path rides along only on opt-in (GetModuleMap resolves paths).
        // Mapping fetches request paths explicitly and is unaffected.
        var includeModulePaths = ToolSupport.ReadArgumentBool(arguments, "includeModulePaths", false);
        var compactStack = ToolSupport.ReadArgumentBool(arguments, "compactStack", true);
        var sparseRegisters = ToolSupport.ReadArgumentBool(arguments, "sparseRegisters", true);
        var diffOnly = ToolSupport.ReadArgumentBool(arguments, "diffOnly", false);
        // Status is a separate tool; the snapshot does not need to duplicate
        // it by default (the brief already omits it too).
        var includeStatus = ToolSupport.ReadArgumentBool(arguments, "includeStatus", false);
        var remainingChars = maxChars;
        var truncated = false;
        var bridgeCalls = 0;
        var sections = new JsonObject();
        var errors = new JsonArray();
        var skipped = new JsonArray();
        JsonObject? moduleResultForSummary = null;
        string? statusRaw = null;
        string? preDiffContextJson = null;

        // P0-3 bundle (opt-in, default-off): includeExpressions[1..16] +
        // includeRanges[1..8] are read inside the same paused window as the
        // base sections. Absent/empty/invalid takes the historical path
        // untouched: wantBundle stays false and every byte below is identical.
        var bundleExpressions = TryReadSnapshotExpressions(arguments, errors);
        var bundleRanges = TryReadSnapshotRanges(arguments, errors);
        var wantBundle = (bundleExpressions is not null && bundleExpressions.Length > 0) ||
            (bundleRanges is not null && bundleRanges.Count > 0);

        void AddNodeSection(string name, JsonNode? node)
        {
            if (node is null)
            {
                errors.Add(new JsonObject { ["section"] = name, ["code"] = "missing_section" });
                return;
            }

            if (name == "callStack" && compactStack)
            {
                node = AnalysisFormatting.FoldCallStackNode(node);
            }
            else if (name == "context")
            {
                if (sparseRegisters)
                    node = AnalysisFormatting.FormatSparseContext(node);
                if (diffOnly)
                    preDiffContextJson ??= node?.ToJsonString();
                if (diffOnly)
                    node = AnalysisFormatting.FormatDiffContext(node, snapshotState);
                else
                    AnalysisFormatting.UpdateLastRegisters(node, snapshotState);
            }

            if (node is null)
            {
                errors.Add(new JsonObject { ["section"] = name, ["code"] = "missing_section" });
                return;
            }

            if (remainingChars <= 0)
            {
                skipped.Add(name);
                truncated = true;
                return;
            }

            string? stringValue = null;
            if (node is JsonValue value && value.TryGetValue<string>(out var candidate))
                stringValue = candidate;
            var isText = stringValue is not null;
            if (!isText)
            {
                var serialized = node.ToJsonString();
                if (serialized.Length + 64 <= remainingChars)
                {
                    sections[name] = node;
                    remainingChars -= serialized.Length + 64;
                    return;
                }

                sections[name] = new JsonObject
                {
                    ["omitted"] = true,
                    ["reason"] = "response_budget",
                };
                remainingChars = Math.Max(0, remainingChars - 64);
                truncated = true;
                return;
            }

            var sectionText = ToolSupport.LimitSnapshotText(stringValue!, remainingChars, ref truncated);
            sections[name] = sectionText;
            remainingChars = Math.Max(0, remainingChars - sectionText.Length);
        }

        void AddModuleNode(JsonNode? moduleNode)
        {
            if (moduleNode is JsonObject moduleResult && moduleResult["modules"] is JsonArray)
            {
                if (compactModules)
                {
                    AnalysisFormatting.FoldModulesNode(moduleResult);
                }
                if (!includeModulePaths && moduleResult["modules"] is JsonArray pathRecords)
                {
                    foreach (var record in pathRecords)
                    {
                        if (record is JsonObject entry)
                            entry.Remove("path");
                    }
                }
                var activeRecords = (JsonArray)moduleResult["modules"]!;
                moduleResultForSummary = moduleResult;
                AnalysisSnapshotSummary.TrimModuleRecordsToBudget(moduleResult, activeRecords, remainingChars);
                truncated |= AnalysisFormatting.ReadNodeBool(moduleResult, "truncated");
                AnalysisFormatting.AddBoundedSection(sections, "modules", moduleResult, ref remainingChars, ref truncated);
                return;
            }

            errors.Add(new JsonObject { ["section"] = "modules", ["code"] = "bridge_error" });
        }

        async Task AddSectionAsync(string name, string method, JsonElement? sectionArguments, bool preserveJson = false)
        {
            if (remainingChars <= 0)
            {
                skipped.Add(name);
                truncated = true;
                return;
            }

            string raw;
            try
            {
                bridgeCalls++;
                raw = await ActiveBridge.RequestAsync(method, sectionArguments, cancellationToken);
                if (name == "status")
                    statusRaw = raw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                errors.Add(new JsonObject
                {
                    ["section"] = name,
                    ["code"] = "bridge_exception",
                    ["message"] = ToolSupport.FailureReason(exception)
                });
                return;
            }

            var bridgeAnalysis = ToolSupport.AnalyzeBridgeResponse(
                raw, includeText: !(preserveJson && method == "GetServerStatus"));
            if (bridgeAnalysis.IsError)
            {
                errors.Add(new JsonObject
                {
                    ["section"] = name,
                    ["code"] = "bridge_error",
                    ["message"] = ToolSupport.LimitSnapshotText(bridgeAnalysis.Text, 512, ref truncated)
                });
                return;
            }

            if (preserveJson)
            {
                try
                {
                    var node = JsonNode.Parse(raw);
                    if (node is not null && raw.Length <= remainingChars)
                    {
                        sections[name] = node;
                        remainingChars -= raw.Length;
                        return;
                    }
                }
                catch (JsonException) { }
            }

            var textToFormat = bridgeAnalysis.Text;
            if (name == "callStack" && compactStack)
            {
                // The individual path gets the bridge result as text. Parse it
                // so object-form stacks fold exactly like the batched path
                // instead of silently keeping every system frame.
                JsonNode? stackNode = null;
                try { stackNode = JsonNode.Parse(textToFormat); }
                catch (JsonException) { }
                var folded = stackNode is not null
                    ? AnalysisFormatting.FoldCallStackNode(stackNode)
                    : AnalysisFormatting.FoldCallStackNode(JsonValue.Create(textToFormat));
                if (stackNode is not null)
                    textToFormat = folded?.ToJsonString() ?? textToFormat;
                else if (folded is JsonValue fVal && fVal.TryGetValue<string>(out var foldedText))
                    textToFormat = foldedText;
            }
            else if (name == "context")
            {
                var node = (JsonNode)JsonValue.Create(textToFormat);
                if (sparseRegisters)
                    node = AnalysisFormatting.FormatSparseContext(node);
                if (diffOnly)
                    preDiffContextJson ??= node?.ToJsonString();
                if (diffOnly)
                    node = AnalysisFormatting.FormatDiffContext(node, snapshotState);
                else
                    AnalysisFormatting.UpdateLastRegisters(node, snapshotState);

                if (node is JsonValue cVal && cVal.TryGetValue<string>(out var ctxText))
                    textToFormat = ctxText;
            }

            var sectionText = ToolSupport.LimitSnapshotText(textToFormat, remainingChars, ref truncated);
            sections[name] = sectionText;
            remainingChars = Math.Max(0, remainingChars - sectionText.Length);
        }

        // P0-3 bundle reads: one EvaluateExpression bridge call per unique
        // expression shape (same method + payload as EvaluateExpressions),
        // rows in the same {index, method, response} envelope so per-index
        // errors never fail the sibling expressions. Budget fit mirrors the
        // non-text AddNodeSection branch: the whole array fits or it is
        // omitted with truncated=true.
        async Task AddSnapshotExpressionsAsync(string?[] expressionTexts)
        {
            if (remainingChars <= 0)
            {
                skipped.Add("expressions");
                truncated = true;
                return;
            }

            var rows = new JsonArray();
            for (var index = 0; index < expressionTexts.Length; index++)
            {
                var text = expressionTexts[index];
                if (string.IsNullOrWhiteSpace(text) || text.Length > 512)
                {
                    rows.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["response"] = JsonNode.Parse(BridgeEnvelope.Error("invalid_argument",
                            $"includeExpressions[{index}] must be a non-blank string up to 512 chars.")),
                    });
                    continue;
                }

                string raw;
                try
                {
                    bridgeCalls++;
                    raw = await ActiveBridge.RequestAsync("EvaluateExpression",
                        ToolSupport.ToJsonElement(new JsonObject { ["expression"] = text }),
                        cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    rows.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["response"] = JsonNode.Parse(BridgeEnvelope.Error("bridge_exception",
                            $"includeExpressions[{index}] transport failure ({ToolSupport.FailureReason(exception)}).")),
                    });
                    continue;
                }

                JsonNode? parsed;
                try
                {
                    parsed = JsonNode.Parse(raw);
                }
                catch (JsonException)
                {
                    parsed = JsonValue.Create(raw);
                }
                rows.Add(new JsonObject
                {
                    ["index"] = index,
                    ["response"] = parsed,
                });
            }

            var serialized = rows.ToJsonString();
            if (serialized.Length + 64 <= remainingChars)
            {
                sections["expressions"] = rows;
                remainingChars -= serialized.Length + 64;
                return;
            }

            sections["expressions"] = new JsonObject
            {
                ["omitted"] = true,
                ["reason"] = "response_budget",
            };
            remainingChars = Math.Max(0, remainingChars - 64);
            truncated = true;
        }

        // P0-3 bundle reads: one ReadMemAtAddress bridge call with the
        // ranges[] shape (same as the ReadMemAtAddress tool), so per-index
        // memory errors stay in the forwarded text and never fail the
        // snapshot. Budget fit mirrors the AddSectionAsync text path.
        async Task AddSnapshotRangesAsync(JsonArray forwardedRanges)
        {
            if (remainingChars <= 0)
            {
                skipped.Add("ranges");
                truncated = true;
                return;
            }

            string raw;
            try
            {
                bridgeCalls++;
                raw = await ActiveBridge.RequestAsync("ReadMemAtAddress",
                    ToolSupport.ToJsonElement(new JsonObject { ["ranges"] = forwardedRanges }),
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                errors.Add(new JsonObject
                {
                    ["section"] = "ranges",
                    ["code"] = "bridge_exception",
                    ["message"] = ToolSupport.FailureReason(exception)
                });
                return;
            }

            var bridgeAnalysis = ToolSupport.AnalyzeBridgeResponse(raw, includeText: true);
            if (bridgeAnalysis.IsError)
            {
                errors.Add(new JsonObject
                {
                    ["section"] = "ranges",
                    ["code"] = "bridge_error",
                    ["message"] = ToolSupport.LimitSnapshotText(bridgeAnalysis.Text, 512, ref truncated)
                });
                return;
            }

            var rangesText = ToolSupport.LimitSnapshotText(bridgeAnalysis.Text, remainingChars, ref truncated);
            sections["ranges"] = rangesText;
            remainingChars = Math.Max(0, remainingChars - rangesText.Length);
        }

        var contextArguments = ToolSupport.ToJsonElement(new JsonObject
        {
            ["beforeBytes"] = beforeBytes,
            ["instructionBytes"] = instructionBytes,
            ["stackBytes"] = stackBytes,
        });
        var stackArguments = ToolSupport.ToJsonElement(new JsonObject { ["maxFrames"] = maxFrames });

        async Task<JsonNode?> ReadStateAsync()
        {
            try
            {
                bridgeCalls++;
                return AnalysisFormatting.ReadBridgeResultNode(
                    await ActiveBridge.RequestAsync("GetSnapshotState", null, cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception) { return null; }
        }

        var capability = snapshotState.BatchedCapability;
        if (includeStatus)
        {
            await AddSectionAsync("status", "GetServerStatus", null, preserveJson: true);
            // The status section doubles as the capability probe.
            capability = AnalysisSnapshotSummary.HasAnalysisSnapshotCapability(statusRaw);
            snapshotState.BatchedCapability = capability;
        }
        var stateBefore = (JsonNode?)null;
        var stateAfter = (JsonNode?)null;
        // A native batched GetAnalysisSnapshot seals its own atomic window on
        // the bridge side; bundle reads issued after it would fall outside
        // that window. Force the individual path when bundling so the shared
        // stateBefore/stateAfter consistency check covers every read.
        // Unknown capability: try the batched method optimistically (one trip)
        // instead of paying a GetServerStatus probe first. Only a definitive
        // unknown-method answer pins the session to the individual path.
        var batched = capability != false && !wantBundle;
        if (batched)
        {
            try
            {
                bridgeCalls++;
                var batchedArguments = ToolSupport.ToJsonElement(new JsonObject
                {
                    ["beforeBytes"] = beforeBytes,
                    ["instructionBytes"] = instructionBytes,
                    ["stackBytes"] = stackBytes,
                    ["maxFrames"] = maxFrames,
                    ["includeThreads"] = includeThreads,
                    ["includeModules"] = includeModules,
                });
                var batchedRaw = await ActiveBridge.RequestAsync("GetAnalysisSnapshot", batchedArguments, cancellationToken);
                var batchedNode = AnalysisFormatting.ReadBridgeResultNode(batchedRaw);
                if (batchedNode is JsonObject batchedObject &&
                    batchedObject["sections"] is JsonObject batchedSections)
                {
                    snapshotState.BatchedCapability = true;
                    stateBefore = batchedObject["stateBefore"]?.DeepClone();
                    stateAfter = batchedObject["stateAfter"]?.DeepClone();
                    AddNodeSection("context", batchedSections["context"]?.DeepClone());
                    AddNodeSection("callStack", batchedSections["callStack"]?.DeepClone());
                    if (includeThreads)
                        AddNodeSection("threads", batchedSections["threads"]?.DeepClone());
                    if (includeModules && remainingChars > 0)
                        AddModuleNode(batchedSections["modules"]?.DeepClone());
                    else if (includeModules)
                    {
                        skipped.Add("modules");
                        truncated = true;
                    }
                }
                else
                {
                    if (ToolSupport.IsUnknownBridgeMethod(batchedRaw))
                        snapshotState.BatchedCapability = false;
                    batched = false;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception)
            {
                // Transient: leave the capability unknown so the next call
                // retries the cheap batched path.
                batched = false;
            }
        }

        if (!batched)
        {
            stateBefore = await ReadStateAsync();
            await AddSectionAsync("context", "GetCurrentContext", contextArguments);
            await AddSectionAsync("callStack", "GetCallStack", stackArguments);
            if (includeThreads)
                await AddSectionAsync("threads", "GetAllActiveThreads", null);
            if (includeModules)
            {
                if (remainingChars <= 0) { skipped.Add("modules"); truncated = true; }
                else
                {
                    try
                    {
                        bridgeCalls++;
                        var raw = await ActiveBridge.RequestAsync("GetModuleRecords", null, cancellationToken);
                        AddModuleNode(AnalysisFormatting.ReadBridgeResultNode(raw));
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                    catch (Exception) { errors.Add(new JsonObject { ["section"] = "modules", ["code"] = "bridge_exception" }); }
                }
            }
            // Bundle reads sit between the base sections and the closing
            // state poll so stateBefore/stateAfter bound the whole window.
            if (bundleExpressions is not null && bundleExpressions.Length > 0)
                await AddSnapshotExpressionsAsync(bundleExpressions);
            if (bundleRanges is not null && bundleRanges.Count > 0)
                await AddSnapshotRangesAsync(bundleRanges);
            stateAfter = await ReadStateAsync();
        }

        var consistency = AnalysisSnapshotSummary.AssessConsistency(stateBefore, stateAfter);
        if (consistency["status"]!.GetValue<string>() != "unchanged")
            errors.Add(new JsonObject
            {
                ["section"] = "consistency", ["code"] = "snapshot_not_verified",
                ["message"] = "Live sections may describe different states. Pause the target and repeat the snapshot."
            });

        // diffOnly polling: when debugger state AND the rendered context are
        // byte-identical to the previous snapshot, return a stub instead of
        // re-sending kilobytes. The fingerprint covers the pre-diff formatted
        // context (not the diff-filtered output): FormatDiffContext mutates the
        // register baseline as a side effect, so fingerprinting its output
        // would guarantee a mismatch on the second poll and waste one full
        // snapshot per quiet cycle. Changed registers never collapse here
        // because the pre-diff text still differs.
        if (diffOnly && errors.Count == 0 && stateAfter is not null)
        {
            var fingerprint = (stateBefore?.ToJsonString() ?? "") + "\n" +
                stateAfter.ToJsonString() + "\n" +
                (preDiffContextJson ?? sections["context"]?.ToJsonString() ?? "") + "\n" +
                (sections["callStack"]?.ToJsonString() ?? "");
            // The compare-and-set is atomic inside the per-session state, so
            // concurrent diffOnly polls cannot both observe "changed" and
            // re-send kilobytes.
            if (snapshotState.TryConsumeFingerprint(fingerprint))
            {
                return BridgeEnvelope.Success(new JsonObject
                {
                    ["schemaVersion"] = 2,
                    ["unchanged"] = true,
                    ["consistency"] = consistency.DeepClone(),
                    ["hint"] = "Unchanged. Poll with diffOnly=true after stepping.",
                });
            }
        }

        var snapshot = new JsonObject
        {
            ["schemaVersion"] = 2,
            ["summary"] = AnalysisSnapshotSummary.BuildSnapshotSummary(stateAfter ?? stateBefore, moduleResultForSummary,
                consistency["status"]!.GetValue<string>(), includeThreads, includeModules,
                sections, skipped, errors.Count, truncated, batched ? "batched" : "individual"),
            ["consistency"] = consistency,
            ["usedChars"] = maxChars - remainingChars,
            ["bridgeCalls"] = bridgeCalls,
            ["truncated"] = truncated,
            ["sections"] = sections,
        };
        // roundTripsSaved rides only when nonzero: presence is the signal,
        // absent equals zero (same convention as truncated/omitted flags).
        var roundTripsSaved = batched
            ? 3 + (includeThreads ? 1 : 0) + (includeModules ? 1 : 0)
            : 0;
        if (roundTripsSaved != 0)
            snapshot["roundTripsSaved"] = roundTripsSaved;
        if (errors.Count > 0)
            snapshot["errors"] = errors;
        if (skipped.Count > 0)
            snapshot["skipped"] = skipped;
        if (truncated)
            snapshot["continuation"] = ToolSupport.WithTokenBudgetHint(
                "Repeat with a higher maxChars or disable optional includeThreads/includeModules sections.",
                maxTokens);
        if (maxTokens > 0)
        {
            snapshot["maxTokens"] = maxTokens;
            snapshot["usedTokensEstimate"] = ToolSupport.EstimateGuardTokens(maxChars - remainingChars);
        }
        return BridgeEnvelope.Success(snapshot);
    }

    /// <summary>
    /// Opt-in auto-pause budget for GetAnalysisSnapshot(autoPause=true): after
    /// the pause request, poll GetSnapshotState on the same ~3s budget as the
    /// BulkStep/TraceUntil step loops before any read.
    /// </summary>
    internal const int AutoPauseWaitAttempts = 60;

    /// <summary>
    /// Opt-in read path for GetAnalysisSnapshot(autoPause=true). When the
    /// target is running, pause it via the same PauseDebugger bridge method
    /// behind ControlDebuggerExecution(action=pause), wait for a stable pause
    /// with the shared WaitForPausedAsync machinery, read via the unchanged
    /// core path, then restore the prior run state with RunDebugger. An
    /// already-paused target (or no live session at all) takes the core path
    /// untouched: no pause/resume calls and no note. Every automation failure
    /// returns an honest error instead of a racing snapshot.
    /// </summary>
    private async Task<string> GetAnalysisSnapshotWithAutoPauseAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        JsonNode? initial;
        try
        {
            initial = AnalysisFormatting.ReadBridgeResultNode(
                await ActiveBridge.RequestAsync("GetSnapshotState", null, cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { initial = null; }
        if (!IsUsableStateNode(initial))
            return BridgeEnvelope.Error("snapshot_state_unreadable",
                "autoPause=true needs the current paused/running state, but GetSnapshotState was unreadable. " +
                "The debugger was not paused or resumed. Pause the target (ControlDebuggerExecution action=pause) " +
                "and retry without autoPause.");
        if (!AnalysisFormatting.ReadNodeBool(initial, "debugging"))
        {
            // No live session to pause; the core snapshot reports not_debugging itself.
            return await GetAnalysisSnapshotCoreAsync(arguments, cancellationToken).ConfigureAwait(false);
        }
        // Resume only when WE paused a RUNNING target. A paused (even
        // not-yet-stable) target must stay paused: autoPause must never flip a
        // paused debuggee to running.
        var wasRunning = AnalysisFormatting.ReadNodeBool(initial, "running");
        if (!wasRunning && AnalysisFormatting.ReadNodeBool(initial, "stableRead"))
        {
            // Already stably paused: the flag is a no-op.
            return await GetAnalysisSnapshotCoreAsync(arguments, cancellationToken).ConfigureAwait(false);
        }

        if (wasRunning)
        {
            string pauseRaw;
            try
            {
                pauseRaw = await ActiveBridge.RequestAsync("PauseDebugger", null, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                return BridgeEnvelope.Error("debugger_pause_failed",
                    ToolSupport.AutoPausePauseFailure(exception));
            }
            if (ToolSupport.AnalyzeBridgeResponse(pauseRaw).IsError)
                return BridgeEnvelope.Error("debugger_pause_failed",
                    "autoPause=true: the debugger refused the pause request; the target was left running. " +
                    "Pause it (ControlDebuggerExecution action=pause) and retry without autoPause.");
        }

        var pauseOutcome = (await WaitForPausedAsync(AutoPauseWaitAttempts, PausePollIntervalMs, swallowErrors: true, cancellationToken)).Outcome;
        if (pauseOutcome != PauseWaitOutcome.Paused)
        {
            // Best-effort restore only when we paused a running target: a
            // no-op when the target never paused, and a resume when the pause
            // landed but the polls stayed unreadable. A target that was already
            // paused is left paused. Either way report honestly and read nothing.
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            return BridgeEnvelope.Error("debugger_running_timeout",
                "autoPause=true: the target did not reach a stable pause within the polling budget; " +
                (wasRunning ? "a best-effort resume was attempted." : "the target was already paused and was left paused.") +
                " Verify the state with GetAnalysisSnapshot before continuing.");
        }

        string snapshotRaw;
        try
        {
            snapshotRaw = await GetAnalysisSnapshotCoreAsync(arguments, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        // Restore the prior running state before looking at the payload, but
        // only if we paused a running target: a failed resume surfaces as an
        // honest error, never as a snapshot that implies the target is running.
        // Resume with no token so a cancelled caller cannot leave the target
        // paused by masking the resume with an OCE (matches batch TryResumeBatchAsync).
        if (wasRunning && !await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false))
            return BridgeEnvelope.Error("debugger_resume_failed",
                "autoPause=true: the snapshot was taken while paused, but resuming the target failed; " +
                "it may still be paused. Resume it (ControlDebuggerExecution action=run) before continuing.");

        var snapshotNode = AnalysisFormatting.ReadBridgeResultNode(snapshotRaw);
        if (snapshotNode is not JsonObject snapshot)
        {
            // Core reported its own error, or a non-object success. A target we
            // paused was already resumed, so keep the note even here.
            if (!wasRunning)
                return snapshotRaw;
            return BridgeEnvelope.Success(new JsonObject
            {
                ["autoPause"] = AutoPauseNote(),
                ["bridgeResult"] = snapshotNode?.DeepClone(),
            });
        }
        if (wasRunning)
            snapshot["autoPause"] = AutoPauseNote();
        return BridgeEnvelope.Success(snapshot);
    }

    /// <summary>The autoPause success marker attached when a running target was
    /// paused and then resumed for the operation.
    ///
    /// The marker carries no free text: the batch path asserts the same
    /// contract ({"resumed":true} and nothing else), and a note would cost
    /// tokens on every auto-pause call for no extra information.</summary>
    private static JsonObject AutoPauseNote()
        => new() { ["resumed"] = true };

    /// <summary>
    /// Best-effort RunDebugger (the same bridge method behind
    /// ControlDebuggerExecution action=run). True only when the bridge
    /// answered success; caller cancellation still propagates.
    /// </summary>
    private async Task<bool> TryResumeDebuggerAsync(CancellationToken cancellationToken)
    {
        try
        {
            var raw = await ActiveBridge.RequestAsync("RunDebugger", null, cancellationToken);
            return !ToolSupport.AnalyzeBridgeResponse(raw).IsError;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return false; }
    }

    /// <summary>
    /// Opt-in auto-pause entry for WriteMemory: absent/false takes the
    /// historical passthrough untouched (autoPause stripped so the bridge
    /// sees the same payload as before). P0-3 .NET half: the bytesHex echo
    /// duplicates the caller input (up to ~6k tokens on large writes), so it
    /// is stripped by default unless echoBytes=true; nextAddress stays (small
    /// and pinned by Live15). New natives already omit the echo, making the
    /// strip a no-op that returns the same reference.
    /// </summary>
    internal async Task<string> WriteMemoryAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var echoBytes = ToolSupport.ReadArgumentBool(arguments, "echoBytes", false);
        string raw;
        if (!ToolSupport.ReadArgumentBool(arguments, "autoPause", false))
            raw = await ActiveBridge.RequestAsync("WriteMemory", StripAutoPauseArgument(arguments), cancellationToken).ConfigureAwait(false);
        else
            raw = await ExecuteMutationWithAutoPauseAsync("WriteMemory", arguments, cancellationToken).ConfigureAwait(false);
        return SlimWriteMemoryAck(raw, echoBytes);
    }

    /// <summary>
    /// P0-3 .NET echo gate: drop the bytesHex request-echo from a successful
    /// WriteMemory ack unless the caller opted into echoBytes=true. Errors,
    /// unparseable bodies and slim acks pass through untouched (the slim case
    /// returns the same string reference). Never throws.
    /// </summary>
    internal static string SlimWriteMemoryAck(string raw, bool echoBytes)
    {
        if (echoBytes || string.IsNullOrEmpty(raw))
            return raw;
        try
        {
            if (ToolSupport.AnalyzeBridgeResponse(raw, includeText: false).IsError)
                return raw;
            var root = JsonNode.Parse(raw)?.AsObject();
            if (root?["result"] is JsonObject result && result.Remove("bytesHex"))
                return root.ToJsonString();
            return raw;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return raw;
        }
    }

    /// <summary>
    /// Opt-in auto-pause entry for SetRegister: same contract as WriteMemory.
    /// </summary>
    internal async Task<string> SetRegisterAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (!ToolSupport.ReadArgumentBool(arguments, "autoPause", false))
            return await ActiveBridge.RequestAsync("SetRegister", StripAutoPauseArgument(arguments), cancellationToken).ConfigureAwait(false);
        return await ExecuteMutationWithAutoPauseAsync("SetRegister", arguments, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Shared opt-in mutation path for WriteMemory/SetRegister with
    /// autoPause=true. Reuses the snapshot PauseDebugger/RunDebugger +
    /// WaitForPausedAsync machinery: pause a running target, apply the
    /// mutation, then restore the prior run state. Already-paused (or no
    /// live session) targets take the direct mutation path with no extra
    /// calls and no note. Pause/resume failures are honest errors; a
    /// failed mutation still resumes before reporting the mutation error.
    /// </summary>
    private async Task<string> ExecuteMutationWithAutoPauseAsync(string bridgeMethod, JsonElement? arguments, CancellationToken cancellationToken)
    {
        JsonNode? initial;
        try
        {
            initial = AnalysisFormatting.ReadBridgeResultNode(
                await ActiveBridge.RequestAsync("GetSnapshotState", null, cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { initial = null; }
        if (!IsUsableStateNode(initial))
            return BridgeEnvelope.Error("snapshot_state_unreadable",
                "autoPause=true needs the current paused/running state, but GetSnapshotState was unreadable. " +
                "The debugger was not paused or resumed. Pause the target (ControlDebuggerExecution action=pause) " +
                "and retry without autoPause.");
        if (!AnalysisFormatting.ReadNodeBool(initial, "debugging"))
        {
            // No live session to pause; the bridge reports not_debugging itself.
            return await ActiveBridge.RequestAsync(bridgeMethod, StripAutoPauseArgument(arguments), cancellationToken).ConfigureAwait(false);
        }
        // Resume only when WE paused a RUNNING target. A paused (even
        // not-yet-stable) target must stay paused: autoPause must never flip a
        // paused debuggee to running.
        var wasRunning = AnalysisFormatting.ReadNodeBool(initial, "running");
        if (!wasRunning && AnalysisFormatting.ReadNodeBool(initial, "stableRead"))
        {
            // Already stably paused: the flag is a no-op.
            return await ActiveBridge.RequestAsync(bridgeMethod, StripAutoPauseArgument(arguments), cancellationToken).ConfigureAwait(false);
        }

        if (wasRunning)
        {
            string pauseRaw;
            try
            {
                pauseRaw = await ActiveBridge.RequestAsync("PauseDebugger", null, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                return BridgeEnvelope.Error("debugger_pause_failed",
                    ToolSupport.AutoPausePauseFailure(exception));
            }
            if (ToolSupport.AnalyzeBridgeResponse(pauseRaw).IsError)
                return BridgeEnvelope.Error("debugger_pause_failed",
                    "autoPause=true: the debugger refused the pause request; the target was left running. " +
                    "Pause it (ControlDebuggerExecution action=pause) and retry without autoPause.");
        }

        var pauseOutcome = (await WaitForPausedAsync(AutoPauseWaitAttempts, PausePollIntervalMs, swallowErrors: true, cancellationToken)).Outcome;
        if (pauseOutcome != PauseWaitOutcome.Paused)
        {
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            return BridgeEnvelope.Error("debugger_running_timeout",
                "autoPause=true: the target did not reach a stable pause within the polling budget; " +
                (wasRunning ? "a best-effort resume was attempted." : "the target was already paused and was left paused.") +
                " Verify the state with GetAnalysisSnapshot before continuing.");
        }

        var stripped = StripAutoPauseArgument(arguments);
        string mutationRaw;
        try
        {
            mutationRaw = await ActiveBridge.RequestAsync(bridgeMethod, stripped, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch (Exception)
        {
            // Transport failure after the pause: restore the running state,
            // then rethrow so the dispatcher reports a backend failure
            // instead of a bogus success. Resume with no token so a cancelled
            // caller cannot mask the original exception with an OCE.
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        var mutationIsError = ToolSupport.AnalyzeBridgeResponse(mutationRaw).IsError;
        var mutationErrorCode = mutationIsError ? BridgeClient.TryParseErrorCode(mutationRaw) : null;
        // Final success-path resume uses no token so caller cancellation
        // cannot leave the target paused (matches batch TryResumeBatchAsync).
        if (wasRunning && !await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false))
            return BridgeEnvelope.Error("debugger_resume_failed",
                $"autoPause=true: the {bridgeMethod} mutation was attempted while paused, but resuming the target failed; " +
                "it may still be paused. Resume it (ControlDebuggerExecution action=run) before continuing." +
                (mutationErrorCode is null ? "" : $" The mutation reported '{mutationErrorCode}' before the resume failure."));
        if (mutationIsError)
        {
            // Clean resume (or nothing to resume): report the original mutation error, no note.
            return mutationRaw;
        }

        var resultNode = AnalysisFormatting.ReadBridgeResultNode(mutationRaw);
        if (resultNode is not JsonObject result)
        {
            // Unexpected success shape. Keep the note when we resumed a target.
            if (!wasRunning)
                return mutationRaw;
            return BridgeEnvelope.Success(new JsonObject
            {
                ["autoPause"] = AutoPauseNote(),
                ["bridgeResult"] = resultNode?.DeepClone(),
            });
        }
        if (wasRunning)
            result["autoPause"] = AutoPauseNote();
        return BridgeEnvelope.Success(result);
    }

    /// <summary>
    /// Frozen read-side auto-pause helper (contract C1 for WS4): mirrors
    /// ExecuteMutationWithAutoPauseAsync but for reads — pause-if-running,
    /// run the bridge call, resume-if-we-paused, attach the autoPause note.
    /// Already-paused (or no live session) targets take the historical
    /// passthrough with no extra calls and no note. Pause/resume failures
    /// are honest errors; a failed read still resumes before reporting the
    /// read error. Not wired to any tool schema yet (WS4 owns schemas):
    /// callers pass already-stripped args.
    /// </summary>
    internal async Task<string> ExecuteReadWithAutoPauseAsync(string bridgeMethod, JsonElement? strippedArgs, CancellationToken cancellationToken)
    {
        JsonNode? initial;
        try
        {
            initial = AnalysisFormatting.ReadBridgeResultNode(
                await ActiveBridge.RequestAsync("GetSnapshotState", null, cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { initial = null; }
        if (!IsUsableStateNode(initial))
            return BridgeEnvelope.Error("snapshot_state_unreadable",
                "autoPause=true needs the current paused/running state, but GetSnapshotState was unreadable. " +
                "The debugger was not paused or resumed. Pause the target (ControlDebuggerExecution action=pause) " +
                "and retry without autoPause.");
        if (!AnalysisFormatting.ReadNodeBool(initial, "debugging"))
        {
            // No live session to pause; the bridge reports not_debugging itself.
            return await ActiveBridge.RequestAsync(bridgeMethod, strippedArgs, cancellationToken).ConfigureAwait(false);
        }
        // Resume only when WE paused a RUNNING target. A paused (even
        // not-yet-stable) target must stay paused: autoPause must never flip a
        // paused debuggee to running.
        var wasRunning = AnalysisFormatting.ReadNodeBool(initial, "running");
        if (!wasRunning && AnalysisFormatting.ReadNodeBool(initial, "stableRead"))
        {
            // Already stably paused: the flag is a no-op.
            return await ActiveBridge.RequestAsync(bridgeMethod, strippedArgs, cancellationToken).ConfigureAwait(false);
        }

        if (wasRunning)
        {
            string pauseRaw;
            try
            {
                pauseRaw = await ActiveBridge.RequestAsync("PauseDebugger", null, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                return BridgeEnvelope.Error("debugger_pause_failed",
                    ToolSupport.AutoPausePauseFailure(exception));
            }
            if (ToolSupport.AnalyzeBridgeResponse(pauseRaw).IsError)
                return BridgeEnvelope.Error("debugger_pause_failed",
                    "autoPause=true: the debugger refused the pause request; the target was left running. " +
                    "Pause it (ControlDebuggerExecution action=pause) and retry without autoPause.");
        }

        var pauseOutcome = (await WaitForPausedAsync(AutoPauseWaitAttempts, PausePollIntervalMs, swallowErrors: true, cancellationToken)).Outcome;
        if (pauseOutcome != PauseWaitOutcome.Paused)
        {
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            return BridgeEnvelope.Error("debugger_running_timeout",
                "autoPause=true: the target did not reach a stable pause within the polling budget; " +
                (wasRunning ? "a best-effort resume was attempted." : "the target was already paused and was left paused.") +
                " Verify the state with GetAnalysisSnapshot before continuing.");
        }

        string readRaw;
        try
        {
            readRaw = await ActiveBridge.RequestAsync(bridgeMethod, strippedArgs, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch (Exception)
        {
            // Transport failure after the pause: restore the running state,
            // then rethrow so the dispatcher reports a backend failure
            // instead of a bogus success. Resume with no token so a cancelled
            // caller cannot mask the original exception with an OCE.
            if (wasRunning)
                await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        var readIsError = ToolSupport.AnalyzeBridgeResponse(readRaw).IsError;
        var readErrorCode = readIsError ? BridgeClient.TryParseErrorCode(readRaw) : null;
        // Final success-path resume uses no token so caller cancellation
        // cannot leave the target paused (matches batch TryResumeBatchAsync).
        // Branch on bridgeMethod (MINOR 3): breakpoint tools must not say
        // "read" in the resume-failure message.
        var operationNoun = bridgeMethod is "SetBreakpoint" or "ClearBreakpoint" ? "breakpoint operation" : "read";
        if (wasRunning && !await TryResumeDebuggerAsync(CancellationToken.None).ConfigureAwait(false))
            return BridgeEnvelope.Error("debugger_resume_failed",
                $"autoPause=true: the {bridgeMethod} {operationNoun} was attempted while paused, but resuming the target failed; " +
                "it may still be paused. Resume it (ControlDebuggerExecution action=run) before continuing." +
                (readErrorCode is null ? "" : $" The {operationNoun} reported '{readErrorCode}' before the resume failure."));
        if (readIsError)
        {
            // Clean resume (or nothing to resume): report the original read error, no note.
            return readRaw;
        }

        var resultNode = AnalysisFormatting.ReadBridgeResultNode(readRaw);
        if (resultNode is not JsonObject result)
        {
            // Unexpected success shape. Keep the note when we resumed a target.
            if (!wasRunning)
                return readRaw;
            return BridgeEnvelope.Success(new JsonObject
            {
                ["autoPause"] = AutoPauseNote(),
                ["bridgeResult"] = resultNode?.DeepClone(),
            });
        }
        if (wasRunning)
            result["autoPause"] = AutoPauseNote();
        return BridgeEnvelope.Success(result);
    }

    /// <summary>
    /// P0-3 bundle arg parsing for GetAnalysisSnapshot(includeExpressions):
    /// null when absent/empty (historical path); per-item nullable strings
    /// when present (invalid items surface as per-index error rows at read
    /// time); null plus an errors[] entry when the count is out of 1..16.
    /// The MCP schema gate is authoritative over the wire; this is
    /// defense-in-depth for direct callers.
    /// </summary>
    private static string?[]? TryReadSnapshotExpressions(JsonElement? arguments, JsonArray errors)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } ||
            !arguments.Value.TryGetProperty("includeExpressions", out var element) ||
            element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        if (element.ValueKind != JsonValueKind.Array)
        {
            errors.Add(new JsonObject
            {
                ["section"] = "expressions",
                ["code"] = "invalid_argument",
                ["message"] = "includeExpressions must be an array of 1-16 x64dbg expressions."
            });
            return null;
        }
        var items = element.EnumerateArray().ToArray();
        if (items.Length == 0)
            return null;
        if (items.Length > 16)
        {
            errors.Add(new JsonObject
            {
                ["section"] = "expressions",
                ["code"] = "invalid_argument",
                ["message"] = "includeExpressions must contain 1-16 items."
            });
            return null;
        }
        return items.Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : null).ToArray();
    }

    /// <summary>
    /// P0-3 bundle arg parsing for GetAnalysisSnapshot(includeRanges):
    /// null when absent/empty (historical path); the verbatim-forwarded
    /// ranges array when valid (the bridge applies its own per-index and
    /// total-cap validation, mirroring a direct ReadMemAtAddress call);
    /// null plus an errors[] entry when the shape is invalid, so no doomed
    /// bridge call is issued.
    /// </summary>
    private static JsonArray? TryReadSnapshotRanges(JsonElement? arguments, JsonArray errors)
    {
        void AddRangesError(string message) => errors.Add(new JsonObject
        {
            ["section"] = "ranges",
            ["code"] = "invalid_argument",
            ["message"] = message
        });

        if (arguments is not { ValueKind: JsonValueKind.Object } ||
            !arguments.Value.TryGetProperty("includeRanges", out var element) ||
            element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        if (element.ValueKind != JsonValueKind.Array)
        {
            AddRangesError("includeRanges must be an array of 1-8 {address, byteCount} entries.");
            return null;
        }
        var items = element.EnumerateArray().ToArray();
        if (items.Length == 0)
            return null;
        if (items.Length > 8)
        {
            AddRangesError("includeRanges must contain 1-8 items.");
            return null;
        }
        var forwarded = new JsonArray();
        var totalBytes = 0;
        for (var index = 0; index < items.Length; index++)
        {
            var item = items[index];
            if (item.ValueKind != JsonValueKind.Object)
            {
                AddRangesError($"includeRanges[{index}] must be an object with address and optional byteCount.");
                return null;
            }
            foreach (var property in item.EnumerateObject())
            {
                if (!property.NameEquals("address") && !property.NameEquals("byteCount"))
                {
                    var name = property.Name.Length > 64 ? property.Name[..64] + "..." : property.Name;
                    AddRangesError($"includeRanges[{index}] has unsupported property '{name}'.");
                    return null;
                }
            }
            if (!item.TryGetProperty("address", out var address) || address.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(address.GetString()) ||
                Encoding.UTF8.GetByteCount(address.GetString()!) > 256)
            {
                AddRangesError($"includeRanges[{index}] needs a non-blank address up to 256 UTF-8 bytes.");
                return null;
            }
            // Mirror the ReadMemAtAddress item default when byteCount is omitted.
            var byteCount = 128;
            if (item.TryGetProperty("byteCount", out var byteCountElement))
            {
                if (byteCountElement.ValueKind != JsonValueKind.Number ||
                    !byteCountElement.TryGetInt32(out var parsed) || parsed < 1 || parsed > 4096)
                {
                    AddRangesError($"includeRanges[{index}].byteCount must be an integer 1-4096.");
                    return null;
                }
                byteCount = parsed;
            }
            totalBytes += byteCount;
            var entry = new JsonObject { ["address"] = address.GetString() };
            if (item.TryGetProperty("byteCount", out _))
                entry["byteCount"] = byteCount;
            forwarded.Add(entry);
        }
        if (totalBytes > 16384)
        {
            AddRangesError("includeRanges total byteCount must not exceed 16384.");
            return null;
        }
        return forwarded;
    }

    /// <summary>
    /// Strip the MCP-only autoPause flag before forwarding to the native
    /// bridge (which knows nothing about it). Absent stays the same
    /// reference so the historical path is byte-for-byte unchanged.
    /// </summary>
    /// <summary>
    /// Strip the MCP-only autoPause flag before forwarding to the native
    /// bridge (which knows nothing about it). Absent stays the same
    /// reference so the historical path is byte-for-byte unchanged.
    /// </summary>
    internal static JsonElement? StripAutoPauseArgument(JsonElement? arguments)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object })
            return arguments;
        if (!arguments.Value.TryGetProperty("autoPause", out _))
            return arguments;
        try
        {
            var node = JsonNode.Parse(arguments.Value.GetRawText())?.AsObject();
            if (node is null)
                return arguments;
            node.Remove("autoPause");
            return ToolSupport.ToJsonElement(node);
        }
        catch (JsonException)
        {
            return arguments;
        }
    }

    /// <summary>
    /// Schema-validated callers only send into/over/out, but direct callers
    /// bypass the dispatcher: reject typos (e.g. "inoto") instead of silently
    /// stepping into.
    /// </summary>
    private static bool TryStepMethod(string? kind, out string method)
    {
        method = kind?.Trim().ToLowerInvariant() switch
        {
            null or "" or "into" => "StepInto",
            "over" => "StepOver",
            "out" => "StepOut",
            _ => "",
        };
        return method.Length != 0;
    }

    /// <summary>
    /// Shorten an agent-supplied target path for error messages (control chars stripped).
    /// </summary>
    private static string TruncateTargetForError(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "";
        var clean = new string(text.Trim().Where(c => !char.IsControl(c)).ToArray());
        return clean.Length > 256 ? clean[..256] : clean;
    }

    /// <summary>
    /// Parse a bridge address string as hex, tolerating an optional 0x prefix.
    /// </summary>
    private static bool TryParseHexAddress(string? text, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var clean = text.Trim();
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            clean = clean[2..];
        return ulong.TryParse(clean, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// Read the single instruction at CIP (address plus text, falling back to disasm).
    /// Fault-tolerant: a transient bridge failure yields (null, null) so step
    /// loops keep their stop-condition checks instead of aborting the trace.
    /// </summary>
    private async Task<(string? Address, string? Instruction)> ReadCurrentInstructionAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var disasmRaw = await ActiveBridge.RequestAsync("ReadDisassemblyChunk",
                ToolSupport.ToJsonElement(new JsonObject { ["address"] = "cip", ["maxInstructions"] = 1 }),
                cancellationToken);
            var disasmNode = AnalysisFormatting.ReadBridgeResultNode(disasmRaw);
            if (disasmNode is JsonObject dObj && dObj["instructions"] is JsonArray iArr &&
                iArr.Count > 0 && iArr[0] is JsonObject instrObj)
            {
                return (instrObj["address"]?.GetValue<string>(),
                    instrObj["instruction"]?.GetValue<string>() ?? instrObj["disasm"]?.GetValue<string>());
            }

            return (null, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Outcome of waiting for the debuggee to pause. Paused means a real pause
    /// was observed (the only case where reading registers/memory is safe).
    /// StillRunning means the budget was exhausted while the bridge kept
    /// returning usable running/not-paused states. BridgeUnusable means no
    /// poll returned a usable state at all (transport errors or unreadable
    /// responses). The two failure modes stay distinct so callers can report
    /// honestly instead of collapsing both into a bare false.
    /// </summary>
    internal enum PauseWaitOutcome
    {
        Paused,
        StillRunning,
        BridgeUnusable,
    }

    /// <summary>
    /// ProbeFunction pause-wait budget. The default 3000ms preserves the
    /// historical 60x50ms polling behavior; the optional waitMs probe argument
    /// extends it, clamped to 0..MaxProbeWaitMs, so a slow injected call can
    /// opt into a longer wait without unbounded hangs.
    /// </summary>
    internal const int DefaultProbeWaitMs = 3000;
    internal const int MaxProbeWaitMs = 30_000;
    internal const int PausePollIntervalMs = 50;

    /// <summary>
    /// Poll GetSnapshotState until the target is paused (debugging, not running,
    /// stable read). Returns Paused only when a real pause was observed, with
    /// the paused result node attached (it may carry the native returnValue
    /// capture when an injected call landed); exhaustion yields StillRunning
    /// when at least one poll produced a usable state response, BridgeUnusable
    /// when every poll failed or was unreadable.
    /// Exceptions are swallowed when <paramref name="swallowErrors"/>
    /// is set; cancellation of <paramref name="cancellationToken"/> always rethrows.
    /// </summary>
    private async Task<(PauseWaitOutcome Outcome, JsonNode? PausedState)> WaitForPausedAsync(int maxAttempts, int delayMs,
        bool swallowErrors, CancellationToken cancellationToken)
    {
        var sawUsableState = false;
        var consecutiveUnusable = 0;
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var usable = false;
            try
            {
                var stateRaw = await ActiveBridge.RequestAsync("GetSnapshotState", null, cancellationToken);
                var stateNode = AnalysisFormatting.ReadBridgeResultNode(stateRaw);
                if (IsUsableStateNode(stateNode))
                {
                    usable = true;
                    sawUsableState = true;
                    consecutiveUnusable = 0;
                    if (stateNode is JsonObject obj &&
                        AnalysisFormatting.ReadNodeBool(obj, "debugging") &&
                        !AnalysisFormatting.ReadNodeBool(obj, "running") &&
                        AnalysisFormatting.ReadNodeBool(obj, "stableRead"))
                        return (PauseWaitOutcome.Paused, stateNode);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception) when (swallowErrors) { }

            if (!usable && !sawUsableState && ++consecutiveUnusable >= 3)
            {
                // A dead pipe will never become usable within 3 s of polling;
                // report it now instead of burning the whole budget.
                return (PauseWaitOutcome.BridgeUnusable, null);
            }

            // Do not sleep after the last attempt: the caller re-checks the
            // outcome immediately, so the trailing delay only adds latency to
            // every timeout.
            if (attempt + 1 < maxAttempts)
                await Task.Delay(delayMs, cancellationToken);
        }

        return (sawUsableState ? PauseWaitOutcome.StillRunning : PauseWaitOutcome.BridgeUnusable, null);
    }

    /// <summary>
    /// A state response is usable when it carries at least one recognizable
    /// paused/running field (debugging/running/stableRead as booleans). An
    /// ok:true envelope with an empty or foreign result (or an ok:false /
    /// unparseable body) says nothing about the target and must not be
    /// mistaken for "still running".
    /// </summary>
    private static bool IsUsableStateNode(JsonNode? node)
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
    /// Snapshot-section options shared by the TraceUntil bulk-step fast path
    /// and predicate tracing, carrying their lean post-step defaults.
    /// </summary>
    internal readonly record struct SnapshotOptions(
        int MaxFrames,
        int BeforeBytes,
        int InstructionBytes,
        int StackBytes,
        int MaxChars,
        bool IncludeThreads,
        bool IncludeModules,
        bool DiffOnly,
        bool CompactStack,
        bool CompactModules,
        bool SparseRegisters)
    {
        internal static SnapshotOptions Read(JsonElement? arguments) => new(
            Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxFrames", 8), 1, 64),
            Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "beforeBytes", 16), 0, 256),
            Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "instructionBytes", 16), 1, 2048),
            Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "stackBytes", 64), 0, 2048),
            Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxChars", 8_000), 2000, 60000),
            ToolSupport.ReadArgumentBool(arguments, "includeThreads", false),
            ToolSupport.ReadArgumentBool(arguments, "includeModules", false),
            ToolSupport.ReadArgumentBool(arguments, "diffOnly", false),
            ToolSupport.ReadArgumentBool(arguments, "compactStack", true),
            ToolSupport.ReadArgumentBool(arguments, "compactModules", true),
            ToolSupport.ReadArgumentBool(arguments, "sparseRegisters", true));

        internal JsonElement ToJsonElement() => ToolSupport.ToJsonElement(new JsonObject
        {
            ["maxFrames"] = MaxFrames,
            ["beforeBytes"] = BeforeBytes,
            ["instructionBytes"] = InstructionBytes,
            ["stackBytes"] = StackBytes,
            ["maxChars"] = MaxChars,
            ["includeThreads"] = IncludeThreads,
            ["includeModules"] = IncludeModules,
            ["compactModules"] = CompactModules,
            ["compactStack"] = CompactStack,
            ["sparseRegisters"] = SparseRegisters,
            ["diffOnly"] = DiffOnly
        });
    }

    internal async Task<string> BulkStepAndSnapshotAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // Clamp to the native bridge contract (1..100): an unbounded count
        // would either be rejected mid-flight or step far past the target.
        var count = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "count", 1), 1, 100);
        var kind = ToolSupport.ReadArgumentString(arguments, "kind") ?? "into";
        if (!TryStepMethod(kind, out var method))
            return BridgeEnvelope.Error("invalid_argument",
                $"kind '{kind.Trim()}' is not 'into', 'over' or 'out'. Do not repeat the same call without changing inputs.");

        var stepArguments = ToolSupport.ToJsonElement(new JsonObject
        {
            ["count"] = count
        });

        var stepRaw = await ActiveBridge.RequestAsync(method, stepArguments, cancellationToken);
        var stepAnalysis = ToolSupport.AnalyzeBridgeResponse(stepRaw);
        if (stepAnalysis.IsError)
            return stepRaw;

        // Same ~3s pause budget as the TraceUntil step loop below: bulk steps
        // crossing a blocking syscall need it before a snapshot is readable.
        // Only a real observed pause counts as completed; an exhausted budget
        // (still running) or an unusable bridge response both leave it false.
        var pauseOutcome = (await WaitForPausedAsync(60, 50, swallowErrors: true, cancellationToken)).Outcome;
        var paused = pauseOutcome == PauseWaitOutcome.Paused;

        var snapArgs = SnapshotOptions.Read(arguments).ToJsonElement();

        var snapshotRaw = await GetAnalysisSnapshotAsync(snapArgs, cancellationToken);
        var snapshotNode = AnalysisFormatting.ReadBridgeResultNode(snapshotRaw);
        if (snapshotNode is JsonObject snapObj)
        {
            snapObj["step"] = new JsonObject
            {
                ["kind"] = kind,
                ["count"] = count,
                ["completed"] = paused,
            };
            return BridgeEnvelope.Success(snapObj);
        }

        return snapshotRaw;
    }

    /// <summary>
    /// Trace path budget: compact entries keep long traces within the
    /// 8KB TraceUntil snapshot budget.
    /// </summary>
    internal const int MaxTracePathEntries = 512;

    /// <summary>
    /// Strip 0x address padding ("0x00007FF8..." -&gt; "0x7ff8...") so compact
    /// path entries carry the RVA-scale short form instead of padded text.
    /// </summary>
    internal static string CompactTraceAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
            return string.Empty;
        var text = address.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var hex = text[2..].TrimStart('0');
            if (hex.Length == 0)
                hex = "0";
            return "0x" + hex.ToLowerInvariant();
        }
        return text;
    }

    /// <summary>
    /// Keep only the mnemonic ("mov rax, rbx" -&gt; "mov") for compact path entries.
    /// </summary>
    internal static string ExtractTraceMnemonic(string? instruction)
    {
        if (string.IsNullOrWhiteSpace(instruction))
            return string.Empty;
        var trimmed = instruction.Trim();
        var end = trimmed.IndexOfAny([' ', '\t']);
        var first = end < 0 ? trimmed : trimmed[..end];
        return first.TrimEnd(':').ToLowerInvariant();
    }

    internal static JsonNode FormatTracePathEntry(int step, string? address, string? instruction, bool compact)
    {
        if (!compact)
        {
            return new JsonObject
            {
                ["step"] = step,
                ["address"] = address,
                ["instruction"] = instruction
            };
        }
        var shortAddress = CompactTraceAddress(address);
        var mnemonic = ExtractTraceMnemonic(instruction);
        var text = string.IsNullOrEmpty(mnemonic) ? shortAddress : $"{shortAddress} {mnemonic}";
        return JsonValue.Create(text)!;
    }

    internal static bool TryAddTracePathEntry(JsonArray path, JsonNode entry, ref bool truncated)
    {
        if (path.Count >= MaxTracePathEntries)
        {
            truncated = true;
            return false;
        }
        path.Add(entry);
        return true;
    }

    private static bool UseCompactPathFormat(JsonElement? arguments)
    {
        var raw = ToolSupport.ReadArgumentString(arguments, "pathFormat");
        if (raw is null)
            return true;
        if (raw.Equals("full", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    internal async Task<string> TraceUntilAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty("maxSteps", out var maxStepsElem))
        {
            if (!maxStepsElem.TryGetInt32(out var rawSteps) || rawSteps <= 0)
            {
                return BridgeEnvelope.Error("invalid_argument", "maxSteps must be a positive integer.");
            }
        }
        var maxSteps = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxSteps", 20), 1, 100);
        var stopAddress = ToolSupport.ReadArgumentString(arguments, "stopAddress");
        var stopMnemonic = ToolSupport.ReadArgumentString(arguments, "stopAt")?.Trim().ToLowerInvariant();
        var stopCondition = ToolSupport.ReadArgumentString(arguments, "condition") ?? ToolSupport.ReadArgumentString(arguments, "stopCondition");
        var stepKind = ToolSupport.ReadArgumentString(arguments, "kind") ?? "into";
        var includePath = ToolSupport.ReadArgumentBool(arguments, "includePath", false);
        if (!TryStepMethod(stepKind, out var stepMethod))
            return BridgeEnvelope.Error("invalid_argument",
                $"kind '{stepKind.Trim()}' is not 'into', 'over' or 'out'. Do not repeat the same call without changing inputs.");
        var stepArgs = ToolSupport.ToJsonElement(new JsonObject { ["count"] = 1 });

        // Bulk-step fast path: a single bridge step call
        // instead of N single-step round trips. Triggers only when count is given
        // without stop criteria; predicate tracing keeps the loop below, and
        // includePath tracing needs per-step reads so it also keeps the loop.
        var hasStopCriteria = !string.IsNullOrWhiteSpace(stopAddress)
            || !string.IsNullOrWhiteSpace(stopMnemonic)
            || !string.IsNullOrWhiteSpace(stopCondition);
        var hasCount = arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty("count", out _);
        if (hasCount && !hasStopCriteria && !includePath)
        {
            var bulkRaw = await BulkStepAndSnapshotAsync(arguments, cancellationToken).ConfigureAwait(false);
            var bulkNode = AnalysisFormatting.ReadBridgeResultNode(bulkRaw);
            if (bulkNode is JsonObject bulkObj)
            {
                // A bulk step that never paused must not masquerade as
                // count_reached: mirror the loop path and refuse the snapshot.
                if (bulkObj["step"] is JsonObject stepObj &&
                    stepObj["completed"] is JsonValue completedValue &&
                    completedValue.TryGetValue<bool>(out var completed) && !completed)
                    return BridgeEnvelope.Error("debugger_running_timeout",
                        "The target did not pause after the bulk step within the polling budget; refusing to read a live snapshot. Retry TraceUntil or pause the debugger.");
                var count = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "count", 1), 1, 100);
                // `step` only carries what `trace` already says; the final
                // context is in sections.context, so the extra disassembly
                // read that used to fill finalAddress/finalInstruction is gone.
                bulkObj.Remove("step");
                bulkObj["trace"] = new JsonObject
                {
                    ["stepsTaken"] = count,
                    ["stopReason"] = "count_reached"
                };
                PruneTraceSnapshot(bulkObj);
                return BridgeEnvelope.Success(bulkObj);
            }
            return bulkRaw;
        }

        var stepsTaken = 0;
        var stopReason = "max_steps_reached";
        var pauseUnusable = false;
        string? matchedAddress = null;
        string? matchedInstruction = null;
        // Count applies when no stop criteria are set (schema: ignored when
        // condition/stopAt/stopAddress is set). The bulk fast path above
        // handles count without includePath; the per-step loop below must
        // honor the same count when recording a path, bounded by maxSteps.
        int? countLimit = null;
        if (hasCount && !hasStopCriteria)
            countLimit = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "count", 1), 1, 100);
        var effectiveMaxSteps = countLimit.HasValue ? Math.Min(countLimit.Value, maxSteps) : maxSteps;
        var pathList = includePath ? new JsonArray() : null;
        var compactPath = UseCompactPathFormat(arguments);
        var pathTruncated = false;
        void AddPathStep(int step, string? address, string? instruction)
        {
            if (pathList is null || string.IsNullOrEmpty(address)) return;
            var entry = FormatTracePathEntry(step, address, instruction, compactPath);
            TryAddTracePathEntry(pathList, entry, ref pathTruncated);
        }

        var targetNumericAddress = TryParseHexAddress(stopAddress, out var parsedTarget)
            ? parsedTarget
            : (ulong?)null;

        async Task<(bool Matched, string Reason)> CheckTargetMatchAsync(string? addr, string? instr)
        {
            if (targetNumericAddress.HasValue && TryParseHexAddress(addr, out var curNum) &&
                curNum == targetNumericAddress.Value)
            {
                return (true, "matched_address");
            }

            if (!string.IsNullOrEmpty(stopMnemonic) && !string.IsNullOrEmpty(instr))
            {
                var instrTrimmed = instr.Trim().ToLowerInvariant();
                if (instrTrimmed == stopMnemonic || instrTrimmed.StartsWith(stopMnemonic + " ", StringComparison.Ordinal))
                {
                    return (true, $"matched_mnemonic: {stopMnemonic}");
                }

                var tokens = instrTrimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var token in tokens)
                {
                    var cleanToken = token.TrimEnd(':');
                    if (cleanToken.Equals(stopMnemonic, StringComparison.Ordinal))
                    {
                        return (true, $"matched_mnemonic: {stopMnemonic}");
                    }
                    if (token.Contains(',') || token.Contains('[') || token.Contains('+'))
                    {
                        break;
                    }
                }
            }

            if (!string.IsNullOrEmpty(stopCondition))
            {
                try
                {
                    var evalRaw = await ActiveBridge.RequestAsync("EvaluateExpression",
                        ToolSupport.ToJsonElement(new JsonObject { ["expression"] = stopCondition }),
                        cancellationToken);
                    var evalNode = AnalysisFormatting.ReadBridgeResultNode(evalRaw);
                    if (evalNode is JsonObject eObj)
                    {
                        var valHex = eObj["valueHex"]?.GetValue<string>()?.Trim() ?? eObj["value"]?.GetValue<string>()?.Trim();
                        var valUnsigned = eObj["valueUnsigned"]?.GetValue<string>()?.Trim();
                        long valDec = -1;
                        if (valUnsigned is not null && long.TryParse(valUnsigned, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedUnsigned))
                            valDec = parsedUnsigned;
                        else if (eObj["valueDecimal"] is JsonValue vDec && vDec.TryGetValue<long>(out var d))
                            valDec = d;

                        var isTruthy = false;
                        if (valDec > 0)
                        {
                            isTruthy = true;
                        }
                        else if (valHex is not null)
                        {
                            var cleanHex = valHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? valHex[2..] : valHex;
                            if (ulong.TryParse(cleanHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexVal) && hexVal > 0)
                            {
                                isTruthy = true;
                            }
                            else if (!valHex.Equals("0x0", StringComparison.OrdinalIgnoreCase) &&
                                     !valHex.Equals("0", StringComparison.OrdinalIgnoreCase) &&
                                     !valHex.Equals("false", StringComparison.OrdinalIgnoreCase) &&
                                     cleanHex.Length > 0 &&
                                     !cleanHex.All(c => c == '0'))
                            {
                                isTruthy = true;
                            }
                        }

                        if (isTruthy)
                        {
                            return (true, $"matched_condition: {stopCondition}");
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch { }
            }

            return (false, "");
        }

        // Check if debugger is already at target before stepping
        (matchedAddress, matchedInstruction) = await ReadCurrentInstructionAsync(cancellationToken);

        if (pathList is not null && !string.IsNullOrEmpty(matchedAddress))
        {
            AddPathStep(0, matchedAddress, matchedInstruction);
        }

        var (initMatched, initMatchReason) = await CheckTargetMatchAsync(matchedAddress, matchedInstruction);
        if (initMatched)
        {
            stopReason = $"already_at_target ({initMatchReason})";
        }
        else
        {
            for (var step = 0; step < effectiveMaxSteps; step++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var stepRaw = await ActiveBridge.RequestAsync(stepMethod, stepArgs, cancellationToken);
                var stepAnalysis = ToolSupport.AnalyzeBridgeResponse(stepRaw);
                if (stepAnalysis.IsError)
                {
                    stopReason = "step_error";
                    break;
                }

                stepsTaken++;

                // A single pause-wait budget of only ~450ms is not enough for
                // steps that cross a blocking syscall: allow ~3s before
                // declaring the target still running. Transient pipe hiccups
                // must not abort a multi-step trace with an exception: an
                // unconfirmed pause surfaces as debugger_running_timeout below.
                var pauseOutcome = (await WaitForPausedAsync(60, 50, swallowErrors: true, cancellationToken)).Outcome;

                if (pauseOutcome != PauseWaitOutcome.Paused)
                {
                    stopReason = "debugger_running_timeout";
                    pauseUnusable = pauseOutcome == PauseWaitOutcome.BridgeUnusable;
                    break;
                }

                var (currentAddress, currentInstr) = await ReadCurrentInstructionAsync(cancellationToken);

                matchedAddress = currentAddress;
                matchedInstruction = currentInstr;

                if (pathList is not null)
                {
                    AddPathStep(stepsTaken, currentAddress, currentInstr);
                }

                var (stepMatched, matchReason) = await CheckTargetMatchAsync(currentAddress, currentInstr);
                if (stepMatched)
                {
                    stopReason = matchReason;
                    break;
                }
            }

            // The per-step loop doubles as the includePath path-recorder: when
            // count was given without stop criteria, reaching the requested
            // count (within the maxSteps bound) is count_reached, mirroring
            // the bulk fast path. A count larger than maxSteps still reports
            // max_steps_reached; errors and timeouts above keep their reasons.
            if (stopReason == "max_steps_reached" && countLimit.HasValue &&
                stepsTaken >= countLimit.Value)
                stopReason = "count_reached";
        }

        if (stopReason == "debugger_running_timeout")
        {
            // The target never paused (or the bridge never gave a usable
            // state): reading a snapshot now would race a running process and
            // return inconsistent register/memory state.
            if (pauseUnusable)
                return BridgeEnvelope.Error("debugger_running_timeout",
                    $"The bridge did not return a usable paused/running state after {stepsTaken} step(s) within the polling budget; refusing to read a possibly live snapshot. Check the bridge connection, then retry TraceUntil or pause the debugger.");
            return BridgeEnvelope.Error("debugger_running_timeout",
                $"The target did not pause after {stepsTaken} step(s) within the polling budget; refusing to read a live snapshot. Retry TraceUntil or pause the debugger.");
        }

        var snapArgs = SnapshotOptions.Read(arguments).ToJsonElement();

        var snapshotRaw = await GetAnalysisSnapshotAsync(snapArgs, cancellationToken);
        var snapshotNode = AnalysisFormatting.ReadBridgeResultNode(snapshotRaw);
        if (snapshotNode is JsonObject snapObj)
        {
            var traceNode = new JsonObject
            {
                ["stepsTaken"] = stepsTaken,
                ["stopReason"] = stopReason
            };
            if (pathList is not null)
            {
                traceNode["path"] = pathList;
                traceNode["pathFormat"] = compactPath ? "compact" : "full";
                if (pathTruncated)
                {
                    traceNode["pathTruncated"] = true;
                    traceNode["continuation"] = "Path capped at 512 entries; repeat with smaller maxSteps.";
                }
            }
            snapObj["trace"] = traceNode;
            PruneTraceSnapshot(snapObj);
            return BridgeEnvelope.Success(snapObj);
        }

        return snapshotRaw;
    }

    /// <summary>
    /// The trace wrapper already states the stop reason and the target is
    /// paused: the snapshot's advisory nextAction is noise on every trace.
    /// </summary>
    private static void PruneTraceSnapshot(JsonObject snapshot)
    {
        if (snapshot["summary"] is JsonObject summary)
            summary.Remove("nextAction");
    }

    /// <summary>
    /// ProbeFunction: stage a live call injection, run it, wait for the target
    /// to pause at the temporary return breakpoint, then read the return
    /// register back in the same tool call. Native methods are reused
    /// unchanged (CallFunction, GetSnapshotState polling, EvaluateExpression);
    /// a failure in any step passes the bridge error through so the caller
    /// knows which step failed by the bridge request count. An optional
    /// expected value is compared numerically against the evaluated return
    /// value. With runAfter=false the call is only staged (no return value or
    /// verdict): reading a register before the call executes would be stale.
    /// The pause wait budget defaults to DefaultProbeWaitMs and an optional
    /// waitMs argument extends it, clamped to 0..MaxProbeWaitMs. A success
    /// result carries executed:true, which is only emitted after the native
    /// return capture proves the injected ret landed on the return
    /// breakpoint; any other pause fails with probe_call_did_not_return and
    /// reports no register, so a stale rax can never read as a call result.
    /// </summary>
    internal async Task<string> ProbeFunctionAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var address = ToolSupport.ReadArgumentString(arguments, "address");
        if (string.IsNullOrWhiteSpace(address))
            return BridgeEnvelope.Error("invalid_argument",
                "ProbeFunction needs address. Do not repeat the same call without changing inputs.");
        var returnExpression = ToolSupport.ReadArgumentString(arguments, "returnExpression");
        // The default return register is architecture-aware: rax on x64, eax
        // on x86. The bridge protocol carries no arch field, so the default
        // tries rax first and retries once with eax when the debugger reports
        // the expression itself unknown (x86 has no rax). An explicit
        // returnExpression is never retried: its bridge error passes through.
        var defaultReturnExpression = string.IsNullOrWhiteSpace(returnExpression);
        if (defaultReturnExpression)
            returnExpression = "rax";
        var expected = ToolSupport.ReadArgumentString(arguments, "expected");
        var runAfter = true;
        if (arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty("runAfter", out var runAfterElement) &&
            runAfterElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
            runAfter = runAfterElement.GetBoolean();

        var callPayload = new JsonObject { ["address"] = address, ["runAfter"] = runAfter };
        foreach (var key in new[] { "arg1", "arg2", "arg3", "arg4" })
        {
            var value = ToolSupport.ReadArgumentString(arguments, key);
            if (value is not null)
                callPayload[key] = value;
        }

        var callRaw = await ActiveBridge.RequestAsync("CallFunction",
            ToolSupport.ToJsonElement(callPayload), cancellationToken).ConfigureAwait(false);
        if (ToolSupport.AnalyzeBridgeResponse(callRaw).IsError)
            return callRaw;

        var callNode = AnalysisFormatting.ReadBridgeResultNode(callRaw);
        if (callNode is null)
            return BridgeEnvelope.Error("backend_error",
                "ProbeFunction got an unreadable CallFunction response. Retry the probe or read the state with GetAnalysisSnapshot.");

        if (!runAfter)
        {
            // Staged only: the injected call has NOT executed, so any register
            // read would be the pre-call value. Refuse to emit a verdict.
            return BridgeEnvelope.Success(new JsonObject
            {
                ["address"] = address,
                ["staged"] = true,
                ["call"] = callNode,
                ["note"] = "The call is staged but not executed (runAfter=false): no return value or matched verdict exists until the target runs. Use runAfter=true (default) to execute the call and read the return register after it pauses.",
            });
        }

        // The return register is only meaningful once the injected call has
        // returned and the target paused at the temporary return breakpoint:
        // reading it while the target runs (or before the call executes) is
        // stale or garbage. Wait for the pause first, then read. The budget
        // defaults to DefaultProbeWaitMs (the historical 60x50ms) and the
        // optional waitMs argument extends it, clamped to 0..MaxProbeWaitMs.
        var waitMs = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "waitMs", DefaultProbeWaitMs), 0, MaxProbeWaitMs);
        var maxAttempts = Math.Clamp((waitMs + PausePollIntervalMs - 1) / PausePollIntervalMs,
            1, MaxProbeWaitMs / PausePollIntervalMs);
        var (pauseOutcome, pausedState) = await WaitForPausedAsync(maxAttempts, PausePollIntervalMs, swallowErrors: true, cancellationToken);
        if (pauseOutcome == PauseWaitOutcome.BridgeUnusable)
            return BridgeEnvelope.Error("debugger_running_timeout",
                $"ProbeFunction: the bridge did not return a usable paused/running state after the injected call within the polling budget (waitMs={waitMs}); refusing to read a possibly racing register. Check the bridge connection or pause the debugger, then retry.");
        if (pauseOutcome != PauseWaitOutcome.Paused)
            return BridgeEnvelope.Error("debugger_running_timeout",
                $"ProbeFunction: the target did not pause after the injected call within the polling budget (waitMs={waitMs}); refusing to read a racing register. Inspect the target with GetAnalysisSnapshot or pause it manually, then retry.");

        // The pause alone does not prove the call executed: a fault inside
        // the injected call (e.g. a static image address such as 0x140001000
        // instead of live = moduleBase + RVA) or an unrelated breakpoint
        // pauses the target the same way. The native bridge only merges
        // returnValue/registersAfter into the first ok:true result after the
        // injected ret genuinely lands on the return breakpoint, so a paused
        // state without that capture means rax is stale and must never be
        // reported as the call result.
        if (pausedState is not JsonObject pausedObj || pausedObj["returnValue"] is null)
        {
            var returnBreakpoint = callNode is JsonObject callObj &&
                callObj["returnBreakpoint"] is JsonValue returnBp &&
                returnBp.TryGetValue<string>(out var returnBpText) ? returnBpText : "unknown";
            return BridgeEnvelope.Error("probe_call_did_not_return",
                $"ProbeFunction: the target paused, but the injected call did not land on its return breakpoint ({returnBreakpoint}); no native return capture exists, so no return value is reported. The call may have faulted (a static image address instead of live = moduleBase + RVA is the usual cause) or the pause came from elsewhere. Inspect the target with GetAnalysisSnapshot (check cip) or retry with a live address.");
        }

        var evalRaw = await ActiveBridge.RequestAsync("EvaluateExpression",
            ToolSupport.ToJsonElement(new JsonObject { ["expression"] = returnExpression }),
            cancellationToken).ConfigureAwait(false);
        if (defaultReturnExpression &&
            string.Equals(returnExpression, "rax", StringComparison.Ordinal) &&
            ToolSupport.AnalyzeBridgeResponse(evalRaw).IsError &&
            IsUnknownExpressionError(evalRaw))
        {
            returnExpression = "eax";
            evalRaw = await ActiveBridge.RequestAsync("EvaluateExpression",
                ToolSupport.ToJsonElement(new JsonObject { ["expression"] = returnExpression }),
                cancellationToken).ConfigureAwait(false);
        }
        if (ToolSupport.AnalyzeBridgeResponse(evalRaw).IsError)
            return evalRaw;

        var evalNode = AnalysisFormatting.ReadBridgeResultNode(evalRaw);
        if (evalNode is null)
            return BridgeEnvelope.Error("backend_error",
                "ProbeFunction got an unreadable EvaluateExpression response. Retry the probe or read the state with GetAnalysisSnapshot.");

        var result = new JsonObject
        {
            ["address"] = address,
            ["returnExpression"] = returnExpression,
            ["executed"] = true,
            ["call"] = callNode,
            ["returnValue"] = evalNode,
        };
        if (!string.IsNullOrWhiteSpace(expected))
        {
            result["expected"] = expected;
            result["matched"] = IsProbeExpectedMatch(expected, evalNode);
        }
        return BridgeEnvelope.Success(result);
    }

    /// <summary>
    /// Batch probes (1..4 hypotheses, one model turn): each row resolves its
    /// address (live as-is, static function via Ghidra identity plus live
    /// mapping) and runs the unchanged single-probe path, so per-probe
    /// semantics match ProbeFunction exactly. Safety: a faulted or
    /// not-landed probe hard-stops the batch (later rows report skipped, never
    /// execute on a possibly disturbed stack); mapping misses and argument
    /// errors fail only their row. The top-level waitMs is a shared pause-wait
    /// budget split across remaining rows; runAfter=false is single-row only
    /// (staging a batch would leave N shifted frames behind).
    /// </summary>
    internal const int MaxBatchProbes = 8;

    internal async Task<string> ProbeBatchAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } args ||
            !args.TryGetProperty("probes", out var probesElement) ||
            probesElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return await ProbeFunctionAsync(arguments, cancellationToken).ConfigureAwait(false);

        if (probesElement.ValueKind != JsonValueKind.Array)
            return BridgeEnvelope.Error("invalid_argument",
                "probes must be an array of 1..4 probe objects. Do not repeat the same call without changing inputs.");
        var probes = probesElement.EnumerateArray().ToArray();
        if (probes.Length is < 1 or > MaxBatchProbes)
            return BridgeEnvelope.Error("invalid_argument",
                $"probes must contain 1..{MaxBatchProbes} entries, got {probes.Length}. Do not repeat the same call without changing inputs.");

        var runAfter = true;
        if (args.TryGetProperty("runAfter", out var runAfterElement) &&
            runAfterElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
            runAfter = runAfterElement.GetBoolean();
        if (!runAfter && probes.Length > 1)
            return BridgeEnvelope.Error("invalid_argument",
                "runAfter=false stages without executing: batch staging would leave several shifted frames behind. " +
                "Probe one function with runAfter=false, or run the batch with runAfter=true (default).");
        var waitMs = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "waitMs", DefaultProbeWaitMs), 0, MaxProbeWaitMs);
        var verifyHash = ToolSupport.ReadArgumentBool(arguments, "verifyHash", true);

        // Validate every row up front: no backend call on a bad shape.
        for (var validateIndex = 0; validateIndex < probes.Length; validateIndex++)
        {
            var error = ValidateProbeRow(probes[validateIndex], validateIndex);
            if (error is not null)
                return error;
        }

        var rows = new JsonArray();
        var matched = 0;
        var executed = 0;
        var hashCache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var startedAt = Environment.TickCount64;
        var stopped = false;
        var stopReason = "";
        for (var index = 0; index < probes.Length; index++)
        {
            var row = probes[index];
            var selector = ProbeRowSelector(row);
            if (stopped)
            {
                rows.Add(new JsonObject
                {
                    ["index"] = index,
                    ["selector"] = selector,
                    ["skipped"] = true,
                    ["reason"] = stopReason,
                });
                continue;
            }

            // Resolve the live address: direct for address rows, Ghidra
            // identity plus live mapping for function rows (one shared hash
            // cache and per-path cached module tables across the batch).
            string liveAddress;
            JsonObject? mapping = null;
            var address = ToolSupport.ReadArgumentString(row, "address");
            if (!string.IsNullOrWhiteSpace(address))
            {
                liveAddress = address;
            }
            else
            {
                var function = ToolSupport.ReadArgumentString(row, "function")!;
                var staticRaw = await ActiveGhidra.RequestAsync("InspectFunction",
                    ToolSupport.ToJsonElement(new JsonObject
                    {
                        ["function"] = function,
                        ["maxChars"] = 4000,
                        ["maxItems"] = 4,
                        ["includeDecomp"] = false,
                    }), cancellationToken).ConfigureAwait(false);
                var staticAnalysis = ToolSupport.AnalyzeBridgeResponse(staticRaw);
                if (staticAnalysis.IsError)
                {
                    rows.Add(ProbeRowError(index, selector,
                        BridgeClient.TryParseErrorCode(staticRaw) ?? "mapping_unavailable", staticAnalysis.Text));
                    continue;
                }
                if (!AddressMapping.TryReadStaticFunction(staticRaw, out var staticFunction, out var staticError))
                {
                    rows.Add(ProbeRowError(index, selector, "mapping_identity_unavailable", staticError));
                    continue;
                }
                var mappingNode = await AddressMapping.BuildLiveMappingAsync(
                    ActiveBridge, staticFunction, verifyHash, cancellationToken, null, hashCache).ConfigureAwait(false);
                if (AnalysisFormatting.ReadNodeNullableBool(mappingNode, "match") != true ||
                    AnalysisFormatting.ReadNodeString(mappingNode, "liveAddress") is not string { } mappedAddress ||
                    string.IsNullOrWhiteSpace(mappedAddress))
                {
                    var reason = AnalysisFormatting.ReadNodeString(mappingNode, "reason") ?? "module_identity_not_found";
                    rows.Add(ProbeRowError(index, selector, reason,
                        $"No live module matched '{function}' ({reason})."));
                    continue;
                }
                liveAddress = mappedAddress;
                mapping = new JsonObject { ["match"] = true };
            }

            var remaining = probes.Length - index;
            var sliceMs = (int)Math.Max(0, (waitMs - (Environment.TickCount64 - startedAt)) / remaining);
            var probeArgs = new JsonObject
            {
                ["address"] = liveAddress,
                ["runAfter"] = runAfter,
                ["waitMs"] = sliceMs,
            };
            foreach (var key in new[] { "arg1", "arg2", "arg3", "arg4", "returnExpression", "expected" })
            {
                var value = ToolSupport.ReadArgumentString(row, key);
                if (value is not null)
                    probeArgs[key] = value;
            }
            var raw = await ProbeFunctionAsync(
                ToolSupport.ToJsonElement(probeArgs), cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            var ok = root.TryGetProperty("ok", out var okElement) && okElement.ValueKind == JsonValueKind.True;
            if (!ok)
            {
                var code = root.TryGetProperty("error", out var errorElement) &&
                    errorElement.ValueKind == JsonValueKind.Object &&
                    errorElement.TryGetProperty("code", out var codeElement) &&
                    codeElement.ValueKind == JsonValueKind.String
                    ? codeElement.GetString()!
                    : "backend_error";
                var message = errorElement.ValueKind == JsonValueKind.Object &&
                    errorElement.TryGetProperty("message", out var messageElement) &&
                    messageElement.ValueKind == JsonValueKind.String
                    ? messageElement.GetString()!
                    : "Probe failed.";
                rows.Add(ProbeRowError(index, selector, code, message));
                // A faulted or still-running target after an injected call
                // means the debugger state may be disturbed: never run later
                // rows on it. Other failures staged nothing, so the batch goes on.
                if (code is "probe_call_did_not_return" or "debugger_running_timeout")
                {
                    stopped = true;
                    stopReason = code == "probe_call_did_not_return"
                        ? "Stopped: an injected call did not land, later rows are skipped, not executed."
                        : "Stopped: the target did not pause in budget, later rows are skipped, not executed.";
                }
                continue;
            }

            var result = root.TryGetProperty("result", out var resultElement) &&
                resultElement.ValueKind == JsonValueKind.Object
                ? JsonNode.Parse(resultElement.GetRawText())!.AsObject()
                : new JsonObject();
            result.Remove("call");
            result.Remove("note");
            result["index"] = index;
            result["selector"] = selector;
            if (mapping is not null)
            {
                result["liveAddress"] = liveAddress;
                result["mapping"] = mapping;
            }
            if (result["executed"] is JsonValue executedValue &&
                executedValue.TryGetValue<bool>(out var didExecute) && didExecute)
                executed++;
            if (result["matched"] is JsonValue matchedValue &&
                matchedValue.TryGetValue<bool>(out var didMatch) && didMatch)
                matched++;
            rows.Add(result);
        }

        var envelope = new JsonObject
        {
            ["probes"] = probes.Length,
            ["matched"] = matched,
            ["executed"] = executed,
            ["results"] = rows,
        };
        if (stopped)
        {
            envelope["stoppedEarly"] = true;
            envelope["stopReason"] = stopReason;
        }
        return BridgeEnvelope.Success(envelope);
    }

    private static string? ValidateProbeRow(JsonElement row, int index)
    {
        string Invalid(string message) =>
            BridgeEnvelope.Error("invalid_argument", $"probes[{index}]: {message} Do not repeat the same call without changing inputs.");
        if (row.ValueKind != JsonValueKind.Object)
            return Invalid("each entry must be an object.");
        var address = ToolSupport.ReadArgumentString(row, "address");
        var function = ToolSupport.ReadArgumentString(row, "function");
        var hasAddress = !string.IsNullOrWhiteSpace(address);
        var hasFunction = !string.IsNullOrWhiteSpace(function);
        if (hasAddress == hasFunction)
            return Invalid("exactly one of address (live) or function (Ghidra selector) is required.");
        var selector = hasAddress ? address! : function!;
        if (selector.Length > 256)
            return Invalid("the address/function selector is too long.");
        return null;
    }

    private static string ProbeRowSelector(JsonElement row)
        => ToolSupport.ReadArgumentString(row, "address") is { } address && !string.IsNullOrWhiteSpace(address)
            ? address
            : ToolSupport.ReadArgumentString(row, "function") ?? "";

    private static JsonObject ProbeRowError(int index, string selector, string code, string message)
    {
        var truncated = false;
        return new JsonObject
        {
            ["index"] = index,
            ["selector"] = selector,
            ["ok"] = false,
            ["code"] = code,
            ["message"] = ToolSupport.LimitSnapshotText(message, 256, ref truncated),
        };
    }

    /// <summary>
    /// True when a failed EvaluateExpression means the expression itself is
    /// unknown to the debugger (e.g. rax on an x86 target), as opposed to a
    /// session or transport failure ("No active debug session.", timeouts).
    /// Only the default return register retries on this, never an explicit
    /// caller expression. Never throws.
    /// </summary>
    internal static bool IsUnknownExpressionError(string raw)
    {
        try
        {
            if (!string.Equals(BridgeClient.TryParseErrorCode(raw), "native_error", StringComparison.Ordinal))
                return false;
            return ToolSupport.AnalyzeBridgeResponse(raw, includeText: true).Text
                .Contains("Could not evaluate expression", StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Compare an expected probe value against an EvaluateExpression result:
    /// 0x... hex and plain decimals compare numerically (so 0x5 matches the
    /// zero-padded native valueHex and valueUnsigned 5); anything else falls
    /// back to a case-insensitive string match on the reported fields.
    /// </summary>
    internal static bool IsProbeExpectedMatch(string expected, JsonNode? returnValue)
    {
        var want = expected.Trim();
        string? hex = null;
        string? unsignedText = null;
        string? signedText = null;
        if (returnValue is JsonObject obj)
        {
            try
            {
                hex = obj["valueHex"]?.GetValue<string>();
                unsignedText = obj["valueUnsigned"]?.GetValue<string>();
                signedText = obj["valueSigned"]?.GetValue<string>();
            }
            catch (InvalidOperationException) { }
        }
        if (TryParseProbeUnsigned(want, out var wantValue))
        {
            foreach (var candidate in new[] { hex, unsignedText })
            {
                if (candidate is not null &&
                    TryParseProbeUnsigned(candidate, out var got) && got == wantValue)
                    return true;
            }
            return false;
        }
        if (long.TryParse(want, NumberStyles.Integer, CultureInfo.InvariantCulture, out var wantSigned) &&
            signedText is not null &&
            long.TryParse(signedText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var gotSigned))
            return wantSigned == gotSigned;
        return string.Equals(hex, want, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(unsignedText, want, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(signedText, want, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseProbeUnsigned(string text, out ulong value)
    {
        value = 0;
        var clean = text.Trim();
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(clean[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        if (clean.StartsWith("-", StringComparison.Ordinal))
            return false;
        return ulong.TryParse(clean, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }
}

