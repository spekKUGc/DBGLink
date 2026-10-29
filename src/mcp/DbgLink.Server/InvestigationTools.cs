using DbgLink.Shared;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace DbgLink.Server;

internal sealed class InvestigationTools
{
    private readonly AnalysisContext _context;
    private IBridgeClient ActiveBridge => _context.Bridge;
    private IGhidraClient ActiveGhidra => _context.Ghidra;
    private static readonly JsonSerializerOptions _jsonOptions = ToolSupport.BudgetJsonOptions;
    private readonly LiveAnalysisTools _liveAnalysisTools;
    public InvestigationTools(AnalysisContext context, LiveAnalysisTools liveAnalysisTools)
    {
        _context = context;
        _liveAnalysisTools = liveAnalysisTools;
    }

    internal async Task<(JsonNode? Node, ToolSupport.StaticFunction? Function, JsonArray Errors)> GetStaticFunctionEvidenceAsync(
        string functionSelector,
        int maxChars,
        int maxItems,
        bool includeDecomp,
        bool includeDisassembly,
        bool includeReferences,
        bool includeSymbols,
        bool includeStrings,
        bool includeConstants,
        CancellationToken cancellationToken)
    {
        var staticArguments = JsonSerializer.SerializeToElement(new
        {
            function = functionSelector,
            maxChars = Math.Clamp(maxChars / 2, 1_000, 30_000),
            maxItems,
            includeDecomp,
            includeDisassembly,
            includeReferences,
            includeSymbols,
            includeStrings,
            includeConstants,
        });
        var staticRaw = await ActiveGhidra.RequestAsync("InspectFunction", staticArguments, cancellationToken);

        var errors = new JsonArray();
        var staticNode = AnalysisFormatting.ReadBridgeResultNode(staticRaw);
        ToolSupport.StaticFunction? staticFunction = null;
        var staticErrorTruncated = false;
        var staticAnalysis = ToolSupport.AnalyzeBridgeResponse(staticRaw);
        if (staticAnalysis.IsError)
        {
            errors.Add(new JsonObject
            {
                ["section"] = "static",
                ["code"] = "ghidra_error",
                ["message"] = ToolSupport.LimitSnapshotText(staticAnalysis.Text, 512, ref staticErrorTruncated),
            });
        }
        else if (!AddressMapping.TryReadStaticFunction(staticRaw, out staticFunction, out var staticError))
        {
            errors.Add(new JsonObject
            {
                ["section"] = "static",
                ["code"] = "mapping_identity_unavailable",
                ["message"] = staticError,
            });
        }

        return (staticNode, staticFunction, errors);
    }

    internal const int MaxBriefFunctions = 4;

    internal static bool TryReadBriefSelectors(
        JsonElement? arguments, out List<string> selectors, out bool batch, out string error)
    {
        selectors = [];
        batch = false;
        error = "";
        var single = ToolSupport.ReadArgumentString(arguments, "function");
        JsonElement functionsElement = default;
        var hasFunctions = arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty("functions", out functionsElement) &&
            functionsElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined);
        if (!string.IsNullOrWhiteSpace(single) && hasFunctions)
        {
            error = "Pass function or functions, not both.";
            return false;
        }
        if (hasFunctions)
        {
            if (functionsElement.ValueKind != JsonValueKind.Array)
            {
                error = "functions must be an array of 1..4 function selectors.";
                return false;
            }
            foreach (var item in functionsElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    error = "functions must be an array of 1..4 function selectors.";
                    return false;
                }
                var selector = item.GetString();
                if (string.IsNullOrWhiteSpace(selector) || selector.Length > 256)
                {
                    error = "Each functions entry must be a non-blank selector of at most 256 chars.";
                    return false;
                }
                selectors.Add(selector);
            }
            if (selectors.Count is < 1 or > MaxBriefFunctions)
            {
                error = $"functions must contain 1..{MaxBriefFunctions} selectors.";
                return false;
            }
            batch = true;
            return true;
        }
        if (string.IsNullOrWhiteSpace(single) || single.Length > 256)
        {
            error = "function or functions is required.";
            return false;
        }
        selectors.Add(single);
        return true;
    }

    internal async Task<string> GetInvestigationBriefAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // Single mode (function) keeps backward compatibility; multi mode
        // (functions, 1..4 selectors) returns one brief whose sections.static
        // is a per-function packet sharing the common maxChars budget.
        if (!TryReadBriefSelectors(arguments, out var selectors, out var batch, out var selectorError))
            return BridgeEnvelope.Error("invalid_argument", selectorError);
        var multi = batch;
        // Defense in depth: the tool schema already bounds these knobs, but
        // internal callers bypass validation, so clamp here before the budget
        // is split between the static and live sections.
        var maxChars = ToolSupport.ReadResponseBudget(arguments, 16_000, 4_000, 60_000, out var maxTokens);
        var maxItems = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxItems", 16), 1, 64);
        var maxFrames = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxFrames", 8), 1, 32);
        var verifyHash = ToolSupport.ReadArgumentBool(arguments, "verifyHash", true);
        var includeLive = ToolSupport.ReadArgumentBool(arguments, "includeLive", true);
        var includeThreads = ToolSupport.ReadArgumentBool(arguments, "includeThreads", false);
        var includeModules = ToolSupport.ReadArgumentBool(arguments, "includeModules", false);
        var includeDecomp = ToolSupport.ReadArgumentBool(arguments, "includeDecomp", false);
        var includeDisassembly = ToolSupport.ReadArgumentBool(arguments, "includeDisassembly", false);
        var includeReferences = ToolSupport.ReadArgumentBool(arguments, "includeReferences", true);
        var includeSymbols = ToolSupport.ReadArgumentBool(arguments, "includeSymbols", false);
        var includeStrings = ToolSupport.ReadArgumentBool(arguments, "includeStrings", true);
        // Constants are the noisiest section and default off. They remain one explicit flag away.
        var includeConstants = ToolSupport.ReadArgumentBool(arguments, "includeConstants", false);
        // P1-7 opt-in, default OFF: the default brief bytes are unchanged.
        var includeLiveBytes = ToolSupport.ReadArgumentBool(arguments, "includeLiveBytes", false);
        // Slim correlation view by default: registers + status + thread id +
        // a bounded folded callstack. The opt-in restores the old full clone
        // (disassembly, stack dump, module table).
        var includeLiveDetail = ToolSupport.ReadArgumentBool(arguments, "includeLiveDetail", false);
        var primarySelector = selectors[0];

        var errors = new JsonArray();
        var staticNodes = new List<JsonNode?>(selectors.Count);
        var staticFunctions = new List<ToolSupport.StaticFunction?>(selectors.Count);
        var staticReadyCount = 0;
        // The static budget is shared: each InspectFunction gets an equal
        // slice so N functions cost ~one single-function brief in total.
        var perFunctionChars = Math.Max(1_000, maxChars / selectors.Count);
        // The bridge runs up to four decompiler workers: issue the independent
        // static reads together instead of serially. Results are still folded
        // in selector order, so the wire packet stays deterministic.
        var evidenceTasks = selectors
            .Select(selector => GetStaticFunctionEvidenceAsync(
                selector,
                perFunctionChars,
                maxItems,
                includeDecomp,
                includeDisassembly,
                includeReferences,
                includeSymbols,
                includeStrings,
                includeConstants,
                cancellationToken))
            .ToArray();
        var staticEvidence = await Task.WhenAll(evidenceTasks).ConfigureAwait(false);
        for (var index = 0; index < staticEvidence.Length; index++)
        {
            var evidence = staticEvidence[index];
            if (multi)
                foreach (var error in evidence.Errors)
                {
                    if (error is JsonObject errorObject)
                        errorObject["function"] = selectors[index];
                    errors.Add(error?.DeepClone());
                }
            else
                foreach (var error in evidence.Errors)
                    errors.Add(error?.DeepClone());
            staticNodes.Add(evidence.Node);
            staticFunctions.Add(evidence.Function);
            if (evidence.Function is not null)
                staticReadyCount++;
        }
        var staticFunction = staticFunctions[0];
        // The compact module summary is hoisted once; the per-function copy is
        // pure duplication and is stripped before the static section ships.
        var moduleSummary = staticNodes.FirstOrDefault() is JsonObject firstStatic &&
            firstStatic["function"] is JsonObject firstFunction &&
            firstFunction["module"] is JsonObject firstModule &&
            firstModule["summary"] is JsonObject summaryNode
            ? summaryNode
            : null;
        PruneStaticEvidence(staticNodes);
        JsonNode? staticSection;
        if (!multi)
        {
            staticSection = staticNodes[0];
        }
        else
        {
            var packet = new JsonArray();
            for (var index = 0; index < selectors.Count; index++)
            {
                var node = staticNodes[index];
                if (node is JsonObject evidence && staticFunctions[index] is not null)
                {
                    var entry = (JsonObject)evidence.DeepClone();
                    entry["index"] = index;
                    entry["selector"] = selectors[index];
                    entry["ok"] = true;
                    packet.Add(entry);
                }
                else
                {
                    packet.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["selector"] = selectors[index],
                        ["ok"] = false,
                        ["code"] = "static_unavailable",
                        ["message"] = "Ghidra did not return evidence for this function.",
                    });
                }
            }
            staticSection = new JsonObject
            {
                ["count"] = selectors.Count,
                ["functions"] = packet,
            };
        }

        JsonNode? liveNode = null;
        var nativeCalls = 0;
        if (includeLive)
        {
            var liveArguments = ToolSupport.ToJsonElement(new JsonObject
            {
                // The slim view still bounds the raw fetch: at most 8 frames
                // ride along even when the caller raised maxFrames.
                ["maxFrames"] = includeLiveDetail ? maxFrames : Math.Min(maxFrames, 8),
                ["maxChars"] = Math.Clamp(maxChars * 2 / 5, 2_000, 30_000),
                ["includeThreads"] = includeThreads,
                // Fetch modules inside the batched snapshot when a mapping is
                // possible: the module table is needed, and riding along
                // removes the separate GetModuleRecords round trip. Callers
                // that did not ask for modules get the section stripped below.
                ["includeModules"] = includeModules || staticFunctions.Exists(fn => fn is not null),
                // Mapping matches on the live module path, which the snapshot
                // strips by default: always fetch it internally and strip the
                // table (or slim the whole section) before shipping.
                ["includeModulePaths"] = true,
                // Status is already available through GetServerStatus; the
                // brief does not need to duplicate its full telemetry node.
                ["includeStatus"] = false,
                ["instructionBytes"] = 16,
                ["stackBytes"] = 32,
                ["compactModules"] = true,
                ["compactStack"] = true,
                ["sparseRegisters"] = true,
            });
            var liveRaw = await _liveAnalysisTools.GetAnalysisSnapshotAsync(liveArguments, cancellationToken);
            liveNode = AnalysisFormatting.ReadBridgeResultNode(liveRaw);
            nativeCalls = AnalysisFormatting.ReadNodeInt(liveNode, "bridgeCalls");
            if (liveNode is null)
            {
                errors.Add(new JsonObject
                {
                    ["section"] = "live",
                    ["code"] = "snapshot_unavailable",
                    ["message"] = "The dynamic snapshot did not return structured JSON.",
                });
            }
            else
            {
                AnalysisFormatting.AddChildErrors(errors, "live", liveNode);
            }
        }

        JsonNode? mappingNode = null;
        var mappingFromSnapshot = false;
        if (includeLive && !multi && !includeLiveBytes)
        {
            // Historical single-function path: byte-identical output when the
            // opt-in is absent. Do not add fields here.
            if (staticFunction is null)
            {
                mappingNode = new JsonObject
                {
                    ["match"] = false,
                    ["reason"] = "static_identity_unavailable",
                };
            }
            else
            {
                var snapshotModules = AnalysisFormatting.ParseSnapshotModules(liveNode);
                if (snapshotModules is not AddressMapping.LiveModuleCollection { Truncated: true })
                {
                    mappingNode = await AddressMapping.BuildMappingResultAsync(
                        staticFunction, snapshotModules, verifyHash, cancellationToken);
                    mappingFromSnapshot = true;
                }
                else
                {
                    nativeCalls++;
                    mappingNode = await AddressMapping.BuildLiveMappingAsync(
                        ActiveBridge, staticFunction, verifyHash, cancellationToken);
                }
            }
        }
        else if (includeLive)
        {
            // P1-7 unified path: map ALL N selectors reusing ONE module table
            // (snapshot modules when complete, else one shared fetch),
            // reusing BuildMappingResultAsync per selector. Opt-in liveBytes
            // attaches one bounded read per matched function.
            if (staticReadyCount == 0)
            {
                // No static identity to map: honest per-selector reasons with
                // no module-table fetch.
                mappingFromSnapshot = false;
                if (!multi)
                {
                    mappingNode = new JsonObject
                    {
                        ["match"] = false,
                        ["reason"] = "static_identity_unavailable",
                    };
                }
                else
                {
                    var emptyPacket = new JsonArray();
                    for (var emptyIndex = 0; emptyIndex < selectors.Count; emptyIndex++)
                        emptyPacket.Add(new JsonObject
                        {
                            ["index"] = emptyIndex,
                            ["selector"] = selectors[emptyIndex],
                            ["mapping"] = new JsonObject
                            {
                                ["match"] = false,
                                ["reason"] = "static_identity_unavailable",
                            },
                        });
                    mappingNode = new JsonObject
                    {
                        ["count"] = selectors.Count,
                        ["mappings"] = emptyPacket,
                    };
                }
            }
            else if (!multi)
            {
                // Single selector with opt-in bytes: same table source as the
                // default path (snapshot, else targeted), plus enrichment.
                var snapshotModules = AnalysisFormatting.ParseSnapshotModules(liveNode);
                JsonObject single;
                if (snapshotModules is not AddressMapping.LiveModuleCollection { Truncated: true })
                {
                    single = await AddressMapping.BuildMappingResultAsync(
                        staticFunction!, snapshotModules, verifyHash, cancellationToken);
                    mappingFromSnapshot = true;
                }
                else
                {
                    nativeCalls++;
                    single = await AddressMapping.BuildLiveMappingAsync(
                        ActiveBridge, staticFunction!, verifyHash, cancellationToken);
                }
                if (AnalysisFormatting.ReadNodeNullableBool(single, "match") == true)
                {
                    var liveAddress = AnalysisFormatting.ReadNodeString(single, "liveAddress");
                    if (includeLiveBytes && !string.IsNullOrWhiteSpace(liveAddress))
                    {
                        nativeCalls++;
                        single["liveBytes"] = await AddressMapping.ReadLiveBytesAsync(
                            ActiveBridge, liveAddress!, cancellationToken);
                    }
                    AddressMapping.AttachBreakpointHint(single, staticFunction!);
                }
                mappingNode = single;
            }
            else
            {
                var snapshotModules = AnalysisFormatting.ParseSnapshotModules(liveNode);
                IReadOnlyList<ToolSupport.LiveModule> sharedTable;
                if (snapshotModules is not AddressMapping.LiveModuleCollection { Truncated: true })
                {
                    sharedTable = snapshotModules;
                    mappingFromSnapshot = true;
                }
                else
                {
                    // One shared fetch for all selectors, not N targeted fetches.
                    // The session-scoped cache also serves breakpoint/module
                    // resolution, so a warm table costs no round trip.
                    nativeCalls++;
                    IReadOnlyList<ToolSupport.LiveModule>? fetched = null;
                    try
                    {
                        fetched = await AddressMapping.ReadCachedModuleTableAsync(
                            ActiveBridge,
                            callToken => ActiveBridge.RequestAsync("GetModuleRecords",
                                ToolSupport.ToJsonElement(new JsonObject()), callToken),
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or JsonException)
                    {
                        fetched = null;
                    }
                    sharedTable = fetched
                        ?? new AddressMapping.LiveModuleCollection { Truncated = true };
                    mappingFromSnapshot = false;
                }

                var packet = new JsonArray();
                // One module table is shared by every selector. Hoist it and
                // reference it by index instead of repeating path/hash/module
                // identity in each mapping entry.
                var moduleTable = new JsonArray();
                var moduleIndexes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                // One hash cache for the whole brief: every selector probes
                // the same live modules, so hash each file once.
                var hashCache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                for (var index = 0; index < selectors.Count; index++)
                {
                    var selectorFunction = staticFunctions[index];
                    JsonObject entryMapping;
                    if (selectorFunction is null)
                    {
                        entryMapping = new JsonObject
                        {
                            ["match"] = false,
                            ["reason"] = "static_identity_unavailable",
                        };
                    }
                    else
                    {
                        entryMapping = await AddressMapping.BuildMappingResultAsync(
                            selectorFunction, sharedTable, verifyHash, cancellationToken, hashCache);
                        if (AnalysisFormatting.ReadNodeNullableBool(entryMapping, "match") == true)
                        {
                            var liveAddress = AnalysisFormatting.ReadNodeString(entryMapping, "liveAddress");
                            if (includeLiveBytes && !string.IsNullOrWhiteSpace(liveAddress))
                            {
                                nativeCalls++;
                                entryMapping["liveBytes"] = await AddressMapping.ReadLiveBytesAsync(
                                    ActiveBridge, liveAddress!, cancellationToken);
                            }
                            AddressMapping.AttachBreakpointHint(entryMapping, selectorFunction);
                        }
                    }
                    CompactMappingEntry(entryMapping, moduleTable, moduleIndexes);
                    packet.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["selector"] = selectors[index],
                        ["mapping"] = entryMapping,
                    });
                }
                mappingNode = new JsonObject
                {
                    ["count"] = selectors.Count,
                    ["modules"] = moduleTable,
                    ["mappings"] = packet,
                };
            }
        }

        // Internal module fetch for mapping: strip the table and its summary
        // counters unless the caller asked for them, so the live section keeps
        // its old compact shape and token cost. The default slim view
        // (includeLiveDetail=false) additionally drops the disassembly/stack
        // clone: registers + status + thread id + bounded callstack is what
        // correlation needs, and mapping already carries module identity.
        // Read the snapshot savings BEFORE SlimLiveForBrief replaces liveNode
        // with its slim projection (which no longer carries them).
        var snapshotRoundTripsSaved = AnalysisFormatting.ReadNodeInt(liveNode, "roundTripsSaved");
        if (!includeLiveDetail && liveNode is JsonObject liveSlim)
            liveNode = SlimLiveForBrief(liveSlim);
        if (!includeModules && liveNode is JsonObject liveObject)
        {
            if (liveObject["sections"] is JsonObject liveSections)
                liveSections.Remove("modules");
            if (liveObject["summary"] is JsonObject liveSummary)
            {
                liveSummary.Remove("moduleStatus");
                liveSummary.Remove("moduleCount");
                liveSummary.Remove("modulesTruncated");
            }
        }

        var sections = new JsonObject();
        var truncated = false;
        var remainingChars = Math.Max(0, maxChars - 768);
        AnalysisFormatting.AddBoundedSection(sections, "static", staticSection, ref remainingChars, ref truncated);
        AnalysisFormatting.AddBoundedSection(sections, "mapping", mappingNode, ref remainingChars, ref truncated);
        AnalysisFormatting.AddBoundedSection(sections, "live", liveNode, ref remainingChars, ref truncated);

        var summary = BuildBriefSummary(
            primarySelector, staticFunction, staticNodes[0], moduleSummary, liveNode, mappingNode,
            includeLive, sections, errors.Count, truncated, mappingFromSnapshot);
        if (multi)
        {
            summary["functions"] = new JsonArray(
                selectors.Select(selector => JsonValue.Create(selector)).ToArray());
            summary["functionCount"] = selectors.Count;
            summary["staticReadyCount"] = staticReadyCount;
            summary["staticReady"] = staticReadyCount == selectors.Count;
            if (includeLive)
            {
                // The packet shape carries per-function match flags; the
                // single-mapping summary above sees only the packet object, so
                // aggregate here. Vocabulary stays in the historical domain
                // plus "partial" for mixed multi results.
                var matchedCount = 0;
                if (mappingNode is JsonObject packetNode &&
                    packetNode["mappings"] is JsonArray packetEntries)
                {
                    foreach (var entry in packetEntries)
                    {
                        if (entry is JsonObject entryObject &&
                            AnalysisFormatting.ReadNodeNullableBool(entryObject["mapping"], "match") == true)
                            matchedCount++;
                    }
                }
                summary["mappingReadyCount"] = matchedCount;
                summary["mappingTotal"] = selectors.Count;
                summary["mapping"] = matchedCount == selectors.Count
                    ? "matched"
                    : matchedCount == 0
                        ? "not_matched"
                        : "partial";
            }
            if (staticReadyCount != selectors.Count)
                summary["nextAction"] = "Review errors for the failed selectors, then repeat the brief for them.";
        }
        var brief = new JsonObject
        {
            ["schemaVersion"] = 1,
            ["summary"] = summary,
            ["usedChars"] = 0,
            ["bridgeCalls"] = new JsonObject
            {
                // total was always ghidra + native; the parts are the data.
                ["ghidra"] = selectors.Count,
                ["native"] = nativeCalls,
            },
            ["mappingSource"] = includeLive
                ? mappingFromSnapshot ? "snapshot_modules" : "targeted_module_request"
                : "not_requested",
            ["truncated"] = truncated,
            ["sections"] = sections,
            ["errors"] = errors,
        };
        // roundTripsSaved rides only when nonzero (same convention as above).
        var briefTripsSaved = includeLive
            ? snapshotRoundTripsSaved + (mappingFromSnapshot ? (multi ? staticReadyCount : 1) : 0)
            : 0;
        if (briefTripsSaved != 0)
            brief["roundTripsSaved"] = briefTripsSaved;
        if (multi)
            brief["functions"] = new JsonArray(
                selectors.Select(selector => JsonValue.Create(selector)).ToArray());
        if (!includeLive)
            brief["skipped"] = new JsonArray("live", "mapping");
        if (truncated)
            brief["continuation"] = ToolSupport.WithTokenBudgetHint(
                "Repeat with a higher maxChars or disable optional live, disassembly, or symbols sections.",
                maxTokens);

        var serializedLength = brief.ToJsonString(_jsonOptions).Length;
        brief["usedChars"] = Math.Min(maxChars, serializedLength);
        if (maxTokens > 0)
        {
            brief["maxTokens"] = maxTokens;
            brief["usedTokensEstimate"] = ToolSupport.EstimateGuardTokens(serializedLength);
        }
        return BridgeEnvelope.Success(brief);
    }

    /// <summary>
    /// Slim live correlation view for the default brief: keeps the summary
    /// (status/running, thread id), consistency, call counts, and a bounded
    /// folded callstack, with the context reduced to registers. The full
    /// disassembly/stack clone and the module table are dropped: mapping
    /// already carries module identity, and includeLiveDetail=true restores
    /// the old full clone. Never throws; unknown shapes pass through.
    /// </summary>
    private static JsonNode SlimLiveForBrief(JsonObject live)
    {
        try
        {
            var slim = new JsonObject
            {
                ["schemaVersion"] = 2,
            };
            if (live["summary"] is JsonObject summary)
            {
                var slimSummary = (JsonObject)summary.DeepClone();
                slimSummary.Remove("moduleStatus");
                slimSummary.Remove("moduleCount");
                slimSummary.Remove("modulesTruncated");
                slim["summary"] = slimSummary;
            }
            if (live["consistency"] is JsonNode consistency)
                slim["consistency"] = consistency.DeepClone();
            // bridgeCalls/roundTripsSaved already ride top-level; no inner copy.
            if (live["truncated"] is JsonValue truncated && truncated.TryGetValue<bool>(out var isTruncated) && isTruncated)
                slim["truncated"] = true;
            var sections = new JsonObject();
            if (live["sections"] is JsonObject liveSections)
            {
                if (liveSections["context"] is JsonValue contextValue &&
                    contextValue.TryGetValue<string>(out var contextText))
                    sections["context"] = AnalysisFormatting.SlimBriefContextText(contextText);
                else if (liveSections["context"] is JsonNode contextNode)
                    sections["context"] = contextNode.DeepClone();
                if (liveSections["callStack"] is JsonNode callStack)
                    sections["callStack"] = callStack.DeepClone();
                if (liveSections["threads"] is JsonNode threads)
                    sections["threads"] = threads.DeepClone();
            }
            slim["sections"] = sections;
            return slim;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
        {
            return live;
        }
    }

    /// <summary>
    /// True when a snapshot summary describes a target that is ready to be
    /// analysed: paused (or already stopped), state-unchanged across the read,
    /// and with a visible module table. Derived here because the producer no
    /// longer emits a readyForAnalysis flag.
    /// </summary>
    private static bool DeriveLiveReady(JsonNode? summary)
    {
        if (summary is not JsonObject summaryObject)
            return false;
        var running = AnalysisFormatting.ReadNodeNullableBool(summaryObject, "running");
        var consistency = AnalysisFormatting.ReadNodeString(summaryObject, "consistency");
        // includeModules=false deliberately omits the table and its count. A
        // missing count is not evidence that the target is unready; only an
        // explicit zero is. A visible table still has to be non-empty.
        var hasModuleCount = summaryObject.TryGetPropertyValue("moduleCount", out var moduleCountNode) &&
            moduleCountNode is not null;
        var moduleCount = AnalysisFormatting.ReadNodeInt(summaryObject, "moduleCount");
        return running == false &&
            string.Equals(consistency, "unchanged", StringComparison.Ordinal) &&
            (!hasModuleCount || moduleCount > 0);
    }

    /// <summary>
    /// The brief hoists one compact module summary; per-function copies are
    /// pure duplication. Instruction-level xrefs are also dropped: callers and
    /// callees carry the call-graph view, while the full xref lists are one
    /// Xrefs(address) call away and dominate the static payload. Applied only
    /// after StaticFunction extraction so mapping still has path/hash.
    /// </summary>
    /// <summary>
    /// Multi-mode mapping repeats the module table and static identity per
    /// selector. Keep one hoisted module row (indexed by base) and the
    /// decision fields; the hash/path echo is already in the module row and
    /// the breakpoint address is liveAddress + rva.
    /// </summary>
    private static void CompactMappingEntry(
        JsonObject mapping,
        JsonArray moduleTable,
        Dictionary<string, int> moduleIndexes)
    {
        if (mapping["staticFunction"] is JsonObject staticFunction)
        {
            staticFunction.Remove("path");
            staticFunction.Remove("sha256");
        }
        if (mapping["identity"] is JsonObject identity)
        {
            identity.Remove("path");
            identity.Remove("sha256");
        }
        mapping.Remove("breakpointHint");
        if (mapping["module"] is JsonObject module)
        {
            var key = AnalysisFormatting.ReadNodeString(module, "base");
            if (string.IsNullOrEmpty(key))
                key = AnalysisFormatting.ReadNodeString(module, "name");
            key ??= string.Empty;
            if (!moduleIndexes.TryGetValue(key, out var moduleIndex))
            {
                moduleIndex = moduleTable.Count;
                moduleIndexes[key] = moduleIndex;
                moduleTable.Add(module.DeepClone());
            }
            mapping.Remove("module");
            mapping["moduleIndex"] = moduleIndex;
        }
    }

    private static void PruneStaticEvidence(IEnumerable<JsonNode?> nodes)
    {
        foreach (var node in nodes)
        {
            if (node is not JsonObject obj)
                continue;
            if (obj["function"] is JsonObject function &&
                function["module"] is JsonObject module)
            {
                module.Remove("summary");
                // Mapping already carries the verified identity; the module
                // path is the only per-selector bit worth repeating.
                module.Remove("sha256");
                module.Remove("imageBase");
                if (obj["references"] is JsonObject references)
                {
                    var hadXrefs = references.ContainsKey("xrefsTo") || references.ContainsKey("xrefsFrom");
                    references.Remove("xrefsTo");
                    references.Remove("xrefsFrom");
                    if (hadXrefs)
                        references["xrefsOmitted"] = "Xrefs(address)";
                }
            }
        }
    }

    internal static JsonObject BuildBriefSummary(
        string functionSelector,
        ToolSupport.StaticFunction? staticFunction,
        JsonNode? staticNode,
        JsonObject? moduleSummary,
        JsonNode? liveNode,
        JsonNode? mappingNode,
        bool includeLive,
        JsonObject sections,
        int errorCount,
        bool truncated,
        bool mappingFromSnapshot = false)
    {
        var summary = new JsonObject
        {
            ["staticReady"] = staticFunction is not null,
            ["liveIncluded"] = includeLive,
            ["errorCount"] = errorCount,
        };

        if (moduleSummary is not null)
        {
            var compactModule = new JsonObject();
            foreach (var propertyName in new[] { "fileName", "format", "architecture", "functionCount" })
                if (moduleSummary[propertyName] is JsonNode value)
                    compactModule[propertyName] = value.DeepClone();
            if (compactModule.Count > 0)
                summary["module"] = compactModule;
        }

        if (includeLive)
        {
            // readyForAnalysis was dropped from the snapshot summary in the
            // token-slimming phase and the docs say to derive it. A snapshot is
            // ready for analysis when the target is paused, the before/after
            // state matched, and the module table was visible — the same triple
            // tools/verify-e2e.ps1 asserts.
            var liveReady = liveNode is JsonObject liveObject
                ? DeriveLiveReady(liveObject["summary"])
                : false;
            summary["liveReady"] = liveReady;

            var mappingMatch = AnalysisFormatting.ReadNodeNullableBool(mappingNode, "match");
            summary["mapping"] = mappingMatch switch
            {
                true => "matched",
                false => "not_matched",
                _ => "unavailable",
            };
            var hashVerified = AnalysisFormatting.ReadNodeNullableBool(
                mappingNode is JsonObject mappingObject ? mappingObject["identity"] : null,
                "hashVerified");
            if (hashVerified.HasValue)
                summary["hashVerified"] = hashVerified.Value;
        }
        else
        {
            summary["mapping"] = "not_requested";
        }

        summary["nextAction"] = staticFunction is null
            ? "Open a Ghidra analysis and repeat with a valid function selector."
            : errorCount > 0
                ? "Review errors before correlating static and live evidence."
                : truncated
                    ? "Repeat with a higher maxChars or disable optional sections for complete evidence."
                    : !includeLive
                        ? "Use MapStaticFunctionToLive when live debugger correlation is needed."
                        : summary["mapping"]?.GetValue<string>() == "matched"
                            ? "Compare sections.static and sections.live, then inspect the mapped live address."
                            : "Use the mapping reason to resolve module identity, then repeat the brief.";
        return summary;
    }
}
