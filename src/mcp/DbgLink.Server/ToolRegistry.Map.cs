using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>
    /// Map-first entry point: one bounded call fans out over the tested static
    /// reads and never runs the decompiler. The model gets identity, layout,
    /// entry point, strongest imports, exports, IOC strings and a function
    /// sample before deciding which single function deserves a digest.
    /// </summary>
    private void RegisterModuleMap(AnalysisContext context) => Register(new JsonObject
    {
        ["name"] = "GetModuleMap",
        ["description"] = "Start here after opening a target: identity, sections+entry, ranked imports/exports/functions, IOC strings in one bounded call. Entry decomp: includeEntryDecomp.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["maxSections"] = IntRule(16, 1, 64, "Max sections."),
                ["maxSymbols"] = IntRule(20, 1, 64, "Max imports/exports per side."),
                ["maxFunctions"] = IntRule(16, 1, 64, "Max ranked functions."),
                ["maxStrings"] = IntRule(10, 1, 32, "Max IOC rows."),
                ["includeStrings"] = BoolRule(true,
                    "Scan .rdata strings."),
                ["includeEntryDecomp"] = BoolRule(false,
                    "Also decompile the entry (bounded InspectFunction, max 4000 chars)."),
                ["compact"] = BoolRule(false)
            },
            ["additionalProperties"] = false
        }
    }, call => GetModuleMapAsync(context, call.Arguments, call.CancellationToken),
        ToolCapability.ReadOnly, requiresControl: false, lean: true, minimumTimeoutMs: 120_000);

    private static async Task<string> GetModuleMapAsync(
        AnalysisContext context, JsonElement? arguments, CancellationToken cancellationToken)
    {
        // The schema already bounds these; clamp again because composites are
        // also reachable through internal call paths that skip validation.
        var maxSections = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxSections", 16), 1, 64);
        var maxSymbols = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxSymbols", 20), 1, 64);
        var maxFunctions = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxFunctions", 16), 1, 64);
        // Rank a wider candidate pool than we return: address order would hide
        // the interesting functions that happen to live later in .text.
        var functionPool = Math.Clamp(maxFunctions * 4, 32, 128);
        var maxStrings = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxStrings", 10), 1, 32);
        var includeStrings = ToolSupport.ReadArgumentBool(arguments, "includeStrings", true);
        var compact = ToolSupport.ReadArgumentBool(arguments, "compact", false);

        var statusTask = context.Ghidra.RequestAsync("status", null, cancellationToken);
        var sectionsTask = context.Ghidra.RequestAsync("ListSections", ToolSupport.ToJsonElement(
            new JsonObject { ["maxSections"] = maxSections }), cancellationToken);
        // Rank the whole symbol pool before taking maxSymbols; see
        // GetSymbolPoolAsync for why one page is not enough.
        var symbolsTask = GetSymbolPoolAsync(context, maxSymbols, cancellationToken);
        var functionsTask = context.Ghidra.RequestAsync("ListFunctions", ToolSupport.ToJsonElement(
            new JsonObject { ["maxItems"] = functionPool, ["includeCounts"] = true }), cancellationToken);
        // Reuse TriageStrings instead of duplicating IOC classification.
        // Two pages x 256 rows keeps an IOC that lives past the first .rdata
        // page visible; the map still reports the real continuation when the
        // budget runs out.
        var stringsTask = includeStrings
            ? new TriageImportsTools(context).TriageStringsAsync(ToolSupport.ToJsonElement(
                new JsonObject { ["section"] = ".rdata", ["maxItems"] = 256, ["maxPages"] = 2 }), cancellationToken)
            : null;

        var pending = new List<Task> { statusTask, sectionsTask, symbolsTask, functionsTask };
        if (stringsTask is not null) pending.Add(stringsTask);
        await Task.WhenAll(pending).ConfigureAwait(false);

        var statusRaw = await statusTask.ConfigureAwait(false);
        if (!TryResult(statusRaw, out var status, out _))
            // No module identity means there is nothing to map; surface the
            // bridge's own error (ghidra_unavailable, program_unavailable, ...).
            return statusRaw;

        var degraded = new JsonArray();
        var sections = ReadResult(await sectionsTask.ConfigureAwait(false), "ListSections", degraded);
        var symbolPool = await symbolsTask.ConfigureAwait(false);
        if (symbolPool.Error is not null)
            degraded.Add(symbolPool.Error);
        var functions = ReadResult(await functionsTask.ConfigureAwait(false), "ListFunctions", degraded);
        var strings = stringsTask is null
            ? null
            : ReadResult(await stringsTask.ConfigureAwait(false), "TriageStrings", degraded);

        var module = status["program"] is JsonObject program
            ? (JsonObject)program.DeepClone()
            : new JsonObject();
        if (compact && module.Count > 0)
        {
            // The compact map only needs identity and size; language and
            // compiler echoes are in module.summary elsewhere.
            var slimModule = new JsonObject();
            foreach (var name in new[] { "fileName", "imageBase", "architecture", "functionCount", "sha256" })
                if (module[name] is JsonNode value) slimModule[name] = value.DeepClone();
            module = slimModule;
        }

        var entryPoints = new JsonArray();
        if (sections?["entryFunction"] is JsonObject entryFunction)
        {
            entryPoints.Add(new JsonObject
            {
                ["name"] = entryFunction["name"]?.DeepClone(),
                ["address"] = entryFunction["entry"]?.DeepClone()
            });
        }
        else if (sections?["entryPoint"] is JsonValue entryPoint &&
                 entryPoint.TryGetValue<string>(out var entryText) &&
                 !string.IsNullOrWhiteSpace(entryText))
        {
            entryPoints.Add(new JsonObject { ["name"] = "entry", ["address"] = entryText });
        }

        var sectionRows = sections?["sections"] is JsonArray array ? array.OfType<JsonObject>().ToList() : [];
        var sectionsTruncated = sections?["truncated"]?.GetValue<bool>() == true || sectionRows.Count > maxSections;
        var mapSections = new JsonArray(sectionRows.Take(maxSections)
            .Select(row => (JsonNode?)row.DeepClone()).ToArray());

        var importRows = symbolPool.Imports;
        var importsTruncated = symbolPool.ImportsTruncated || importRows.Count > maxSymbols;
        var libraries = importRows
            .Select(row => row["library"]?.GetValue<string>())
            .Where(library => !string.IsNullOrWhiteSpace(library))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(library => library, StringComparer.OrdinalIgnoreCase)
            .Take(16)
            .Select(library => (JsonNode?)JsonValue.Create(library))
            .ToArray();
        var topImports = importRows
            .OrderByDescending(row => row["refCount"]?.GetValue<int>() ?? 0)
            .ThenBy(row => row["name"]?.GetValue<string>() ?? "", StringComparer.Ordinal)
            .Take(maxSymbols)
            .Select(row => (JsonNode?)new JsonObject
            {
                ["name"] = row["name"]?.DeepClone(),
                ["library"] = row["library"]?.DeepClone(),
                ["refCount"] = row["refCount"]?.DeepClone()
            })
            .ToArray();

        var exportRows = symbolPool.Exports;
        var exportsTruncated = symbolPool.ExportsTruncated || exportRows.Count > maxSymbols;
        var topExports = exportRows.Take(maxSymbols)
            .Select(row => (JsonNode?)new JsonObject
            {
                ["name"] = row["name"]?.DeepClone(),
                ["address"] = row["address"]?.DeepClone()
            })
            .ToArray();

        var functionRows = functions?["functions"] is JsonArray sample ? sample.OfType<JsonObject>().ToList() : [];
        var functionsTruncated = functions?["truncated"]?.GetValue<bool>() == true || functionRows.Count > maxFunctions;
        var functionSample = functionRows
            .Select(row =>
            {
                var risk = FunctionRisk(row, out var why);
                return (Row: row, Risk: risk, Why: why);
            })
            .OrderByDescending(candidate => candidate.Risk)
            .ThenBy(candidate => candidate.Row["entry"]?.GetValue<string>() ?? "", StringComparer.Ordinal)
            .Take(maxFunctions)
            .Select(candidate =>
            {
                var row = candidate.Row;
                var slim = new JsonObject
                {
                    ["name"] = row["name"]?.DeepClone(),
                    ["entry"] = row["entry"]?.DeepClone()
                };
                if (row["size"] is JsonNode size) slim["size"] = size.DeepClone();
                slim["risk"] = candidate.Risk;
                slim["why"] = candidate.Why;
                return (JsonNode?)slim;
            })
            .ToArray();

        JsonObject? stringsSection = null;
        if (strings is not null)
        {
            var iocs = strings["iocs"] is JsonArray rows ? rows.OfType<JsonObject>().ToList() : [];
            var byType = new JsonObject();
            foreach (var ioc in iocs)
            {
                var type = ioc["type"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(type)) continue;
                byType[type] = (byType[type]?.GetValue<int>() ?? 0) + 1;
            }
            stringsSection = new JsonObject
            {
                ["examined"] = strings["totalExamined"]?.DeepClone(),
                ["suspicious"] = strings["suspiciousCount"]?.DeepClone(),
                ["byType"] = byType,
                ["top"] = new JsonArray(iocs.Take(maxStrings)
                    .Select(row => (JsonNode?)new JsonObject
                    {
                        ["type"] = row["type"]?.DeepClone(),
                        ["value"] = row["value"]?.DeepClone()
                    }).ToArray()),
                ["truncated"] = strings["truncated"]?.GetValue<bool>() == true || iocs.Count > maxStrings
            };
            if (strings["nextAddress"] is JsonNode nextAddress)
                stringsSection["nextAddress"] = nextAddress.DeepClone();
        }

        var functionsSection = new JsonObject
        {
            ["order"] = "risk",
            ["candidates"] = functionRows.Count,
            ["sample"] = new JsonArray(functionSample),
            ["truncated"] = functionsTruncated
        };
        if (module["functionCount"] is JsonNode total) functionsSection["total"] = total.DeepClone();

        var map = new JsonObject
        {
            ["schemaVersion"] = 1,
            ["module"] = module,
            ["entryPoints"] = entryPoints,
            ["sections"] = mapSections,
            ["sectionsTruncated"] = sectionsTruncated,
            ["imports"] = new JsonObject
            {
                ["returned"] = topImports.Length,
                ["truncated"] = importsTruncated,
                ["libraries"] = new JsonArray(libraries),
                ["top"] = new JsonArray(topImports)
            },
            ["exports"] = new JsonObject
            {
                ["returned"] = topExports.Length,
                ["truncated"] = exportsTruncated,
                ["top"] = new JsonArray(topExports)
            },
            ["functions"] = functionsSection,
            ["nextAction"] = "Risk-ranked sample. Use InspectFunction/AnalyzeFunctions includeDecomp:false; decompile only what matters. Page ListFunctions/ListSymbols for more."
        };
        if (stringsSection is not null) map["strings"] = stringsSection;
        if (ToolSupport.ReadArgumentBool(arguments, "includeEntryDecomp", false))
            await AddEntryDecompAsync(context, entryPoints, map, degraded, cancellationToken).ConfigureAwait(false);
        if (degraded.Count > 0) map["degraded"] = degraded;
        if (compact)
        {
            // libraries and functions.total are derivable from top[].library
            // and module.functionCount; don't pay for them twice.
            if (map["imports"] is JsonObject compactImports) compactImports.Remove("libraries");
            if (map["functions"] is JsonObject compactFunctions) compactFunctions.Remove("total");
            CompactJson.CompactChild(map, "sections");
            CompactJson.CompactChild((JsonObject)map["imports"]!, "top");
            CompactJson.CompactChild((JsonObject)map["exports"]!, "top");
            CompactJson.CompactChild((JsonObject)map["functions"]!, "sample");
            if (map["strings"] is JsonObject compactStrings)
                CompactJson.CompactChild(compactStrings, "top");
        }
        return BridgeEnvelope.Success(map);
    }

    /// <summary>
    /// Opt-in one-call first look: decompiles the entry function through the
    /// existing InspectFunction path with a fixed 4000-char budget, so the
    /// map still answers "what does entry do" in one call. The other slices
    /// stay decompiler-free; failure degrades honestly.
    /// </summary>
    private static async Task AddEntryDecompAsync(
        AnalysisContext context, JsonArray entryPoints, JsonObject map, JsonArray degraded,
        CancellationToken cancellationToken)
    {
        var address = entryPoints.OfType<JsonObject>().FirstOrDefault()?["address"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(address))
        {
            degraded.Add("entryDecomp: no entry address");
            return;
        }
        var raw = await context.Ghidra.RequestAsync("InspectFunction", ToolSupport.ToJsonElement(
            new JsonObject { ["function"] = address, ["maxChars"] = 4000, ["includeReferences"] = false }),
            cancellationToken).ConfigureAwait(false);
        if (TryResult(raw, out var entry, out var code) && entry["decompilation"] is JsonNode decomp)
            map["entryDecomp"] = decomp.DeepClone();
        else
            degraded.Add($"InspectFunction(entry): {code}");
    }

    private static readonly string[] SensitiveFunctionTokens =
    [
        "crypt", "cipher", "decrypt", "encrypt", "pack", "unpack", "inject", "hook",
        "shell", "exec", "connect", "download", "upload", "persist", "antidebug",
        "vmdetect", "auth", "password", "token", "license", "config", "command", "dispatch"
    ];

    /// <summary>
    /// Cheap, decompiler-free routing score: interesting bodies (instructions,
    /// branches), unnamed code and entry-like names rank up; thunks and tiny
    /// stubs rank down. The reason travels with the score so the model can
    /// decide whether to spend a digest on it.
    /// </summary>
    private static int FunctionRisk(JsonObject row, out string why)
    {
        var reasons = new List<string>(4);
        var score = 0;
        var name = row["name"]?.GetValue<string>() ?? string.Empty;
        if (BoolValue(row, "thunk"))
        {
            score -= 50;
            reasons.Add("thunk");
        }
        else
        {
            if (IsUnnamedFunction(name))
            {
                score += 25;
                reasons.Add("unnamed");
            }
            if (IsEntryLikeName(name))
            {
                score += 60;
                reasons.Add("entry-like");
            }
            else if (IsSensitiveName(name))
            {
                score += 20;
                reasons.Add("sensitive-name");
            }

            var instructionScore = Math.Min(30, IntValue(row, "instructionCount") / 10);
            if (instructionScore > 0)
            {
                score += instructionScore;
                reasons.Add("instructions");
            }

            var branchScore = Math.Min(25, IntValue(row, "branchCount") * 2);
            if (branchScore > 0)
            {
                score += branchScore;
                reasons.Add("branches");
            }

            var size = IntValue(row, "size");
            if (size >= 256)
            {
                score += 5;
                reasons.Add("large");
            }
            else if (size is > 0 and < 16)
            {
                score -= 10;
                reasons.Add("stub");
            }
        }

        why = reasons.Count == 0 ? "address-order" : string.Join(",", reasons);
        return score;
    }

    private static bool IsUnnamedFunction(string name) =>
        string.IsNullOrWhiteSpace(name) ||
        name.StartsWith("FUN_", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("SUB_", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("LAB_", StringComparison.OrdinalIgnoreCase);

    private static bool IsEntryLikeName(string name) =>
        name.Equals("entry", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("_start", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("main", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("wmain", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("WinMain", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("wWinMain", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("DllMain", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("ServiceMain", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("DriverEntry", StringComparison.OrdinalIgnoreCase);

    private static bool IsSensitiveName(string name) =>
        SensitiveFunctionTokens.Any(token => name.Contains(token, StringComparison.OrdinalIgnoreCase));

    private static int IntValue(JsonObject row, string name) =>
        row[name] is JsonValue value && value.TryGetValue<int>(out var number) ? number : 0;

    private static bool BoolValue(JsonObject row, string name) =>
        row[name] is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;

    private static JsonObject? ReadResult(string raw, string method, JsonArray degraded)
    {
        if (TryResult(raw, out var result, out _)) return result;
        TryResult(raw, out _, out var code);
        degraded.Add($"{method}: {code}");
        return null;
    }

    private sealed record SymbolPool(
        List<JsonObject> Imports,
        List<JsonObject> Exports,
        bool ImportsTruncated,
        bool ExportsTruncated,
        string? Error);

    /// <summary>
    /// Page the bridge symbol table before ranking. A single first page is
    /// symbol-table order, not refCount order: on Chromium-sized imports the
    /// strongest APIs (GetProcAddress, VirtualAlloc, ...) sit far past row 20.
    /// </summary>
    private static async Task<SymbolPool> GetSymbolPoolAsync(
        AnalysisContext context,
        int maxSymbols,
        CancellationToken cancellationToken)
    {
        var imports = new List<JsonObject>();
        var exports = new List<JsonObject>();
        var importsTruncated = false;
        var exportsTruncated = false;
        var offset = 0;
        // Two pages (up to 1024 imports) keep the risk pool wide enough for a
        // top-20 sample while halving the worst-case bridge trips.
        for (var page = 0; page < 2; page++)
        {
            var raw = await context.Ghidra.RequestAsync("ListSymbolsBoth", ToolSupport.ToJsonElement(
                new JsonObject
                {
                    ["maxItemsImports"] = 512,
                    ["maxItemsExports"] = maxSymbols,
                    ["offsetImports"] = offset
                }), cancellationToken).ConfigureAwait(false);
            if (!TryResult(raw, out var result, out var code))
                return new(imports, exports, importsTruncated, exportsTruncated, $"ListSymbolsBoth: {code}");

            if (result["imports"] is JsonArray importRows)
                imports.AddRange(importRows.OfType<JsonObject>().Select(row => (JsonObject)row.DeepClone()));
            if (page == 0)
            {
                if (result["exports"] is JsonArray exportRows)
                    exports.AddRange(exportRows.OfType<JsonObject>().Select(row => (JsonObject)row.DeepClone()));
                exportsTruncated = result["exportsTruncated"]?.GetValue<bool>() == true;
            }
            importsTruncated = result["importsTruncated"]?.GetValue<bool>() == true;
            if (result["nextOffsetImports"] is JsonValue nextNode &&
                nextNode.TryGetValue<int>(out var next) && next > offset)
            {
                offset = next;
                continue;
            }
            break;
        }

        if (imports.Count > maxSymbols)
            importsTruncated = true;
        return new(imports, exports, importsTruncated, exportsTruncated, null);
    }

    private static bool TryResult(string raw, out JsonObject result, out string code)
    {
        result = new JsonObject();
        code = "invalid_response";
        try
        {
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True &&
                root.TryGetProperty("result", out var payload) && payload.ValueKind == JsonValueKind.Object &&
                JsonNode.Parse(payload.GetRawText()) is JsonObject parsed)
            {
                result = parsed;
                return true;
            }
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                error.TryGetProperty("code", out var errorCode) && errorCode.ValueKind == JsonValueKind.String)
                code = errorCode.GetString() ?? "bridge_error";
        }
        catch (JsonException) { }
        return false;
    }
}
