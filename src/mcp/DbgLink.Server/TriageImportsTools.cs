using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

/// <summary>
/// Token-efficient import triage: risk-ranked imports with reference counts.
/// Cuts tokens vs <c>ListSymbols kind=imports</c> by echoing per-import
/// reference <i>counts</i> instead of full <c>referenceSites</c> address arrays.
/// </summary>
internal sealed class TriageImportsTools
{
    private readonly AnalysisContext _context;
    private IGhidraClient ActiveGhidra => _context.Ghidra;
    private IBridgeClient ActiveBridge => _context.Bridge;

    public TriageImportsTools(AnalysisContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Unified triage entry point behind the advertised <c>Triage</c> tool:
    /// <c>kind</c> (default <c>imports</c>) picks the existing implementation,
    /// <c>both</c> runs the two concurrently and merges the result objects.
    /// Each side receives only its own keys, so omitted budgets keep that
    /// side's historical defaults and Triage(kind=X, args) answers exactly
    /// like the direct X call.
    /// </summary>
    internal async Task<string> TriageAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var kind = (ToolSupport.ReadArgumentString(arguments, "kind") ?? "imports").Trim();
        if (string.Equals(kind, "imports", StringComparison.OrdinalIgnoreCase))
            return await TriageImportsAsync(Only(arguments, ImportsKeys), cancellationToken).ConfigureAwait(false);
        if (string.Equals(kind, "strings", StringComparison.OrdinalIgnoreCase))
            return await TriageStringsAsync(Only(arguments, StringsKeys), cancellationToken).ConfigureAwait(false);
        if (!string.Equals(kind, "both", StringComparison.OrdinalIgnoreCase))
            return BridgeEnvelope.Error("invalid_argument", "Triage kind must be imports, strings or both.");
        var importsTask = TriageImportsAsync(Only(arguments, ImportsKeys), cancellationToken);
        var stringsTask = TriageStringsAsync(Only(arguments, StringsKeys), cancellationToken);
        await Task.WhenAll(importsTask, stringsTask).ConfigureAwait(false);
        return BridgeEnvelope.Success(new JsonObject
        {
            ["imports"] = Side(await importsTask.ConfigureAwait(false)),
            ["strings"] = Side(await stringsTask.ConfigureAwait(false)),
        });
    }

    private static readonly HashSet<string> ImportsKeys = new(StringComparer.Ordinal)
    {
        "filter", "module", "top", "maxItems", "maxChars", "offset", "maxPages", "includeExports", "compact",
    };

    private static readonly HashSet<string> StringsKeys = new(StringComparer.Ordinal)
    {
        "section", "module", "filter", "start", "minLength", "maxItems", "maxScanBytes", "maxPages", "compact",
    };

    /// <summary>
    /// Forwards only the callee's own keys (plus nothing else): the union
    /// Triage schema admits both sides' knobs, but each implementation keeps
    /// its historical defaults and ignores nothing it wasn't given.
    /// </summary>
    private static JsonElement? Only(JsonElement? arguments, HashSet<string> keys)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } source)
            return arguments;
        var node = JsonNode.Parse(source.GetRawText())!.AsObject();
        var drop = node.Select(property => property.Key).Where(key => !keys.Contains(key)).ToList();
        if (drop.Count == 0)
            return arguments;
        foreach (var key in drop)
            node.Remove(key);
        return JsonSerializer.SerializeToElement(node);
    }

    private static JsonNode Side(string raw)
    {
        // Each side keeps its own truncated/next* honesty: surface the
        // result object on success, the error envelope otherwise.
        var node = AnalysisFormatting.ReadBridgeResultNode(raw);
        if (node is not null)
            return node;
        try
        {
            return JsonNode.Parse(raw)!;
        }
        catch (JsonException)
        {
            return JsonValue.Create(raw);
        }
    }

    internal async Task<string> TriageImportsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // Schema: top 1..128 (default 32), maxItems 1..512 (default 256),
        // maxChars 1000..30000 (default 8000), offset 0..1000000 (default 0),
        // maxPages 1..8 (default 1, mirroring TriageStrings).
        // Clamp here as well: internal call paths skip validation, and an
        // unclamped maxItems multiplies the ListImports bridge payload.
        var filter = ToolSupport.ReadArgumentString(arguments, "filter");
        var module = ToolSupport.ReadArgumentString(arguments, "module");
        var top = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "top", 16), 1, 128);
        var maxItems = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxItems", 256), 1, 512);
        var maxChars = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxChars", 4000), 1000, 30000);
        var offset = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "offset", 0), 0, 1_000_000);
        var maxPages = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxPages", 1), 1, 8);
        var includeExports = ToolSupport.ReadArgumentBool(arguments, "includeExports", false);
        // P2-4 compact opt-in: absent/false is the historical readable shape
        // (byte-identical); true dict-encodes repeated library/category
        // strings below. Never forwarded: the ListImports bridge dialect has
        // no compact flag, so it stays a pure .NET-side transform.

        var examined = 0;
        var ranked = new List<JsonObject>();
        var categoryCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        // Server-side page iteration over ListImports is opt-in via maxPages
        // (default 1 is the historical single ListImports fetch, byte-identical;
        // maxPages>1 walks successive pages instead of forcing the caller to
        // re-issue manual filter/offset calls). Bounded: at most maxPages
        // fetches, at most maxItems matched rows, and stops early once the
        // top-ranked page alone exceeds maxChars (the shrink loop below stays
        // authoritative). The bridge offset counts examined DB rows, so
        // nextOffset resumes exactly; maxItems bounds matched rows per page.
        const int PerFetchCap = 512;
        var remaining = maxItems;
        var fetchOffset = offset;
        int? pendingNextOffset = null;
        var pages = 0;
        var sawData = false;
        // With exports requested, one ListSymbolsBoth call carries both sides,
        // so the call costs one Ghidra round trip instead of two. If the
        // bridge rejects the combined call, fall back to the legacy pair.
        var foldExports = includeExports;
        JsonArray? combinedExports = null;
        int? combinedExportsNext = null;

        async Task<(string Raw, JsonObject? Node)> FetchImportsPageAsync(int pageOffset, int wanted)
        {
            var listPayload = new JsonObject
            {
                ["offset"] = pageOffset,
                ["maxItems"] = Math.Min(wanted, PerFetchCap),
            };
            if (!string.IsNullOrWhiteSpace(filter))
                listPayload["filter"] = filter;
            if (!string.IsNullOrWhiteSpace(module))
                listPayload["module"] = module;
            var raw = await ActiveGhidra.RequestAsync(
                "ListImports", ToolSupport.ToJsonElement(listPayload), cancellationToken);
            return (raw, AnalysisFormatting.ReadBridgeResultNode(raw) as JsonObject);
        }

        while (remaining > 0 && pages < maxPages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // RefCount-by-default: the bridge always returns refCount, so no
            // site payload is fetched unless the caller explicitly opted in.
            // Triage only needs counts, never addresses, so neither maxSites
            // nor includeSites is sent here.
            string rawResp;
            JsonObject? result;
            var fromBoth = false;
            if (foldExports)
            {
                var bothPayload = new JsonObject
                {
                    ["offsetImports"] = fetchOffset,
                    ["maxItemsImports"] = Math.Min(remaining, PerFetchCap),
                    ["maxItemsExports"] = top,
                };
                if (!string.IsNullOrWhiteSpace(filter))
                    bothPayload["filter"] = filter;
                if (!string.IsNullOrWhiteSpace(module))
                    bothPayload["module"] = module;

                rawResp = await ActiveGhidra.RequestAsync(
                    "ListSymbolsBoth", ToolSupport.ToJsonElement(bothPayload), cancellationToken);
                result = AnalysisFormatting.ReadBridgeResultNode(rawResp) as JsonObject;
                if (result is not null)
                {
                    fromBoth = true;
                }
                else
                {
                    // Legacy/older bridge or a transient error: keep the call
                    // useful by switching back to the two-call path.
                    foldExports = false;
                    (rawResp, result) = await FetchImportsPageAsync(fetchOffset, remaining);
                }
            }
            else
            {
                (rawResp, result) = await FetchImportsPageAsync(fetchOffset, remaining);
            }

            if (result is null)
            {
                // First-page failure preserves the historical passthrough of
                // the raw bridge error. A later-page failure keeps the
                // accumulated rows and reports honestly: truncated with the
                // resume offset of the unfetched page.
                if (!sawData)
                    return rawResp;
                pendingNextOffset = fetchOffset;
                break;
            }
            sawData = true;

            var pageTruncated = result["truncated"] is JsonValue truncatedValue &&
                truncatedValue.TryGetValue<bool>(out var truncatedFlag) && truncatedFlag;
            int? pageNext = result["nextOffset"] is JsonValue nextValue &&
                nextValue.TryGetValue<int>(out var nextInt) ? nextInt : null;
            if (fromBoth)
            {
                // The combined dialect reports truncation per side via the
                // cursor only; the OR flag also covers exports.
                pageNext = result["nextOffsetImports"] is JsonValue importsNextValue &&
                    importsNextValue.TryGetValue<int>(out var importsNextInt) ? importsNextInt : null;
                pageTruncated = pageNext.HasValue;
                if (pages == 0)
                {
                    combinedExports = result["exports"] as JsonArray;
                    combinedExportsNext = result["nextOffsetExports"] is JsonValue exportsNextValue &&
                        exportsNextValue.TryGetValue<int>(out var exportsNextInt) ? exportsNextInt : null;
                }
            }
            pendingNextOffset = pageTruncated && pageNext.HasValue ? pageNext : null;

            var rowsSeen = 0;
            if (result["imports"] is JsonArray imports)
            {
                rowsSeen = imports.Count;
                foreach (var item in imports)
                {
                    if (item is not JsonObject row)
                        continue;
                    var name = SafeRecordString(row, "name") ?? SafeRecordString(row, "function");
                    if (string.IsNullOrWhiteSpace(name))
                        continue;
                    examined++;
                    var library = SafeRecordString(row, "library") ?? string.Empty;
                    var address = SafeRecordString(row, "address") ?? string.Empty;
                    // Bridge refCount when present (refCount-by-default); fall
                    // back to the legacy referenceSites array length.
                    var refCount = SafeRecordInt(row, "refCount")
                        ?? (row["referenceSites"] is JsonArray sites ? sites.Count : 0);
                    var sitesTruncated = row["referencesTruncated"] is JsonValue flag &&
                        flag.TryGetValue<bool>(out var flagValue) && flagValue;

                    var categories = ClassifyImport(string.IsNullOrEmpty(library) ? name : library + "!" + name);
                    if (categories.Count == 0)
                    {
                        continue;
                    }

                    foreach (var category in categories)
                        categoryCounts[category] = categoryCounts.TryGetValue(category, out var count) ? count + 1 : 1;

                    var entry = new JsonObject
                    {
                        ["name"] = name,
                        ["library"] = library,
                        ["refCount"] = refCount,
                        ["categories"] = new JsonArray(categories.Select(c => (JsonNode?)JsonValue.Create(c)).ToArray()),
                    };
                    if (!string.IsNullOrEmpty(address) &&
                        !address.StartsWith("EXTERNAL:", StringComparison.OrdinalIgnoreCase))
                        entry["address"] = address;
                    if (sitesTruncated)
                        entry["referencesTruncated"] = true;
                    // Sort key stays out of the wire payload.
                    entry["__refs"] = refCount;
                    ranked.Add(entry);
                }
            }

            pages++;
            remaining -= rowsSeen;
            if (!pageTruncated || !pageNext.HasValue)
                break;
            if (pageNext.Value <= fetchOffset)
            {
                // No forward progress: stop rather than re-fetch the same
                // page until the cap. Resume stays possible at fetchOffset.
                pendingNextOffset = fetchOffset;
                break;
            }
            fetchOffset = pageNext.Value;

            // Budget probe: when the bridge holds more pages but the
            // top-ranked slice alone already exceeds maxChars, further
            // fetches only grow what the shrink loop must cut. The +512
            // slack covers the envelope around the imports array; the shrink
            // loop below remains authoritative.
            if (remaining > 0 && pages < maxPages)
            {
                var probe = new JsonArray(ranked.Take(top).Select(entry => (JsonNode?)entry.DeepClone()).ToArray());
                if (probe.ToJsonString(_jsonOptions).Length + 512 > maxChars)
                    break;
            }
        }

        // Exports ride along with the folded ListSymbolsBoth call; the legacy
        // ListExports path is only used when that call had to fall back.
        // Summary depth follows top; continuation mirrors the bridge dialect
        // (exportNextOffset) for ListSymbols follow-ups.
        JsonArray? exportRows = null;
        var exportsTruncated = false;
        int? exportNextOffset = null;
        if (includeExports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (combinedExports is null)
            {
                var exportPayload = new JsonObject
                {
                    ["offset"] = 0,
                    ["maxItems"] = top,
                };
                if (!string.IsNullOrWhiteSpace(filter))
                    exportPayload["filter"] = filter;
                if (!string.IsNullOrWhiteSpace(module))
                    exportPayload["module"] = module;

                var exportResp = await ActiveGhidra.RequestAsync(
                    "ListExports", ToolSupport.ToJsonElement(exportPayload), cancellationToken);
                if (AnalysisFormatting.ReadBridgeResultNode(exportResp) is JsonObject exportResult)
                {
                    combinedExports = exportResult["exports"] as JsonArray;
                    combinedExportsNext = exportResult["nextOffset"] is JsonValue exportNextValue &&
                        exportNextValue.TryGetValue<int>(out var exportNextInt) ? exportNextInt : null;
                }
            }
            if (combinedExports is not null)
            {
                exportRows = new JsonArray();
                foreach (var item in combinedExports)
                {
                    if (item is not JsonObject row)
                        continue;
                    var name = SafeRecordString(row, "name");
                    if (string.IsNullOrWhiteSpace(name))
                        continue;
                    var entry = new JsonObject { ["name"] = name };
                    var address = SafeRecordString(row, "address");
                    if (!string.IsNullOrEmpty(address))
                        entry["address"] = address;
                    exportRows.Add(entry);
                }
                exportNextOffset = combinedExportsNext;
                exportsTruncated = exportNextOffset.HasValue;
            }
            // A failed exports fetch omits the exports keys rather than
            // failing the whole imports triage (per-item honesty).
        }

        ranked.Sort(static (left, right) =>
        {
            var refs = right["__refs"]!.GetValue<int>().CompareTo(left["__refs"]!.GetValue<int>());
            return refs != 0 ? refs
                : string.Compare(left["name"]!.GetValue<string>(), right["name"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
        });
        foreach (var entry in ranked)
            entry.Remove("__refs");

        var suspiciousCount = ranked.Count;
        var truncated = pendingNextOffset.HasValue || exportsTruncated;
        List<JsonObject> page = ranked.Take(top).ToList();
        if (ranked.Count > page.Count)
            truncated = true;

        var triageResult = new JsonObject
        {
            ["totalExamined"] = examined,
            ["suspiciousCount"] = suspiciousCount,
            ["truncated"] = truncated,
            ["categories"] = new JsonObject(categoryCounts.Select(pair => KeyValuePair.Create(pair.Key, (JsonNode?)JsonValue.Create(pair.Value)))),
            ["imports"] = new JsonArray(page.Select(entry => (JsonNode?)entry.DeepClone()).ToArray()),
        };
        // Continuation mirrors the bridge dialect: present only when more
        // data exists, so absence means complete.
        if (pendingNextOffset.HasValue)
            triageResult["nextOffset"] = pendingNextOffset.Value;
        if (exportRows is not null)
        {
            triageResult["exports"] = exportRows;
            if (exportNextOffset.HasValue)
                triageResult["exportNextOffset"] = exportNextOffset.Value;
        }

        // Shared budget: drop lowest-ranked import rows first, then export
        // rows, until the envelope fits. Serialized length is monotonic in the
        // kept row counts, so a binary search finds the same survivor set as
        // the old drop-one-and-reserialize loop in O(log n) envelopes instead
        // of O(dropped rows).
        if (triageResult.ToJsonString(_jsonOptions).Length > maxChars)
        {
            var importCount = page.Count;
            var exportCount = exportRows?.Count ?? 0;

            int LengthWith(int keepImports, int keepExports)
            {
                triageResult["imports"] = new JsonArray(page.Take(keepImports)
                    .Select(entry => (JsonNode?)entry.DeepClone()).ToArray());
                if (exportRows is not null)
                    triageResult["exports"] = new JsonArray(exportRows.Take(keepExports)
                        .Select(entry => entry?.DeepClone()).ToArray());
                return triageResult.ToJsonString(_jsonOptions).Length;
            }

            if (LengthWith(importCount, exportCount) > maxChars)
            {
                var low = 0;
                var high = page.Count;
                while (low < high)
                {
                    var middle = (low + high + 1) / 2;
                    if (LengthWith(middle, exportCount) <= maxChars) low = middle;
                    else high = middle - 1;
                }
                importCount = low;

                if (exportRows is not null && LengthWith(importCount, exportCount) > maxChars)
                {
                    low = 0;
                    high = exportRows.Count;
                    while (low < high)
                    {
                        var middle = (low + high + 1) / 2;
                        if (LengthWith(importCount, middle) <= maxChars) low = middle;
                        else high = middle - 1;
                    }
                    exportCount = low;
                }

                page = page.Take(importCount).ToList();
                if (exportRows is not null)
                {
                    if (exportCount < exportRows.Count) exportsTruncated = true;
                    var trimmed = new JsonArray();
                    foreach (var entry in exportRows.Take(exportCount))
                        trimmed.Add(entry?.DeepClone());
                    exportRows = trimmed;
                }
                truncated = true;
                triageResult["truncated"] = true;
            }

            triageResult["imports"] = new JsonArray(page
                .Select(entry => (JsonNode?)entry.DeepClone()).ToArray());
            if (exportRows is not null)
                triageResult["exports"] = new JsonArray(exportRows
                    .Select(entry => entry?.DeepClone()).ToArray());
        }

        // P2-4 compact is applied AFTER the budget shrink loop, so the
        // default path above stays byte-identical when the flag is off, and
        // truncation stays honest (rows were dropped pre-compact). Legends
        // cover only the surviving page rows.
        if (ToolSupport.ReadArgumentBool(arguments, "compact", false))
            ApplyImportsCompact(triageResult);

        return BridgeEnvelope.Success(triageResult);
    }

    /// <summary>
    /// P2-4 compact transform for TriageImports: repeated <c>library</c> and
    /// <c>categories</c> strings become integer indices into top-level
    /// <c>libraryLegend</c>/<c>categoryLegend</c> arrays (ordinal-sorted for
    /// cross-page stability). Keys are unchanged; only values are coded, and
    /// only when the caller opted in. Non-string values (shouldn't happen on
    /// this path, but the bridge is external) are left untouched.
    /// </summary>
    internal static void ApplyImportsCompact(JsonObject triageResult)
    {
        if (triageResult["imports"] is not JsonArray imports)
            return;
        var libraries = new SortedSet<string>(StringComparer.Ordinal);
        var categories = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var item in imports.OfType<JsonObject>())
        {
            if (item["library"] is JsonValue libraryValue &&
                libraryValue.TryGetValue<string>(out var library) && library is not null)
                libraries.Add(library);
            if (item["categories"] is JsonArray categoryArray)
            {
                foreach (var category in categoryArray)
                {
                    if (category is JsonValue categoryValue &&
                        categoryValue.TryGetValue<string>(out var categoryText) && categoryText is not null)
                        categories.Add(categoryText);
                }
            }
        }
        var libraryList = libraries.ToList();
        var categoryList = categories.ToList();
        var libraryIndex = libraryList
            .Select((value, index) => (value, index))
            .ToDictionary(pair => pair.value, pair => pair.index, StringComparer.Ordinal);
        var categoryIndex = categoryList
            .Select((value, index) => (value, index))
            .ToDictionary(pair => pair.value, pair => pair.index, StringComparer.Ordinal);
        foreach (var item in imports.OfType<JsonObject>())
        {
            if (item["library"] is JsonValue libraryValue &&
                libraryValue.TryGetValue<string>(out var library) && library is not null &&
                libraryIndex.TryGetValue(library, out var libraryCode))
                item["library"] = libraryCode;
            if (item["categories"] is JsonArray categoryArray)
            {
                var coded = new JsonArray();
                foreach (var category in categoryArray)
                {
                    if (category is JsonValue categoryValue &&
                        categoryValue.TryGetValue<string>(out var categoryText) && categoryText is not null &&
                        categoryIndex.TryGetValue(categoryText, out var categoryCode))
                        coded.Add(categoryCode);
                    else
                        coded.Add(category?.DeepClone());
                }
                item["categories"] = coded;
            }
        }
        triageResult["libraryLegend"] = new JsonArray(libraryList.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
        triageResult["categoryLegend"] = new JsonArray(categoryList.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
    }

    private static readonly System.Text.RegularExpressions.Regex UrlRegex = new(@"https?://[^\s""'<>]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex Ipv4Regex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex CmdRegex = new(@"(?:powershell|cmd\.exe|wscript|cscript|mshta|rundll32|certutil|bitsadmin)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex RegistryRegex = new(@"(?:HKEY_|Software\\Microsoft\\Windows\\CurrentVersion)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex SecurityApiRegex = new(@"(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|VirtualProtect|VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtQueryInformationProcess)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex CryptoRegex = new(@"(?:\bAES\b|\bRC4\b|\bRSA\b|0x5A4D|0x5A5A|This program cannot be run in DOS mode)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    internal const int MaxIocValueChars = 512;

    /// <summary>Bound on the raw fallback report echoed when DumpStrings
    /// fails and the native string scan answers with text instead of rows.</summary>
    private const int MaxFallbackTextChars = 4_000;

    internal async Task<string> TriageStringsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        // Schema: section defaults to .rdata, minLength 2..256 (default 4),
        // maxItems 1..512 (default 64), maxPages 1..8 (default 1),
        // maxScanBytes 4096..16777216 (omitted by default). The 512 cap is the
        // bridge's own MAX_PAGE_ITEMS: advertising 1024 made the schema accept
        // a value Ghidra always rejects with invalid_argument. Clamp here as
        // well: TriageStrings is also reachable through internal call paths
        // that skip validation, and an unclamped maxItems multiplies bridge
        // payload and regex work. filter/start pass straight through to
        // DumpStrings, so matching keeps the Java matches() glob semantics
        // instead of a second client-side dialect.
        var section = ToolSupport.ReadArgumentString(arguments, "section");
        if (string.IsNullOrWhiteSpace(section))
            section = ".rdata";
        var module = ToolSupport.ReadArgumentString(arguments, "module");
        var filter = ToolSupport.ReadArgumentString(arguments, "filter");
        var start = ToolSupport.ReadArgumentString(arguments, "start");
        var minLength = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "minLength", 4), 2, 256);
        var maxItems = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxItems", 64), 1, 512);
        var maxPages = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "maxPages", 1), 1, 8);
        int? maxScanBytes = null;
        if (arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty("maxScanBytes", out var scanElement) &&
            scanElement.TryGetInt32(out var scanValue))
            maxScanBytes = Math.Clamp(scanValue, 4096, 16_777_216);

        var stringItems = new List<(string? Addr, string Val, int Len)>();
        // Bounded server-side page walk: maxPages=1 (default) is the
        // historical single fetch; higher values auto-follow nextAddress so
        // a filter/page miss no longer forces a raw DumpStrings re-call.
        // maxItems bounds each page fetch; total rows stay within
        // maxItems * maxPages.
        var currentStart = start;
        string? nextAddress = null;
        var truncated = false;
        var pages = 0;
        // Set when DumpStrings failed and the native FindInterestingStrings
        // fallback answered. That handler returns a TEXT report, not a strings
        // array, so the row classifier below cannot consume it; without a
        // marker the tool would return ok:true with zero IOCs and no error,
        // which reads as "nothing found" — the worst answer for a triage tool.
        string? fallbackText = null;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dumpPayload = new JsonObject
            {
                ["section"] = section,
                ["minLength"] = minLength,
                ["maxItems"] = maxItems
            };
            if (!string.IsNullOrWhiteSpace(module))
                dumpPayload["module"] = module;
            if (!string.IsNullOrWhiteSpace(filter))
                dumpPayload["filter"] = filter;
            if (!string.IsNullOrWhiteSpace(currentStart))
                dumpPayload["start"] = currentStart;
            if (maxScanBytes.HasValue)
                dumpPayload["maxScanBytes"] = maxScanBytes.Value;

            var rawResp = await ActiveGhidra.RequestAsync("DumpStrings", ToolSupport.ToJsonElement(dumpPayload), cancellationToken);
            var analysis = ToolSupport.AnalyzeBridgeResponse(rawResp, includeText: false);
            if (analysis.IsError)
            {
                if (pages == 0 && stringItems.Count == 0)
                {
                    var fallbackPayload = new JsonObject();
                    if (!string.IsNullOrWhiteSpace(module))
                        fallbackPayload["module"] = module;
                    if (maxScanBytes.HasValue)
                        fallbackPayload["maxScanBytes"] = maxScanBytes.Value;
                    rawResp = await ActiveBridge.RequestAsync("FindInterestingStrings", ToolSupport.ToJsonElement(fallbackPayload), cancellationToken);
                    fallbackText = ToolSupport.AnalyzeBridgeResponse(rawResp, includeText: true).Text;
                }
                else
                {
                    // A later-page failure keeps the accumulated rows and
                    // reports honestly: truncated at the unfetched resume
                    // point instead of silently dropping the tail.
                    truncated = true;
                    nextAddress = currentStart;
                    break;
                }
            }

            var resultNode = AnalysisFormatting.ReadBridgeResultNode(rawResp);

            if (resultNode is JsonObject resObj && resObj["strings"] is JsonArray strArr)
            {
                foreach (var item in strArr)
                {
                    if (item is JsonObject sObj)
                    {
                        // Malformed bridge records (numeric value, boolean address)
                        // must be skipped, not crash the whole triage: GetValue<T>
                        // throws on type mismatch, so read defensively and fall
                        // back to the value text length when length is absent or
                        // not an integer.
                        var val = SafeRecordString(sObj, "value") ?? SafeRecordString(sObj, "text");
                        var addr = SafeRecordString(sObj, "address");
                        var len = SafeRecordInt(sObj, "length") ?? SafeRecordInt(sObj, "byteLength") ?? (val?.Length ?? 0);
                        if (!string.IsNullOrEmpty(val))
                            stringItems.Add((addr, val, len));
                    }
                }
            }

            pages++;
            // Follow the bridge continuation only: truncated + a fresh
            // nextAddress + remaining page budget. Anything else (complete
            // page, fallback text without a cursor, no-progress cursor)
            // ends the walk; a truncated stop without budget stays honest
            // via truncated/nextAddress below.
            string? pageNext = null;
            var pageTruncated = resultNode is JsonObject resObj2 &&
                resObj2["truncated"] is JsonValue truncatedValue &&
                truncatedValue.TryGetValue<bool>(out var truncatedFlag) && truncatedFlag;
            if (resultNode is JsonObject resObj3 &&
                resObj3["nextAddress"] is JsonValue nextValue &&
                nextValue.TryGetValue<string>(out var nextText) &&
                !string.IsNullOrWhiteSpace(nextText))
                pageNext = nextText;

            if (pageTruncated && pageNext is not null && pages < maxPages &&
                !string.Equals(pageNext, currentStart, StringComparison.Ordinal))
            {
                truncated = true;
                nextAddress = pageNext;
                currentStart = pageNext;
                continue;
            }

            if (pageTruncated)
            {
                truncated = true;
                nextAddress = pageNext ?? currentStart;
            }
            else
            {
                // Ended on a complete page: every row was consumed, so
                // provisional continuation from an earlier page is stale.
                truncated = false;
                nextAddress = null;
            }
            break;
        }

        var iocs = new JsonArray();
        var truncatedValues = 0;

        foreach (var (addr, val, len) in stringItems)
        {
            string? detectedType = null;
            if (UrlRegex.IsMatch(val)) detectedType = "C2_URL";
            else if (Ipv4Regex.IsMatch(val) && val != "0.0.0.0" && val != "127.0.0.1" && val != "255.255.255.255") detectedType = "IP_Address";
            else if (CmdRegex.IsMatch(val)) detectedType = "Command_Execution";
            else if (RegistryRegex.IsMatch(val)) detectedType = "Registry_Persistence";
            else if (SecurityApiRegex.IsMatch(val)) detectedType = "Security_Sensitive_API";
            else if (CryptoRegex.IsMatch(val)) detectedType = "Crypto_Artifact";

            if (detectedType is not null)
            {
                // Token guard: a single overlong string (embedded blob, 20k
                // filler, long URL) must not blow up the whole triage
                // response. Classification runs on the full value; only the
                // echoed preview is bounded. Full bytes stay reachable via
                // DumpStrings with a filter.
                var previewTruncated = false;
                var preview = ToolSupport.LimitSnapshotText(val, MaxIocValueChars, ref previewTruncated);
                var entry = new JsonObject
                {
                    ["type"] = detectedType,
                    ["value"] = preview
                };
                if (!string.IsNullOrEmpty(addr)) entry["address"] = addr;
                if (previewTruncated)
                {
                    entry["fullLength"] = val.Length;
                    truncatedValues++;
                }
                iocs.Add(entry);
            }
            else
            {
            }
        }

        var triageResult = new JsonObject
        {
            ["totalExamined"] = stringItems.Count,
            ["suspiciousCount"] = iocs.Count,
            ["truncatedValues"] = truncatedValues,
            ["truncated"] = truncated,
            ["iocs"] = iocs
        };
        if (iocs.Count == 0 && fallbackText is null)
        {
            // Zero rows is the expected shape when nothing matches the IOC
            // patterns, but it reads as "nothing found". One short,
            // actionable field says why so the agent tunes the scan instead
            // of wasting calls re-running the same triage.
            triageResult["note"] =
                $"No IOC match in {stringItems.Count} {section} strings (wide strings included). " +
                "Not evidence of a clean target: retry with filter/start or read raw rows via DumpStrings.";
        }
        if (fallbackText is not null)
        {
            // Honest degradation: the rows below are empty because the
            // fallback is a text report, not because the target is clean.
            var fallbackPreviewTruncated = false;
            triageResult["degraded"] = true;
            triageResult["fallback"] = "FindInterestingStrings";
            triageResult["warning"] =
                "DumpStrings failed; the native fallback returned a text report, so no IOC rows were classified. " +
                "This is NOT evidence that the target is clean. Read fallbackText, or retry DumpStrings with a valid section.";
            triageResult["fallbackText"] = ToolSupport.LimitSnapshotText(
                fallbackText, MaxFallbackTextChars, ref fallbackPreviewTruncated);
            if (fallbackPreviewTruncated)
                triageResult["fallbackTextTruncated"] = true;
        }
        // Continuation mirrors the bridge dialect: present only when more
        // data exists, so absence means complete.
        if (nextAddress is not null)
            triageResult["nextAddress"] = nextAddress;

        // P2-4 compact opt-in (default off = historical shape): repeated
        // IOC type strings become integer indices into a top-level
        // typeLegend. Pure .NET-side transform; never forwarded to
        // DumpStrings.
        if (ToolSupport.ReadArgumentBool(arguments, "compact", false))
            ApplyStringsCompact(triageResult);

        return BridgeEnvelope.Success(triageResult);
    }

    /// <summary>
    /// P2-4 compact transform for TriageStrings: repeated IOC <c>type</c>
    /// strings become integer indices into a top-level <c>typeLegend</c>
    /// array (ordinal-sorted). Keys are unchanged; only values are coded,
    /// and only when the caller opted in.
    /// </summary>
    internal static void ApplyStringsCompact(JsonObject triageResult)
    {
        if (triageResult["iocs"] is not JsonArray iocs)
            return;
        var types = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var item in iocs.OfType<JsonObject>())
        {
            if (item["type"] is JsonValue typeValue &&
                typeValue.TryGetValue<string>(out var type) && type is not null)
                types.Add(type);
        }
        var typeList = types.ToList();
        var typeIndex = typeList
            .Select((value, index) => (value, index))
            .ToDictionary(pair => pair.value, pair => pair.index, StringComparer.Ordinal);
        foreach (var item in iocs.OfType<JsonObject>())
        {
            if (item["type"] is JsonValue typeValue &&
                typeValue.TryGetValue<string>(out var type) && type is not null &&
                typeIndex.TryGetValue(type, out var code))
                item["type"] = code;
        }
        triageResult["typeLegend"] = new JsonArray(typeList.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
    }


    private static int? SafeRecordInt(JsonObject record, string key)
        => record[key] is JsonValue value && value.TryGetValue<int>(out var number) ? number : null;

    private static readonly JsonSerializerOptions _jsonOptions = ToolSupport.BudgetJsonOptions;

    internal static IReadOnlyList<string> ClassifyImport(string qualifiedName)
    {
        var text = qualifiedName.ToLowerInvariant();
        var categories = new List<string>(2);
        if (ContainsAny(text, NetworkMarkers))
            categories.Add("network");
        if (ContainsAny(text, CryptoMarkers))
            categories.Add("crypto");
        if (ContainsAny(text, AntiDebugMarkers))
            categories.Add("anti-debug");
        if (ContainsAny(text, RegistryMarkers))
            categories.Add("registry");
        if (ContainsAny(text, ExecMarkers))
            categories.Add("exec");
        if (ContainsAny(text, InjectionMarkers))
            categories.Add("injection");
        return categories;
    }

    private static bool ContainsAny(string text, string[] markers)
    {
        foreach (var marker in markers)
        {
            if (text.Contains(marker, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static readonly string[] NetworkMarkers =
    [
        "ws2_32", "wininet", "winhttp", "urlmon", "dnsapi", "wsa",
        "socket", "connect", "recv", "send", "http", "ftp",
        "getaddrinfo", "gethostbyname", "internetopen", "internetconnect",
    ];

    private static readonly string[] CryptoMarkers =
    [
        "crypt", "bcrypt", "ncrypt", "aes", "rsa", "rc4", "chacha",
        "sha256", "sha1", "md5", "diffie", "x509", "certificate",
    ];

    private static readonly string[] AntiDebugMarkers =
    [
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "queryinformationprocess",
        "ntquerysysteminformation", "outputdebugstring", "debugbreak",
        "setunhandledexceptionfilter", "addvectoredexceptionhandler",
    ];

    private static readonly string[] RegistryMarkers =
    [
        "regopen", "regcreate", "regset", "regquery", "regdelete", "regenum",
        "registry", "shreg",
    ];

    private static readonly string[] ExecMarkers =
    [
        "createprocess", "shellexecute", "winexec", "execv", "spawn",
    ];

    private static readonly string[] InjectionMarkers =
    [
        "virtualalloc", "virtualprotect", "writeprocessmemory",
        "createremotethread", "rtlcreateuserthread", "queueuserapc",
        "setwindowshook", "loadlibrary", "getprocaddress",
        "ntmapview", "ntunmapview", "openprocess",
    ];

    private static string? SafeRecordString(JsonObject record, string key)
        => record[key] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
}
