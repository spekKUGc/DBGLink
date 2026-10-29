using DbgLink.Shared;
using System.Buffers;
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

internal sealed class AddressMapping
{
    private const int MaxMappingCandidates = 8;
    private const long MaxIdentityHashBytes = 512L * 1024 * 1024;
    // P1-5: opt-in byte verification sample. Fixed 32 bytes keeps the
    // enriched map response bounded (~64 hex chars static, ~2 hexdump lines
    // live) so map+verify collapses to one call without budget risk.
    internal const int MapByteSampleLength = 32;
    private readonly AnalysisContext _context;
    private IBridgeClient ActiveBridge => _context.Bridge;
    private IGhidraClient ActiveGhidra => _context.Ghidra;
    public AddressMapping(AnalysisContext context)
    {
        _context = context;
    }

    internal async Task<string> MapStaticFunctionToLiveAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object })
            return BridgeEnvelope.Error("mapping_invalid_argument", "mapping arguments must be an object.");

        if (!arguments.Value.TryGetProperty("function", out var functionElement) ||
            functionElement.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(functionElement.GetString()))
        {
            return BridgeEnvelope.Error("mapping_invalid_argument", "function argument must be a non-empty string.");
        }

        var functionSelector = functionElement.GetString()!;
        var verifyHash = !arguments.Value.TryGetProperty("verifyHash", out var verifyHashElement) ||
            verifyHashElement.ValueKind != JsonValueKind.False;
        // P1-5 opt-ins, default OFF so the default response bytes are unchanged.
        var includeLiveBytes = arguments.Value.TryGetProperty("includeLiveBytes", out var liveBytesElement) &&
            liveBytesElement.ValueKind == JsonValueKind.True;
        var includeStaticBytes = arguments.Value.TryGetProperty("includeStaticBytes", out var staticBytesElement) &&
            staticBytesElement.ValueKind == JsonValueKind.True;
        var inspectArguments = JsonSerializer.SerializeToElement(new
        {
            function = functionSelector,
            maxChars = 1_000,
            maxItems = 1,
            includeDecomp = false,
            includeDisassembly = false,
            includeReferences = false,
            includeSymbols = false,
        });
        var stats = new MappingCallStats();
        // The Ghidra session owns one immutable program, so the identity of a
        // selector is stable for the session. Cache it briefly so a map/verify
        // loop does not re-enter Ghidra on every call.
        var staticKey = $"{ActiveGhidra.GetHashCode()}:{functionSelector}";
        var now = Stopwatch.GetTimestamp();
        ToolSupport.StaticFunction staticFunction;
        if (SessionCaches.StaticIdentities.TryGet(staticKey, now, out var cachedFunction))
        {
            staticFunction = cachedFunction;
        }
        else
        {
            var staticResponse = await ActiveGhidra.RequestAsync("InspectFunction", inspectArguments, cancellationToken);
            stats.GhidraCalls++;
            if (ToolSupport.AnalyzeBridgeResponse(staticResponse, includeText: false).IsError)
                return staticResponse;

            if (!TryReadStaticFunction(staticResponse, out staticFunction, out var staticError))
                return BridgeEnvelope.Error("mapping_unavailable", staticError);

            SessionCaches.StaticIdentities.Set(staticKey, now, staticFunction);
        }

        var mapping = await BuildLiveMappingAsync(ActiveBridge, staticFunction, verifyHash, cancellationToken, stats);
        if (includeLiveBytes || includeStaticBytes)
        {
            await AttachMapBytesAsync(ActiveBridge, ActiveGhidra, staticFunction, mapping,
                includeLiveBytes, includeStaticBytes, cancellationToken, stats);
        }
        mapping["bridgeCalls"] = stats.ToJson();
        return BridgeEnvelope.Success(mapping);
    }

    /// <summary>
    /// P1-5 read-only enrichment: attach bounded byte samples to a successful
    /// mapping so map+verify is one call. Composes the existing
    /// ReadMemAtAddress (native) and ReadStaticBytes (Ghidra) primitives only;
    /// no new bridge methods. Misses keep their honest reason codes untouched;
    /// byte-read failures attach per-field errors and never fail the map.
    /// </summary>
    internal static async Task AttachMapBytesAsync(
        IBridgeClient bridge,
        IGhidraClient ghidra,
        ToolSupport.StaticFunction staticFunction,
        JsonObject mapping,
        bool includeLiveBytes,
        bool includeStaticBytes,
        CancellationToken cancellationToken,
        MappingCallStats? stats = null)
    {
        if (mapping["match"]?.GetValue<bool>() != true)
            return;
        var liveAddress = mapping["liveAddress"]?.GetValue<string>();
        if (includeLiveBytes && !string.IsNullOrWhiteSpace(liveAddress))
        {
            if (stats is not null)
                stats.NativeCalls++;
            mapping["liveBytes"] = await ReadLiveBytesAsync(bridge, liveAddress!, cancellationToken);
        }
        if (includeStaticBytes && !string.IsNullOrWhiteSpace(staticFunction.Entry))
        {
            if (stats is not null)
                stats.GhidraCalls++;
            mapping["staticBytes"] = await ReadStaticBytesAsync(ghidra, staticFunction.Entry, cancellationToken);
        }
        AttachBreakpointHint(mapping, staticFunction);
    }

    /// <summary>
    /// Flat SetBreakpoint-ready echo {module, rva, liveAddress} on a matched
    /// mapping. The fields already exist in nested form; the flat hint lets
    /// the caller issue SetBreakpoint(module, rva) first try.
    /// </summary>
    internal static void AttachBreakpointHint(JsonObject mapping, ToolSupport.StaticFunction staticFunction)
    {
        if (AnalysisFormatting.ReadNodeNullableBool(mapping, "match") != true)
            return;
        var liveAddress = AnalysisFormatting.ReadNodeString(mapping, "liveAddress");
        var moduleName = mapping["module"] is JsonObject module
            ? AnalysisFormatting.ReadNodeString(module, "name")
            : null;
        if (string.IsNullOrWhiteSpace(moduleName) || string.IsNullOrWhiteSpace(liveAddress))
            return;
        mapping["breakpointHint"] = new JsonObject
        {
            ["module"] = moduleName,
            ["rva"] = FormatAddress(staticFunction.Rva),
            ["liveAddress"] = liveAddress,
        };
    }

    internal static async Task<JsonNode> ReadLiveBytesAsync(
        IBridgeClient bridge, string liveAddress, CancellationToken cancellationToken)
    {
        try
        {
            var raw = await bridge.RequestAsync("ReadMemAtAddress",
                JsonSerializer.SerializeToElement(new { address = liveAddress, byteCount = MapByteSampleLength }),
                cancellationToken);
            var node = AnalysisFormatting.ReadBridgeResultNode(raw);
            if (node is not null)
                return node;
            // The native bridge answers single reads with a text envelope
            // ({ok:true, method, text: hexdump}), not a result object, so
            // ReadBridgeResultNode is null on success. A non-error analysis
            // with non-empty text means the bytes ARE present: report ok:true
            // with the same ok/code/message keys and message format instead
            // of misreporting live_bytes_unavailable.
            var analysis = ToolSupport.AnalyzeBridgeResponse(raw);
            if (!analysis.IsError && !string.IsNullOrWhiteSpace(analysis.Text))
                return MapBytesSuccess("live_bytes", analysis.Text);
            return MapBytesError("live_bytes_unavailable", analysis.Text);
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or JsonException)
        {
            return MapBytesError("live_bytes_unavailable", exception.Message);
        }
    }

    internal static async Task<JsonNode> ReadStaticBytesAsync(
        IGhidraClient ghidra, string entryAddress, CancellationToken cancellationToken)
    {
        try
        {
            var raw = await ghidra.RequestAsync("ReadStaticBytes",
                JsonSerializer.SerializeToElement(new { address = entryAddress, length = MapByteSampleLength }),
                cancellationToken);
            var node = AnalysisFormatting.ReadBridgeResultNode(raw);
            if (node is not null)
                return node;
            return MapBytesError("static_bytes_unavailable", ToolSupport.AnalyzeBridgeResponse(raw).Text);
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or JsonException)
        {
            return MapBytesError("static_bytes_unavailable", exception.Message);
        }
    }

    private static JsonObject MapBytesError(string code, string message)
    {
        var clean = CleanMapBytesMessage(message);
        return new JsonObject
        {
            ["ok"] = false,
            ["code"] = code,
            ["message"] = string.IsNullOrWhiteSpace(clean) ? "Byte read did not return structured JSON." : clean,
        };
    }

    private static JsonObject MapBytesSuccess(string code, string message)
    {
        var clean = CleanMapBytesMessage(message);
        return new JsonObject
        {
            ["ok"] = true,
            ["code"] = code,
            ["message"] = string.IsNullOrWhiteSpace(clean) ? "Byte read did not return structured JSON." : clean,
        };
    }

    private static string CleanMapBytesMessage(string? message)
    {
        var clean = new string((message ?? "").Where(c => !char.IsControl(c) || c is '\r' or '\n' or '\t').ToArray());
        if (clean.Length > 256)
            clean = clean[..256] + "...[truncated]";
        return clean;
    }

    // Process-wide module caches live in SessionCaches (typed accessors +
    // TTL constants in one place); this forwarder keeps the existing call
    // sites (SessionControlTools target open/switch hook, tests) working.
    internal static void InvalidateModuleCache() => SessionCaches.InvalidateModuleCaches();

    /// <summary>
    /// One module table per bridge, shared by every tool that needs module
    /// identity: breakpoint module+rva resolution, static-to-live mapping and
    /// error enrichment each used to fetch their own copy. A stable debugger
    /// session's table does not change between calls, so the second caller
    /// inside the TTL window is free; any target open/switch clears it through
    /// <see cref="SessionCaches.InvalidateModuleCaches"/>. Failures are not cached.
    /// </summary>
    internal static async Task<IReadOnlyList<ToolSupport.LiveModule>?> ReadCachedModuleTableAsync(
        IBridgeClient bridge,
        Func<CancellationToken, Task<string>> fetch,
        CancellationToken cancellationToken)
    {
        var cacheKey = bridge.GetHashCode().ToString(CultureInfo.InvariantCulture);
        var now = Stopwatch.GetTimestamp();
        if (SessionCaches.ModuleTables.TryGet(cacheKey, now, out var cachedModules))
            return cachedModules;

        string raw;
        try
        {
            raw = await fetch(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }

        var node = AnalysisFormatting.ReadBridgeResultNode(raw);
        if (node is not JsonObject result || result["modules"] is not JsonArray)
            return null;
        var modules = ParseModuleRecords(result);
        if (modules.Count == 0)
            return null;
        SessionCaches.ModuleTables.Set(cacheKey, now, modules);
        return modules;
    }

    /// <summary>
    /// Backend calls actually issued while producing one mapping result. Cache
    /// hits are free, so the tool reports the real cost instead of a guess.
    /// </summary>
    internal sealed class MappingCallStats
    {
        public int GhidraCalls { get; set; }
        public int NativeCalls { get; set; }

        public JsonObject ToJson() => new()
        {
            ["ghidra"] = GhidraCalls,
            ["native"] = NativeCalls,
        };
    }

    internal static async Task<JsonObject> BuildLiveMappingAsync(
        IBridgeClient bridge,
        ToolSupport.StaticFunction staticFunction,
        bool verifyHash,
        CancellationToken cancellationToken,
        MappingCallStats? stats = null,
        IDictionary<string, string?>? hashCache = null)
    {
        IReadOnlyList<ToolSupport.LiveModule> modules;
        var cacheKey = $"{bridge.GetHashCode()}:{NormalizeIdentityPath(staticFunction.Path ?? "")}";
        var now = Stopwatch.GetTimestamp();
        if (!SessionCaches.ModuleCollections.TryGet(cacheKey, now, out var cachedModules))
        {
            if (stats is not null)
                stats.NativeCalls++;
            var liveResponse = await bridge.RequestAsync("GetModuleRecords",
                JsonSerializer.SerializeToElement(new { modulePath = staticFunction.Path }), cancellationToken);
            var liveAnalysis = ToolSupport.AnalyzeBridgeResponse(liveResponse);
            if (liveAnalysis.IsError)
                return new JsonObject { ["match"] = false, ["reason"] = "live_modules_unavailable" };
            var parsed = ParseModuleRecords(AnalysisFormatting.ReadBridgeResultNode(liveResponse));
            // A truncated module table is a partial view: caching it would
            // pin "module_search_incomplete" for the whole TTL even after
            // the full table becomes available. Cache only complete tables.
            if (!parsed.Truncated)
                SessionCaches.ModuleCollections.Set(cacheKey, now, parsed);
            modules = parsed;
        }
        else
        {
            modules = cachedModules;
        }
        return await BuildMappingResultAsync(staticFunction, modules, verifyHash, cancellationToken, hashCache);
    }

    internal static async Task<JsonObject> BuildMappingResultAsync(
        ToolSupport.StaticFunction staticFunction,
        IReadOnlyList<ToolSupport.LiveModule> liveModules,
        bool verifyHash,
        CancellationToken cancellationToken,
        IDictionary<string, string?>? hashCache = null)
    {
        var match = await FindModuleMatchAsync(staticFunction, liveModules, verifyHash, cancellationToken, hashCache);
        var staticJson = new JsonObject
        {
            ["name"] = staticFunction.Name,
            ["entry"] = staticFunction.Entry,
        };
        // Echo the static identity the match was attempted against: on a miss
        // the LLM otherwise has to re-query Ghidra to see which path/hash
        // failed to match, costing another round trip.
        if (!string.IsNullOrWhiteSpace(staticFunction.Path))
            staticJson["path"] = staticFunction.Path;
        if (!string.IsNullOrWhiteSpace(staticFunction.Sha256))
            staticJson["sha256"] = staticFunction.Sha256;
        var result = new JsonObject
        {
            ["rva"] = FormatAddress(staticFunction.Rva),
            ["staticFunction"] = staticJson,
            ["candidateCount"] = liveModules.Count,
            ["modulesTruncated"] = liveModules is LiveModuleCollection { Truncated: true },
        };

        if (match is null)
        {
            result["match"] = false;
            result["reason"] = liveModules is LiveModuleCollection { Truncated: true }
                ? "module_search_incomplete" : "module_identity_not_found";
            result["candidates"] = BuildModuleCandidates(liveModules);
            return result;
        }

        var moduleSize = match.Module.End > match.Module.Base ? match.Module.End - match.Module.Base : 0;
        if (moduleSize == 0 || staticFunction.Rva >= moduleSize || staticFunction.Rva > ulong.MaxValue - match.Module.Base)
        {
            result["match"] = false;
            result["reason"] = "rva_out_of_module";
            result["module"] = ModuleJson(match.Module);
            return result;
        }

        var liveAddress = match.Module.Base + staticFunction.Rva;
        result["match"] = true;
        result["liveAddress"] = FormatAddress(liveAddress);
        // staticFunction already carries path+sha; the module row adds the
        // live placement, so its path would be a third copy.
        var matchedModule = ModuleJson(match.Module);
        matchedModule.Remove("path");
        result["module"] = matchedModule;
        result["identity"] = new JsonObject
        {
            ["kind"] = match.IdentityKind,
            ["hashVerified"] = match.HashVerified,
        };
        return result;
    }

    internal static async Task<ToolSupport.ModuleMatch?> FindModuleMatchAsync(
        ToolSupport.StaticFunction staticFunction,
        IReadOnlyList<ToolSupport.LiveModule> modules,
        bool verifyHash,
        CancellationToken cancellationToken,
        IDictionary<string, string?>? hashCache = null)
    {
        var staticPath = NormalizeIdentityPath(staticFunction.Path);
        var staticFileName = FileName(staticFunction.Path);
        var staticHash = NormalizeSha256(staticFunction.Sha256);
        // Shared by the caller across selectors (multi-brief): hashing the
        // same live module once per brief instead of once per selector.
        // Null keeps the old per-call scope, so single callers are unchanged.
        hashCache ??= new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in modules)
        {
            var samePath = !string.IsNullOrEmpty(staticPath) &&
                string.Equals(staticPath, NormalizeIdentityPath(module.Path), StringComparison.OrdinalIgnoreCase);
            var sameFileName = !string.IsNullOrEmpty(staticFileName) &&
                string.Equals(staticFileName, FileName(module.Path), StringComparison.OrdinalIgnoreCase);
            if (!samePath && !(verifyHash && staticHash is not null && sameFileName))
                continue;

            if (verifyHash && staticHash is not null)
            {
                var liveHash = await HashModuleAsync(module.Path, hashCache, cancellationToken);
                if (liveHash is not null)
                {
                    if (string.Equals(staticHash, liveHash, StringComparison.OrdinalIgnoreCase))
                        return new ToolSupport.ModuleMatch(module, "sha256", true);
                    continue;
                }
            }

            if (samePath)
                return new ToolSupport.ModuleMatch(module, "path", false);
        }

        return null;
    }

    internal static async Task<string?> HashModuleAsync(
        string path,
        IDictionary<string, string?> cache,
        CancellationToken cancellationToken)
    {
        var cacheKey = NormalizeIdentityPath(path);
        if (cache.TryGetValue(cacheKey, out var cached))
            return cached;

        var hash = await ComputeBoundedModuleHashAsync(path, cancellationToken);

        cache[cacheKey] = hash;
        return hash;
    }

    internal static async Task<string?> ComputeBoundedModuleHashAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists ||
                file.Attributes.HasFlag(FileAttributes.Directory) ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Length is <= 0 or > MaxIdentityHashBytes ||
                !DbgLinkConfigPath.IsSafePath(file.FullName))
                return null;

            await using var stream = new FileStream(
                file.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 64 * 1024,
                options: FileOptions.Asynchronous | FileOptions.SequentialScan);
            var expectedLength = stream.Length;
            if (expectedLength is <= 0 or > MaxIdentityHashBytes)
                return null;

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            long totalRead = 0;
            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
                    if (read == 0)
                        break;

                    totalRead += read;
                    if (totalRead > expectedLength || totalRead > MaxIdentityHashBytes)
                        return null;
                    hash.AppendData(buffer, 0, read);
                }

                if (totalRead != expectedLength || stream.Length != expectedLength)
                    return null;

                return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
        catch (System.Security.SecurityException) { return null; }
    }

    internal static bool TryReadStaticFunction(string raw, out ToolSupport.StaticFunction function, out string error)
    {
        function = default!;
        error = "Ghidra response did not contain a complete function identity.";
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object ||
                !result.TryGetProperty("function", out var functionElement) || functionElement.ValueKind != JsonValueKind.Object ||
                !functionElement.TryGetProperty("module", out var moduleElement) || moduleElement.ValueKind != JsonValueKind.Object)
                return false;

            var name = ReadString(functionElement, "name");
            var entry = ReadString(functionElement, "entry");
            var rvaText = ReadString(functionElement, "rva") ?? ReadString(moduleElement, "rva");
            var path = ReadString(moduleElement, "path") ?? "";
            var sha256 = ReadString(moduleElement, "sha256");
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(entry) ||
                string.IsNullOrWhiteSpace(rvaText) || !TryParseAddress(rvaText, out var rva) ||
                (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(sha256)))
                return false;

            function = new ToolSupport.StaticFunction(name, entry, path, sha256, rva);
            error = "";
            return true;
        }
        catch (JsonException)
        {
            error = "Ghidra returned invalid JSON for function mapping.";
            return false;
        }
    }

    internal sealed class LiveModuleCollection : List<ToolSupport.LiveModule>
    {
        public bool Truncated { get; set; }
    }

    internal static LiveModuleCollection ParseModuleRecords(JsonNode? node)
    {
        var modules = new LiveModuleCollection { Truncated = true };
        if (node is not JsonObject result || result["modules"] is not JsonArray records ||
            result["truncated"] is not JsonValue flag || !flag.TryGetValue<bool>(out var truncated))
            return modules;
        modules.Truncated = truncated;
        foreach (var record in records)
        {
            if (record is not JsonObject entry ||
                !TryString(entry, "base", out var baseText) || !TryParseAddress(baseText, out var start) ||
                !TryString(entry, "end", out var endText) || !TryParseAddress(endText, out var end) || end <= start ||
                !TryString(entry, "name", out var name) || !TryString(entry, "path", out var path))
            {
                modules.Truncated = true;
                continue;
            }
            modules.Add(new ToolSupport.LiveModule(start, end, name, path));
        }
        return modules;
    }

    private static bool TryString(JsonObject node, string key, out string text)
    {
        text = "";
        return node[key] is JsonValue value && value.TryGetValue<string>(out text!) && !string.IsNullOrWhiteSpace(text);
    }

    internal static IReadOnlyList<ToolSupport.LiveModule> ParseLiveModules(string text)
    {
        var modules = new LiveModuleCollection
        {
            Truncated = text.Contains("mapTruncated=true", StringComparison.Ordinal) ||
                text.Contains("outputTruncated=true", StringComparison.Ordinal) ||
                text.Contains("...[truncated]", StringComparison.Ordinal)
        };
        foreach (var rawLine in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.TrimEnd('\r');
            if (!line.StartsWith("base=", StringComparison.OrdinalIgnoreCase) ||
                !TryReadHexField(line, "base", out var baseAddress) ||
                !TryReadHexField(line, "end", out var endAddress))
                continue;

            var pathMarker = line.LastIndexOf(" path=", StringComparison.OrdinalIgnoreCase);
            var nameMarker = line.IndexOf(" name=", StringComparison.OrdinalIgnoreCase);
            if (nameMarker < 0 || pathMarker <= nameMarker)
                continue;

            var nameStart = nameMarker + " name=".Length;
            var pathStart = pathMarker + " path=".Length;
            var name = line[nameStart..pathMarker].Trim();
            var path = line[pathStart..].Trim();
            if (baseAddress >= endAddress || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(path))
            {
                modules.Truncated = true;
                continue;
            }
            modules.Add(new ToolSupport.LiveModule(baseAddress, endAddress, name, path));
        }
        return modules;
    }

    internal static JsonArray BuildModuleCandidates(IReadOnlyList<ToolSupport.LiveModule> modules)
    {
        var result = new JsonArray();
        foreach (var module in modules.Take(MaxMappingCandidates))
            result.Add(ModuleJson(module));
        return result;
    }

    internal static JsonObject ModuleJson(ToolSupport.LiveModule module)
        => new()
        {
            ["name"] = module.Name,
            ["base"] = FormatAddress(module.Base),
            ["end"] = FormatAddress(module.End),
            ["path"] = module.Path,
        };

    internal static bool TryReadHexField(string line, string field, out ulong value)
    {
        value = 0;
        var marker = field + "=";
        var start = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
            return false;
        start += marker.Length;
        var end = line.IndexOf(' ', start);
        var raw = (end < 0 ? line[start..] : line[start..end]).Trim();
        return TryParseAddress(raw, out value);
    }

    internal static bool TryParseAddress(string? value, out ulong address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var text = value.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return !string.IsNullOrEmpty(text) &&
            ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out address);
    }

    internal static string? ReadString(JsonElement objectElement, string propertyName)
        => objectElement.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    internal static string NormalizeIdentityPath(string path)
    {
        var normalized = path.Trim().Trim('"').Replace('/', '\\');
        if (normalized.StartsWith("\\", StringComparison.Ordinal) && normalized.Length > 2 && normalized[2] == ':')
            normalized = normalized[1..];
        return normalized.TrimEnd('\\').ToUpperInvariant();
    }

    internal static string FileName(string path)
    {
        var normalized = path.Replace('/', '\\');
        var separator = normalized.LastIndexOf('\\');
        return separator >= 0 ? normalized[(separator + 1)..] : normalized;
    }

    internal static string? NormalizeSha256(string? value)
    {
        var text = value?.Trim();
        return text is { Length: 64 } && text.All(Uri.IsHexDigit) ? text.ToLowerInvariant() : null;
    }

    internal static string FormatAddress(ulong value) => $"0x{value:X}";

}
