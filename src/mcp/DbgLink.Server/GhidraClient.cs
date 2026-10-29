using System.Buffers;
using System.Diagnostics;
using DbgLink.Shared;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal interface IGhidraClient
{
    Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken);
}

internal sealed class GhidraClient : IGhidraClient, IDisposable
{
    private const int MaxRequestBytes = 1 * 1024 * 1024;
    private const int MaxEndpointBytes = 8 * 1024;
    private const int MaxTokenChars = 256;
    private const int MaxResponseBytes = 256 * 1024;
    private const int MaxEndpointCandidates = 16;
    private const int MaxEndpointDirectoryEntries = 4_096;
    private const int ConnectTimeoutMs = 1_500;
    private const int ResponseTimeoutMs = 35_000;
    private const int EndpointCacheMilliseconds = SessionCaches.GhidraEndpointCacheMilliseconds;
    private const int ResponseCacheMilliseconds = SessionCaches.GhidraResponseCacheMilliseconds;
    private const int StaticResponseCacheMilliseconds = SessionCaches.GhidraStaticResponseCacheMilliseconds;
    private const int MaxCachedResponses = SessionCaches.GhidraMaxCachedResponses;
    private const int MaxCachedResponseChars = SessionCaches.GhidraMaxCachedResponseChars;
    private static readonly byte[] NewLine = [(byte)'\n'];

    private readonly string? _endpointDirectory;
    private readonly object _endpointCacheLock = new();
    private int _requestId;
    private EndpointInfo? _cachedEndpoint;
    private long _cachedEndpointExpiresAt;
    private readonly object _responseCacheLock = new();
    private readonly Dictionary<string, CachedResponse> _responseCache = new(StringComparer.Ordinal);
    private long _responseCacheGeneration;
    private EndpointInfo? _lastEndpoint;
    private string? _lastEndpointDirectoryKey;
    // Matches GhidraBridgeServer.MAX_CONNECTION_WORKERS: the bridge runs a
    // fixed pool of four connection workers, each with its own decompile
    // process, and read-only methods share a program read lock. Serialising
    // here (the old value was 1) made that whole design unused — only one
    // worker could ever be busy, so a batch of reads took N x the time of one.
    // Keep this <= the bridge worker count: the bridge rejects queued
    // connections once its pending queue is full.
    private const int MaxConcurrentBridgeRequests = 4;
    private readonly SemaphoreSlim _requests = new(MaxConcurrentBridgeRequests, MaxConcurrentBridgeRequests);
    private readonly SemaphoreSlim _admission = new(17, 17);

    internal ServerMetrics? Telemetry { get; set; }

    public GhidraClient(string? endpointDirectory = null)
    {
        _endpointDirectory = endpointDirectory;
    }

    public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
            return BridgeEnvelope.Error("ghidra_unavailable", "The Ghidra client was disposed; the analysis session is closing.");
        if (!_admission.Wait(0))
        {
            Telemetry?.RecordBackendCall("ghidra", method ?? "queue", false, "ghidra_queue_full", 0);
            return BridgeEnvelope.Error("ghidra_queue_full", "The bounded Ghidra request queue is full. Do not poll: back off, batch reads via BatchStaticQueries, then retry once.");
        }
        var acquired = false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(120_000);
        try
        {
            await _requests.WaitAsync(deadline.Token).ConfigureAwait(false);
            acquired = true;
            string response;
            try
            {
                response = await RequestCoreAsync(method, arguments, deadline.Token).ConfigureAwait(false);
            }
            finally
            {
                _requests.Release();
                acquired = false;
            }
            // P3-16 selector help: a function_not_found/ambiguous_function
            // error gains a server-side ListFunctions candidates lookup. The
            // outer request already released its concurrency slot, so the
            // nested request cannot starve itself, and any lookup failure
            // returns the original error untouched.
            return await MaybeAttachCandidatesAsync(method, arguments, response, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Telemetry?.RecordBackendCall("ghidra", method ?? "_unknown", false, "ghidra_timeout", 0);
            return BridgeEnvelope.Error("ghidra_timeout", "Ghidra request exceeded its queue/execution deadline. The Ghidra process may have exited; check ListAnalysisSessions (ghidraRunning:false means exited) and CloseAnalysisSession/ReopenAnalysisSession to restart. If still running, back off, then retry once.");
        }
        finally
        {
            if (acquired) _requests.Release();
            _admission.Release();
        }
    }

    private async Task<string> RequestCoreAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
    {
        var telemetry = Telemetry;
        var stopwatch = telemetry is null ? null : Stopwatch.StartNew();
        string Recorded(string response, bool cached = false)
        {
            try
            {
                telemetry?.RecordBackendCall("ghidra", method, BridgeClient.TryParseOutcome(response, out var ok) && ok,
                    BridgeClient.TryParseErrorCode(response), stopwatch is null ? 0 : (long)Math.Round(stopwatch.Elapsed.TotalMilliseconds), cached);
            }
            catch { }
            return response;
        }

        if (!GhidraMethods.TryGetValue(method, out var methodKind))
            return Recorded(BridgeEnvelope.Error("method_not_allowed",
                $"Ghidra method '{method}' is not allowlisted. Use a static read tool (ListFunctions, ListSymbols, Xrefs, ReadStaticBytes, DumpStrings, InspectFunction, AnalyzeFunctions, DecompileModule, GetAnalysisQueue, CallGraph) or BatchStaticQueries."));
        if (arguments.HasValue && arguments.Value.ValueKind != JsonValueKind.Object)
            return Recorded(BridgeEnvelope.Error("invalid_arguments", $"Ghidra method '{method}' requires its arguments as a JSON object."));

        // Cache/durability/invalidation all follow from the one method table:
        // reads are durable, the volatile status probe is short-lived, and a
        // mutation is never cached and clears what the cache holds.
        var cacheable = methodKind != GhidraMethod.Mutation;
        var durable = methodKind == GhidraMethod.Read;
        var cacheKey = cacheable ? method + "\n" + (arguments?.GetRawText() ?? "{}") : "";
        InvalidateOnDirectoryChange();
        var endpoint = FindEndpoint(_endpointDirectory);
        InvalidateOnEndpointChange(endpoint);
        if (cacheable && TryGetCachedResponse(cacheKey, out var cached))
            return Recorded(cached, cached: true);
        var cacheGeneration = Volatile.Read(ref _responseCacheGeneration);
        if (methodKind == GhidraMethod.Mutation)
            ClearResponseCache();

        if (endpoint is null)
            return Recorded(BridgeEnvelope.Error("ghidra_unavailable",
                "Ghidra bridge endpoint was not found. No Ghidra program is active in this session: " +
                "call ListAnalysisSessions and pass a live analysisId, or OpenGhidraFile to import a target. " +
                "Do not poll: wait for the import's GetGhidraOpenStatus result instead of retrying this query."));

        var id = Interlocked.Increment(ref _requestId);
        var requestBuffer = new ArrayBufferWriter<byte>(1_024);
        using (var writer = new Utf8JsonWriter(requestBuffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("id", id);
            writer.WriteString("token", endpoint.Token);
            writer.WriteString("method", method);
            if (arguments is { ValueKind: JsonValueKind.Object })
            {
                writer.WritePropertyName("params");
                arguments.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }

        try
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(ConnectTimeoutMs);
            await client.ConnectAsync(IPAddress.Loopback, endpoint.Port, connectTimeout.Token);

            await using NetworkStream network = client.GetStream();
            using var responseTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            responseTimeout.CancelAfter(ResponseTimeoutMs);
            if (requestBuffer.WrittenCount + 1 > MaxRequestBytes)
                return Recorded(BridgeEnvelope.Error("ghidra_request_too_large", "Ghidra bridge request exceeded the byte limit."));
            await network.WriteAsync(requestBuffer.WrittenMemory, responseTimeout.Token);
            await network.WriteAsync(NewLine, responseTimeout.Token);
            await network.FlushAsync(responseTimeout.Token);

            var line = await BoundedLineReader.ReadAsync(network, MaxResponseBytes, rejectEmptyLine: false, responseTimeout.Token);
            if (line is null)
                return Recorded(BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned an empty response."));

            var response = ValidateResponse(line, id);
            // Only successful envelopes are cacheable: a transient bridge error
            // (program_unavailable, ghidra_timeout, protocol error) must not
            // poison the 300s static cache.
            if (cacheable && BridgeClient.TryParseOutcome(response, out var ok) && ok)
                StoreCachedResponse(cacheKey, response, cacheGeneration, durable);
            return Recorded(response);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            InvalidateEndpoint();
            return Recorded(BridgeEnvelope.Error("ghidra_timeout", "Ghidra bridge did not respond within the timeout. The Ghidra process may have exited; check ListAnalysisSessions (ghidraRunning:false means exited) and CloseAnalysisSession/ReopenAnalysisSession to restart. If still running, back off, then retry once or batch via BatchStaticQueries."));
        }
        catch (SocketException)
        {
            InvalidateEndpoint();
            return Recorded(BridgeEnvelope.Error("ghidra_unavailable",
                "Ghidra bridge could not be reached on loopback. The Ghidra process may have stopped; " +
                "call ListAnalysisSessions to confirm live sessions. Do not poll: confirm session state first, then retry."));
        }
        catch (IOException)
        {
            InvalidateEndpoint();
            return Recorded(BridgeEnvelope.Error("ghidra_unavailable",
                "Ghidra bridge connection failed. The Ghidra process may have stopped; " +
                "call ListAnalysisSessions to confirm live sessions. Do not poll: confirm session state first, then retry."));
        }
        catch (DecoderFallbackException)
        {
            InvalidateEndpoint();
            return Recorded(BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned invalid UTF-8."));
        }
    }

    /// <summary>
    /// P3-16 selector help: a top-level function_not_found/ambiguous_function
    /// error gains additive candidates from a server-side ListFunctions filter
    /// lookup over the failed selector. No auto-resolve: the error keeps its
    /// code and the caller still picks the retry. The candidates array rides
    /// in the error object for structured callers (batch rows preserve full
    /// response JSON) and the names are appended to the message so the
    /// dispatcher text carries them too. Any lookup or rewrite failure
    /// returns the original response untouched.
    /// </summary>
    private async Task<string> MaybeAttachCandidatesAsync(
        string method, JsonElement? arguments, string response, CancellationToken cancellationToken)
    {
        // The lookup itself must never re-enter enrichment.
        if (string.Equals(method, "ListFunctions", StringComparison.Ordinal))
            return response;
        string? selector;
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.False ||
                !root.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object ||
                !error.TryGetProperty("code", out var code) || code.ValueKind != JsonValueKind.String)
                return response;
            if (code.GetString() is not ("function_not_found" or "ambiguous_function"))
                return response;
            selector = ExtractFunctionSelector(arguments);
            if (string.IsNullOrWhiteSpace(selector))
                return response;
        }
        catch (JsonException)
        {
            return response;
        }

        string lookupRaw;
        try
        {
            var filter = selector.Length > 256 ? selector[..256] : selector;
            lookupRaw = await RequestAsync("ListFunctions",
                JsonSerializer.SerializeToElement(new { filter, maxItems = 8 }),
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return response;
        }

        List<(string Name, string Entry)> candidates;
        try
        {
            candidates = ReadFunctionCandidates(lookupRaw);
            if (candidates.Count == 0)
                return response;
        }
        catch
        {
            return response;
        }

        try
        {
            var node = JsonNode.Parse(response)?.AsObject();
            var error = node?["error"]?.AsObject();
            if (node is null || error is null)
                return response;
            var array = new JsonArray();
            foreach (var (name, entry) in candidates)
                array.Add(new JsonObject { ["name"] = name, ["entry"] = entry });
            error["candidates"] = array;
            var message = error["message"]?.GetValue<string>() ?? "";
            var suffix = " candidates: " + string.Join(", ", candidates.Select(c => c.Name));
            var combined = message + suffix;
            if (combined.Length > 512)
                combined = combined[..511] + "…";
            error["message"] = combined;
            return node.ToJsonString();
        }
        catch (JsonException)
        {
            return response;
        }
        catch (InvalidOperationException)
        {
            return response;
        }
    }

    private static string? ExtractFunctionSelector(JsonElement? arguments)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object })
            return null;
        foreach (var name in new[] { "function", "start", "address" })
        {
            if (arguments.Value.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(value.GetString()))
                return value.GetString()!.Trim();
        }
        return null;
    }

    private static List<(string Name, string Entry)> ReadFunctionCandidates(string lookupRaw)
    {
        var candidates = new List<(string Name, string Entry)>();
        using var document = JsonDocument.Parse(lookupRaw, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object ||
            !result.TryGetProperty("functions", out var functions) || functions.ValueKind != JsonValueKind.Array)
            return candidates;
        foreach (var item in functions.EnumerateArray())
        {
            if (candidates.Count >= 8)
                break;
            if (item.ValueKind != JsonValueKind.Object ||
                !item.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("entry", out var entry) || entry.ValueKind != JsonValueKind.String)
                continue;
            var nameText = (name.GetString() ?? "").Trim();
            var entryText = (entry.GetString() ?? "").Trim();
            if (string.IsNullOrWhiteSpace(nameText) || string.IsNullOrWhiteSpace(entryText))
                continue;
            if (nameText.Length > 128)
                nameText = nameText[..128];
            if (entryText.Length > 64)
                entryText = entryText[..64];
            candidates.Add((nameText, entryText));
        }
        return candidates;
    }

    private static string ValidateResponse(string line, int expectedId)
    {
        try
        {
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("id", out var id) ||
                id.ValueKind != JsonValueKind.Number ||
                !id.TryGetInt32(out var responseId) ||
                responseId != expectedId ||
                !root.TryGetProperty("ok", out var ok) ||
                (ok.ValueKind != JsonValueKind.True && ok.ValueKind != JsonValueKind.False))
            {
                return BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned an invalid response.");
            }
            if (ok.ValueKind == JsonValueKind.True &&
                (!root.TryGetProperty("result", out var result) || result.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined))
            {
                return BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned no result.");
            }
            if (ok.ValueKind == JsonValueKind.False &&
                (!root.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object))
            {
                return BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned no error details.");
            }
            return line;
        }
        catch (JsonException)
        {
            return BridgeEnvelope.Error("ghidra_protocol_error", "Ghidra bridge returned invalid JSON.");
        }
    }

    private EndpointInfo? FindEndpoint(string? endpointDirectory)
    {
        IEnumerable<string> candidates;
        var explicitPath = endpointDirectory is null ? Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_ENDPOINT") : null;
        var usesDirectory = string.IsNullOrWhiteSpace(explicitPath);
        if (usesDirectory)
        {
            lock (_endpointCacheLock)
            {
                if (_cachedEndpoint is not null && Environment.TickCount64 < _cachedEndpointExpiresAt)
                    return _cachedEndpoint;
            }
        }

        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            candidates = Path.IsPathFullyQualified(explicitPath) && LocalPathPolicy.IsSafeLocalPath(explicitPath)
                ? new[] { Path.GetFullPath(explicitPath) }
                : Array.Empty<string>();
        }
        else
        {
            var directory = endpointDirectory ?? Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_ENDPOINT_DIR");
            directory = string.IsNullOrWhiteSpace(directory)
                ? Path.Combine(Path.GetTempPath(), "DbgLink")
                : directory;
            if (!Path.IsPathFullyQualified(directory) || !LocalPathPolicy.IsSafeLocalPath(directory) || !Directory.Exists(directory))
                return null;

            try
            {
                var newest = new PriorityQueue<string, DateTime>();
                var scanned = 0;
                foreach (var path in Directory.EnumerateFiles(directory, "ghidra-bridge-*.json"))
                {
                    if (scanned++ >= MaxEndpointDirectoryEntries)
                        break;

                    try
                    {
                        newest.Enqueue(path, File.GetLastWriteTimeUtc(path));
                        if (newest.Count > MaxEndpointCandidates)
                            newest.Dequeue();
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                    catch (ArgumentException) { }
                    catch (NotSupportedException) { }
                }

                candidates = newest.UnorderedItems
                    .OrderByDescending(item => item.Priority)
                    .Select(item => item.Element)
                    .ToArray();
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (NotSupportedException)
            {
                return null;
            }
        }

        foreach (var candidate in candidates)
        {
            var endpoint = ReadEndpoint(candidate);
            if (endpoint is not null)
            {
                if (usesDirectory)
                {
                    lock (_endpointCacheLock)
                    {
                        _cachedEndpoint = endpoint;
                        _cachedEndpointExpiresAt = Environment.TickCount64 + EndpointCacheMilliseconds;
                    }
                }
                return endpoint;
            }
        }
        return null;
    }

    private void InvalidateEndpoint()
    {
        lock (_endpointCacheLock)
        {
            _cachedEndpoint = null;
            _cachedEndpointExpiresAt = 0;
        }
        ClearResponseCache();
    }

    private bool TryGetCachedResponse(string key, out string response)
    {
        lock (_responseCacheLock)
        {
            if (_responseCache.TryGetValue(key, out var cached) &&
                Environment.TickCount64 < cached.ExpiresAt)
            {
                response = cached.Response;
                return true;
            }

            _responseCache.Remove(key);
        }

        response = "";
        return false;
    }

    private void StoreCachedResponse(string key, string response, long cacheGeneration, bool durable)
    {
        if (response.Length > MaxCachedResponseChars)
            return;

        lock (_responseCacheLock)
        {
            if (cacheGeneration != _responseCacheGeneration)
                return;

            if (_responseCache.Count >= MaxCachedResponses && !_responseCache.ContainsKey(key))
            {
                var oldest = _responseCache
                    .OrderBy(pair => pair.Value.ExpiresAt)
                    .FirstOrDefault();
                if (!string.IsNullOrEmpty(oldest.Key))
                    _responseCache.Remove(oldest.Key);
            }

            _responseCache[key] = new CachedResponse(
                response,
                Environment.TickCount64 + (durable ? StaticResponseCacheMilliseconds : ResponseCacheMilliseconds));
        }
    }

    /// <summary>
    /// What a Ghidra method costs and how long its answer stays true. One
    /// table replaces the three parallel hardcoded lists (allow-list,
    /// cacheable, durable) that had to be edited together: a new method is
    /// registered once and inherits cache and invalidation behavior instead of
    /// drifting out of sync.
    /// </summary>
    private enum GhidraMethod
    {
        /// <summary>Pure static read: durable cache until a mutation clears it.</summary>
        Read,
        /// <summary>Reports volatile state: allowlisted, but only a 1.5s cache.</summary>
        Status,
        /// <summary>Mutates the program: never cached, always clears the cache.</summary>
        Mutation,
    }

    private static readonly IReadOnlyDictionary<string, GhidraMethod> GhidraMethods =
        new Dictionary<string, GhidraMethod>(StringComparer.Ordinal)
        {
            ["status"] = GhidraMethod.Status,
            ["InspectFunction"] = GhidraMethod.Read,
            ["AnalyzeFunctions"] = GhidraMethod.Read,
            ["DecompileModule"] = GhidraMethod.Read,
            ["GetAnalysisQueue"] = GhidraMethod.Read,
            ["CallGraph"] = GhidraMethod.Read,
            ["DumpStrings"] = GhidraMethod.Read,
            ["ReadStaticBytes"] = GhidraMethod.Read,
            ["XrefsTo"] = GhidraMethod.Read,
            ["XrefsFrom"] = GhidraMethod.Read,
            ["XrefsBoth"] = GhidraMethod.Read,
            ["ListImports"] = GhidraMethod.Read,
            ["ListExports"] = GhidraMethod.Read,
            ["ListSymbolsBoth"] = GhidraMethod.Read,
            ["ListFunctions"] = GhidraMethod.Read,
            ["ListSections"] = GhidraMethod.Read,
            ["RenameFunction"] = GhidraMethod.Mutation,
            ["SetFunctionComment"] = GhidraMethod.Mutation,
            ["RenameVariable"] = GhidraMethod.Mutation,
            ["SetVariableType"] = GhidraMethod.Mutation,
            ["BatchAnnotate"] = GhidraMethod.Mutation,
            ["SubmitAnnotations"] = GhidraMethod.Mutation,
            ["CreateFunction"] = GhidraMethod.Mutation,
            ["SaveProgram"] = GhidraMethod.Mutation,
        };

    private string ResolveEndpointDirectoryKey()
    {
        if (_endpointDirectory is not null)
            return "dir:" + _endpointDirectory;
        var explicitPath = Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_ENDPOINT");
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return "file:" + explicitPath;
        var directory = Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_ENDPOINT_DIR");
        directory = string.IsNullOrWhiteSpace(directory)
            ? Path.Combine(Path.GetTempPath(), "DbgLink")
            : directory;
        return "dir:" + directory;
    }

    private void InvalidateOnDirectoryChange()
    {
        var current = ResolveEndpointDirectoryKey();
        lock (_responseCacheLock)
        {
            if (_lastEndpointDirectoryKey is null)
            {
                _lastEndpointDirectoryKey = current;
                return;
            }
            if (!string.Equals(_lastEndpointDirectoryKey, current, StringComparison.Ordinal))
            {
                _lastEndpointDirectoryKey = current;
                _lastEndpoint = null;
                lock (_endpointCacheLock)
                {
                    _cachedEndpoint = null;
                    _cachedEndpointExpiresAt = 0;
                }
                Interlocked.Increment(ref _responseCacheGeneration);
                _responseCache.Clear();
            }
        }
    }

    private void InvalidateOnEndpointChange(EndpointInfo? endpoint)
    {
        if (endpoint is null)
            return;
        lock (_responseCacheLock)
        {
            if (!Equals(_lastEndpoint, endpoint))
            {
                _lastEndpoint = endpoint;
                Interlocked.Increment(ref _responseCacheGeneration);
                _responseCache.Clear();
            }
        }
    }

    private void ClearResponseCache()
    {
        Interlocked.Increment(ref _responseCacheGeneration);
        lock (_responseCacheLock)
            _responseCache.Clear();
    }

    private static EndpointInfo? ReadEndpoint(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!Path.IsPathFullyQualified(path) || !LocalPathPolicy.IsSafeLocalPath(path) ||
                !info.Exists || info.Attributes.HasFlag(FileAttributes.Directory) ||
                info.Length <= 0 || info.Length > MaxEndpointBytes)
                return null;
            // The endpoint file carries the bridge token: reject files not
            // owned by the current user so a planted endpoint in a shared
            // directory cannot redirect queries to an attacker listener.
            if (!IsOwnedByCurrentUser(path))
                return null;

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.SequentialScan);
            var endpointBytes = new byte[MaxEndpointBytes];
            var endpointLength = 0;
            while (endpointLength < endpointBytes.Length)
            {
                var read = stream.Read(endpointBytes.AsSpan(endpointLength));
                if (read == 0)
                    break;
                endpointLength += read;
            }
            if (endpointLength == 0 ||
                (endpointLength == endpointBytes.Length && stream.ReadByte() != -1))
                return null;

            using var document = JsonDocument.Parse(
                endpointBytes.AsMemory(0, endpointLength),
                new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || JsonProtocolValidation.HasDuplicateProperties(root))
                return null;
            var host = root.TryGetProperty("host", out var hostElement) &&
                hostElement.ValueKind == JsonValueKind.String
                ? hostElement.GetString()
                : null;
            var port = root.TryGetProperty("port", out var portElement) &&
                portElement.ValueKind == JsonValueKind.Number &&
                portElement.TryGetInt32(out var parsedPort)
                ? parsedPort
                : -1;
            var token = root.TryGetProperty("token", out var tokenElement) &&
                tokenElement.ValueKind == JsonValueKind.String
                ? tokenElement.GetString()
                : null;
            var protocol = root.TryGetProperty("protocolVersion", out var protocolElement) &&
                protocolElement.ValueKind == JsonValueKind.Number &&
                protocolElement.TryGetInt32(out var parsedProtocol)
                ? parsedProtocol
                : -1;

            if (!string.Equals(host, "127.0.0.1", StringComparison.Ordinal) ||
                port is < 1 or > 65_535 ||
                protocol != 1 ||
                string.IsNullOrWhiteSpace(token) ||
                token.Length > MaxTokenChars ||
                token.Length < 16 ||
                token.Any(char.IsControl))
            {
                return null;
            }
            return new EndpointInfo(port, token);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private static bool IsOwnedByCurrentUser(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                return EndpointOwnership.IsOwnedByCurrentUser(owner);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException or InvalidOperationException or PlatformNotSupportedException)
            {
                return false;
            }
        }
        // Unix: file uid must equal euid, symlinks rejected outright.
        // Fail closed on any error or unknown platform.
        try
        {
            try
            {
                if (new FileInfo(path).LinkTarget is not null)
                    return false;
            }
            catch
            {
                return false;
            }
            uint euid;
            try
            {
                euid = GetEUid();
            }
            catch
            {
                return false;
            }
            uint ownerUid;
            if (OperatingSystem.IsLinux())
            {
                if (!TryGetStatOwner(path, isMacOS: false, out ownerUid))
                    return false;
            }
            else if (OperatingSystem.IsMacOS())
            {
                if (!TryGetStatOwner(path, isMacOS: true, out ownerUid))
                    return false;
            }
            else
            {
                return false;
            }
            return ownerUid == euid;
        }
        catch
        {
            return false;
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEUid();

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "stat", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Ansi, BestFitMapping = false)]
    private static extern int StatLibc(string pathname, IntPtr buf);

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "stat$INODE64", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Ansi, BestFitMapping = false)]
    private static extern int StatLibcMacOS(string pathname, IntPtr buf);

    private static bool TryGetStatOwner(string path, bool isMacOS, out uint ownerUid)
    {
        ownerUid = 0;
        IntPtr buf = IntPtr.Zero;
        try
        {
            buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(512);
            for (var i = 0; i < 512; i++)
                System.Runtime.InteropServices.Marshal.WriteByte(buf, i, 0);
            int result;
            try
            {
                result = isMacOS ? StatLibcMacOS(path, buf) : StatLibc(path, buf);
            }
            catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
            {
                // macOS stat versioning: fall back to the plain symbol and back.
                try
                {
                    result = isMacOS ? StatLibc(path, buf) : StatLibcMacOS(path, buf);
                }
                catch
                {
                    return false;
                }
            }
            if (result != 0)
                return false;
            // Linux x64 glibc: st_uid at offset 28 (dev8+ino8+nlink8+mode4).
            // macOS (x64/arm64, INODE64): st_uid at offset 16
            // (dev4+mode2+nlink2+ino8). Fail closed on short reads.
            var offset = isMacOS ? 16 : 28;
            ownerUid = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(buf, offset);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (buf != IntPtr.Zero)
                System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
        }
    }

    private sealed record EndpointInfo(int Port, string Token);
    private sealed record CachedResponse(string Response, long ExpiresAt);

    private int _disposed;

    public void Dispose()
    {
        // The semaphores are deliberately NOT disposed: a request that is in
        // flight releases them in its finally block, and disposing them under
        // it would throw ObjectDisposedException out of that finally and
        // replace the real bridge result. New requests are refused instead.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        GC.SuppressFinalize(this);
    }
}
