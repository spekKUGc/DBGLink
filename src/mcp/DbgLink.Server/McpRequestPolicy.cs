using System.Buffers;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol;

namespace DbgLink.Server;

internal sealed class McpRequestPolicy(RequestDelegate next, ServerConfig config, ServerMetrics metrics)
{
    private readonly SemaphoreSlim _requests = new(Math.Clamp(
        config.MaxConcurrentRequests + config.MaxQueuedOperations + 16, 16, 512));

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_requests.Wait(0))
        {
            metrics.RecordHttpStatus(503);
            context.Response.StatusCode = 503;
            return;
        }
        metrics.HttpEnter();
        var original = context.Response.Body;
        using var counted = new CountingResponseStream(original, metrics);
        context.Response.Body = counted;
        try { await HandleAsync(context); }
        finally
        {
            context.Response.Body = original;
            _requests.Release();
            metrics.HttpExit();
            try
            {
                if (context.Response.StatusCode is >= 200 and <= 599)
                    metrics.RecordHttpStatus(context.Response.StatusCode);
            }
            catch { }
        }
    }

    private async Task HandleAsync(HttpContext context)
    {
        // Defense in depth: the Host header is client-controlled, so a
        // non-loopback transport peer is rejected even if Host claims
        // loopback. A null RemoteIpAddress (e.g. in-process test hosts)
        // falls back to the Host-header check below.
        var remote = context.Connection.RemoteIpAddress;
        if (remote is not null && !IPAddress.IsLoopback(remote))
        {
            metrics.RecordOriginRejected();
            context.Response.StatusCode = 403;
            return;
        }
        var origin = context.Request.Headers.Origin.ToString();
        if (!OriginAllowed(origin, config.Port) ||
            context.Request.Host.Host is not ("127.0.0.1" or "localhost"))
        {
            metrics.RecordOriginRejected();
            context.Response.StatusCode = 403;
            return;
        }
        metrics.RecordHttpRequest();
        // Bearer-token gate: /metrics always requires the configured token
        // (it exposes session/process details), and /mcp does when
        // RequireAuthToken is set (enabled by default;
        // DBGLINK_REQUIRE_AUTH=0 disables). Loopback binding alone does not
        // stop other local users or hostile browser pages from reaching the port.
        var path = context.Request.Path;
        // Segment-boundary prefix match, not an exact comparison: ASP.NET
        // endpoint routing treats "/metrics" and "/metrics/" as the same
        // endpoint, so an exact PathString comparison left "/metrics/" outside
        // the token gate and served the unauthenticated metrics snapshot.
        var isMcpPath = path.StartsWithSegments(new PathString("/mcp"));
        var isMetricsPath = path.StartsWithSegments(new PathString("/metrics"));
        if (isMetricsPath || (isMcpPath && config.RequireAuthToken))
        {
            if (!HasValidBearerToken(context.Request, config.AuthToken))
            {
                metrics.RecordAuthFailure();
                context.Response.StatusCode = 401;
                context.Response.Headers.WWWAuthenticate = "Bearer";
                return;
            }
        }
        // This host is stateless. Older clients may retain a session header
        // across launcher restarts; the SDK otherwise rejects it with HTTP 400.
        // Analysis selection uses the tool's analysisId, never this header.
        if (isMcpPath)
            context.Request.Headers.Remove("Mcp-Session-Id");
        if (HttpMethods.IsPost(context.Request.Method))
        {
            if (context.Request.ContentLength > config.MaxRequestBodyBytes)
            {
                await WriteJsonRpcErrorAsync(context, 413, (int)McpErrorCode.InvalidRequest,
                    "Request entity too large.", "null").ConfigureAwait(false);
                return;
            }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            deadline.CancelAfter(Math.Clamp(config.DefaultToolTimeoutMs, 1_000, 120_000));
            using var body = new MemoryStream(Math.Min(config.MaxRequestBodyBytes, 16 * 1024));
            var buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int read;
                while ((read = await context.Request.Body.ReadAsync(buffer, deadline.Token)) != 0)
                {
                    if (body.Length + read > config.MaxRequestBodyBytes)
                    {
                        await WriteJsonRpcErrorAsync(context, 413, (int)McpErrorCode.InvalidRequest,
                            "Request entity too large.", "null").ConfigureAwait(false);
                        return;
                    }
                    body.Write(buffer, 0, read);
                }

                body.Position = 0;
                using var json = await JsonDocument.ParseAsync(body, new JsonDocumentOptions { MaxDepth = 16 }, deadline.Token);
                var idRaw = GetRequestIdRaw(json.RootElement);
                // Lone-surrogate / incomplete-UTF-16 strings parse as JSON but
                // throw InvalidOperationException on decode. The MCP SDK then
                // fails the request inside its handler as an opaque -32603
                // ("An error occurred."). Fail fast here as -32602 with a
                // useful, non-leaking message instead.
                if (!TryValidateJsonStrings(json.RootElement))
                {
                    SafeRecordMcpRequest(json.RootElement, body.Length);
                    await WriteJsonRpcErrorAsync(context, 400, (int)McpErrorCode.InvalidParams,
                        "Invalid params: the request contains malformed Unicode and could not be decoded.",
                        idRaw).ConfigureAwait(false);
                    return;
                }
                SafeRecordMcpRequest(json.RootElement, body.Length);
                bool hasDuplicates;
                try
                {
                    hasDuplicates = JsonProtocolValidation.HasDuplicateProperties(json.RootElement);
                }
                catch (Exception)
                {
                    // A surrogate property name (or any undecodable shape)
                    // is an input fault, not a 500: report -32602.
                    await WriteJsonRpcErrorAsync(context, 400, (int)McpErrorCode.InvalidParams,
                        "Invalid params: the request contains malformed Unicode and could not be decoded.",
                        idRaw).ConfigureAwait(false);
                    return;
                }
                if (hasDuplicates)
                {
                    await WriteJsonRpcErrorAsync(context, 400, (int)McpErrorCode.InvalidRequest,
                        "Invalid request: duplicate properties are not allowed.", idRaw).ConfigureAwait(false);
                    return;
                }
                // The MCP Streamable-HTTP transport requires application/json.
                // ASP.NET's ReadFromJsonAsync throws InvalidOperationException
                // for a missing/empty Content-Type, which Kestrel turns into
                // an empty-body HTTP 500. Validate here so every content-type
                // rejection is a clean 415 with a JSON-RPC error body.
                // Auth runs before this (above), so 401 keeps precedence.
                if (!IsJsonContentType(context.Request.ContentType))
                {
                    await WriteJsonRpcErrorAsync(context, 415, (int)McpErrorCode.InvalidRequest,
                        "Unsupported Media Type: POST /mcp requires Content-Type: application/json.",
                        idRaw).ConfigureAwait(false);
                    return;
                }
                // Envelope-shape faults (non-object params/arguments on
                // tools/call) would otherwise fall into the SDK as an opaque
                // -32603 ("An error occurred."). Map them here to -32602 with
                // a useful message. Content-Type (415) keeps precedence by
                // running first; auth already ran above. Transport stays
                // HTTP 200 like the dispatcher's own -32602 so clients see
                // only the code change, and the backend is never touched.
                var shapeError = ValidateToolsCallEnvelope(json.RootElement);
                if (shapeError is not null)
                {
                    await WriteJsonRpcErrorAsync(context, 200, (int)McpErrorCode.InvalidParams,
                        shapeError, idRaw).ConfigureAwait(false);
                    return;
                }
            }
            catch (JsonException)
            {
                await WriteJsonRpcErrorAsync(context, 400, (int)McpErrorCode.ParseError,
                    "Parse error: the request body is not valid JSON.", "null").ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
            {
                await WriteJsonRpcErrorAsync(context, 408, (int)McpErrorCode.InvalidRequest,
                    "Request timeout.", "null").ConfigureAwait(false);
                return;
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
            body.Position = 0;
            var original = context.Request.Body;
            context.Request.Body = body;
            try { await next(context); }
            finally { context.Request.Body = original; }
            return;
        }
        await next(context);
    }

    /// <summary>MCP Streamable HTTP requires <c>application/json</c>.
    /// Missing, empty, or any other media type is rejected with 415 before
    /// the SDK's ReadFromJsonAsync can throw it into an empty-body 500.
    /// Parameters (e.g. <c>; charset=utf-8</c>) are ignored; matching is
    /// case-insensitive.</summary>
    internal static bool IsJsonContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            return false;
        var media = contentType;
        var semi = media.IndexOf(';');
        if (semi >= 0)
            media = media[..semi];
        return media.Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Best-effort <c>tools/call</c> accounting that never throws:
    /// a <c>method</c> carrying malformed Unicode would otherwise throw on
    /// GetString and turn the request into a 500.</summary>
    private void SafeRecordMcpRequest(JsonElement root, long bodyBytes)
    {
        try
        {
            string? method = null;
            try
            {
                if (root.ValueKind == JsonValueKind.Object &&
                    root.TryGetProperty("method", out var value) &&
                    value.ValueKind == JsonValueKind.String)
                    method = value.GetString();
            }
            catch { method = null; }
            metrics.RecordMcpRequest(method, bodyBytes);
        }
        catch { }
    }

    /// <summary>Raw JSON text of the request <c>id</c> for error echoing
    /// (string/number/bool/null preserved, capped, never decoded so a
    /// surrogate id cannot throw). Falls back to <c>null</c>.</summary>
    private static string GetRequestIdRaw(JsonElement root)
    {
        try
        {
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("id", out var id))
            {
                var raw = id.GetRawText();
                if (!string.IsNullOrEmpty(raw) && raw.Length <= 256)
                    return raw;
            }
        }
        catch { }
        return "null";
    }

    /// <summary>Forces every string value and property name to decode so a
    /// lone surrogate (or any incomplete UTF-16) is caught here with a
    /// diagnosable -32602 instead of the SDK's opaque -32603. Bounded:
    /// the parsed document is already depth/size capped.</summary>
    private static bool TryValidateJsonStrings(JsonElement element)
    {
        try
        {
            return ValidateStringsRecursive(element);
        }
        catch (Exception)
        {
            // Any decode failure (surrogate, malformed UTF-16) is an input
            // fault: report -32602, never let it reach the SDK as -32603.
            return false;
        }
    }

    private static bool ValidateStringsRecursive(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    // Property-name access decodes and throws on surrogates.
                    _ = property.Name.Length;
                    if (!ValidateStringsRecursive(property.Value))
                        return false;
                }
                return true;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (!ValidateStringsRecursive(item))
                        return false;
                }
                return true;
            case JsonValueKind.String:
                _ = element.GetString();
                return true;
            default:
                return true;
        }
    }

    /// <summary>Shared with the dispatcher via
    /// <see cref="ToolSupport.SanitizeOneLine"/>: two copies of a
    /// security-relevant sanitizer would drift.</summary>
    private static string SanitizeErrorMessage(string message)
        => ToolSupport.SanitizeOneLine(message, "Invalid request.");

    private static async Task WriteJsonRpcErrorAsync(HttpContext context, int httpStatus, int rpcCode, string message, string idRaw)
    {
        // Serialize the body BEFORE touching the response: a lone-surrogate
        // id parses (GetRawText never decodes) but cannot re-serialize, and
        // the old code set StatusCode/ContentType first, then threw inside
        // ToJsonString -> declared-JSON empty body. Now every path below
        // yields a well-formed body (id falls back to null).
        string body;
        try
        {
            var safe = SanitizeErrorMessage(message);
            JsonNode? id;
            try
            {
                id = JsonNode.Parse(string.IsNullOrWhiteSpace(idRaw) ? "null" : idRaw);
                // Force serialization now so an undecodable id (lone
                // surrogate) falls back to null before headers are touched.
                _ = id?.ToJsonString();
            }
            catch { id = JsonNode.Parse("null"); }
            var payload = new JsonObject
            {
                ["jsonrpc"] = "2.0",
                ["id"] = id,
                ["error"] = new JsonObject
                {
                    ["code"] = rpcCode,
                    ["message"] = safe,
                },
            };
            try { body = payload.ToJsonString(); }
            catch
            {
                payload["id"] = JsonNode.Parse("null");
                try { body = payload.ToJsonString(); }
                catch { body = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":" + rpcCode.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",\"message\":\"Invalid request.\"}}"; }
            }
        }
        catch
        {
            body = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":" + rpcCode.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",\"message\":\"Invalid request.\"}}";
        }
        try
        {
            context.Response.StatusCode = httpStatus;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(body, context.RequestAborted).ConfigureAwait(false);
        }
        catch
        {
            // Headers may already be sent; still avoid a declared-JSON
            // empty body with a best-effort second write.
            try
            {
                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = httpStatus;
                    context.Response.ContentType = "application/json";
                }
                await context.Response.WriteAsync(body, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                try { context.Response.StatusCode = httpStatus; } catch { }
            }
        }
    }

    /// <summary>Maps <c>tools/call</c> envelope-shape faults to an
    /// InvalidParams (-32602) message. Returns null when the request is not
    /// a tools/call or the shape is one the dispatcher already reports as
    /// -32602 (missing/null arguments). Never throws: undecodable input
    /// returns null and lets the earlier -32602 path own it.</summary>
    internal static string? ValidateToolsCallEnvelope(JsonElement root)
    {
        try
        {
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            if (!root.TryGetProperty("method", out var methodElement) ||
                methodElement.ValueKind != JsonValueKind.String)
                return null;
            string? method;
            try { method = methodElement.GetString(); }
            catch { return null; }
            if (!string.Equals(method, "tools/call", StringComparison.Ordinal))
                return null;
            if (!root.TryGetProperty("params", out var paramsElement) ||
                paramsElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                return "Invalid params: tools/call params must be an object with 'name' and 'arguments'.";
            if (paramsElement.ValueKind != JsonValueKind.Object)
                return "Invalid params: tools/call params must be an object with 'name' and 'arguments'.";
            if (!paramsElement.TryGetProperty("name", out var nameElement) ||
                nameElement.ValueKind != JsonValueKind.String)
                return "Invalid params: tools/call params.name must be a non-empty string.";
            string? name;
            try { name = nameElement.GetString(); }
            catch { return "Invalid params: tools/call params.name must be a non-empty string."; }
            if (string.IsNullOrWhiteSpace(name))
                return "Invalid params: tools/call params.name must be a non-empty string.";
            // Missing/null arguments pass through: the dispatcher already
            // reports those as -32602 via schema validation. Only a present
            // non-object arguments (string/array/number/bool) would fall
            // into the SDK as opaque -32603, so map it here.
            if (paramsElement.TryGetProperty("arguments", out var argumentsElement))
            {
                if (argumentsElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                    return null;
                if (argumentsElement.ValueKind != JsonValueKind.Object)
                    return "Invalid params: tools/call arguments must be an object.";
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    internal static bool OriginAllowed(string? origin, int port)
    {
        if (string.IsNullOrWhiteSpace(origin)) return true;
        // Control characters (e.g. a header-smuggled trailing newline) never
        // appear in a legitimate serialized origin, and the Uri parser below
        // silently strips some of them, so reject up front.
        if (origin.Any(char.IsControl)) return false;
        if (origin.Contains("..", StringComparison.Ordinal) || origin.Contains('%')) return false;
        return origin.Length <= 256 && Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
            uri.Scheme == "http" && uri.Host is "127.0.0.1" or "localhost" && uri.Port == port &&
            uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0 && uri.UserInfo.Length == 0;
    }

    internal static bool HasValidBearerToken(HttpRequest request, string expectedToken)
    {
        if (!DbgLinkConfigPath.IsValidBearerToken(expectedToken))
            return false;
        var header = request.Headers.Authorization.ToString();
        const string scheme = "Bearer ";
        if (header.Length <= scheme.Length || !header.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            return false;
        // Compare in fixed time so the token cannot be probed byte by byte.
        // Surrounding whitespace (copied trailing newline/space) is trimmed:
        // the token alphabet is base64url, so this rejects nothing valid.
        var provided = System.Text.Encoding.UTF8.GetBytes(header[scheme.Length..].Trim());
        var expected = System.Text.Encoding.UTF8.GetBytes(expectedToken);
        return provided.Length == expected.Length &&
            System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(provided, expected);
    }
}
