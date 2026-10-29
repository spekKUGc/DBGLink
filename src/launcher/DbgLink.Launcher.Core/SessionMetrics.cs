using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

public sealed record SessionActivitySnapshot(
    string Tool,
    string Target,
    string Phase,
    string DataFlow,
    string State,
    double ElapsedMilliseconds)
{
    public long Sequence { get; init; }
    public long OperationId { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}

public sealed record SessionMetricsSnapshot(
    long HttpRequests,
    long RoundTrips,
    long ToolCalls,
    long BytesReceived,
    long BytesSent,
    double UptimeSeconds)
{
    public IReadOnlyList<SessionActivitySnapshot> ActiveOperations { get; init; } = Array.Empty<SessionActivitySnapshot>();
    public IReadOnlyList<SessionActivitySnapshot> ActivityHistory { get; init; } = Array.Empty<SessionActivitySnapshot>();
    public SessionActivitySnapshot? LastOperation { get; init; }

    public double ReceivedMegabytes => BytesReceived / (1024d * 1024d);
    public double SentMegabytes => BytesSent / (1024d * 1024d);
}

public sealed class SessionMetricsClient : IDisposable
{
    private const int MaxResponseBytes = 256 * 1024;
    private const int RequestTimeoutMilliseconds = 1_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly HttpClient _http;
    private readonly string _configPath;
    private readonly Uri _metricsUri;
    private long _activityCursor;

    public SessionMetricsClient(int port, string configPath)
    {
        if (port is < 1 or > 65_535)
            throw new ArgumentOutOfRangeException(nameof(port));
        if (string.IsNullOrWhiteSpace(configPath))
            throw new ArgumentException("A config path is required.", nameof(configPath));

        _configPath = Path.GetFullPath(configPath);
        _metricsUri = new Uri($"http://127.0.0.1:{port}/metrics", UriKind.Absolute);
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromMilliseconds(RequestTimeoutMilliseconds),
        };
    }

    public async Task<SessionMetricsSnapshot?> ReadAsync(CancellationToken cancellationToken)
    {
        var token = ReadToken();
        if (token is null)
            return null;

        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_metricsUri + $"?after={_activityCursor}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // ResponseHeadersRead completes before the content body is consumed;
        // keep the same deadline active for the bounded body read as well.
        timeout.CancelAfter(RequestTimeoutMilliseconds);
        try
        {
            using var response = await _http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
                return null;

            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
                return null;

            using var contentStream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            var bytes = await ReadBoundedBytesAsync(contentStream, MaxResponseBytes, timeout.Token).ConfigureAwait(false);
            if (bytes is null or { Length: 0 })
                return null;

            var json = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (!TryParse(document.RootElement, out var snapshot))
                return null;
            if (snapshot!.ActivityHistory.Count > 0)
                _activityCursor = snapshot.ActivityHistory[^1].Sequence;
            return snapshot;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (OperationCanceledException)
        {
            // HttpClient.Timeout uses its own cancellation source. Metrics are
            // best-effort, so an internal request timeout is also a cache miss.
            return null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (ObjectDisposedException)
        {
            // Stop/dispose may race with a best-effort metrics refresh.
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool TryParse(JsonElement root, out SessionMetricsSnapshot? snapshot)
    {
        snapshot = null;
        if (root.ValueKind != JsonValueKind.Object ||
            JsonProtocolValidation.HasDuplicateProperties(root) ||
            !root.TryGetProperty("schemaVersion", out var schema) ||
            schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var schemaVersion) || (schemaVersion != 2 && schemaVersion != 3) ||
            !ReadNonNegativeLong(root, "httpRequests", out var httpRequests) ||
            !ReadNonNegativeLong(root, "roundTrips", out var roundTrips) ||
            !ReadNonNegativeLong(root, "toolCalls", out var toolCalls) ||
            !ReadNonNegativeLong(root, "bytesReceived", out var bytesReceived) ||
            !ReadNonNegativeLong(root, "bytesSent", out var bytesSent) ||
            !root.TryGetProperty("uptimeSeconds", out var uptime) ||
            uptime.ValueKind != JsonValueKind.Number ||
            !uptime.TryGetDouble(out var uptimeSeconds) ||
            double.IsNaN(uptimeSeconds) || double.IsInfinity(uptimeSeconds) || uptimeSeconds < 0)
            return false;

        var activeOperations = Array.Empty<SessionActivitySnapshot>();
        if (root.TryGetProperty("activeOperations", out var active) &&
            !TryParseActivities(active, out activeOperations))
            return false;

        SessionActivitySnapshot? lastOperation = null;
        if (root.TryGetProperty("lastOperation", out var last) &&
            last.ValueKind is not JsonValueKind.Null &&
            !TryParseActivity(last, out lastOperation))
            return false;

        var history = Array.Empty<SessionActivitySnapshot>();
        if (root.TryGetProperty("activityHistory", out var historyJson))
        {
            if (!TryParseActivities(historyJson, out history))
                return false;
            long previous = 0;
            foreach (var item in history)
            {
                if (item.Sequence <= previous || item.OperationId <= 0 || item.Timestamp == default)
                    return false;
                previous = item.Sequence;
            }
        }

        snapshot = new SessionMetricsSnapshot(
            httpRequests,
            roundTrips,
            toolCalls,
            bytesReceived,
            bytesSent,
            uptimeSeconds)
        {
            ActiveOperations = activeOperations,
            LastOperation = lastOperation,
            ActivityHistory = history
        };
        return true;
    }

    public void Dispose()
    {
        _http.Dispose();
        GC.SuppressFinalize(this);
    }

    private string? ReadToken()
    {
        try
        {
            var environmentToken = Environment.GetEnvironmentVariable(
                DbgLinkConfigPath.BearerTokenEnvironmentVariable);
            if (DbgLinkConfigPath.IsValidBearerToken(environmentToken))
                return environmentToken;

            var fileInfo = new FileInfo(_configPath);
            if (!PathSafety.IsReparseFree(_configPath) || !fileInfo.Exists ||
                fileInfo.Attributes.HasFlag(FileAttributes.Directory) ||
                fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                fileInfo.Length is <= 0 or > MaxResponseBytes)
                return null;

            using var stream = SafeFileCopy.OpenNonReparseRead(_configPath);
            var bytes = ReadBoundedBytes(stream, MaxResponseBytes);
            if (bytes is null or { Length: 0 })
                return null;
            var json = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            return TryReadToken(document.RootElement);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonException)
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
        catch (InvalidDataException)
        {
            return null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    internal static byte[]? ReadBoundedBytes(Stream stream, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (maxBytes <= 0 || stream.Length < 0 || stream.Length > maxBytes)
            return null;

        using var data = new MemoryStream(capacity: checked((int)stream.Length));
        var buffer = new byte[Math.Min(4096, maxBytes)];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
                break;
            if (data.Length > maxBytes - read)
                return null;
            data.Write(buffer, 0, read);
        }

        return data.ToArray();
    }

    internal static async Task<byte[]?> ReadBoundedBytesAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (maxBytes <= 0)
            return null;

        using var data = new MemoryStream(capacity: Math.Min(maxBytes, 4096));
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(maxBytes, 8192));
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return data.ToArray();
                if (data.Length > maxBytes - read)
                    return null;
                data.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    internal static string? TryReadToken(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            JsonProtocolValidation.HasDuplicateProperties(root) ||
            !root.TryGetProperty("AuthToken", out var token) ||
            token.ValueKind != JsonValueKind.String)
            return null;

        var value = token.GetString();
        return DbgLinkConfigPath.IsValidBearerToken(value) ? value : null;
    }

    private static bool ReadNonNegativeLong(JsonElement root, string propertyName, out long value)
    {
        value = 0;
        return root.TryGetProperty(propertyName, out var element) &&
            element.ValueKind == JsonValueKind.Number &&
            element.TryGetInt64(out value) && value >= 0;
    }

    private static bool TryParseActivities(JsonElement element, out SessionActivitySnapshot[] activities)
    {
        activities = Array.Empty<SessionActivitySnapshot>();
        if (element.ValueKind != JsonValueKind.Array || element.GetArrayLength() > 16)
            return false;

        var parsed = new List<SessionActivitySnapshot>(element.GetArrayLength());
        foreach (var item in element.EnumerateArray())
        {
            if (!TryParseActivity(item, out var activity) || activity is null)
                return false;
            parsed.Add(activity);
        }

        activities = parsed.ToArray();
        return true;
    }

    private static bool TryParseActivity(JsonElement element, out SessionActivitySnapshot? activity)
    {
        activity = null;
        if (element.ValueKind != JsonValueKind.Object ||
            !ReadBoundedString(element, "tool", 128, out var tool) ||
            !ReadBoundedString(element, "target", 128, out var target) ||
            !ReadBoundedString(element, "phase", 128, out var phase) ||
            !ReadBoundedString(element, "dataFlow", 256, out var dataFlow) ||
            !ReadBoundedString(element, "state", 32, out var state) ||
            state is not ("running" or "completed" or "failed") ||
            !element.TryGetProperty("elapsedMilliseconds", out var elapsed) ||
            elapsed.ValueKind != JsonValueKind.Number ||
            !elapsed.TryGetDouble(out var elapsedMilliseconds) ||
            double.IsNaN(elapsedMilliseconds) || double.IsInfinity(elapsedMilliseconds) ||
            elapsedMilliseconds < 0 || elapsedMilliseconds > 3_600_000)
            return false;

        activity = new SessionActivitySnapshot(tool, target, phase, dataFlow, state, elapsedMilliseconds);
        if (element.TryGetProperty("sequence", out _))
        {
            if (!ReadNonNegativeLong(element, "sequence", out var sequence) ||
                !ReadNonNegativeLong(element, "operationId", out var operationId) ||
                !element.TryGetProperty("timestamp", out var timestamp) ||
                timestamp.ValueKind != JsonValueKind.String || !timestamp.TryGetDateTimeOffset(out var time))
                return false;
            activity = activity with { Sequence = sequence, OperationId = operationId, Timestamp = time };
        }
        return true;
    }

    private static bool ReadBoundedString(JsonElement root, string name, int maxLength, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.String ||
            element.GetString() is not { } text ||
            text.Length > maxLength ||
            text.Any(char.IsControl))
            return false;
        value = text;
        return true;
    }
}
