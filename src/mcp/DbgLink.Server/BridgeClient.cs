using System.Buffers;
using System.Diagnostics;
using DbgLink.Shared;
using System.Text;
using System.Text.Json;

namespace DbgLink.Server;

internal interface IBridgeClient
{
    Task<bool> PingAsync(CancellationToken cancellationToken);
    Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken);
}

internal sealed class BridgeClient : IBridgeClient, IDisposable
{
    private const int MaxRequestBytes = 64 * 1024;
    private const int MaxResponseBytes = 256 * 1024;
    private const int ConnectTimeoutMilliseconds = 1_500;
    private const int DefaultResponseTimeoutMilliseconds = 120_000;
    // Control-plane ops (run/pause/step) must fail fast: hanging the full
    // bulk timeout would leave the target state unknown and burn the whole
    // MCP turn. State reads are small and polled in tight loops, so they get
    // an even shorter budget.
    private const int ControlResponseTimeoutMilliseconds = 30_000;
    private const int StateReadTimeoutMilliseconds = 15_000;
    private const int ReadRetryDelayMilliseconds = 100;

    private static readonly HashSet<string> FastControlMethods = new(StringComparer.Ordinal)
    {
        "RunDebugger", "PauseDebugger", "StepInto", "StepOver", "StepOut",
    };

    private static readonly HashSet<string> StateReadMethods = new(StringComparer.Ordinal)
    {
        "ping", "GetSnapshotState", "GetServerStatus",
    };

    // Methods safe to retry once on a transient transport failure: pure reads
    // with no debugger-state side effects. Mutations are never retried here;
    // a retried mutation could double-apply (e.g. two steps, two writes).
    private static readonly HashSet<string> IdempotentReadMethods = new(StringComparer.Ordinal)
    {
        "ping", "GetSnapshotState", "GetServerStatus", "GetCurrentContext",
        "GetCallStack", "GetAnalysisSnapshot", "GetModuleRecords",
        "EvaluateExpression", "ListBreakpoints", "ListThreads", "GetBacktrace",
        "GetMemoryMap", "GetModuleFunctions",
    };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const int MaxPipeTokenChars = 256;
    private readonly string _pipeName;
    private readonly string? _pipeToken;
    private readonly bool _requirePipeToken;
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly ArrayBufferWriter<byte> _requestBuffer = new(4 * 1024);
    private int _requestId;
    private string? _lastFailure;

    internal ServerMetrics? Telemetry { get; set; }

    public BridgeClient(string pipeName, string? pipeToken = null, bool requirePipeToken = false)
    {
        if (!IsValidPipeName(pipeName))
            throw new ArgumentException("The native bridge pipe name is invalid.", nameof(pipeName));
        if (pipeToken is not null && !IsValidPipeToken(pipeToken))
            throw new ArgumentException("The native bridge pipe token is invalid.", nameof(pipeToken));
        _pipeName = pipeName;
        _pipeToken = pipeToken;
        _requirePipeToken = requirePipeToken;
    }

    internal string? PipeToken => _pipeToken;

    internal bool RequiresPipeToken => _requirePipeToken;

    internal static bool IsValidPipeToken(string? pipeToken)
        => !string.IsNullOrWhiteSpace(pipeToken) &&
            pipeToken.Length <= MaxPipeTokenChars &&
            !pipeToken.Any(char.IsControl);

    public string? LastFailure => Volatile.Read(ref _lastFailure);

    public async Task<bool> PingAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await RequestAsync("ping", cancellationToken);
            var healthy = IsHealthyPingResponse(response);
            Volatile.Write(ref _lastFailure, healthy ? null : "The native bridge returned an invalid ping response.");
            return healthy;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _lastFailure, $"{exception.GetType().Name}: {exception.Message}");
            return false;
        }
    }

    internal static bool IsHealthyPingResponse(string response)
    {
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object &&
                !JsonProtocolValidation.HasDuplicateProperties(root) &&
                root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True &&
                root.TryGetProperty("plugin", out var plugin) &&
                plugin.ValueKind == JsonValueKind.String && plugin.GetString() == "DBGLink" &&
                root.TryGetProperty("bridge", out var bridge) &&
                bridge.ValueKind == JsonValueKind.String && bridge.GetString() == "native" &&
                root.TryGetProperty("pid", out var pid) &&
                pid.ValueKind == JsonValueKind.Number &&
                pid.TryGetInt32(out var processId) && processId > 0 &&
                root.TryGetProperty("debugging", out var debugging) &&
                debugging.ValueKind is JsonValueKind.True or JsonValueKind.False;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public async Task<string> RequestAsync(string method, CancellationToken cancellationToken)
    {
        return await RequestAsync(method, null, cancellationToken);
    }

    public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(method) || method.Length > 64 || method.Any(char.IsControl))
            throw new ArgumentException("The native bridge method is invalid.", nameof(method));
        if (arguments.HasValue && arguments.Value.ValueKind != JsonValueKind.Object)
            throw new ArgumentException("The native bridge arguments must be a JSON object.", nameof(arguments));
        if (_requirePipeToken && string.IsNullOrEmpty(_pipeToken))
            throw new InvalidOperationException(
                "The native bridge pipe token is required but was not provided. " +
                "Restart DbgLink.Server with --pipe-token <token> (the launcher passes it from the native rendezvous file).");

        var telemetry = Telemetry;
        var stopwatch = telemetry is null ? null : Stopwatch.StartNew();
        var timeoutMs = ResolveTimeoutMilliseconds(method);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        var lockAcquired = false;
        try
        {
            await _requestLock.WaitAsync(timeout.Token);
            lockAcquired = true;

            var id = NextRequestId();
            _requestBuffer.Clear();
            using (var writer = new Utf8JsonWriter(_requestBuffer))
            {
                writer.WriteStartObject();
                writer.WriteNumber("id", id);
                writer.WriteString("method", method);
                // N1 native pipe authentication: the token rides top-level on
                // every request when configured. Absent only on the explicit
                // legacy/test path (no token provided); exact-match
                // enforcement lives on the native side.
                if (_pipeToken is not null)
                    writer.WriteString("token", _pipeToken);
                if (arguments.HasValue)
                {
                    writer.WritePropertyName("params");
                    arguments.Value.WriteTo(writer);
                }
                writer.WriteEndObject();
            }

            if (_requestBuffer.WrittenCount + 1 > MaxRequestBytes)
                throw new InvalidDataException("DBGLink bridge request exceeded its byte limit.");
            _requestBuffer.GetSpan(1)[0] = (byte)'\n';
            _requestBuffer.Advance(1);
            var responseBytes = await RequestWithReadRetryAsync(method, timeoutMs, timeout.Token, cancellationToken).ConfigureAwait(false);
            var response = DecodeResponse(responseBytes);
            ValidateResponse(response, id);
            telemetry?.RecordBackendCall("native", method, TryParseOutcome(response, out var ok) ? ok : true, TryParseErrorCode(response), ElapsedMs(stopwatch));
            return response;
        }
        catch (Exception exception) when (telemetry is not null && exception is not ArgumentException)
        {
            telemetry.RecordBackendCall("native", method, false, ClassifyTransportError(exception, cancellationToken), ElapsedMs(stopwatch));
            throw;
        }
        finally
        {
            if (lockAcquired)
                _requestLock.Release();
        }
    }

    private static int ResolveTimeoutMilliseconds(string method)
    {
        if (FastControlMethods.Contains(method))
            return ControlResponseTimeoutMilliseconds;
        if (StateReadMethods.Contains(method))
            return StateReadTimeoutMilliseconds;
        return DefaultResponseTimeoutMilliseconds;
    }

    /// <summary>
    /// Monotonic request id that stays positive: <see cref="Interlocked.Increment"/>
    /// wraps to <see cref="int.MinValue"/> after ~2B calls, which would put a
    /// negative id on the wire. Wraps to 1 instead; the bridge only echoes it.
    /// </summary>
    private int NextRequestId()
    {
        while (true)
        {
            var current = Volatile.Read(ref _requestId);
            var next = current >= int.MaxValue - 1 ? 1 : current + 1;
            if (Interlocked.CompareExchange(ref _requestId, next, current) == current)
                return next;
        }
    }

    /// <summary>
    /// One retry for idempotent reads on transient transport failures
    /// (<see cref="IOException"/> / <see cref="TimeoutException"/>): the native
    /// pipe can drop a first connect under debugger load. Mutations and
    /// caller-cancellation are never retried.
    /// </summary>
    private async Task<byte[]> RequestWithReadRetryAsync(
        string method, int timeoutMs, CancellationToken timeoutToken, CancellationToken callerToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await DbgLinkNativePipe.RequestAsync(
                    _pipeName,
                    _requestBuffer.WrittenMemory,
                    ConnectTimeoutMilliseconds,
                    TimeSpan.FromMilliseconds(timeoutMs),
                    MaxResponseBytes,
                    timeoutToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (attempt == 0 &&
                !callerToken.IsCancellationRequested &&
                !timeoutToken.IsCancellationRequested &&
                IdempotentReadMethods.Contains(method) &&
                exception is IOException or TimeoutException)
            {
                try
                {
                    await Task.Delay(ReadRetryDelayMilliseconds, callerToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
            }
        }
    }

    private static long ElapsedMs(Stopwatch? stopwatch) => stopwatch is null ? 0 : (long)Math.Round(stopwatch.Elapsed.TotalMilliseconds);

    private static string ClassifyTransportError(Exception exception, CancellationToken callerToken)
        => exception switch
        {
            OperationCanceledException when !callerToken.IsCancellationRequested => "timeout",
            OperationCanceledException => "cancelled",
            InvalidDataException when exception.Message.Contains("byte limit", StringComparison.OrdinalIgnoreCase) => "request_too_large",
            InvalidDataException => "protocol_error",
            TimeoutException => "timeout",
            IOException => "transport_error",
            _ => "transport_error",
        };

    internal static bool TryParseOutcome(string response, out bool ok)
    {
        ok = false;
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("ok", out var okElement))
                return false;
            if (okElement.ValueKind == JsonValueKind.True) { ok = true; return true; }
            if (okElement.ValueKind == JsonValueKind.False) { ok = false; return true; }
            return false;
        }
        catch (JsonException) { return false; }
    }

    internal static string? TryParseErrorCode(string response)
    {
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
                return code.GetString();
            return null;
        }
        catch (JsonException) { return null; }
    }

    private static bool IsValidPipeName(string? pipeName)
        => NativePipeNamePolicy.IsValid(pipeName);

    private static string DecodeResponse(byte[] responseBytes)
    {
        var newline = Array.IndexOf(responseBytes, (byte)'\n');
        if (newline < 0 || newline + 1 != responseBytes.Length)
            throw new InvalidDataException("DBGLink bridge returned a response that was not one complete JSON line.");

        try
        {
            return StrictUtf8.GetString(responseBytes, 0, newline).TrimEnd('\r');
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("DBGLink bridge returned invalid UTF-8.", exception);
        }
    }

    internal static void ValidateResponse(string response, int expectedId)
    {
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("id", out var id) ||
                id.ValueKind != JsonValueKind.Number ||
                !id.TryGetInt32(out var responseId) ||
                responseId != expectedId ||
                !root.TryGetProperty("ok", out var ok) ||
                ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw new InvalidDataException("DBGLink bridge returned an invalid response envelope.");
            }

            if (ok.ValueKind == JsonValueKind.False &&
                (!root.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object))
                throw new InvalidDataException("DBGLink bridge returned an error without object details.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("DBGLink bridge returned invalid JSON.", exception);
        }
    }

    public void Dispose()
    {
        _requestLock.Dispose();
        GC.SuppressFinalize(this);
    }
}
