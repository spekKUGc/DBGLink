using DbgLink.Shared;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Exposes one bounded, launcher-owned control operation through a random per-session pipe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GhidraControlPipeServer : IAsyncDisposable
{
    private const int MaxRequestBytes = 64 * 1024;
    private const int MaxResponseBytes = 16 * 1024;
    private const int MaxTokenChars = 256;
    // Match the full analysis budget plus the no-analysis fallback and bridge
    // startup, so a legitimate fallback is not cut off by the control pipe.
    private static readonly int RequestTimeoutMilliseconds =
        (int)GhidraSession.ResolveImportTimeout().TotalMilliseconds + 120_000;
    private const int RequestReadTimeoutMilliseconds = 2_000;
    private const int ResponseWriteTimeoutMilliseconds = 2_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] NewLine = [(byte)'\n'];
    private readonly string _pipeName;
    private readonly string _token;
    private readonly byte[] _tokenBytes;
    private readonly Func<string, CancellationToken, Task<GhidraOpenResult>> _openHandler;
    private readonly TimeSpan _requestTimeout;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _pipeLock = new();
    private NamedPipeServerStream? _activePipe;
    private Task? _acceptTask;
    private int _disposed;

    public GhidraControlPipeServer(
        string pipeName,
        string token,
        Func<string, CancellationToken, Task<GhidraOpenResult>> openHandler)
        : this(
            pipeName,
            token,
            openHandler,
            TimeSpan.FromMilliseconds(RequestTimeoutMilliseconds))
    {
    }

    internal GhidraControlPipeServer(
        string pipeName,
        string token,
        Func<string, CancellationToken, Task<GhidraOpenResult>> openHandler,
        TimeSpan requestTimeout)
    {
        if (string.IsNullOrWhiteSpace(pipeName) ||
            !pipeName.StartsWith("DbgLink.GhidraControl.", StringComparison.Ordinal) ||
            pipeName.Length == "DbgLink.GhidraControl.".Length ||
            pipeName.Length > 200 ||
            pipeName.Any(char.IsControl))
        {
            throw new ArgumentException("The Ghidra control pipe name is invalid.", nameof(pipeName));
        }
        if (string.IsNullOrWhiteSpace(token) || token.Length is < 32 or > MaxTokenChars || token.Any(char.IsControl))
            throw new ArgumentException("The Ghidra control token is invalid.", nameof(token));
        if (requestTimeout <= TimeSpan.Zero || requestTimeout > TimeSpan.FromMilliseconds(RequestTimeoutMilliseconds))
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));

        _pipeName = pipeName;
        _token = token;
        _tokenBytes = Encoding.UTF8.GetBytes(token);
        _openHandler = openHandler ?? throw new ArgumentNullException(nameof(openHandler));
        _requestTimeout = requestTimeout;
    }

    internal Func<string, bool, CancellationToken, Task<GhidraOpenResult>>? OpenWithAnalysisMode { get; init; }
    internal Func<string, JsonElement, CancellationToken, Task<JsonObject>>? SessionControl { get; init; }

    public string PipeName => _pipeName;

    public void Start()
    {
        lock (_pipeLock)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_acceptTask is not null)
                throw new InvalidOperationException("The Ghidra control pipe is already running.");

            var acceptTask = AcceptLoopAsync();
            _acceptTask = acceptTask;
            if (acceptTask.IsFaulted)
            {
                _acceptTask = null;
                ExceptionDispatchInfo.Capture(
                    acceptTask.Exception?.GetBaseException() ??
                    new InvalidOperationException("The Ghidra control pipe could not start.")).Throw();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        _stop.Cancel();
        lock (_pipeLock)
            _activePipe?.Dispose();

        if (_acceptTask is not null)
        {
            try { await _acceptTask.ConfigureAwait(false); }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
            catch (IOException) when (_stop.IsCancellationRequested) { }
        }

        _stop.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task AcceptLoopAsync()
    {
        var firstAttempt = true;
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                    4096,
                    4096);
                // Once the pipe instance has been created, the server has
                // successfully started. Errors from this connection (for
                // example, a client disconnect during I/O) must not be
                // reported as a fatal first-start failure.
                firstAttempt = false;
                lock (_pipeLock)
                    _activePipe = pipe;

                await pipe.WaitForConnectionAsync(_stop.Token).ConfigureAwait(false);
                await HandleConnectionAsync(pipe, _stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (OperationCanceledException)
            {
                if (firstAttempt)
                    throw;
                await DelayAfterAcceptFailureAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
            catch (IOException)
            {
                if (firstAttempt)
                    throw;
                await DelayAfterAcceptFailureAsync().ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                if (firstAttempt)
                    throw;
                await DelayAfterAcceptFailureAsync().ConfigureAwait(false);
            }
            catch (Exception) when (!_stop.IsCancellationRequested)
            {
                if (firstAttempt)
                    throw;
                await DelayAfterAcceptFailureAsync().ConfigureAwait(false);
            }
            finally
            {
                lock (_pipeLock)
                    _activePipe = null;
            }
        }
    }

    private async Task DelayAfterAcceptFailureAsync()
    {
        if (_stop.IsCancellationRequested)
            return;

        try { await Task.Delay(100, _stop.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private async Task HandleConnectionAsync(Stream pipe, CancellationToken cancellationToken)
    {
        string? line;
        var requestTimedOut = false;
        using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            readTimeout.CancelAfter(RequestReadTimeoutMilliseconds);
            try
            {
                line = await ReadBoundedLineAsync(pipe, readTimeout.Token).ConfigureAwait(false);
            }
            catch (DecoderFallbackException)
            {
                line = null;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException) when (readTimeout.IsCancellationRequested)
            {
                line = null;
                requestTimedOut = true;
            }
        }

        using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        requestTimeout.CancelAfter(_requestTimeout);
        using var monitorStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var disconnect = MonitorDisconnectAsync(pipe, requestTimeout, monitorStop.Token);
        var response = requestTimedOut
            ? BridgeEnvelope.BoundedError(0, "request_timeout", "The Ghidra control request exceeded its bounded timeout.")
            : await DispatchAsync(line, requestTimeout.Token).ConfigureAwait(false);
        monitorStop.Cancel();
        await disconnect.ConfigureAwait(false);
        var bytes = StrictUtf8.GetBytes(response + "\n");
        if (bytes.Length > MaxResponseBytes)
            bytes = StrictUtf8.GetBytes(BridgeEnvelope.BoundedError(0, "response_too_large", "The Ghidra control response exceeded its limit.") + "\n");

        // The request token may already be cancelled when the handler timed out. Use a
        // fresh, short write budget so the peer can still receive the bounded error
        // response without allowing a stalled pipe to hold the accept loop forever.
        using var responseTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        responseTimeout.CancelAfter(ResponseWriteTimeoutMilliseconds);
        await pipe.WriteAsync(bytes, responseTimeout.Token).ConfigureAwait(false);
        await pipe.FlushAsync(responseTimeout.Token).ConfigureAwait(false);
    }

    private static async Task MonitorDisconnectAsync(Stream pipe, CancellationTokenSource request, CancellationToken token)
    {
        try
        {
            // This protocol accepts one request per connection. EOF (or extra input)
            // means the caller abandoned the import; propagate it to headless cleanup.
            await pipe.ReadAsync(new byte[1], token).ConfigureAwait(false);
            request.Cancel();
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (IOException) { request.Cancel(); }
    }

    internal async Task<string> DispatchAsync(string? line, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(line))
            return BridgeEnvelope.BoundedError(0, "invalid_request", "The Ghidra control request was empty.");

        try
        {
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return BridgeEnvelope.BoundedError(0, "invalid_request", "The Ghidra control request must be an object.");
            if (JsonProtocolValidation.HasDuplicateProperties(root))
                return BridgeEnvelope.BoundedError(0, "invalid_request", "The Ghidra control request must not contain duplicate properties.");

            if (!root.TryGetProperty("id", out var idElement) ||
                idElement.ValueKind != JsonValueKind.Number ||
                !idElement.TryGetInt32(out var id))
                return BridgeEnvelope.BoundedError(0, "invalid_request", "The Ghidra control request must contain an integer id.");

            if (!root.TryGetProperty("method", out var method) ||
                method.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("token", out var token) ||
                token.ValueKind != JsonValueKind.String ||
                !ConstantTimeTokenEquals(token.GetString()))
            {
                return BridgeEnvelope.BoundedError(id, "invalid_request", "An authenticated launcher operation is required.");
            }

            try
            {
                if (method.GetString() is "ListAnalysisSessions" or "SwitchDebugger" or "CloseAnalysisSession" or "ReopenAnalysisSession")
                {
                    if (SessionControl is null)
                        return BridgeEnvelope.BoundedError(id, "session_control_unavailable", "Session control is unavailable in this launcher.");
                    var response = await SessionControl(method.GetString()!, root, cancellationToken).ConfigureAwait(false);
                    response["id"] = id;
                    return response.ToJsonString();
                }
                if (method.GetString() != "OpenGhidraFile" ||
                    !root.TryGetProperty("path", out var path) || path.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(path.GetString()))
                    return BridgeEnvelope.BoundedError(id, "invalid_request", "Only OpenGhidraFile with a path or a supported session operation is allowed.");
                var analyze = true;
                if (root.TryGetProperty("analyze", out var mode))
                {
                    if (mode.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        return BridgeEnvelope.BoundedError(id, "invalid_request", "analyze must be a boolean.");
                    analyze = mode.GetBoolean();
                }
                if (!analyze && OpenWithAnalysisMode is null)
                    return BridgeEnvelope.BoundedError(id, "unsupported_import_mode", "Fast import is unavailable.");
                var result = OpenWithAnalysisMode is null
                    ? await _openHandler(path.GetString()!, cancellationToken).ConfigureAwait(false)
                    : await OpenWithAnalysisMode(path.GetString()!, analyze, cancellationToken).ConfigureAwait(false);
                return BridgeEnvelope.Success(new JsonObject
                {
                    ["opened"] = result.Opened,
                    ["fileName"] = result.FileName,
                    ["staticReady"] = result.StaticReady,
                    ["analysisId"] = result.AnalysisId,
                    ["nativePipeName"] = result.NativePipeName,
                    ["nativePipeToken"] = result.NativePipeToken,
                    ["ghidraEndpointDirectory"] = result.GhidraEndpointDirectory,
                    ["program"] = ProgramSummaryJson(result.Program)
                }, id);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return BridgeEnvelope.BoundedError(id, "operation_cancelled", "Opening the Ghidra program was cancelled.");
            }
            catch (FileNotFoundException)
            {
                return BridgeEnvelope.BoundedError(id, "target_not_found", "The requested Ghidra target file was not found.");
            }
            catch (InvalidDataException)
            {
                return BridgeEnvelope.BoundedError(id, "target_rejected", "The selected Ghidra target was rejected by the bounded policy.");
            }
            catch (TimeoutException)
            {
                return BridgeEnvelope.BoundedError(id, "ghidra_timeout", "Ghidra did not become ready before the bounded timeout.");
            }
            catch (Exception exception) when (
                exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // A full session table throws pre-spawn from OpenGhidraFileAsync;
                // surface its capacity code instead of the generic open failure
                // so callers close a slot instead of retrying blindly.
                if (exception is InvalidOperationException && IsSessionCapacity(exception.Message))
                    return BridgeEnvelope.BoundedError(id, "session_capacity_reached",
                        "The maximum number of parallel analysis sessions has been reached. Close an unused session with CloseAnalysisSession, then retry.");
                return BridgeEnvelope.BoundedError(id, "ghidra_open_failed", "The launcher could not open the selected Ghidra target.");
            }
            catch (UnauthorizedAccessException)
            {
                return BridgeEnvelope.BoundedError(id, "ghidra_open_failed", "The launcher could not access the selected Ghidra target.");
            }
            catch (ArgumentException)
            {
                return BridgeEnvelope.BoundedError(id, "target_rejected", "The selected Ghidra target path is invalid.");
            }
            catch (NotSupportedException)
            {
                return BridgeEnvelope.BoundedError(id, "target_rejected", "The selected Ghidra target path is not supported.");
            }
            catch (Exception)
            {
                return BridgeEnvelope.BoundedError(id, "ghidra_open_failed", "The launcher could not complete the selected Ghidra operation.");
            }
        }
        catch (JsonException)
        {
            return BridgeEnvelope.BoundedError(0, "invalid_json", "The Ghidra control request was not valid JSON.");
        }
        catch (InvalidOperationException)
        {
            return BridgeEnvelope.BoundedError(0, "invalid_request", "The Ghidra control request was malformed.");
        }
    }

    internal static Task<string?> ReadBoundedLineAsync(Stream stream, CancellationToken cancellationToken)
        => BoundedLineReader.ReadAsync(stream, MaxRequestBytes, rejectEmptyLine: true, cancellationToken);

    /// <summary>
    /// Capacity-throw detector for the pre-spawn session-table check in
    /// OpenGhidraFileAsync. String-matched because the throw crosses as an
    /// InvalidOperationException; the phrase is the launcher's own message.
    /// </summary>
    internal static bool IsSessionCapacity(string? message)
        => message is not null &&
            message.Contains("maximum number of parallel analysis sessions", StringComparison.OrdinalIgnoreCase);

    private static JsonNode? ProgramSummaryJson(GhidraProgramSummary? program)
        => program is null
            ? null
            : new JsonObject
            {
                ["fileName"] = program.FileName,
                ["format"] = program.Format,
                ["architecture"] = program.Architecture,
                ["language"] = program.Language,
                ["languageId"] = program.LanguageId,
                ["compiler"] = program.Compiler,
                ["compilerSpec"] = program.CompilerSpec,
                ["sha256"] = program.Sha256,
                ["imageBase"] = program.ImageBase,
                ["minAddress"] = program.MinAddress,
                ["maxAddress"] = program.MaxAddress,
                ["functionCount"] = program.FunctionCount
            };

    private bool ConstantTimeTokenEquals(string? presented)
    {
        if (presented is null || presented.Length > MaxTokenChars)
            return false;

        Span<byte> presentedBytes = stackalloc byte[MaxTokenChars * 4];
        var byteCount = Encoding.UTF8.GetBytes(presented.AsSpan(), presentedBytes);
        return CryptographicOperations.FixedTimeEquals(
            _tokenBytes,
            presentedBytes[..byteCount]);
    }
}

public sealed record GhidraOpenResult(
    bool Opened,
    string FileName,
    bool StaticReady,
    string AnalysisId = "default",
    string NativePipeName = "",
    string GhidraEndpointDirectory = "",
    GhidraProgramSummary? Program = null,
    string NativePipeToken = "");
