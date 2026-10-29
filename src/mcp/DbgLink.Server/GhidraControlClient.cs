using DbgLink.Shared;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal interface IGhidraControlClient
{
    bool SupportsSessionControl => false;
    Task<string> SessionControlAsync(string method, JsonElement arguments, CancellationToken cancellationToken)
        => Task.FromResult(BridgeEnvelope.Error("session_control_unavailable", "Restart DBGLink with the updated launcher to manage sessions."));
    Task<string> OpenFileAsync(string path, CancellationToken cancellationToken);
    Task<string> OpenFileAsync(string path, bool analyze, CancellationToken cancellationToken)
        => analyze ? OpenFileAsync(path, cancellationToken)
            : Task.FromResult(BridgeEnvelope.Error("unsupported_import_mode", "Fast imports without analysis are not supported: retry with analyze=true (the default)."));
}

internal sealed class GhidraControlClient : IGhidraControlClient, IDisposable
{
    public bool SupportsSessionControl => true;

    public Task<string> SessionControlAsync(string method, JsonElement arguments, CancellationToken cancellationToken)
    {
        if (method is not ("ListAnalysisSessions" or "SwitchDebugger" or "CloseAnalysisSession" or "ReopenAnalysisSession"))
            throw new ArgumentException("Unsupported session operation.", nameof(method));
        var request = JsonNode.Parse(arguments.GetRawText())!.AsObject();
        request["id"] = 1;
        request["method"] = method;
        request["token"] = _token;
        return SendAsync(JsonSerializer.SerializeToUtf8Bytes(request), false, cancellationToken);
    }
    private const int MaxPathLength = 32_760;
    private const int MaxRequestBytes = 64 * 1024;
    private const int MaxResponseBytes = 16 * 1024;
    private const int ConnectTimeoutMilliseconds = 2_000;
    // The import deadline plus two minutes covers the launcher's no-analysis
    // fallback and bridge activation; the old fixed 315 s cut off exactly the
    // large real binaries this timeout exists to support.
    private static readonly int ResponseTimeoutMilliseconds =
        (int)GhidraOpenOperations.ResolveImportTimeout().TotalMilliseconds + 120_000;
    private const int MaxTokenChars = 256;
    private static readonly byte[] NewLine = [(byte)'\n'];
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ax", ".bin", ".com", ".cpl", ".dll", ".drv", ".dylib", ".efi", ".elf", ".exe", ".o", ".ocx", ".rll", ".scr", ".so", ".sys"
    };

    private readonly string _pipeName;
    private readonly string _token;
    private readonly SemaphoreSlim _requestLock = new(1, 1);

    public GhidraControlClient(string pipeName, string token)
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

        _pipeName = pipeName;
        _token = token;
    }

    public Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
        => OpenFileAsync(path, true, cancellationToken);

    public async Task<string> OpenFileAsync(string path, bool analyze, CancellationToken cancellationToken)
    {
        string normalizedPath;
        try
        {
            normalizedPath = ValidatePath(path);
        }
        catch (FileNotFoundException)
        {
            return BridgeEnvelope.BoundedError(0, "target_not_found", "The requested Ghidra target file was not found.");
        }
        catch (InvalidDataException exception)
        {
            return BridgeEnvelope.BoundedError(0, "target_rejected", exception.Message);
        }
        catch (ArgumentException)
        {
            return BridgeEnvelope.BoundedError(0, "target_rejected", "The requested Ghidra target path is invalid.");
        }
        catch (IOException)
        {
            return BridgeEnvelope.BoundedError(0, "target_not_found", "The requested Ghidra target file could not be read.");
        }
        catch (UnauthorizedAccessException)
        {
            return BridgeEnvelope.BoundedError(0, "target_not_found", "The requested Ghidra target file could not be accessed.");
        }
        catch (NotSupportedException)
        {
            return BridgeEnvelope.BoundedError(0, "target_rejected", "The requested Ghidra target path is not supported.");
        }

        return await SendAsync(JsonSerializer.SerializeToUtf8Bytes(new
        {
            id = 1, method = "OpenGhidraFile", token = _token, path = normalizedPath, analyze
        }), true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> SendAsync(byte[] request, bool importing, CancellationToken cancellationToken)
    {
        // Fail fast on oversized paths before taking the import lock so a bad
        // request never blocks a running import or session operation.
        if (request.Length + 1 > MaxRequestBytes)
            return BridgeEnvelope.BoundedError(0,
                "ghidra_control_request_too_large",
                "The selected Ghidra target path exceeds the control-pipe byte limit.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ResponseTimeoutMilliseconds);
        var lockAcquired = false;
        try
        {
            if (!importing && !await _requestLock.WaitAsync(0, timeout.Token).ConfigureAwait(false))
                return BridgeEnvelope.BoundedError(0, "session_control_busy", "An import or session operation is active. Do not poll: wait for its GetGhidraOpenStatus result or cancel the import, then retry once.");
            if (importing)
                await _requestLock.WaitAsync(timeout.Token).ConfigureAwait(false);
            lockAcquired = true;

            await using var pipe = new NamedPipeClientStream(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ConnectTimeoutMilliseconds, timeout.Token).ConfigureAwait(false);

            await pipe.WriteAsync(request, timeout.Token).ConfigureAwait(false);
            await pipe.WriteAsync(NewLine, timeout.Token).ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);

            var response = await BoundedLineReader.ReadAsync(pipe, MaxResponseBytes, rejectEmptyLine: true, timeout.Token).ConfigureAwait(false);
            if (response is null)
                return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The Ghidra control pipe returned no response.");

            return ValidateResponse(response, importing);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_timeout", "Ghidra did not open the target before the bounded timeout. Track the operation via GetGhidraOpenStatus; poll no faster than its retryAfterMs.");
        }
        catch (TimeoutException)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_timeout", "Ghidra did not open the target before the bounded timeout. Track the operation via GetGhidraOpenStatus; poll no faster than its retryAfterMs.");
        }
        catch (IOException)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_unavailable", "The launcher Ghidra control pipe could not be reached.");
        }
        catch (UnauthorizedAccessException)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_unavailable", "The launcher Ghidra control pipe could not be reached.");
        }
        catch (DecoderFallbackException)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The launcher Ghidra control pipe returned invalid UTF-8.");
        }
        finally
        {
            if (lockAcquired)
                _requestLock.Release();
        }
    }

    private static string ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0 || path.Length > MaxPathLength)
            throw new ArgumentException("path must be a bounded local file path.", nameof(path));

        var trimmedPath = path.Trim();
        if (!Path.IsPathFullyQualified(trimmedPath))
            throw new InvalidDataException("path must be an absolute local file path.");
        // Host-scope escapes: UNC (\\server\share, Uri.IsUnc), non-drive
        // roots, ADS (:) and DOS device segments fail closed before any I/O.
        if (!LocalPathPolicy.IsSafeLocalPath(trimmedPath))
            throw new InvalidDataException("path must be an absolute local drive file path.");

        string fullPath;
        try { fullPath = Path.GetFullPath(trimmedPath); }
        catch (ArgumentException exception) { throw new ArgumentException("path must be a valid local file path.", nameof(path), exception); }
        catch (NotSupportedException exception) { throw new ArgumentException("path must be a valid local file path.", nameof(path), exception); }
        if (!LocalPathPolicy.IsSafeLocalPath(fullPath))
            throw new InvalidDataException("path must be an absolute local drive file path.");

        var info = new FileInfo(fullPath);
        if (!PathSafety.IsReparseFree(fullPath) || !info.Exists || info.Attributes.HasFlag(FileAttributes.Directory) ||
            info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new FileNotFoundException("The requested Ghidra target file was not found.");
        if (info.Length <= 0 || info.Length > 512L * 1024 * 1024)
            throw new InvalidDataException("The Ghidra target file is empty or exceeds the 512 MB limit.");
        if (!AllowedExtensions.Contains(info.Extension))
            throw new InvalidDataException(
                $"The Ghidra target extension '{info.Extension}' is not allowlisted. Supported: .ax .bin .com .cpl .dll .drv .dylib .efi .elf .exe .o .ocx .rll .scr .so .sys.");
        return fullPath;
    }

    internal static string ValidateResponse(string response, bool importing = true)
    {
        try
        {
            using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("id", out var id) ||
                id.ValueKind != JsonValueKind.Number ||
                !id.TryGetInt32(out var responseId) || responseId != 1 ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The Ghidra control response was invalid.");
            }

            if (ok.ValueKind == JsonValueKind.True && importing &&
                (!root.TryGetProperty("result", out var result) ||
                 result.ValueKind != JsonValueKind.Object ||
                 !result.TryGetProperty("opened", out var opened) || opened.ValueKind != JsonValueKind.True ||
                 !result.TryGetProperty("staticReady", out var ready) || ready.ValueKind != JsonValueKind.True ||
                 !result.TryGetProperty("fileName", out var fileName) ||
                 fileName.ValueKind != JsonValueKind.String ||
                 string.IsNullOrWhiteSpace(fileName.GetString()) || fileName.GetString()!.Length > 260 ||
                 fileName.GetString()!.Any(char.IsControl) ||
                 !AnalysisSessionResponse.TryRead(response, out _)))
            {
                return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The Ghidra control response did not confirm static readiness.");
            }

            if (ok.ValueKind == JsonValueKind.True && !importing &&
                (!root.TryGetProperty("result", out var sessionResult) || sessionResult.ValueKind != JsonValueKind.Object))
                return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The launcher did not return a session operation result.");

            if (ok.ValueKind == JsonValueKind.False &&
                (!root.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object))
            {
                return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The Ghidra control error response was invalid.");
            }

            return response;
        }
        catch (JsonException)
        {
            return BridgeEnvelope.BoundedError(0, "ghidra_control_protocol", "The Ghidra control response was not valid JSON.");
        }
    }

    private int _disposed;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        try { _requestLock.Dispose(); } catch { }
        GC.SuppressFinalize(this);
    }
}
