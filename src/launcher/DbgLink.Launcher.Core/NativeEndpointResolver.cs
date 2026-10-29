using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Rendezvous for the N1 native pipe authentication contract.
/// After the debugger starts, the native bridge publishes
/// <c>%LOCALAPPDATA%\DBGLink\native-endpoint-&lt;pid&gt;.json</c> with its pipe
/// name and session token. The launcher polls that per-PID file inside the
/// existing native-handshake window, validates it, deletes it, and forwards
/// the pipe name and token to <c>DbgLink.Server</c>. Anything missing or
/// invalid fails closed.
///
/// Windows-only in practice (named pipes, %LOCALAPPDATA%, file ownership);
/// every Windows-only call is guarded and fails closed elsewhere.
/// </summary>
public static class NativeEndpointResolver
{
    internal const string EndpointDirectoryName = "DBGLink";
    internal const string EndpointFilePrefix = "native-endpoint-";
    internal const string EndpointFileSuffix = ".json";
    internal const long MaxEndpointFileBytes = 64 * 1024;
    internal const int ExpectedSchemaVersion = 1;
    internal const string PipePrefix = @"\\.\pipe\";
    internal const int MaxPipeNameChars = 260;
    internal const int TokenHexChars = 64;

    /// <summary>
    /// Permissive skew for the recycled-PID stale check: a file is stale only
    /// when its newest timestamp is more than this far before the debugger
    /// process start. Same-machine clock, NTFS granularity.
    /// </summary>
    internal static readonly TimeSpan StaleTolerance = TimeSpan.FromSeconds(2);

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Test seam: fake %LOCALAPPDATA% root. Null in production.</summary>
    internal static string? LocalAppDataOverride;

    /// <summary>Test seam: fake debugger-process start time (UTC) by PID. Null in production.</summary>
    internal static Func<int, DateTime?>? ProcessStartUtcOverride;

    internal static string EndpointFileNameFor(int processId)
        => $"{EndpointFilePrefix}{processId}{EndpointFileSuffix}";

    /// <summary>
    /// Full path of the per-PID rendezvous file, or null when %LOCALAPPDATA%
    /// is unavailable or the PID is invalid.
    /// </summary>
    internal static string? EndpointPathFor(int processId)
    {
        if (processId <= 0)
            return null;
        try
        {
            var root = LocalAppDataOverride ??
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(root) || root.Any(char.IsControl))
                return null;
            var path = Path.Combine(root, EndpointDirectoryName, EndpointFileNameFor(processId));
            return path.Length > 32_760 ? null : path;
        }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    public static async Task<NativeEndpoint> WaitForEndpointAsync(
        int expectedProcessId,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Func<bool>? isProcessAlive = null,
        Action<string>? report = null)
    {
        if (expectedProcessId <= 0)
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(timeout));

        var stopwatch = Stopwatch.StartNew();
        var lastDetail = "the endpoint file was missing.";
        var path = EndpointPathFor(expectedProcessId) ??
            throw new InvalidOperationException(
                "The local application-data directory is unavailable.");
        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (isProcessAlive is not null && !isProcessAlive())
                throw new InvalidOperationException(
                    "The debugger exited before the native bridge published its endpoint.");

            if (File.Exists(path) || Directory.Exists(path))
            {
                if (TryReadValidEndpoint(path, expectedProcessId, out var endpoint, out var detail))
                {
                    if (!TryDeleteEndpointFile(path))
                        ReportSafely(report, "The native endpoint file was verified but could not be removed.");
                    return endpoint!;
                }
                lastDetail = detail;
            }
            else
            {
                lastDetail = "the endpoint file was missing.";
            }

            var remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
                break;
            await Task.Delay(
                TimeSpan.FromMilliseconds(Math.Min(100, remaining.TotalMilliseconds)),
                cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException(
            $"The DBGLink native bridge did not publish a valid endpoint before the timeout " +
            $"(debugger PID {expectedProcessId}). Last result: {lastDetail} " +
            "Verify that the matching DbgLink.dp64/DbgLink.dp32 plugin is loaded " +
            "in this debugger and that it runs under the same Windows account.");
    }

    /// <summary>
    /// Reads and validates the rendezvous file. Never throws: every failure
    /// mode reports a token-free detail string and returns false.
    /// When <paramref name="debuggerStartUtc"/> is null, the debugger process
    /// start is queried best-effort; unknown start times skip only the stale
    /// check, everything else still applies.
    /// </summary>
    internal static bool TryReadValidEndpoint(
        string path,
        int expectedProcessId,
        out NativeEndpoint? endpoint,
        out string detail,
        DateTime? debuggerStartUtc = null)
    {
        endpoint = null;
        detail = "the endpoint file was invalid.";

        string fileDetail;
        if (!IsReadableRegularFile(path, out fileDetail))
        {
            detail = fileDetail;
            return false;
        }
        if (!PathSafety.IsReparseFree(path))
        {
            detail = "the endpoint file must not traverse a reparse point.";
            return false;
        }
        if (!IsCurrentUserOwned(path))
        {
            detail = "the endpoint file is not owned by the current user.";
            return false;
        }

        string json;
        try
        {
            using var stream = SafeFileCopy.OpenNonReparseRead(path);
            if (stream.Length <= 0 || stream.Length > MaxEndpointFileBytes)
            {
                detail = "the endpoint file exceeds its size limit.";
                return false;
            }
            using var reader = new StreamReader(stream, StrictUtf8, false, 4096);
            json = reader.ReadToEnd();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or InvalidDataException or DecoderFallbackException)
        {
            detail = "the endpoint file could not be read.";
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            detail = "the endpoint file was not valid JSON.";
            return false;
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root))
            {
                detail = "the endpoint file must be a JSON object without duplicate properties.";
                return false;
            }

            if (!root.TryGetProperty("schemaVersion", out var schema) ||
                schema.ValueKind != JsonValueKind.Number ||
                !schema.TryGetInt32(out var schemaVersion) ||
                schemaVersion != ExpectedSchemaVersion)
            {
                detail = "the endpoint schemaVersion must be 1.";
                return false;
            }

            if (!root.TryGetProperty("pid", out var pid) ||
                pid.ValueKind != JsonValueKind.Number ||
                !pid.TryGetInt32(out var actualPid) ||
                actualPid != expectedProcessId)
            {
                detail = "the endpoint pid did not match the debugger.";
                return false;
            }

            if (IsStaleEndpointFile(path, expectedProcessId, debuggerStartUtc))
            {
                detail = "the endpoint file is stale (older than the debugger process start).";
                return false;
            }

            if (!root.TryGetProperty("pipeName", out var pipeName) ||
                pipeName.ValueKind != JsonValueKind.String ||
                !IsValidPipeName(pipeName.GetString()))
            {
                detail = "the endpoint pipeName was not a valid named-pipe path.";
                return false;
            }

            if (!root.TryGetProperty("token", out var token) ||
                token.ValueKind != JsonValueKind.String ||
                !IsValidPipeToken(token.GetString()))
            {
                detail = "the endpoint token was not 64 lowercase hex characters.";
                return false;
            }

            endpoint = new NativeEndpoint(pipeName.GetString()!, token.GetString()!);
            return true;
        }
    }

    internal static bool IsValidPipeName(string? pipeName)
    {
        if (string.IsNullOrEmpty(pipeName) ||
            !pipeName.StartsWith(PipePrefix, StringComparison.Ordinal) ||
            pipeName.Length > MaxPipeNameChars)
            return false;
        var bare = pipeName[PipePrefix.Length..];
        return bare.Length != 0 &&
            !bare.Any(character => character == '\\' || char.IsControl(character));
    }

    internal static bool IsValidPipeToken(string? token)
        => token is { Length: TokenHexChars } &&
            token.All(character =>
                (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f'));

    /// <summary>
    /// Recycled-PID guard: a file whose newest timestamp predates the debugger
    /// process start (beyond <see cref="StaleTolerance"/>) is a leftover from
    /// a previous PID incarnation and must never be accepted. Best-effort:
    /// unknown process starts or unreadable timestamps are not stale.
    /// </summary>
    internal static bool IsStaleEndpointFile(
        string path,
        int expectedProcessId,
        DateTime? debuggerStartUtc = null)
    {
        try
        {
            var start = debuggerStartUtc ?? TryGetDebuggerStartUtc(expectedProcessId);
            if (start is null)
                return false;
            var latest = TryGetLatestEndpointFileTimeUtc(path);
            if (latest is null)
                return false;
            return latest.Value + StaleTolerance < start.Value;
        }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    internal static DateTime? TryGetDebuggerStartUtc(int processId)
    {
        try
        {
            if (ProcessStartUtcOverride is not null)
                return ProcessStartUtcOverride(processId);
            if (processId <= 0)
                return null;
            using var process = Process.GetProcessById(processId);
            return process.StartTime.ToUniversalTime();
        }
        catch (ArgumentException) { return null; }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
        catch (NotSupportedException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (IOException) { return null; }
    }

    private static DateTime? TryGetLatestEndpointFileTimeUtc(string path)
    {
        try
        {
            var creation = File.GetCreationTimeUtc(path);
            var write = File.GetLastWriteTimeUtc(path);
            return creation > write ? creation : write;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    private static bool IsReadableRegularFile(string path, out string detail)
    {
        detail = "the endpoint file was invalid.";
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory))
            {
                detail = "the endpoint file was missing.";
                return false;
            }
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                detail = "the endpoint file must not be a reparse point.";
                return false;
            }
            if (info.Length <= 0 || info.Length > MaxEndpointFileBytes)
            {
                detail = "the endpoint file exceeds its size limit.";
                return false;
            }
            return true;
        }
        catch (IOException) { detail = "the endpoint file could not be read."; return false; }
        catch (UnauthorizedAccessException) { detail = "the endpoint file could not be read."; return false; }
        catch (ArgumentException) { detail = "the endpoint file was invalid."; return false; }
        catch (NotSupportedException) { detail = "the endpoint file was invalid."; return false; }
    }

    private static bool IsCurrentUserOwned(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                return false;
            var result = GetNamedSecurityInfoW(
                path,
                SeFileObject,
                OwnerSecurityInformation,
                out var ownerSid,
                out _,
                out _,
                out _,
                out var descriptor);
            if (result != 0 || ownerSid == IntPtr.Zero)
            {
                if (descriptor != IntPtr.Zero)
                    LocalFree(descriptor);
                return false;
            }
            try
            {
                var owner = new SecurityIdentifier(ownerSid);
                return EndpointOwnership.IsOwnedByCurrentUser(owner);
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                    LocalFree(descriptor);
            }
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (DllNotFoundException) { return false; }
        catch (EntryPointNotFoundException) { return false; }
    }

    private static bool TryDeleteEndpointFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists ||
                info.Attributes.HasFlag(FileAttributes.Directory) ||
                info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                !PathSafety.IsReparseFree(path))
                return false;
            File.Delete(path);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    private static void ReportSafely(Action<string>? report, string message)
    {
        try { report?.Invoke(message); } catch (Exception) { }
    }

    private const int SeFileObject = 1;
    private const int OwnerSecurityInformation = 0x00000001;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetNamedSecurityInfoW(
        string pObjectName,
        int ObjectType,
        int SecurityInfo,
        out IntPtr ppsidOwner,
        out IntPtr ppsidGroup,
        out IntPtr ppDacl,
        out IntPtr ppSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);
}

/// <summary>
/// Validated N1 rendezvous: the pipe name exactly as published (full
/// <c>\\.\pipe\...</c> form, forwarded verbatim to <c>DbgLink.Server</c>)
/// plus the session token.
/// </summary>
public sealed record NativeEndpoint(string PipeName, string Token)
{
    /// <summary>
    /// Bare pipe name for <c>NamedPipeClientStream</c>, which joins the server
    /// and pipe name itself.
    /// </summary>
    public string BarePipeName => PipeName.StartsWith(NativeEndpointResolver.PipePrefix, StringComparison.Ordinal)
        ? PipeName[NativeEndpointResolver.PipePrefix.Length..]
        : PipeName;
}
