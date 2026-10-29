using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DbgLink.Shared;

namespace DbgLink.Server;

internal enum ToolProfile
{
    Comprehensive,
    Lean,
}

internal sealed record ServerPermissionOverrides(bool? AllowAnnotation, bool? AllowMutation);

internal sealed class ServerConfig
{
    /// <summary>
    /// Default loopback HTTP port for the MCP endpoint
    /// (<c>http://127.0.0.1:{DefaultPort}/mcp</c>). Contractual user-facing
    /// default (README/opencode.json/CLI help); do not change the value —
    /// tests that really bind sockets allocate free ports via
    /// <c>TestPortAllocator</c> instead of overriding this.
    /// </summary>
    public const int DefaultPort = 50301;

    private const int MaxConfigBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private static readonly JsonSerializerOptions ReadJsonOptions = new()
    {
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public int Port { get; init; }
    public string AuthToken { get; init; } = "";
    // Enabled-by-default enforcement of `Authorization: Bearer <AuthToken>` on /mcp.
    // /metrics always requires the token; requiring it for /mcp too closes
    // local request-forgery from other users/processes on the same machine.
    // Overridden per process by DBGLINK_REQUIRE_AUTH=1|0 (0 disables).
    // Nullable backing so a pre-existing config file missing the flag loads as
    // true instead of silently downgrading to false: absent stays true, an
    // explicit false in the file is honored.
    private bool? _requireAuthToken = true;
    public bool RequireAuthToken
    {
        get => _requireAuthToken ?? true;
        init => _requireAuthToken = value;
    }
    public int DefaultToolTimeoutMs { get; init; } = 10_000;
    public int MaxConcurrentRequests { get; init; } = 16;
    public int MaxQueuedOperations { get; init; } = 32;
    public int MaxRequestBodyBytes { get; init; } = 1_048_576;
    public bool AllowAnnotation { get; init; } = true;
    public bool AllowMutation { get; init; } = true;
    public ToolProfile Profile { get; init; } = ToolProfile.Comprehensive;
    [JsonIgnore]
    public string? GhidraControlPipeName { get; init; }
    [JsonIgnore]
    public string? GhidraControlToken { get; init; }
    [JsonIgnore]
    // Explicit telemetry directory. Null (default) keeps the
    // DBGLINK_TELEMETRY_DIR environment lookup; an explicit value skips it,
    // so tests can isolate telemetry without mutating process-wide state.
    public string? TelemetryDirectory { get; init; }
    public string DisplayUrl => $"http://127.0.0.1:{Port}/mcp";

    /// <summary>IMPL-4 Policy slice (TELEMETRY-T5 §3.1): the single telemetry
    /// kill-switch. Default-enabled (opt-out): only the six frozen values
    /// disable telemetry; anything else — including null/empty/absent —
    /// keeps it enabled. Delegates to TelemetryFileSink.IsDisabled so the two
    /// can never drift; no new flags (no TIMING/HISTORY/LEVEL/verbose).</summary>
    internal static bool IsTelemetryDisabled(string? raw)
        => TelemetryFileSink.IsDisabled(raw);

    public static ServerConfig Load(
        int port,
        ServerPermissionOverrides? permissionOverrides = null,
        string? configPath = null,
        string? ghidraControlPipeName = null,
        string? ghidraControlToken = null,
        Func<string, string?>? environment = null)
    {
        if (port is < 1 or > 65_535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");

        environment ??= Environment.GetEnvironmentVariable;
        string path;
        try
        {
            path = string.IsNullOrWhiteSpace(configPath)
                ? DbgLinkConfigPath.GetPath(environment)
                : Path.GetFullPath(configPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new ArgumentException("The DBGLink config path is invalid.", nameof(configPath), exception);
        }
        // Host-scope gate (residual-sec M2): UNC/ADS/device spellings that
        // IsSafePath alone does not cover must fail closed here, like the
        // telemetry directory already does via LocalPathPolicy.
        if (!LocalPathPolicy.IsSafeLocalPath(path))
            throw new ArgumentException("The DBGLink config path must be an absolute local drive path without UNC, ADS, or device segments.", nameof(configPath));

        ServerConfig? existing = TryReadConfig(path);

        var environmentToken = environment(DbgLinkConfigPath.BearerTokenEnvironmentVariable);
        if (!DbgLinkConfigPath.IsValidBearerToken(environmentToken))
            environmentToken = null;

        var authToken = environmentToken ?? existing?.AuthToken ?? GenerateBearerToken();
        var requireAuth = ParseBooleanFlag(environment("DBGLINK_REQUIRE_AUTH"))
            ?? existing?.RequireAuthToken ?? true;
        // Single standard catalog: the lean/comprehensive split is merged.
        // DBGLINK_TOOL_PROFILE / DBGLINK_PROFILE / DBGLINK_LEAN are ignored;
        // every caller gets the comprehensive advertisement.
        var profile = ToolProfile.Comprehensive;

        var loadedConfig = new ServerConfig
        {
            Port = port,
            AuthToken = authToken,
            DefaultToolTimeoutMs = Math.Clamp(existing?.DefaultToolTimeoutMs ?? 10_000, 1_000, 120_000),
            MaxConcurrentRequests = Math.Clamp(existing?.MaxConcurrentRequests ?? 16, 1, 64),
            MaxQueuedOperations = Math.Clamp(existing?.MaxQueuedOperations ?? 32, 0, 256),
            MaxRequestBodyBytes = Math.Clamp(existing?.MaxRequestBodyBytes ?? 1_048_576, 1024, 16 * 1024 * 1024),
            AllowAnnotation = permissionOverrides?.AllowAnnotation ?? existing?.AllowAnnotation ?? true,
            AllowMutation = permissionOverrides?.AllowMutation ?? existing?.AllowMutation ?? true,
            RequireAuthToken = requireAuth,
            Profile = profile,
            GhidraControlPipeName = ghidraControlPipeName,
            GhidraControlToken = ghidraControlToken,
            // TelemetryDirectory round-trips through the config file (it is
            // serialized), so a persisted value must take effect here.
            // Unsafe paths are dropped to null (env lookup default) rather
            // than failing startup over a hand-edited config entry.
            TelemetryDirectory = SanitizeTelemetryDirectory(existing?.TelemetryDirectory),
        };

        var mustPersist = existing is null ||
            (environmentToken is not null && !string.Equals(existing?.AuthToken, environmentToken, StringComparison.Ordinal));
        if (mustPersist)
        {
            try
            {
                PersistConfig(path, loadedConfig);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (environmentToken is null && existing is null)
                    throw new InvalidOperationException("Could not persist the local DBGLink config. Set DBGLINK_BEARER_TOKEN or make the user config directory writable.", exception);

                Console.Error.WriteLine($"Could not persist local DBGLink config ({exception.GetType().Name}); continuing with the available token.");
            }
        }

        if (!requireAuth)
            Console.Error.WriteLine("WARNING: DBGLink MCP authentication is DISABLED (RequireAuthToken=false): /mcp accepts unauthenticated loopback requests. Set DBGLINK_REQUIRE_AUTH=1 or remove the explicit opt-out to re-enable bearer-token enforcement.");

        return loadedConfig;
    }

    private static bool? ParseBooleanFlag(string? raw)
        => raw?.Trim().ToLowerInvariant() switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => null,
        };

    private static string? SanitizeTelemetryDirectory(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        try
        {
            var full = Path.GetFullPath(raw);
            return LocalPathPolicy.IsSafeLocalPath(full) ? full : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static ServerConfig? TryReadConfig(string path)
    {
        try
        {
            if (!DbgLinkConfigPath.IsSafePath(path) || !LocalPathPolicy.IsSafeLocalPath(path))
                return null;
            if (!File.Exists(path))
                return null;

            var json = ReadBoundedText(path);
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(document.RootElement))
                return null;

            var existing = JsonSerializer.Deserialize<ServerConfig>(json, ReadJsonOptions);
            if (existing is null || !DbgLinkConfigPath.IsValidBearerToken(existing.AuthToken))
                return null;

            ProtectConfigFile(path);
            return existing;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            Console.Error.WriteLine($"Could not read DBGLink config ({exception.GetType().Name}).");
            return null;
        }
    }

    private static string ReadBoundedText(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        if (stream.Length > MaxConfigBytes)
            throw new JsonException("The DBGLink config file exceeds its byte limit.");

        using var data = new MemoryStream(capacity: (int)stream.Length);
        var buffer = new byte[4096];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
                break;
            if (data.Length + read > MaxConfigBytes)
                throw new JsonException("The DBGLink config file exceeds its byte limit.");
            data.Write(buffer, 0, read);
        }

        return StrictUtf8.GetString(data.GetBuffer(), 0, checked((int)data.Length));
    }

    private static string GenerateBearerToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static void PersistConfig(string path, ServerConfig config)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("The DBGLink config directory is invalid.");
        if (!DbgLinkConfigPath.IsSafePath(fullPath) || !LocalPathPolicy.IsSafeLocalPath(fullPath))
            throw new IOException("The DBGLink config path traverses a reparse point.");
        Directory.CreateDirectory(directory);
        ProtectConfigDirectory(directory);
        if (!DbgLinkConfigPath.IsSafePath(fullPath) || !LocalPathPolicy.IsSafeLocalPath(fullPath))
            throw new IOException("The DBGLink config path traverses a reparse point.");
        var temporaryPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var json = JsonSerializer.Serialize(config, IndentedJsonOptions);
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false), 4096, leaveOpen: true))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            ProtectConfigFile(temporaryPath);
            if (!DbgLinkConfigPath.IsSafePath(fullPath) || !LocalPathPolicy.IsSafeLocalPath(fullPath))
                throw new IOException("The DBGLink config path traverses a reparse point.");
            File.Move(temporaryPath, fullPath, overwrite: true);
            ProtectConfigFile(fullPath);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// The config holds the bearer token, so it is restricted to the current
    /// user (Windows ACL / Unix 0600). The ACL logic lives in
    /// <see cref="FileProtection"/>; this wrapper only adds the operator
    /// visible diagnostic.
    /// </summary>
    private static void ProtectConfigFile(string path)
    {
        FileProtection.ProtectFile(path, reason =>
            Console.Error.WriteLine(
                $"Could not protect local DBGLink config ({reason}); continuing with existing file permissions."));
    }

    private static int _directoryProtectionReported;

    /// <summary>
    /// Directory twin of <see cref="ProtectConfigFile"/>: a lax config
    /// directory exposes the bearer token as surely as a lax config file.
    /// One-shot per process — PersistConfig runs on the hot path, and a
    /// persistent failure (FAT32, vault without ACLs) must not spam stderr.
    /// Manual-console diagnostic only, like the file twin: an auto-started
    /// server has no visible stderr.
    /// </summary>
    private static void ProtectConfigDirectory(string path)
    {
        FileProtection.ProtectDirectory(path, reason =>
        {
            if (Interlocked.Exchange(ref _directoryProtectionReported, 1) == 0)
                Console.Error.WriteLine(
                    $"Could not protect local DBGLink config directory ({reason}); continuing with existing directory permissions.");
        });
    }
}
