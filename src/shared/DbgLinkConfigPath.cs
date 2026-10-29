namespace DbgLink.Shared;

public static class DbgLinkConfigPath
{
    public const string ConfigPathEnvironmentVariable = "DBGLINK_CONFIG_PATH";
    public const string BearerTokenEnvironmentVariable = "DBGLINK_BEARER_TOKEN";
    public const string CheckpointPathEnvironmentVariable = "DBGLINK_CHECKPOINT_PATH";
    /// <summary>
    /// Environment variable that carries the native bridge pipe token to the
    /// server. The token is a per-session credential: on the command line it
    /// would be readable by every local process through
    /// Win32_Process.CommandLine. The native plugin sets the same variable
    /// name when it auto-starts the server.
    /// </summary>
    public const string NativePipeTokenEnvironmentVariable = "DBGLINK_NATIVE_PIPE_TOKEN";

    public static string GetPath(Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var configured = environment(ConfigPathEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var fullPath = Path.GetFullPath(configured);
            if (fullPath.Length > 32_760)
                throw new ArgumentException($"The {ConfigPathEnvironmentVariable} path is too long.", ConfigPathEnvironmentVariable);
            // Source-level gate (OD-9): an operator-provided override must
            // pass the colon/ADS + reparse policy. The computed default below
            // is internal and stays unchecked, so launchers under
            // reparse-heavy profiles (OneDrive, junctions) keep working.
            // UNC/device spellings are outside IsSafePath's scope and stay
            // the downstream LocalPathPolicy's job.
            if (!IsSafePath(fullPath))
                throw new ArgumentException($"The {ConfigPathEnvironmentVariable} path is not a safe local path (ADS stream or reparse point).", ConfigPathEnvironmentVariable);
            return fullPath;
        }

        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localApplicationData))
            throw new InvalidOperationException("The local application-data directory is unavailable.");

        return Path.Combine(localApplicationData, "DBGLink", "mcp_config.json");
    }

    public static string GetCheckpointPath(Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var configured = environment(CheckpointPathEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var fullPath = Path.GetFullPath(configured);
            if (fullPath.Length > 32_760)
                throw new ArgumentException($"The {CheckpointPathEnvironmentVariable} path is too long.", CheckpointPathEnvironmentVariable);
            // Same source-level gate as GetPath (OD-9); same scope note.
            if (!IsSafePath(fullPath))
                throw new ArgumentException($"The {CheckpointPathEnvironmentVariable} path is not a safe local path (ADS stream or reparse point).", CheckpointPathEnvironmentVariable);
            return fullPath;
        }

        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localApplicationData))
            throw new InvalidOperationException("The local application-data directory is unavailable.");

        return Path.Combine(localApplicationData, "DBGLink", "checkpoints.json");
    }

    public static bool IsValidBearerToken(string? token)
    {
        if (token is not { Length: >= 32 and <= 512 })
            return false;

        var paddingStart = token.IndexOf('=');
        var valueEnd = paddingStart < 0 ? token.Length : paddingStart;
        if (valueEnd == 0 ||
            !token[..valueEnd].All(IsToken68Character) ||
            (paddingStart >= 0 && token[paddingStart..].Any(character => character != '=')))
            return false;

        return true;
    }

    public static bool IsSafePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        try
        {
            var fullPath = Path.GetFullPath(path);

            var firstColon = fullPath.IndexOf(':');
            if (firstColon >= 0)
            {
                var isDriveColon = (firstColon == 1 && char.IsAsciiLetter(fullPath[0])) ||
                                   (firstColon == 5 && fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) && char.IsAsciiLetter(fullPath[4]));
                if (!isDriveColon || fullPath.IndexOf(':', firstColon + 1) >= 0)
                    return false;
            }

            return PathSafety.IsReparseFree(fullPath);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsToken68Character(char character)
        => character is >= 'A' and <= 'Z' ||
            character is >= 'a' and <= 'z' ||
            character is >= '0' and <= '9' ||
            character is '-' or '.' or '_' or '~' or '+' or '/';
}
