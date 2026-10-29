using DbgLink.Shared;

namespace DbgLink.Server;

/// <summary>
/// Host-scope path policy for debug targets, Ghidra files, work dirs and
/// endpoint directories. Rejects UNC / ADS / device spellings that
/// <see cref="DbgLinkConfigPath.IsSafePath"/> alone does not cover on its own
/// (UNC has no colon; device names are legal path segments).
/// Fail-closed: any I/O, argument or URI failure rejects.
/// </summary>
internal static class LocalPathPolicy
{
    private static readonly HashSet<string> ReservedDosNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "CONIN$", "CONOUT$"
    };

    internal static IReadOnlyCollection<string> ReservedDeviceNames => ReservedDosNames;

    internal static bool IsUncPath(string path)
    {
        try
        {
            var trimmed = path.Trim();
            if (trimmed.StartsWith(@"\\", StringComparison.Ordinal) ||
                trimmed.StartsWith("//", StringComparison.Ordinal))
                return true;
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && uri.IsUnc)
                return true;
            return false;
        }
        catch (Exception exception) when (exception is ArgumentException or UriFormatException)
        {
            return true;
        }
    }

    internal static bool HasLocalDriveRoot(string path)
    {
        try
        {
            var trimmed = path.Trim();
            if (trimmed.Length < 3)
                return false;
            if (!char.IsAsciiLetter(trimmed[0]) || trimmed[1] != ':')
                return false;
            return trimmed[2] is '\\' or '/';
        }
        catch
        {
            return false;
        }
    }

    internal static bool ContainsReservedDeviceSegment(string fullPath)
    {
        try
        {
            var segments = fullPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
            foreach (var segment in segments)
            {
                var name = segment.Trim();
                if (name.Length == 0)
                    continue;
                // Strip trailing dots/spaces (Windows ignores them) and the
                // extension: "NUL.txt", "CON ", "COM1." are still the device.
                name = name.TrimEnd('.', ' ');
                var dot = name.IndexOf('.');
                var baseName = dot >= 0 ? name[..dot] : name;
                // Extended-prefix "?" / "$" segments (\\?\, \\.\ ) are not devices.
                if (baseName is "?" or "." or ".." or "$")
                    continue;
                if (ReservedDosNames.Contains(baseName))
                    return true;
            }
            return false;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Full host-scope check: UNC rejected, local drive required on Windows
    /// (Unix absolute rooted paths allowed off-Windows so /tmp endpoint dirs
    /// keep working), ADS + reparse via <see cref="DbgLinkConfigPath.IsSafePath"/>,
    /// DOS device segments rejected everywhere (fail-closed, cheap).
    /// </summary>
    internal static bool IsSafeLocalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            var trimmed = path.Trim();
            if (IsUncPath(trimmed))
                return false;
            if (OperatingSystem.IsWindows())
            {
                if (!HasLocalDriveRoot(trimmed))
                    return false;
            }
            else if (!Path.IsPathFullyQualified(trimmed))
            {
                return false;
            }
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(trimmed);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return false;
            }
            if (OperatingSystem.IsWindows() && !HasLocalDriveRoot(fullPath))
                return false;
            if (IsUncPath(fullPath))
                return false;
            if (ContainsReservedDeviceSegment(fullPath))
                return false;
            return DbgLinkConfigPath.IsSafePath(fullPath);
        }
        catch
        {
            return false;
        }
    }
}
