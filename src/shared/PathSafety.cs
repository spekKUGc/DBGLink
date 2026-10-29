namespace DbgLink.Shared;

/// <summary>
/// Canonical reparse-point guard shared by the MCP server and the launcher.
/// Rejects a path whose file/directory itself is a reparse point and any path
/// whose ancestor chain crosses one (junctions, symlinks, mount points).
/// I/O and argument failures fail closed (return false).
/// </summary>
public static class PathSafety
{
    public static bool IsReparseFree(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var fileInfo = new FileInfo(fullPath);
            if (fileInfo.Exists && fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return false;

            var current = fileInfo.Exists && !fileInfo.Attributes.HasFlag(FileAttributes.Directory)
                ? fileInfo.Directory
                : new DirectoryInfo(fullPath);
            while (current is not null)
            {
                if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    return false;
                current = current.Parent;
            }
            return true;
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
}
