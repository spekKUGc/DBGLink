namespace DbgLink.Launcher.Core;

/// <summary>
/// Validates and stages a user-selected local binary for an isolated Ghidra session.
/// </summary>
public static class GhidraTargetPolicy
{
    public const int MaxPathLength = 32_760;
    public const long MaxFileBytes = 512L * 1024 * 1024;

    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Keep in sync with GhidraControlClient.AllowedExtensions (server side):
        // launcher-staged sessions reject anything missing here first.
        ".ax", ".bin", ".com", ".cpl", ".dll", ".drv", ".dylib", ".efi", ".elf", ".exe", ".o", ".ocx", ".rll", ".scr", ".so", ".sys"
    };

    public static GhidraTargetInfo Validate(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath) || rawPath.IndexOf('\0') >= 0 || rawPath.Length > MaxPathLength)
            throw new InvalidDataException("The Ghidra target path is invalid or too long.");

        var trimmedPath = rawPath.Trim();
        if (!Path.IsPathFullyQualified(trimmedPath))
            throw new InvalidDataException("The Ghidra target path must be absolute.");

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(trimmedPath);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The Ghidra target path is invalid.", exception);
        }
        catch (NotSupportedException exception)
        {
            throw new InvalidDataException("The Ghidra target path is invalid.", exception);
        }

        if (!AllowedExtensions.Contains(Path.GetExtension(fullPath)))
            throw new InvalidDataException("The Ghidra target extension is not allowlisted.");

        var info = new FileInfo(fullPath);
        if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory))
            throw new FileNotFoundException("The Ghidra target file was not found.");
        if (!ProcessLauncher.IsCommandArgumentSafe(info.Name))
            throw new InvalidDataException("The Ghidra target filename may not contain percent signs or exclamation marks on Windows.");
        RejectReparseAncestors(fullPath);
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException("The Ghidra target may not be a reparse point.");
        if (info.Length <= 0 || info.Length > MaxFileBytes)
            throw new InvalidDataException("The Ghidra target file is empty or exceeds the 512 MB limit.");
        return new(fullPath, info.Name, info.Extension, info.Length);
    }

    public static GhidraTargetInfo Stage(string rawPath, string sessionRoot)
    {
        var target = Validate(rawPath);
        if (string.IsNullOrWhiteSpace(sessionRoot))
            throw new ArgumentException("A Ghidra session root is required.", nameof(sessionRoot));

        RejectReparseAncestors(sessionRoot);
        var inputDirectory = Path.Combine(sessionRoot, "inputs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(inputDirectory);
        RejectReparseAncestors(inputDirectory);
        var stagedPath = Path.Combine(inputDirectory, target.FileName);
        CopyFromNonReparseSource(target, stagedPath);

        var stagedInfo = new FileInfo(stagedPath);
        RejectReparseAncestors(stagedPath);
        if (!stagedInfo.Exists || stagedInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            stagedInfo.Attributes.HasFlag(FileAttributes.Directory) || stagedInfo.Length != target.Length)
            throw new InvalidDataException("The staged Ghidra target did not pass the size check.");

        return target with { StagedPath = stagedPath };
    }

    private static void CopyFromNonReparseSource(GhidraTargetInfo target, string stagedPath)
    {
        try
        {
            SafeFileCopy.Copy(target.FullPath, stagedPath, MaxFileBytes, overwrite: false);
        }
        catch (IOException exception)
        {
            throw new InvalidDataException(
                $"The Ghidra target could not be copied safely: {exception.Message}",
                exception);
        }
    }

    private static void RejectReparseAncestors(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("The Ghidra target path may not traverse a reparse point.");
            current = current.Parent;
        }
    }

}

public sealed record GhidraTargetInfo(
    string FullPath,
    string FileName,
    string Extension,
    long Length,
    string? StagedPath = null);
