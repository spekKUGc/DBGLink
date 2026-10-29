using System.Collections.ObjectModel;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

public static partial class LauncherPlanner
{
    private const long MaxJavaReleaseBytes = 2L * 1024 * 1024;
    private const int MaxJavaHomeCandidatesPerDirectory = 256;

    private static string? FindExtensionZip(
        LauncherSettings settings,
        string pluginDirectory,
        Func<string, string?> environment,
        ICollection<ValidationIssue> issues)
    {
        var configured = settings.ExtensionZip;
        if (string.IsNullOrWhiteSpace(configured))
            configured = environment("DBGLINK_GHIDRA_EXTENSION_ZIP");

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configured))
            candidates.Add(configured);
        candidates.Add(Path.Combine(pluginDirectory, "GhidraBridge.zip"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "GhidraBridge.zip"));

        foreach (var candidate in candidates)
        {
            var full = NormalizePath(candidate);
            if (full is null || !File.Exists(full) ||
                !Path.GetExtension(full).Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
                !PathSafety.IsReparseFree(full))
                continue;

            try
            {
                var info = new FileInfo(full);
                if (!info.Attributes.HasFlag(FileAttributes.Directory) &&
                    info.Length is > 0 and <= GhidraSession.MaxExtensionArchiveBytes)
                    return full;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (ArgumentException) { }
            catch (NotSupportedException) { }
        }

        issues.Add(new("ghidra_extension_missing", "A validated GhidraBridge extension ZIP is required."));
        return null;
    }

    private static string? FindJavaHome(
        Func<string, string?> environment,
        ICollection<ValidationIssue> issues)
    {
        var candidates = new List<string>();
        var configured = environment("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(configured))
            candidates.Add(configured);

        var programFiles = environment("ProgramFiles");
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            candidates.AddRange(SafeDirectories(Path.Combine(programFiles, "Eclipse Adoptium"), "jdk-*"));
            candidates.AddRange(SafeDirectories(Path.Combine(programFiles, "Java"), "jdk-*"));
        }

        var localAppData = environment("LOCALAPPDATA");
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            candidates.AddRange(SafeDirectories(Path.Combine(localAppData, "Programs", "Eclipse Adoptium"), "jdk-*"));
            candidates.AddRange(SafeDirectories(Path.Combine(localAppData, "Programs", "Java"), "jdk-*"));
        }

        foreach (var candidate in candidates)
        {
            var full = NormalizePath(candidate);
            if (full is not null && PathSafety.IsReparseFree(full) && IsJava21(full))
                return full;
        }

        issues.Add(new("java21_missing", "A JDK 21+ installation with java.exe is required for Ghidra."));
        return null;
    }

    private static IEnumerable<string> SafeDirectories(string root, string pattern)
    {
        try
        {
            return Directory.Exists(root)
                ? Directory.EnumerateDirectories(root, pattern, SearchOption.TopDirectoryOnly)
                    .Take(MaxJavaHomeCandidatesPerDirectory)
                    .ToArray()
                : Array.Empty<string>();
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
        catch (ArgumentException)
        {
            return Array.Empty<string>();
        }
        catch (NotSupportedException)
        {
            return Array.Empty<string>();
        }
    }

    private static bool IsJava21(string path)
    {
        var java = Path.Combine(path, "bin", "java.exe");
        var release = Path.Combine(path, "release");
        if (!File.Exists(java) || !File.Exists(release) ||
            !PathSafety.IsReparseFree(java) || !PathSafety.IsReparseFree(release))
            return false;

        try
        {
            if (new FileInfo(release).Length > MaxJavaReleaseBytes)
                return false;

            return File.ReadLines(release).Any(line =>
            {
                if (!line.StartsWith("JAVA_VERSION=\"", StringComparison.Ordinal))
                    return false;
                var versionStr = line.Substring("JAVA_VERSION=\"".Length);
                var dotIndex = versionStr.IndexOf('.');
                var quoteIndex = versionStr.IndexOf('"');
                var end = dotIndex >= 0 && (quoteIndex < 0 || dotIndex < quoteIndex) ? dotIndex : quoteIndex;
                return end > 0 && int.TryParse(versionStr.AsSpan(0, end), out var major) && major >= 21;
            });
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string? FindPluginDirectory(
        LauncherSettings settings,
        string x64DbgPath,
        Func<string, string?> environment,
        ICollection<ValidationIssue> issues,
        bool useConfiguredDirectory = true)
    {
        var configured = useConfiguredDirectory ? settings.PluginDirectory : null;
        if (useConfiguredDirectory && string.IsNullOrWhiteSpace(configured))
            configured = environment("DBGLINK_PLUGIN_DIRECTORY");

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            candidates.Add(configured);
        }
        else
        {
            var debuggerDirectory = Path.GetDirectoryName(x64DbgPath)!;
            candidates.Add(Path.Combine(debuggerDirectory, "plugins"));
            var parent = Directory.GetParent(debuggerDirectory)?.FullName;
            if (parent is not null)
                candidates.Add(Path.Combine(parent, "plugins"));
        }

        foreach (var candidate in candidates)
        {
            var full = NormalizePath(candidate);
            if (full is not null && Directory.Exists(full) && PathSafety.IsReparseFree(full))
                return full;
        }

        issues.Add(new("plugin_directory_missing", "The debugger plugins directory was not found."));
        return null;
    }

    private static string? ExistingFile(
        string? raw,
        string code,
        string label,
        ICollection<ValidationIssue> issues)
    {
        var full = NormalizePath(raw);
        if (full is null || !File.Exists(full) || !PathSafety.IsReparseFree(full))
        {
            issues.Add(new(code, $"A valid {label} is required."));
            return null;
        }
        return full;
    }

    private static void ValidateGhidraTarget(
        string? raw,
        ICollection<ValidationIssue> issues)
    {
        try
        {
            GhidraTargetPolicy.Validate(raw ?? string.Empty);
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            issues.Add(new("input_file", exception.Message));
        }
    }

    private static string? ValidateDebuggerPath(
        string? raw,
        string code,
        string expectedFileName,
        ICollection<ValidationIssue> issues)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var full = ExistingFile(raw, code, expectedFileName, issues);
        if (full is not null && !Path.GetFileName(full).Equals(expectedFileName, StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new($"invalid_{code}", $"Select {expectedFileName}."));
            return null;
        }
        return full;
    }

    private static string? ExistingDirectory(
        string? raw,
        string code,
        string label,
        ICollection<ValidationIssue> issues)
    {
        var full = NormalizePath(raw);
        if (full is null || !Directory.Exists(full) || !PathSafety.IsReparseFree(full))
        {
            issues.Add(new(code, $"A valid {label} directory is required."));
            return null;
        }
        return full;
    }

    private static string? NormalizePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.IndexOf('\0') >= 0)
            return null;

        try
        {
            var full = Path.GetFullPath(raw.Trim());
            return full.Length <= MaxWindowsPathLength ? full : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private static bool IsX86Debugger(string path) =>
        Path.GetFileName(path).Equals("x32dbg.exe", StringComparison.OrdinalIgnoreCase);
}
