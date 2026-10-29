using System.Security.AccessControl;
using System.Security.Principal;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Owns the launcher's per-run temporary root: every <c>GhidraSession</c> of
/// one toolkit run nests beneath a single <c>DbgLink-Run-*</c> directory that
/// the coordinator removes on shutdown (success and failure paths). All
/// deletions are containment-checked (under %TEMP%, launcher-owned leaf
/// names), reparse-checked, and never follow links.
/// </summary>
internal static class LauncherTempRoot
{
    internal const string RunRootPrefix = "DbgLink-Run-";
    internal const string SessionRootPrefix = "DbgLink-Ghidra-Launcher-";
    private const int RunRootHexChars = 16;

    internal static string CreateRunRoot()
    {
        string tempRoot;
        try
        {
            tempRoot = Path.GetFullPath(Path.GetTempPath());
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new InvalidOperationException("The Windows temporary path is unavailable.", exception);
        }

        var root = Path.Combine(tempRoot, RunRootPrefix + Guid.NewGuid().ToString("N")[..RunRootHexChars]);
        if (!IsOwnedRunRoot(root))
            throw new InvalidOperationException("The launcher temporary root escaped its owned directory.");
        if (!ProcessLauncher.IsCommandArgumentSafe(root))
            throw new InvalidOperationException("The Windows temporary path may not contain percent signs or exclamation marks for a launcher session.");

        try
        {
            Directory.CreateDirectory(root);
            if (!PathSafety.IsReparseFree(root))
            {
                TryDeleteTree(root);
                throw new InvalidOperationException("The launcher temporary root must not contain reparse points.");
            }
            return root;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException("The launcher temporary root could not be created.", exception);
        }
    }

    internal static bool IsOwnedRunRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            var tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase))
                return false;
            var leaf = Path.GetFileName(full.TrimEnd(Path.DirectorySeparatorChar));
            return leaf is not null &&
                leaf.StartsWith(RunRootPrefix, StringComparison.Ordinal) &&
                leaf.Length == RunRootPrefix.Length + RunRootHexChars &&
                leaf[(RunRootPrefix.Length)..].All(character =>
                    char.IsAsciiHexDigit(character));
        }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    internal static bool IsOwnedSessionRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            var tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase))
                return false;
            var leaf = Path.GetFileName(full.TrimEnd(Path.DirectorySeparatorChar));
            return leaf is not null &&
                leaf.StartsWith(SessionRootPrefix, StringComparison.Ordinal) &&
                leaf.Length > SessionRootPrefix.Length;
        }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    /// <summary>
    /// Deletes an owned tree with retries. Refuses foreign paths; never
    /// follows reparse points (links are removed, not traversed).
    /// </summary>
    internal static bool TryDeleteTree(string? path, int retries = 100, int delayMilliseconds = 100)
        => TryDeleteTreeAsync(path, retries, delayMilliseconds, CancellationToken.None)
            .GetAwaiter().GetResult();

    internal static async Task<bool> TryDeleteTreeAsync(
        string? path,
        int retries = 100,
        int delayMilliseconds = 100,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            (!IsOwnedRunRoot(path) && !IsOwnedSessionRoot(path)))
            return false;

        var attempt = 0;
        while (true)
        {
            try
            {
                if (!Directory.Exists(path))
                    return !File.Exists(path);
                if (!PathSafety.IsReparseFree(path))
                    return false;
                DeleteTreeOnce(path);
                return !Directory.Exists(path) && !File.Exists(path);
            }
            catch (DirectoryNotFoundException)
            {
                return true;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            if (++attempt >= retries)
                return !Directory.Exists(path) && !File.Exists(path);
            await Task.Delay(delayMilliseconds, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Single-pass recursive delete of a launcher-owned directory. Clears
    /// read-only attributes (a stale read-only bit otherwise leaks the whole
    /// tree), repairs owner-only DACLs that lack DELETE (the Ghidra endpoint
    /// file carries such a hardened ACL), and removes reparse links without
    /// following them.
    /// </summary>
    internal static void DeleteTreeOnce(string root)
    {
        foreach (var file in Directory.EnumerateFiles(root))
            DeleteFileOnce(file);

        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            var attributes = File.GetAttributes(directory);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                // Non-recursive: removes the junction/symlink itself without
                // touching (or following to) its target.
                Directory.Delete(directory, recursive: false);
            }
            else
            {
                DeleteTreeOnce(directory);
            }
        }

        var rootAttributes = File.GetAttributes(root);
        if ((rootAttributes & FileAttributes.ReparsePoint) == 0)
        {
            if ((rootAttributes & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(root, rootAttributes & ~FileAttributes.ReadOnly);
            try
            {
                Directory.Delete(root, recursive: false);
            }
            catch (UnauthorizedAccessException)
            {
                // A hardened DACL on an owned directory (same shape as the
                // endpoint file below): re-grant the current user and retry
                // once before the outer retry loop classifies the failure.
                TryRepairDirectoryAccess(root);
                Directory.Delete(root, recursive: false);
            }
        }
        else
        {
            Directory.Delete(root, recursive: false);
        }
    }

    private static void DeleteFileOnce(string file)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(file);
        }
        catch (UnauthorizedAccessException)
        {
            // Attributes themselves are unreadable: never assume a regular
            // file (a DACL repair could follow a link to its target), so only
            // unlink and let the outer retry surface persistent failures.
            File.Delete(file);
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            // File.Delete on a link removes the link, never its target.
            // Never repair a link: SetAccessControl would follow it.
            File.Delete(file);
            return;
        }

        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            try
            {
                File.SetAttributes(file, attributes & ~FileAttributes.ReadOnly);
            }
            catch (UnauthorizedAccessException)
            {
                TryRepairFileAccess(file);
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
            }
        }

        try
        {
            File.Delete(file);
        }
        catch (UnauthorizedAccessException)
        {
            TryRepairFileAccess(file);
            File.Delete(file);
        }
    }

    /// <summary>
    /// Re-grants the current user full control over one launcher-owned regular
    /// file, then the caller retries the delete. Repairs the hardened
    /// owner-only DACL the Ghidra bridge applies to its endpoint file (which
    /// omits DELETE, so even the owner cannot remove it): the owner implicitly
    /// holds WRITE_DAC and may always re-grant itself, so this widens nothing
    /// beyond what the owner already has. Refuses reparse points (repair would
    /// follow the link) and swallows every failure — the caller retries and
    /// the outer loop still reports an unrecoverable tree.
    /// </summary>
    private static void TryRepairFileAccess(string file)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                return;
            var attributes = File.GetAttributes(file);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) != 0)
                return;
            var identity = WindowsIdentity.GetCurrent().User;
            if (identity is null)
                return;
            var security = new FileInfo(file).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                identity,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            new FileInfo(file).SetAccessControl(security);
        }
        catch (Exception exception) when (exception is IOException or
            UnauthorizedAccessException or ArgumentException or NotSupportedException or
            InvalidOperationException or PlatformNotSupportedException or
            IdentityNotMappedException)
        {
        }
    }

    private static void TryRepairDirectoryAccess(string directory)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                return;
            var attributes = File.GetAttributes(directory);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) == 0)
                return;
            var identity = WindowsIdentity.GetCurrent().User;
            if (identity is null)
                return;
            var security = new DirectoryInfo(directory).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                identity,
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(security);
        }
        catch (Exception exception) when (exception is IOException or
            UnauthorizedAccessException or ArgumentException or NotSupportedException or
            InvalidOperationException or PlatformNotSupportedException or
            IdentityNotMappedException)
        {
        }
    }
}
