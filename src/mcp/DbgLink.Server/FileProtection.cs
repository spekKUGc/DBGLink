using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DbgLink.Server;

/// <summary>
/// Current-user-only file/directory protection. Windows ACL plus Unix
/// 0600/0700; best-effort, never throws.
///
/// The config file protection lives here too (the server used to keep a
/// second copy of the same ACL logic, which could drift).
/// </summary>
internal static class FileProtection
{
    /// <summary>
    /// Restricts <paramref name="path"/> to the current user.
    /// <paramref name="onError"/> receives the failure reason so a caller
    /// that wants to report the problem (the config path writes to stderr)
    /// can do so without duplicating the ACL code.
    /// </summary>
    internal static void ProtectFile(string path, Action<string>? onError = null)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var currentIdentity = WindowsIdentity.GetCurrent();
                var identity = currentIdentity.User
                    ?? throw new InvalidOperationException("The current Windows identity is unavailable.");
                var security = new FileSecurity();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    identity,
                    FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.Synchronize,
                    AccessControlType.Allow));
                new FileInfo(path).SetAccessControl(security);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or SecurityException or InvalidOperationException or PlatformNotSupportedException)
            {
                onError?.Invoke(exception.GetType().Name);
            }
            return;
        }
        try
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or SecurityException or InvalidOperationException or PlatformNotSupportedException)
        {
            onError?.Invoke(exception.GetType().Name);
        }
    }

    /// <summary>
    /// Restricts <paramref name="path"/> to the current user.
    /// <paramref name="onError"/> receives the failure reason so a caller
    /// that wants to report the problem (the config path writes to stderr)
    /// can do so without duplicating the ACL code.
    /// </summary>
    internal static void ProtectDirectory(string path, Action<string>? onError = null)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var currentIdentity = WindowsIdentity.GetCurrent();
                var identity = currentIdentity.User
                    ?? throw new InvalidOperationException("The current Windows identity is unavailable.");
                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    identity,
                    FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.Synchronize
                        | FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.ListDirectory,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                new DirectoryInfo(path).SetAccessControl(security);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or SecurityException or InvalidOperationException or PlatformNotSupportedException)
            {
                onError?.Invoke(exception.GetType().Name);
            }
            return;
        }
        try
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or SecurityException or InvalidOperationException or PlatformNotSupportedException)
        {
            onError?.Invoke(exception.GetType().Name);
        }
    }
}
