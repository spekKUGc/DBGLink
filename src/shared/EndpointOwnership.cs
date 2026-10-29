using System.Security.Principal;

namespace DbgLink.Shared;

/// <summary>
/// Shared owner check for endpoint rendezvous files (Ghidra + native).
/// A file counts as ours when its owner SID is the current user, or the
/// BuiltinAdministrators group while the current process is elevated: an
/// elevated creator is recorded as Administrators, so strict equality
/// would reject our own files under elevation (and only there — a
/// non-admin cannot mint Administrators-owned files, and a file merely
/// moved into place still fails the elevation gate).
/// Known limits, do not generalize silently: owner SIDs from other admin
/// groups (Domain Admins, …) are still rejected, and the check-then-open
/// TOCTOU remains (this fix neither widens nor closes it).
/// </summary>
internal static class EndpointOwnership
{
    internal static bool IsOwnedByCurrentUser(SecurityIdentifier? owner)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                return false;
            using var currentIdentity = WindowsIdentity.GetCurrent();
            var current = currentIdentity.User;
            if (owner is not null && current is not null && owner.Equals(current))
                return true;
            return owner is not null &&
                owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) &&
                new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException or InvalidOperationException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
