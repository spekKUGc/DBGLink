extern alias Server;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using ServerShared = Server::DbgLink.Shared.EndpointOwnership;

namespace DbgLink.Tests;

/// <summary>
/// EndpointOwnership truth table: a rendezvous file counts as ours when its
/// owner is the current user, or BuiltinAdministrators while elevated
/// (elevated creators are recorded as Administrators). Anything else —
/// SYSTEM, Users, other groups, null — is rejected on every elevation
/// level. Expectations that depend on the runner's elevation are computed
/// live, so the table is deterministic elevated or not.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EndpointOwnershipTests
{
    private static bool IsElevated() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private static string CurrentUserSid() => WindowsIdentity.GetCurrent().User?.Value ?? "";

    public static TheoryData<string, bool> OwnershipCases()
    {
        var elevated = IsElevated();
        return new TheoryData<string, bool>
        {
            { CurrentUserSid(), true },
            { "S-1-5-32-544", elevated },
            { "S-1-5-18", false },
            { "S-1-5-32-545", false },
        };
    }

    [Theory]
    [MemberData(nameof(OwnershipCases))]
    public void OwnerSid_MapsToExpectedVerdict(string sid, bool expected)
    {
        Assert.False(string.IsNullOrWhiteSpace(sid), "could not read the current user SID");
        Assert.Equal(expected, ServerShared.IsOwnedByCurrentUser(new SecurityIdentifier(sid)));
    }

    [Fact]
    public void NullOwner_IsRejected()
    {
        Assert.False(ServerShared.IsOwnedByCurrentUser(null));
    }

    [Fact]
    public void TempEndpointFile_ReadEndpointAcceptsIt()
    {
        // End-to-end through the real private ReadEndpoint: a file this
        // process just created in Temp must resolve. Pre-fix this failed
        // under an elevated runner (owner Administrators != user SID).
        using var dir = TempDir.Create("dbglink-owned-");
        var path = Path.Combine(dir, "ghidra-bridge-owned.json");
        File.WriteAllText(path,
            "{\"host\":\"127.0.0.1\",\"port\":5001,\"protocolVersion\":1,\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
        var method = typeof(DbgLink.Server.GhidraClient).GetMethod(
            "ReadEndpoint", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        Assert.NotNull(method.Invoke(null, [path]));
    }
}
