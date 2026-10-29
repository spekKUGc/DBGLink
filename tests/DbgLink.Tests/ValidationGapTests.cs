using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// Coverage-gap audit backfill: validation edges that had no pinning test.
/// Tests only APIs that exist in this worktree (no unfinished-src dependency).
/// All temp state is owned via <see cref="TempDir"/> (auto-deleted).
/// </summary>
public sealed class ValidationGapTests
{
    // ========================================================================================
    // LocalPathPolicy: trailing dot/space + device-with-extension + mixed separators
    // ========================================================================================

    [Theory]
    // Trailing dots/spaces are ignored by Windows: still the device.
    [InlineData(@"C:\temp\CON.")]
    [InlineData(@"C:\temp\NUL ")]
    [InlineData(@"C:\temp\COM1. ")]
    [InlineData(@"C:\temp\LPT9.")]
    // Device name with an extension / different case: still the device.
    [InlineData(@"c:\temp\con.txt")]
    [InlineData(@"C:\temp\AUX.log")]
    [InlineData(@"C:\temp\conout$.txt")]
    // Mixed separators split the same way: still the device.
    [InlineData("C:/temp/con.txt")]
    [InlineData(@"C:\temp/AUX.log")]
    [InlineData("C:/temp/COM1/x.exe")]
    public void LocalPathPolicy_DeviceSpellings_Rejected(string path)
        => Assert.False(LocalPathPolicy.IsSafeLocalPath(path));

    [Fact]
    public void LocalPathPolicy_PlainExePath_Accepted()
        => Assert.True(LocalPathPolicy.IsSafeLocalPath(@"C:\temp\app.exe"));

    // ========================================================================================
    // SetBreakpoint condition edge cases
    // ========================================================================================

    private static LocalMcpServer CreateServer(RecordingBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

    private static Dictionary<string, JsonElement> BpArgs(string field, string value)
        => new()
        {
            ["address"] = JsonSerializer.SerializeToElement("cip"),
            [field] = JsonSerializer.SerializeToElement(value),
        };

    [Theory]
    // Backslash is not a quote or control: valid expression text, reaches the bridge.
    [InlineData("condition", "a\\b")]
    [InlineData("condition", "eax == 1")]
    [InlineData("logText", "CIP={cip} \\ done")]
    [InlineData("logCondition", "eax != 0")]
    public async Task SetBreakpoint_AllowedCondition_ReachesBridge(string field, string value)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "SetBreakpoint", Arguments = BpArgs(field, value) },
            CancellationToken.None);
        // Reached the bridge (the stub shape may surface as isError; the
        // RequestCount proves no MCP-layer rejection happened).
        Assert.Equal(1, bridge.RequestCount);
    }

    [Fact]
    public async Task SetBreakpoint_256CharCondition_ReachesBridge()
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge);
        await server.CallToolAsync(
            new CallToolRequestParams { Name = "SetBreakpoint", Arguments = BpArgs("condition", new string('a', 256)) },
            CancellationToken.None);
        Assert.Equal(1, bridge.RequestCount);
    }

    [Theory]
    // C0 controls + DEL are banned by the schema pattern and IsSafeText.
    [InlineData("condition", "eax == 1\n")]
    [InlineData("condition", "eax\u007F== 1")]
    [InlineData("condition", "eax\u0001== 1")]
    [InlineData("logText", "bad\u007Ftext")]
    [InlineData("logCondition", "bad\u0001text")]
    public async Task SetBreakpoint_ControlChars_RejectedWithoutBridge(string field, string value)
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = "SetBreakpoint", Arguments = BpArgs(field, value) },
            CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task SetBreakpoint_257CharCondition_RejectedWithoutBridge()
    {
        var bridge = new RecordingBridge();
        using var server = CreateServer(bridge);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "SetBreakpoint",
                Arguments = BpArgs("condition", new string('a', 257)),
            },
            CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    // ========================================================================================
    // DBGLINK_REQUIRE_AUTH env precedence + legacy invalid-token config
    // ========================================================================================

    [Theory]
    // Recognized env values win over the file; unrecognized falls back to the file.
    [InlineData("1", false, true)]
    [InlineData("0", true, false)]
    [InlineData("maybe", false, false)]
    [InlineData("maybe", true, true)]
    public void RequireAuth_EnvPrecedence_OverFile(string? env, bool fileValue, bool expected)
    {
        using var tmp = TempDir.Create("dbglink-reqauth-");
        var path = Path.Combine(tmp, "config.json");
        File.WriteAllText(path, "{\"AuthToken\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"RequireAuthToken\":"
            + (fileValue ? "true" : "false") + "}");
        var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path,
            environment: name => name == "DBGLINK_REQUIRE_AUTH" ? env : null);
        Assert.Equal(expected, config.RequireAuthToken);
    }

    [Theory]
    // No file: recognized values apply, unrecognized keeps the secure default.
    [InlineData("0", false)]
    [InlineData("1", true)]
    [InlineData("maybe", true)]
    public void RequireAuth_EnvWithoutFile_FallsBackToDefault(string? env, bool expected)
    {
        using var tmp = TempDir.Create("dbglink-reqauth-");
        var path = Path.Combine(tmp, "config.json");
        var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path,
            environment: name => name == "DBGLINK_REQUIRE_AUTH" ? env : null);
        Assert.Equal(expected, config.RequireAuthToken);
    }

    [Fact]
    public void LegacyConfig_InvalidShortToken_LoadsAuthTrueWithFreshToken()
    {
        // A legacy config with an invalid short token and no flag must not
        // downgrade auth: the bad file is ignored, a fresh token is minted,
        // and auth stays required.
        using var tmp = TempDir.Create("dbglink-reqauth-");
        var path = Path.Combine(tmp, "config.json");
        File.WriteAllText(path, "{\"AuthToken\":\"short\"}");
        var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => null);
        Assert.True(config.RequireAuthToken);
        Assert.NotEqual("short", config.AuthToken);
        Assert.InRange(config.AuthToken.Length, 32, 512);
        Assert.DoesNotContain(config.AuthToken, char.IsControl);
    }

    // ========================================================================================
    // IsValidEndpointDirectory (device / UNC / control-char / overlong)
    // ========================================================================================

    private static bool IsValidEndpointDirectory(string value)
    {
        var method = typeof(AnalysisSessionRegistry).GetMethod(
            "IsValidEndpointDirectory", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (bool)method.Invoke(null, [value])!;
    }

    [Theory]
    [InlineData(@"C:\temp\CON")]
    [InlineData(@"C:\temp\NUL.txt")]
    [InlineData(@"\\server\share\dir")]
    [InlineData("C:\\temp\\bad\u0001dir")]
    public void IsValidEndpointDirectory_Hostile_Rejected(string value)
        => Assert.False(IsValidEndpointDirectory(value));

    [Fact]
    public void IsValidEndpointDirectory_Overlong_Rejected()
        => Assert.False(IsValidEndpointDirectory("C:\\" + new string('a', 32761)));

    [Fact]
    public void TryRegister_HostileEndpointDirectory_Rejected()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.False(registry.TryRegister(new("sess-1", "DbgLink.Control.42", @"C:\temp\CON")));
        Assert.False(registry.TryRegister(new("sess-1", "DbgLink.Control.42", @"\\server\share\dir")));
        // Only the built-in "default" session exists: nothing was registered.
        Assert.Equal(["default"], registry.ActiveIds);
    }

    // ========================================================================================
    // GhidraClient.ReadEndpoint hostile inputs return null
    // ========================================================================================

    private static object? ReadEndpoint(string path)
    {
        var method = typeof(GhidraClient).GetMethod(
            "ReadEndpoint", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return method.Invoke(null, [path]);
    }

    private static string WriteEndpoint(TempDir dir, string json)
    {
        var path = Path.Combine(dir, "ghidra-bridge-test.json");
        File.WriteAllText(path, json);
        return path;
    }

    private static string ValidEndpointJson(string host = "127.0.0.1", string token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        => "{\"host\":\"" + host + "\",\"port\":5001,\"protocolVersion\":1,\"token\":\"" + token + "\"}";

    [Fact]
    public void ReadEndpoint_ValidEndpoint_ReturnsNonNull()
    {
        using var dir = TempDir.Create("dbglink-endpoint-");
        Assert.NotNull(ReadEndpoint(WriteEndpoint(dir, ValidEndpointJson())));
    }

    [Fact]
    public void ReadEndpoint_NonLoopbackHost_ReturnsNull()
    {
        using var dir = TempDir.Create("dbglink-endpoint-");
        Assert.Null(ReadEndpoint(WriteEndpoint(dir, ValidEndpointJson(host: "0.0.0.0"))));
    }

    [Fact]
    public void ReadEndpoint_ShortToken_ReturnsNull()
    {
        using var dir = TempDir.Create("dbglink-endpoint-");
        Assert.Null(ReadEndpoint(WriteEndpoint(dir, ValidEndpointJson(token: "short"))));
    }

    [Fact]
    public void ReadEndpoint_Symlink_ReturnsNull()
    {
        using var dir = TempDir.Create("dbglink-endpoint-");
        var target = WriteEndpoint(dir, ValidEndpointJson());
        var link = Path.Combine(dir, "ghidra-bridge-link.json");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        // The reparse guard rejects the link even though it resolves to a
        // valid, self-owned endpoint file.
        Assert.Null(ReadEndpoint(link));
    }

    [Fact]
    public void ReadEndpoint_OtherUserOwnedFile_ReturnsNull()
    {
        if (!OperatingSystem.IsWindows())
            return;
        using var dir = TempDir.Create("dbglink-endpoint-");
        var path = WriteEndpoint(dir, ValidEndpointJson());
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier? original;
        try
        {
            original = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch { return; }
        try
        {
            try
            {
                var security = new FileInfo(path).GetAccessControl();
                security.SetOwner(system);
                new FileInfo(path).SetAccessControl(security);
            }
            catch { return; } // Transferring ownership needs privilege: skip.
            SecurityIdentifier? actual;
            try
            {
                actual = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            }
            catch { return; }
            if (actual is null || !actual.Equals(system))
                return; // The environment vetoed the transfer: skip.
            Assert.Null(ReadEndpoint(path));
        }
        finally
        {
            // Best-effort restore so TempDir cleanup is not wedged by ownership.
            try
            {
                if (original is not null)
                {
                    var security = new FileInfo(path).GetAccessControl();
                    security.SetOwner(original);
                    new FileInfo(path).SetAccessControl(security);
                }
            }
            catch { }
        }
    }

    // ========================================================================================
    // TelemetryFileSink.TryCreate on device/UNC dirs: null, never throws
    // ========================================================================================

    [Theory]
    [InlineData(@"\\server\share\dir")]
    [InlineData(@"C:\temp\CON")]
    [InlineData(@"C:\temp\NUL.txt")]
    [InlineData(@"C:\temp\dir:stream")]
    public void TelemetryFileSink_HostileDirectory_ReturnsNullWithoutThrow(string directory)
    {
        TelemetryFileSink? sink = null;
        var exception = Record.Exception(() =>
            sink = TelemetryFileSink.TryCreate(new ServerMetrics(), directory, _ => null));
        Assert.Null(exception);
        Assert.Null(sink);
    }
}
