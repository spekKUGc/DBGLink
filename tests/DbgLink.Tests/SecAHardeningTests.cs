using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>WAVE SEC-A hardening regression: debug-target path gate
/// (SwitchDebugger shared it via OpenDebugTarget; the single now covers it),
/// UNC/ADS/device rejection, breakpoint quote gate, auth-default-true.</summary>
public sealed class SecAHardeningTests
{
    private sealed class CountingControl : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public int Calls;
        public string? LastMethod;
        public Task<string> OpenFileAsync(string path, CancellationToken token)
            => Task.FromResult("{\"ok\":true}");
        public Task<string> OpenFileAsync(string path, bool analyze, CancellationToken token)
            => Task.FromResult("{\"ok\":true}");
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token)
        {
            Interlocked.Increment(ref Calls);
            LastMethod = method;
            return Task.FromResult("{\"ok\":true,\"result\":{\"analysisId\":\"default\",\"nativePipeName\":\"DbgLink.Control.42\",\"changed\":true,\"architecture\":\"x64\"}}");
        }
    }

    private static LocalMcpServer CreateServer(CountingControl control, RecordingBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge, new NullGhidra(), control);

    private static Dictionary<string, JsonElement> Args(object o)
        => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(JsonSerializer.Serialize(o))!;

    // #1: debug-target path validated before pipe traffic (OpenDebugTarget
    // shares the Switch gate; the SwitchDebugger single is purged).
    // #2: UNC/ADS/device rejected for debug target + workDir + Ghidra file.
    [Theory]
    [InlineData(@"\\server\share\evil.exe")]
    [InlineData(@"C:\temp\evil.exe:stream")]
    [InlineData(@"C:\temp\CON.exe")]
    [InlineData(@"C:\NUL.exe")]
    [InlineData(@"C:\COM1\evil.exe")]
    [InlineData(@"C:\temp\evil.exe::$DATA")]
    public async Task OpenDebugTarget_HostilePaths_RejectedWithoutBackend(string path)
    {
        var bridge = new RecordingBridge();
        var control = new CountingControl();
        using var server = CreateServer(control, bridge);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = Args(new { path }),
        }, CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Contains("debug_target_invalid", Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text);
        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, control.Calls);
    }

    [Fact]
    public async Task OpenDebugTarget_HostileWorkDir_RejectedWithoutBackend()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dbglink-sec-a-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, "app.exe");
        File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });
        try
        {
            var bridge = new RecordingBridge();
            using var server = CreateServer(new CountingControl(), bridge);
            foreach (var workDir in new[] { @"\\server\share\dir", @"C:\temp\CON", @"C:\temp\dir:stream" })
            {
                var result = await server.CallToolAsync(new CallToolRequestParams
                {
                    Name = "OpenDebugTarget",
                    Arguments = Args(new { path = exe, workDir }),
                }, CancellationToken.None);
                Assert.True(result.IsError);
                Assert.Contains("debug_target_invalid", Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text);
            }
            Assert.Equal(0, bridge.RequestCount);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(@"\\server\share\evil.exe")]
    [InlineData(@"C:\temp\evil.exe:stream")]
    [InlineData(@"C:\temp\CON.exe")]
    [InlineData(@"C:\NUL.exe")]
    public async Task GhidraTarget_HostilePaths_Rejected(string path)
    {
        var client = new GhidraControlClient("DbgLink.GhidraControl.test123", new string('a', 32));
        var response = await client.OpenFileAsync(path, CancellationToken.None);
        Assert.Contains("target_rejected", response);
    }

    [Fact]
    public void LocalPathPolicy_RejectsUncAdsDevice_RequiresDrive()
    {
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"\\server\share\a.exe"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"//server/share/a.exe"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"C:\a.exe:stream"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"C:\CON"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"C:\foo\NUL.txt"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"C:\COM1\a.exe"));
        Assert.False(LocalPathPolicy.IsSafeLocalPath(@"relative\a.exe"));
        Assert.True(LocalPathPolicy.HasLocalDriveRoot(@"C:\a.exe"));
        Assert.True(LocalPathPolicy.IsUncPath(@"\\server\share\a.exe"));
    }

    // #3: breakpoint quote gate fails fast at MCP layer.
    [Theory]
    [InlineData("condition", "eax == \"1\"")]
    [InlineData("logText", "CIP=\"{cip}\"")]
    [InlineData("logCondition", "eax != \"0\"")]
    public async Task SetBreakpoint_QuoteInjection_RejectedAtSchemaWithoutBridge(string field, string value)
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var args = new Dictionary<string, JsonElement>
        {
            ["address"] = JsonSerializer.SerializeToElement("cip"),
            [field] = JsonSerializer.SerializeToElement(value),
        };
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = "SetBreakpoint", Arguments = args }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Theory]
    [InlineData("condition", "eax == 1")]
    [InlineData("logText", "CIP={cip} RAX={rax}")]
    [InlineData("logCondition", "eax != 0")]
    public async Task SetBreakpoint_ValidCondition_ReachesBridge(string field, string value)
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                [field] = JsonSerializer.SerializeToElement(value),
            },
        }, CancellationToken.None);
        // Validation passed (reached the bridge); the stub bridge shape may
        // surface as isError, but RequestCount proves no MCP-layer rejection.
        Assert.Equal(1, bridge.RequestCount);
    }

    // #4: missing RequireAuthToken loads true.
    [Fact]
    public void MissingRequireAuthToken_LoadsTrue()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dbglink-sec-a-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "config.json");
        try
        {
            File.WriteAllText(path, "{\"AuthToken\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
            var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => null);
            Assert.True(config.RequireAuthToken);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExplicitRequireAuthToken_RoundTrips(bool value)
    {
        var dir = Path.Combine(Path.GetTempPath(), "dbglink-sec-a-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "config.json");
        try
        {
            File.WriteAllText(path, "{\"AuthToken\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"RequireAuthToken\":" + (value ? "true" : "false") + "}");
            var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => null);
            Assert.Equal(value, config.RequireAuthToken);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void FreshConfig_DefaultsToAuthTrue()
    {
        var config = new ServerConfig { Port = ServerConfig.DefaultPort };
        Assert.True(config.RequireAuthToken);
    }
}
