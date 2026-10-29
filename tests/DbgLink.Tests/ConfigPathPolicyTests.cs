extern alias Server;
using DbgLink.Server;
using ConfigPath = Server::DbgLink.Shared.DbgLinkConfigPath;

namespace DbgLink.Tests;

/// <summary>
/// OD-9: an operator-provided config/checkpoint override must pass the
/// colon/ADS + reparse policy at the source (<see cref="ConfigPath"/>).
/// The computed default stays unchecked and a missing leaf stays accepted
/// (first run). No process-wide environment mutation: the injectable reader
/// func covers every case.
/// </summary>
public sealed class ConfigPathPolicyTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankConfigPath_FallsBackToDefault(string? value)
    {
        var resolved = ConfigPath.GetPath(_ => value);
        Assert.EndsWith(Path.Combine("DBGLink", "mcp_config.json"), resolved, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingLeafConfigPath_IsAccepted()
    {
        var leaf = Path.Combine(Path.GetTempPath(), "dbglink-od9-" + Guid.NewGuid().ToString("N"), "mcp_config.json");
        Assert.Equal(Path.GetFullPath(leaf), ConfigPath.GetPath(_ => leaf));
    }

    [Theory]
    [InlineData(@"C:\tmp\mcp_config.json:stream")]
    [InlineData(@"C:\tm:p\mcp_config.json")]
    public void UnsafeConfigPath_ThrowsNamingVariable(string raw)
    {
        var error = Assert.Throws<ArgumentException>(() => ConfigPath.GetPath(_ => raw));
        Assert.Equal(ConfigPath.ConfigPathEnvironmentVariable, error.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void BlankCheckpointPath_FallsBackToDefault(string? value)
    {
        var resolved = ConfigPath.GetCheckpointPath(_ => value);
        Assert.EndsWith(Path.Combine("DBGLink", "checkpoints.json"), resolved, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingLeafCheckpointPath_IsAccepted()
    {
        var leaf = Path.Combine(Path.GetTempPath(), "dbglink-od9-" + Guid.NewGuid().ToString("N"), "checkpoints.json");
        Assert.Equal(Path.GetFullPath(leaf), ConfigPath.GetCheckpointPath(_ => leaf));
    }

    [Fact]
    public void UnsafeCheckpointPath_ThrowsNamingVariable()
    {
        var error = Assert.Throws<ArgumentException>(
            () => ConfigPath.GetCheckpointPath(_ => @"C:\tmp\checkpoints.json:stream"));
        Assert.Equal(ConfigPath.CheckpointPathEnvironmentVariable, error.ParamName);
    }

    [Fact]
    public void ServerConfigLoad_UnsafeEnvPath_FailsClosed()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            ServerConfig.Load(12345, environment: name =>
                name == ConfigPath.ConfigPathEnvironmentVariable ? @"C:\tmp\mcp_config.json:stream" : null));
        Assert.Contains("invalid", error.Message, StringComparison.OrdinalIgnoreCase);
    }
}
