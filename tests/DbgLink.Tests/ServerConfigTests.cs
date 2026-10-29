using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class ServerConfigTests
{
    [Theory]
    [InlineData(null, null, true)]
    [InlineData("", null, true)]
    [InlineData(",\"AllowAnnotation\":false,\"AllowMutation\":false", null, false)]
    [InlineData(",\"AllowAnnotation\":false,\"AllowMutation\":false", true, true)]
    [InlineData("", false, false)]
    public void Load_defaults_to_full_access_and_respects_explicit_overrides(
        string? permissionsJson, bool? permissionOverride, bool expected)
    {
        var path = CreateTemporaryPath();
        try
        {
            if (permissionsJson is not null)
                File.WriteAllText(path, "{\"AuthToken\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"" + permissionsJson + "}");
            var config = ServerConfig.Load(ServerConfig.DefaultPort,
                new ServerPermissionOverrides(permissionOverride, permissionOverride),
                configPath: path, environment: _ => null);
            Assert.Equal(expected, config.AllowAnnotation);
            Assert.Equal(expected, config.AllowMutation);
        }
        finally
        {
            DeleteTemporaryPath(path);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65_536)]
    public void Load_rejects_an_invalid_port_before_reading_or_persisting_config(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ServerConfig.Load(port, environment: _ => null));
    }

    [Fact]
    public void Load_replaces_a_config_with_duplicate_properties()
    {
        var path = CreateTemporaryPath();
        try
        {
            const string firstToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            const string secondToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            File.WriteAllText(
                path,
                $"{{\"AuthToken\":\"{firstToken}\",\"AuthToken\":\"{secondToken}\"}}");

            var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => null);

            Assert.NotEqual(firstToken, config.AuthToken);
            Assert.NotEqual(secondToken, config.AuthToken);
            Assert.InRange(config.AuthToken.Length, 32, 512);
            Assert.DoesNotContain(config.AuthToken, char.IsControl);
        }
        finally
        {
            DeleteTemporaryPath(path);
        }
    }

    [Fact]
    public void Load_replaces_an_oversized_config()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(path, new string('x', 64 * 1024 + 1));

            var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => null);

            Assert.InRange(config.AuthToken.Length, 32, 512);
            Assert.DoesNotContain(config.AuthToken, char.IsControl);
        }
        finally
        {
            DeleteTemporaryPath(path);
        }
    }

    [Fact]
    public void Load_replaces_a_config_with_removed_transport_properties()
    {
        var path = CreateTemporaryPath();
        try
        {
            const string token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            File.WriteAllText(
                path,
                $"{{\"AuthToken\":\"{token}\",\"MaxSessions\":1,\"SessionTtlSeconds\":30,\"SseHeartbeatSeconds\":15}}");

            var config = ServerConfig.Load(ServerConfig.DefaultPort, configPath: path, environment: _ => token);
            var persisted = File.ReadAllText(path);

            Assert.Equal(token, config.AuthToken);
            Assert.DoesNotContain("MaxSessions", persisted);
            Assert.DoesNotContain("SessionTtlSeconds", persisted);
            Assert.DoesNotContain("SseHeartbeatSeconds", persisted);
        }
        finally
        {
            DeleteTemporaryPath(path);
        }
    }

    private static string CreateTemporaryPath()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-config-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, "config.json");
    }

    private static void DeleteTemporaryPath(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory is not null && Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }
}
