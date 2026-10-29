using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class ServerCommandLineTests
{
    [Fact]
    public void ParseCommandLine_applies_defaults()
    {
        var options = Program.ParseCommandLine(Array.Empty<string>());

        Assert.Equal("DbgLink.Control", options.PipeName);
        Assert.Equal(ServerConfig.DefaultPort, options.Port);
        Assert.Null(options.ConfigPath);
        Assert.Null(options.PermissionOverrides.AllowAnnotation);
        Assert.Null(options.PermissionOverrides.AllowMutation);
        Assert.False(options.Help);
    }

    [Fact]
    public void ParseCommandLine_reads_all_supported_options()
    {
        var options = Program.ParseCommandLine(
            ["--pipe-name", "DbgLink.Control.42", "--port", "50400", "--config-path", "config.json", "--allow-annotation", "true", "--allow-mutation", "false"]);

        Assert.Equal("DbgLink.Control.42", options.PipeName);
        Assert.Equal(50400, options.Port);
        Assert.Equal("config.json", options.ConfigPath);
        Assert.True(options.PermissionOverrides.AllowAnnotation);
        Assert.False(options.PermissionOverrides.AllowMutation);
    }

    [Theory]
    [InlineData("--unknown")]
    [InlineData("--port")]
    [InlineData("--port", "0")]
    [InlineData("--allow-mutation", "maybe")]
    public void ParseCommandLine_rejects_invalid_arguments(params string[] args)
    {
        Assert.Throws<ArgumentException>(() => Program.ParseCommandLine(args));
    }

    [Fact]
    public void ParseCommandLine_rejects_duplicate_options()
    {
        Assert.Throws<ArgumentException>(() =>
            Program.ParseCommandLine(["--port", $"{ServerConfig.DefaultPort}", "--port", "50401"]));
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("/?")]
    public void ParseCommandLine_accepts_help_aliases(string argument)
    {
        var options = Program.ParseCommandLine([argument]);

        Assert.True(options.Help);
    }

    [Fact]
    public async Task Main_returns_success_for_help_without_starting_the_server()
    {
        var exitCode = await Program.Main(["--help"]);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task Main_returns_argument_error_code_for_invalid_arguments()
    {
        var exitCode = await Program.Main(["--port"]);

        Assert.Equal(2, exitCode);
    }
}
