using DbgLink.Launcher.Core;
using Xunit;

namespace DbgLink.Tests;

public sealed class GhidraSessionFidbTests : IDisposable
{
    private readonly string _tempDirectory;

    public GhidraSessionFidbTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "dbglink_fidb_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDirectory))
                Directory.Delete(_tempDirectory, recursive: true);
        }
        catch
        {
        }
    }

    [Fact]
    public void BuildImportArguments_NoFidbAnalyze_MatchesLegacyOrder()
    {
        var args = GhidraSession.BuildImportArguments(@"C:\proj", "DbgLinkSession", @"C:\in.exe", true, null);

        Assert.Equal(["C:\\proj", "DbgLinkSession", "-import", "C:\\in.exe", "-overwrite"], args);
    }

    [Fact]
    public void BuildImportArguments_NoFidbNoAnalysis_MatchesLegacyOrder()
    {
        var args = GhidraSession.BuildImportArguments(@"C:\proj", "DbgLinkSession", @"C:\in.exe", false, null);

        Assert.Equal(["C:\\proj", "DbgLinkSession", "-import", "C:\\in.exe", "-overwrite", "-noanalysis"], args);
    }

    [Fact]
    public void BuildImportArguments_WithFidb_AppendsPreScript()
    {
        var args = GhidraSession.BuildImportArguments(@"C:\proj", "DbgLinkSession", @"C:\in.exe", true, @"C:\fid\lib.fidb");

        Assert.Equal(
            ["C:\\proj", "DbgLinkSession", "-import", "C:\\in.exe", "-overwrite",
                "-preScript", "ApplyFidb.java", "C:\\fid\\lib.fidb"],
            args);
    }

    [Fact]
    public void Import_timeout_env_override_is_bounded_and_honest()
    {
        Assert.Equal(TimeSpan.FromMinutes(10), GhidraSession.ResolveImportTimeout(_ => null));
        Assert.Equal(TimeSpan.FromMinutes(10), GhidraSession.ResolveImportTimeout(_ => "bogus"));
        Assert.Equal(TimeSpan.FromMinutes(1), GhidraSession.ResolveImportTimeout(_ => "1000"));
        Assert.Equal(TimeSpan.FromMinutes(10), GhidraSession.ResolveImportTimeout(_ => "600000"));
        Assert.Equal(TimeSpan.FromMinutes(15), GhidraSession.ResolveImportTimeout(_ => "3600000"));
    }

    [Fact]
    public void Startup_timeout_is_import_budget_plus_two_minutes()
    {
        Assert.Equal(TimeSpan.FromMinutes(12), GhidraSession.ResolveStartupTimeout(_ => null));
        Assert.Equal(TimeSpan.FromMinutes(3), GhidraSession.ResolveStartupTimeout(_ => "60000"));
        Assert.Equal(TimeSpan.FromMinutes(17), GhidraSession.ResolveStartupTimeout(_ => "3600000"));
    }

    [Fact]
    public void Fast_analysis_is_opt_in_and_accepts_boolean_spellings()
    {
        Assert.False(GhidraSession.ResolveFastAnalysis(_ => null));
        Assert.False(GhidraSession.ResolveFastAnalysis(_ => "0"));
        Assert.False(GhidraSession.ResolveFastAnalysis(_ => "no"));
        Assert.True(GhidraSession.ResolveFastAnalysis(_ => "1"));
        Assert.True(GhidraSession.ResolveFastAnalysis(_ => "true"));
        Assert.True(GhidraSession.ResolveFastAnalysis(_ => "TRUE"));
    }

    [Fact]
    public void ResolveFidbSpec_Unset_ReturnsNull()
    {
        Assert.Null(GhidraSession.ResolveFidbSpec(_ => null));
    }

    [Fact]
    public void ResolveFidbSpec_Blank_ReturnsNull()
    {
        Assert.Null(GhidraSession.ResolveFidbSpec(_ => "   "));
    }

    [Fact]
    public void ResolveFidbSpec_MissingPath_ReturnsNull()
    {
        var missing = Path.Combine(_tempDirectory, "missing.fidb");

        Assert.Null(GhidraSession.ResolveFidbSpec(_ => missing));
    }

    [Fact]
    public void ResolveFidbSpec_UnsafeCharacters_ReturnsNull()
    {
        Assert.Null(GhidraSession.ResolveFidbSpec(_ => @"C:\fid%unsafe\lib.fidb"));
    }

    [Fact]
    public void ResolveFidbSpec_ExistingFile_ReturnsPath()
    {
        var file = Path.Combine(_tempDirectory, "lib.fidb");
        File.WriteAllBytes(file, [1, 2, 3]);

        Assert.Equal(file, GhidraSession.ResolveFidbSpec(_ => file));
    }

    [Fact]
    public void ResolveFidbSpec_ExistingDirectory_ReturnsPath()
    {
        var directory = Path.Combine(_tempDirectory, "fidbs");
        Directory.CreateDirectory(directory);

        Assert.Equal(directory, GhidraSession.ResolveFidbSpec(_ => directory));
    }

    [Fact]
    public void ResolveFidbSpec_MixedEntries_KeepsOnlyExisting()
    {
        var file = Path.Combine(_tempDirectory, "lib.fidb");
        File.WriteAllBytes(file, [1, 2, 3]);
        var missing = Path.Combine(_tempDirectory, "missing.fidb");

        Assert.Equal(file, GhidraSession.ResolveFidbSpec(_ => missing + ";" + file + " ; "));
    }
}
