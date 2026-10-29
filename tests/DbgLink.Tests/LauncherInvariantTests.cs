using DbgLink.Launcher.Core;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class LauncherInvariantTests
{
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void Server_spec_enables_all_permissions_unless_readonly_is_explicit(bool readOnly, bool expected)
    {
        var plan = CreatePlan();
        if (readOnly)
            plan = plan with { Settings = plan.Settings with { Permissions = LauncherPermissionProfile.ReadOnly } };
        var spec = LauncherPlanner.CreateServerSpec(plan, 42);
        var options = Program.ParseCommandLine(spec.Arguments.ToArray());
        Assert.Equal(expected, options.PermissionOverrides.AllowAnnotation);
        Assert.Equal(expected, options.PermissionOverrides.AllowMutation);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Manual_target_requires_a_file(string? input)
    {
        var result = LauncherPlanner.Plan(new LauncherSettings("", "", "", ReverseMode.ChooseFile, input));
        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "input_file");
        var llmResult = LauncherPlanner.Plan(new LauncherSettings("", "", "", ReverseMode.LetLlmChoose, input));
        Assert.DoesNotContain(llmResult.Issues, issue => issue.Code == "input_file");
    }

    [Fact]
    public void Pipe_name_rejects_nonpositive_process_ids()
    {
        var plan = CreatePlan();
        Assert.Throws<ArgumentOutOfRangeException>(() => plan.PipeNameFor(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => plan.PipeNameFor(-1));
    }

    [Fact]
    public void Debugger_spec_requires_resolved_architecture()
    {
        var plan = CreatePlan();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            LauncherPlanner.CreateDebuggerSpec(plan, DebuggerArchitecture.Auto, null));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            LauncherPlanner.CreateDebuggerSpec(plan, (DebuggerArchitecture)99, null));
    }

    [Fact]
    public void Planner_rejects_unknown_mode_and_architecture_values()
    {
        var result = LauncherPlanner.Plan(new LauncherSettings(
            "",
            "",
            "",
            (ReverseMode)99,
            null,
            Debugger: (DebuggerArchitecture)99));

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "invalid_reverse_mode");
        Assert.Contains(result.Issues, issue => issue.Code == "invalid_debugger_architecture");
    }

    [Fact]
    public void Planner_reports_an_invalid_input_path_instead_of_throwing()
    {
        var result = LauncherPlanner.Plan(new LauncherSettings(
            "",
            "",
            "",
            ReverseMode.ChooseFile,
            "\0invalid",
            Debugger: DebuggerArchitecture.Auto));

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "input_file");
    }

    [Fact]
    public void Diagnostics_truncation_does_not_split_a_surrogate_pair()
    {
        var message = new string('x', 2_047) + "😀tail";

        var result = ToolkitDiagnostics.Sanitize(message);

        Assert.Equal(new string('x', 2_047) + "…", result);
        Assert.DoesNotContain(result, char.IsHighSurrogate);
        Assert.DoesNotContain(result, char.IsLowSurrogate);
    }

    [Theory]
    [InlineData(DebuggerArchitecture.X64, true)]
    [InlineData(DebuggerArchitecture.X64, false)]
    [InlineData(DebuggerArchitecture.X86, true)]
    [InlineData(DebuggerArchitecture.X86, false)]
    public void Planner_validates_the_secondary_plugin_beside_its_debugger(
        DebuggerArchitecture primaryArchitecture, bool secondaryPluginInstalled)
    {
        var root = Path.Combine(Path.GetTempPath(), "dbglink-planner-" + Guid.NewGuid().ToString("N"));
        var x64Directory = Path.Combine(root, "x64dbg");
        var x32Directory = Path.Combine(root, "x32dbg");
        var ghidraHome = Path.Combine(root, "ghidra");
        var javaHome = Path.Combine(root, "jdk-21");
        try
        {
            Directory.CreateDirectory(Path.Combine(x64Directory, "plugins"));
            Directory.CreateDirectory(Path.Combine(x32Directory, "plugins"));
            Directory.CreateDirectory(Path.Combine(ghidraHome, "Ghidra"));
            Directory.CreateDirectory(Path.Combine(ghidraHome, "support"));
            Directory.CreateDirectory(Path.Combine(javaHome, "bin"));
            File.WriteAllText(Path.Combine(x64Directory, "x64dbg.exe"), "x64");
            File.WriteAllText(Path.Combine(x32Directory, "x32dbg.exe"), "x32");
            if (primaryArchitecture == DebuggerArchitecture.X64 || secondaryPluginInstalled)
                File.WriteAllText(Path.Combine(x64Directory, "plugins", "DbgLink.dp64"), "x64 plugin");
            File.WriteAllText(Path.Combine(x64Directory, "plugins", "DbgLink.Server.exe"), "server");
            File.WriteAllText(Path.Combine(x64Directory, "plugins", "GhidraBridge.zip"), "zip");
            if (primaryArchitecture == DebuggerArchitecture.X86 || secondaryPluginInstalled)
                File.WriteAllText(Path.Combine(x32Directory, "plugins", "DbgLink.dp32"), "x32 plugin");
            File.WriteAllText(Path.Combine(ghidraHome, "Ghidra", "application.properties"), "app");
            File.WriteAllText(Path.Combine(ghidraHome, "ghidraRun.bat"), "run");
            File.WriteAllText(Path.Combine(ghidraHome, "support", "analyzeHeadless.bat"), "headless");
            File.WriteAllText(Path.Combine(javaHome, "bin", "java.exe"), "java");
            File.WriteAllText(Path.Combine(javaHome, "release"), "JAVA_VERSION=\"21.0.1\"\n");

            var result = LauncherPlanner.Plan(
                new LauncherSettings(
                    Path.Combine(x64Directory, "x64dbg.exe"),
                    Path.Combine(x32Directory, "x32dbg.exe"),
                    ghidraHome,
                    ReverseMode.LetLlmChoose,
                    null,
                    PluginDirectory: Path.Combine(primaryArchitecture == DebuggerArchitecture.X64 ? x64Directory : x32Directory, "plugins"),
                    ServerPath: Path.Combine(x64Directory, "plugins", "DbgLink.Server.exe"),
                    ExtensionZip: Path.Combine(x64Directory, "plugins", "GhidraBridge.zip"),
                    Debugger: primaryArchitecture),
                name => name == "JAVA_HOME" ? javaHome : null);

            if (secondaryPluginInstalled)
            {
                Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Issues.Select(issue => issue.Message)));
                Assert.Equal(primaryArchitecture, result.Plan!.Settings.Debugger);
                Assert.True(result.Plan.Settings.Permissions!.AllowGhidraAnnotation);
                Assert.True(result.Plan.Settings.Permissions.AllowGhidraMutation);
            }
            else
            {
                Assert.False(result.IsValid);
                var issue = Assert.Single(result.Issues);
                Assert.Equal(primaryArchitecture == DebuggerArchitecture.X64 ? "x32_plugin_missing" : "x64_plugin_missing", issue.Code);
            }
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Monotonic_elapsed_handles_counter_wraparound()
    {
        Assert.Equal(11, MonotonicClock.ElapsedMilliseconds(long.MaxValue - 5, long.MinValue + 5));
    }

    private static LauncherPlan CreatePlan()
    {
        var settings = new LauncherSettings("x64dbg.exe", "x32dbg.exe", "ghidra", ReverseMode.LetLlmChoose, null);
        var paths = new ToolkitPaths(
            "x64dbg.exe", "x32dbg.exe", "x64dbg.exe", "ghidra", "ghidraRun.bat", "analyzeHeadless.bat",
            "plugins", "DbgLink.Server.exe", "DbgLink.dp64", "GhidraBridge.zip", "jdk");
        return new LauncherPlan(settings, paths);
    }
}
