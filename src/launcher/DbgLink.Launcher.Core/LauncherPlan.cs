using System.Collections.ObjectModel;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

public enum ReverseMode
{
    ChooseFile,
    LetLlmChoose
}

public enum DebuggerArchitecture
{
    Auto,
    X64,
    X86
}

/// <summary>
/// Launch-related permission/mode profile for the toolkit. Relaxed is the
/// opt-in mode that lets the toolkit run from user-owned folders; the launcher
/// forwards it to the server so both sides agree on the mode.
/// </summary>
public sealed record LauncherPermissionProfile(
    bool AllowGhidraAnnotation = true,
    bool AllowGhidraMutation = true,
    bool Relaxed = false)
{
    public static LauncherPermissionProfile Default { get; } = new();
    public static LauncherPermissionProfile ReadOnly { get; } = new(false, false);

    internal const string RelaxedFlag = "--relaxed";
}

public static class LauncherDefaults
{
    /// <summary>
    /// Default loopback MCP port. Mirrors <c>DbgLink.Server.ServerConfig.DefaultPort</c>
    /// (kept as a separate constant because Launcher.Core must not reference the
    /// server assembly); the value is contractual — do not change it.
    /// </summary>
    public const int DefaultPort = 50301;
}

public sealed record LauncherSettings(
    string X64DbgPath,
    string X32DbgPath,
    string GhidraHome,
    ReverseMode Mode,
    string? InputFile,
    int Port = LauncherDefaults.DefaultPort,
    string? PluginDirectory = null,
    string? ServerPath = null,
    string? ExtensionZip = null,
    LauncherPermissionProfile? Permissions = null,
    DebuggerArchitecture Debugger = DebuggerArchitecture.Auto,
    bool Relaxed = false);

public sealed record ValidationIssue(string Code, string Message);

public sealed record ToolkitPaths(
    string X64DbgPath,
    string X32DbgPath,
    string DebuggerPath,
    string GhidraHome,
    string GhidraLauncherPath,
    string GhidraHeadlessPath,
    string PluginDirectory,
    string ServerPath,
    string PluginFileName,
    string GhidraExtensionZip,
    string JavaHome);

public sealed record LauncherPlanningResult(
    LauncherPlan? Plan,
    IReadOnlyList<ValidationIssue> Issues)
{
    public bool IsValid => Plan is not null && Issues.Count == 0;
}

public sealed record LauncherPlan(LauncherSettings Settings, ToolkitPaths Paths)
{
    public string PipeNameFor(int debuggerProcessId)
    {
        if (debuggerProcessId <= 0)
            throw new ArgumentOutOfRangeException(nameof(debuggerProcessId), "A live debugger process id is required.");
        return $"DbgLink.Control.{debuggerProcessId}";
    }
}

public sealed record ProcessLaunchSpec(
    string FileName,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    IReadOnlyDictionary<string, string> EnvironmentVariables,
    bool UseShellExecute,
    bool CaptureOutput = false,
    IReadOnlyCollection<string>? RemoveEnvironmentVariables = null);

public static partial class LauncherPlanner
{
    private const int MaxWindowsPathLength = 32_760;
    // The debuggee and Ghidra must not inherit the tunnel/bearer credentials
    // from the shell that launched DBGLink.
    private static readonly string[] SensitiveChildEnvironment =
    [
        "CONTROL_PLANE_API_KEY",
        "DBGLINK_BEARER_TOKEN",
        "DBGLINK_NATIVE_PIPE_TOKEN"
    ];

    public static LauncherPlanningResult Plan(
        LauncherSettings settings,
        Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var issues = new List<ValidationIssue>();
        var permissions = settings.Permissions ?? LauncherPermissionProfile.Default;

        if (settings.Mode is not (ReverseMode.ChooseFile or ReverseMode.LetLlmChoose))
            issues.Add(new("invalid_reverse_mode", "Reverse mode is not supported."));
        if (settings.Debugger is not (DebuggerArchitecture.Auto or DebuggerArchitecture.X64 or DebuggerArchitecture.X86))
            issues.Add(new("invalid_debugger_architecture", "Debugger architecture is not supported."));

        if (settings.Port is < 1 or > 65_535)
            issues.Add(new("invalid_port", "Port must be between 1 and 65535."));

        var x64DbgPath = ValidateDebuggerPath(settings.X64DbgPath, "x64dbg_path", "x64dbg.exe", issues);
        var x32DbgPath = ValidateDebuggerPath(settings.X32DbgPath, "x32dbg_path", "x32dbg.exe", issues);
        var selectedArchitecture = settings.Debugger switch
        {
            DebuggerArchitecture.X64 => DebuggerArchitecture.X64,
            DebuggerArchitecture.X86 => DebuggerArchitecture.X86,
            DebuggerArchitecture.Auto when settings.Mode == ReverseMode.ChooseFile && !string.IsNullOrWhiteSpace(settings.InputFile)
                => DebuggerArchitectureDetector.Detect(settings.InputFile!, DebuggerArchitecture.X64),
            DebuggerArchitecture.Auto => DebuggerArchitecture.X64,
            _ => DebuggerArchitecture.X64
        };
        var debuggerPath = selectedArchitecture == DebuggerArchitecture.X64 ? x64DbgPath : x32DbgPath;
        if (debuggerPath is null)
        {
            issues.Add(new(
                selectedArchitecture == DebuggerArchitecture.X64 ? "x64dbg_path" : "x32dbg_path",
                $"A valid {(selectedArchitecture == DebuggerArchitecture.X64 ? "x64dbg.exe" : "x32dbg.exe")} path is required."));
        }
        if (settings.Mode == ReverseMode.LetLlmChoose)
        {
            if (string.IsNullOrWhiteSpace(settings.X64DbgPath))
                issues.Add(new("x64dbg_path", "A valid x64dbg.exe path is required for parallel analysis."));
            if (string.IsNullOrWhiteSpace(settings.X32DbgPath))
                issues.Add(new("x32dbg_path", "A valid x32dbg.exe path is required for parallel analysis."));
        }

        var ghidraHome = ExistingDirectory(settings.GhidraHome, "ghidra_home", "Ghidra home", issues);
        string? ghidraLauncherPath = null;
        string? ghidraHeadlessPath = null;
        if (ghidraHome is not null)
        {
            var applicationProperties = Path.Combine(ghidraHome, "Ghidra", "application.properties");
            if (!File.Exists(applicationProperties) || !PathSafety.IsReparseFree(applicationProperties))
                issues.Add(new("invalid_ghidra_home", "The selected directory is not a Ghidra installation."));

            ghidraLauncherPath = Path.Combine(ghidraHome, "ghidraRun.bat");
            if (!File.Exists(ghidraLauncherPath) || !PathSafety.IsReparseFree(ghidraLauncherPath))
                issues.Add(new("ghidra_launcher_missing", "ghidraRun.bat was not found in the selected Ghidra directory."));

            ghidraHeadlessPath = Path.Combine(ghidraHome, "support", "analyzeHeadless.bat");
            if (!File.Exists(ghidraHeadlessPath) || !PathSafety.IsReparseFree(ghidraHeadlessPath))
                issues.Add(new("ghidra_headless_missing", "Ghidra support\\analyzeHeadless.bat was not found."));
            if (!ProcessLauncher.IsCommandArgumentSafe(ghidraLauncherPath) ||
                !ProcessLauncher.IsCommandArgumentSafe(ghidraHeadlessPath))
            {
                issues.Add(new(
                    "invalid_ghidra_home",
                    "The Ghidra path may not contain percent signs or exclamation marks on Windows."));
            }
        }

        if (settings.Mode == ReverseMode.ChooseFile)
            ValidateGhidraTarget(settings.InputFile, issues);

        if (debuggerPath is null || ghidraHome is null || ghidraLauncherPath is null || ghidraHeadlessPath is null)
            return new(null, new ReadOnlyCollection<ValidationIssue>(issues));

        var pluginDirectory = FindPluginDirectory(settings, debuggerPath, environment, issues);
        if (pluginDirectory is null)
            return new(null, new ReadOnlyCollection<ValidationIssue>(issues));

        var expectedPlugin = IsX86Debugger(debuggerPath) ? "DbgLink.dp32" : "DbgLink.dp64";
        if (!File.Exists(Path.Combine(pluginDirectory, expectedPlugin)) ||
            !PathSafety.IsReparseFree(Path.Combine(pluginDirectory, expectedPlugin)))
            issues.Add(new("plugin_missing", $"{expectedPlugin} was not found in the debugger plugins directory."));

        var secondaryDebuggerPath = selectedArchitecture == DebuggerArchitecture.X64 ? x32DbgPath : x64DbgPath;
        if (settings.Mode == ReverseMode.LetLlmChoose && secondaryDebuggerPath is not null)
        {
            // The configured directory belongs to the primary debugger;
            // discover the other architecture's bridge beside its debugger.
            var secondaryIsX86 = selectedArchitecture == DebuggerArchitecture.X64;
            var secondaryPluginName = secondaryIsX86 ? "DbgLink.dp32" : "DbgLink.dp64";
            var secondaryPluginDirectory = FindPluginDirectory(
                settings,
                secondaryDebuggerPath,
                environment,
                new List<ValidationIssue>(),
                useConfiguredDirectory: false);
            var secondaryPlugin = secondaryPluginDirectory is null
                ? null
                : Path.Combine(secondaryPluginDirectory, secondaryPluginName);
            if (secondaryPlugin is null || !File.Exists(secondaryPlugin) || !PathSafety.IsReparseFree(secondaryPlugin))
                issues.Add(new(
                    secondaryIsX86 ? "x32_plugin_missing" : "x64_plugin_missing",
                    $"{secondaryPluginName} was not found for the secondary debugger used by parallel analysis."));
        }

        var serverPath = settings.ServerPath;
        if (string.IsNullOrWhiteSpace(serverPath))
            serverPath = Path.Combine(pluginDirectory, "DbgLink.Server.exe");
        serverPath = ExistingFile(serverPath, "server_path", "DbgLink.Server.exe", issues);
        if (serverPath is not null && !Path.GetFileName(serverPath).Equals("DbgLink.Server.exe", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new("invalid_server_path", "The launcher may start only DbgLink.Server.exe."));
            serverPath = null;
        }

        var extensionZip = FindExtensionZip(settings, pluginDirectory, environment, issues);
        var javaHome = FindJavaHome(environment, issues);

        if (issues.Count != 0)
            return new(null, new ReadOnlyCollection<ValidationIssue>(issues));

        var paths = new ToolkitPaths(
            x64DbgPath ?? string.Empty,
            x32DbgPath ?? string.Empty,
            debuggerPath,
            ghidraHome,
            ghidraLauncherPath,
            ghidraHeadlessPath,
            pluginDirectory,
            serverPath!,
            expectedPlugin,
            extensionZip!,
            javaHome!);
        return new(
            new LauncherPlan(settings with
            {
                X64DbgPath = x64DbgPath ?? string.Empty,
                X32DbgPath = x32DbgPath ?? string.Empty,
                GhidraHome = ghidraHome,
                Debugger = selectedArchitecture,
                InputFile = settings.Mode == ReverseMode.ChooseFile
                    ? Path.GetFullPath(settings.InputFile!)
                    : null,
                Permissions = permissions
            }, paths),
            Array.Empty<ValidationIssue>());
    }

    public static ProcessLaunchSpec CreateDebuggerSpec(LauncherPlan plan)
        => CreateDebuggerSpec(plan, plan.Settings.Debugger, plan.Settings.Mode == ReverseMode.ChooseFile
            ? plan.Settings.InputFile
            : null);

    public static ProcessLaunchSpec CreateDebuggerSpec(
        LauncherPlan plan,
        DebuggerArchitecture architecture,
        string? inputFile)
    {
        if (architecture is not (DebuggerArchitecture.X64 or DebuggerArchitecture.X86))
            throw new ArgumentOutOfRangeException(nameof(architecture), "Resolve the debugger architecture before creating a launch specification.");
        var debuggerPath = architecture == DebuggerArchitecture.X64
            ? plan.Paths.X64DbgPath
            : plan.Paths.X32DbgPath;
        if (string.IsNullOrWhiteSpace(debuggerPath))
            throw new InvalidOperationException($"The {architecture} debugger path is not configured.");

        var arguments = !string.IsNullOrWhiteSpace(inputFile)
            ? new[] { inputFile }
            : Array.Empty<string>();
        return new(
            debuggerPath,
            arguments,
            Path.GetDirectoryName(debuggerPath)!,
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["DBGLINK_SKIP_SERVER_AUTOSTART"] = "1",
                ["DBGLINK_PORT"] = plan.Settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }),
            false,
            RemoveEnvironmentVariables: SensitiveChildEnvironment);
    }

    public static ProcessLaunchSpec CreateServerSpec(
        LauncherPlan plan,
        int debuggerProcessId,
        string? ghidraEndpointDirectory = null,
        string? ghidraControlPipeName = null,
        string? ghidraControlToken = null,
        string? nativePipeName = null,
        string? nativePipeToken = null)
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DBGLINK_PORT"] = plan.Settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [DbgLinkConfigPath.ConfigPathEnvironmentVariable] = DbgLinkConfigPath.GetPath()
        };
        var permissions = plan.Settings.Permissions ?? LauncherPermissionProfile.Default;
        if (!string.IsNullOrWhiteSpace(ghidraEndpointDirectory))
            environment["DBGLINK_GHIDRA_ENDPOINT_DIR"] = ghidraEndpointDirectory;
        if (!string.IsNullOrWhiteSpace(ghidraControlPipeName) || !string.IsNullOrWhiteSpace(ghidraControlToken))
        {
            if (string.IsNullOrWhiteSpace(ghidraControlPipeName) ||
                !ghidraControlPipeName.StartsWith("DbgLink.GhidraControl.", StringComparison.Ordinal) ||
                ghidraControlPipeName.Length == "DbgLink.GhidraControl.".Length ||
                ghidraControlPipeName.Length > 200 ||
                ghidraControlPipeName.Any(char.IsControl))
            {
                throw new ArgumentException("The Ghidra control pipe name is invalid.", nameof(ghidraControlPipeName));
            }
            if (string.IsNullOrWhiteSpace(ghidraControlToken) ||
                ghidraControlToken.Length is < 32 or > 256 ||
                ghidraControlToken.Any(char.IsControl))
            {
                throw new ArgumentException("The Ghidra control token is invalid.", nameof(ghidraControlToken));
            }
            environment["DBGLINK_GHIDRA_CONTROL_PIPE"] = ghidraControlPipeName;
            environment["DBGLINK_GHIDRA_CONTROL_TOKEN"] = ghidraControlToken;
        }

        // N1 native pipe authentication: the pipe name and token come from the
        // validated native-endpoint.json rendezvous. Both or neither; without
        // them the legacy bare pipe name is used (no token).
        var serverPipeName = plan.PipeNameFor(debuggerProcessId);
        var serverArguments = new List<string> { "--pipe-name", serverPipeName };
        if (nativePipeName is not null || nativePipeToken is not null)
        {
            if (nativePipeName is null || nativePipeToken is null)
                throw new ArgumentException(
                    "The native pipe name and token must be provided together.",
                    nativePipeName is null ? nameof(nativePipeName) : nameof(nativePipeToken));
            if (!NativeEndpointResolver.IsValidPipeName(nativePipeName))
                throw new ArgumentException("The native pipe name is invalid.", nameof(nativePipeName));
            if (!NativeEndpointResolver.IsValidPipeToken(nativePipeToken))
                throw new ArgumentException("The native pipe token is invalid.", nameof(nativePipeToken));
            // The server's pipe client expects the bare name (it prefixes
            // \\.\pipe\ itself); the rendezvous stores the full path form.
            serverArguments[1] = nativePipeName.StartsWith(NativeEndpointResolver.PipePrefix, StringComparison.Ordinal)
                ? nativePipeName[NativeEndpointResolver.PipePrefix.Length..]
                : nativePipeName;
            // The token goes through the environment, not the command line:
            // argv is readable by every local process through
            // Win32_Process.CommandLine.
            environment[DbgLinkConfigPath.NativePipeTokenEnvironmentVariable] = nativePipeToken;
        }
        serverArguments.Add("--port");
        serverArguments.Add(plan.Settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        serverArguments.Add("--allow-annotation");
        serverArguments.Add(permissions.AllowGhidraAnnotation.ToString().ToLowerInvariant());
        serverArguments.Add("--allow-mutation");
        serverArguments.Add(permissions.AllowGhidraMutation.ToString().ToLowerInvariant());
        // The server inherits the launcher's relaxed mode so the bridge
        // startup budget matches the rest of the run (see Program.cs).
        if (permissions.Relaxed)
            serverArguments.Add(LauncherPermissionProfile.RelaxedFlag);

        return new(
            plan.Paths.ServerPath,
            serverArguments.ToArray(),
            plan.Paths.PluginDirectory,
            new ReadOnlyDictionary<string, string>(environment),
            false,
            CaptureOutput: true);
    }

    public static ProcessLaunchSpec CreateGhidraSpec(LauncherPlan plan, GhidraSession? session = null)
    {
        // Foreground Java stays under the launcher-owned cmd process. The normal
        // ghidraRun.bat uses bg, which detaches Java and defeats per-session cleanup.
        var arguments = new List<string> { "fg", "jdk", "Ghidra", "", "", "ghidra.GhidraRun" };
        if (session?.ProjectFile is not null)
            arguments.Add(session.ProjectFile);
        return new(
            Path.Combine(plan.Paths.GhidraHome, "support", "launch.bat"),
            arguments,
            plan.Paths.GhidraHome,
            session?.EnvironmentVariables ??
                new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)),
            true,
            RemoveEnvironmentVariables: SensitiveChildEnvironment);
    }

}
