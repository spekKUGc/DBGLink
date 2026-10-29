using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Creates an isolated, bounded Ghidra profile for one launcher session.
/// </summary>
public sealed partial class GhidraSession : IDisposable, IAsyncDisposable
{
    private const string ExtensionName = "GhidraBridge";
    private const string FrontendPluginClass = "dbglink.ghidra.DbgLinkFrontEndPlugin";
    private const int MaxZipEntries = 256;
    private const long MaxZipBytes = 128L * 1024 * 1024;
    internal const long MaxExtensionArchiveBytes = 64L * 1024 * 1024;
    private const long MaxProfileFileBytes = 2L * 1024 * 1024;
    private const int MaxProfileCandidates = 16;
    private const int MaxProfileDirectoryEntries = 4_096;
    private const int CleanupRetryMilliseconds = 100;
    private const int CleanupTimeoutSeconds = 10;
    internal const string FidbEnvironmentVariable = "DBGLINK_FIDB";
    internal const string ImportTimeoutEnvironmentVariable = "DBGLINK_GHIDRA_IMPORT_TIMEOUT_MS";
    internal const string FastAnalysisEnvironmentVariable = "DBGLINK_GHIDRA_FAST";
    internal static readonly TimeSpan DefaultImportTimeout = TimeSpan.FromMinutes(10);
    internal static readonly TimeSpan MinImportTimeout = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaxImportTimeout = TimeSpan.FromMinutes(15);
    internal const string ApplyFidbScriptName = "ApplyFidb.java";

    private readonly string _temporaryRoot;
    private readonly Dictionary<string, string> _environment;
    private readonly string? _projectCacheRoot;
    private int _disposed;

    public bool CleanupSucceeded { get; private set; } = true;

    private GhidraSession(
        string temporaryRoot,
        string endpointDirectory,
        string? projectFile,
        IReadOnlyDictionary<string, string> environmentVariables,
        string? projectCacheRoot)
    {
        _temporaryRoot = temporaryRoot;
        EndpointDirectory = endpointDirectory;
        ProjectFile = projectFile;
        _environment = new Dictionary<string, string>(environmentVariables, StringComparer.OrdinalIgnoreCase);
        _projectCacheRoot = projectCacheRoot;
    }

    public string EndpointDirectory { get; }

    public string? ProjectFile { get; private set; }

    public IReadOnlyDictionary<string, string> EnvironmentVariables => _environment;

    public async Task<GhidraTargetInfo> OpenProgramAsync(
        LauncherPlan plan,
        string inputFile,
        Action<string> report,
        CancellationToken cancellationToken, bool analyze = true)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(report);

        var target = GhidraTargetPolicy.Stage(inputFile, _temporaryRoot);
        // Ghidra analyzes the staged copy, but callers should see the file the
        // user actually selected. The bridge uses this value only for display
        // and keeps the staged path private to the isolated session.
        _environment["DBGLINK_GHIDRA_DISPLAY_FILE"] = target.FullPath;
        var projectDirectory = Path.Combine(_temporaryRoot, "project-" + Guid.NewGuid().ToString("N"));
        var projectName = "DbgLinkSession";
        Directory.CreateDirectory(projectDirectory);
        await RestoreOrImportProjectAsync(
            plan,
            _environment,
            projectDirectory,
            projectName,
            target.StagedPath!,
            target.FileName,
            report,
            cancellationToken,
            _projectCacheRoot, analyze).ConfigureAwait(false);

        var projectFile = Path.Combine(projectDirectory, projectName + ".gpr");
        if (!File.Exists(projectFile))
            throw new InvalidDataException("Ghidra headless import did not create a project file.");

        ProjectFile = projectFile;
        _environment["DBGLINK_GHIDRA_AUTO_OPEN"] = "1";
        _environment["DBGLINK_GHIDRA_INPUT_FILE"] = target.StagedPath!;
        // Fast imports skip headless analysis; the frontend plugin uses this
        // to suppress the modal "analyze?" prompt that nobody can answer in
        // the hidden launcher-owned window.
        _environment["DBGLINK_GHIDRA_ANALYZE"] = analyze ? "1" : "0";
        return target;
    }

    public static async Task<GhidraSession> PrepareAsync(
        LauncherPlan plan,
        Action<string> report,
        CancellationToken cancellationToken,
        string? parentRunRoot = null,
        bool analyze = true)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(report);

        if (parentRunRoot is not null)
            ValidateRunRootParent(parentRunRoot);

        var temporaryRoot = parentRunRoot is null
            ? Path.Combine(
                Path.GetTempPath(),
                "DbgLink-Ghidra-Launcher-" + Guid.NewGuid().ToString("N"))
            : Path.Combine(
                parentRunRoot,
                "DbgLink-Ghidra-Launcher-" + Guid.NewGuid().ToString("N"));
        var endpointDirectory = Path.Combine(temporaryRoot, "endpoint");
        var profileRoot = Path.Combine(temporaryRoot, "profile");
        var appData = Path.Combine(profileRoot, "AppData", "Roaming");
        var isolatedLocalAppData = Path.Combine(profileRoot, "AppData", "Local");

        if (!ProcessLauncher.IsCommandArgumentSafe(temporaryRoot))
            throw new InvalidOperationException("The Windows temporary path may not contain percent signs or exclamation marks for a Ghidra session.");

        try
        {
            EnsureNoReparseAncestors(temporaryRoot);
            Directory.CreateDirectory(endpointDirectory);
            Directory.CreateDirectory(appData);
            EnsureNoReparseAncestors(endpointDirectory);
            EnsureNoReparseAncestors(appData);

            var sourceProfile = FindAcceptedProfile(plan.Paths.GhidraHome);
            var localAppData = SelectLocalAppData(
                sourceProfile.Name,
                isolatedLocalAppData,
                report);
            var projectCacheRoot = SelectProjectCacheRoot(sourceProfile.Name);
            var annotationsDirectory = SelectAnnotationsDirectory(report);
            Directory.CreateDirectory(localAppData);
            EnsureNoReparseAncestors(localAppData);
            var targetSettings = Path.Combine(appData, "ghidra", sourceProfile.Name);
            var targetExtension = Path.Combine(targetSettings, "Extensions", ExtensionName);
            Directory.CreateDirectory(targetSettings);
            Directory.CreateDirectory(targetExtension);
            EnsureNoReparseAncestors(targetSettings);
            EnsureNoReparseAncestors(targetExtension);

            CopyBoundedFile(Path.Combine(sourceProfile.FullName, "preferences"), Path.Combine(targetSettings, "preferences"));
            CopyBoundedFile(Path.Combine(sourceProfile.FullName, "FrontEndTool.xml"), Path.Combine(targetSettings, "FrontEndTool.xml"));
            ConfigureFrontend(Path.Combine(targetSettings, "FrontEndTool.xml"));

            var sourceCodeBrowser = Path.Combine(sourceProfile.FullName, "tools", "_code_browser.tcd");
            var targetTools = Path.Combine(targetSettings, "tools");
            Directory.CreateDirectory(targetTools);
            EnsureNoReparseAncestors(targetTools);
            var targetCodeBrowser = Path.Combine(targetTools, "_code_browser.tcd");
            CopyBoundedFile(sourceCodeBrowser, targetCodeBrowser);
            ConfigureKnownExtension(targetCodeBrowser);

            report("Preparing an isolated Ghidra profile and verified extension...");
            InstallExtension(plan.Paths.GhidraExtensionZip, targetExtension);

            var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["JAVA_HOME"] = plan.Paths.JavaHome,
                ["USERPROFILE"] = profileRoot,
                ["APPDATA"] = appData,
                ["LOCALAPPDATA"] = localAppData,
                ["DBGLINK_GHIDRA_ENDPOINT_DIR"] = endpointDirectory,
                ["DBGLINK_GHIDRA_AUTO_OPEN"] = "0",
                ["DBGLINK_GHIDRA_INPUT_FILE"] = string.Empty,
                ["DBGLINK_GHIDRA_DISPLAY_FILE"] = string.Empty,
                // The initial target can opt into a no-analysis import; per-file
                // dynamic imports override this in OpenProgramAsync.
                ["DBGLINK_GHIDRA_ANALYZE"] = analyze ? "1" : "0"
            };
            if (!string.IsNullOrWhiteSpace(annotationsDirectory))
                environment["DBGLINK_ANNOTATIONS_DIR"] = annotationsDirectory;

            string? projectFile = null;
            if (plan.Settings.Mode == ReverseMode.ChooseFile)
            {
                var target = GhidraTargetPolicy.Stage(plan.Settings.InputFile!, temporaryRoot);
                environment["DBGLINK_GHIDRA_DISPLAY_FILE"] = target.FullPath;
                var projectDirectory = Path.Combine(temporaryRoot, "project");
                Directory.CreateDirectory(projectDirectory);
                var projectName = "DbgLinkSession";
                await RestoreOrImportProjectAsync(
                    plan,
                    environment,
                    projectDirectory,
                    projectName,
                    target.StagedPath!,
                    target.FileName,
                    report,
                    cancellationToken,
                    projectCacheRoot,
                    analyze: analyze).ConfigureAwait(false);
                projectFile = Path.Combine(projectDirectory, projectName + ".gpr");
                if (!File.Exists(projectFile))
                    throw new InvalidDataException("Ghidra headless import did not create a project file.");

                environment["DBGLINK_GHIDRA_AUTO_OPEN"] = "1";
                environment["DBGLINK_GHIDRA_INPUT_FILE"] = target.StagedPath!;
            }

            return new GhidraSession(
                temporaryRoot,
                endpointDirectory,
                projectFile,
                environment,
                projectCacheRoot);
        }
        catch (Exception exception)
        {
            if (!await TryDeleteAsync(temporaryRoot).ConfigureAwait(false))
                throw new InvalidOperationException("Ghidra isolated-session cleanup did not complete.", exception);
            throw;
        }
    }

    /// <summary>
    /// A session may nest under the coordinator's owned run root so one
    /// shutdown sweep removes every per-run directory. The parent must be a
    /// live launcher-owned run root; anything else fails fast before any
    /// directory is created.
    /// </summary>
    private static void ValidateRunRootParent(string parentRunRoot)
    {
        if (!LauncherTempRoot.IsOwnedRunRoot(parentRunRoot) || !Directory.Exists(parentRunRoot))
            throw new ArgumentException("A launcher-owned run root is required.", nameof(parentRunRoot));
    }

    private static string SelectLocalAppData(
        string profileName,
        string isolatedPath,
        Action<string> report)
    {
        try
        {
            var localApplicationData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localApplicationData))
                return isolatedPath;

            var sharedPath = Path.Combine(
                localApplicationData,
                "DBGLink",
                "GhidraCache",
                profileName);
            if (!ProcessLauncher.IsCommandArgumentSafe(sharedPath))
                return isolatedPath;

            Directory.CreateDirectory(sharedPath);
            EnsureNoReparseAncestors(sharedPath);
            report("Reusing the persistent Ghidra analysis cache.");
            return sharedPath;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // The cache is an optimization. If the user profile is unavailable
            // or protected, keep the fully isolated per-session fallback.
            return isolatedPath;
        }
    }

    private static string? SelectProjectCacheRoot(string profileName)
    {
        try
        {
            var localApplicationData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localApplicationData))
                return null;

            var cacheRoot = Path.Combine(
                localApplicationData,
                "DBGLink",
                "GhidraProjects",
                profileName);
            if (!ProcessLauncher.IsCommandArgumentSafe(cacheRoot))
                return null;

            Directory.CreateDirectory(cacheRoot);
            EnsureNoReparseAncestors(cacheRoot);
            return cacheRoot;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Real (non-redirected) annotations directory for the durable rename
    /// journal. The Ghidra child process sees a redirected LOCALAPPDATA that
    /// points into the shared Ghidra cache, so the journal cannot derive its
    /// location from that variable: clearing the cache would delete every
    /// rename. The launcher passes this path explicitly instead.
    /// </summary>
    private static string? SelectAnnotationsDirectory(Action<string> report)
    {
        try
        {
            var localApplicationData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localApplicationData))
                return null;

            var annotations = Path.Combine(
                localApplicationData,
                "DBGLink",
                "annotations");
            if (!ProcessLauncher.IsCommandArgumentSafe(annotations))
                return null;

            Directory.CreateDirectory(annotations);
            EnsureNoReparseAncestors(annotations);
            return annotations;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // The journal is best-effort durability; a missing directory only
            // means renames rely on SaveProgram within the live session.
            report("Annotation journal directory is unavailable; renames will not persist across restarts.");
            return null;
        }
    }

    private static async Task RestoreOrImportProjectAsync(
        LauncherPlan plan,
        IReadOnlyDictionary<string, string> environment,
        string projectDirectory,
        string projectName,
        string inputFile,
        string fileName,
        Action<string> report,
        CancellationToken cancellationToken,
        string? projectCacheRoot, bool analyze = true)
    {
        var fidbSpec = ResolveFidbSpec();
        if (fidbSpec is null && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(FidbEnvironmentVariable)))
            report("DBGLINK_FIDB does not point to an existing .fidb file or directory; importing without Function ID data.");

        var cache = string.IsNullOrWhiteSpace(projectCacheRoot)
            ? null
            : new GhidraProjectCache(projectCacheRoot, report: report);
        var cacheKey = "";
        string? sha256 = null;
        string? fidbHash = null;
        string? extensionHash = null;
        if (cache is not null)
        {
            sha256 = await ComputeSha256Async(inputFile, cancellationToken).ConfigureAwait(false);
            fidbHash = fidbSpec is null
                ? null
                : Convert.ToHexString(
                    SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fidbSpec))).ToLowerInvariant()[..16];
            extensionHash = await ComputeSha256Async(
                plan.Paths.GhidraExtensionZip, cancellationToken).ConfigureAwait(false);
            cacheKey = GhidraProjectCache.ComposeKey(
                sha256, analyze, fidbHash, extensionHash[..16]);
            if (cache.TryRestore(cacheKey, projectDirectory, out _))
            {
                report($"Reusing the cached Ghidra project for {fileName}...");
                return;
            }
        }

        report($"Importing {fileName} into an isolated Ghidra project...");
        if (fidbSpec is not null)
            report("Applying Function ID databases (DBGLINK_FIDB) during the Ghidra import...");
        var importTimeout = ResolveImportTimeout();
        try
        {
            await ImportAsync(
                plan,
                environment,
                projectDirectory,
                projectName,
                inputFile,
                cancellationToken, analyze, fidbSpec, importTimeout).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && analyze)
        {
            // Large real binaries can exceed the analysis window. A hard
            // startup failure is worse than a useful partial session: retry
            // without auto-analysis so imports/sections/strings and live
            // debugging stay available. The user can opt into a longer
            // window with DBGLINK_GHIDRA_IMPORT_TIMEOUT_MS.
            report(
                $"Ghidra analysis exceeded the {importTimeout.TotalMinutes:0.#}-minute window; " +
                "retrying the import without analysis so the session stays usable.");
            if (environment is IDictionary<string, string> mutableEnvironment)
                mutableEnvironment["DBGLINK_GHIDRA_ANALYZE"] = "0";
            TryDeleteDirectory(projectDirectory);
            Directory.CreateDirectory(projectDirectory);
            await ImportAsync(
                plan,
                environment,
                projectDirectory,
                projectName,
                inputFile,
                cancellationToken, analyze: false, fidbSpec, importTimeout).ConfigureAwait(false);
            if (cache is not null)
            {
                cacheKey = GhidraProjectCache.ComposeKey(
                    sha256!, analyze: false, fidbHash, extensionHash![..16]);
            }
        }

        cache?.Store(cacheKey, projectDirectory);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan | FileOptions.Asynchronous);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Removes every cached Ghidra project for the current profile. Used by
    /// <c>--clear-cache</c>; an absent cache is not an error.
    /// </summary>
    public static GhidraCacheClearResult ClearProjectCache()
    {
        var root = GhidraProjectCache.DefaultRoot();
        return root is null ? new GhidraCacheClearResult(0, 0) : GhidraProjectCache.ClearRoot(root);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        CleanupSucceeded = TryDeleteAsync(_temporaryRoot).GetAwaiter().GetResult();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        CleanupSucceeded = await TryDeleteAsync(_temporaryRoot).ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Bounded import budget. Ten minutes covers observed real Windows
    /// binaries (taskmgr.exe took about seven minutes on a cold cache); an
    /// operator can raise or lower it without disabling the safety bound.
    /// Values outside 1..15 minutes fall back to the default, so a typo cannot
    /// make the launcher wait forever.
    /// </summary>
    internal static TimeSpan ResolveImportTimeout(Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        if (!int.TryParse(environment(ImportTimeoutEnvironmentVariable), out var milliseconds) ||
            milliseconds <= 0)
            return DefaultImportTimeout;
        return TimeSpan.FromMilliseconds(Math.Clamp(
            milliseconds, (int)MinImportTimeout.TotalMilliseconds, (int)MaxImportTimeout.TotalMilliseconds));
    }

    /// <summary>
    /// Hard wall-clock bound for the whole launch. It sits above the import
    /// budget plus the no-analysis fallback, but still turns an unresponsive
    /// Ghidra/debugger startup into a bounded, actionable failure instead of a
    /// silently hung launcher.
    /// </summary>
    public static TimeSpan ResolveStartupTimeout(Func<string, string?>? environment = null)
        => ResolveImportTimeout(environment) + TimeSpan.FromMinutes(2);

    /// <summary>
    /// Opt-in fast start: skip headless auto-analysis for the initial target.
    /// Imports/sections/strings and live debugging remain available, while the
    /// cold multi-minute analyzer pass is avoided. Full analysis can still be
    /// requested later from the model through the normal static tools.
    /// </summary>
    internal static bool ResolveFastAnalysis(Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var value = environment(FastAnalysisEnvironmentVariable);
        return value is not null &&
            (value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
             value.Equals("true", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Reads <c>DBGLINK_FIDB</c>: one <c>.fidb</c> file or directory, or several
    /// separated with <c>;</c>. Only existing, reparse-free, command-safe entries
    /// are kept; anything else resolves to <c>null</c> (import as before).
    /// </summary>
    internal static string? ResolveFidbSpec(Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var raw = environment(FidbEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var entries = raw
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(entry =>
                ProcessLauncher.IsCommandArgumentSafe(entry) &&
                (File.Exists(entry) || Directory.Exists(entry)) &&
                PathSafety.IsReparseFree(entry))
            .ToArray();
        return entries.Length == 0 ? null : string.Join(';', entries);
    }

    /// <summary>
    /// Builds the <c>analyzeHeadless</c> argument list for a project import.
    /// With a FID spec the <c>ApplyFidb.java</c> pre-script attaches the
    /// databases before analysis so the Function ID analyzer can apply them.
    /// </summary>
    internal static IReadOnlyList<string> BuildImportArguments(
        string projectDirectory,
        string projectName,
        string inputFile,
        bool analyze,
        string? fidbSpec)
    {
        var arguments = new List<string>(8)
        {
            projectDirectory,
            projectName,
            "-import",
            inputFile,
            "-overwrite",
        };
        if (!analyze)
            arguments.Add("-noanalysis");
        if (!string.IsNullOrWhiteSpace(fidbSpec))
            arguments.AddRange(["-preScript", ApplyFidbScriptName, fidbSpec]);
        return arguments;
    }

    private static async Task ImportAsync(
        LauncherPlan plan,
        IReadOnlyDictionary<string, string> environment,
        string projectDirectory,
        string projectName,
        string inputFile,
        CancellationToken cancellationToken, bool analyze = true, string? fidbSpec = null,
        TimeSpan? importTimeout = null)
    {
        var importEnvironment = new Dictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase);
        var spec = new ProcessLaunchSpec(
            plan.Paths.GhidraHeadlessPath,
            BuildImportArguments(projectDirectory, projectName, inputFile, analyze, fidbSpec),
            plan.Paths.GhidraHome,
            new ReadOnlyDictionary<string, string>(importEnvironment),
            true);
        using var process = ProcessLauncher.Start(spec);
        try
        {
            // Process.Start succeeds before the job object is created. If job
            // creation/configuration fails, disposing Process only closes the
            // wrapper and would leave headless Ghidra orphaned.
            using var job = WindowsProcessJob.Create();
            job.Assign(process);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(importTimeout ?? ResolveImportTimeout());
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0)
                throw new InvalidOperationException($"Ghidra headless import failed with exit code {process.ExitCode}.");
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // Preserve the import failure; the caller still reports the
                // failed session and performs its normal cleanup attempt.
            }
            throw;
        }
    }

    private static void EnsureNoReparseParents(string path, string root)
    {
        var rootPath = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("Ghidra session path contains a reparse point.");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar), rootPath, StringComparison.OrdinalIgnoreCase))
                return;
            current = current.Parent;
        }

        throw new InvalidDataException("Ghidra session path escaped its isolated root.");
    }

    private static async Task<bool> TryDeleteAsync(string path)
    {
        // Only ever remove launcher-owned session roots; anything else fails
        // closed without touching it.
        if (!LauncherTempRoot.IsOwnedSessionRoot(path))
            return false;

        var stopwatch = Stopwatch.StartNew();
        var timeout = TimeSpan.FromSeconds(CleanupTimeoutSeconds);
        while (stopwatch.Elapsed < timeout)
        {
            try
            {
                if (!Directory.Exists(path))
                    return !File.Exists(path);
                if (!PathSafety.IsReparseFree(path))
                    return false;

                LauncherTempRoot.DeleteTreeOnce(path);
                return !Directory.Exists(path) && !File.Exists(path);
            }
            catch (DirectoryNotFoundException)
            {
                return true;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            await Task.Delay(CleanupRetryMilliseconds).ConfigureAwait(false);
        }

        return !Directory.Exists(path);
    }

    private static void EnsureNoReparseAncestors(string path)
    {
        if (!PathSafety.IsReparseFree(path))
            throw new InvalidDataException("Ghidra session path contains a reparse point.");
    }
}
