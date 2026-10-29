using System.Text.Json;
using DbgLink.Launcher.Core;
using DbgLink.Shared;

namespace DbgLink.Launcher.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        CommandLineOptions options;
        try { options = CommandLineOptions.Parse(args); }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            Console.Error.WriteLine("Use --help for usage.");
            return 2;
        }

        if (options.Help)
        {
            PrintHelp();
            return 0;
        }

        if (options.ClearCache)
        {
            var cleared = GhidraSession.ClearProjectCache();
            Write(options, "cache", $"Cleared {cleared.Entries} cached Ghidra project(s), {cleared.Bytes} bytes.", new
            {
                entries = cleared.Entries,
                bytes = cleared.Bytes
            });
            return 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("DBGLink headless launcher requires Windows.");
            return 2;
        }

        try
        {
            var shutdownFile = ResolveShutdownFile(options.ShutdownFile);
            var resolved = HeadlessConfiguration.Resolve(options);
            foreach (var message in resolved.Messages)
                Write(options, "configuration", message);
            if (!resolved.IsValid)
            {
                foreach (var error in resolved.Errors)
                    Write(options, "error", error);
                return 2;
            }

            var planning = LauncherPlanner.Plan(resolved.Settings!);
            if (!planning.IsValid)
            {
                foreach (var issue in planning.Issues)
                    Write(options, "error", issue.Message, new { code = issue.Code });
                return 2;
            }

            using var stop = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                stop.Cancel();
            };
            await using var coordinator = new ToolkitCoordinator();
            coordinator.StatusChanged += status => Write(options, "status", status.Message, new
            {
                component = status.Component.ToString(),
                state = status.State.ToString()
            });
            var startupTimeout = GhidraSession.ResolveStartupTimeout();
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                startup.CancelAfter(startupTimeout);
                try
                {
                    await coordinator.LaunchAsync(
                        planning.Plan!, message => Write(options, "log", message), startup.Token);
                }
                catch (OperationCanceledException) when (!stop.IsCancellationRequested && startup.IsCancellationRequested)
                {
                    Write(options, "error",
                        $"Startup exceeded the bounded {startupTimeout.TotalMinutes:0.#}-minute window; stopping the toolkit.",
                        new { code = "startup_timeout" });
                    await coordinator.StopAsync(message => Write(options, "log", message));
                    return 1;
                }
            }
            var program = coordinator.GhidraStatus?.Program;
            Write(options, "ready", program is null
                ? "DBGLink MCP server is ready; choose a static target with OpenGhidraFile."
                : $"DBGLink MCP server is ready; opened {program.FileName}.", new
            {
                endpoint = $"http://127.0.0.1:{options.Port}/mcp",
                configPath = DbgLinkConfigPath.GetPath(),
                mode = resolved.Settings!.Mode.ToString(),
                pid = Environment.ProcessId,
                startupMs = coordinator.StartupElapsedMs,
                target = program is null ? null : new
                {
                    fileName = program.FileName,
                    format = program.Format,
                    architecture = program.Architecture,
                    language = program.Language,
                    languageId = program.LanguageId,
                    compiler = program.Compiler,
                    compilerSpec = program.CompilerSpec,
                    sha256 = program.Sha256,
                    imageBase = program.ImageBase,
                    minAddress = program.MinAddress,
                    maxAddress = program.MaxAddress,
                    functionCount = program.FunctionCount
                }
            });

            try
            {
                if (shutdownFile is null)
                    await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
                else
                {
                    await WaitForShutdownFileAsync(shutdownFile, stop.Token);
                    Write(options, "log", "Shutdown signal file detected.");
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            await coordinator.StopAsync(message => Write(options, "log", message));
            Write(options, "stopped", "DBGLink toolkit stopped.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception exception)
        {
            Write(options, "error", ToolkitDiagnostics.Describe(exception));
            return 1;
        }
    }

    private static void Write(CommandLineOptions options, string type, string message, object? data = null)
    {
        if (!options.Json)
        {
            Console.WriteLine($"[{type}] {message}");
            return;
        }
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            type,
            message,
            timestamp = DateTimeOffset.UtcNow,
            data
        }));
    }

    private static void PrintHelp() => Console.WriteLine(
        $"""
        DBGLink headless launcher

        Usage:
          DbgLink.Launcher.Cli [options]

        With no options, discovers x64dbg, x32dbg, Ghidra and the packaged DBGLink
        runtime, installs both native bridges, starts the toolkit in LLM-select mode,
        prints a JSON ready event, and runs until Ctrl+C or process termination.

        Options:
          --input <file>          Open one target immediately instead of LLM-select mode
          --shutdown-file <file>  Stop gracefully when this local signal file appears
          --x64dbg <file>         Override x64dbg.exe
          --x32dbg <file>         Override x32dbg.exe
          --ghidra-home <dir>     Override the Ghidra installation
          --bundle-root <dir>     DBGLink package containing x64/plugins and x86/plugins
          --port <1-65535>        MCP port (default: {LauncherDefaults.DefaultPort})
          --no-install            Use an already installed runtime without copying files
          --allow-annotation      Already enabled by default (accepted for compatibility)
          --allow-mutation        Already enabled by default (accepted for compatibility)
          --relaxed               Allow discovery of the toolkit in user-owned folders
                                   (%USERPROFILE%, Desktop, Downloads, %LOCALAPPDATA%)
                                   instead of only Program Files and the shipped bundle
          --clear-cache           Delete cached Ghidra projects and exit
          --text                  Human-readable output instead of JSON Lines
          --json                  JSON Lines output (default; accepted for compatibility)
          --help                  Show this help (-h and /? also work)

        Environment overrides:
          DBGLINK_X64DBG_PATH, DBGLINK_X32DBG_PATH, DBGLINK_GHIDRA_HOME,
          GHIDRA_INSTALL_DIR, DBGLINK_BUNDLE_ROOT, JAVA_HOME
        """);

    private static string? ResolveShutdownFile(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
            return null;

        try
        {
            var fullPath = Path.GetFullPath(configuredPath);
            if (!Path.IsPathFullyQualified(fullPath) || Directory.Exists(fullPath))
                throw new ArgumentException("--shutdown-file must name a local file.");
            return fullPath;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new ArgumentException("--shutdown-file must name a local file.", exception);
        }
    }

    private static async Task WaitForShutdownFileAsync(string shutdownFile, CancellationToken cancellationToken)
    {
        while (!File.Exists(shutdownFile))
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
    }
}
