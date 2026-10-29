using static DbgLink.Server.ToolSupport;
using static DbgLink.Server.AddressMapping;
using DbgLink.Shared;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace DbgLink.Server;

internal static class Program
{
    // Default bridge startup budget: the native plugin normally starts within
    // a few seconds, but a cold start (or a slow machine) can legitimately take
    // much longer.
    private static readonly TimeSpan BridgeStartupTimeout = TimeSpan.FromSeconds(60);

    // Relaxed mode shortens the budget: it is the mode for ad-hoc runs from
    // user-owned folders where the toolkit is started by hand and the operator
    // wants an immediate answer about the native bridge instead of a long wait.
    private static readonly TimeSpan RelaxedBridgeStartupTimeout = TimeSpan.FromSeconds(5);

    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunAsync(args);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"DBGLink server arguments are invalid: {exception.Message}");
            Console.Error.WriteLine("Use --pipe-name, --pipe-token, --port, --config-path, --allow-annotation, or --allow-mutation.");
            return 2;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Console.Error.WriteLine($"DBGLink server startup failed ({exception.GetType().Name}): {exception.Message}");
            return 4;
        }
    }

    internal static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var commandLine = ParseCommandLine(args);
        if (commandLine.Help)
        {
            Console.WriteLine(Usage());
            return 0;
        }

        var config = ServerConfig.Load(
            commandLine.Port,
            commandLine.PermissionOverrides,
            configPath: commandLine.ConfigPath,
            ghidraControlPipeName: Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_CONTROL_PIPE"),
            ghidraControlToken: Environment.GetEnvironmentVariable("DBGLINK_GHIDRA_CONTROL_TOKEN"));
        using var bridge = new BridgeClient(
            commandLine.PipeName,
            commandLine.PipeToken,
            requirePipeToken: commandLine.PipeToken is not null);
        var ghidra = new GhidraClient();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ConsoleCancelEventHandler cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            stop.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        var startupTimeout = commandLine.Relaxed
            ? RelaxedBridgeStartupTimeout
            : BridgeStartupTimeout;
        try
        {
            if (!await WaitForBridgeAsync(bridge, startupTimeout, stop.Token))
            {
                if (stop.IsCancellationRequested)
                    return 0;

                Console.Error.WriteLine(
                    $"DBGLink native bridge is not available on pipe '{commandLine.PipeName}' " +
                    $"after {startupTimeout.TotalSeconds:0} seconds." +
                    (string.IsNullOrWhiteSpace(bridge.LastFailure) ? string.Empty : $" Last error: {bridge.LastFailure}"));
                return 2;
            }

            using var server = new LocalMcpServer(config, bridge, ghidra);
            foreach (var message in StartupMessages(config))
                Console.WriteLine(message);
            if (commandLine.Relaxed)
                Console.WriteLine($"DBGLink relaxed mode: bridge startup ping budget is {startupTimeout.TotalSeconds:0} seconds.");

            var exitCode = 0;
            try
            {
                // The launcher (or the autostarting native plugin) owns this process.
                // The startup debugger is only the initial session backend: switching
                // architecture or closing that session must leave MCP available to
                // inspect, reopen and manage the remaining sessions.
                try { await server.RunAsync(stop.Token); }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            }
            catch (HttpListenerException exception)
            {
                Console.Error.WriteLine($"DBGLink HTTP listener could not start on 127.0.0.1:{config.Port} ({exception.ErrorCode}). Stop the other DBGLink server instance first.");
                exitCode = 3;
            }
            finally { server.Stop(); }

            return exitCode;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static async Task<bool> WaitForBridgeAsync(
        BridgeClient bridge,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            timeoutCancellation.Token,
            cancellationToken);
        var waitToken = linkedCancellation.Token;
        while (stopwatch.Elapsed < timeout && !waitToken.IsCancellationRequested)
        {
            try
            {
                if (await bridge.PingAsync(waitToken))
                    return true;
            }
            catch (OperationCanceledException) when (waitToken.IsCancellationRequested)
            {
                break;
            }

            var remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
                break;
            try
            {
                await Task.Delay(
                    TimeSpan.FromMilliseconds(Math.Min(250, remaining.TotalMilliseconds)),
                    waitToken);
            }
            catch (OperationCanceledException) when (waitToken.IsCancellationRequested)
            {
                break;
            }
        }

        return false;
    }

    internal static IReadOnlyList<string> StartupMessages(ServerConfig config)
        => new[]
        {
            $"DBGLink server listening on {config.DisplayUrl}",
            config.RequireAuthToken
                ? "DBGLink MCP authentication: Authorization: Bearer required on /mcp and /metrics (enabled by default; DBGLINK_REQUIRE_AUTH=0 disables /mcp auth)."
                : "DBGLink MCP authentication: /metrics requires Authorization: Bearer; /mcp auth disabled via DBGLINK_REQUIRE_AUTH=0 (loopback binding only).",
            $"DBGLink profile: {config.Profile}, annotation={(config.AllowAnnotation ? "enabled" : "disabled")}, mutation={(config.AllowMutation ? "enabled" : "disabled")}, limits=requests{config.MaxConcurrentRequests}/queue{config.MaxQueuedOperations}/body{config.MaxRequestBodyBytes}B/timeout{config.DefaultToolTimeoutMs}ms",
        };

    internal static string Usage()
        => $"""
            DBGLink MCP server

            Usage:
              DbgLink.Server.exe [options]

            Options:
              --pipe-name <name>       Native bridge pipe (default: DbgLink.Control)
              --pipe-token <token>     Native bridge pipe token passed by the launcher
                                       (omit only against the legacy plugin)
              --port <1-65535>         Loopback HTTP port (default: {ServerConfig.DefaultPort})
              --config-path <path>     Local server configuration path
              --allow-annotation true|false
              --allow-mutation true|false
              --relaxed                Shorten the bridge startup ping budget to
                                       {RelaxedBridgeStartupTimeout.TotalSeconds:0} seconds (default {BridgeStartupTimeout.TotalSeconds:0})
              --help, -h, /?           Show this help and exit

            Environment:
              DBGLINK_BEARER_TOKEN     Override the generated bearer token
              DBGLINK_REQUIRE_AUTH     Auth on /mcp is enabled by default
                                       (/metrics always requires it);
                                       DBGLINK_REQUIRE_AUTH=0 disables /mcp auth
            """;

    internal static ServerCommandLineOptions ParseCommandLine(string[] args)
    {
        string? pipeName = null;
        // The pipe token arrives through the environment (DBGLINK_NATIVE_PIPE_TOKEN)
        // because a command-line credential is readable by every local process
        // through Win32_Process.CommandLine. --pipe-token stays supported for
        // manual runs and wins over the environment when both are present.
        string? pipeToken = Environment.GetEnvironmentVariable(DbgLink.Shared.DbgLinkConfigPath.NativePipeTokenEnvironmentVariable);
        string? pipeTokenFromCommandLine = null;
        string? configPath = null;
        var port = ServerConfig.DefaultPort;
        var portSpecified = false;
        bool? allowAnnotation = null;
        bool? allowMutation = null;
        var relaxed = false;
        var help = false;

        for (var index = 0; index < args.Length; index++)
        {
            var option = args[index].ToLowerInvariant();
            switch (option)
            {
                case "--pipe-name":
                    EnsureUnset(pipeName, option);
                    pipeName = Value(args, ref index, option);
                    break;
                case "--pipe-token":
                    EnsureUnset(pipeTokenFromCommandLine, option);
                    pipeTokenFromCommandLine = Value(args, ref index, option);
                    break;
                case "--port":
                    if (portSpecified)
                        throw new ArgumentException("--port may be specified only once.");
                    port = ParsePort(Value(args, ref index, option));
                    portSpecified = true;
                    break;
                case "--config-path":
                    EnsureUnset(configPath, option);
                    configPath = Value(args, ref index, option);
                    break;
                case "--allow-annotation":
                    if (allowAnnotation.HasValue)
                        throw new ArgumentException("--allow-annotation may be specified only once.");
                    allowAnnotation = ParseBoolean(Value(args, ref index, option));
                    break;
                case "--allow-mutation":
                    if (allowMutation.HasValue)
                        throw new ArgumentException("--allow-mutation may be specified only once.");
                    allowMutation = ParseBoolean(Value(args, ref index, option));
                    break;
                case "--relaxed":
                    relaxed = true;
                    break;
                case "--help":
                case "-h":
                case "/?":
                    help = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[index]}");
            }
        }

        return new(
            pipeName ?? "DbgLink.Control",
            // An explicit --pipe-token overrides the environment; a blank
            // environment value must not silently disable the requirement.
            pipeTokenFromCommandLine ?? (string.IsNullOrWhiteSpace(pipeToken) ? null : pipeToken),
            port,
            configPath,
            new ServerPermissionOverrides(allowAnnotation, allowMutation),
            relaxed,
            help);
    }

    private static string Value(string[] args, ref int index, string option)
    {
        if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]) ||
            (args[index].StartsWith("-", StringComparison.Ordinal) && !Path.IsPathFullyQualified(args[index])))
            throw new ArgumentException($"{option} requires a value.");
        return args[index];
    }

    private static void EnsureUnset(string? current, string option)
    {
        if (current is not null)
            throw new ArgumentException($"{option} may be specified only once.");
    }

    private static int ParsePort(string raw)
    {
        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            throw new ArgumentException("--port must be between 1 and 65535.");
        return port;
    }

    private static bool ParseBoolean(string raw)
    {
        if (!bool.TryParse(raw, out var value))
            throw new ArgumentException($"Boolean option value '{raw}' is invalid; use true or false.");
        return value;
    }
}

internal sealed record ServerCommandLineOptions(
    string PipeName,
    string? PipeToken,
    int Port,
    string? ConfigPath,
    ServerPermissionOverrides PermissionOverrides,
    bool Relaxed,
    bool Help);

internal static class MonotonicClock
{
    public static long ElapsedMilliseconds(long startMilliseconds)
        => ElapsedMilliseconds(startMilliseconds, Environment.TickCount64);

    public static long ElapsedMilliseconds(long startMilliseconds, long endMilliseconds)
        => unchecked(endMilliseconds - startMilliseconds);
}
