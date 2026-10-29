using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Starts and stops the fixed DBGLink toolkit process set.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class ToolkitCoordinator : IAsyncDisposable
{
    private static readonly ToolkitComponent[] Components =
    {
        ToolkitComponent.Debugger,
        ToolkitComponent.NativeBridge,
        ToolkitComponent.McpServer,
        ToolkitComponent.GhidraBridge,
        ToolkitComponent.Toolkit
    };

    private readonly object _statusLock = new();
    private readonly Dictionary<ToolkitComponent, ToolkitStatusUpdate> _statuses = new();
    private Process? _debugger;
    private Process? _server;
    private Process? _ghidra;
    private WindowsProcessJob? _job;
    private string? _sessionRunRoot;
    private GhidraSession? _ghidraSession;
    private GhidraControlPipeServer? _ghidraControl;
    private string? _ghidraControlToken;
    private SessionMetricsClient? _metricsClient;
    private readonly ConcurrentQueue<string> _serverDiagnostics = new();
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);
    private readonly SemaphoreSlim _ghidraOpenLock = new(1, 1);
    private readonly ConcurrentDictionary<string, AnalysisRuntime> _analysisSessions = new(StringComparer.Ordinal);
    private const int MaxAnalysisSessions = 8;
    // Ghidra may spend several minutes importing/loading its first project on
    // a cold JVM. Keep this bounded, but leave one minute over the configured
    // headless budget for JVM start-up and bridge activation.
    private static readonly TimeSpan GhidraReadyTimeout =
        GhidraSession.ResolveImportTimeout() + TimeSpan.FromMinutes(1);
    private int _disposed;

    public ToolkitCoordinator()
    {
        foreach (var component in Components)
            _statuses[component] = new(component, ToolkitComponentState.Pending, "Waiting to launch.");
    }

    public event Action<ToolkitStatusUpdate>? StatusChanged;

    public IReadOnlyList<ToolkitStatusUpdate> StatusSnapshot
    {
        get
        {
            lock (_statusLock)
                return Components.Select(component => _statuses[component]).ToArray();
        }
    }

    public bool IsRunning => IsAlive(_debugger) || IsAlive(_server) || IsAlive(_ghidra) ||
        _analysisSessions.Values.Any(session => IsAlive(session.Debugger) || IsAlive(session.Ghidra));

    private bool HasOwnedRuntimeState =>
        _debugger is not null ||
        _server is not null ||
        _ghidra is not null ||
        _job is not null ||
        _sessionRunRoot is not null ||
        _ghidraSession is not null ||
        _ghidraControl is not null ||
        _ghidraControlToken is not null ||
        _metricsClient is not null ||
        !_analysisSessions.IsEmpty;

    public string? GhidraEndpointDirectory => _ghidraSession?.EndpointDirectory;

    public GhidraBridgeStatus? GhidraStatus { get; private set; }

    public double? StartupElapsedMs { get; private set; }

    public bool GhidraCleanupSucceeded { get; private set; } = true;

    public bool TempRootCleanupSucceeded { get; private set; } = true;

    public string? GhidraControlPipeName => _ghidraControl?.PipeName;

    public string? McpServerDiagnostics => ServerDiagnostics();

    public int? McpServerExitCode
    {
        get
        {
            try
            {
                return _server is { HasExited: true } ? _server.ExitCode : null;
            }
            catch (InvalidOperationException) { return null; }
            catch (System.ComponentModel.Win32Exception) { return null; }
        }
    }

    public ToolkitProcessSnapshot ReadProcessSnapshot() =>
        new(
            DateTimeOffset.UtcNow,
            ToolkitProcessMetricsReader.Read(ToolkitComponent.Debugger, _debugger),
            ToolkitProcessMetricsReader.Read(ToolkitComponent.McpServer, _server),
            ReadGhidraProcessMetrics());

    public async Task<SessionMetricsSnapshot?> ReadMetricsAsync(CancellationToken cancellationToken)
        => _metricsClient is null
            ? null
            : await _metricsClient.ReadAsync(cancellationToken).ConfigureAwait(false);

    public void ReportRuntimeFailure(ToolkitComponent component, string message)
    {
        UpdateStatus(component, ToolkitComponentState.Failed, message);
        UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Failed, "Toolkit failed at runtime; see launcher diagnostics.");
    }

    private async Task<GhidraOpenResult> OpenGhidraFileAsync(
        LauncherPlan plan,
        Action<string> report,
        string inputFile,
        CancellationToken cancellationToken, bool analyze = true)
    {
        plan = plan with { Settings = plan.Settings with { Mode = ReverseMode.LetLlmChoose, InputFile = null } };

        await _ghidraOpenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_analysisSessions.Count >= MaxAnalysisSessions)
                throw new InvalidOperationException("The maximum number of parallel analysis sessions has been reached.");

            UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Starting, "Creating a parallel analysis session.");
            var analysisId = "analysis-" + Guid.NewGuid().ToString("N");
            var session = await GhidraSession.PrepareAsync(plan, report, cancellationToken, _sessionRunRoot).ConfigureAwait(false);
            Process? debugger = null;
            Process? ghidra = null;
            AnalysisRuntime? registeredRuntime = null;
            // Explicit ownership flag instead of a null sentinel: the session
            // is ours until the runtime is registered, and a "session = null!"
            // marker made the catch handler's ownership decision depend on
            // the accident of where the failure happened.
            var sessionOwned = true;
            try
            {
                UpdateStatus(ToolkitComponent.GhidraBridge, ToolkitComponentState.Starting, "Importing the analysis target into an isolated Ghidra session.");
                var target = await session.OpenProgramAsync(plan, inputFile, report, cancellationToken, analyze).ConfigureAwait(false);
                ghidra = Start(LauncherPlanner.CreateGhidraSpec(plan, session));
                (_job ?? throw new InvalidOperationException("The launcher process job is unavailable.")).Assign(ghidra);
                var ghidraStatus = await GhidraBridgeProbe.WaitForReadyAsync(
                    session.EndpointDirectory,
                    requireActiveProgram: true,
                    GhidraReadyTimeout,
                    cancellationToken).ConfigureAwait(false);

                var architecture = DebuggerArchitectureDetector.Detect(target.FullPath, plan.Settings.Debugger);
                debugger = Start(LauncherPlanner.CreateDebuggerSpec(plan, architecture, target.FullPath));
                (_job ?? throw new InvalidOperationException("The launcher process job is unavailable.")).Assign(debugger);
                var (analysisEndpoint, _) = await WaitForNativeBridgeAsync(
                    debugger,
                    report,
                    cancellationToken).ConfigureAwait(false);

                var runtime = new AnalysisRuntime(analysisId, debugger, ghidra, session, analysisEndpoint.BarePipeName, analysisEndpoint.Token, ghidraStatus.ProcessId,
                    architecture, target.FullPath);
                if (!_analysisSessions.TryAdd(analysisId, runtime))
                    throw new InvalidOperationException("The analysis session identifier collided.");

                registeredRuntime = runtime;
                UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Ready, "Parallel analysis session is ready.");
                report(
                    $"Analysis session {analysisId} is ready for {DescribeProgram(ghidraStatus.Program, target.FileName)} " +
                    $"({architecture}).");
                debugger = null;
                ghidra = null;
                sessionOwned = false;
                return new(
                    true,
                    target.FileName,
                    true,
                    analysisId,
                    analysisEndpoint.BarePipeName,
                    runtime.GhidraSession.EndpointDirectory,
                    ghidraStatus.Program,
                    analysisEndpoint.Token);
            }
            catch
            {
                if (registeredRuntime is not null)
                {
                    if (_analysisSessions.TryRemove(registeredRuntime.AnalysisId, out var removedRuntime))
                    {
                        await CloseGracefullyAsync(removedRuntime.Ghidra, "Ghidra analysis session", null, force: true).ConfigureAwait(false);
                        await CloseGracefullyAsync(removedRuntime.Debugger, "debugger analysis session", null, force: true).ConfigureAwait(false);
                        await removedRuntime.GhidraSession.DisposeAsync().ConfigureAwait(false);
                    }
                }
                else
                {
                    if (ghidra is not null)
                        await CloseGracefullyAsync(ghidra, "Ghidra analysis session", null, force: true).ConfigureAwait(false);
                    if (debugger is not null)
                        await CloseGracefullyAsync(debugger, "debugger analysis session", null, force: true).ConfigureAwait(false);
                    if (sessionOwned)
                        await session.DisposeAsync().ConfigureAwait(false);
                }
                throw;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            UpdateStatus(
                ToolkitComponent.GhidraBridge,
                ToolkitComponentState.Failed,
                ToolkitDiagnostics.Sanitize($"{exception.GetType().Name}: {exception.Message}"));
            UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Failed, "The parallel analysis session could not be created.");
            throw;
        }
        finally
        {
            _ghidraOpenLock.Release();
        }
    }

    private sealed record AnalysisRuntime(
        string AnalysisId,
        Process Debugger,
        Process Ghidra,
        GhidraSession GhidraSession,
        string NativePipeName,
        string NativePipeToken,
        long GhidraProcessId,
        DebuggerArchitecture Architecture,
        string TargetPath);

    /// <summary>
    /// N1 native handshake for one debugger process: polls the rendezvous
    /// file inside the shared handshake window, then probes the published
    /// pipe with the remaining budget. The rendezvous file is deleted once
    /// validated. Throws (fail closed) when the window expires.
    /// </summary>
    private static async Task<(NativeEndpoint Endpoint, NativeBridgeHandshake Handshake)> WaitForNativeBridgeAsync(
        Process debugger,
        Action<string>? report,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(debugger);
        var window = TimeSpan.FromSeconds(15);
        var stopwatch = Stopwatch.StartNew();
        var endpoint = await NativeEndpointResolver.WaitForEndpointAsync(
            debugger.Id,
            window,
            cancellationToken,
            () => !debugger.HasExited,
            report).ConfigureAwait(false);
        var remaining = window - stopwatch.Elapsed;
        if (remaining <= TimeSpan.Zero)
            throw new TimeoutException(
                $"The DBGLink native bridge handshake exceeded its window (debugger PID {debugger.Id}).");
        var handshake = await NativePipeProbe.WaitForReadyAsync(
            endpoint.PipeName,
            debugger.Id,
            remaining,
            cancellationToken,
            () => !debugger.HasExited,
            endpoint.Token).ConfigureAwait(false);
        return (endpoint, handshake);
    }

    private static Process Start(ProcessLaunchSpec spec)
        => ProcessLauncher.Start(spec);

    private ToolkitProcessMetrics? ReadGhidraProcessMetrics()
    {
        if (GhidraStatus is { ProcessId: > 0 and <= int.MaxValue } status)
        {
            try
            {
                using var activeProcess = Process.GetProcessById((int)status.ProcessId);
                return ToolkitProcessMetricsReader.Read(ToolkitComponent.GhidraBridge, activeProcess);
            }
            catch (ArgumentException) { }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }

        return ToolkitProcessMetricsReader.Read(ToolkitComponent.GhidraBridge, _ghidra);
    }

    private void ResetStatuses()
    {
        foreach (var component in Components)
            UpdateStatus(component, ToolkitComponentState.Pending, "Waiting to launch.");
    }

    private static string DescribeProgram(GhidraProgramSummary? program, string? fallbackFileName = null)
    {
        if (program is null)
            return string.IsNullOrWhiteSpace(fallbackFileName) ? "active program" : fallbackFileName;

        var parts = new List<string> { program.FileName };
        if (!string.IsNullOrWhiteSpace(program.Format) &&
            !program.Format.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            parts.Add(program.Format);
        if (!string.IsNullOrWhiteSpace(program.Architecture) &&
            !program.Architecture.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            parts.Add(program.Architecture);
        parts.Add($"{program.FunctionCount} functions");
        return string.Join(", ", parts);
    }

    private void UpdateStatus(
        ToolkitComponent component,
        ToolkitComponentState state,
        string message)
    {
        var update = new ToolkitStatusUpdate(component, state, ToolkitDiagnostics.Sanitize(message));
        lock (_statusLock)
            _statuses[component] = update;

        var handlers = StatusChanged;
        if (handlers is null)
            return;

        foreach (Action<ToolkitStatusUpdate> handler in handlers.GetInvocationList())
        {
            try { handler(update); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
            catch (Exception) { }
        }
    }

    private static bool IsAlive(Process? process)
    {
        try { return process is { HasExited: false }; }
        catch (InvalidOperationException) { return false; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private void BeginServerDiagnostics(Process process)
    {
        while (_serverDiagnostics.TryDequeue(out _)) { }
        process.OutputDataReceived += (_, eventArgs) => RecordServerDiagnostic("stdout", eventArgs.Data);
        process.ErrorDataReceived += (_, eventArgs) => RecordServerDiagnostic("stderr", eventArgs.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    private void RecordServerDiagnostic(string stream, string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        var diagnostic = ToolkitDiagnostics.Sanitize($"{stream}: {line}");
        while (_serverDiagnostics.Count >= 64 && _serverDiagnostics.TryDequeue(out _)) { }
        _serverDiagnostics.Enqueue(diagnostic);
    }

    private string? ServerDiagnostics()
    {
        var diagnostics = string.Join(" | ", _serverDiagnostics);
        return string.IsNullOrWhiteSpace(diagnostics) ? null : diagnostics;
    }

    private static async Task WaitForTcpListenerAsync(
        Process serverProcess,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Func<string?>? diagnostics = null)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (serverProcess.HasExited)
            {
                serverProcess.WaitForExit(100);
                var exitCode = serverProcess.ExitCode;
                var detail = exitCode switch
                {
                    2 => "The native bridge did not answer; verify that the matching DbgLink plugin is loaded in the debugger and that the debugger is still running.",
                    3 => "The configured localhost port is already in use.",
                    4 => "The MCP server failed during startup; inspect the captured server diagnostics.",
                    _ => "Check the DbgLink.Server diagnostics and the selected debugger installation."
                };
                var diagnosticText = diagnostics?.Invoke();
                throw new InvalidOperationException(
                    $"DbgLink.Server exited before listening (exit code {exitCode}). {detail}" +
                    (string.IsNullOrWhiteSpace(diagnosticText) ? string.Empty : $" Diagnostics: {diagnosticText}"));
            }
            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                return;
            }
            catch (SocketException) { }
            catch (IOException) { }

            var remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
                break;
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(250, remaining.TotalMilliseconds)), cancellationToken);
        }

        var timeoutDiagnostics = diagnostics?.Invoke();
        throw new TimeoutException(
            "The local DBGLink MCP server did not start listening." +
            (string.IsNullOrWhiteSpace(timeoutDiagnostics) ? string.Empty : $" Diagnostics: {timeoutDiagnostics}"));
    }

    private static async Task CloseGracefullyAsync(
        Process? process,
        string name,
        Action<string>? report,
        bool force)
    {
        if (process is null)
            return;

        try
        {
            if (!process.HasExited)
            {
                if (process.MainWindowHandle != IntPtr.Zero)
                    process.CloseMainWindow();

                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try { await process.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException) { }

                if (force && !process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    using var killTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    try { await process.WaitForExitAsync(killTimeout.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { }
                }
            }

            ReportSafely(report, $"{name} stopped.");
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception exception)
        {
            ReportSafely(report, $"Could not stop {name}: {exception.Message}");
        }
        finally
        {
            process.Dispose();
        }
    }

    private static void ReportSafely(Action<string>? report, string message)
    {
        try { report?.Invoke(message); }
        catch (Exception) { }
    }
}
