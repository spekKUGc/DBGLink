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
    public async Task LaunchAsync(
        LauncherPlan plan,
        Action<string> report,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            await LaunchCoreAsync(plan, report, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private async Task LaunchCoreAsync(
        LauncherPlan plan,
        Action<string> report,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(report);

        if (IsRunning)
            throw new InvalidOperationException("The toolkit is already running.");

        if (HasOwnedRuntimeState)
        {
            report("Cleaning up stale toolkit state before restarting.");
            await StopCoreAsync(report).ConfigureAwait(false);
        }

        GhidraStatus = null;
        StartupElapsedMs = null;
        GhidraCleanupSucceeded = true;
        TempRootCleanupSucceeded = true;
        _defaultEndpoint = null;
        ResetStatuses();
        UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Starting, "Starting the toolkit.");
        var activeComponent = ToolkitComponent.GhidraBridge;
        var activePhase = "preparing the isolated Ghidra session";
        _job = WindowsProcessJob.Create();
        var startupStopwatch = Stopwatch.StartNew();
        Task<GhidraSession>? sessionPreparation = null;
        using var preparationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            // Owned first: every session directory of this run nests beneath
            // it, and the shutdown sweep removes it on all paths below.
            _sessionRunRoot = LauncherTempRoot.CreateRunRoot();
            UpdateStatus(
                ToolkitComponent.GhidraBridge,
                ToolkitComponentState.Starting,
                "Preparing the isolated Ghidra session in parallel with debugger startup.");
            report("Preparing the isolated Ghidra session in parallel with debugger startup.");
            sessionPreparation = GhidraSession.PrepareAsync(
                plan,
                report,
                preparationCancellation.Token,
                _sessionRunRoot,
                analyze: !GhidraSession.ResolveFastAnalysis());

            {
                var controlPipeName = "DbgLink.GhidraControl." + Guid.NewGuid().ToString("N");
                _ghidraControlToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
                _ghidraControl = new GhidraControlPipeServer(
                    controlPipeName,
                    _ghidraControlToken,
                    (path, requestCancellation) => OpenGhidraFileAsync(plan, report, path, requestCancellation))
                {
                    OpenWithAnalysisMode = (path, analyze, token) => OpenGhidraFileAsync(plan, report, path, token, analyze),
                    SessionControl = (method, request, token) => ControlSessionAsync(plan, method, request, token)
                };
                _ghidraControl.Start();
                report("Ghidra file-selection control is ready for the connected LLM.");
            }

            activeComponent = ToolkitComponent.Debugger;
            activePhase = "starting debugger";
            UpdateStatus(activeComponent, ToolkitComponentState.Starting, "Starting debugger.");
            var debuggerSpec = LauncherPlanner.CreateDebuggerSpec(plan);
            _debugger = Start(debuggerSpec);
            _defaultArchitecture = plan.Settings.Debugger;
            _defaultTarget = plan.Settings.InputFile;
            _job.Assign(_debugger);
            UpdateStatus(activeComponent, ToolkitComponentState.Ready, $"Process started (PID {_debugger.Id}).");
            report($"Debugger started (PID {_debugger.Id}). Waiting for the native bridge...");

            activeComponent = ToolkitComponent.GhidraBridge;
            activePhase = "preparing the isolated Ghidra session";
            _ghidraSession = await sessionPreparation.ConfigureAwait(false);
            sessionPreparation = null;
            UpdateStatus(
                activeComponent,
                ToolkitComponentState.Starting,
                "Ghidra project is prepared; starting the analysis bridge.");

            activePhase = "starting the Ghidra bridge";
            _ghidra = Start(LauncherPlanner.CreateGhidraSpec(plan, _ghidraSession));
            _job.Assign(_ghidra);
            report("Ghidra started; its program activation now overlaps native and MCP startup.");

            var debuggerProcess = _debugger;
            activeComponent = ToolkitComponent.NativeBridge;
            activePhase = "verifying the native bridge";
            UpdateStatus(
                activeComponent,
                ToolkitComponentState.Starting,
                "Waiting for the native pipe handshake (up to 15 seconds).");
            var (nativeEndpoint, handshake) = await WaitForNativeBridgeAsync(
                debuggerProcess,
                report,
                cancellationToken).ConfigureAwait(false);
            _defaultEndpoint = nativeEndpoint;
            UpdateStatus(activeComponent, ToolkitComponentState.Ready, $"Verified for debugger PID {handshake.ProcessId}.");
            report($"Native DBGLink bridge verified (PID {handshake.ProcessId}, debugging={handshake.Debugging}). Starting the MCP server...");

            activeComponent = ToolkitComponent.McpServer;
            activePhase = "starting the MCP server";
            UpdateStatus(activeComponent, ToolkitComponentState.Starting, "Starting on the loopback endpoint.");
            var serverSpec = LauncherPlanner.CreateServerSpec(
                plan,
                debuggerProcess.Id,
                _ghidraSession.EndpointDirectory,
                _ghidraControl?.PipeName,
                _ghidraControlToken,
                nativeEndpoint.PipeName,
                nativeEndpoint.Token);
            _server = Start(serverSpec);
            BeginServerDiagnostics(_server);
            _job.Assign(_server);
            await WaitForTcpListenerAsync(
                _server,
                plan.Settings.Port,
                TimeSpan.FromSeconds(10),
                cancellationToken,
                ServerDiagnostics);
            UpdateStatus(activeComponent, ToolkitComponentState.Ready, $"Listening on 127.0.0.1:{plan.Settings.Port}.");
            report("DBGLink MCP server started on localhost.");
            _metricsClient = new SessionMetricsClient(
                plan.Settings.Port,
                DbgLink.Shared.DbgLinkConfigPath.GetPath());

            activeComponent = ToolkitComponent.GhidraBridge;
            activePhase = "verifying the Ghidra bridge";
            if (plan.Settings.Mode == ReverseMode.ChooseFile)
            {
                report("Ghidra is running. Waiting for the selected program to become active...");
                var ghidraStatus = await GhidraBridgeProbe.WaitForReadyAsync(
                    _ghidraSession.EndpointDirectory,
                    requireActiveProgram: true,
                    GhidraReadyTimeout,
                    cancellationToken).ConfigureAwait(false);
                GhidraStatus = ghidraStatus;
                var programDescription = DescribeProgram(
                    ghidraStatus.Program,
                    Path.GetFileName(plan.Settings.InputFile));
                UpdateStatus(
                    activeComponent,
                    ToolkitComponentState.Ready,
                    $"Active program verified: {programDescription} (PID {ghidraStatus.ProcessId}).");
                report(
                    $"Ghidra bridge verified (PID {ghidraStatus.ProcessId}, response {ghidraStatus.ResponseBytes} bytes). " +
                    $"Opened {programDescription}.");
            }
            else
            {
                UpdateStatus(
                    activeComponent,
                    ToolkitComponentState.WaitingForTarget,
                    "Ghidra is waiting for the LLM to choose a target through OpenGhidraFile.");
                report("Ghidra started without a target file. The LLM can now call OpenGhidraFile to import and open one safely.");
            }
            startupStopwatch.Stop();
            StartupElapsedMs = startupStopwatch.Elapsed.TotalMilliseconds;
            var toolkitMessage = plan.Settings.Mode == ReverseMode.ChooseFile
                ? "All required components are ready."
                : "Dynamic toolkit is ready; call OpenGhidraFile to choose the static target.";
            var startupMessage = $"Startup completed in {StartupElapsedMs.Value / 1000:F1}s.";
            UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Ready, $"{toolkitMessage} {startupMessage}");
            report(startupMessage);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            preparationCancellation.Cancel();
            if (sessionPreparation is not null && _ghidraSession is null)
            {
                try { _ghidraSession = await sessionPreparation.ConfigureAwait(false); }
                catch (Exception) { }
            }
            await StopCoreAsync(report).ConfigureAwait(false);
            report("Launch cancelled; all started components were stopped.");
            throw;
        }
        catch (Exception exception)
        {
            preparationCancellation.Cancel();
            if (sessionPreparation is not null && _ghidraSession is null)
            {
                try { _ghidraSession = await sessionPreparation.ConfigureAwait(false); }
                catch (Exception) { }
            }
            var failure = exception as ToolkitLaunchException ??
                new ToolkitLaunchException(activeComponent, activePhase, exception);
            UpdateStatus(activeComponent, ToolkitComponentState.Failed, ToolkitDiagnostics.Sanitize(failure.Message));
            UpdateStatus(ToolkitComponent.Toolkit, ToolkitComponentState.Failed, "Startup failed; see launcher diagnostics.");
            await StopCoreAsync(report).ConfigureAwait(false);
            report($"Launch failed: {ToolkitDiagnostics.Sanitize(failure.Message)}");
            throw failure;
        }
    }

    public async Task StopAsync(Action<string>? report = null)
    {
        if (Volatile.Read(ref _disposed) != 0)
            return;

        await _lifecycleLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed) != 0)
                return;
            await StopCoreAsync(report).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private async Task StopCoreAsync(Action<string>? report)
    {
        var hadToolkit = IsRunning || _job is not null || _ghidraSession is not null || _ghidraControl is not null || _metricsClient is not null;
        var control = Interlocked.Exchange(ref _ghidraControl, null);
        if (control is not null)
        {
            try
            {
                await control.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                ReportSafely(
                    report,
                    $"Could not stop Ghidra control pipe: {ToolkitDiagnostics.Sanitize(exception.Message)}");
            }
        }
        _ghidraControlToken = null;

        // The control pipe cancellation stops any in-flight parallel open. Wait
        // for that operation before draining the session registry so it cannot
        // register a runtime after cleanup has already enumerated the sessions.
        await _ghidraOpenLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await CloseGracefullyAsync(_ghidra, "Ghidra", report, force: true);
            _ghidra = null;

            await CloseGracefullyAsync(_server, "DBGLink MCP server", report, force: true);
            _server = null;
            while (_serverDiagnostics.TryDequeue(out _)) { }

            // x64dbg owns the native plugin's helper server. Give it a short
            // graceful-close window, then kill the complete process tree so a
            // plugin child cannot survive the launcher.
            await CloseGracefullyAsync(_debugger, "debugger", report, force: true);
            _debugger = null;

            foreach (var pair in _analysisSessions.ToArray())
            {
                if (!_analysisSessions.TryRemove(pair.Key, out var session))
                    continue;
                await CloseGracefullyAsync(session.Ghidra, $"Ghidra analysis {session.AnalysisId}", report, force: true);
                await CloseGracefullyAsync(session.Debugger, $"debugger analysis {session.AnalysisId}", report, force: true);
                await session.GhidraSession.DisposeAsync().ConfigureAwait(false);
            }

            _job?.Dispose();
            _job = null;

            var ghidraSession = Interlocked.Exchange(ref _ghidraSession, null);
            if (ghidraSession is not null)
            {
                await ghidraSession.DisposeAsync().ConfigureAwait(false);
                GhidraCleanupSucceeded = ghidraSession.CleanupSucceeded;
                if (!ghidraSession.CleanupSucceeded)
                    ReportSafely(report, "Ghidra isolated-session cleanup did not complete.");
            }

            // The run root owns every per-run session directory. Sessions
            // delete their own leaves above; this sweep is the backstop that
            // leaves nothing behind on success and failure paths alike.
            var runRoot = _sessionRunRoot;
            _sessionRunRoot = null;
            if (runRoot is not null &&
                !await LauncherTempRoot.TryDeleteTreeAsync(runRoot).ConfigureAwait(false))
            {
                TempRootCleanupSucceeded = false;
                ReportSafely(report, "Launcher temporary session root cleanup did not complete.");
            }

            _metricsClient?.Dispose();
            _metricsClient = null;
            GhidraStatus = null;
            _defaultEndpoint = null;

            if (hadToolkit)
            {
                foreach (var component in Components)
                {
                    ToolkitComponentState currentState;
                    lock (_statusLock)
                        currentState = _statuses[component].State;
                    if (currentState != ToolkitComponentState.Failed)
                        UpdateStatus(component, ToolkitComponentState.Stopped, "Stopped.");
                }
            }
        }
        finally
        {
            _ghidraOpenLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        await _lifecycleLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopCoreAsync(null).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
            // Do not dispose these semaphores here. A caller that entered
            // WaitAsync before disposal may still be queued and must be able
            // to acquire and release the gate after the disposed flag is seen.
            // SemaphoreSlim is fully managed and will be reclaimed with the
            // coordinator once those callers have completed.
        }
        GC.SuppressFinalize(this);
    }

}
