using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

public sealed partial class ToolkitCoordinator
{
    private DebuggerArchitecture _defaultArchitecture;
    private NativeEndpoint? _defaultEndpoint;
    private string? _defaultTarget;

    internal async Task<JsonObject> ControlSessionAsync(LauncherPlan plan, string method,
        JsonElement request, CancellationToken cancellationToken)
    {
        // Reopen drives a full Ghidra import via OpenGhidraFileAsync, which owns
        // the (non-reentrant) import lock below, so it runs outside this method's
        // lock instead of nesting it.
        if (method == "ReopenAnalysisSession")
            return await ReopenAnalysisSessionAsync(plan, request, cancellationToken).ConfigureAwait(false);
        await _ghidraOpenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (method == "ListAnalysisSessions")
            {
                // Diet listing: live sessions only by default; pass
                // includeClosed:true to also see dead runtime sessions and
                // manifest-restored entries (still reopenable by id). The
                // persisted manifest is never pruned here, only filtered at
                // render time.
                var includeClosed = request.ValueKind == JsonValueKind.Object &&
                    request.TryGetProperty("includeClosed", out var closedValue) &&
                    closedValue.ValueKind == JsonValueKind.True;
                // Materialize manifest entries first: live sessions hash their
                // target once here, then every later listing reuses the cached
                // hash below instead of hashing on the hot path.
                EnsureManifestEntries();
                var manifest = AnalysisSessionManifest.Load().Take(AnalysisSessionManifest.MaxEntries).ToList();
                var shaByAnalysisId = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var entry in manifest)
                {
                    if (shaByAnalysisId.ContainsKey(entry.AnalysisId))
                        continue;
                    if (AnalysisSessionManifest.NormalizeSha256(entry.Sha256) is string sha)
                        shaByAnalysisId[entry.AnalysisId] = sha;
                }
                var items = new JsonArray();
                // The ambient default slot is listed when live, or in closed
                // mode so the rest of the table is complete.
                if (IsAlive(_debugger) || IsAlive(_ghidra) || includeClosed)
                {
                    shaByAnalysisId.TryGetValue("default", out var defaultSha);
                    items.Add(SessionSummary("default", _debugger, _ghidra,
                        _defaultArchitecture, _defaultTarget, defaultSha));
                }
                foreach (var session in _analysisSessions.Values.OrderBy(s => s.AnalysisId))
                {
                    if (!IsAlive(session.Debugger) && !IsAlive(session.Ghidra) && !includeClosed)
                        continue;
                    // Cached manifest hash only: sessions without an entry (or
                    // with an unhashed one) omit sha256 instead of hashing now.
                    shaByAnalysisId.TryGetValue(session.AnalysisId, out var sha256);
                    items.Add(SessionSummary(session.AnalysisId, session.Debugger, session.Ghidra,
                        session.Architecture, session.TargetPath, sha256));
                }
                if (includeClosed)
                    foreach (var restored in manifest)
                    {
                        if (restored.AnalysisId == "default" || _analysisSessions.ContainsKey(restored.AnalysisId))
                            continue;
                        items.Add(RestoredSessionSummary(restored));
                    }
                return SessionSuccess(new JsonObject { ["sessions"] = items, ["maxAnalysisSessions"] = MaxAnalysisSessions });
            }

            if (!request.TryGetProperty("analysisId", out var idValue) || idValue.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(idValue.GetString()))
                return SessionError("invalid_request", "An explicit analysisId is required.");
            var id = idValue.GetString()!;
            var isDefault = id == "default";
            _analysisSessions.TryGetValue(id, out var runtime);
            if (!isDefault && runtime is null)
            {
                // A dead/restored id is not live, but CloseAnalysisSession must
                // still retire its manifest entry: the reopen failure texts
                // tell the caller to "drop the entry with CloseAnalysisSession",
                // and that advice must actually work (and stay idempotent).
                if (method == "CloseAnalysisSession")
                {
                    AnalysisSessionManifest.Remove(id);
                    return SessionSuccess(new JsonObject { ["analysisId"] = id, ["closed"] = true, ["alreadyClosed"] = true });
                }
                return SessionError("analysis_session_not_found", "The analysis session was not found. Use ListAnalysisSessions.");
            }

            var debugger = isDefault ? _debugger : runtime!.Debugger;
            var ghidra = isDefault ? _ghidra : runtime!.Ghidra;
            if (method == "CloseAnalysisSession")
            {
                // Once shutdown starts, finish it even if the caller disconnects. A retry is idempotent.
                await StopOwnedProcessAsync(ghidra).ConfigureAwait(false);
                await StopOwnedProcessAsync(debugger).ConfigureAwait(false);
                var session = isDefault ? _ghidraSession : runtime!.GhidraSession;
                if (session is not null)
                    await session.DisposeAsync().ConfigureAwait(false);
                if (isDefault)
                {
                    _ghidra = null;
                    _debugger = null;
                    _ghidraSession = null;
                    _defaultTarget = null;
                    _defaultEndpoint = null;
                    GhidraStatus = null;
                }
                else
                    _analysisSessions.TryRemove(id, out _);
                AnalysisSessionManifest.Remove(id);
                ghidra?.Dispose();
                debugger?.Dispose();
                return SessionSuccess(new JsonObject
                {
                    ["analysisId"] = id, ["closed"] = true,
                    ["cleanupSucceeded"] = session?.CleanupSucceeded ?? true,
                    ["mcpAvailable"] = true
                });
            }
            if (method != "SwitchDebugger")
                return SessionError("invalid_request", "Unsupported session operation.");

            var selection = SelectDebuggerArchitecture(request);
            if (selection.Error is not null)
                return SessionError("debugger_architecture_invalid", selection.Error);
            var architecture = selection.Architecture;
            var current = isDefault ? _defaultArchitecture : runtime!.Architecture;
            var changed = current != architecture || !IsAlive(debugger);
            NativeEndpoint? freshEndpoint = null;
            if (changed)
            {
                Process? replacement = null;
                NativeEndpoint switchEndpoint;
                try
                {
                    if (SwitchLaunchOverride is not null)
                    {
                        var switched = await SwitchLaunchOverride(
                            plan, architecture, debugger, cancellationToken).ConfigureAwait(false);
                        replacement = switched.Replacement;
                        switchEndpoint = switched.Endpoint;
                    }
                    else
                    {
                        replacement = Start(LauncherPlanner.CreateDebuggerSpec(plan, architecture, null));
                        (_job ?? throw new InvalidOperationException("The launcher process job is unavailable.")).Assign(replacement);
                        var (endpoint, _) = await WaitForNativeBridgeAsync(
                            replacement,
                            report: null,
                            cancellationToken).ConfigureAwait(false);
                        switchEndpoint = endpoint;
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    await StopOwnedProcessAsync(debugger).ConfigureAwait(false);
                    debugger?.Dispose();
                    debugger = replacement;
                    freshEndpoint = switchEndpoint;
                    if (isDefault)
                    {
                        _debugger = replacement;
                        _defaultArchitecture = architecture;
                        _defaultEndpoint = switchEndpoint;
                    }
                    else
                        _analysisSessions[id] = runtime! with
                        {
                            Debugger = replacement,
                            Architecture = architecture,
                            NativePipeName = switchEndpoint.BarePipeName,
                            NativePipeToken = switchEndpoint.Token
                        };
                    replacement = null;
                }
                finally
                {
                    if (replacement is not null)
                    {
                        await StopOwnedProcessAsync(replacement).ConfigureAwait(false);
                        replacement.Dispose();
                    }
                }
            }
            return SessionSuccess(new JsonObject
            {
                ["analysisId"] = id, ["architecture"] = architecture == DebuggerArchitecture.X86 ? "x86" : "x64",
                ["debuggerPid"] = debugger!.Id,
                ["nativePipeName"] = isDefault
                    ? _defaultEndpoint?.BarePipeName ?? plan.PipeNameFor(debugger.Id)
                    : freshEndpoint?.BarePipeName ?? runtime!.NativePipeName,
                ["nativePipeToken"] = isDefault
                    ? _defaultEndpoint?.Token ?? string.Empty
                    : freshEndpoint?.Token ?? runtime!.NativePipeToken,
                ["changed"] = changed, ["debugSessionReset"] = changed,
                ["ghidraPreserved"] = true
            });
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or
            System.ComponentModel.Win32Exception or TimeoutException)
        {
            return SessionError("session_control_failed", ToolkitDiagnostics.Sanitize(exception.Message));
        }
        finally { _ghidraOpenLock.Release(); }
    }

    internal static (DebuggerArchitecture Architecture, string? Error) SelectDebuggerArchitecture(JsonElement request)
    {
        var name = request.TryGetProperty("architecture", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : "auto";
        var requested = name switch
        {
            "x86" => DebuggerArchitecture.X86, "x64" => DebuggerArchitecture.X64,
            _ => DebuggerArchitecture.Auto
        };
        if (name is not ("auto" or "x86" or "x64"))
            return (requested, "architecture must be auto, x86 or x64.");
        if (request.TryGetProperty("path", out var path))
        {
            if (path.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(path.GetString()) ||
                !Path.IsPathFullyQualified(path.GetString()!) || !DbgLinkConfigPath.IsSafePath(path.GetString()!) ||
                !File.Exists(path.GetString()))
                return (requested, "path must be an existing safe absolute local PE file path.");
            var detected = DebuggerArchitectureDetector.Detect(path.GetString()!, DebuggerArchitecture.Auto);
            if (detected == DebuggerArchitecture.Auto)
                return (detected, "The file is not a supported x86/x64 PE image.");
            if (requested != DebuggerArchitecture.Auto && requested != detected)
                return (requested, "The requested architecture does not match the target PE image.");
            return (detected, null);
        }
        return requested == DebuggerArchitecture.Auto
            ? (requested, "auto requires a target path; otherwise specify x86 or x64.")
            : (requested, null);
    }

    /// <summary>
    /// Diet session row: identity, file name (never the absolute path),
    /// architecture, liveness flags, and a short "sha256:"-prefixed hash.
    /// Pids are dropped entirely: the caller cannot act on them.
    /// </summary>
    internal static JsonObject SessionSummary(string id, Process? debugger, Process? ghidra,
        DebuggerArchitecture architecture, string? target, string? sha256 = null)
    {
        var summary = new JsonObject
        {
            ["analysisId"] = id,
        };
        // The ambient default slot may have no target yet; omit the name
        // instead of advertising a placeholder.
        if (!string.IsNullOrWhiteSpace(target))
            summary["fileName"] = AnalysisSessionManifest.FileNameFor(target);
        summary["architecture"] = architecture == DebuggerArchitecture.X86 ? "x86" : "x64";
        summary["debuggerRunning"] = IsAlive(debugger);
        summary["ghidraRunning"] = IsAlive(ghidra);
        // Cached manifest hash only: callers pass the already-computed value
        // (or null); this method never hashes the target itself. Short
        // "sha256:"-prefixed form; omitted when unknown.
        if (ShortSha256(sha256) is string shortSha)
            summary["sha256"] = shortSha;
        return summary;
    }

    /// <summary>
    /// Short session hash for listings: first 12 hex chars with a "sha256:"
    /// prefix, or null when the full hash is unknown. The prefix keeps the
    /// row self-describing next to addresses and rvas.
    /// </summary>
    internal static string? ShortSha256(string? sha256)
    {
        var normalized = AnalysisSessionManifest.NormalizeSha256(sha256);
        return normalized is null ? null : "sha256:" + normalized[..12];
    }

    /// <summary>
    /// A manifest entry for a session that died with the previous launcher run.
    /// Nothing is live: both processes are gone with the old temp endpoint, so the
    /// entry only carries enough to reopen the same target (file name, sha256,
    /// arch). Shown only with includeClosed:true; still resolvable by id for
    /// ReopenAnalysisSession.
    /// </summary>
    private static JsonObject RestoredSessionSummary(AnalysisSessionManifest.Entry restored)
    {
        var summary = new JsonObject
        {
            ["analysisId"] = restored.AnalysisId,
        };
        if (!string.IsNullOrWhiteSpace(restored.FileName))
            summary["fileName"] = restored.FileName;
        summary["architecture"] = restored.Architecture;
        summary["debuggerRunning"] = false;
        summary["ghidraRunning"] = false;
        if (ShortSha256(restored.Sha256) is string shortSha)
            summary["sha256"] = shortSha;
        summary["restored"] = true;
        summary["needsReopen"] = true;
        return summary;
    }

    private static bool TargetExists(string path)
    {
        try { return File.Exists(path); }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    /// <summary>
    /// The session-open path (<c>OpenGhidraFileAsync</c>) lives outside the
    /// editable session surface, so the manifest materializes here instead:
    /// every listing records live sessions that have no entry yet (hashing the
    /// target once, then reusing the file), keeping the manifest warm for the
    /// next launcher run. Best-effort: hashing or IO failures only skip the
    /// entry, never the listing.
    /// </summary>
    private void EnsureManifestEntries()
    {
        try
        {
            var known = new HashSet<string>(
                AnalysisSessionManifest.Load().Select(entry => entry.AnalysisId),
                StringComparer.Ordinal);
            foreach (var session in _analysisSessions.Values.OrderBy(s => s.AnalysisId))
            {
                if (known.Contains(session.AnalysisId))
                    continue;
                var sha256 = ComputeTargetSha256(session.TargetPath);
                AnalysisSessionManifest.Save(new AnalysisSessionManifest.Entry(
                    session.AnalysisId,
                    session.TargetPath,
                    sha256 ?? string.Empty,
                    AnalysisSessionManifest.ArchitectureName(session.Architecture),
                    AnalysisSessionManifest.FileNameFor(session.TargetPath),
                    AnalysisSessionManifest.CountJournalEntries(sha256),
                    DateTimeOffset.UtcNow));
                known.Add(session.AnalysisId);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or JsonException or InvalidDataException or
            InvalidOperationException)
        {
        }
    }

    internal static string? ComputeTargetSha256(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            var info = new FileInfo(path);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory) ||
                info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return null;
            if (info.Length <= 0 || info.Length > 512L * 1024 * 1024)
                return null;
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.SequentialScan);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static JsonObject SessionSuccess(JsonObject result) => new() { ["ok"] = true, ["result"] = result };
    private static JsonObject SessionError(string code, string message) => new()
    {
        ["ok"] = false, ["error"] = new JsonObject { ["code"] = code, ["message"] = message }
    };

    /// <summary>Test seam: replaces the real Ghidra import for reopen tests. Null in production.</summary>
    internal Func<LauncherPlan, string, CancellationToken, Task<GhidraOpenResult>>? ReopenOpenOverride;

    /// <summary>Test seam: fakes the debugger relaunch for SwitchDebugger tests. Null in production.</summary>
    internal Func<LauncherPlan, DebuggerArchitecture, Process?, CancellationToken,
        Task<(Process Replacement, NativeEndpoint Endpoint)>>? SwitchLaunchOverride;

    /// <summary>Test seam: registers a non-default session without a Ghidra import.</summary>
    internal void RegisterSwitchTestSession(string analysisId, Process debugger, Process ghidra,
        string pipeName, string pipeToken, DebuggerArchitecture architecture, string targetPath)
        => _analysisSessions[analysisId] = new AnalysisRuntime(
            analysisId, debugger, ghidra, null!, pipeName, pipeToken, 0, architecture, targetPath);

    /// <summary>Test seam: reads the stored pipe credentials for a test session.</summary>
    internal bool TryReadSwitchTestSession(string analysisId, out string pipeName, out string pipeToken)
    {
        pipeName = string.Empty;
        pipeToken = string.Empty;
        if (!_analysisSessions.TryGetValue(analysisId, out var runtime))
            return false;
        pipeName = runtime.NativePipeName;
        pipeToken = runtime.NativePipeToken;
        return true;
    }

    /// <summary>Test seam: drops a test session without touching its (dummy) processes.</summary>
    internal void RemoveSwitchTestSession(string analysisId) => _analysisSessions.TryRemove(analysisId, out _);

    /// <summary>
    /// One-step reopen of a manifest-restored session: re-imports the recorded
    /// target through the standard open machinery and retires the dead
    /// analysisId. Read-only until the import starts: unknown/live ids,
    /// missing targets and a full session table all return before any process
    /// is launched, so the manifest entry survives for a later retry. On
    /// success the dead entry is removed; the next listing re-saves the new
    /// live session with a fresh journal cursor via <c>EnsureManifestEntries</c>.
    /// </summary>
    private async Task<JsonObject> ReopenAnalysisSessionAsync(LauncherPlan plan, JsonElement request,
        CancellationToken cancellationToken)
    {
        if (!request.TryGetProperty("analysisId", out var idValue) || idValue.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(idValue.GetString()))
            return SessionError("invalid_request", "An explicit analysisId is required.");
        var id = idValue.GetString()!;
        if (id == "default" || _analysisSessions.ContainsKey(id))
            return SessionSuccess(new JsonObject
            {
                ["analysisId"] = id, ["reopened"] = false, ["alreadyLive"] = true,
                ["sessionNote"] = $"Session '{id}' is still live; continue with analysisId '{id}'. No reopen was needed."
            });
        var restored = AnalysisSessionManifest.Load().Take(AnalysisSessionManifest.MaxEntries)
            .FirstOrDefault(e => string.Equals(e.AnalysisId, id, StringComparison.Ordinal));
        if (restored is null)
            return SessionError("analysis_session_not_found", "The analysis session was not found. Use ListAnalysisSessions.");
        if (!TargetExists(restored.TargetPath))
            return SessionError("target_missing",
                $"The reopen target for session '{id}' no longer exists; the restored entry was kept. " +
                "Restore the file and retry, or drop the entry with CloseAnalysisSession.");
        if (_analysisSessions.Count >= MaxAnalysisSessions)
            return SessionError("session_capacity_reached",
                "The maximum number of parallel analysis sessions has been reached. " +
                "Close an unused session with CloseAnalysisSession, then retry.");
        GhidraOpenResult opened;
        try
        {
            opened = ReopenOpenOverride is not null
                ? await ReopenOpenOverride(plan, restored.TargetPath, cancellationToken).ConfigureAwait(false)
                : await OpenGhidraFileAsync(plan, _ => { }, restored.TargetPath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (FileNotFoundException)
        {
            return SessionError("target_missing",
                $"The reopen target for session '{id}' no longer exists; the restored entry was kept. " +
                "Restore the file and retry, or drop the entry with CloseAnalysisSession.");
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or
            System.ComponentModel.Win32Exception or TimeoutException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException)
        {
            // A capacity race between the pre-check above and the import must
            // keep the specific code, not collapse to session_control_failed.
            if (exception is InvalidOperationException &&
                exception.Message.Contains("maximum number of parallel analysis sessions", StringComparison.OrdinalIgnoreCase))
                return SessionError("session_capacity_reached",
                    "The maximum number of parallel analysis sessions has been reached. " +
                    "Close an unused session with CloseAnalysisSession, then retry.");
            return SessionError("session_control_failed", ToolkitDiagnostics.Sanitize(exception.Message));
        }
        if (string.IsNullOrWhiteSpace(opened.AnalysisId))
            return SessionError("session_control_failed", "The launcher did not return the reopened analysis session.");
        AnalysisSessionManifest.Remove(id);
        var journalEntries = AnalysisSessionManifest.CountJournalEntries(restored.Sha256);
        // analysisId/nativePipeName/ghidraEndpointDirectory mirror the
        // OpenGhidraFile result shape so the MCP dispatcher auto-registers the
        // new session from this response.
        return SessionSuccess(new JsonObject
        {
            ["reopened"] = true,
            ["analysisId"] = opened.AnalysisId,
            ["previousAnalysisId"] = id,
            ["nativePipeName"] = opened.NativePipeName,
            ["nativePipeToken"] = opened.NativePipeToken,
            ["ghidraEndpointDirectory"] = opened.GhidraEndpointDirectory,
            ["fileName"] = opened.FileName,
            // The restored manifest entry already knows the binary hash: pass
            // it along so the MCP server can embed the checkpoint summary in
            // the reopen reply without another lookup. Empty when unhashed.
            ["sha256"] = restored.Sha256,
            ["sessionNote"] = $"Session '{id}' was reopened as '{opened.AnalysisId}'; '{id}' is invalid. " +
                $"{journalEntries} journaled rename(s) replay automatically on reimport; " +
                "restore context with CreateCheckpoint/GetLastCheckpoint."
        });
    }

    // Keep the process handle on failure so callers can retry cleanup. Never kill by process name or a stale PID.
    private static async Task StopOwnedProcessAsync(Process? process)
    {
        if (process is null || process.HasExited) return;
        if (process.MainWindowHandle != IntPtr.Zero) process.CloseMainWindow();
        using (var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
        {
            try { await process.WaitForExitAsync(grace.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        if (!process.HasExited) process.Kill(entireProcessTree: true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw new TimeoutException("An owned process did not stop; retry CloseAnalysisSession."); }
    }
}

/// <summary>
/// Durable manifest of launcher-owned analysis sessions at
/// <c>%LOCALAPPDATA%\DBGLink\sessions.json</c>.
///
/// Analysis sessions do not survive a launcher restart (both child processes
/// die with the old temp endpoint), so without this file the previous ids
/// vanish silently. Each <c>ListAnalysisSessions</c> records live sessions
/// that have no entry yet (target path, sha256, architecture, journal cursor);
/// each explicit close removes its entry. After a restart the leftovers are
/// re-advertised as <c>restored/needsReopen</c> instead of being lost.
/// Best-effort throughout: any IO or parse failure degrades to
/// "no restored sessions", never to a failed open/list/close.
/// </summary>
internal static class AnalysisSessionManifest
{
    internal const int MaxEntries = 8;
    private const int MaxFileBytes = 64 * 1024;
    private const long MaxJournalBytes = 8L * 1024 * 1024;
    private const int MaxJournalLines = 20_000;
    private const int MaxPathChars = 32_760;
    private const int MaxIdChars = 128;
    private const int MaxFileNameChars = 260;

    /// <summary>Test seam: fake %LOCALAPPDATA% root. Null in production.</summary>
    internal static string? LocalAppDataOverride;

    internal sealed record Entry(
        string AnalysisId,
        string TargetPath,
        string Sha256,
        string Architecture,
        string FileName,
        int JournalEntries,
        DateTimeOffset SavedAtUtc);

    internal static string ArchitectureName(DebuggerArchitecture architecture)
        => architecture == DebuggerArchitecture.X86 ? "x86" : "x64";

    internal static string? NormalizeSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var clean = value.Trim().ToLowerInvariant();
        if (clean.Length != 64 || clean.Any(c => !char.IsAsciiHexDigit(c)))
            return null;
        return clean;
    }

    internal static string FileNameFor(string targetPath)
    {
        try
        {
            var name = Path.GetFileName(targetPath);
            if (!string.IsNullOrWhiteSpace(name))
            {
                var clean = new string(name.Where(c => !char.IsControl(c)).ToArray());
                if (!string.IsNullOrWhiteSpace(clean))
                    return clean.Length > MaxFileNameChars ? clean[..MaxFileNameChars] : clean;
            }
        }
        catch (ArgumentException) { }
        return "target";
    }

    internal static void Save(Entry entry)
    {
        try
        {
            var path = ManifestPath();
            if (path is null || !IsValidEntry(entry))
                return;
            var entries = ReadEntries(path);
            entries.RemoveAll(e => string.Equals(e.AnalysisId, entry.AnalysisId, StringComparison.Ordinal));
            entries.Insert(0, entry);
            while (entries.Count > MaxEntries)
                entries.RemoveAt(entries.Count - 1);
            WriteEntries(path, entries);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or JsonException or InvalidDataException or
            InvalidOperationException)
        {
        }
    }

    internal static void Remove(string analysisId)
    {
        try
        {
            var path = ManifestPath();
            if (path is null || !IsValidAnalysisId(analysisId) || !File.Exists(path))
                return;
            var entries = ReadEntries(path);
            if (entries.RemoveAll(e => string.Equals(e.AnalysisId, analysisId, StringComparison.Ordinal)) > 0)
                WriteEntries(path, entries);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or JsonException or InvalidDataException or
            InvalidOperationException)
        {
        }
    }

    internal static IReadOnlyList<Entry> Load()
    {
        try
        {
            var path = ManifestPath();
            return path is null ? Array.Empty<Entry>() : ReadEntries(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or JsonException or InvalidDataException or
            InvalidOperationException)
        {
            return Array.Empty<Entry>();
        }
    }

    /// <summary>
    /// Annotation-journal cursor for a program sha256: the number of
    /// <c>&lt;sha256&gt;.jsonl</c> lines that will replay on reimport.
    /// Bounded (byte + line caps); unreadable journals read as zero.
    /// </summary>
    internal static int CountJournalEntries(string? sha256)
    {
        try
        {
            var normalized = NormalizeSha256(sha256);
            if (normalized is null)
                return 0;
            var directory = AnnotationsDirectory();
            if (directory is null)
                return 0;
            var file = Path.Combine(directory, normalized + ".jsonl");
            var info = new FileInfo(file);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory) ||
                info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return 0;
            if (info.Length <= 0 || info.Length > MaxJournalBytes)
                return info.Length <= 0 ? 0 : MaxJournalLines;
            var count = 0;
            foreach (var _ in File.ReadLines(file))
            {
                if (++count >= MaxJournalLines)
                    break;
            }
            return count;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException)
        {
            return 0;
        }
    }

    internal static string? ManifestPath()
    {
        try
        {
            var root = LocalAppDataOverride ??
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(root))
                return null;
            var path = Path.Combine(root, "DBGLink", "sessions.json");
            return path.Length > MaxPathChars || path.Any(char.IsControl) ? null : path;
        }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    private static string? AnnotationsDirectory()
    {
        try
        {
            var root = LocalAppDataOverride ??
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(root))
                return null;
            var directory = Path.Combine(root, "DBGLink", "annotations");
            return directory.Length > MaxPathChars || directory.Any(char.IsControl) ? null : directory;
        }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    private static List<Entry> ReadEntries(string path)
    {
        var entries = new List<Entry>();
        if (!File.Exists(path))
            return entries;
        if (new FileInfo(path).Length > MaxFileBytes)
            return entries;
        var json = File.ReadAllText(path);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("sessions", out var sessions) ||
            sessions.ValueKind != JsonValueKind.Array)
            return entries;
        foreach (var item in sessions.EnumerateArray())
        {
            if (entries.Count >= MaxEntries)
                break;
            if (item.ValueKind != JsonValueKind.Object ||
                !TryReadString(item, "analysisId", out var analysisId) ||
                !TryReadString(item, "targetPath", out var targetPath))
                continue;
            TryReadString(item, "sha256", out var sha256);
            TryReadString(item, "architecture", out var architecture);
            TryReadString(item, "fileName", out var fileName);
            var journalEntries = item.TryGetProperty("journalEntries", out var journal) &&
                journal.ValueKind == JsonValueKind.Number && journal.TryGetInt32(out var count)
                ? Math.Clamp(count, 0, MaxJournalLines)
                : 0;
            var savedAt = item.TryGetProperty("savedAtUtc", out var saved) &&
                saved.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(saved.GetString(), out var parsed)
                ? parsed
                : DateTimeOffset.MinValue;
            // Coerce a missing/unknown architecture to the host default (x64)
            // and validate the COERCED value. The previous code coerced into the
            // Entry but then re-checked the raw string, so every repaired entry
            // was dropped and the repair could never take effect.
            var safeArchitecture = architecture is "x86" or "x64" ? architecture : "x64";
            var entry = new Entry(
                analysisId!,
                targetPath!,
                NormalizeSha256(sha256) ?? string.Empty,
                safeArchitecture,
                string.IsNullOrWhiteSpace(fileName) ? FileNameFor(targetPath!) : fileName!,
                journalEntries,
                savedAt);
            // Entries with a bad id or path are dropped, never advertised.
            if (IsValidEntry(entry))
                entries.Add(entry);
        }
        return entries;
    }

    private static void WriteEntries(string path, List<Entry> entries)
    {
        var trimmed = entries.Take(MaxEntries).ToList();
        while (true)
        {
            var sessions = new JsonArray(trimmed.Select(e => (JsonNode)new JsonObject
            {
                ["analysisId"] = e.AnalysisId,
                ["targetPath"] = e.TargetPath,
                ["sha256"] = e.Sha256,
                ["architecture"] = e.Architecture,
                ["fileName"] = e.FileName,
                ["journalEntries"] = e.JournalEntries,
                ["savedAtUtc"] = e.SavedAtUtc.ToString("O")
            }).ToArray());
            var json = new JsonObject { ["version"] = 1, ["sessions"] = sessions }.ToJsonString();
            if (System.Text.Encoding.UTF8.GetByteCount(json) <= MaxFileBytes || trimmed.Count == 0)
            {
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(directory))
                    Directory.CreateDirectory(directory);
                var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    File.WriteAllText(tempPath, json);
                    File.Move(tempPath, path, overwrite: true);
                }
                finally
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
                return;
            }
            trimmed.RemoveAt(trimmed.Count - 1);
        }
    }

    private static bool TryReadString(JsonElement element, string name, out string? value)
    {
        value = null;
        if (!element.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String)
            return false;
        value = property.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool IsValidEntry(Entry entry)
        => IsValidAnalysisId(entry.AnalysisId) &&
            !string.IsNullOrWhiteSpace(entry.TargetPath) &&
            entry.TargetPath.Length <= MaxPathChars &&
            !entry.TargetPath.Any(char.IsControl) &&
            IsFullyQualified(entry.TargetPath) &&
            entry.Architecture is ("x86" or "x64");

    private static bool IsValidAnalysisId(string value)
        => !string.IsNullOrWhiteSpace(value) &&
            value.Length <= MaxIdChars &&
            value.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');

    private static bool IsFullyQualified(string path)
    {
        try { return Path.IsPathFullyQualified(path); }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }
}
