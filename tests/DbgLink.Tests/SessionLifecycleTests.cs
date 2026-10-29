using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Launcher.Core;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace DbgLink.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class SessionLifecycleTests
{
    private readonly ITestOutputHelper _output;

    public SessionLifecycleTests(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData(0x014c, DebuggerArchitecture.X86)]
    [InlineData(0x8664, DebuggerArchitecture.X64)]
    public void Auto_selects_PE_architecture_and_rejects_explicit_mismatch(int machine, DebuggerArchitecture expected)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe");
        try
        {
            var bytes = new byte[128];
            BitConverter.GetBytes((ushort)0x5a4d).CopyTo(bytes, 0);
            BitConverter.GetBytes(64).CopyTo(bytes, 0x3c);
            BitConverter.GetBytes(0x4550).CopyTo(bytes, 64);
            BitConverter.GetBytes((ushort)machine).CopyTo(bytes, 68);
            File.WriteAllBytes(path, bytes);
            var result = ToolkitCoordinator.SelectDebuggerArchitecture(JsonSerializer.SerializeToElement(new { path, architecture = "auto" }));
            Assert.Null(result.Error);
            Assert.Equal(expected, result.Architecture);
            var wrong = expected == DebuggerArchitecture.X86 ? "x64" : "x86";
            Assert.Contains("does not match", ToolkitCoordinator.SelectDebuggerArchitecture(
                JsonSerializer.SerializeToElement(new { path, architecture = wrong })).Error);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("{\"architecture\":\"auto\"}")]
    [InlineData("{\"architecture\":\"arm64\"}")]
    [InlineData("{\"architecture\":\"auto\",\"path\":\"relative.exe\"}")]
    public void Invalid_selection_is_rejected_before_process_changes(string json)
        => Assert.NotNull(ToolkitCoordinator.SelectDebuggerArchitecture(JsonSerializer.Deserialize<JsonElement>(json)).Error);

    [Fact]
    public void Closing_latest_session_falls_back_to_default_and_old_import_cannot_resurrect_it()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var descriptor = new AnalysisSessionDescriptor("analysis-test", "DbgLink.Control.42", Path.GetTempPath());
        Assert.True(registry.TryRegister(descriptor));
        registry.Close("analysis-test");
        Assert.Equal("default", registry.Resolve(null).AnalysisId);
        Assert.Throws<AnalysisSessionNotFoundException>(() => registry.Resolve("analysis-test"));
        Assert.False(registry.TryRegister(descriptor));
        registry.Close("analysis-test");
    }

    [Fact]
    public void Switch_preserves_Ghidra_and_session_gate_and_default_can_restart_after_close()
    {
        var ghidra = new NullGhidra();
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), ghidra);
        var gate = registry.GetGate("default");
        registry.ReplaceBridge("default", "DbgLink.Control.42");
        Assert.Same(ghidra, registry.Resolve("default").Ghidra);
        Assert.Same(gate, registry.GetGate("default"));
        registry.Close("default");
        Assert.IsType<ClosedDebuggerClient>(registry.Resolve(null).Bridge);
        registry.ReplaceBridge("default", "DbgLink.Control.43");
        Assert.Equal("DbgLink.Control.43", registry.Resolve(null).NativePipeName);
        Assert.Same(gate, registry.GetGate("default"));
    }

    [Theory]
    [InlineData("ListAnalysisSessions")]
    [InlineData("SwitchDebugger")]
    [InlineData("CloseAnalysisSession")]
    [InlineData("ReopenAnalysisSession")]
    public async Task Lifecycle_pipe_requires_authentication(string method)
    {
        var calls = 0;
        await using var server = new GhidraControlPipeServer("DbgLink.GhidraControl.test", new string('a', 32),
            (_, _) => throw new InvalidOperationException())
        {
            SessionControl = (_, _, _) => { calls++; return Task.FromResult(new JsonObject { ["ok"] = true }); }
        };
        var invalid = await server.DispatchAsync(JsonSerializer.Serialize(new
            { id = 1, method, token = new string('b', 32), analysisId = "default" }), CancellationToken.None);
        Assert.Contains("invalid_request", invalid);
        Assert.Equal(0, calls);
        var valid = await server.DispatchAsync(JsonSerializer.Serialize(new
            { id = 1, method, token = new string('a', 32), analysisId = "default" }), CancellationToken.None);
        Assert.Contains("\"ok\":true", valid);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Close_is_explicit_and_mutation_gated()
    {
        var control = new SessionControlStub();
        using var readOnly = Server(control, false);
        Assert.DoesNotContain(readOnly.ListTools(), t => t!["name"]!.GetValue<string>() == "CloseAnalysisSession");
        Assert.Contains(readOnly.ListTools(), t => t!["name"]!.GetValue<string>() == "ListAnalysisSessions");
        using var server = Server(control);
        await Assert.ThrowsAnyAsync<Exception>(() => Call(server, "CloseAnalysisSession", new { }));
        Assert.Equal(0, control.Calls);
    }

    [Fact]
    public async Task Failed_close_keeps_session_and_successful_close_disables_old_bridge()
    {
        var control = new SessionControlStub { Fail = true };
        var bridge = new RecordingBridge();
        using var server = Server(control, bridge: bridge);
        Assert.True((await Call(server, "CloseAnalysisSession", new { analysisId = "default" })).IsError);
        await Call(server, "ReadMemAtAddress", new { address = "0x1000", byteCount = 1 });
        Assert.Equal(1, bridge.RequestCount);
        control.Fail = false;
        Assert.False((await Call(server, "CloseAnalysisSession", new { analysisId = "default" })).IsError);
        var after = await Call(server, "ReadMemAtAddress", new { address = "0x1000", byteCount = 1 });
        Assert.True(after.IsError);
        Assert.Contains("debugger_closed", ((TextContentBlock)after.Content[0]).Text);
        Assert.Equal(1, bridge.RequestCount);
        Assert.False((await Call(server, "ListAnalysisSessions", new { })).IsError);
    }

    [Fact]
    public async Task Close_waits_for_inflight_session_read()
    {
        var bridge = new WaitingBridge();
        var control = new SessionControlStub();
        using var server = Server(control, bridge: bridge);
        var read = Call(server, "ReadMemAtAddress", new { address = "0x1000", byteCount = 1 });
        await bridge.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var close = Call(server, "CloseAnalysisSession", new { analysisId = "default" });
        Assert.False(close.IsCompleted);
        Assert.Equal(0, control.Calls);
        bridge.Release.SetResult();
        await read;
        Assert.False((await close).IsError);
        Assert.Equal(1, control.Calls);
    }

    [Fact]
    public async Task OpenDebugTarget_requests_auto_selection_before_native_open_and_preserves_old_bridge_on_failure()
    {
        var control = new SessionControlStub { Fail = true };
        var bridge = new RecordingBridge();
        using var server = Server(control, bridge: bridge);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe");
        try
        {
            File.WriteAllBytes(path, [0x4d, 0x5a]);
            Assert.True((await Call(server, "OpenDebugTarget", new { path })).IsError);
            Assert.Equal("SwitchDebugger", control.LastMethod);
            Assert.Equal("auto", control.LastArguments.GetProperty("architecture").GetString());
            Assert.Equal(path, control.LastArguments.GetProperty("path").GetString());
            Assert.Equal(0, bridge.RequestCount);
            await Call(server, "ReadMemAtAddress", new { address = "0x1000", byteCount = 1 });
            Assert.Equal(1, bridge.RequestCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task SwitchDebugger_on_non_default_session_returns_fresh_pipe_and_token()
    {
        var analysisId = "analysis-switch" + Guid.NewGuid().ToString("N")[..8];
        var oldDebugger = StartExitedProcess();
        var oldGhidra = StartExitedProcess();
        var replacement = StartLiveProcess();
        var oldPipe = "DbgLink.Old.Pipe";
        var oldToken = new string('b', 64);
        var newBare = "DbgLink.Switch.New";
        var newToken = new string('a', 64);
        var newEndpoint = new NativeEndpoint(@"\\.\pipe\" + newBare, newToken);
        await using var coordinator = new ToolkitCoordinator();
        coordinator.RegisterSwitchTestSession(
            analysisId, oldDebugger, oldGhidra, oldPipe, oldToken,
            DebuggerArchitecture.X86, @"C:\fake\target.exe");
        coordinator.SwitchLaunchOverride = (_, architecture, _, _) =>
        {
            Assert.Equal(DebuggerArchitecture.X64, architecture);
            return Task.FromResult((replacement, newEndpoint));
        };
        try
        {
            var plan = new LauncherPlan(
                new LauncherSettings(string.Empty, string.Empty, string.Empty, ReverseMode.LetLlmChoose, null),
                new ToolkitPaths(string.Empty, string.Empty, string.Empty, string.Empty, string.Empty,
                    string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty));
            var response = await coordinator.ControlSessionAsync(
                plan,
                "SwitchDebugger",
                JsonSerializer.SerializeToElement(new { analysisId, architecture = "x64" }),
                CancellationToken.None);
            Assert.True(response["ok"]?.GetValue<bool>());
            var result = Assert.IsType<JsonObject>(response["result"]);
            Assert.Equal(newBare, result["nativePipeName"]?.GetValue<string>());
            Assert.Equal(newToken, result["nativePipeToken"]?.GetValue<string>());
            Assert.Equal(replacement.Id, result["debuggerPid"]?.GetValue<int>());
            Assert.True(result["changed"]?.GetValue<bool>());
            Assert.True(coordinator.TryReadSwitchTestSession(analysisId, out var storedPipe, out var storedToken));
            Assert.Equal(newBare, storedPipe);
            Assert.Equal(newToken, storedToken);
        }
        finally
        {
            coordinator.SwitchLaunchOverride = null;
            coordinator.RemoveSwitchTestSession(analysisId);
            try
            {
                if (!replacement.HasExited)
                    replacement.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or
                System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }
            replacement.Dispose();
            oldGhidra.Dispose();
            try { oldDebugger.Dispose(); } catch (InvalidOperationException) { }
        }
    }

    private static Process StartExitedProcess()
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c exit",
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        Assert.True(process.WaitForExit(5000));
        return process;
    }

    private static Process StartLiveProcess()
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "ping.exe",
            Arguments = "127.0.0.1 -n 60",
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        Assert.False(process.HasExited);
        return process;
    }

    [Fact]
    public void Manifest_Save_Load_round_trips_a_bounded_entry()
    {
        using var scope = ManifestScope(out _);
        var target = Path.Combine(Path.GetTempPath(), "dbglink-manifest-target-" + Guid.NewGuid().ToString("N") + ".exe");
        var sha = new string('a', 64);
        AnalysisSessionManifest.Save(new("analysis-deadbeef", target, sha, "x64", "target.exe", 3, DateTimeOffset.UtcNow));

        var loaded = AnalysisSessionManifest.Load();
        var entry = Assert.Single(loaded);
        Assert.Equal("analysis-deadbeef", entry.AnalysisId);
        Assert.Equal(target, entry.TargetPath);
        Assert.Equal(sha, entry.Sha256);
        Assert.Equal("x64", entry.Architecture);
        Assert.Equal("target.exe", entry.FileName);
        Assert.Equal(3, entry.JournalEntries);
    }

    [Fact]
    public void Manifest_Save_caps_entries_and_keeps_the_newest()
    {
        using var scope = ManifestScope(out _);
        for (var i = 0; i < AnalysisSessionManifest.MaxEntries + 2; i++)
            AnalysisSessionManifest.Save(new($"analysis-{i:00}",
                Path.Combine(Path.GetTempPath(), $"dbglink-manifest-cap-{i:00}.exe"),
                new string('b', 64), "x86", $"cap-{i:00}.exe", 0, DateTimeOffset.UtcNow));

        var loaded = AnalysisSessionManifest.Load();
        Assert.Equal(AnalysisSessionManifest.MaxEntries, loaded.Count);
        Assert.Equal("analysis-09", loaded[0].AnalysisId);
        Assert.DoesNotContain(loaded, e => e.AnalysisId == "analysis-00");
    }

    [Fact]
    public void Manifest_Remove_drops_only_the_named_entry()
    {
        using var scope = ManifestScope(out _);
        AnalysisSessionManifest.Save(new("analysis-keep",
            Path.Combine(Path.GetTempPath(), "dbglink-manifest-keep.exe"), new string('c', 64), "x64", "keep.exe", 0, DateTimeOffset.UtcNow));
        AnalysisSessionManifest.Save(new("analysis-drop",
            Path.Combine(Path.GetTempPath(), "dbglink-manifest-drop.exe"), new string('d', 64), "x64", "drop.exe", 0, DateTimeOffset.UtcNow));

        AnalysisSessionManifest.Remove("analysis-drop");
        Assert.Equal("analysis-keep", Assert.Single(AnalysisSessionManifest.Load()).AnalysisId);
        AnalysisSessionManifest.Remove("analysis-missing");
        Assert.Equal("analysis-keep", Assert.Single(AnalysisSessionManifest.Load()).AnalysisId);
    }

    [Theory]
    [InlineData("{\"version\":1}")]
    [InlineData("not json at all {{{")]
    [InlineData("{\"version\":1,\"sessions\":[{\"analysisId\":\"bad id!\",\"targetPath\":\"relative.exe\"}]}")]
    [InlineData("{\"version\":1,\"sessions\":[{\"analysisId\":\"analysis-ok\",\"targetPath\":\"relative.exe\"}]}")]
    public void Manifest_corrupt_or_invalid_content_loads_empty_without_throwing(string content)
    {
        using var scope = ManifestScope(out var root);
        Directory.CreateDirectory(Path.Combine(root, "DBGLink"));
        File.WriteAllText(Path.Combine(root, "DBGLink", "sessions.json"), content);

        Assert.Empty(AnalysisSessionManifest.Load());
    }

    [Fact]
    public void Manifest_CountJournalEntries_reads_the_sha256_journal_cursor()
    {
        using var scope = ManifestScope(out var root);
        var sha = new string('e', 64);
        Assert.Equal(0, AnalysisSessionManifest.CountJournalEntries(sha));
        Directory.CreateDirectory(Path.Combine(root, "DBGLink", "annotations"));
        File.WriteAllLines(Path.Combine(root, "DBGLink", "annotations", sha + ".jsonl"),
            ["{\"kind\":\"rename_function\"}", "{\"kind\":\"set_function_comment\"}", ""]);
        Assert.Equal(3, AnalysisSessionManifest.CountJournalEntries(sha));
        Assert.Equal(0, AnalysisSessionManifest.CountJournalEntries("not-a-sha"));
        Assert.Equal(0, AnalysisSessionManifest.CountJournalEntries(null));
    }

    [Fact]
    public async Task ListAnalysisSessions_hides_dead_sessions_by_default_and_shows_them_closed()
    {
        using var scope = ManifestScope(out var root);
        var sha = new string('f', 64);
        var target = Path.Combine(root, "dbglink-restored-target.exe");
        File.WriteAllBytes(target, [0x4d, 0x5a]);
        Directory.CreateDirectory(Path.Combine(root, "DBGLink", "annotations"));
        File.WriteAllLines(Path.Combine(root, "DBGLink", "annotations", sha + ".jsonl"),
            ["{\"kind\":\"rename_function\"}"]);
        AnalysisSessionManifest.Save(new("analysis-restored", target, sha, "x64", "dbglink-restored-target.exe", 0, DateTimeOffset.UtcNow));

        await using var coordinator = new ToolkitCoordinator();
        // Dead sessions are hidden by default: nothing live, so the table is empty.
        var hidden = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions", default, CancellationToken.None);
        Assert.True(hidden["ok"]?.GetValue<bool>());
        Assert.Empty(Assert.IsType<JsonArray>(hidden["result"]?["sessions"]));

        // includeClosed:true shows the ambient slot plus the restored entry in diet shape.
        var shown = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions",
            JsonSerializer.SerializeToElement(new { includeClosed = true }), CancellationToken.None);
        Assert.True(shown["ok"]?.GetValue<bool>());
        var sessions = Assert.IsType<JsonArray>(shown["result"]?["sessions"]);
        Assert.Equal(2, sessions.Count);
        var restored = Assert.IsType<JsonObject>(sessions[1]);
        Assert.Equal("analysis-restored", restored["analysisId"]?.GetValue<string>());
        Assert.Equal("dbglink-restored-target.exe", restored["fileName"]?.GetValue<string>());
        Assert.Null(restored["analysisTargetPath"]);
        Assert.Null(restored["debuggerPid"]);
        Assert.Null(restored["ghidraPid"]);
        Assert.Null(restored["ghidraLauncherPid"]);
        Assert.Equal("x64", restored["architecture"]?.GetValue<string>());
        Assert.Equal("sha256:" + sha[..12], restored["sha256"]?.GetValue<string>());
        Assert.True(restored["restored"]?.GetValue<bool>());
        Assert.True(restored["needsReopen"]?.GetValue<bool>());
        Assert.False(restored["debuggerRunning"]?.GetValue<bool>());
        Assert.False(restored["ghidraRunning"]?.GetValue<bool>());
    }

    [Fact]
    public async Task ListAsync_adds_a_restore_hint_only_when_restored_sessions_exist()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var bridge = new RecordingBridge();
        var ghidra = new NullGhidra();
        var context = new AnalysisContext(bridge, ghidra);
        var stub = new RestoredListStub();
        var control = new SessionControlTools(stub, registry, context);

        stub.Payload = "{\"ok\":true,\"result\":{\"sessions\":[{\"analysisId\":\"default\"}," +
            "{\"analysisId\":\"analysis-old\",\"restored\":true,\"needsReopen\":true}],\"maxAnalysisSessions\":8}}";
        using var restored = JsonDocument.Parse(await control.ListAsync(null, CancellationToken.None));
        Assert.Contains("OpenGhidraFile", restored.RootElement.GetProperty("result").GetProperty("restoreHint").GetString());

        stub.Payload = "{\"ok\":true,\"result\":{\"sessions\":[{\"analysisId\":\"default\"}],\"maxAnalysisSessions\":8}}";
        using var live = JsonDocument.Parse(await control.ListAsync(null, CancellationToken.None));
        Assert.False(live.RootElement.GetProperty("result").TryGetProperty("restoreHint", out _));
        Assert.Equal("default", live.RootElement.GetProperty("result").GetProperty("activeAnalysisId").GetString());
    }

    [Fact]
    public async Task ReopenAnalysisSession_unknown_id_reports_not_found()
    {
        using var scope = ManifestScope(out _);
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "analysis-missing" }), CancellationToken.None);
        Assert.False(response["ok"]?.GetValue<bool>());
        Assert.Equal("analysis_session_not_found", response["error"]?["code"]?.GetValue<string>());
    }

    [Theory]
    [InlineData("""{}""")]
    [InlineData("""{"analysisId":""}""")]
    [InlineData("""{"analysisId":"   "}""")]
    public async Task ReopenAnalysisSession_rejects_requests_without_an_explicit_id(string json)
    {
        using var scope = ManifestScope(out _);
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.Deserialize<JsonElement>(json), CancellationToken.None);
        Assert.False(response["ok"]?.GetValue<bool>());
        Assert.Equal("invalid_request", response["error"]?["code"]?.GetValue<string>());
    }

    [Fact]
    public async Task ReopenAnalysisSession_live_default_id_is_a_noop()
    {
        using var scope = ManifestScope(out _);
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "default" }), CancellationToken.None);
        Assert.True(response["ok"]?.GetValue<bool>());
        var result = Assert.IsType<JsonObject>(response["result"]);
        Assert.True(result["alreadyLive"]?.GetValue<bool>());
        Assert.False(result["reopened"]?.GetValue<bool>());
        Assert.Equal("default", result["analysisId"]?.GetValue<string>());
    }

    [Fact]
    public async Task ReopenAnalysisSession_missing_target_keeps_the_manifest_entry()
    {
        using var scope = ManifestScope(out var root);
        var target = Path.Combine(root, "dbglink-reopen-gone.exe");
        AnalysisSessionManifest.Save(new("analysis-gone", target,
            new string('a', 64), "x64", "dbglink-reopen-gone.exe", 2, DateTimeOffset.UtcNow));
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "analysis-gone" }), CancellationToken.None);
        Assert.False(response["ok"]?.GetValue<bool>());
        Assert.Equal("target_missing", response["error"]?["code"]?.GetValue<string>());
        Assert.Equal("analysis-gone", Assert.Single(AnalysisSessionManifest.Load()).AnalysisId);
    }

    [Fact]
    public async Task CloseAnalysisSession_on_a_dead_id_retires_its_manifest_entry()
    {
        using var scope = ManifestScope(out var root);
        var target = Path.Combine(root, "dbglink-dead-close.exe");
        AnalysisSessionManifest.Save(new("analysis-deadclose", target,
            new string('c', 64), "x64", "dbglink-dead-close.exe", 1, DateTimeOffset.UtcNow));
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "CloseAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "analysis-deadclose" }), CancellationToken.None);
        Assert.True(response["ok"]?.GetValue<bool>());
        Assert.True(response["result"]?["alreadyClosed"]?.GetValue<bool>());
        Assert.Empty(AnalysisSessionManifest.Load());
    }

    [Fact]
    public async Task ReopenAnalysisSession_success_retires_the_dead_id_and_reports_the_new_session()
    {
        using var scope = ManifestScope(out var root);
        var target = Path.Combine(root, "dbglink-reopen-target.exe");
        File.WriteAllBytes(target, [0x4d, 0x5a]);
        AnalysisSessionManifest.Save(new("analysis-old01", target,
            new string('b', 64), "x64", "dbglink-reopen-target.exe", 2, DateTimeOffset.UtcNow));
        await using var coordinator = new ToolkitCoordinator
        {
            ReopenOpenOverride = (_, path, _) =>
            {
                Assert.Equal(target, path);
                return Task.FromResult(new GhidraOpenResult(true, "dbglink-reopen-target.exe", true,
                    "analysis-new01", "DbgLink.Control.42", Path.GetTempPath()));
            }
        };
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "analysis-old01" }), CancellationToken.None);
        Assert.True(response["ok"]?.GetValue<bool>());
        var result = Assert.IsType<JsonObject>(response["result"]);
        Assert.True(result["reopened"]?.GetValue<bool>());
        Assert.Equal("analysis-new01", result["analysisId"]?.GetValue<string>());
        Assert.Equal("analysis-old01", result["previousAnalysisId"]?.GetValue<string>());
        Assert.Equal("DbgLink.Control.42", result["nativePipeName"]?.GetValue<string>());
        Assert.Equal(Path.GetTempPath(), result["ghidraEndpointDirectory"]?.GetValue<string>());
        Assert.Contains("analysis-new01", result["sessionNote"]?.GetValue<string>());
        Assert.Empty(AnalysisSessionManifest.Load());
    }

    [Fact]
    public async Task ReopenAnalysisSession_ignores_manifest_entries_evicted_by_the_cap()
    {
        using var scope = ManifestScope(out _);
        for (var i = 0; i < AnalysisSessionManifest.MaxEntries + 1; i++)
            AnalysisSessionManifest.Save(new($"analysis-{i:00}",
                Path.Combine(Path.GetTempPath(), $"dbglink-manifest-evict-{i:00}.exe"),
                new string('c', 64), "x64", $"evict-{i:00}.exe", 0, DateTimeOffset.UtcNow));
        Assert.Equal(AnalysisSessionManifest.MaxEntries, AnalysisSessionManifest.Load().Count);
        await using var coordinator = new ToolkitCoordinator();
        var response = await coordinator.ControlSessionAsync(null!, "ReopenAnalysisSession",
            JsonSerializer.SerializeToElement(new { analysisId = "analysis-00" }), CancellationToken.None);
        Assert.False(response["ok"]?.GetValue<bool>());
        Assert.Equal("analysis_session_not_found", response["error"]?["code"]?.GetValue<string>());
    }

    [Fact]
    public async Task Reopen_is_advertised_and_mutation_gated()
    {
        var control = new SessionControlStub();
        using var readOnly = Server(control, false);
        Assert.DoesNotContain(readOnly.ListTools(), t => t!["name"]!.GetValue<string>() == "ReopenAnalysisSession");
        await Assert.ThrowsAnyAsync<Exception>(() => Call(readOnly, "ReopenAnalysisSession", new { analysisId = "analysis-old01" }));
        using var server = Server(control);
        Assert.Contains(server.ListTools(), t => t!["name"]!.GetValue<string>() == "ReopenAnalysisSession");
        using var lean = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Lean },
            new RecordingBridge(), new NullGhidra(), control);
        Assert.Contains(lean.ListTools(), t => t!["name"]!.GetValue<string>() == "ReopenAnalysisSession");
    }

    [Fact]
    public async Task ReopenAsync_passes_through_a_successful_reopen_with_the_new_session()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
        var stub = new ReopenStub("{\"ok\":true,\"result\":{\"reopened\":true,\"analysisId\":\"analysis-new01\"," +
            "\"previousAnalysisId\":\"analysis-old01\",\"nativePipeName\":\"DbgLink.Control.42\"," +
            "\"ghidraEndpointDirectory\":" + JsonSerializer.Serialize(Path.GetTempPath()) + ",\"fileName\":\"target.exe\"}}");
        var control = new SessionControlTools(stub, registry, context);

        var response = await control.ReopenAsync("analysis-old01", CancellationToken.None);
        Assert.Equal("ReopenAnalysisSession", stub.LastMethod);
        using var parsed = JsonDocument.Parse(response);
        Assert.True(parsed.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("analysis-new01", parsed.RootElement.GetProperty("result").GetProperty("analysisId").GetString());
        Assert.Equal("analysis-old01", parsed.RootElement.GetProperty("result").GetProperty("previousAnalysisId").GetString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ReopenAsync_rejects_a_blank_analysis_id_without_touching_the_launcher(string? analysisId)
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
        var stub = new ReopenStub("{\"ok\":true}");
        var control = new SessionControlTools(stub, registry, context);

        var response = await control.ReopenAsync(analysisId, CancellationToken.None);
        Assert.Contains("invalid_argument", response);
        Assert.Null(stub.LastMethod);
    }

    [Fact]
    public async Task ReopenAsync_passes_target_missing_through_unchanged()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
        var stub = new ReopenStub("{\"ok\":false,\"error\":{\"code\":\"target_missing\",\"message\":\"gone\"}}");
        var control = new SessionControlTools(stub, registry, context);

        var response = await control.ReopenAsync("analysis-gone", CancellationToken.None);
        Assert.Equal("ReopenAnalysisSession", stub.LastMethod);
        Assert.Contains("target_missing", response);
    }

    [Fact]
    public async Task ReopenAnalysisSession_registers_the_new_session_end_to_end()
    {
        var control = new ReopenStub("{\"ok\":true,\"result\":{\"reopened\":true,\"analysisId\":\"analysis-new01\"," +
            "\"previousAnalysisId\":\"analysis-old01\",\"nativePipeName\":\"DbgLink.Control.42\"," +
            "\"ghidraEndpointDirectory\":" + JsonSerializer.Serialize(Path.GetTempPath()) + ",\"fileName\":\"target.exe\"," +
            "\"sessionNote\":\"reopened\"}}");
        using var server = Server(control);
        var result = await Call(server, "ReopenAnalysisSession", new { analysisId = "analysis-old01" });
        Assert.False(result.IsError);
        var text = ((TextContentBlock)result.Content[0]).Text;
        Assert.Contains("analysis-new01", text);
    }

    [Fact]
    public async Task CloseAsync_returns_remaining_sessions_instead_of_a_list_pointer()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.True(registry.TryRegister(new("live-keep", "DbgLink.Control.42", Path.GetTempPath())));
        Assert.True(registry.TryRegister(new("live-gone", "DbgLink.Control.43", Path.GetTempPath())));
        var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
        var control = new SessionControlTools(new CloseStub("live-gone"), registry, context);

        using var first = JsonDocument.Parse(await control.CloseAsync("live-gone", CancellationToken.None));
        var result = first.RootElement.GetProperty("result");
        Assert.Equal("live-gone", result.GetProperty("analysisId").GetString());
        Assert.True(result.GetProperty("closed").GetBoolean());
        Assert.Contains("no longer valid", result.GetProperty("sessionNote").GetString());
        Assert.DoesNotContain("ListAnalysisSessions", result.GetProperty("sessionNote").GetString());
        Assert.Equal(2, result.GetProperty("remainingSessionCount").GetInt32());
        Assert.Equal(new[] { "default", "live-keep" },
            result.GetProperty("remainingSessions").EnumerateArray().Select(e => e.GetString()).ToArray());

        using var second = JsonDocument.Parse(await control.CloseAsync("live-gone", CancellationToken.None));
        var repeated = second.RootElement.GetProperty("result");
        Assert.True(repeated.GetProperty("alreadyClosed").GetBoolean());
        Assert.Equal(2, repeated.GetProperty("remainingSessionCount").GetInt32());
        Assert.Equal(new[] { "default", "live-keep" },
            repeated.GetProperty("remainingSessions").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Fact]
    public async Task ReopenAsync_embeds_the_checkpoint_summary_when_a_handoff_exists()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-reopen-embed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new CheckpointStore(Path.Combine(directory, "checkpoints.json"));
            var tools = new CheckpointTools(store);
            var sha = new string('a', 64);
            await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = sha,
                title = "resume here",
                findings = "entry calls parser",
                hypotheses = "parser reachable",
                verified = "entry checked",
                nextStep = "inspect parser"
            }), "analysis-old01");

            using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
            var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
            var stub = new ReopenStub("{\"ok\":true,\"result\":{\"reopened\":true,\"analysisId\":\"analysis-new01\"," +
                "\"previousAnalysisId\":\"analysis-old01\",\"nativePipeName\":\"DbgLink.Control.42\"," +
                "\"ghidraEndpointDirectory\":" + JsonSerializer.Serialize(Path.GetTempPath()) +
                ",\"fileName\":\"target.exe\",\"sha256\":\"" + sha + "\"}}");
            var control = new SessionControlTools(stub, registry, context) { CheckpointStoreOverride = store };

            using var parsed = JsonDocument.Parse(await control.ReopenAsync("analysis-old01", CancellationToken.None));
            var result = parsed.RootElement.GetProperty("result");
            Assert.Equal("analysis-new01", result.GetProperty("analysisId").GetString());
            Assert.True(result.GetProperty("checkpointFound").GetBoolean());
            var summary = result.GetProperty("checkpointSummary");
            Assert.Equal("resume here", summary.GetProperty("title").GetString());
            Assert.Equal(sha, summary.GetProperty("sha256").GetString());
            Assert.Contains("entry calls parser", summary.GetProperty("findingsPreview").GetString());
            Assert.Contains("Checkpoint", result.GetProperty("checkpointNote").GetString());
        }
        finally { try { Directory.Delete(directory, recursive: true); } catch { } }
    }

    [Fact]
    public async Task ReopenAsync_reports_a_missing_checkpoint_without_forcing_a_lookup()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-reopen-miss-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new CheckpointStore(Path.Combine(directory, "checkpoints.json"));
            using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
            var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
            var stub = new ReopenStub("{\"ok\":true,\"result\":{\"reopened\":true,\"analysisId\":\"analysis-new01\"," +
                "\"previousAnalysisId\":\"analysis-old01\",\"nativePipeName\":\"DbgLink.Control.42\"," +
                "\"ghidraEndpointDirectory\":" + JsonSerializer.Serialize(Path.GetTempPath()) +
                ",\"fileName\":\"target.exe\",\"sha256\":\"" + new string('b', 64) + "\"}}");
            var control = new SessionControlTools(stub, registry, context) { CheckpointStoreOverride = store };

            using var parsed = JsonDocument.Parse(await control.ReopenAsync("analysis-old01", CancellationToken.None));
            var result = parsed.RootElement.GetProperty("result");
            Assert.False(result.GetProperty("checkpointFound").GetBoolean());
            Assert.False(result.TryGetProperty("checkpointSummary", out _));
        }
        finally { try { Directory.Delete(directory, recursive: true); } catch { } }
    }

    [Fact]
    public async Task ReopenAsync_leaves_the_response_untouched_without_a_launcher_sha256()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var context = new AnalysisContext(new RecordingBridge(), new NullGhidra());
        var stub = new ReopenStub("{\"ok\":true,\"result\":{\"reopened\":true,\"analysisId\":\"analysis-new01\"," +
            "\"previousAnalysisId\":\"analysis-old01\",\"nativePipeName\":\"DbgLink.Control.42\"," +
            "\"ghidraEndpointDirectory\":" + JsonSerializer.Serialize(Path.GetTempPath()) + ",\"fileName\":\"target.exe\"}}");
        var control = new SessionControlTools(stub, registry, context);

        using var parsed = JsonDocument.Parse(await control.ReopenAsync("analysis-old01", CancellationToken.None));
        var result = parsed.RootElement.GetProperty("result");
        Assert.Equal("analysis-new01", result.GetProperty("analysisId").GetString());
        Assert.False(result.TryGetProperty("checkpointFound", out _));
        Assert.False(result.TryGetProperty("checkpointSummary", out _));
    }

    [Fact]
    public async Task ListAnalysisSessions_lists_live_only_by_default_and_all_with_includeClosed()
    {
        using var scope = ManifestScope(out var root);
        var liveTarget = Path.Combine(root, "live-target.exe");
        File.WriteAllBytes(liveTarget, [0x4d, 0x5a]);
        var deadTarget = Path.Combine(root, "dead-target.exe");
        File.WriteAllBytes(deadTarget, [0x4d, 0x5a]);
        // Two stale manifest entries plus the dead ambient default slot: 3 dead.
        AnalysisSessionManifest.Save(new("analysis-dead1", deadTarget,
            new string('a', 64), "x64", "dead-target.exe", 0, DateTimeOffset.UtcNow));
        AnalysisSessionManifest.Save(new("analysis-dead2", deadTarget,
            new string('b', 64), "x86", "dead-target.exe", 0, DateTimeOffset.UtcNow));

        var debugger = StartLiveProcess();
        var ghidra = StartLiveProcess();
        await using var coordinator = new ToolkitCoordinator();
        coordinator.RegisterSwitchTestSession("analysis-live", debugger, ghidra,
            "DbgLink.Test.Pipe", new string('c', 64), DebuggerArchitecture.X64, liveTarget);
        try
        {
            var live = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions", default, CancellationToken.None);
            Assert.True(live["ok"]?.GetValue<bool>());
            var liveRows = Assert.IsType<JsonArray>(live["result"]?["sessions"]);
            var single = Assert.Single(liveRows);
            var row = Assert.IsType<JsonObject>(single);
            Assert.Equal("analysis-live", row["analysisId"]?.GetValue<string>());
            Assert.Equal("live-target.exe", row["fileName"]?.GetValue<string>());
            Assert.Null(row["analysisTargetPath"]);
            Assert.Null(row["debuggerPid"]);
            Assert.True(row["debuggerRunning"]?.GetValue<bool>());
            Assert.True(row["ghidraRunning"]?.GetValue<bool>());
            var liveSha = row["sha256"]?.GetValue<string>();
            Assert.StartsWith("sha256:", liveSha);
            Assert.Equal(19, liveSha!.Length);

            var closed = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions",
                JsonSerializer.SerializeToElement(new { includeClosed = true }), CancellationToken.None);
            Assert.True(closed["ok"]?.GetValue<bool>());
            var closedRows = Assert.IsType<JsonArray>(closed["result"]?["sessions"]);
            Assert.Equal(4, closedRows.Count);
            var ids = new HashSet<string>(closedRows.OfType<JsonObject>()
                .Select(r => r["analysisId"]?.GetValue<string>() ?? ""), StringComparer.Ordinal);
            Assert.Equal(new HashSet<string>(["default", "analysis-live", "analysis-dead1", "analysis-dead2"], StringComparer.Ordinal), ids);
            // Every row carries a file name, never a path or pid.
            foreach (var item in closedRows.OfType<JsonObject>())
            {
                Assert.Null(item["analysisTargetPath"]);
                Assert.Null(item["debuggerPid"]);
                Assert.Null(item["ghidraPid"]);
            }
            var dead1 = closedRows.OfType<JsonObject>().Single(r => r["analysisId"]?.GetValue<string>() == "analysis-dead1");
            Assert.Equal("dead-target.exe", dead1["fileName"]?.GetValue<string>());
            Assert.Equal("sha256:aaaaaaaaaaaa", dead1["sha256"]?.GetValue<string>());
            Assert.True(dead1["restored"]?.GetValue<bool>());

            _output.WriteLine($"LIST default={live.ToJsonString().Length}B closed={closed.ToJsonString().Length}B rows=1/4");
        }
        finally
        {
            coordinator.RemoveSwitchTestSession("analysis-live");
            try
            {
                if (!debugger.HasExited) debugger.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or
                System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }
            debugger.Dispose();
            try
            {
                if (!ghidra.HasExited) ghidra.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or
                System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }
            ghidra.Dispose();
        }
    }

    [Fact]
    public async Task ListAnalysisSessions_reports_diet_sizes_for_one_live_plus_eight_dead()
    {
        using var scope = ManifestScope(out var root);
        var liveTarget = Path.Combine(root, "live-target.exe");
        File.WriteAllBytes(liveTarget, [0x4d, 0x5a]);
        var deadTarget = Path.Combine(root, "dead-target.exe");
        File.WriteAllBytes(deadTarget, [0x4d, 0x5a]);
        // Seven stale manifest entries plus the dead ambient slot: 8 dead.
        for (var i = 0; i < 7; i++)
            AnalysisSessionManifest.Save(new($"analysis-dead{i:00}", deadTarget,
                new string((char)('a' + i), 64), "x64", "dead-target.exe", 0, DateTimeOffset.UtcNow));

        var debugger = StartLiveProcess();
        var ghidra = StartLiveProcess();
        await using var coordinator = new ToolkitCoordinator();
        coordinator.RegisterSwitchTestSession("analysis-live", debugger, ghidra,
            "DbgLink.Test.Pipe", new string('c', 64), DebuggerArchitecture.X64, liveTarget);
        try
        {
            var live = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions", default, CancellationToken.None);
            Assert.True(live["ok"]?.GetValue<bool>());
            Assert.Single(Assert.IsType<JsonArray>(live["result"]?["sessions"]));

            var closed = await coordinator.ControlSessionAsync(null!, "ListAnalysisSessions",
                JsonSerializer.SerializeToElement(new { includeClosed = true }), CancellationToken.None);
            Assert.True(closed["ok"]?.GetValue<bool>());
            Assert.Equal(9, Assert.IsType<JsonArray>(closed["result"]?["sessions"]).Count);

            _output.WriteLine($"LIST-1P8D default={live.ToJsonString().Length}B closed={closed.ToJsonString().Length}B rows=1/9");
        }
        finally
        {
            coordinator.RemoveSwitchTestSession("analysis-live");
            try
            {
                if (!debugger.HasExited) debugger.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or
                System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }
            debugger.Dispose();
            try
            {
                if (!ghidra.HasExited) ghidra.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or
                System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }
            ghidra.Dispose();
        }
    }

    [Fact]
    public void SessionSummary_is_a_diet_row_with_file_name_and_short_sha()
    {
        var sha = new string('9', 64);
        var withSha = ToolkitCoordinator.SessionSummary(
            "analysis-x", null, null, DebuggerArchitecture.X64, "C:\\t.exe", sha);
        Assert.Equal("analysis-x", withSha["analysisId"]?.GetValue<string>());
        Assert.Equal("t.exe", withSha["fileName"]?.GetValue<string>());
        Assert.Null(withSha["analysisTargetPath"]);
        Assert.Null(withSha["debuggerPid"]);
        Assert.Null(withSha["ghidraPid"]);
        Assert.Null(withSha["ghidraLauncherPid"]);
        Assert.Equal("x64", withSha["architecture"]?.GetValue<string>());
        Assert.Equal("sha256:" + sha[..12], withSha["sha256"]?.GetValue<string>());

        var withoutSha = ToolkitCoordinator.SessionSummary(
            "analysis-x", null, null, DebuggerArchitecture.X64, "C:\\t.exe", null);
        Assert.Equal("analysis-x", withoutSha["analysisId"]?.GetValue<string>());
        Assert.Null(withoutSha["sha256"]);
        Assert.False(withoutSha["debuggerRunning"]?.GetValue<bool>());

        Assert.Equal("sha256:abcdef123456", ToolkitCoordinator.ShortSha256("ABCDEF123456" + new string('0', 52)));
        Assert.Null(ToolkitCoordinator.ShortSha256(null));
        Assert.Null(ToolkitCoordinator.ShortSha256("not-a-sha"));
    }

    [Fact]
    public void Manifest_TargetHash_matches_sha256_and_rejects_unreadable_paths()
    {
        using var scope = ManifestScope(out var root);
        var target = Path.Combine(root, "dbglink-hash-target.exe");
        File.WriteAllBytes(target, "abc"u8.ToArray());
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ToolkitCoordinator.ComputeTargetSha256(target));
        Assert.Null(ToolkitCoordinator.ComputeTargetSha256(Path.Combine(root, "missing.exe")));
        Assert.Null(ToolkitCoordinator.ComputeTargetSha256(null));
        Assert.Null(ToolkitCoordinator.ComputeTargetSha256("relative.exe"));
    }

    private static IDisposable ManifestScope(out string root)
    {
        root = Path.Combine(Path.GetTempPath(), "dbglink-manifest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        AnalysisSessionManifest.LocalAppDataOverride = root;
        var captured = root;
        return new ManifestReset(captured);
    }

    private sealed class ManifestReset(string root) : IDisposable
    {
        public void Dispose()
        {
            AnalysisSessionManifest.LocalAppDataOverride = null;
            try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private sealed class RestoredListStub : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public string Payload = "";
        public Task<string> OpenFileAsync(string path, CancellationToken token) => throw new NotSupportedException();
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token)
            => Task.FromResult(Payload);
    }

    private sealed class ReopenStub(string payload) : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public string? LastMethod;
        public Task<string> OpenFileAsync(string path, CancellationToken token) => throw new NotSupportedException();
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token)
        {
            LastMethod = method;
            return Task.FromResult(payload);
        }
    }

    private sealed class CloseStub(string analysisId) : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public Task<string> OpenFileAsync(string path, CancellationToken token) => throw new NotSupportedException();
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token)
            => Task.FromResult("{\"ok\":true,\"result\":{\"analysisId\":\"" + analysisId + "\",\"closed\":true}}");
    }

    private static LocalMcpServer Server(IGhidraControlClient control, bool mutation = true, IBridgeClient? bridge = null)
        => new(new ServerConfig { AllowMutation = mutation, MaxConcurrentRequests = 4 },
            bridge ?? new RecordingBridge(), new NullGhidra(), control);
    private static Task<CallToolResult> Call(LocalMcpServer server, string name, object args)
        => server.CallToolAsync(new CallToolRequestParams
        {
            Name = name, Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(JsonSerializer.Serialize(args))
        }, CancellationToken.None);

    private sealed class SessionControlStub : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public bool Fail;
        public int Calls;
        public string? LastMethod;
        public JsonElement LastArguments;
        public Task<string> OpenFileAsync(string path, CancellationToken token) => throw new NotSupportedException();
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token)
        {
            Calls++;
            LastMethod = method;
            LastArguments = args.Clone();
            return Task.FromResult(Fail ? "{\"ok\":false,\"error\":{\"code\":\"test_failure\",\"message\":\"failed\"}}"
                : "{\"ok\":true,\"result\":{\"analysisId\":\"default\",\"closed\":true}}");
        }
    }

    private sealed class WaitingBridge : IBridgeClient
    {
        public readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<bool> PingAsync(CancellationToken token) => Task.FromResult(true);
        public async Task<string> RequestAsync(string method, JsonElement? args, CancellationToken token)
        {
            Started.SetResult();
            await Release.Task.WaitAsync(token);
            return "{\"ok\":true,\"result\":{}}";
        }
    }
}
