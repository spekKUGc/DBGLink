using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Mock-based tests for the opt-in WriteMemory/SetRegister(autoPause=true)
// path, mirroring SnapshotAutoPauseTests: already-paused is a no-op,
// running pauses/mutates/resumes with a note, absent/false is byte-for-byte
// the historical passthrough, and every automation failure is an honest
// error with no bogus success.
public sealed class MutationAutoPauseTests
{
    private const string PausedState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":false,\"threadId\":42,\"stableRead\":true}";
    private const string RunningState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":true,\"threadId\":42,\"stableRead\":true}";
    // Paused but not yet settled: a no-op check must not treat this as running
    // (which would resume a paused target), nor as a stable pause no-op.
    private const string UnstablePausedState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":false,\"threadId\":42,\"stableRead\":false}";

    private const string WriteOk =
        "{\"action\":\"writeMemory\",\"address\":\"0x0000000000001000\"," +
        "\"bytesWritten\":2,\"nextAddress\":\"0x0000000000001002\"}";
    private const string RegisterOk =
        "{\"action\":\"setRegister\",\"register\":\"rax\"," +
        "\"oldValue\":\"0x0000000000000000\",\"newValue\":\"0x0000000000000001\"}";

    private sealed class MutationBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        private readonly HashSet<string> _throwing = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];
        public readonly List<(string Method, string? ArgsJson)> WithArgs = [];

        public MutationBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
            return this;
        }

        public MutationBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public MutationBridge Throws(string method)
        {
            _throwing.Add(method);
            return this;
        }

        public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

        public static string BridgeError(string code, string message) =>
            "{\"id\":1,\"ok\":false,\"error\":{\"code\":" + JsonSerializer.Serialize(code) +
            ",\"message\":" + JsonSerializer.Serialize(message) + "}}";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            WithArgs.Add((method, arguments?.GetRawText()));
            if (_throwing.Contains(method))
                return Task.FromException<string>(new IOException("test transport failure"));
            if (_scripts.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            if (_sticky.TryGetValue(method, out var response))
                return Task.FromResult(response);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    private static LiveAnalysisTools Live(MutationBridge bridge)
        => new(new AnalysisContext(bridge, new NullGhidra()));

    private static JsonElement Args(string json)
        => JsonSerializer.Deserialize<JsonElement>(json);

    private static string? ArgsFor(MutationBridge bridge, string method)
        => bridge.WithArgs.FirstOrDefault(c => c.Method == method).ArgsJson;

    private static MutationBridge PausedWriteBridge()
        => new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(PausedState))
            .Sticky("WriteMemory", MutationBridge.Ok(WriteOk));

    private static MutationBridge PausedRegisterBridge()
        => new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(PausedState))
            .Sticky("SetRegister", MutationBridge.Ok(RegisterOk));

    private static MutationBridge RunningWriteBridge()
        => new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(RunningState))
            .Sticky("WriteMemory", MutationBridge.Ok(WriteOk));

    [Fact]
    public async Task WriteMemory_Absent_Matches_ExplicitFalse_WithNoControlCalls()
    {
        var first = PausedWriteBridge();
        var second = PausedWriteBridge();
        var absent = await Live(first).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\"}"), CancellationToken.None);
        var explicitFalse = await Live(second).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":false}"), CancellationToken.None);

        Assert.Equal(absent, explicitFalse);
        Assert.DoesNotContain("PauseDebugger", first.Calls);
        Assert.DoesNotContain("RunDebugger", first.Calls);
        Assert.DoesNotContain("PauseDebugger", second.Calls);
        Assert.DoesNotContain("RunDebugger", second.Calls);
        // The MCP-only flag never reaches the native bridge.
        Assert.DoesNotContain("autoPause", ArgsFor(second, "WriteMemory") ?? "");
    }

    [Fact]
    public async Task SetRegister_Absent_Matches_ExplicitFalse_WithNoControlCalls()
    {
        var first = PausedRegisterBridge();
        var second = PausedRegisterBridge();
        var absent = await Live(first).SetRegisterAsync(
            Args("{\"register\":\"rax\",\"value\":\"0x1\"}"), CancellationToken.None);
        var explicitFalse = await Live(second).SetRegisterAsync(
            Args("{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":false}"), CancellationToken.None);

        Assert.Equal(absent, explicitFalse);
        Assert.DoesNotContain("PauseDebugger", second.Calls);
        Assert.DoesNotContain("RunDebugger", second.Calls);
        Assert.DoesNotContain("autoPause", ArgsFor(second, "SetRegister") ?? "");
    }

    [Fact]
    public async Task WriteMemory_False_OnRunningTarget_UnchangedOutput_NoControlCalls()
    {
        var first = RunningWriteBridge();
        var second = RunningWriteBridge();
        var absent = await Live(first).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\"}"), CancellationToken.None);
        var explicitFalse = await Live(second).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":false}"), CancellationToken.None);

        Assert.Equal(absent, explicitFalse);
        using var doc = JsonDocument.Parse(explicitFalse);
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.DoesNotContain("PauseDebugger", second.Calls);
        Assert.DoesNotContain("RunDebugger", second.Calls);
    }

    [Fact]
    public async Task WriteMemory_AlreadyPaused_IsNoOp_NoControlCalls_NoNote()
    {
        var bridge = PausedWriteBridge();
        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        Assert.False(root.GetProperty("result").TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("autoPause", ArgsFor(bridge, "WriteMemory") ?? "");
    }

    [Fact]
    public async Task SetRegister_AlreadyPaused_IsNoOp_NoControlCalls_NoNote()
    {
        var bridge = PausedRegisterBridge();
        var raw = await Live(bridge).SetRegisterAsync(
            Args("{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("result").TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task WriteMemory_Running_PausesMutatesResumes_WithNote()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("WriteMemory", MutationBridge.Ok(WriteOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());
        Assert.False(autoPause.TryGetProperty("note", out _));

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var mutateAt = bridge.Calls.IndexOf("WriteMemory");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && mutateAt > pauseAt && resumeAt > mutateAt);
        Assert.DoesNotContain("autoPause", ArgsFor(bridge, "WriteMemory") ?? "");
    }

    [Fact]
    public async Task SetRegister_Running_PausesMutatesResumes_WithNote()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("SetRegister", MutationBridge.Ok(RegisterOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await Live(bridge).SetRegisterAsync(
            Args("{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var mutateAt = bridge.Calls.IndexOf("SetRegister");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && mutateAt > pauseAt && resumeAt > mutateAt);
    }

    [Fact]
    public async Task WriteMemory_PauseRefused_HonestError_NoMutate_NoResume()
    {
        var bridge = RunningWriteBridge()
            .Sticky("PauseDebugger", MutationBridge.BridgeError("pause_failed", "cannot pause"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_pause_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("WriteMemory", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task WriteMemory_PauseThrows_HonestError_NoMutate()
    {
        var bridge = RunningWriteBridge().Throws("PauseDebugger");

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.Equal("debugger_pause_failed",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("WriteMemory", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task WriteMemory_NeverPauses_BestEffortResume_HonestError()
    {
        // Full 60x50ms auto-pause budget against a target that never pauses:
        // ~3s by design, matching the snapshot budget.
        var bridge = RunningWriteBridge()
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_running_timeout", root.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("WriteMemory", bridge.Calls);
    }

    [Fact]
    public async Task WriteMemory_ResumeFailure_HonestError_NoSuccess()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("WriteMemory", MutationBridge.Ok(WriteOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.BridgeError("run_failed", "cannot resume"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_resume_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("bytesWritten", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetRegister_ResumeFailure_HonestError_NoSuccess()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("SetRegister", MutationBridge.Ok(RegisterOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.BridgeError("run_failed", "cannot resume"));

        var raw = await Live(bridge).SetRegisterAsync(
            Args("{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_resume_failed",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task WriteMemory_MutationFailure_StillResumes_ReportsMutationError()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("WriteMemory", MutationBridge.BridgeError("native_error", "Failed to write memory"))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("native_error", root.GetProperty("error").GetProperty("code").GetString());
        // Best-effort restore still happened; no bogus autoPause success note.
        Assert.Contains("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("autoPause", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WriteMemory_MutationThrows_ResumesThenRethrows()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"))
            .Throws("WriteMemory");

        await Assert.ThrowsAsync<IOException>(() => Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None));
        Assert.Contains("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task WriteMemory_UnreadableState_NoControlCalls()
    {
        var bridge = PausedWriteBridge()
            .Sticky("GetSnapshotState", MutationBridge.BridgeError("transport_error", "pipe hiccup"));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.Equal("snapshot_state_unreadable",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("WriteMemory", bridge.Calls);
    }

    [Fact]
    public void Mutation_Schema_AdvertisesFlag_And_ValidatesOverWire()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        var valid = new Dictionary<string, string>
        {
            ["WriteMemory"] = "{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}",
            ["SetRegister"] = "{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":true}",
        };
        var invalid = new Dictionary<string, string>
        {
            ["WriteMemory"] = "{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":\"yes\"}",
            ["SetRegister"] = "{\"register\":\"rax\",\"value\":\"0x1\",\"autoPause\":\"yes\"}",
        };
        foreach (var name in new[] { "WriteMemory", "SetRegister" })
        {
            var tool = server.ListTools().OfType<JsonObject>()
                .Single(t => t["name"]!.GetValue<string>() == name);
            var rule = tool["inputSchema"]!["properties"]!["autoPause"]!.AsObject();
            Assert.Equal("boolean", rule["type"]!.GetValue<string>());
            // The false default rides server-side: omitted still validates.
            Assert.Null(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>(valid[name].Replace(",\"autoPause\":true", ""))));

            Assert.Null(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>(valid[name])));
            Assert.NotNull(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>(invalid[name])));
        }
    }

    [Fact]
    public async Task WriteMemory_PausedButUnstable_NeverResumes_StaysPaused()
    {
        // autoPause must never flip a paused target to running. A paused-but-
        // unstable target is waited for a stable pause, mutated, and left
        // paused: no PauseDebugger, no RunDebugger, no resume note.
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(UnstablePausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("WriteMemory", MutationBridge.Ok(WriteOk));

        var raw = await Live(bridge).WriteMemoryAsync(
            Args("{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        Assert.False(root.GetProperty("result").TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.Contains("WriteMemory", bridge.Calls);
    }

    [Fact]
    public async Task Batch_Rejects_AutoPause_Inside_Requests()
    {
        // autoPause is a direct-tool-only flag: the batch forwards sub-args raw
        // to the bridge, so it must be rejected, not silently stripped.
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true },
            new RecordingBridge());
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                "{\"requests\":[{\"method\":\"WriteMemory\",\"arguments\":{\"address\":\"csp\",\"hexBytes\":\"90 90\",\"autoPause\":true}}]}")!,
        }, CancellationToken.None);
        var text = ((TextContentBlock)result.Content[0]).Text;
        Assert.Contains("invalid_batch", text, StringComparison.Ordinal);
        Assert.Contains("autoPause", text, StringComparison.Ordinal);
    }

    // ---- WS3 C1 read-side auto-pause helper (contract for WS4) ----
    //
    // ExecuteReadWithAutoPauseAsync mirrors ExecuteMutationWithAutoPauseAsync
    // for reads: pause-if-running, run the bridge call, resume-if-we-paused,
    // attach the autoPause note. Already-paused/no-session is the historical
    // passthrough with no extra calls. Not wired to any tool schema yet.

    private const string NoSessionState =
        "{\"debuggerPid\":0,\"generation\":\"1\",\"debugging\":false," +
        "\"running\":false,\"threadId\":0,\"stableRead\":true}";

    private const string ThreadsOk = "{\"threads\":[{\"tid\":1,\"cip\":\"0x140001000\"}]}";

    private static Task<string> ReadAsync(MutationBridge bridge, string method, string argsJson)
        => Live(bridge).ExecuteReadWithAutoPauseAsync(method, Args(argsJson), CancellationToken.None);

    [Fact]
    public async Task ReadAutoPause_AlreadyPaused_Passthrough_NoControlCalls_NoNote()
    {
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(PausedState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        Assert.Equal(MutationBridge.Ok(ThreadsOk), raw);
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("autoPause", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAutoPause_NoSession_Passthrough_NoControlCalls()
    {
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(NoSessionState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        Assert.Equal(MutationBridge.Ok(ThreadsOk), raw);
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_Running_PausesReadsResumes_WithNote()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());
        Assert.False(autoPause.TryGetProperty("note", out _));
        Assert.Single(result.GetProperty("threads").EnumerateArray());

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var readAt = bridge.Calls.IndexOf("ListThreads");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && readAt > pauseAt && resumeAt > readAt);
        Assert.Equal("{\"maxItems\":8}", ArgsFor(bridge, "ListThreads"));
    }

    [Fact]
    public async Task ReadAutoPause_PauseRefused_HonestError_NoRead_NoResume()
    {
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(RunningState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk))
            .Sticky("PauseDebugger", MutationBridge.BridgeError("pause_failed", "cannot pause"));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_pause_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("ListThreads", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_PauseThrows_HonestError_NoRead()
    {
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(RunningState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk))
            .Throws("PauseDebugger");

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        Assert.Equal("debugger_pause_failed",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("ListThreads", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_NeverPauses_BestEffortResume_HonestError()
    {
        // Full 60x50ms auto-pause budget against a target that never pauses:
        // ~3s by design, matching the mutation budget.
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.Ok(RunningState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_running_timeout", root.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("ListThreads", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_ReadError_StillResumes_ReportsReadError_NoNote()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("ListThreads", MutationBridge.BridgeError("native_error", "Failed to list threads"))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("native_error", root.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("autoPause", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAutoPause_ReadThrows_ResumesThenRethrows()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.Ok("{}"))
            .Throws("ListThreads");

        await Assert.ThrowsAsync<IOException>(() => ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}"));
        Assert.Contains("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_ResumeFailure_HonestError_NoSuccess()
    {
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(RunningState),
                MutationBridge.Ok(PausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk))
            .Sticky("PauseDebugger", MutationBridge.Ok("{}"))
            .Sticky("RunDebugger", MutationBridge.BridgeError("run_failed", "cannot resume"));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_resume_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("threads", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAutoPause_UnreadableState_NoControlCalls()
    {
        var bridge = new MutationBridge()
            .Sticky("GetSnapshotState", MutationBridge.BridgeError("transport_error", "pipe hiccup"))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        Assert.Equal("snapshot_state_unreadable",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("ListThreads", bridge.Calls);
    }

    [Fact]
    public async Task ReadAutoPause_PausedButUnstable_NeverResumes_StaysPaused()
    {
        // autoPause must never flip a paused target to running. A paused-but-
        // unstable target is waited for a stable pause, read, and left
        // paused: no PauseDebugger, no RunDebugger, no resume note.
        var bridge = new MutationBridge()
            .Script("GetSnapshotState",
                MutationBridge.Ok(UnstablePausedState),
                MutationBridge.Ok(PausedState))
            .Sticky("ListThreads", MutationBridge.Ok(ThreadsOk));

        var raw = await ReadAsync(bridge, "ListThreads", "{\"maxItems\":8}");

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        Assert.Single(root.GetProperty("result").GetProperty("threads").EnumerateArray());
        Assert.DoesNotContain("autoPause", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.Contains("ListThreads", bridge.Calls);
    }
}
