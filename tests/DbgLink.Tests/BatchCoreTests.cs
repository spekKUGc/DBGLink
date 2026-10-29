using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// WS7 batch-core pins (round-trip plan C2/C3, P2-11 docs):
/// localDispatch routing, per-row validation error shape, batch-level
/// autoPause, and mutation ack-trust descriptions. Sibling suites pin the
/// bridge-only path (whole-batch abort); this file additionally pins that
/// the null-localDispatch path keeps it.
/// </summary>
public sealed class BatchCoreTests : IDisposable
{
    private const string PausedState =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true}";
    private const string RunningState =
        "{\"debugging\":true,\"running\":true,\"stableRead\":true}";
    private const string UnstablePausedState =
        "{\"debugging\":true,\"running\":false,\"stableRead\":false}";

    private readonly List<string> _tempDirs = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }
    }

    private sealed class ScriptBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        private readonly HashSet<string> _throwing = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];

        public ScriptBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public ScriptBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
            return this;
        }

        public ScriptBridge Throws(string method)
        {
            _throwing.Add(method);
            return this;
        }

        public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

        public static string Fail(string code, string message) =>
            "{\"id\":1,\"ok\":false,\"error\":{\"code\":" + JsonSerializer.Serialize(code) +
            ",\"message\":" + JsonSerializer.Serialize(message) + "}}";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (_throwing.Contains(method))
                return Task.FromException<string>(new IOException("test transport failure"));
            if (_scripts.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            if (_sticky.TryGetValue(method, out var response))
                return Task.FromResult(response);
            return Task.FromResult(Ok("{}"));
        }
    }

    private sealed class CountingGhidra : IGhidraClient
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    /// <summary>
    /// Ghidra double that holds every request until <paramref name="expected"/>
    /// of them are inside it at once, and records the peak. A sequential batch
    /// can never reach the peak, so the wait times out.
    /// </summary>
    private sealed class BarrieredGhidra : IGhidraClient
    {
        private readonly int _expected;
        private readonly CountdownEvent _arrived;
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _current;
        private int _peak;

        public BarrieredGhidra(int expected)
        {
            _expected = expected;
            _arrived = new CountdownEvent(expected);
        }

        public int Peak => Volatile.Read(ref _peak);

        public bool WaitForConcurrency(TimeSpan timeout) => _arrived.Wait(timeout);

        public void Release() => _release.TrySetResult();

        public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            var now = Interlocked.Increment(ref _current);
            int observed;
            do
            {
                observed = Volatile.Read(ref _peak);
                if (now <= observed) break;
            }
            while (Interlocked.CompareExchange(ref _peak, now, observed) != observed);

            if (now <= _expected)
                _arrived.Signal();
            try
            {
                await _release.Task.WaitAsync(token);
                return "{\"id\":1,\"ok\":true,\"result\":{}}";
            }
            finally
            {
                Interlocked.Decrement(ref _current);
            }
        }
    }

    /// <summary>
    /// BatchStaticQueries must use the bridge's four read slots. The old loop
    /// awaited every sub-request, so a four-item batch cost four decompiles in
    /// series even though Ghidra runs four connection workers with per-thread
    /// decompilers.
    /// </summary>
    [Fact]
    public async Task Static_batch_dispatches_reads_in_parallel_up_to_the_bridge_width()
    {
        var ghidra = new BarrieredGhidra(expected: 4);
        using var server = new LocalMcpServer(new ServerConfig { Port = 50390 }, new RecordingBridge(), ghidra);

        var call = server.CallToolAsync(
            TestWire.Call("BatchStaticQueries", BatchArgs(
                ("InspectFunction", "{\"function\":\"alpha\"}"),
                ("InspectFunction", "{\"function\":\"beta\"}"),
                ("InspectFunction", "{\"function\":\"gamma\"}"),
                ("InspectFunction", "{\"function\":\"delta\"}")).GetRawText()),
            CancellationToken.None);

        var overlapped = await Task.Run(() => ghidra.WaitForConcurrency(TimeSpan.FromSeconds(10)));
        ghidra.Release();
        var text = TextOf(await call);

        Assert.True(overlapped,
            $"only {ghidra.Peak} Ghidra reads overlapped; the static batch is serialising them");
        Assert.DoesNotContain("invalid_batch", text);
        Assert.DoesNotContain("\"ok\":false", text);
    }

    [Fact]
    public async Task Static_batch_success_rows_drop_bridge_id_and_false_flags()
    {
        var bridge = new ScriptBridge();
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ListFunctions", "ListSymbols" };

        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("ListFunctions", "{}"), ("ListSymbols", "{\"kind\":\"imports\"}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, static method => $"unsupported '{method}'",
            60_000, true, null);

        using var document = JsonDocument.Parse(raw);
        var result = document.RootElement.GetProperty("result");
        // Complete all-success batch: the fixed false flags are absent, not
        // echoed as "partial":false,"truncated":false.
        Assert.False(result.TryGetProperty("partial", out var partial) && partial.GetBoolean());
        Assert.False(result.TryGetProperty("truncated", out var truncated) && truncated.GetBoolean());
        foreach (var row in result.GetProperty("results").EnumerateArray())
            Assert.False(row.GetProperty("response").TryGetProperty("id", out _));
    }

    private ToolRegistry CreateRegistry(IBridgeClient bridge, IGhidraClient ghidra)
    {
        var dir = Path.Combine(Path.GetTempPath(), "dbglink-batchcore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        var context = new AnalysisContext(bridge, ghidra);
        var live = new LiveAnalysisTools(context);
        return new ToolRegistry(context,
            new CheckpointTools(new CheckpointStore(Path.Combine(dir, "checkpoints.json"))),
            live, new InvestigationTools(context, live), new AddressMapping(context),
            new GhidraOpenOperations(null));
    }

    private static JsonElement BatchArgs(params (string Method, string ArgsJson)[] rows)
    {
        var items = string.Join(",", rows.Select(row =>
            "{\"method\":" + JsonSerializer.Serialize(row.Method) +
            ",\"arguments\":" + row.ArgsJson + "}"));
        return JsonSerializer.Deserialize<JsonElement>("{\"requests\":[" + items + "]}");
    }

    private static CallToolRequestParams Call(string name, string argsJson) => TestWire.Call(name, argsJson);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    // ---- C2: localDispatch routing ----

    [Fact]
    public async Task LocalDispatch_RoutesLocalRowsLocally_BridgeRowsToSend()
    {
        var bridge = new ScriptBridge().Sticky("ListFunctions", ScriptBridge.Ok("{\"source\":\"bridge\"}"));
        var local = new ScriptBridge().Sticky("GetAnalysisQueue", ScriptBridge.Ok("{\"source\":\"local\"}"));
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "GetAnalysisQueue", "ListFunctions" };

        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("GetAnalysisQueue", "{}"), ("ListFunctions", "{}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, static method => $"unsupported '{method}'",
            60_000, true, local.RequestAsync);

        Assert.Equal(["ListFunctions"], bridge.Calls);
        Assert.Equal(["GetAnalysisQueue"], local.Calls);
        using var doc = JsonDocument.Parse(raw);
        var rows = doc.RootElement.GetProperty("result").GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.Equal(0, rows[0].GetProperty("index").GetInt32());
        Assert.Contains("local", rows[0].GetProperty("response").GetRawText(), StringComparison.Ordinal);
        Assert.Equal(1, rows[1].GetProperty("index").GetInt32());
        Assert.Contains("bridge", rows[1].GetProperty("response").GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LocalDispatch_Null_SendsEverything_ToBridge()
    {
        // Null localDispatch is the historical bridge-only path: every
        // admitted method goes to send.
        var bridge = new ScriptBridge()
            .Sticky("GetAnalysisQueue", ScriptBridge.Ok("{}"))
            .Sticky("ListFunctions", ScriptBridge.Ok("{}"));
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "GetAnalysisQueue", "ListFunctions" };

        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("GetAnalysisQueue", "{}"), ("ListFunctions", "{}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, static method => $"unsupported '{method}'",
            60_000, true, localDispatch: null);

        Assert.Equal(["GetAnalysisQueue", "ListFunctions"], bridge.Calls);
        using var doc = JsonDocument.Parse(raw);
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("result").TryGetProperty("partial", out var partialFlag) && partialFlag.GetBoolean());
    }

    // ---- C2: per-row validation ----

    [Fact]
    public async Task PerRowValidation_BadRowIsolated_GoodRowsRun()
    {
        var bridge = new ScriptBridge().Sticky("ListFunctions", ScriptBridge.Ok("{\"functions\":[]}"));
        var local = new ScriptBridge().Sticky("ListFunctions", ScriptBridge.Ok("{\"functions\":[]}"));
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ListFunctions" };

        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("ListFunctions", "{}"),
                    ("ListFunctions", "{\"maxItems\":0}"),
                    ("ListFunctions", "{\"maxItems\":5}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, static method => $"unsupported '{method}'",
            60_000, true, local.RequestAsync);

        // Only the two valid rows reach a backend; ListFunctions is not local.
        Assert.Equal(2, bridge.Calls.Count);
        Assert.Empty(local.Calls);
        using var doc = JsonDocument.Parse(raw);
        var result = doc.RootElement.GetProperty("result");
        Assert.True(result.TryGetProperty("partial", out var partialRow) && partialRow.GetBoolean());
        Assert.False(result.TryGetProperty("truncated", out var truncatedRow) && truncatedRow.GetBoolean());
        var rows = result.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(3, rows.Length);
        Assert.True(rows[0].GetProperty("response").GetProperty("ok").GetBoolean());
        var bad = rows[1].GetProperty("response");
        Assert.False(bad.GetProperty("ok").GetBoolean());
        Assert.Equal("invalid_batch", bad.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("Request #1", bad.GetProperty("error").GetProperty("message").GetString(), StringComparison.Ordinal);
        Assert.Contains("ListFunctions", bad.GetProperty("error").GetProperty("message").GetString(), StringComparison.Ordinal);
        Assert.True(rows[2].GetProperty("response").GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task PerRowValidation_FamilyMismatch_StaysHardError_WithZeroCalls()
    {
        var bridge = new ScriptBridge();
        var local = new ScriptBridge();
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ListFunctions" };

        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("ListFunctions", "{}"),
                    ("ReadMemAtAddress", "{\"address\":\"cip\"}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, static method => $"unsupported '{method}'",
            60_000, true, local.RequestAsync);

        Assert.Contains("invalid_batch", raw, StringComparison.Ordinal);
        Assert.Contains("Request #1", raw, StringComparison.Ordinal);
        Assert.Empty(bridge.Calls);
        Assert.Empty(local.Calls);
    }

    [Fact]
    public async Task BridgeOnlyBatch_KeepsWholeBatchAbort_BeforeAnyCall()
    {
        // Pins the null-localDispatch contract: with NO local dispatcher a
        // schema failure aborts the whole batch exactly as before, zero calls.
        var bridge = new ScriptBridge();
        var registry = CreateRegistry(bridge, new NullGhidra());
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ListFunctions" };
        var raw = await registry.ExecuteBatchAsync(
            new ToolInvocation("BatchStaticQueries",
                BatchArgs(("ListFunctions", "{}"), ("ListFunctions", "{\"bogus\":1}")),
                null, CancellationToken.None),
            bridge.RequestAsync, allowed, method => $"unsupported '{method}'",
            60_000, true, localDispatch: null);
        Assert.Contains("invalid_batch", raw, StringComparison.Ordinal);
        Assert.Contains("Request #1", raw, StringComparison.Ordinal);
        Assert.Empty(bridge.Calls);
    }

    // ---- C3: batch-level autoPause ----

    [Fact]
    public void BatchSchema_ExposesAutoPause_OnBothBatches()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        foreach (var name in new[] { "BatchStaticQueries", "BatchDebuggerOperations" })
        {
            var tool = server.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == name);
            var rule = tool["inputSchema"]!["properties"]!["autoPause"]!.AsObject();
            Assert.Equal("boolean", rule["type"]!.GetValue<string>());
            // The false default rides server-side: omitted still validates.
            Assert.Null(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>("{\"requests\":[{\"method\":\"ListFunctions\",\"arguments\":{}}]}")));
            Assert.Null(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>("{\"requests\":[{\"method\":\"ListFunctions\",\"arguments\":{}}],\"autoPause\":true}")));
            Assert.NotNull(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>("{\"requests\":[{\"method\":\"ListFunctions\",\"arguments\":{}}],\"autoPause\":\"yes\"}")));
        }
    }

    private static ScriptBridge RunningBatchBridge() => new ScriptBridge()
        .Script("GetSnapshotState", ScriptBridge.Ok(RunningState))
        .Sticky("GetSnapshotState", ScriptBridge.Ok(PausedState))
        .Sticky("PauseDebugger", ScriptBridge.Ok("{}"))
        .Sticky("RunDebugger", ScriptBridge.Ok("{}"))
        .Sticky("ReadMemAtAddress", ScriptBridge.Ok("{\"bytes\":\"90\"}"))
        .Sticky("ListBreakpoints", ScriptBridge.Ok("{\"breakpoints\":[]}"));

    private const string TwoReadsWithPause =
        "{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"cip\"}},{\"method\":\"ListBreakpoints\",\"arguments\":{}}],\"autoPause\":true}";

    [Fact]
    public async Task BatchAutoPause_Running_PausesRunsResumesOnce_WithNote()
    {
        var bridge = RunningBatchBridge();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(
            Call("BatchDebuggerOperations", TwoReadsWithPause), CancellationToken.None);

        Assert.False(result.IsError);
        using var doc = JsonDocument.Parse(TextOf(result));
        var envelope = doc.RootElement;
        Assert.False(envelope.TryGetProperty("partial", out var envelopePartial) && envelopePartial.GetBoolean());
        var rows = envelope.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        var note = envelope.GetProperty("autoPause");
        Assert.True(note.GetProperty("resumed").GetBoolean());
        Assert.False(note.TryGetProperty("note", out _));

        Assert.Equal(1, bridge.Calls.Count(c => c == "PauseDebugger"));
        Assert.Equal(1, bridge.Calls.Count(c => c == "RunDebugger"));
        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt < bridge.Calls.IndexOf("ReadMemAtAddress"));
        Assert.True(pauseAt < bridge.Calls.IndexOf("ListBreakpoints"));
        Assert.True(resumeAt > bridge.Calls.IndexOf("ReadMemAtAddress"));
        Assert.True(resumeAt > bridge.Calls.IndexOf("ListBreakpoints"));
    }

    [Fact]
    public async Task BatchAutoPause_AlreadyPaused_IsNoOp_NoNote()
    {
        var bridge = new ScriptBridge()
            .Sticky("GetSnapshotState", ScriptBridge.Ok(PausedState))
            .Sticky("ReadMemAtAddress", ScriptBridge.Ok("{\"bytes\":\"90\"}"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            "{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"cip\"}}],\"autoPause\":true}"),
            CancellationToken.None);

        Assert.False(result.IsError);
        using var doc = JsonDocument.Parse(TextOf(result));
        Assert.False(doc.RootElement.TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.Contains("ReadMemAtAddress", bridge.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_PauseRefused_HonestError_NoItemsRun()
    {
        var bridge = new ScriptBridge()
            .Script("GetSnapshotState", ScriptBridge.Ok(RunningState))
            .Sticky("GetSnapshotState", ScriptBridge.Ok(PausedState))
            .Sticky("PauseDebugger", ScriptBridge.Fail("pause_failed", "cannot pause"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(
            Call("BatchDebuggerOperations", TwoReadsWithPause), CancellationToken.None);

        Assert.True(result.IsError);
        Assert.Contains("debugger_pause_failed", TextOf(result), StringComparison.Ordinal);
        Assert.DoesNotContain("ReadMemAtAddress", bridge.Calls);
        Assert.DoesNotContain("ListBreakpoints", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_ResumeFailure_HonestError()
    {
        var bridge = RunningBatchBridge()
            .Sticky("RunDebugger", ScriptBridge.Fail("run_failed", "cannot resume"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(
            Call("BatchDebuggerOperations", TwoReadsWithPause), CancellationToken.None);

        Assert.True(result.IsError);
        Assert.Contains("debugger_resume_failed", TextOf(result), StringComparison.Ordinal);
        Assert.Contains("ReadMemAtAddress", bridge.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_StaticBatch_RejectsFlag_BeforeAnyCall()
    {
        var ghidra = new CountingGhidra();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort },
            new RecordingBridge(), ghidra);
        var result = await server.CallToolAsync(Call("BatchStaticQueries",
            """{"requests":[{"method":"ListFunctions","arguments":{}}],"autoPause":true}"""),
            CancellationToken.None);
        Assert.True(result.IsError);
        Assert.Contains("invalid_batch", TextOf(result), StringComparison.Ordinal);
        Assert.Contains("autoPause", TextOf(result), StringComparison.Ordinal);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_ItemTransportFailure_StillResumes()
    {
        var bridge = RunningBatchBridge().Throws("ReadMemAtAddress");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            "{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"cip\"}}],\"autoPause\":true}"),
            CancellationToken.None);

        Assert.True(result.IsError);
        Assert.Contains("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_UnstableNeverSettles_LeftPaused_HonestError()
    {
        // Full ~3s pause budget against a target that never stabilizes, mirroring
        // the LiveAnalysisTools never-pauses pin: honest timeout, and a target
        // we never paused is left paused (no resume call).
        var bridge = new ScriptBridge()
            .Sticky("GetSnapshotState", ScriptBridge.Ok(UnstablePausedState))
            .Sticky("ReadMemAtAddress", ScriptBridge.Ok("{\"bytes\":\"90\"}"));
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);
        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            "{\"requests\":[{\"method\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"cip\"}}],\"autoPause\":true}"),
            CancellationToken.None);

        Assert.True(result.IsError);
        Assert.Contains("debugger_running_timeout", TextOf(result), StringComparison.Ordinal);
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("ReadMemAtAddress", bridge.Calls);
    }

    // ---- P2-11: mutation ack-trust docs ----

    [Fact]
    public void MutationDescriptions_DeclareAckTrust_And_Disambiguate()
    {
        // Registration metadata: the single-op annotate/mutate tools were
        // physically purged (P3); BatchAnnotate/SubmitAnnotations are the only
        // annotation surface left and carry the committed=true contract.
        var registry = CreateRegistry(new RecordingBridge(), new NullGhidra());
        string Description(string name) => registry.Definitions
            .Single(d => d.Name == name).Metadata["description"]!.GetValue<string>();

        foreach (var name in new[] { "BatchAnnotate", "SubmitAnnotations" })
            Assert.Contains("committed=true", Description(name), StringComparison.Ordinal);
        Assert.Contains("SubmitAnnotations", Description("BatchAnnotate"), StringComparison.Ordinal);
        Assert.Contains("GetAnalysisQueue", Description("SubmitAnnotations"), StringComparison.Ordinal);
    }
}

