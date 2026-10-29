using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

// Mock-based tests for the opt-in GetAnalysisSnapshot(autoPause=true) path:
// already-paused is a no-op, running pauses/reads/resumes with a note,
// absent/false is byte-for-byte the historical path, and every automation
// failure is an honest error with no racing snapshot.
public sealed class SnapshotAutoPauseTests
{
    private const string PausedState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":false,\"threadId\":42,\"stableRead\":true}";
    private const string RunningState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":true,\"threadId\":42,\"stableRead\":true}";

    // Status without the batched capability, so the snapshot takes the
    // individual section path (same shape as AnalysisAccuracyTests).
    private const string PlainStatus =
        "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
        "\"pid\":123,\"debugging\":true}";

    private sealed class AutoPauseBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        private readonly HashSet<string> _throwing = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];
        public readonly List<(string Method, string? ArgsJson)> WithArgs = [];

        public AutoPauseBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
            return this;
        }

        public AutoPauseBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public AutoPauseBridge Throws(string method)
        {
            _throwing.Add(method);
            return this;
        }

        public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

        public static string Text(string text) =>
            "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(text) + "}";

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

    private static LiveAnalysisTools Live(AutoPauseBridge bridge)
        => new(new AnalysisContext(bridge, new NullGhidra()));

    private static JsonElement Args(string json)
        => JsonSerializer.Deserialize<JsonElement>(json);

    private static string? ArgsFor(AutoPauseBridge bridge, string method)
        => bridge.WithArgs.FirstOrDefault(c => c.Method == method).ArgsJson;

    private static AutoPauseBridge PausedSectionsBridge()
        => new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Sticky("GetSnapshotState", AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"));

    private static AutoPauseBridge RunningSectionsBridge()
        => new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Sticky("GetSnapshotState", AutoPauseBridge.Ok(RunningState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"));

    [Fact]
    public async Task AutoPause_Absent_Matches_ExplicitFalse_WithNoControlCalls()
    {
        var first = PausedSectionsBridge();
        var second = PausedSectionsBridge();
        var absent = await Live(first).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);
        var explicitFalse = await Live(second).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":false}"), CancellationToken.None);

        Assert.Equal(absent, explicitFalse);
        Assert.DoesNotContain("PauseDebugger", first.Calls);
        Assert.DoesNotContain("RunDebugger", first.Calls);
        Assert.DoesNotContain("PauseDebugger", second.Calls);
        Assert.DoesNotContain("RunDebugger", second.Calls);
    }

    [Fact]
    public async Task AutoPause_False_OnRunningTarget_UnchangedOutput_NoControlCalls()
    {
        var first = RunningSectionsBridge();
        var second = RunningSectionsBridge();
        var absent = await Live(first).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);
        var explicitFalse = await Live(second).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":false}"), CancellationToken.None);

        Assert.Equal(absent, explicitFalse);
        using var doc = JsonDocument.Parse(explicitFalse);
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        Assert.DoesNotContain("PauseDebugger", second.Calls);
        Assert.DoesNotContain("RunDebugger", second.Calls);
    }

    [Fact]
    public async Task AutoPause_AlreadyPaused_IsNoOp_NoControlCalls_NoNote()
    {
        var bridge = PausedSectionsBridge();
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        Assert.False(root.GetProperty("result").TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task AutoPause_Running_PausesReadsResumes_WithNote()
    {
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Script("GetSnapshotState",
                AutoPauseBridge.Ok(RunningState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"))
            .Sticky("PauseDebugger", AutoPauseBridge.Ok("{}"))
            .Sticky("RunDebugger", AutoPauseBridge.Ok("{}"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.Equal("unchanged", result.GetProperty("consistency").GetProperty("status").GetString());
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());
        Assert.False(autoPause.TryGetProperty("note", out _));

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var readAt = bridge.Calls.IndexOf("GetCurrentContext");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && readAt > pauseAt && resumeAt > readAt);
    }

    [Fact]
    public async Task AutoPause_PauseRefused_HonestError_NoRead_NoResume()
    {
        var bridge = RunningSectionsBridge()
            .Sticky("PauseDebugger", AutoPauseBridge.BridgeError("pause_failed", "cannot pause"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_pause_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("GetCurrentContext", bridge.Calls);
        Assert.DoesNotContain("GetCallStack", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("sections", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AutoPause_PauseThrows_HonestError_NoRead()
    {
        var bridge = RunningSectionsBridge().Throws("PauseDebugger");

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_pause_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("GetCurrentContext", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task AutoPause_NeverPauses_BestEffortResume_HonestError()
    {
        // Full 60x50ms auto-pause budget against a target that never pauses:
        // ~3s by design, matching the BulkStep/TraceUntil step budgets.
        var bridge = RunningSectionsBridge()
            .Sticky("PauseDebugger", AutoPauseBridge.Ok("{}"))
            .Sticky("RunDebugger", AutoPauseBridge.Ok("{}"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_running_timeout", root.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("GetCurrentContext", bridge.Calls);
        Assert.DoesNotContain("sections", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AutoPause_ResumeFailure_HonestError_NoSnapshot()
    {
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Script("GetSnapshotState",
                AutoPauseBridge.Ok(RunningState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"))
            .Sticky("PauseDebugger", AutoPauseBridge.Ok("{}"))
            .Sticky("RunDebugger", AutoPauseBridge.BridgeError("run_failed", "cannot resume"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_resume_failed", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("sections", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AutoPause_UnreadableState_NoControlCalls()
    {
        var bridge = PausedSectionsBridge()
            .Sticky("GetSnapshotState", AutoPauseBridge.BridgeError("transport_error", "pipe hiccup"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("ok").GetBoolean());
        Assert.Equal("snapshot_state_unreadable", root.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task AutoPause_ThrowingState_NoControlCalls()
    {
        var bridge = PausedSectionsBridge().Throws("GetSnapshotState");

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        Assert.Equal("snapshot_state_unreadable",
            doc.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public void AutoPause_Schema_AdvertisesFlag_And_ValidatesOverWire()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "GetAnalysisSnapshot");
        var rule = tool["inputSchema"]!["properties"]!["autoPause"]!.AsObject();
        Assert.Equal("boolean", rule["type"]!.GetValue<string>());
        // The false default rides server-side: omitted still validates.
        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{}")));

        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"autoPause\":true}")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"autoPause\":\"yes\"}")));
    }

    // ---- WS3 P0-3 snapshot bundle (includeExpressions/includeRanges) ----
    //
    // Opt-in bundle: Snapshot+ReadMem+Eval in one MCP call, evaluated inside
    // the same paused window (between the base sections and the closing
    // state poll). Absent/empty takes the historical path byte-identically.

    private const string EvalRax =
        "{\"expression\":\"rax\",\"valueHex\":\"0x0000000000000005\"," +
        "\"valueUnsigned\":\"5\",\"valueSigned\":\"5\"}";
    private const string EvalCip =
        "{\"expression\":\"cip\",\"valueHex\":\"0x0000000140001000\"," +
        "\"valueUnsigned\":\"5368717568\",\"valueSigned\":\"5368717568\"}";

    private const string RangesText =
        "[ReadMemAtAddress] ranges=2\\n[0] address=0x140001000 byteCount=4\\n" +
        "AA BB CC DD\\n[1] address=0x140002000 byteCount=4\\n11 22 33 44";

    private static AutoPauseBridge BundleBridge() => new AutoPauseBridge()
        .Sticky("GetServerStatus", PlainStatus)
        .Sticky("GetSnapshotState", AutoPauseBridge.Ok(PausedState))
        .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
        .Sticky("GetCallStack", AutoPauseBridge.Text("stack"))
        .Script("EvaluateExpression",
            AutoPauseBridge.Ok(EvalRax),
            AutoPauseBridge.Ok(EvalCip))
        .Sticky("ReadMemAtAddress",
            "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(RangesText) + "}");

    private const string BundleArgs =
        "{\"includeExpressions\":[\"rax\",\"cip\"]," +
        "\"includeRanges\":[" +
        "{\"address\":\"0x140001000\",\"byteCount\":4}," +
        "{\"address\":\"0x140002000\",\"byteCount\":4}]}";

    [Fact]
    public async Task SnapshotBundle_Absent_HasNoBundleSections_AndNoExtraBridgeCalls()
    {
        var bridge = BundleBridge();
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var result = doc.RootElement.GetProperty("result");
        var sections = result.GetProperty("sections");
        Assert.False(sections.TryGetProperty("expressions", out _));
        Assert.False(sections.TryGetProperty("ranges", out _));
        Assert.DoesNotContain("EvaluateExpression", bridge.Calls);
        Assert.DoesNotContain("ReadMemAtAddress", bridge.Calls);
    }

    [Fact]
    public async Task SnapshotBundle_EmptyArrays_MatchAbsent_ByteIdentical()
    {
        var first = BundleBridge();
        var second = BundleBridge();
        var absent = await Live(first).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);
        var empty = await Live(second).GetAnalysisSnapshotAsync(
            Args("{\"includeExpressions\":[],\"includeRanges\":[]}"), CancellationToken.None);

        Assert.Equal(absent, empty);
        Assert.DoesNotContain("EvaluateExpression", second.Calls);
        Assert.DoesNotContain("ReadMemAtAddress", second.Calls);
    }

    [Fact]
    public async Task SnapshotBundle_HappyPath_EvaluatesInsideSameWindow()
    {
        var bridge = BundleBridge();
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args(BundleArgs), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.Equal("unchanged", result.GetProperty("consistency").GetProperty("status").GetString());
        Assert.False(result.TryGetProperty("autoPause", out _));

        var sections = result.GetProperty("sections");
        var expressions = sections.GetProperty("expressions");
        Assert.Equal(2, expressions.GetArrayLength());
        Assert.Equal(0, expressions[0].GetProperty("index").GetInt32());
        Assert.False(expressions[0].TryGetProperty("method", out _));
        Assert.True(expressions[0].GetProperty("response").GetProperty("ok").GetBoolean());
        Assert.Equal("5", expressions[0].GetProperty("response").GetProperty("result").GetProperty("valueUnsigned").GetString());
        Assert.Equal(1, expressions[1].GetProperty("index").GetInt32());
        Assert.True(expressions[1].GetProperty("response").GetProperty("ok").GetBoolean());

        var ranges = sections.GetProperty("ranges").GetString() ?? "";
        Assert.Contains("[0]", ranges);
        Assert.Contains("[1]", ranges);
        Assert.Contains("0x140001000", ranges);
        Assert.Contains("0x140002000", ranges);

        // No capability probe: 2 state polls + context + stack + 2 evals + 1 ranges read.
        Assert.Equal(7, result.GetProperty("bridgeCalls").GetInt32());

        var readAt = bridge.Calls.IndexOf("GetCurrentContext");
        var evalAt = bridge.Calls.IndexOf("EvaluateExpression");
        var rangesAt = bridge.Calls.IndexOf("ReadMemAtAddress");
        var stateLast = bridge.Calls.LastIndexOf("GetSnapshotState");
        Assert.True(readAt >= 0 && evalAt > readAt && rangesAt > evalAt && stateLast > rangesAt);

        // Ranges forwarded verbatim to the bridge.
        var forwarded = ArgsFor(bridge, "ReadMemAtAddress") ?? "";
        Assert.Contains("0x140001000", forwarded);
        Assert.Contains("0x140002000", forwarded);
    }

    [Fact]
    public async Task SnapshotBundle_PerIndexExpressionError_KeepsSiblings()
    {
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Sticky("GetSnapshotState", AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"))
            .Script("EvaluateExpression",
                AutoPauseBridge.Ok(EvalRax),
                AutoPauseBridge.BridgeError("native_error", "Could not evaluate expression: bogus"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"includeExpressions\":[\"rax\",\"bogus\"]}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var rows = root.GetProperty("result").GetProperty("sections").GetProperty("expressions");
        Assert.Equal(2, rows.GetArrayLength());
        Assert.True(rows[0].GetProperty("response").GetProperty("ok").GetBoolean());
        Assert.False(rows[1].GetProperty("response").GetProperty("ok").GetBoolean());
        // Per-index failure, not a section error.
        if (root.GetProperty("result").TryGetProperty("errors", out var errors))
        foreach (var error in errors.EnumerateArray())
            Assert.NotEqual("expressions", error.GetProperty("section").GetString());
    }

    [Fact]
    public async Task SnapshotBundle_RangesBridgeError_RecordsSectionError()
    {
        var bridge = BundleBridge()
            .Sticky("ReadMemAtAddress",
                AutoPauseBridge.BridgeError("native_error", "Failed to read memory at 0x600000"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args(BundleArgs), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.False(result.GetProperty("sections").TryGetProperty("ranges", out _));
        var rangesError = result.GetProperty("errors").EnumerateArray()
            .Single(e => e.GetProperty("section").GetString() == "ranges");
        Assert.Equal("bridge_error", rangesError.GetProperty("code").GetString());
        // The snapshot itself survives: base sections + expressions present.
        Assert.True(result.GetProperty("sections").TryGetProperty("context", out _));
        Assert.True(result.GetProperty("sections").TryGetProperty("expressions", out _));
    }

    [Fact]
    public async Task SnapshotBundle_InvalidArgs_RecordErrors_WithoutBridgeReads()
    {
        var tooManyExpressions = string.Join(",", Enumerable.Repeat("\"rax\"", 17));
        var tooManyRanges = string.Join(",",
            Enumerable.Range(0, 9).Select(_ => "{\"address\":\"0x140001000\",\"byteCount\":16}"));
        var bridge = BundleBridge();
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"includeExpressions\":[" + tooManyExpressions + "]," +
                "\"includeRanges\":[" + tooManyRanges + "]}"),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var codes = root.GetProperty("result").GetProperty("errors").EnumerateArray()
            .Select(e => e.GetProperty("section").GetString() + "/" + e.GetProperty("code").GetString())
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("expressions/invalid_argument", codes);
        Assert.Contains("ranges/invalid_argument", codes);
        Assert.DoesNotContain("EvaluateExpression", bridge.Calls);
        Assert.DoesNotContain("ReadMemAtAddress", bridge.Calls);
    }

    [Fact]
    public async Task SnapshotBundle_RangesTotalCap_FailsFast_WithoutBridgeCall()
    {
        var bridge = BundleBridge();
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"includeRanges\":[" +
                "{\"address\":\"0x140001000\",\"byteCount\":4096}," +
                "{\"address\":\"0x140002000\",\"byteCount\":4096}," +
                "{\"address\":\"0x140003000\",\"byteCount\":4096}," +
                "{\"address\":\"0x140004000\",\"byteCount\":4096}," +
                "{\"address\":\"0x140005000\",\"byteCount\":4096}]}"),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var rangesError = root.GetProperty("result").GetProperty("errors").EnumerateArray()
            .Single(e => e.GetProperty("section").GetString() == "ranges");
        Assert.Equal("invalid_argument", rangesError.GetProperty("code").GetString());
        Assert.Contains("16384", rangesError.GetProperty("message").GetString());
        Assert.DoesNotContain("ReadMemAtAddress", bridge.Calls);
    }

    [Fact]
    public async Task SnapshotBundle_SmallBudget_SkipsBundleSections_WithTruncated()
    {
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Sticky("GetSnapshotState", AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text(new string('r', 300)))
            .Sticky("GetCallStack", AutoPauseBridge.Text(new string('s', 300)))
            .Sticky("EvaluateExpression", AutoPauseBridge.Ok(EvalRax))
            .Sticky("ReadMemAtAddress",
                "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(RangesText) + "}");

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"maxChars\":200,\"includeExpressions\":[\"rax\"]," +
                "\"includeRanges\":[{\"address\":\"0x140001000\",\"byteCount\":4}]}"),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.GetProperty("truncated").GetBoolean());
        var skipped = result.GetProperty("skipped").EnumerateArray()
            .Select(e => e.GetString()).ToHashSet(StringComparer.Ordinal);
        Assert.Contains("expressions", skipped);
        Assert.Contains("ranges", skipped);
    }

    [Fact]
    public async Task SnapshotBundle_BatchedCapability_FallsBackToIndividual_WithBundle()
    {
        const string batchedStatus =
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
            "\"pid\":123,\"debugging\":true,\"capabilities\":{\"analysisSnapshot\":true}}";
        var bridge = BundleBridge().Sticky("GetServerStatus", batchedStatus);
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args(BundleArgs), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var result = doc.RootElement.GetProperty("result");
        // No roundTripsSaved means the individual path was taken.
        Assert.False(result.TryGetProperty("roundTripsSaved", out _));
        Assert.DoesNotContain("GetAnalysisSnapshot", bridge.Calls);
        Assert.True(result.GetProperty("sections").TryGetProperty("expressions", out _));
        Assert.True(result.GetProperty("sections").TryGetProperty("ranges", out _));
        Assert.Equal("unchanged", result.GetProperty("consistency").GetProperty("status").GetString());
    }

    [Fact]
    public async Task SnapshotBundle_BatchedCapability_StillBatched_WithoutBundle()
    {
        const string batchedStatus =
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
            "\"pid\":123,\"debugging\":true,\"capabilities\":{\"analysisSnapshot\":true}}";
        var batchedSections =
            "{\"sections\":{\"context\":\"batched-registers\",\"callStack\":\"batched-stack\"}," +
            "\"stateBefore\":" + PausedState + ",\"stateAfter\":" + PausedState + "}";
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", batchedStatus)
            .Sticky("GetAnalysisSnapshot", AutoPauseBridge.Ok(batchedSections));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var result = doc.RootElement.GetProperty("result");
        // roundTripsSaved present means the batched path was taken.
        Assert.True(result.TryGetProperty("roundTripsSaved", out _));
        Assert.Contains("GetAnalysisSnapshot", bridge.Calls);
        Assert.Equal("batched-registers",
            result.GetProperty("sections").GetProperty("context").GetString());
        Assert.False(result.GetProperty("sections").TryGetProperty("expressions", out _));
    }

    [Fact]
    public async Task SnapshotBundle_AutoPause_Running_ReadsBundleBeforeResume()
    {
        var bridge = new AutoPauseBridge()
            .Sticky("GetServerStatus", PlainStatus)
            .Script("GetSnapshotState",
                AutoPauseBridge.Ok(RunningState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState),
                AutoPauseBridge.Ok(PausedState))
            .Sticky("GetCurrentContext", AutoPauseBridge.Text("registers"))
            .Sticky("GetCallStack", AutoPauseBridge.Text("stack"))
            .Script("EvaluateExpression", AutoPauseBridge.Ok(EvalRax))
            .Sticky("ReadMemAtAddress",
                "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(RangesText) + "}")
            .Sticky("PauseDebugger", AutoPauseBridge.Ok("{}"))
            .Sticky("RunDebugger", AutoPauseBridge.Ok("{}"));

        var raw = await Live(bridge).GetAnalysisSnapshotAsync(
            Args("{\"autoPause\":true,\"includeExpressions\":[\"rax\"]," +
                "\"includeRanges\":[{\"address\":\"0x140001000\",\"byteCount\":4}]}"),
            CancellationToken.None);

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("ok").GetBoolean());
        var result = root.GetProperty("result");
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());
        Assert.True(result.GetProperty("sections").TryGetProperty("expressions", out _));
        Assert.True(result.GetProperty("sections").TryGetProperty("ranges", out _));

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var evalAt = bridge.Calls.IndexOf("EvaluateExpression");
        var rangesAt = bridge.Calls.IndexOf("ReadMemAtAddress");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && evalAt > pauseAt && rangesAt > evalAt && resumeAt > rangesAt);
    }

    [Fact]
    public async Task SnapshotBundle_Schema_Advertises_And_ValidatesOverWire()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "GetAnalysisSnapshot");
        var properties = tool["inputSchema"]!["properties"]!.AsObject();

        var expressions = properties["includeExpressions"]!.AsObject();
        Assert.Equal("array", expressions["type"]!.GetValue<string>());
        Assert.Equal(1, expressions["minItems"]!.GetValue<int>());
        Assert.Equal(16, expressions["maxItems"]!.GetValue<int>());

        var ranges = properties["includeRanges"]!.AsObject();
        Assert.Equal("array", ranges["type"]!.GetValue<string>());
        Assert.Equal(1, ranges["minItems"]!.GetValue<int>());
        Assert.Equal(8, ranges["maxItems"]!.GetValue<int>());

        var maxTokens = properties["maxTokens"]!.AsObject();
        Assert.Equal(30000, maxTokens["maximum"]!.GetValue<int>());
        // The zero default rides server-side: omitted still validates.
        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{}")));

        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>(
                "{\"includeExpressions\":[\"rax\"]," +
                "\"includeRanges\":[{\"address\":\"0x140001000\",\"byteCount\":16}]}")));
        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"maxTokens\":500}")));
        // Below-floor maxTokens passes the advertised schema but the
        // dispatcher still enforces the executable floor before any backend call.
        await Assert.ThrowsAsync<ModelContextProtocol.McpProtocolException>(() => server.CallToolAsync(
            new ModelContextProtocol.Protocol.CallToolRequestParams
            {
                Name = "GetAnalysisSnapshot",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["maxTokens"] = JsonSerializer.SerializeToElement(-1),
                },
            }, CancellationToken.None));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"maxTokens\":30001}")));
        var tooManyExpressions = string.Join(",", Enumerable.Repeat("\"rax\"", 17));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>(
                "{\"includeExpressions\":[" + tooManyExpressions + "]}")));
        var tooManyRanges = string.Join(",",
            Enumerable.Range(0, 9).Select(_ => "{\"address\":\"0x140001000\",\"byteCount\":16}"));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>(
                "{\"includeRanges\":[" + tooManyRanges + "]}")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>(
                "{\"includeRanges\":[{\"address\":\"0x140001000\",\"byteCount\":4097}]}")));
        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>(
                "{\"includeModules\":true,\"includeModulePaths\":true}")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"includeModulePaths\":\"yes\"}")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"includeRanges\":[{}]}")));
        Assert.NotNull(server.ValidateArguments("GetAnalysisSnapshot",
            JsonSerializer.Deserialize<JsonElement>("{\"includeExpressions\":[]}")));
    }
}

