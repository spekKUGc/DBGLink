using System.Runtime.Versioning;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// w15 hostile surface for BatchAnnotate/AnalyzeFunctions through the real
/// dispatcher/validator: oversized arrays, duplicate keys, control chars,
/// mixed-error batches, empty batches, truncated backend packets and
/// fat-field leak attempts. Validation errors throw before any backend call;
/// backend anomalies return bounded IsError results without throwing.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BatchToolsHostileTests
{
    private static readonly string FatSha = new('a', 64);

    private sealed class CountingGhidra : IGhidraClient
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public Func<string, JsonElement?, string> Handler { get; set; } =
            (_, _) => """{"id":1,"ok":false,"error":{"code":"unavailable","message":"test"}}""";

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(Handler(method, arguments));
        }
    }

    private static (LocalMcpServer Server, RecordingBridge Bridge, CountingGhidra Ghidra) CreateServer()
    {
        var bridge = new RecordingBridge();
        var ghidra = new CountingGhidra();
        var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true },
            bridge,
            ghidra);
        return (server, bridge, ghidra);
    }

    private static JsonElement E(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static CallToolRequestParams Call(string name, string argsJson) => TestWire.Call(name, argsJson);

    private static string BuildOps(int count, int badIndex = -1, string? badOp = null)
    {
        badOp ??= """{"kind":"delete_function","function":"f"}""";
        var operations = Enumerable.Range(0, count).Select(index => index == badIndex
            ? badOp
            : "{\"kind\":\"rename_function\",\"function\":\"f" + index + "\",\"name\":\"n" + index + "\"}");
        return "{\"operations\":[" + string.Join(',', operations) + "]}";
    }

    private static string BuildFunctions(int count) =>
        "{\"functions\":[" + string.Join(',', Enumerable.Range(0, count).Select(index => "\"f" + index + "\"")) + "]}";

    [Fact]
    public async Task OversizedArrays_RejectedBeforeBackend()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E(BuildOps(17))));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", E(BuildFunctions(9))));
        // Boundaries still pass.
        Assert.Null(server.ValidateArguments("BatchAnnotate", E(BuildOps(16))));
        Assert.Null(server.ValidateArguments("AnalyzeFunctions", E(BuildFunctions(8))));

        var batchError = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(Call("BatchAnnotate", BuildOps(17)), CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, batchError.ErrorCode);
        Assert.True(batchError.Message.Length < 2048);

        var analyzeError = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(Call("AnalyzeFunctions", BuildFunctions(9)), CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, analyzeError.ErrorCode);
        Assert.True(analyzeError.Message.Length < 2048);

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task EmptyBatches_RejectedBeforeBackend()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E("""{"operations":[]}""")));
        Assert.NotNull(server.ValidateArguments("AnalyzeFunctions", E("""{"functions":[]}""")));
        Assert.NotNull(server.ValidateArguments("BatchStaticQueries", E("""{"requests":[]}""")));

        foreach (var call in new[]
        {
            Call("BatchAnnotate", """{"operations":[]}"""),
            Call("AnalyzeFunctions", """{"functions":[]}"""),
            Call("BatchStaticQueries", """{"requests":[]}"""),
        })
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(
                () => server.CallToolAsync(call, CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task DuplicateKeys_RejectedBeforeBackend()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        // Nested duplicate inside one operation.
        const string nestedDup =
            """{"operations":[{"kind":"rename_function","kind":"rename_function","function":"f","name":"n"}]}""";
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E(nestedDup)));

        // Top-level duplicate envelope.
        const string topDup =
            """{"operations":[{"kind":"rename_function","function":"f","name":"n"}],"operations":[]}""";
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E(topDup)));
        Assert.NotNull(server.ValidateArguments(
            "AnalyzeFunctions", E("""{"functions":["a"],"functions":["b"]}""")));

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(Call("BatchAnnotate", nestedDup), CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task ControlChars_InSelectors_RejectedBeforeBackend()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        // JSON escapes decode to NUL / SOH / DEL inside selectors: never valid text.
        var hostile = new[]
        {
            "{\"operations\":[{\"kind\":\"rename_function\",\"function\":\"a\\u0000b\",\"name\":\"n\"}]}",
            "{\"operations\":[{\"kind\":\"rename_function\",\"function\":\"x\\u0001y\",\"name\":\"n\"}]}",
            "{\"functions\":[\"a\\u0000b\"]}",
            "{\"functions\":[\" \\u007F \"]}",
            "{\"operations\":[{\"kind\":\"set_function_comment\",\"function\":\"f\",\"comment\":\"a\\u0000b\"}]}",
        };
        foreach (var json in hostile)
        {
            var tool = json.Contains("operations") ? "BatchAnnotate" : "AnalyzeFunctions";
            Assert.NotNull(server.ValidateArguments(tool, E(json)));
            var error = await Assert.ThrowsAsync<McpProtocolException>(
                () => server.CallToolAsync(Call(tool, json), CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }

        // Boundary: LF is allowed only in multiline comments, never in selectors.
        Assert.Null(server.ValidateArguments("BatchAnnotate",
            E("{\"operations\":[{\"kind\":\"set_function_comment\",\"function\":\"f\",\"comment\":\"a\\nb\"}]}")));
        Assert.NotNull(server.ValidateArguments("BatchAnnotate",
            E("{\"operations\":[{\"kind\":\"rename_function\",\"function\":\"a\\nb\",\"name\":\"n\"}]}")));

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task MixedErrors_FullBatchRejectedBeforeAnyBackendCall()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        // 16 ops where the last one has an unknown kind: whole batch rejected.
        var badKind = BuildOps(16, badIndex: 15);
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E(badKind)));
        var kindError = await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(Call("BatchAnnotate", badKind), CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, kindError.ErrorCode);

        // 16 ops where one carries an undeclared property: closed envelope.
        var badExtra = BuildOps(16, badIndex: 7,
            badOp: """{"kind":"rename_function","function":"f","name":"n","extra":1}""");
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", E(badExtra)));
        await Assert.ThrowsAsync<McpProtocolException>(
            () => server.CallToolAsync(Call("BatchAnnotate", badExtra), CancellationToken.None));

        // Static batch mixes a valid read with a debugger op: rejected up front,
        // the valid prefix must not have executed.
        var mixed = await server.CallToolAsync(Call("BatchStaticQueries",
            """{"requests":[{"method":"AnalyzeFunctions","arguments":{"functions":["main"]}},{"method":"WriteMemory","arguments":{"address":"0x140001000","hexBytes":"90"}}]}"""),
            CancellationToken.None);
        Assert.True(mixed.IsError);
        var mixedText = Assert.IsType<TextContentBlock>(Assert.Single(mixed.Content)).Text;
        Assert.Contains("invalid_batch", mixedText);
        Assert.True(mixedText.Length < 2048);

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(0, ghidra.Calls);
    }

    [Fact]
    public async Task TruncatedAndGarbageBackend_BoundedErrorWithoutThrow()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;
        const string validOp = """{"operations":[{"kind":"rename_function","function":"f","name":"n"}]}""";

        ghidra.Handler = (_, _) => """{"id":1,"ok":true,"result":{"applied":1,""";
        var truncated = await server.CallToolAsync(Call("BatchAnnotate", validOp), CancellationToken.None);
        Assert.True(truncated.IsError);
        var truncatedText = Assert.IsType<TextContentBlock>(Assert.Single(truncated.Content)).Text;
        Assert.True(truncatedText.Length < 2048);

        ghidra.Handler = (_, _) => "not json at all {{{";
        var garbage = await server.CallToolAsync(
            Call("AnalyzeFunctions", """{"functions":["main"]}"""), CancellationToken.None);
        Assert.True(garbage.IsError);
        var garbageText = Assert.IsType<TextContentBlock>(Assert.Single(garbage.Content)).Text;
        Assert.NotEmpty(garbageText);
        Assert.True(garbageText.Length < 2048);

        // A huge non-JSON blob must be capped by the dispatcher error budget.
        ghidra.Handler = (_, _) => new string('x', 100_000);
        var huge = await server.CallToolAsync(Call("BatchAnnotate", validOp), CancellationToken.None);
        Assert.True(huge.IsError);
        var hugeText = Assert.IsType<TextContentBlock>(Assert.Single(huge.Content)).Text;
        Assert.True(hugeText.Length <= 2048 + "...[truncated]".Length);

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(3, ghidra.Calls);
    }

    [Fact]
    public async Task FatFields_StrippedAndBounded()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        var longComment = new string('c', 200);
        var longMessage = new string('m', 400);
        ghidra.Handler = (id, _) => JsonSerializer.Serialize(new
        {
            id,
            ok = true,
            result = new
            {
                success = true,
                applied = 1,
                failed = 1,
                results = new object[]
                {
                    new
                    {
                        index = 0, kind = "rename_function", function = "0x140001000", ok = true,
                        committed = true, journaled = true, name = "fixture_caller",
                        previousName = "FixtureCaller", module = new { sha256 = FatSha },
                    },
                    new
                    {
                        index = 1, kind = "set_variable_type", function = "0x140001080", ok = false,
                        committed = false, journaled = false, code = "mutation_conflict",
                        message = longMessage, comment = longComment, previousComment = "old",
                    },
                }
            }
        });

        var result = await server.CallToolAsync(Call("BatchAnnotate",
            """{"operations":[{"kind":"rename_function","function":"f","name":"n"},{"kind":"set_variable_type","function":"g","variable":"v","type":"int"}]}"""),
            CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

        Assert.DoesNotContain("previousName", text);
        Assert.DoesNotContain("previousComment", text);
        Assert.DoesNotContain(FatSha, text);
        Assert.DoesNotContain(longComment, text);
        Assert.DoesNotContain(longMessage, text);

        using var ack = JsonDocument.Parse(text);
        var root = ack.RootElement;
        Assert.Equal("BatchAnnotate", root.GetProperty("operation").GetString());
        var rows = root.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.True(rows[1].GetProperty("message").GetString()!.Length <= 160);
        Assert.True(text.Length < 4096);

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(1, ghidra.Calls);
    }

    [Fact]
    public async Task BackendMixedFailures_SixteenRowsStayIndexedAndBounded()
    {
        var (server, bridge, ghidra) = CreateServer();
        using var _ = server;

        ghidra.Handler = (id, _) =>
        {
            var rows = Enumerable.Range(0, 16).Select(index => index % 2 == 0
                ? (object)new
                {
                    index, kind = "rename_function", function = "f" + index, ok = true,
                    committed = true, journaled = true, name = "n" + index,
                    previousName = "OLD" + index, module = new { sha256 = FatSha },
                }
                : (object)new
                {
                    index, kind = "set_variable_type", function = "f" + index, ok = false,
                    committed = false, journaled = false, code = "mutation_conflict",
                    message = new string('m', 400),
                });
            return JsonSerializer.Serialize(new
            {
                id, ok = true,
                result = new { success = true, applied = 8, failed = 8, results = rows }
            });
        };

        var result = await server.CallToolAsync(
            Call("BatchAnnotate", BuildOps(16)), CancellationToken.None);
        Assert.False(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

        Assert.DoesNotContain("previousName", text);
        Assert.DoesNotContain(FatSha, text);
        Assert.DoesNotContain(new string('m', 400), text);

        using var ack = JsonDocument.Parse(text);
        var rows = ack.RootElement.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(16, rows.Length);
        Assert.Equal(Enumerable.Range(0, 16), rows.Select(row => row.GetProperty("index").GetInt32()));
        foreach (var row in rows)
        {
            if (row.TryGetProperty("message", out var message))
                Assert.True(message.GetString()!.Length <= 160);
        }

        Assert.Equal(0, bridge.RequestCount);
        Assert.Equal(1, ghidra.Calls);
    }
}

/// <summary>
/// WS4 debugger-half pins (round-trip plan P1-6): BatchDebuggerOperations
/// admits EvaluateExpressions (local fan-out), SwitchThread,
/// ListLiveFunctions (translated to GetModuleFunctions), SampleCallStacks and
/// GetAnalysisSnapshot (local snapshot core). One MCP call carries
/// pause+N-reads+resume work that used to cost 3-6 calls. Family mismatch
/// stays a hard error with zero backend calls; per-item autoPause stays
/// rejected (the batch-level flag is the only pause scope).
/// </summary>
public sealed class DebuggerBatchAdmissionTests
{
    private const string PausedState =
        "{\"debugging\":true,\"running\":false,\"stableRead\":true}";
    private const string RunningState =
        "{\"debugging\":true,\"running\":true,\"stableRead\":true}";

    // Status without the batched capability, so GetAnalysisSnapshot takes the
    // individual section path (same shape as SnapshotAutoPauseTests).
    private const string PlainStatus =
        "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
        "\"pid\":123,\"debugging\":true}";

    private sealed class DebuggerScriptBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];

        public DebuggerScriptBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public DebuggerScriptBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
            return this;
        }

        public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

        public static string Text(string text) =>
            "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(text) + "}";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (_scripts.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            if (_sticky.TryGetValue(method, out var response))
                return Task.FromResult(response);
            return Task.FromResult(Ok("{}"));
        }
    }

    private static LocalMcpServer CreateDebuggerServer(DebuggerScriptBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);

    private static CallToolRequestParams Call(string name, string argsJson) => TestWire.Call(name, argsJson);

    private static string TextOf(CallToolResult result) => TestWire.RawText(result);

    private static DebuggerScriptBridge PausedSectionsBridge() => new DebuggerScriptBridge()
        .Sticky("GetSnapshotState", DebuggerScriptBridge.Ok(PausedState))
        .Sticky("GetServerStatus", PlainStatus)
        .Sticky("GetCurrentContext", DebuggerScriptBridge.Text("registers"))
        .Sticky("GetCallStack", DebuggerScriptBridge.Text("stack"));

    [Fact]
    public async Task Admits_FanOut_Translated_And_Snapshot_Rows_In_One_Call()
    {
        // Pause+snapshot+reads+exprs used to cost 3-6 MCP calls; one batch now
        // carries all of it (already-paused target here, so no pause/resume).
        var bridge = PausedSectionsBridge()
            .Sticky("EvaluateExpression", DebuggerScriptBridge.Ok("{\"value\":1}"))
            .Sticky("ListThreads", DebuggerScriptBridge.Ok("{\"threads\":[]}"))
            .Sticky("SwitchThread", DebuggerScriptBridge.Ok("{}"))
            .Sticky("GetModuleFunctions", DebuggerScriptBridge.Ok("{\"functions\":[]}"))
            .Sticky("SampleCallStacks", DebuggerScriptBridge.Ok("{\"frames\":[]}"))
            .Sticky("ReadMemAtAddress", DebuggerScriptBridge.Ok("{\"bytes\":\"90\"}"));
        using var server = CreateDebuggerServer(bridge);

        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            """{"requests":[{"method":"EvaluateExpressions","arguments":{"expressions":["cip","rax"]}},{"method":"ListThreads","arguments":{}},{"method":"SwitchThread","arguments":{"threadId":1}},{"method":"ListLiveFunctions","arguments":{"module":"game.exe"}},{"method":"SampleCallStacks","arguments":{"maxSamples":2}},{"method":"GetAnalysisSnapshot","arguments":{}},{"method":"ReadMemAtAddress","arguments":{"address":"cip"}}]}"""),
            CancellationToken.None);

        Assert.False(result.IsError);
        // Server wire shape: the dispatcher unwraps the ok:true envelope, so
        // the text is the batch result payload itself (no ok/result wrapper).
        using var doc = JsonDocument.Parse(TextOf(result));
        var body = doc.RootElement;
        Assert.False(body.TryGetProperty("partial", out var bodyPartial) && bodyPartial.GetBoolean());
        var rows = body.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(7, rows.Length);
        foreach (var row in rows)
            Assert.True(row.GetProperty("response").GetProperty("ok").GetBoolean());

        // Local fan-out never hits the wire under its MCP names: the bridge
        // sees the singular EvaluateExpression and the snapshot sections.
        Assert.DoesNotContain("EvaluateExpressions", bridge.Calls);
        Assert.DoesNotContain("ListLiveFunctions", bridge.Calls);
        Assert.Contains("EvaluateExpression", bridge.Calls);
        Assert.Equal(2, bridge.Calls.Count(c => c == "EvaluateExpression"));
        Assert.Contains("GetModuleFunctions", bridge.Calls);
        Assert.Contains("SwitchThread", bridge.Calls);
        Assert.Contains("SampleCallStacks", bridge.Calls);
        Assert.Contains("GetSnapshotState", bridge.Calls);
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task BatchAutoPause_WithLocalRows_PausesOnce_For_The_Whole_Batch()
    {
        var bridge = new DebuggerScriptBridge()
            .Script("GetSnapshotState", DebuggerScriptBridge.Ok(RunningState))
            .Sticky("GetSnapshotState", DebuggerScriptBridge.Ok(PausedState))
            .Sticky("PauseDebugger", DebuggerScriptBridge.Ok("{}"))
            .Sticky("RunDebugger", DebuggerScriptBridge.Ok("{}"))
            .Sticky("EvaluateExpression", DebuggerScriptBridge.Ok("{\"value\":1}"))
            .Sticky("ListThreads", DebuggerScriptBridge.Ok("{\"threads\":[]}"))
            .Sticky("GetServerStatus", PlainStatus)
            .Sticky("GetCurrentContext", DebuggerScriptBridge.Text("registers"))
            .Sticky("GetCallStack", DebuggerScriptBridge.Text("stack"));
        using var server = CreateDebuggerServer(bridge);

        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            """{"requests":[{"method":"EvaluateExpressions","arguments":{"expressions":["cip"]}},{"method":"ListThreads","arguments":{}},{"method":"GetAnalysisSnapshot","arguments":{}}],"autoPause":true}"""),
            CancellationToken.None);

        Assert.False(result.IsError);
        using var doc = JsonDocument.Parse(TextOf(result));
        var body = doc.RootElement;
        Assert.False(body.TryGetProperty("partial", out var bodyPartial) && bodyPartial.GetBoolean());
        Assert.Equal(3, body.GetProperty("results").EnumerateArray().Count());
        var note = body.GetProperty("autoPause");
        Assert.True(note.GetProperty("resumed").GetBoolean());

        // One pause and one resume for the whole batch, never per item: the
        // local snapshot row must not nest its own pause inside the batch.
        Assert.Equal(1, bridge.Calls.Count(c => c == "PauseDebugger"));
        Assert.Equal(1, bridge.Calls.Count(c => c == "RunDebugger"));
        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt < bridge.Calls.IndexOf("EvaluateExpression"));
        Assert.True(pauseAt < bridge.Calls.IndexOf("ListThreads"));
        Assert.True(pauseAt < bridge.Calls.IndexOf("GetCurrentContext"));
        Assert.True(resumeAt > bridge.Calls.IndexOf("EvaluateExpression"));
        Assert.True(resumeAt > bridge.Calls.IndexOf("GetCallStack"));
    }

    [Fact]
    public async Task FamilyMismatch_StaysHardError_WithZeroCalls()
    {
        var bridge = PausedSectionsBridge();
        using var server = CreateDebuggerServer(bridge);

        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            """{"requests":[{"method":"ReadMemAtAddress","arguments":{"address":"cip"}},{"method":"InspectFunction","arguments":{"function":"main"}}]}"""),
            CancellationToken.None);

        Assert.True(result.IsError);
        var text = TextOf(result);
        Assert.Contains("invalid_batch", text, StringComparison.Ordinal);
        Assert.Contains("Request #1", text, StringComparison.Ordinal);
        Assert.Empty(bridge.Calls);
    }

    [Fact]
    public async Task SingularEvaluateExpression_StillRedirected_WithZeroCalls()
    {
        var bridge = PausedSectionsBridge();
        using var server = CreateDebuggerServer(bridge);

        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            """{"requests":[{"method":"EvaluateExpression","arguments":{"expression":"cip"}}]}"""),
            CancellationToken.None);

        Assert.True(result.IsError);
        Assert.Contains("EvaluateExpressions", TextOf(result), StringComparison.Ordinal);
        Assert.Empty(bridge.Calls);
    }

    [Fact]
    public async Task PerItemAutoPause_Rejected_Without_Any_Bridge_Read()
    {
        // Every tool that gained a top-level autoPause flag must reject it
        // per row (batch-level flag is the only pause scope); validation-level
        // rejections (EvaluateExpressions) and sender-level rejections (the
        // rest) both surface per row with zero op calls.
        var bridge = PausedSectionsBridge()
            .Sticky("ReadMemAtAddress", DebuggerScriptBridge.Ok("{\"bytes\":\"90\"}"))
            .Sticky("GetBacktrace", DebuggerScriptBridge.Ok("{\"frames\":[]}"))
            .Sticky("ListThreads", DebuggerScriptBridge.Ok("{\"threads\":[]}"))
            .Sticky("SampleCallStacks", DebuggerScriptBridge.Ok("{\"frames\":[]}"))
            .Sticky("SetBreakpoint", DebuggerScriptBridge.Ok("{}"))
            .Sticky("ClearBreakpoint", DebuggerScriptBridge.Ok("{}"));
        using var server = CreateDebuggerServer(bridge);

        var result = await server.CallToolAsync(Call("BatchDebuggerOperations",
            """{"requests":[{"method":"ReadMemAtAddress","arguments":{"address":"cip","autoPause":true}},{"method":"GetBacktrace","arguments":{"autoPause":true}},{"method":"ListThreads","arguments":{"autoPause":true}},{"method":"SampleCallStacks","arguments":{"autoPause":true}},{"method":"SetBreakpoint","arguments":{"address":"cip","autoPause":true}},{"method":"ClearBreakpoint","arguments":{"address":"cip","autoPause":true}},{"method":"EvaluateExpressions","arguments":{"expressions":["cip"],"autoPause":true}},{"method":"GetAnalysisSnapshot","arguments":{"autoPause":true}}]}"""),
            CancellationToken.None);

        Assert.False(result.IsError);
        using var doc = JsonDocument.Parse(TextOf(result));
        var body = doc.RootElement;
        Assert.True(body.TryGetProperty("partial", out var bodyPartialHit) && bodyPartialHit.GetBoolean());
        var rows = body.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(8, rows.Length);
        foreach (var row in rows)
        {
            var response = row.GetProperty("response");
            Assert.False(response.GetProperty("ok").GetBoolean());
            Assert.Contains("autoPause", response.GetRawText(), StringComparison.Ordinal);
        }

        // No op and no pause/resume call ran: rejection precedes every backend.
        foreach (var op in new[] { "ReadMemAtAddress", "GetBacktrace", "ListThreads",
            "SampleCallStacks", "SetBreakpoint", "ClearBreakpoint", "EvaluateExpression",
            "GetCurrentContext", "PauseDebugger", "RunDebugger" })
            Assert.DoesNotContain(op, bridge.Calls);
    }
}


