using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

public sealed class ToolExecutionTests
{
    private const string CurrentProtocol = "2025-06-18";

    [Fact]
    public void Snapshot_text_truncation_does_not_split_a_surrogate_pair()
    {
        var truncated = false;

        var result = ToolSupport.LimitSnapshotText("A😀" + new string('x', 20), 17, ref truncated);

        Assert.True(truncated);
        Assert.Equal("A\n...[truncated]", result);
        Assert.DoesNotContain(result, char.IsHighSurrogate);
        Assert.DoesNotContain(result, char.IsLowSurrogate);
    }

    [Fact]
    public void Snapshot_text_truncation_respects_a_short_suffix_budget()
    {
        var truncated = false;

        var result = ToolSupport.LimitSnapshotText("payload", 4, ref truncated);

        Assert.True(truncated);
        Assert.Equal("\n...", result);
        Assert.Equal(4, result.Length);
    }

    [Fact]
    public async Task Module_hash_is_bounded_and_matches_sha256()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-mapping-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "module.bin");
        Directory.CreateDirectory(directory);
        try
        {
            var content = System.Text.Encoding.UTF8.GetBytes("module-content");
            await File.WriteAllBytesAsync(path, content);

            var hash = await AddressMapping.ComputeBoundedModuleHashAsync(path, CancellationToken.None);

            Assert.Equal(Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), hash);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Snapshot_text_exact_fit_is_returned_unchanged()
    {
        // Boundary pin: text.Length <= budget is a passthrough (truncated
        // stays false). Guards against an off-by-one that would append a
        // truncation suffix to payloads that already fit.
        var truncated = false;

        var result = ToolSupport.LimitSnapshotText("12345", 5, ref truncated);

        Assert.False(truncated);
        Assert.Equal("12345", result);
    }

    [Fact]
    public void Snapshot_text_truncation_does_not_split_before_a_low_surrogate()
    {
        // Mirror of the high-surrogate pin: when the cut lands immediately
        // before a low surrogate, the prefix shrinks so no lone surrogate
        // leaks into the returned string.
        var truncated = false;

        var result = ToolSupport.LimitSnapshotText("abc\uDE00" + new string('x', 20), 17, ref truncated);

        Assert.True(truncated);
        Assert.Equal("ab\n...[truncated]", result);
        Assert.DoesNotContain(result, char.IsLowSurrogate);
    }

    [Fact]
    public async Task Bridge_error_with_string_code_and_message_is_surfaced_verbatim()
    {
        // Well-formed ok:false envelope: "[code] message" reaches the caller
        // as a tool error (isError), not a protocol error, with the backend
        // code preserved for triage.
        var server = CreateServer(new FixedResponseBridge(
            "{\"ok\":false,\"error\":{\"code\":\"step_failed\",\"message\":\"boom\"}}"));
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"byteCount\":1}}}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        Assert.True(body.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Contains("[step_failed] boom", body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task Malformed_bridge_error_is_returned_as_a_safe_tool_error()
    {
        var server = CreateServer(new FixedResponseBridge(
            "{\"ok\":false,\"error\":{\"code\":123,\"message\":{}}}"));
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"byteCount\":1}}}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        Assert.True(body.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Contains("[bridge_error] bridge request failed", body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task Backend_exception_is_returned_as_a_tool_error_result()
    {
        var server = CreateServer(new ThrowingBridge());
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"byteCount\":1}}}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        // MCP tool execution failures are reported in the result body
        // (isError=true), not as a JSON-RPC protocol error.
        Assert.True(body.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Contains("backend component failed", body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task Bridge_response_without_boolean_ok_is_marked_as_an_error()
    {
        var server = CreateServer(new FixedResponseBridge("{\"result\":{\"value\":1}}"));
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"byteCount\":1}}}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        Assert.True(body.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal("{\"value\":1}", body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task Bridge_success_without_a_payload_is_marked_as_an_error()
    {
        var server = CreateServer(new FixedResponseBridge("{\"ok\":true}"));
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadMemAtAddress\",\"arguments\":{\"address\":\"0x1000\",\"byteCount\":1}}}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        Assert.True(body.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        // No text/result/error member to unwrap: the raw bridge payload is
        // returned verbatim so the failure is diagnosable, not swallowed.
        Assert.Contains("ok", body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task Tools_list_keeps_distinct_high_level_views_and_compact_function_defaults()
    {
        var server = CreateServer();
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();
        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        var tools = body.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray().ToArray();
        var names = tools.Select(tool => tool.GetProperty("name").GetString()).ToArray();
        Assert.Contains("GetAnalysisSnapshot", names);
        Assert.Contains("GetInvestigationBrief", names);
        var snapshotProperties = tools.Single(tool => tool.GetProperty("name").GetString() == "GetAnalysisSnapshot")
            .GetProperty("inputSchema").GetProperty("properties");
        // Diet budgets ride server-side; the advertised caps stay.
        Assert.Equal(64, snapshotProperties.GetProperty("maxFrames").GetProperty("maximum").GetInt32());
        var briefProperties = tools.Single(tool => tool.GetProperty("name").GetString() == "GetInvestigationBrief")
            .GetProperty("inputSchema").GetProperty("properties");
        Assert.Equal(60000, briefProperties.GetProperty("maxChars").GetProperty("maximum").GetInt32());
        Assert.Equal(64, briefProperties.GetProperty("maxItems").GetProperty("maximum").GetInt32());
        Assert.False(briefProperties.TryGetProperty("examples", out _));
        var moduleProperties = tools.Single(tool => tool.GetProperty("name").GetString() == "DecompileModule")
            .GetProperty("inputSchema").GetProperty("properties");
        Assert.Equal(128, moduleProperties.GetProperty("maxFunctions").GetProperty("maximum").GetInt32());
        Assert.False(moduleProperties.TryGetProperty("function", out _));
        Assert.Equal(JsonValueKind.String, moduleProperties.GetProperty("start").GetProperty("type").ValueKind);
        var properties = tools.Single(tool => tool.GetProperty("name").GetString() == "InspectFunction")
            .GetProperty("inputSchema").GetProperty("properties");
        Assert.Equal(120000, properties.GetProperty("maxChars").GetProperty("maximum").GetInt32());
        Assert.Equal(512, properties.GetProperty("maxItems").GetProperty("maximum").GetInt32());
        var functionProperties = tools.Single(tool => tool.GetProperty("name").GetString() == "ListFunctions")
            .GetProperty("inputSchema").GetProperty("properties");
        Assert.Equal("boolean", functionProperties.GetProperty("includeCounts").GetProperty("type").GetString());
        var xrefProperties = tools.Single(tool => tool.GetProperty("name").GetString() == "Xrefs")
            .GetProperty("inputSchema").GetProperty("properties");
        Assert.Equal(128, xrefProperties.GetProperty("maxItems").GetProperty("maximum").GetInt32());
        Assert.Equal(128, xrefProperties.GetProperty("maxItemsTo").GetProperty("maximum").GetInt32());
        Assert.Equal(128, xrefProperties.GetProperty("maxItemsFrom").GetProperty("maximum").GetInt32());
        Assert.Equal("boolean", properties.GetProperty("includeSymbols").GetProperty("type").GetString());
        Assert.False(tools.Single(tool => tool.GetProperty("name").GetString() == "InspectFunction")
            .GetProperty("inputSchema").TryGetProperty("examples", out _));
        Assert.False(tools.Single(tool => tool.GetProperty("name").GetString() == "DecompileModule")
            .GetProperty("inputSchema").TryGetProperty("examples", out _));
    }

    [Fact]
    public void DecompileModule_rejects_single_function_selector()
    {
        using var arguments = JsonDocument.Parse("{\"function\":\"0x1000\"}");

        var error = CreateServer().ValidateArguments("DecompileModule", arguments.RootElement);

        Assert.Contains("Unsupported argument: function", error);
    }

    [Fact]
    public async Task Tools_list_exposes_checkpoint_tool()
    {
        var server = CreateServer();
        var response = await server.ExecuteTestRequestAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
            CancellationToken.None,
            CurrentProtocol);
        server.Stop();

        using var body = JsonDocument.Parse(Assert.IsType<string>(response));
        var tools = body.RootElement.GetProperty("result").GetProperty("tools");
        var checkpoint = tools.EnumerateArray().Single(tool => tool.GetProperty("name").GetString() == "Checkpoint");
        var required = checkpoint.GetProperty("inputSchema").GetProperty("required").EnumerateArray().Select(value => value.GetString());
        Assert.Contains("action", required);
        var properties = checkpoint.GetProperty("inputSchema").GetProperty("properties");
        foreach (var property in new[] { "action", "sha256", "findings", "hypotheses", "verified", "nextStep", "liveValues", "fields" })
            Assert.True(properties.TryGetProperty(property, out _), $"Checkpoint is missing {property}.");
    }

    [Fact]
    public async Task Checkpoint_survives_a_new_server_instance()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-checkpoint-" + Guid.NewGuid().ToString("N"));
        var checkpointPath = Path.Combine(directory, "latest.json");
        const string sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        Directory.CreateDirectory(directory);
        try
        {
            var firstServer = CreateServer(checkpointPath: checkpointPath);
            var saved = await firstServer.ExecuteTestRequestAsync(
                CreateCheckpointBody(1, "analysis-session", sha256),
                CancellationToken.None,
                CurrentProtocol);
            firstServer.Stop();

            using (var saveResponse = JsonDocument.Parse(Assert.IsType<string>(saved)))
            {
                var saveText = saveResponse.RootElement
                    .GetProperty("result")
                    .GetProperty("content")[0]
                    .GetProperty("text")
                    .GetString();
                using var saveResult = JsonDocument.Parse(Assert.IsType<string>(saveText));
                Assert.True(saveResult.RootElement.GetProperty("saved").GetBoolean());
            }

            var secondServer = CreateServer(checkpointPath: checkpointPath);
            var loaded = await secondServer.ExecuteTestRequestAsync(
                GetLastCheckpointBody(2, sha256),
                CancellationToken.None,
                CurrentProtocol);
            secondServer.Stop();

            using var response = JsonDocument.Parse(Assert.IsType<string>(loaded));
            var text = response.RootElement
                .GetProperty("result")
                .GetProperty("content")[0]
                .GetProperty("text")
                .GetString();
            using var checkpoint = JsonDocument.Parse(Assert.IsType<string>(text));
            var result = checkpoint.RootElement;
            Assert.True(result.GetProperty("found").GetBoolean());
            Assert.Equal("analysis-session", result.GetProperty("checkpoint").GetProperty("analysisId").GetString());
            Assert.Equal(sha256, result.GetProperty("checkpoint").GetProperty("sha256").GetString());
            Assert.Contains("objective", result.GetProperty("checkpoint").GetProperty("findings").GetString());
            Assert.Contains("next command", result.GetProperty("checkpoint").GetProperty("nextStep").GetString());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Ghidra_open_operations_are_bounded()
    {
        var control = new BlockingGhidraControl();
        var server = CreateServer(ghidraControl: control);

        for (var id = 1; id <= 8; id++)
        {
            var accepted = await server.ExecuteTestRequestAsync(OpenGhidraBody(id), CancellationToken.None, CurrentProtocol);
            Assert.Contains("pending", accepted);
            if (id == 1)
            {
                using var acceptedBody = JsonDocument.Parse(Assert.IsType<string>(accepted));
                var operationText = acceptedBody.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString();
                using var pending = JsonDocument.Parse(Assert.IsType<string>(operationText));
                Assert.Equal(1_000, pending.RootElement.GetProperty("retryAfterMs").GetInt32());
            }
        }

        var rejected = await server.ExecuteTestRequestAsync(OpenGhidraBody(9), CancellationToken.None, CurrentProtocol);
        server.Stop();
        Assert.Contains("ghidra_operation_limit", rejected);
    }

    [Fact]
    public async Task Ghidra_status_rejects_an_unusable_session_descriptor()
    {
        var missingEndpoint = Path.Combine(
            Path.GetTempPath(),
            "dbglink-missing-endpoint-" + Guid.NewGuid().ToString("N"));
        var control = new CompletedGhidraControl($"{{\"id\":1,\"ok\":true,\"result\":{{\"analysisId\":\"analysis-test\",\"nativePipeName\":\"DbgLink.Control.42\",\"ghidraEndpointDirectory\":{JsonSerializer.Serialize(missingEndpoint)}}}}}");
        var server = CreateServer(ghidraControl: control);
        try
        {
            var accepted = await server.ExecuteTestRequestAsync(OpenGhidraBody(1), CancellationToken.None, CurrentProtocol);
            using var acceptedBody = JsonDocument.Parse(Assert.IsType<string>(accepted));
            var operationId = acceptedBody.RootElement
                .GetProperty("result")
                .GetProperty("content")[0]
                .GetProperty("text")
                .GetString();
            Assert.NotNull(operationId);
            using var pending = JsonDocument.Parse(operationId!);
            var id = pending.RootElement.GetProperty("operationId").GetString();

            var response = await server.ExecuteTestRequestAsync(
                GetGhidraOpenStatusBody(2, id!),
                CancellationToken.None,
                CurrentProtocol);

            using var body = JsonDocument.Parse(Assert.IsType<string>(response));
            var result = body.RootElement.GetProperty("result");
            Assert.True(result.GetProperty("isError").GetBoolean());
            Assert.Contains("analysis_session_unavailable", result.GetProperty("content")[0].GetProperty("text").GetString());
        }
        finally
        {
            server.Stop();
        }
    }

    [Fact]
    public async Task Ghidra_status_retains_a_failed_open_operation_until_collected()
    {
        var server = CreateServer(ghidraControl: new FailingGhidraControl());
        try
        {
            var accepted = await server.ExecuteTestRequestAsync(OpenGhidraBody(1), CancellationToken.None, CurrentProtocol);
            using var acceptedBody = JsonDocument.Parse(Assert.IsType<string>(accepted));
            var operationText = acceptedBody.RootElement
                .GetProperty("result")
                .GetProperty("content")[0]
                .GetProperty("text")
                .GetString();
            using var pending = JsonDocument.Parse(Assert.IsType<string>(operationText));
            var operationId = pending.RootElement.GetProperty("operationId").GetString();

            var response = await server.ExecuteTestRequestAsync(
                GetGhidraOpenStatusBody(2, operationId!),
                CancellationToken.None,
                CurrentProtocol);

            using var body = JsonDocument.Parse(Assert.IsType<string>(response));
            var result = body.RootElement.GetProperty("result");
            Assert.True(result.GetProperty("isError").GetBoolean());
            Assert.Contains("ghidra_open_failed", result.GetProperty("content")[0].GetProperty("text").GetString());
        }
        finally
        {
            server.Stop();
        }
    }

    private static LocalMcpServer CreateServer(
        IBridgeClient? bridge = null,
        IGhidraControlClient? ghidraControl = null,
        string? checkpointPath = null) => new(
            new ServerConfig
            {
                Port = ServerConfig.DefaultPort,
                MaxConcurrentRequests = 16,
                MaxQueuedOperations = 32,
                DefaultToolTimeoutMs = 5_000
            },
            bridge ?? new RecordingBridge(),
            new NullGhidra(),
            ghidraControl,
            checkpointPath);

    private static string InitializeBody(string protocol) =>
        $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{protocol}\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"tests\",\"version\":\"1\"}}}}}}";

    private static string OpenGhidraBody(int id) =>
        $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"OpenGhidraFile\",\"arguments\":{{\"path\":\"C:\\\\target{id}.dll\",\"waitMs\":0}}}}}}";

    private static string CreateCheckpointBody(int id, string analysisId, string sha256)
    {
        var arguments = JsonSerializer.Serialize(new
        {
            action = "create",
            analysisId,
            title = "Resume reverse engineering",
            sha256,
            findings = "The objective is to identify the suspicious call path.\nThe current finding is a string reference near the entry point.",
            hypotheses = "The suspicious call may be reached through the parser.",
            verified = "The entry point was checked against the target module.",
            nextStep = "Run the next command and verify the caller.",
            context = "Target: C:\\target.dll"
        });
        return $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"Checkpoint\",\"arguments\":{arguments}}}}}";
    }

    private static string GetLastCheckpointBody(int id, string sha256) =>
        $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"Checkpoint\",\"arguments\":{{\"action\":\"restore\",\"sha256\":\"{sha256}\"}}}}}}";

    private static string GetGhidraOpenStatusBody(int id, string operationId) =>
        $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"GetGhidraOpenStatus\",\"arguments\":{{\"operationId\":{JsonSerializer.Serialize(operationId)}}}}}}}";

    [Fact]
    public async Task OpenDebugTarget_RepeatRejectedInstantly()
    {
        var live = new LiveAnalysisTools(new AnalysisContext(new RecordingBridge(), new NullGhidra()));
        var args = JsonSerializer.SerializeToElement(new { path = "C:\\nope\\missing-target.exe" });
        var first = JsonNode.Parse(await live.OpenDebugTargetAsync(args, CancellationToken.None))!;
        Assert.False(first["ok"]!.GetValue<bool>());
        var second = JsonNode.Parse(await live.OpenDebugTargetAsync(args, CancellationToken.None))!;
        Assert.False(second["ok"]!.GetValue<bool>());
        Assert.Contains("already rejected", second["error"]!["message"]!.GetValue<string>());
    }

    [Fact]
    public async Task Close_AlreadyClosed_NotesInvalidId()
    {
        var sessions = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        sessions.Close("sess-x");
        var control = new SessionControlTools(null, sessions,
            new AnalysisContext(new RecordingBridge(), new NullGhidra()));
        var response = JsonNode.Parse(await control.CloseAsync("sess-x", CancellationToken.None))!;
        Assert.True(response["result"]!["alreadyClosed"]!.GetValue<bool>());
        Assert.Contains("no longer valid", response["result"]!["sessionNote"]!.GetValue<string>());
    }
}

internal sealed class FixedResponseBridge : IBridgeClient
{
    private readonly string _response;

    public FixedResponseBridge(string response) => _response = response;

    public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        => Task.FromResult(_response);
}

internal sealed class ThrowingBridge : IBridgeClient
{
    public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        => Task.FromException<string>(new IOException("test backend failure"));
}

internal sealed class BlockingGhidraControl : IGhidraControlClient
{
    public async Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        return "";
    }
}

internal sealed class CompletedGhidraControl : IGhidraControlClient
{
    private readonly string _response;

    public CompletedGhidraControl(string response) => _response = response;

    public Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
        => Task.FromResult(_response);
}

/// <summary>
/// WS4 read/breakpoint autoPause pins (round-trip plan P2-9/P3-15 via C1):
/// ReadMemAtAddress, GetBacktrace, ListThreads, SampleCallStacks,
/// SetBreakpoint and ClearBreakpoint gain an opt-in autoPause flag.
/// Absent/false is the byte-identical historical passthrough (flag stripped);
/// true on a running target pauses, runs the op, and restores the prior run
/// state with honest pause/resume errors. Breakpoint arming never runs to the
/// breakpoint and never flips a paused target to running.
/// </summary>
public sealed class DebuggerAutoPauseToolsTests
{
    private const string PausedState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":false,\"threadId\":42,\"stableRead\":true}";
    private const string RunningState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":true,\"threadId\":42,\"stableRead\":true}";

    private const string ModulesResult =
        "{\"modules\":[{\"name\":\"game.exe\",\"base\":\"0x140000000\"," +
        "\"end\":\"0x140010000\",\"path\":\"C:\\\\game\\\\game.exe\"}],\"truncated\":false}";

    private sealed class CapturingBridge : IBridgeClient
    {
        private readonly Dictionary<string, Queue<string>> _scripts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _sticky = new(StringComparer.Ordinal);
        public readonly List<string> Calls = [];
        public readonly List<(string Method, string? ArgsJson)> WithArgs = [];

        public CapturingBridge Script(string method, params string[] responses)
        {
            _scripts[method] = new Queue<string>(responses);
            return this;
        }

        public CapturingBridge Sticky(string method, string response)
        {
            _sticky[method] = response;
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
            WithArgs.Add((method, arguments?.GetRawText()));
            if (_scripts.TryGetValue(method, out var queue) && queue.Count > 0)
                return Task.FromResult(queue.Dequeue());
            if (_sticky.TryGetValue(method, out var response))
                return Task.FromResult(response);
            return Task.FromResult(Ok("{}"));
        }
    }

    private static LocalMcpServer CreateServer(CapturingBridge bridge)
        => new(new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = true }, bridge);

    private static string? ArgsFor(CapturingBridge bridge, string method)
        => bridge.WithArgs.FirstOrDefault(c => c.Method == method).ArgsJson;

    [Fact]
    public void Schema_AdvertisesAutoPause_With_False_Default()
    {
        using var server = CreateServer(new CapturingBridge());
        // SampleCallStacks is hidden from discovery (BatchDebuggerOperations
        // is the superset) but keeps the same autoPause contract; its
        // validation is pinned by the execution tests below and CoverageTests.
        foreach (var name in new[] { "ReadMemAtAddress", "GetBacktrace", "ListThreads",
            "SetBreakpoint", "ClearBreakpoint" })
        {
            var tool = server.ListTools().OfType<JsonObject>()
                .Single(t => t["name"]!.GetValue<string>() == name);
            var rule = tool["inputSchema"]!["properties"]!["autoPause"]!.AsObject();
            // The false default rides server-side (pinned behaviorally by
            // Wire_Validation_Accepts_Bool_Rejects_String below); the flag stays advertised.
            Assert.Equal("boolean", rule["type"]!.GetValue<string>());
        }
    }

    [Theory]
    [InlineData("ReadMemAtAddress", "{\"address\":\"cip\"}", "{\"address\":\"cip\",\"autoPause\":true}")]
    [InlineData("GetBacktrace", "{}", "{\"maxFrames\":4,\"autoPause\":true}")]
    [InlineData("ListThreads", "{}", "{\"maxItems\":8,\"autoPause\":true}")]
    [InlineData("ClearBreakpoint", "{\"address\":\"cip\"}", "{\"address\":\"cip\",\"autoPause\":true}")]
    // SampleCallStacks is hidden from discovery, so its bool/string autoPause
    // validation is pinned via the call path in CoverageTests instead.
    public void Wire_Validation_Accepts_Bool_Rejects_String(string tool, string plainArgs, string flaggedArgs)
    {
        using var server = CreateServer(new CapturingBridge());
        Assert.Null(server.ValidateArguments(tool, JsonSerializer.Deserialize<JsonElement>(plainArgs)));
        Assert.Null(server.ValidateArguments(tool, JsonSerializer.Deserialize<JsonElement>(flaggedArgs)));
        var bad = flaggedArgs.Replace("\"autoPause\":true", "\"autoPause\":\"yes\"");
        Assert.NotNull(server.ValidateArguments(tool, JsonSerializer.Deserialize<JsonElement>(bad)));
    }

    [Theory]
    [InlineData("ReadMemAtAddress", "{\"address\":\"cip\"}", "ReadMemAtAddress")]
    [InlineData("GetBacktrace", "{\"maxFrames\":4}", "GetBacktrace")]
    [InlineData("ListThreads", "{\"maxItems\":8}", "ListThreads")]
    [InlineData("SampleCallStacks", "{\"maxSamples\":2}", "SampleCallStacks")]
    [InlineData("SetBreakpoint", "{\"address\":\"cip\"}", "SetBreakpoint")]
    [InlineData("ClearBreakpoint", "{\"address\":\"cip\"}", "ClearBreakpoint")]
    public async Task Absent_Matches_ExplicitFalse_WithNoControlCalls_And_Stripped_Flag(
        string tool, string plainArgs, string bridgeMethod)
    {
        var first = new CapturingBridge().Sticky("GetSnapshotState", CapturingBridge.Ok(PausedState));
        var second = new CapturingBridge().Sticky("GetSnapshotState", CapturingBridge.Ok(PausedState));
        string absent, explicitFalse;
        using (var server = CreateServer(first))
            absent = TextOf(await server.CallToolAsync(Call(tool, plainArgs), CancellationToken.None));
        using (var server = CreateServer(second))
        {
            using var document = JsonDocument.Parse(plainArgs);
            var raw = document.RootElement.GetRawText();
            var flagged = raw.TrimEnd('}') + (raw == "{}" ? "\"autoPause\":false}" : ",\"autoPause\":false}");
            explicitFalse = TextOf(await server.CallToolAsync(Call(tool, flagged), CancellationToken.None));
        }

        Assert.Equal(absent, explicitFalse);
        foreach (var bridge in new[] { first, second })
        {
            Assert.DoesNotContain("PauseDebugger", bridge.Calls);
            Assert.DoesNotContain("RunDebugger", bridge.Calls);
            Assert.DoesNotContain("autoPause", ArgsFor(bridge, bridgeMethod) ?? "");
        }
    }

    [Fact]
    public async Task ListThreads_Running_PausesReadsResumes_WithNote()
    {
        var bridge = new CapturingBridge()
            .Script("GetSnapshotState",
                CapturingBridge.Ok(RunningState),
                CapturingBridge.Ok(PausedState),
                CapturingBridge.Ok(PausedState))
            .Sticky("ListThreads", CapturingBridge.Ok("{\"threads\":[{\"tid\":1}]}"))
            .Sticky("PauseDebugger", CapturingBridge.Ok("{}"))
            .Sticky("RunDebugger", CapturingBridge.Ok("{}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("ListThreads", "{\"maxItems\":8,\"autoPause\":true}"), CancellationToken.None));

        // Server wire shape: ok:true envelopes are unwrapped to the result
        // payload, so the autoPause note sits on the payload root.
        using var doc = JsonDocument.Parse(text);
        var result = doc.RootElement;
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());
        Assert.Single(result.GetProperty("threads").EnumerateArray());

        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var readAt = bridge.Calls.IndexOf("ListThreads");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && readAt > pauseAt && resumeAt > readAt);
        Assert.DoesNotContain("autoPause", ArgsFor(bridge, "ListThreads") ?? "");
    }

    [Fact]
    public async Task ReadMemAtAddress_AlreadyPaused_IsNoOp_NoControlCalls_NoNote()
    {
        var bridge = new CapturingBridge()
            .Sticky("GetSnapshotState", CapturingBridge.Ok(PausedState))
            .Sticky("ReadMemAtAddress", CapturingBridge.Ok("{\"bytes\":\"90\"}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("ReadMemAtAddress", "{\"address\":\"cip\",\"autoPause\":true}"), CancellationToken.None));

        using var doc = JsonDocument.Parse(text);
        Assert.False(doc.RootElement.TryGetProperty("autoPause", out _));
        Assert.DoesNotContain("PauseDebugger", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
        Assert.DoesNotContain("autoPause", ArgsFor(bridge, "ReadMemAtAddress") ?? "");
    }

    [Fact]
    public async Task SampleCallStacks_Running_PausesSamplesResumes_WithNote()
    {
        var bridge = new CapturingBridge()
            .Script("GetSnapshotState",
                CapturingBridge.Ok(RunningState),
                CapturingBridge.Ok(PausedState),
                CapturingBridge.Ok(PausedState))
            .Sticky("SampleCallStacks", CapturingBridge.Ok("{\"frames\":[]}"))
            .Sticky("PauseDebugger", CapturingBridge.Ok("{}"))
            .Sticky("RunDebugger", CapturingBridge.Ok("{}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("SampleCallStacks", "{\"maxSamples\":2,\"autoPause\":true}"), CancellationToken.None));

        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("autoPause", out _));
        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var sampleAt = bridge.Calls.IndexOf("SampleCallStacks");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && sampleAt > pauseAt && resumeAt > sampleAt);
    }

    [Fact]
    public async Task SetBreakpoint_Running_ArmsAndRestoresRunState_WithNote()
    {
        var bridge = new CapturingBridge()
            .Script("GetSnapshotState",
                CapturingBridge.Ok(RunningState),
                CapturingBridge.Ok(PausedState),
                CapturingBridge.Ok(PausedState))
            .Sticky("SetBreakpoint", CapturingBridge.Ok("{\"address\":\"0x140001000\"}"))
            .Sticky("PauseDebugger", CapturingBridge.Ok("{}"))
            .Sticky("RunDebugger", CapturingBridge.Ok("{}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("SetBreakpoint", "{\"address\":\"cip\",\"autoPause\":true}"), CancellationToken.None));

        using var doc = JsonDocument.Parse(text);
        var result = doc.RootElement;
        Assert.True(result.TryGetProperty("autoPause", out var autoPause));
        Assert.True(autoPause.GetProperty("resumed").GetBoolean());

        // Pause -> arm -> restore-prior-run-state only: the resume restores
        // running, it never runs to the breakpoint (no RunDebugger-before-arm
        // beyond the restore, no extra control calls).
        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var armAt = bridge.Calls.IndexOf("SetBreakpoint");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && armAt > pauseAt && resumeAt > armAt);
        Assert.Equal(1, bridge.Calls.Count(c => c == "PauseDebugger"));
        Assert.Equal(1, bridge.Calls.Count(c => c == "RunDebugger"));
        var armArgs = ArgsFor(bridge, "SetBreakpoint") ?? "";
        Assert.Contains("cip", armArgs, StringComparison.Ordinal);
        Assert.DoesNotContain("autoPause", armArgs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetBreakpoint_ModuleRva_AutoPause_ResolvesThenArms_StrippedArgs()
    {
        var bridge = new CapturingBridge()
            .Sticky("GetModuleRecords", CapturingBridge.Ok(ModulesResult))
            .Script("GetSnapshotState",
                CapturingBridge.Ok(RunningState),
                CapturingBridge.Ok(PausedState),
                CapturingBridge.Ok(PausedState))
            .Sticky("SetBreakpoint", CapturingBridge.Ok("{\"address\":\"0x140001000\"}"))
            .Sticky("PauseDebugger", CapturingBridge.Ok("{}"))
            .Sticky("RunDebugger", CapturingBridge.Ok("{}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("SetBreakpoint", "{\"module\":\"game.exe\",\"rva\":\"0x1000\",\"autoPause\":true}"),
            CancellationToken.None));

        Assert.Contains("0x140001000", text, StringComparison.Ordinal);
        var armArgs = ArgsFor(bridge, "SetBreakpoint") ?? "";
        Assert.Contains("0x140001000", armArgs, StringComparison.Ordinal);
        Assert.DoesNotContain("module", armArgs, StringComparison.Ordinal);
        Assert.DoesNotContain("rva", armArgs, StringComparison.Ordinal);
        Assert.DoesNotContain("autoPause", armArgs, StringComparison.Ordinal);
        Assert.Contains("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task SetBreakpoint_PauseRefused_HonestError_NoArm_NoResume()
    {
        var bridge = new CapturingBridge()
            .Sticky("GetSnapshotState", CapturingBridge.Ok(RunningState))
            .Sticky("SetBreakpoint", CapturingBridge.Ok("{\"address\":\"0x140001000\"}"))
            .Sticky("PauseDebugger", CapturingBridge.Fail("pause_failed", "cannot pause"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(
            Call("SetBreakpoint", "{\"address\":\"cip\",\"autoPause\":true}"), CancellationToken.None);
        var text = ErrorTextOf(result);

        // Server wire shape for honest errors: plain "[code] message" text.
        Assert.Contains("[debugger_pause_failed]", text, StringComparison.Ordinal);
        // The honest error is byte-identical (no module-table enrichment on
        // machinery errors) and the target was left running, never armed.
        Assert.DoesNotContain("Loaded modules", text, StringComparison.Ordinal);
        Assert.DoesNotContain("SetBreakpoint", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }

    [Fact]
    public async Task ClearBreakpoint_Running_ClearsAndResumes_WithNote()
    {
        var bridge = new CapturingBridge()
            .Script("GetSnapshotState",
                CapturingBridge.Ok(RunningState),
                CapturingBridge.Ok(PausedState),
                CapturingBridge.Ok(PausedState))
            .Sticky("ClearBreakpoint", CapturingBridge.Ok("{\"cleared\":1}"))
            .Sticky("PauseDebugger", CapturingBridge.Ok("{}"))
            .Sticky("RunDebugger", CapturingBridge.Ok("{}"));
        using var server = CreateServer(bridge);

        var text = TextOf(await server.CallToolAsync(
            Call("ClearBreakpoint", "{\"address\":\"cip\",\"autoPause\":true}"), CancellationToken.None));

        using var doc = JsonDocument.Parse(text);
        Assert.True(doc.RootElement.TryGetProperty("autoPause", out _));
        var pauseAt = bridge.Calls.IndexOf("PauseDebugger");
        var clearAt = bridge.Calls.IndexOf("ClearBreakpoint");
        var resumeAt = bridge.Calls.IndexOf("RunDebugger");
        Assert.True(pauseAt >= 0 && clearAt > pauseAt && resumeAt > clearAt);
        Assert.DoesNotContain("autoPause", ArgsFor(bridge, "ClearBreakpoint") ?? "");
    }

    [Fact]
    public async Task ReadAutoPause_PauseRefused_HonestError_NoRead_NoResume()
    {
        var bridge = new CapturingBridge()
            .Sticky("GetSnapshotState", CapturingBridge.Ok(RunningState))
            .Sticky("GetBacktrace", CapturingBridge.Ok("{\"frames\":[]}"))
            .Sticky("PauseDebugger", CapturingBridge.Fail("pause_failed", "cannot pause"));
        using var server = CreateServer(bridge);

        var result = await server.CallToolAsync(
            Call("GetBacktrace", "{\"autoPause\":true}"), CancellationToken.None);
        var text = ErrorTextOf(result);

        Assert.Contains("[debugger_pause_failed]", text, StringComparison.Ordinal);
        Assert.DoesNotContain("GetBacktrace", bridge.Calls);
        Assert.DoesNotContain("RunDebugger", bridge.Calls);
    }
}
