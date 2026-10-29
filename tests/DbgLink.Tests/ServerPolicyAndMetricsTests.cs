using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

public sealed class ServerPolicyAndMetricsTests
{
    // ========================================================================================
    // GROUP 1: MCP REQUEST POLICY & ORIGIN VALIDATION (30 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(null, ServerConfig.DefaultPort, true)]
    [InlineData("", ServerConfig.DefaultPort, true)]
    [InlineData("   ", ServerConfig.DefaultPort, true)]
    [InlineData("http://127.0.0.1:50301", ServerConfig.DefaultPort, true)]
    [InlineData("http://localhost:50301", ServerConfig.DefaultPort, true)]
    [InlineData("http://127.0.0.1:8080", 8080, true)]
    [InlineData("http://localhost:8080", 8080, true)]
    [InlineData("http://127.0.0.1:50301/", ServerConfig.DefaultPort, true)]
    [InlineData("http://localhost:50301/", ServerConfig.DefaultPort, true)]
    [InlineData("http://127.0.0.1:50301/..", ServerConfig.DefaultPort, false)] // Path traversal ..
    [InlineData("http://localhost:50301/..", ServerConfig.DefaultPort, false)] // Path traversal ..
    [InlineData("http://127.0.0.1:50301/%2e%2e", ServerConfig.DefaultPort, false)] // % character rejected
    [InlineData("http://localhost:50301/%20", ServerConfig.DefaultPort, false)] // % character rejected
    [InlineData("https://127.0.0.1:50301", ServerConfig.DefaultPort, false)] // https rejected (only http)
    [InlineData("https://localhost:50301", ServerConfig.DefaultPort, false)] // https rejected
    [InlineData("ftp://127.0.0.1:50301", ServerConfig.DefaultPort, false)] // ftp rejected
    [InlineData("ws://127.0.0.1:50301", ServerConfig.DefaultPort, false)] // ws rejected
    [InlineData("http://attacker.com:50301", ServerConfig.DefaultPort, false)] // untrusted host
    [InlineData("http://192.168.1.50:50301", ServerConfig.DefaultPort, false)] // untrusted host
    [InlineData("http://0.0.0.0:50301", ServerConfig.DefaultPort, false)] // untrusted host
    [InlineData("http://localhost.attacker.com:50301", ServerConfig.DefaultPort, false)] // sub-domain attack
    [InlineData("http://127.0.0.1.evil.com:50301", ServerConfig.DefaultPort, false)] // sub-domain attack
    [InlineData("http://127.0.0.1:50302", ServerConfig.DefaultPort, false)] // port mismatch
    [InlineData("http://localhost:80", ServerConfig.DefaultPort, false)] // port mismatch
    [InlineData("http://127.0.0.1:50301/mcp", ServerConfig.DefaultPort, false)] // path not allowed
    [InlineData("http://127.0.0.1:50301/api", ServerConfig.DefaultPort, false)] // path not allowed
    [InlineData("http://127.0.0.1:50301/?token=123", ServerConfig.DefaultPort, false)] // query not allowed
    [InlineData("http://127.0.0.1:50301/#fragment", ServerConfig.DefaultPort, false)] // fragment not allowed
    [InlineData("http://admin:secret@127.0.0.1:50301", ServerConfig.DefaultPort, false)] // userinfo not allowed
    [InlineData("not-a-valid-uri", ServerConfig.DefaultPort, false)] // malformed
    public void OriginAllowed_EnforcesStrictOriginRules(string? origin, int port, bool expectedAllowed)
    {
        var allowed = McpRequestPolicy.OriginAllowed(origin, port);
        Assert.Equal(expectedAllowed, allowed);
    }

    [Fact]
    public void OriginAllowed_OversizedOrigin_Rejected()
    {
        var longOrigin = "http://localhost:50301/" + new string('a', 300);
        Assert.False(McpRequestPolicy.OriginAllowed(longOrigin, ServerConfig.DefaultPort));
    }

    // ========================================================================================
    // GROUP 2: SERVER METRICS TELEMETRY & OPERATIONS (25 Tests)
    // ========================================================================================

    [Fact]
    public void ServerMetrics_InitialSnapshot_ContainsValidDefaults()
    {
        var metrics = new ServerMetrics();
        var snapshot = metrics.Snapshot();

        Assert.Equal(2, snapshot["schemaVersion"]?.GetValue<int>());
        Assert.Equal(0L, snapshot["httpRequests"]?.GetValue<long>());
        Assert.Equal(0L, snapshot["roundTrips"]?.GetValue<long>());
        Assert.Equal(0L, snapshot["toolCalls"]?.GetValue<long>());
        Assert.Equal(0L, snapshot["bytesReceived"]?.GetValue<long>());
        Assert.Equal(0L, snapshot["bytesSent"]?.GetValue<long>());
        Assert.NotNull(snapshot["startedAtUtc"]?.GetValue<string>());
        Assert.True(snapshot["uptimeSeconds"]?.GetValue<double>() >= 0);
    }

    [Fact]
    public void ServerMetrics_RecordHttpRequest_IncrementsCount()
    {
        var metrics = new ServerMetrics();
        metrics.RecordHttpRequest();
        metrics.RecordHttpRequest();

        var snapshot = metrics.Snapshot();
        Assert.Equal(2L, snapshot["httpRequests"]?.GetValue<long>());
    }

    [Fact]
    public void ServerMetrics_RecordMcpRequest_TracksToolsCallAndBytes()
    {
        var metrics = new ServerMetrics();
        metrics.RecordMcpRequest("tools/list", 256);
        metrics.RecordMcpRequest("tools/call", 512);

        var snapshot = metrics.Snapshot();
        Assert.Equal(2L, snapshot["roundTrips"]?.GetValue<long>());
        Assert.Equal(1L, snapshot["toolCalls"]?.GetValue<long>());
        Assert.Equal(768L, snapshot["bytesReceived"]?.GetValue<long>());
    }

    [Fact]
    public void ServerMetrics_RecordBytesSent_AccumulatesAndCalculatesMegabytes()
    {
        var metrics = new ServerMetrics();
        metrics.RecordBytesSent(1024 * 1024); // 1 MB

        var snapshot = metrics.Snapshot();
        Assert.Equal(1048576L, snapshot["bytesSent"]?.GetValue<long>());
        Assert.Equal(1.0, snapshot["sentMegabytes"]?.GetValue<double>());
    }

    [Fact]
    public void ServerMetrics_BeginTool_SanitizesControlCharsAndBoundsLength()
    {
        var metrics = new ServerMetrics();
        var evilName = "Read\0Mem\r\nory" + new string('X', 200);
        using var scope = metrics.BeginTool(evilName);

        var snapshot = metrics.Snapshot();
        var activeOps = snapshot["activeOperations"] as JsonArray;
        Assert.NotNull(activeOps);
        Assert.Single(activeOps);

        var op = activeOps[0] as JsonObject;
        Assert.NotNull(op);
        var safeName = op["tool"]?.GetValue<string>();
        Assert.NotNull(safeName);
        Assert.False(safeName.Contains('\0'));
        Assert.False(safeName.Contains('\r'));
        Assert.False(safeName.Contains('\n'));
        Assert.True(safeName.Length <= 128);
    }

    [Fact]
    public void ServerMetrics_BeginTool_RingBufferCapsAt16()
    {
        var metrics = new ServerMetrics();
        for (var i = 0; i < 25; i++)
        {
            metrics.BeginTool($"Tool_{i}");
        }

        var snapshot = metrics.Snapshot();
        var activeOps = snapshot["activeOperations"] as JsonArray;
        Assert.NotNull(activeOps);
        Assert.True(activeOps.Count <= 16);
    }

    [Fact]
    public void ServerMetrics_ActivityHistoryPaging_RespectsAfterParameter()
    {
        var metrics = new ServerMetrics();
        for (var i = 0; i < 5; i++)
        {
            using var scope = metrics.BeginTool($"PagingTool_{i}");
            scope.Complete(failed: false);
        }

        // 5 tools started + 5 tools completed = 10 entries in activityHistory
        var allHistory = metrics.Snapshot(after: 0)["activityHistory"] as JsonArray;
        var partialHistory = metrics.Snapshot(after: 5)["activityHistory"] as JsonArray;

        Assert.NotNull(allHistory);
        Assert.NotNull(partialHistory);
        Assert.Equal(10, allHistory.Count);
        Assert.Equal(5, partialHistory.Count);
    }

    [Fact]
    public void ServerMetrics_ConcurrentUpdates_ThreadSafeWithoutLoss()
    {
        var metrics = new ServerMetrics();
        Parallel.For(0, 100, _ =>
        {
            metrics.RecordHttpRequest();
            metrics.RecordMcpRequest("tools/call", 100);
            metrics.RecordBytesSent(200);
        });

        var snapshot = metrics.Snapshot();
        Assert.Equal(100L, snapshot["httpRequests"]?.GetValue<long>());
        Assert.Equal(100L, snapshot["roundTrips"]?.GetValue<long>());
        Assert.Equal(100L, snapshot["toolCalls"]?.GetValue<long>());
        Assert.Equal(10000L, snapshot["bytesReceived"]?.GetValue<long>());
        Assert.Equal(20000L, snapshot["bytesSent"]?.GetValue<long>());
    }

    // ========================================================================================
    // GROUP 3: COUNTING RESPONSE STREAM (15 Tests)
    // ========================================================================================

    [Fact]
    public void CountingResponseStream_WriteByteArray_UpdatesMetrics()
    {
        var metrics = new ServerMetrics();
        using var memStream = new MemoryStream();
        using var stream = new CountingResponseStream(memStream, metrics);

        var data = new byte[] { 1, 2, 3, 4, 5 };
        stream.Write(data, 0, data.Length);

        Assert.Equal(5, memStream.Length);
        Assert.Equal(5L, metrics.Snapshot()["bytesSent"]?.GetValue<long>());
    }

    [Fact]
    public async Task CountingResponseStream_WriteReadOnlyMemoryAsync_UpdatesMetrics()
    {
        var metrics = new ServerMetrics();
        using var memStream = new MemoryStream();
        using var stream = new CountingResponseStream(memStream, metrics);

        var data = new byte[] { 10, 20, 30, 40 };
        await stream.WriteAsync(data.AsMemory());

        Assert.Equal(4, memStream.Length);
        Assert.Equal(4L, metrics.Snapshot()["bytesSent"]?.GetValue<long>());
    }

    [Fact]
    public void CountingResponseStream_StreamProperties_VerifyCapabilities()
    {
        var metrics = new ServerMetrics();
        using var memStream = new MemoryStream();
        using var stream = new CountingResponseStream(memStream, metrics);

        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.True(stream.CanWrite);
    }

    [Fact]
    public void CountingResponseStream_UnsupportedOperations_ThrowNotSupportedException()
    {
        var metrics = new ServerMetrics();
        using var memStream = new MemoryStream();
        using var stream = new CountingResponseStream(memStream, metrics);

        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(10));
    }

    [Theory]
    [InlineData("http://[::1]:50301", ServerConfig.DefaultPort, false)] // IPv6 rejected (only 127.0.0.1 / localhost)
    [InlineData("HTTP://127.0.0.1:50301", ServerConfig.DefaultPort, true)] // Case-insensitive scheme
    [InlineData("HTTP://LOCALHOST:50301", ServerConfig.DefaultPort, true)] // Case-insensitive host
    [InlineData("http://127.0.0.1:1", 1, true)] // Boundary port 1
    [InlineData("http://localhost:65535", 65535, true)] // Boundary port 65535
    [InlineData("http://127.0.0.1:0", ServerConfig.DefaultPort, false)] // Port mismatch with server port
    [InlineData("http://localhost:-1", ServerConfig.DefaultPort, false)] // Negative port
    [InlineData("http://127.0.0.1:50301\\evil", ServerConfig.DefaultPort, false)] // Backslash
    [InlineData("http://127.0.0.1:50301/subdir", ServerConfig.DefaultPort, false)] // Subdirectory
    [InlineData("http://127.0.0.1:50301/sub/dir", ServerConfig.DefaultPort, false)] // Nested path
    [InlineData("http://127.0.0.1:50301/%00", ServerConfig.DefaultPort, false)] // Null byte encoded
    [InlineData("http://127.0.0.1:50301/%%", ServerConfig.DefaultPort, false)] // Double percent
    [InlineData("http://localhost:50301/?", ServerConfig.DefaultPort, false)] // Empty query string
    [InlineData("http://localhost:50301/#", ServerConfig.DefaultPort, false)] // Empty fragment
    [InlineData("http://127.0.0.1:50301/index.html", ServerConfig.DefaultPort, false)] // File path
    public void OriginAllowed_AdvancedSecurityEdgeCases(string origin, int port, bool expectedAllowed)
    {
        var allowed = McpRequestPolicy.OriginAllowed(origin, port);
        Assert.Equal(expectedAllowed, allowed);
    }

    [Fact]
    public void CountingResponseStream_ZeroByteWrite_DoesNotAlterByteCount()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        stream.Write([], 0, 0);

        Assert.Equal(0L, metrics.Snapshot()["bytesSent"]?.GetValue<long>());
    }

    [Fact]
    public async Task CountingResponseStream_SequentialWrites_AccumulateCorrectly()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        for (var i = 0; i < 10; i++)
        {
            await stream.WriteAsync(new byte[100].AsMemory());
        }

        Assert.Equal(1000, mem.Length);
        Assert.Equal(1000L, metrics.Snapshot()["bytesSent"]?.GetValue<long>());
    }

    [Fact]
    public void CountingResponseStream_FlushOperations_AreSafe()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        stream.Flush();
        Assert.True(stream.FlushAsync(CancellationToken.None).IsCompletedSuccessfully);
    }

    [Fact]
    public void CountingResponseStream_ReadThrowsNotSupportedException()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        Assert.Throws<NotSupportedException>(() => stream.Read(new byte[10], 0, 10));
    }

    [Fact]
    public void CountingResponseStream_SeekThrowsNotSupportedException()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.End));
    }

    [Fact]
    public void CountingResponseStream_LengthAndPositionThrowNotSupportedException()
    {
        var metrics = new ServerMetrics();
        using var mem = new MemoryStream();
        using var stream = new CountingResponseStream(mem, metrics);

        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 5);
        Assert.Throws<NotSupportedException>(() => stream.SetLength(100));
    }

    // ========================================================================================
    // GROUP 3: BEARER TOKEN GATE & BOUNDED ACTIVITY HISTORY
    // ========================================================================================

    private const string ValidTestToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Bearer wrongtokenwrongtokenwrongtokenwrongtoker")]
    [InlineData("Basic aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Bearer_gate_rejects_missing_or_malformed_headers(string? header)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        if (header is not null)
            context.Request.Headers.Authorization = header;

        Assert.False(McpRequestPolicy.HasValidBearerToken(context.Request, ValidTestToken));
    }

    [Theory]
    [InlineData("Bearer ")]
    [InlineData("bearer ")]
    [InlineData("BEARER ")]
    public void Bearer_gate_accepts_the_configured_token_with_case_insensitive_scheme(string scheme)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.Headers.Authorization = scheme + ValidTestToken;

        Assert.True(McpRequestPolicy.HasValidBearerToken(context.Request, ValidTestToken));
    }

    [Fact]
    public void Bearer_gate_rejects_a_same_length_wrong_token_and_an_invalid_server_token()
    {
        var wrongToken = new string('b', ValidTestToken.Length);
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer " + wrongToken;
        Assert.False(McpRequestPolicy.HasValidBearerToken(context.Request, ValidTestToken));

        // With no valid server-side token configured nothing can authenticate.
        context.Request.Headers.Authorization = "Bearer " + ValidTestToken;
        Assert.False(McpRequestPolicy.HasValidBearerToken(context.Request, ""));
    }

    [Theory]
    [InlineData("1", true)]
    [InlineData("true", true)]
    [InlineData("YES", true)]
    [InlineData("0", false)]
    [InlineData("off", false)]
    [InlineData("maybe", true)]
    [InlineData(null, true)]
    public void RequireAuth_env_flag_controls_mcp_token_enforcement(string? raw, bool expected)
    {
        using var tmp = TempDir.Create("dbglink-reqauth-");
        var path = Path.Combine(tmp, "config.json");
        var config = ServerConfig.Load(50399, configPath: path,
            environment: name => name == "DBGLINK_REQUIRE_AUTH" ? raw : null);
        Assert.Equal(expected, config.RequireAuthToken);
        Assert.False(string.IsNullOrEmpty(config.AuthToken));
    }

    [Fact]
    public void Activity_history_is_bounded_and_the_sequence_cursor_survives_trims()
    {
        var metrics = new ServerMetrics();
        for (var index = 0; index < 300; index++)
        {
            using var operation = metrics.BeginTool("InspectFunction");
            operation.Complete(failed: false);
        }

        // A single response carries at most one page of history.
        var page = metrics.Snapshot()["activityHistory"]!.AsArray();
        Assert.Equal(16, page.Count);

        // Paging with a sequence cursor walks exactly the retained window:
        // 600 recorded events, the ring keeps the newest 128 (473..600), and
        // the sequence numbers remain strictly increasing across trims.
        var seen = new List<long>();
        long cursor = 0;
        while (true)
        {
            var next = metrics.Snapshot(cursor)["activityHistory"]!.AsArray();
            if (next.Count == 0) break;
            foreach (var item in next)
                seen.Add(item!["sequence"]!.GetValue<long>());
            cursor = seen[^1];
        }
        Assert.Equal(128, seen.Count);
        Assert.Equal(seen.OrderBy(value => value), seen);
        Assert.Equal(473L, seen[0]);
        Assert.Equal(600L, seen[^1]);
    }

    [Fact]
    public void QueueFullMessage_ContainsCountsAndHint()
    {
        var message = McpToolDispatcher.QueueFullMessage(8, 16);
        Assert.Contains("8 running", message);
        Assert.Contains("16 queued", message);
        Assert.Contains("retryAfterMs=2000", message);
        Assert.Contains("EvaluateExpressions", message);
    }

    // ========================================================================================
    // GROUP 4: GETSERVERSTATUS TOKEN DIET — sections + default ≤8KB (w10)
    // ========================================================================================

    [Fact]
    public void StatusDiet_DefaultNode_StaysUnder8KB_OnHostileSnapshot()
    {
        var metrics = new ServerMetrics();
        for (var t = 0; t < 30; t++)
        {
            for (var i = 0; i < 4; i++)
            {
                using var scope = metrics.BeginTool("DietTool_" + t + "_" + new string('n', 60));
                scope.Complete(failed: true, outcome: "backend_error",
                    requestBytes: 500, responseBytes: 9000, errorCode: "err_" + t);
            }
        }
        for (var i = 0; i < 40; i++)
            metrics.RecordMcpRequest("hostile_method_" + i + "_" + new string('m', 40), 100);
        for (var i = 0; i < 20; i++)
            metrics.RecordHttpStatus(500 + (i % 5));
        metrics.RecordBackendCall("native", "EvaluateExpression", false, "debugger_closed", 99);
        var snapshot = metrics.Snapshot();
        var failures = Enumerable.Range(0, 20).Select(i => "fail " + i + " " + new string('x', 600)).ToArray();
        var node = new StatusRenderer().RenderJson(
            snapshot, failures, 999, 10_000, 50_000, DateTimeOffset.UtcNow);
        var json = node.ToJsonString();
        Assert.True(json.Length <= 8 * 1024, $"diet default grew: {json.Length}");
        Assert.Null(node["bytes"]);
        Assert.Null(node["topLargestAvgOut"]);
        Assert.True((node["topSlowest"] as JsonArray)!.Count <= 3);
        Assert.True((node["topErrors"] as JsonArray)!.Count <= 3);
        Assert.Equal(5, (node["recentFailures"] as JsonArray)!.Count);
    }

    [Fact]
    public void StatusSections_Filter_KeepsOnlyRequestedGroups()
    {
        var metrics = new ServerMetrics();
        using (var scope = metrics.BeginTool("SectionTool"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 10, responseBytes: 100);
        metrics.RecordHttpStatus(200);
        metrics.RecordSessionRegistered("sess-9");
        var snapshot = metrics.Snapshot();
        var renderer = new StatusRenderer();
        var updated = new DateTimeOffset(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

        var backends = renderer.RenderJson(snapshot, [], 0, 1, -1, updated,
            new HashSet<string>(["backends"]));
        Assert.NotNull(backends["backends"]);
        Assert.Equal(2L, backends["schemaVersion"]?.GetValue<long>());
        Assert.NotNull(backends["updated"]);
        Assert.Null(backends["total"]);
        Assert.Null(backends["topSlowest"]);
        Assert.Null(backends["sessions"]);
        Assert.Null(backends["http"]);

        var telemetry = renderer.RenderJson(snapshot, ["boom"], 0, 1, -1, updated,
            new HashSet<string>(["telemetry"]));
        Assert.NotNull(telemetry["topSlowest"]);
        Assert.Single((telemetry["recentFailures"] as JsonArray)!);
        Assert.Null(telemetry["total"]);
        Assert.Null(telemetry["backends"]);

        var summary = renderer.RenderJson(snapshot, [], 0, 1, -1, updated,
            new HashSet<string>(["summary", "http"]));
        Assert.NotNull(summary["total"]);
        Assert.NotNull(summary["http"]);
        Assert.Null(summary["backends"]);
        Assert.Null(summary["topErrors"]);
        Assert.Null(summary["recentFailures"]);
    }

    [Fact]
    public void StatusSections_Parse_LenientAndCaseInsensitive()
    {
        Assert.Null(StatusRenderer.ParseStatusSections(null));
        Assert.Null(StatusRenderer.ParseStatusSections(JsonSerializer.SerializeToElement(new { })));
        var set = StatusRenderer.ParseStatusSections(
            JsonSerializer.SerializeToElement(new { sections = new[] { "Backends", "SESSIONS" } }));
        Assert.Equal(new HashSet<string>(["backends", "sessions"], StringComparer.Ordinal), set);
        // Unknown names never produce an empty node: they fall back to default.
        Assert.Null(StatusRenderer.ParseStatusSections(
            JsonSerializer.SerializeToElement(new { sections = new[] { "nope" } })));
    }

    [Fact]
    public void StatusDiet_Schema_AdvertisesSectionsSubset()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>().Single(t => t["name"]!.GetValue<string>() == "GetServerStatus");
        var props = (JsonObject)tool["inputSchema"]!["properties"]!;
        var sections = Assert.IsType<JsonObject>(props["sections"]);
        Assert.Equal("array", sections["type"]!.GetValue<string>());
        var allowed = ((JsonArray)sections["items"]!["enum"]!).Select(n => n!.GetValue<string>()).ToHashSet();
        Assert.Equal(new HashSet<string>(["summary", "telemetry", "backends", "sessions", "http"]), allowed);
    }

    [Fact]
    public async Task StatusSections_UnknownName_RejectedBeforeBackend()
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["sections"] = JsonSerializer.SerializeToElement(new[] { "nope" }),
                },
            }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public async Task StatusSections_EndToEnd_FiltersTelemetryNode()
    {
        using var dir = TempDir.Create("dbglink-status-");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, TelemetryDirectory = dir },
            new StatusDietBridge(), new StatusDietGhidra());
        try
        {
            var full = await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>(),
            }, CancellationToken.None);
            var fullTelemetry = JsonNode.Parse(Assert.Single(full.Content.OfType<TextContentBlock>()).Text)!
                .AsObject()["telemetry"]!.AsObject();
            Assert.True(fullTelemetry.ToJsonString().Length <= 8 * 1024);
            Assert.NotNull(fullTelemetry["total"]);

            var filtered = await server.CallToolAsync(new CallToolRequestParams
            {
                Name = "GetServerStatus",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["sections"] = JsonSerializer.SerializeToElement(new[] { "backends" }),
                },
            }, CancellationToken.None);
            var telemetry = JsonNode.Parse(Assert.Single(filtered.Content.OfType<TextContentBlock>()).Text)!
                .AsObject()["telemetry"]!.AsObject();
            Assert.NotNull(telemetry["backends"]);
            Assert.Null(telemetry["total"]);
            Assert.Null(telemetry["topSlowest"]);
            Assert.Null(telemetry["sessions"]);
            Assert.True(telemetry.ToJsonString().Length < fullTelemetry.ToJsonString().Length);
        }
        finally
        {
            ToolRegistry.TelemetryExtrasProvider = null;
            ToolRegistry.TelemetrySnapshotProvider = null;
            ToolRegistry.TelemetryRenderer = StatusRenderer.Shared;
        }
    }

    private sealed class StatusDietBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{\"debugging\":false}}");
    }

    private sealed class StatusDietGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{\"available\":true}}");
    }
}
