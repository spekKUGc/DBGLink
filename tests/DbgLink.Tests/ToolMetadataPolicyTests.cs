using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

public sealed class ToolMetadataPolicyTests
{
    [Fact]
    public async Task SessionScope_Global_DoesNotRequireOpenSession()
    {
        // Tools with SessionScope.Global (e.g. Checkpoint, ListAnalysisSessions)
        // do not require an active session even if a nonexistent analysisId is supplied.
        var tempCheckpoints = Path.Combine(Path.GetTempPath(), "dbglink_meta_checkpoints_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempCheckpoints);
        try
        {
            var bridge = new FixedResponseBridge("{\"ok\":true,\"result\":{\"status\":\"ok\"}}");
            using var server = new LocalMcpServer(new ServerConfig { Port = 50521 }, bridge, checkpointPath: tempCheckpoints);

            var globalReq = new CallToolRequestParams
            {
                Name = "Checkpoint",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["action"] = JsonSerializer.SerializeToElement("restore"),
                    ["sha256"] = JsonSerializer.SerializeToElement(new string('a', 64)),
                    ["analysisId"] = JsonSerializer.SerializeToElement("nonexistent_session_id")
                }
            };

            // Global tool executes without requiring the nonexistent session to exist
            var result = await server.CallToolAsync(globalReq, CancellationToken.None);
            Assert.False(result.IsError);

            // Contrast with a tool requiring an active SessionScope (e.g. EvaluateExpressions)
            var sessionReq = new CallToolRequestParams
            {
                Name = "EvaluateExpressions",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" }),
                    ["analysisId"] = JsonSerializer.SerializeToElement("nonexistent_session_id")
                }
            };

            var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(sessionReq, CancellationToken.None));
            Assert.Contains("nonexistent_session_id", ex.Message);
        }
        finally
        {
            if (Directory.Exists(tempCheckpoints))
                Directory.Delete(tempCheckpoints, true);
        }
    }

    [Fact]
    public async Task SessionScope_Closing_BypassesResolve_AndSurfacesControlError()
    {
        // Genuine Closing-scope path (not the no-control Unknown-tool path):
        // with a control client present, CloseAnalysisSession on an unopened
        // id must NOT throw "Analysis session '...' was not found" (Find,
        // not Resolve). It reaches CloseAsync, which reports
        // session_control_unavailable from the stub as a tool error.
        var bridge = new FixedResponseBridge("{\"ok\":true}");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = 50522 }, bridge, ghidraControl: new ClosingStubControl());

        var closeReq = new CallToolRequestParams
        {
            Name = "CloseAnalysisSession",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["analysisId"] = JsonSerializer.SerializeToElement("unopened_session_id")
            }
        };

        var result = await server.CallToolAsync(closeReq, CancellationToken.None);
        Assert.True(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("session_control_unavailable", text);
        Assert.DoesNotContain("was not found", text);
    }

    [Theory]
    [InlineData(10, 1_000, 1_000)]       // DefaultToolTimeoutMs < tool.MinimumTimeoutMs -> tool.MinimumTimeoutMs
    [InlineData(500, 1_000, 1_000)]      // DefaultToolTimeoutMs < tool.MinimumTimeoutMs -> tool.MinimumTimeoutMs
    [InlineData(5_000, 1_000, 5_000)]    // tool.MinimumTimeoutMs <= DefaultToolTimeoutMs <= 120_000 -> DefaultToolTimeoutMs
    [InlineData(60_000, 1_000, 60_000)]  // tool.MinimumTimeoutMs <= DefaultToolTimeoutMs <= 120_000 -> DefaultToolTimeoutMs
    [InlineData(150_000, 1_000, 120_000)]// DefaultToolTimeoutMs > 120_000 -> 120_000
    [InlineData(200_000, 60_000, 120_000)]// DefaultToolTimeoutMs > 120_000 -> 120_000
    [InlineData(30_000, 60_000, 60_000)] // DefaultToolTimeoutMs < tool.MinimumTimeoutMs -> tool.MinimumTimeoutMs
    public void TimeoutClamp_PolicyEnforcesMinimumAndMaximumCap(int defaultTimeout, int toolMinimum, int expected)
    {
        var clamped = Math.Clamp(defaultTimeout, toolMinimum, 120_000);
        Assert.Equal(expected, clamped);
    }

    [Fact]
    public async Task TimeoutClamp_DispatcherAppliesToolMinimum_WhenConfigDefaultIsLower()
    {
        // When config.DefaultToolTimeoutMs is 10ms, but tool.MinimumTimeoutMs is 1000ms (EvaluateExpressions),
        // dispatcher clamps to at least 1000ms. An operation completing in 100ms must NOT be aborted by 10ms!
        var delayingBridge = new DelayingResponseBridge(100, "{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x123\"}}");
        var config = new ServerConfig
        {
            Port = 50523,
            DefaultToolTimeoutMs = 10 // much lower than tool.MinimumTimeoutMs (1000ms)
        };
        using var server = new LocalMcpServer(config, delayingBridge);

        var req = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };

        // If clamped properly, 100ms delay succeeds because deadline is 1000ms, not 10ms.
        var result = await server.CallToolAsync(req, CancellationToken.None);
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task LongSamplingTool_DeclaresMinimumTimeout_NotCutByDefaultDeadline()
    {
        // SampleCallStacks may hold the bridge pipe for durationMs (up to 60s),
        // so it declares a 120s minimum: a 1s config deadline must not abort
        // it. DelayingResponseBridge honors the tool token, so without the
        // minimum this call would fail with the bounded-deadline error.
        var bridge = new DelayingResponseBridge(1_500, "{\"id\":1,\"ok\":true,\"result\":{\"sampled\":1}}");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = 50526, DefaultToolTimeoutMs = 1_000 }, bridge);
        var req = new CallToolRequestParams
        {
            Name = "SampleCallStacks",
            Arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                "{\"maxSamples\":1,\"intervalMs\":50,\"durationMs\":100}")!,
        };
        var result = await server.CallToolAsync(req, CancellationToken.None);
        Assert.False(result.IsError);
    }

    [Fact]
    public async Task RawResponse_ToolReturnsPayloadWithoutWrapper()
    {
        // Tools configured with RawResponse = true (like GetServerStatus) return raw payload without unwrapping.
        // Normal tools (RawResponse = false, like EvaluateExpressions) unwrap the bridge JSON text or result.
        var rawStatusJson = "{\"id\":1,\"ok\":true,\"debugging\":false,\"version\":\"1.0\"}";
        var bridge = new FixedResponseBridge(rawStatusJson);
        using var server = new LocalMcpServer(new ServerConfig { Port = 50524 }, bridge);

        // 1. RawResponse tool: GetServerStatus
        var statusReq = new CallToolRequestParams { Name = "GetServerStatus" };
        var statusResult = await server.CallToolAsync(statusReq, CancellationToken.None);
        var statusText = Assert.IsType<TextContentBlock>(Assert.Single(statusResult.Content)).Text;

        // Raw response is a complete JSON document, not unwrapped text
        Assert.StartsWith("{", statusText.Trim());
        Assert.Contains("\"debugging\"", statusText);
        Assert.Contains("\"ghidra\"", statusText);

        // 2. Non-RawResponse tool: EvaluateExpressions
        var evalBridge = new FixedResponseBridge("{\"id\":1,\"ok\":true,\"text\":\"rax=0x00000000\"}");
        using var evalServer = new LocalMcpServer(new ServerConfig { Port = 50525 }, evalBridge);
        var evalReq = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };
        var evalResult = await evalServer.CallToolAsync(evalReq, CancellationToken.None);
        var evalText = Assert.IsType<TextContentBlock>(Assert.Single(evalResult.Content)).Text;

        // Non-raw response is unwrapped directly; batch envelope carries the bridge text per item.
        Assert.Contains("rax=0x00000000", evalText);
    }

    [Fact]
    public async Task TimeoutClamp_DispatcherAbortsSlowOperation_AtClampedFloor()
    {
        // Complement to DispatcherAppliesToolMinimum: the clamp is a real
        // deadline, not just a floor for fast ops. DefaultToolTimeoutMs=1000
        // with a 5s backend delay must abort at ~1s with a bounded-deadline
        // tool error (IsError, not an exception / hang).
        var delayingBridge = new DelayingResponseBridge(5_000, "{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x123\"}}");
        var config = new ServerConfig
        {
            Port = 50526,
            DefaultToolTimeoutMs = 1_000
        };
        using var server = new LocalMcpServer(config, delayingBridge);

        var req = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };

        var started = DateTime.UtcNow;
        var result = await server.CallToolAsync(req, CancellationToken.None);
        var elapsed = DateTime.UtcNow - started;

        Assert.True(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("bounded deadline", text);
        Assert.True(elapsed < TimeSpan.FromSeconds(4),
            $"Deadline did not abort the slow backend; elapsed {elapsed.TotalSeconds:F1}s.");
    }

    [Fact]
    public async Task DisabledCapability_CallError_NamesToolAndCapability()
    {
        // Dispatcher names the tool and the missing capability so agents can
        // fix the server settings instead of retrying blindly.
        // (P3: single-op UpdateVariable purged; BatchAnnotate carries the
        // same Mutation gate.)
        var bridge = new FixedResponseBridge("{\"ok\":true}");
        using var server = new LocalMcpServer(
            new ServerConfig { Port = 50527, AllowMutation = false }, bridge);

        var req = new CallToolRequestParams
        {
            Name = "BatchAnnotate",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["operations"] = JsonSerializer.SerializeToElement(new[]
                {
                    new { kind = "rename_function", function = "f", name = "n" },
                })
            }
        };

        var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(req, CancellationToken.None));
        Assert.Contains("BatchAnnotate", ex.Message);
        Assert.Contains("Mutation", ex.Message);
        Assert.Contains("AllowMutation", ex.Message);
    }

    private sealed class DelayingResponseBridge(int delayMs, string response) : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            await Task.Delay(delayMs, cancellationToken);
            return response;
        }
    }

    private sealed class ClosingStubControl : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;

        public Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true}");
    }
}
