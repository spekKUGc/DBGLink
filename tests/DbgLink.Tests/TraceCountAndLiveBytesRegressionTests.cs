using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Regression tests for live-test-confirmed bugs:
/// #1 TraceUntil ignores count when includePath:true,
/// #2 MapStaticFunctionToLive includeLiveBytes reports ok:false with correct bytes.
/// </summary>
public sealed class TraceCountAndLiveBytesRegressionTests
{
    // ---- #1: count honored by the includePath per-step loop ----

    [Fact]
    public async Task TraceUntil_includePath_honors_count_with_count_reached()
    {
        var bridge = new CountTraceBridge();
        var tools = new LiveAnalysisTools(new AnalysisContext(bridge, new CountDummyGhidra()));
        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["count"] = 2,
            ["kind"] = "over",
            ["includePath"] = true,
            ["pathFormat"] = "compact",
        });

        var raw = await tools.TraceUntilAsync(args, CancellationToken.None);
        var trace = (JsonNode.Parse(raw)!["result"] as JsonObject)!["trace"] as JsonObject;
        Assert.NotNull(trace);
        Assert.Equal(2, trace!["stepsTaken"]!.GetValue<int>());
        Assert.Equal("count_reached", trace["stopReason"]!.GetValue<string>());
        Assert.Equal(2, bridge.StepCalls);
        // Step 0 (initial) + 2 stepped entries.
        var path = trace["path"]!.AsArray();
        Assert.Equal(3, path.Count);
    }

    [Fact]
    public async Task TraceUntil_includePath_count_larger_than_maxSteps_keeps_max_steps_reached()
    {
        var bridge = new CountTraceBridge();
        var tools = new LiveAnalysisTools(new AnalysisContext(bridge, new CountDummyGhidra()));
        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["count"] = 10,
            ["maxSteps"] = 3,
            ["kind"] = "into",
            ["includePath"] = true,
        });

        var raw = await tools.TraceUntilAsync(args, CancellationToken.None);
        var trace = (JsonNode.Parse(raw)!["result"] as JsonObject)!["trace"] as JsonObject;
        Assert.NotNull(trace);
        Assert.Equal(3, trace!["stepsTaken"]!.GetValue<int>());
        Assert.Equal("max_steps_reached", trace["stopReason"]!.GetValue<string>());
        Assert.Equal(3, bridge.StepCalls);
    }

    [Fact]
    public async Task TraceUntil_includePath_count_ignored_when_stop_criteria_set()
    {
        var bridge = new CountTraceBridge();
        var tools = new LiveAnalysisTools(new AnalysisContext(bridge, new CountDummyGhidra()));
        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["count"] = 50,
            ["stopAt"] = "call",
            ["maxSteps"] = 5,
            ["includePath"] = true,
        });

        var raw = await tools.TraceUntilAsync(args, CancellationToken.None);
        var trace = (JsonNode.Parse(raw)!["result"] as JsonObject)!["trace"] as JsonObject;
        Assert.NotNull(trace);
        // No "call" mnemonic ever appears (bridge always reports "nop"),
        // so the predicate loop exhausts maxSteps; count stays ignored.
        Assert.Equal(5, trace!["stepsTaken"]!.GetValue<int>());
        Assert.Equal("max_steps_reached", trace["stopReason"]!.GetValue<string>());
        Assert.Equal(5, bridge.StepCalls);
    }

    // ---- #2: liveBytes text envelope reports ok:true ----

    [Fact]
    public async Task ReadLiveBytes_native_text_envelope_reports_ok_true()
    {
        var hexdump = "0x140001000 (32 bytes)\n9090909090909090";
        var bridge = new LiveBytesTextBridge(hexdump);
        var node = await AddressMapping.ReadLiveBytesAsync(bridge, "0x140001000", CancellationToken.None);
        var obj = Assert.IsType<JsonObject>(node);
        Assert.True(obj["ok"]!.GetValue<bool>());
        Assert.Contains("90909090", obj["message"]!.GetValue<string>());
    }

    [Fact]
    public async Task ReadLiveBytes_genuine_failure_stays_ok_false()
    {
        var bridge = new LiveBytesErrorBridge();
        var node = await AddressMapping.ReadLiveBytesAsync(bridge, "0x140001000", CancellationToken.None);
        var obj = Assert.IsType<JsonObject>(node);
        Assert.False(obj["ok"]!.GetValue<bool>());
        Assert.Equal("live_bytes_unavailable", obj["code"]!.GetValue<string>());
    }

    [Fact]
    public async Task ReadLiveBytes_result_envelope_still_returns_bytes_node()
    {
        var bridge = new LiveBytesResultBridge();
        var node = await AddressMapping.ReadLiveBytesAsync(bridge, "0x140001000", CancellationToken.None);
        var obj = Assert.IsType<JsonObject>(node);
        Assert.Equal("AA BB", obj["bytes"]!.GetValue<string>());
    }

    // ---- #3: not_debugging consistency normalization ----

    [Fact]
    public void AssessConsistency_not_debugging_normalizes_running_in_before_after()
    {
        var before = new JsonObject
        {
            ["debuggerPid"] = 123,
            ["generation"] = "1",
            ["debugging"] = false,
            ["running"] = true,
            ["stableRead"] = true,
            ["threadId"] = 1,
        };
        var after = new JsonObject
        {
            ["debuggerPid"] = 123,
            ["generation"] = "1",
            ["debugging"] = false,
            ["running"] = true,
            ["stableRead"] = true,
            ["threadId"] = 1,
        };
        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("not_debugging", result["status"]!.GetValue<string>());
        Assert.False(result["before"]!["running"]!.GetValue<bool>());
        Assert.False(result["after"]!["running"]!.GetValue<bool>());
    }

    private sealed class CountDummyGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unavailable\",\"message\":\"test\"}}");
    }

    private sealed class CountTraceBridge : IBridgeClient
    {
        public int StepCalls { get; private set; }
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method is "StepInto" or "StepOver" or "StepOut")
            {
                StepCalls++;
                return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"stepped\":true}}");
            }
            if (method == "GetSnapshotState")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"debuggerPid\":1234,\"generation\":\"1\",\"debugging\":true,\"running\":false,\"stableRead\":true,\"threadId\":1}}");
            if (method == "ReadDisassemblyChunk")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"instructions\":[{\"address\":\"0x140001000\",\"instruction\":\"nop\"}]}}");
            if (method == "GetServerStatus")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"capabilities\":{\"analysisSnapshot\":false}}");
            if (method == "GetCurrentContext")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"text\":\"CIP=0x140001000\"}");
            if (method == "GetCallStack")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"text\":\"frame 0\"}");
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    private sealed class LiveBytesTextBridge : IBridgeClient
    {
        private readonly string _hexdump;
        public LiveBytesTextBridge(string hexdump) => _hexdump = hexdump;
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Assert.Equal("ReadMemAtAddress", method);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"method\":\"ReadMemAtAddress\",\"text\":" +
                JsonSerializer.Serialize(_hexdump) + "}");
        }
    }

    private sealed class LiveBytesErrorBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"Failed to read memory\"}}");
    }

    private sealed class LiveBytesResultBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"address\":\"0x140001000\",\"bytes\":\"AA BB\",\"bytesRead\":2}}");
    }
}
