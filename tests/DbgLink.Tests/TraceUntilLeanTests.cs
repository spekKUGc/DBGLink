using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// TraceUntil diet: the trace node carries the verdict, the final context
/// already lives in the snapshot, and a dead bridge is detected after three
/// unusable polls instead of burning the whole 3 s budget.
/// </summary>
public sealed class TraceUntilLeanTests
{
    private sealed class TraceBridge : IBridgeClient
    {
        public List<string> Calls { get; } = [];
        public bool StateThrows { get; set; }

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            return Task.FromResult(method switch
            {
                "StepInto" or "StepOver" or "StepOut" =>
                    "{\"id\":1,\"ok\":true,\"result\":{\"stepped\":true}}",
                "GetSnapshotState" when StateThrows =>
                    throw new IOException("bridge is gone"),
                "GetSnapshotState" =>
                    "{\"id\":1,\"ok\":true,\"result\":{\"debuggerPid\":123,\"generation\":\"1\"," +
                    "\"debugging\":true,\"running\":false,\"stableRead\":true,\"threadId\":1}}",
                "GetServerStatus" =>
                    "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"pid\":123,\"debugging\":true}",
                "GetCurrentContext" =>
                    "{\"id\":1,\"ok\":true,\"text\":\"CIP=0x140001000\"}",
                "GetCallStack" =>
                    "{\"id\":1,\"ok\":true,\"text\":\"frame 0\"}",
                "ReadDisassemblyChunk" =>
                    "{\"id\":1,\"ok\":true,\"result\":{\"address\":\"cip\",\"instructions\":[" +
                    "{\"address\":\"0x140001000\",\"instruction\":\"nop\"}]}}",
                _ => "{\"id\":1,\"ok\":true,\"result\":{}}"
            });
        }
    }

    private static LiveAnalysisTools Live(TraceBridge bridge) =>
        new(new AnalysisContext(bridge, new NullGhidra()));

    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    [Fact]
    public async Task Bulk_trace_drops_the_step_node_and_final_duplicates()
    {
        var bridge = new TraceBridge();
        var raw = await Live(bridge).TraceUntilAsync(
            Args("{\"count\":1,\"kind\":\"into\"}"), CancellationToken.None);

        var result = (JsonObject)JsonNode.Parse(raw)!["result"]!;
        var trace = (JsonObject)result["trace"]!;
        Assert.Equal(1, trace["stepsTaken"]!.GetValue<int>());
        Assert.Equal("count_reached", trace["stopReason"]!.GetValue<string>());
        Assert.Null(result["step"]);
        Assert.Null(trace["finalAddress"]);
        Assert.Null(trace["finalInstruction"]);
        Assert.Null(result["summary"]!["nextAction"]);
        Assert.DoesNotContain("ReadDisassemblyChunk", bridge.Calls);
    }

    [Fact]
    public async Task Dead_bridge_stops_after_three_state_polls()
    {
        var bridge = new TraceBridge { StateThrows = true };
        var watch = Stopwatch.StartNew();
        var raw = await Live(bridge).TraceUntilAsync(
            Args("{\"count\":1,\"kind\":\"into\"}"), CancellationToken.None);
        watch.Stop();

        using var document = JsonDocument.Parse(raw);
        Assert.False(document.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("debugger_running_timeout",
            document.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.True(bridge.Calls.Count(call => call == "GetSnapshotState") <= 5,
            "poll budget should stop after three unusable polls");
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2),
            $"dead bridge took {watch.ElapsedMilliseconds} ms");
    }
}
