using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// GetAnalysisSnapshot defaults: status is opt-in, the capability probe runs
/// once per session, and compactStack folds object-form stacks on the
/// individual path too.
/// </summary>
public sealed class SnapshotLeanTests
{
    private const string PlainStatus =
        "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
        "\"pid\":123,\"debugging\":true}";

    private const string CapableStatus =
        "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\"," +
        "\"pid\":123,\"debugging\":true,\"capabilities\":{\"analysisSnapshot\":true}}";

    private const string UnknownMethod =
        "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"Unknown bridge method.\"}}";

    private const string PausedState =
        "{\"debuggerPid\":123,\"generation\":\"1\",\"debugging\":true," +
        "\"running\":false,\"threadId\":42,\"stableRead\":true}";

    private const string StackWithSystemFrames =
        "{\"frames\":[\"app!main\",\"ntdll.dll!A\",\"ntdll.dll!B\"," +
        "\"kernel32.dll!C\",\"app!worker\"]}";

    private sealed class CountingBridge : IBridgeClient
    {
        public Dictionary<string, string> Responses { get; } = new(StringComparer.Ordinal);
        public List<string> Calls { get; } = [];

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            return Task.FromResult(Responses.TryGetValue(method, out var response)
                ? response
                : "{\"id\":1,\"ok\":true,\"result\":{}}");
        }

        public int Count(string method) => Calls.Count(call => call == method);
    }

    private static CountingBridge Individual(string status)
        => new()
        {
            Responses =
            {
                ["GetServerStatus"] = status,
                ["GetSnapshotState"] = Ok(PausedState),
                ["GetCurrentContext"] = Text("registers"),
                ["GetCallStack"] = Ok(StackWithSystemFrames),
            }
        };

    private static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

    private static string Text(string text) =>
        "{\"id\":1,\"ok\":true,\"text\":" + JsonSerializer.Serialize(text) + "}";

    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static LiveAnalysisTools Live(CountingBridge bridge) =>
        new(new AnalysisContext(bridge, new NullGhidra()));

    [Fact]
    public async Task Default_omits_status_and_learns_an_unsupported_batch_in_one_trip()
    {
        var bridge = Individual(PlainStatus);
        bridge.Responses["GetAnalysisSnapshot"] = UnknownMethod;
        var live = Live(bridge);

        var first = JsonDocument.Parse(
            await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None));
        var firstResult = first.RootElement.GetProperty("result");
        Assert.False(firstResult.GetProperty("sections").TryGetProperty("status", out _));
        // Optimistic attempt + the individual fallback; no capability probe.
        Assert.Equal(0, bridge.Count("GetServerStatus"));
        Assert.Equal(1, bridge.Count("GetAnalysisSnapshot"));
        Assert.Equal(5, firstResult.GetProperty("bridgeCalls").GetInt32());

        var second = JsonDocument.Parse(
            await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None));
        var secondResult = second.RootElement.GetProperty("result");
        // A definitive unknown-method answer pins the individual path.
        Assert.Equal(0, bridge.Count("GetServerStatus"));
        Assert.Equal(1, bridge.Count("GetAnalysisSnapshot"));
        Assert.Equal(4, secondResult.GetProperty("bridgeCalls").GetInt32());
    }

    [Fact]
    public async Task Transient_batched_failure_retries_the_cheap_path()
    {
        var bridge = Individual(PlainStatus);
        bridge.Responses["GetAnalysisSnapshot"] =
            "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"busy\"}}";
        var live = Live(bridge);

        _ = await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);
        _ = await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);

        // Not a capability verdict: the second call tries the batched path again.
        Assert.Equal(2, bridge.Count("GetAnalysisSnapshot"));
        Assert.Equal(0, bridge.Count("GetServerStatus"));
    }

    [Fact]
    public async Task Batched_session_skips_the_status_probe_after_the_first_call()
    {
        var bridge = Individual(CapableStatus);
        bridge.Responses["GetAnalysisSnapshot"] = Ok(
            "{\"stateBefore\":" + PausedState + ",\"stateAfter\":" + PausedState + "," +
            "\"sections\":{\"context\":\"ctx\",\"callStack\":{\"frames\":[]}}}");
        var live = Live(bridge);

        var first = JsonDocument.Parse(
            await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None));
        // roundTripsSaved present means the batched path was taken.
        Assert.True(first.RootElement.GetProperty("result").TryGetProperty("roundTripsSaved", out _));
        // One batched call, no capability probe.
        Assert.Equal(1, first.RootElement.GetProperty("result").GetProperty("bridgeCalls").GetInt32());
        Assert.Equal(0, bridge.Count("GetServerStatus"));

        var second = JsonDocument.Parse(
            await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None));
        var secondResult = second.RootElement.GetProperty("result");
        Assert.True(secondResult.TryGetProperty("roundTripsSaved", out _));
        Assert.Equal(1, secondResult.GetProperty("bridgeCalls").GetInt32());
        Assert.Equal(0, bridge.Count("GetServerStatus"));
    }

    [Fact]
    public async Task Individual_path_folds_system_frames_by_default()
    {
        var bridge = Individual(PlainStatus);
        var raw = await Live(bridge).GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);

        using var document = JsonDocument.Parse(raw);
        var callStack = document.RootElement.GetProperty("result")
            .GetProperty("sections").GetProperty("callStack").GetString();
        Assert.NotNull(callStack);
        Assert.Contains("collapsed", callStack, StringComparison.Ordinal);
        Assert.Contains("kernel32.dll", callStack, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ntdll.dll!B", callStack, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Schema_defaults_status_off()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        var tool = server.ListTools().OfType<System.Text.Json.Nodes.JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "GetAnalysisSnapshot");
        var rule = (System.Text.Json.Nodes.JsonObject)tool["inputSchema"]!["properties"]!["includeStatus"]!;

        // The false default rides server-side: omitted still validates.
        Assert.Null(server.ValidateArguments("GetAnalysisSnapshot",
            System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>("{}")));
    }

    private sealed class SnapshotArgsBridge : IBridgeClient
    {
        public string LastSnapshotArgs { get; private set; } = "";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method == "GetAnalysisSnapshot")
            {
                LastSnapshotArgs = arguments?.GetRawText() ?? "";
                return Task.FromResult(Ok(
                    "{\"stateBefore\":" + PausedState + ",\"stateAfter\":" + PausedState + "," +
                    "\"sections\":{\"context\":\"ctx\",\"callStack\":{\"frames\":[]}}}"));
            }
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
        }
    }

    [Fact]
    public async Task Default_forwards_the_16byte_window_and_omits_readOnly()
    {
        var bridge = new SnapshotArgsBridge();
        var live = new LiveAnalysisTools(new AnalysisContext(bridge, new NullGhidra()));
        var raw = await live.GetAnalysisSnapshotAsync(Args("{}"), CancellationToken.None);

        Assert.Contains("\"instructionBytes\":16", bridge.LastSnapshotArgs, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(raw);
        var result = document.RootElement.GetProperty("result");
        Assert.True(result.TryGetProperty("roundTripsSaved", out _));
        Assert.False(result.TryGetProperty("readOnly", out _));
    }

    [Fact]
    public async Task Explicit_instructionBytes_64_still_requests_the_wide_window()
    {
        var bridge = new SnapshotArgsBridge();
        var live = new LiveAnalysisTools(new AnalysisContext(bridge, new NullGhidra()));
        var raw = await live.GetAnalysisSnapshotAsync(
            Args("{\"instructionBytes\":64}"), CancellationToken.None);

        Assert.Contains("\"instructionBytes\":64", bridge.LastSnapshotArgs, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(raw);
        Assert.True(document.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void SnapshotOptions_Read_applies_diet_defaults()
    {
        // Diet budgets live in executable code, not in advertised defaults:
        // omitted args must resolve to the pinned diet values.
        var options = LiveAnalysisTools.SnapshotOptions.Read(null);
        Assert.Equal(8, options.MaxFrames);
        Assert.Equal(16, options.BeforeBytes);
        Assert.Equal(16, options.InstructionBytes);
        Assert.Equal(64, options.StackBytes);
        Assert.Equal(8000, options.MaxChars);
        Assert.False(options.IncludeThreads);
        Assert.False(options.IncludeModules);
    }

    [Fact]
    public void Schema_advertises_16byte_default_with_2048_max()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive },
            new RecordingBridge());
        foreach (var name in new[] { "GetAnalysisSnapshot", "TraceUntil" })
        {
            var tool = server.ListTools().OfType<JsonObject>()
                .Single(t => t["name"]!.GetValue<string>() == name);
            var rule = (JsonObject)tool["inputSchema"]!["properties"]!["instructionBytes"]!;
            // The 16-byte default rides server-side; the advertised bounds stay.
            Assert.Equal(1, rule["minimum"]!.GetValue<int>());
            Assert.Equal(2048, rule["maximum"]!.GetValue<int>());
            Assert.Null(server.ValidateArguments(name,
                JsonSerializer.Deserialize<JsonElement>("{}")));
        }
        var snapshot = server.ListTools().OfType<JsonObject>()
            .Single(t => t["name"]!.GetValue<string>() == "GetAnalysisSnapshot");
        var description = snapshot["description"]!.GetValue<string>();
        Assert.Contains("~5 instructions", description, StringComparison.Ordinal);
        Assert.Contains("2048", description, StringComparison.Ordinal);
    }
}
