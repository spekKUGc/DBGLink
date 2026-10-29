using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

// Shared scripted/recorded bridge + Ghidra doubles.
//
// Moved verbatim from LiveDebuggerControlTests.cs (ScriptedBridge) and
// ToolExecutionTests.cs (RecordingBridge, NullGhidra, FailingGhidraControl)
// so the ~15 consuming suites share one definition instead of private
// copies. Class names are unchanged so call sites do not churn.
// No behavior change: same counting, same payloads, same thread-safety
// (ScriptedBridge is single-threaded script playback like before;
// RecordingBridge counts via Interlocked like before).

internal sealed class ScriptedBridge : IBridgeClient
{
    private readonly Dictionary<string, string> _responses = new(StringComparer.Ordinal);
    public readonly List<(string Method, string? ArgsJson)> Calls = [];

    public ScriptedBridge On(string method, string response)
    {
        _responses[method] = response;
        return this;
    }

    public static string Ok(string resultJson) => "{\"id\":1,\"ok\":true,\"result\":" + resultJson + "}";

    public static string Error(string code, string message) =>
        "{\"id\":1,\"ok\":false,\"error\":{\"code\":" + JsonSerializer.Serialize(code) +
        ",\"message\":" + JsonSerializer.Serialize(message) + "}}";

    public int RequestCount => Calls.Count;

    public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
    {
        Calls.Add((method, arguments?.GetRawText()));
        if (_responses.TryGetValue(method, out var response))
            return Task.FromResult(response);
        return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
    }
}

internal sealed class RecordingBridge : IBridgeClient
{
    private int _requestCount;
    public int RequestCount => Volatile.Read(ref _requestCount);
    public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _requestCount);
        return Task.FromResult("{\"id\":1,\"ok\":true}");
    }
}

internal sealed class NullGhidra : IGhidraClient
{
    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unavailable\",\"message\":\"test\"}}");
}

internal sealed class FailingGhidraControl : IGhidraControlClient
{
    public Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
        => Task.FromException<string>(new IOException("test Ghidra failure"));
}
