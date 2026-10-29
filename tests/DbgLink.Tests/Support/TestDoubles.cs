using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

// Shared merge-test doubles (RA + RB tracks).
//
// Extracted from the three verbatim stub copies that used to live in
// ToolMergeFuzzTests / ToolMergePerfTests / ToolMergePhase3Tests
// (RaceBridge / RaceGhidra / StubControl, ToolMerge*Tests.cs:15-54):
// a drift in any single copy used to produce a false perf/fuzz signal,
// so there is exactly one definition now. ToolMergePhase3Tests is owned
// by zone C (its third StubControl copy goes away with that file); the
// Fuzz and Perf suites both consume the doubles below.
//
// Thread-safety contract: the merge suites hammer these recorders from
// 20-60 parallel tool calls, so every recorder serializes on a private
// gate and snapshots under the same gate. Consumers must only observe
// via the snapshot properties (RequestCount / Methods / Calls), never
// via the live lists.

/// <summary>
/// Thread-safe counting native-bridge double. Records every
/// (method, argsJson) pair; answers every method with a minimal
/// ok:true envelope unless the method was armed via <see cref="FailOn"/>.
/// </summary>
internal sealed class MergeRaceBridge : IBridgeClient
{
    private readonly object _gate = new();
    private readonly List<(string Method, string? ArgsJson)> _calls = new();
    private readonly HashSet<string> _failMethods = new(StringComparer.Ordinal);

    public int RequestCount { get { lock (_gate) return _calls.Count; } }
    public IReadOnlyList<string> Methods { get { lock (_gate) return _calls.Select(c => c.Method).ToArray(); } }
    public IReadOnlyList<(string Method, string? ArgsJson)> Calls { get { lock (_gate) return _calls.ToArray(); } }

    public MergeRaceBridge FailOn(params string[] methods)
    {
        lock (_gate) foreach (var method in methods) _failMethods.Add(method);
        return this;
    }

    public Task<bool> PingAsync(CancellationToken token) => Task.FromResult(true);

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
    {
        lock (_gate) _calls.Add((method, arguments?.GetRawText()));
        lock (_gate)
        {
            if (_failMethods.Contains(method))
                return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"step_failed\",\"message\":\"injected step error\"}}");
        }
        return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
    }
}

/// <summary>
/// Thread-safe counting Ghidra-static double. Records (method, argsJson)
/// in call order so fan-out tests can pin both the method sequence
/// (RenameVariable then SetVariableType) and the chained argument shape
/// (the retype carries variable=name, not the pre-rename name).
/// </summary>
internal sealed class MergeRaceGhidra : IGhidraClient
{
    private readonly object _gate = new();
    private readonly List<(string Method, string? ArgsJson)> _calls = new();

    public int RequestCount { get { lock (_gate) return _calls.Count; } }
    public IReadOnlyList<string> Methods { get { lock (_gate) return _calls.Select(c => c.Method).ToArray(); } }
    public IReadOnlyList<(string Method, string? ArgsJson)> Calls { get { lock (_gate) return _calls.ToArray(); } }

    public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken token)
    {
        lock (_gate) _calls.Add((method, arguments?.GetRawText()));
        return Task.FromResult("{\"ok\":true,\"result\":{}}");
    }
}

/// <summary>Minimal session-control double: control plane present, open succeeds.</summary>
internal sealed class MergeStubControl : IGhidraControlClient
{
    public bool SupportsSessionControl => true;
    public Task<string> OpenFileAsync(string path, CancellationToken token) => Task.FromResult("{\"ok\":true}");
}
