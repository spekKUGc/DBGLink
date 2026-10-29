namespace DbgLink.Server;

internal sealed class AnalysisContext(IBridgeClient bridge, IGhidraClient ghidra)
{
    private readonly AsyncLocal<AnalysisSessionRuntime?> _active = new();
    public string AnalysisId => _active.Value?.AnalysisId ?? "default";
    public IBridgeClient Bridge => _active.Value?.Bridge ?? bridge;
    public IGhidraClient Ghidra => _active.Value?.Ghidra ?? ghidra;

    public async Task<string> ExecuteAsync(AnalysisSessionRuntime? session, Func<Task<string>> action)
    {
        var previous = _active.Value;
        try { _active.Value = session; return await action().ConfigureAwait(false); }
        finally { _active.Value = previous; }
    }
}
