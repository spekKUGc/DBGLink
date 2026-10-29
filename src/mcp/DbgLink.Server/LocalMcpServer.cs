using DbgLink.Shared;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;

namespace DbgLink.Server;

internal sealed class LocalMcpServer : IDisposable
{
    private readonly ServerConfig _config;
    private readonly AnalysisSessionRegistry _sessions;
    private readonly GhidraOpenOperations _open;
    private readonly McpToolDispatcher _dispatcher;
    private readonly ToolRegistry _registry;
    private readonly ServerMetrics _metrics = new();
    private readonly TelemetryFileSink? _telemetry;
    private readonly ILoggerFactory _logging;
    private readonly List<Tool> _advertisedTools;
    private readonly bool _hasControl;
    private readonly CancellationTokenSource _lifetime = new();
    private int _stopped;
    private int _disposed;

    public LocalMcpServer(ServerConfig config, IBridgeClient bridge, IGhidraClient? ghidra = null,
        IGhidraControlClient? ghidraControl = null, string? checkpointPath = null)
    {
        _config = config;
        ghidra ??= new GhidraClient();
        ghidraControl ??= string.IsNullOrWhiteSpace(config.GhidraControlPipeName) ? null :
            new GhidraControlClient(config.GhidraControlPipeName,
                config.GhidraControlToken ?? throw new InvalidOperationException("The Ghidra control token is missing."));
        _hasControl = ghidraControl is not null;
        if (bridge is BridgeClient nativeBridge)
            nativeBridge.Telemetry = _metrics;
        if (ghidra is GhidraClient ghidraBridge)
            ghidraBridge.Telemetry = _metrics;
        _sessions = new AnalysisSessionRegistry(bridge, ghidra) { Telemetry = _metrics };
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(ghidraControl, _sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        _open = new GhidraOpenOperations(ghidraControl) { Telemetry = _metrics };
        var checkpoints = new CheckpointTools(new CheckpointStore(checkpointPath ?? DbgLinkConfigPath.GetCheckpointPath()));
        _registry = new ToolRegistry(context, checkpoints, live, investigation, new AddressMapping(context), _open, sessionControl);
        _advertisedTools = _registry.List(_config, _hasControl)
            .OfType<JsonObject>()
            .Select(metadata => JsonSerializer.Deserialize<Tool>(metadata.ToJsonString(), ToolJsonOptions)!)
            .ToList();
        _logging = LoggerFactory.Create(builder => builder.AddSimpleConsole());
        _dispatcher = new McpToolDispatcher(config, _registry, context, _sessions, _metrics, _hasControl,
            _logging.CreateLogger<McpToolDispatcher>());
        // Local LLM-readable cache: no commands needed, everything lands in
        // %LOCALAPPDATA%\DBGLink\telemetry\ (events-<pid>.log + digest.md).
        // Disabled with DBGLINK_TELEMETRY=0, relocated with DBGLINK_TELEMETRY_DIR.
        try
        {
            _telemetry = TelemetryFileSink.TryCreate(_metrics, _config.TelemetryDirectory);
            _metrics.FileSink = _telemetry;
            _telemetry?.LogEvent($"_server start profile={config.Profile} mutation={(config.AllowMutation ? 1 : 0)} annotation={(config.AllowAnnotation ? 1 : 0)} port={config.Port}");
        }
        catch { }
    }

    internal JsonArray ListTools() => _registry.List(_config, _hasControl);
    internal Task<CallToolResult> CallToolAsync(CallToolRequestParams request, CancellationToken token) => _dispatcher.CallAsync(request, token);
    internal JsonObject GetMetricsSnapshot(long after = 0)
    {
        var snapshot = _metrics.Snapshot(after);
        try
        {
            if (snapshot["sessions"] is JsonObject sessions)
                sessions["active"] = _sessions.ActiveCount;
            snapshot["ghidraOpenQueueDepth"] = _open.PendingCount;
            // Telemetry health: a sink that swallowed its failures silently
            // would be invisible otherwise.
            var health = _telemetry?.Health;
            snapshot["telemetry"] = new JsonObject
            {
                ["enabled"] = health?.Enabled ?? false,
                ["queuedLines"] = health?.QueuedLines ?? 0,
                ["droppedLines"] = health?.DroppedLines ?? 0,
                ["flushes"] = health?.Flushes ?? 0,
                ["rotations"] = health?.Rotations ?? 0,
                ["compressions"] = health?.Compressions ?? 0,
                ["flushErrors"] = health?.FlushErrors ?? 0,
                ["errors"] = health?.Errors ?? 0,
                ["lastError"] = health?.LastError,
                ["disableReason"] = health?.DisableReason.ToString() ?? TelemetryDisableReason.None.ToString(),
            };
            snapshot["config"] = new JsonObject
            {
                ["profile"] = _config.Profile.ToString(),
                ["allowMutation"] = _config.AllowMutation,
                ["allowAnnotation"] = _config.AllowAnnotation,
                ["maxConcurrentRequests"] = _config.MaxConcurrentRequests,
                ["maxQueuedOperations"] = _config.MaxQueuedOperations,
                ["defaultToolTimeoutMs"] = _config.DefaultToolTimeoutMs,
                ["maxRequestBodyBytes"] = _config.MaxRequestBodyBytes,
            };
        }
        catch { }
        return snapshot;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _stopped) != 0) return;
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.WebHost.UseUrls($"http://127.0.0.1:{_config.Port}");
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Limits.MaxRequestBodySize = _config.MaxRequestBodyBytes;
            // Loopback is shared by all local users. Bound sockets and slow
            // headers before the request reaches bearer-token validation.
            options.Limits.MaxConcurrentConnections = Math.Max(16, _config.MaxConcurrentRequests * 4);
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
        });
        builder.Services.AddMcpServer(options =>
        {
            options.ServerInfo = new Implementation { Name = "DBGLink", Version = typeof(LocalMcpServer).Assembly.GetName().Version!.ToString(3) };
        }).WithHttpTransport(options =>
        {
            options.SessionMode = HttpServerSessionMode.Stateless;
        }).WithListToolsHandler((_, _) => ValueTask.FromResult(new ListToolsResult
        {
            Tools = _advertisedTools
        })).WithCallToolHandler(async (request, token) =>
            await _dispatcher.CallAsync(request.Params!, token).ConfigureAwait(false));

        await using var app = builder.Build();
        app.UseMiddleware<McpRequestPolicy>(_config, _metrics);
        app.UseRouting();
        app.MapGet("/metrics", (long? after) => GetMetricsSnapshot(after ?? 0));
        app.MapMcp("/mcp");
        try { await app.RunAsync(lifetime.Token).ConfigureAwait(false); }
        finally { Stop(); }
    }

    private static readonly JsonSerializerOptions ToolJsonOptions = new(JsonSerializerDefaults.Web);

    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        _lifetime.Cancel();
        _open.Stop();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Stop();
        _dispatcher.Dispose();
        _sessions.Dispose();
        try { _telemetry?.Dispose(); } catch { }
        _logging.Dispose();
        _lifetime.Dispose();
    }
}
