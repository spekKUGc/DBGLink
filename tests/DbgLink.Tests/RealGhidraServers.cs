using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DbgLink.Launcher.Core;

namespace DbgLink.Tests;

/// <summary>
/// Really opened Ghidra servers:
/// 1. Real Win32 Named Pipe server for GhidraControlClient (\\.\pipe\DbgLink.GhidraControl.{token})
/// 2. Real TCP server for GhidraClient (127.0.0.1:{port}) with valid endpoint discovery file.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RealGhidraServers : IAsyncDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly string _token;
    private readonly string _pipeName;
    private readonly GhidraControlPipeServer _controlPipeServer;
    private readonly string _endpointDirectory;
    private readonly string _endpointFilePath;
    private readonly TcpListener _tcpListener;
    private readonly int _tcpPort;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _tcpListenTask;
    private readonly Dictionary<string, Func<int, JsonElement?, string>> _tcpHandlers = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public string Token => _token;
    public string PipeName => _pipeName;
    public int TcpPort => _tcpPort;
    public string EndpointDirectory => _endpointDirectory;

    public RealGhidraServers(string? nativePipeName = null)
    {
        _token = "ghidra_control_token_32_characters_long_min";
        _pipeName = $"DbgLink.GhidraControl.{Guid.NewGuid():N}";
        var targetNativePipe = nativePipeName ?? "DbgLink.Control.70001";

        _endpointDirectory = Path.Combine(Path.GetTempPath(), "dbglink_ghidra_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_endpointDirectory);

        _controlPipeServer = new GhidraControlPipeServer(
            _pipeName,
            _token,
            (path, _) => Task.FromResult(new GhidraOpenResult(true, path, true, "session_ghidra", targetNativePipe, _endpointDirectory)))
        {
            SessionControl = (method, req, _) =>
            {
                if (method == "ListAnalysisSessions")
                {
                    return Task.FromResult(new System.Text.Json.Nodes.JsonObject
                    {
                        ["ok"] = true,
                        ["result"] = new System.Text.Json.Nodes.JsonObject
                        {
                            ["sessions"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject
                            {
                                ["analysisId"] = "default",
                                ["program"] = "test.exe",
                                ["active"] = true
                            })
                        }
                    });
                }
                if (method == "SwitchDebugger")
                {
                    return Task.FromResult(new System.Text.Json.Nodes.JsonObject
                    {
                        ["ok"] = true,
                        ["result"] = new System.Text.Json.Nodes.JsonObject
                        {
                            ["analysisId"] = "default",
                            ["nativePipeName"] = targetNativePipe,
                            ["architecture"] = "x64",
                            ["debuggerPid"] = 70001,
                            ["changed"] = false
                        }
                    });
                }
                return Task.FromResult(new System.Text.Json.Nodes.JsonObject
                {
                    ["ok"] = true,
                    ["result"] = new System.Text.Json.Nodes.JsonObject
                    {
                        ["closed"] = true,
                        ["analysisId"] = "default"
                    }
                });
            }
        };
        _controlPipeServer.Start();

        _tcpListener = new TcpListener(IPAddress.Loopback, 0);
        _tcpListener.Start();
        _tcpPort = ((IPEndPoint)_tcpListener.LocalEndpoint).Port;

        _endpointFilePath = Path.Combine(_endpointDirectory, $"ghidra-bridge-{_tcpPort}.json");
        var endpointJson = JsonSerializer.Serialize(new
        {
            host = "127.0.0.1",
            port = _tcpPort,
            token = _token,
            protocolVersion = 1
        });
        File.WriteAllText(_endpointFilePath, endpointJson, StrictUtf8);

        RegisterDefaultTcpHandlers();
        _tcpListenTask = Task.Run(ListenTcpLoopAsync);
    }

    public void RegisterTcpHandler(string method, Func<int, JsonElement?, string> handler)
    {
        lock (_lock)
        {
            _tcpHandlers[method] = handler;
        }
    }

    private void RegisterDefaultTcpHandlers()
    {
        RegisterTcpHandler("status", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"connected\":true,\"program\":\"test.exe\",\"imageBase\":\"0x140000000\"}}}}");

        RegisterTcpHandler("InspectFunction", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"function\":\"main\",\"start\":\"0x140001000\",\"size\":64,\"decomp\":\"int main() {{ return 0; }}\",\"symbols\":[]}}}}");

        RegisterTcpHandler("DecompileModule", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"functions\":[{{\"name\":\"main\",\"address\":\"0x140001000\",\"decomp\":\"int main() {{ return 0; }}\"}}]}}}}");

        RegisterTcpHandler("ListFunctions", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"functions\":[{{\"name\":\"main\",\"entry\":\"0x140001000\"}}]}}}}");

        RegisterTcpHandler("ListImports", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"imports\":[{{\"library\":\"KERNEL32.dll\",\"function\":\"ExitProcess\"}}]}}}}");

        RegisterTcpHandler("ListExports", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"exports\":[{{\"name\":\"main\",\"address\":\"0x140001000\"}}]}}}}");

        RegisterTcpHandler("XrefsTo", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"xrefs\":[{{\"from\":\"0x140001050\",\"type\":\"CALL\"}}]}}}}");

        RegisterTcpHandler("ReadStaticBytes", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"bytes\":\"48895C2408\",\"address\":\"0x140001000\"}}}}");

        RegisterTcpHandler("DumpStrings", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"strings\":[{{\"address\":\"0x140002000\",\"string\":\"Hello Ghidra\"}}]}}}}");

        RegisterTcpHandler("RenameFunction", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"success\":true}}}}");

        RegisterTcpHandler("SetFunctionComment", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"success\":true}}}}");

        RegisterTcpHandler("RenameVariable", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"success\":true}}}}");

        RegisterTcpHandler("SetVariableType", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"success\":true}}}}");

        RegisterTcpHandler("SaveProgram", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"operation\":\"SaveProgram\",\"saved\":true,\"hadUnsavedChanges\":true}}}}");
    }

    private async Task ListenTcpLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var client = await _tcpListener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                _ = HandleTcpClientAsync(client, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                if (_cts.IsCancellationRequested) break;
                await Task.Delay(20, _cts.Token).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        await using (var network = client.GetStream())
        {
            try
            {
                using var reader = new StreamReader(network, StrictUtf8, leaveOpen: true);
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(line)) return;

                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var id = root.TryGetProperty("id", out var idProp) && idProp.TryGetInt32(out var parsedId) ? parsedId : 1;
                var method = root.TryGetProperty("method", out var mProp) ? mProp.GetString() ?? "" : "";
                var token = root.TryGetProperty("token", out var tProp) ? tProp.GetString() : null;
                JsonElement? args = root.TryGetProperty("params", out var pProp) ? pProp.Clone() : null;

                string responseText;
                if (!string.Equals(token, _token, StringComparison.Ordinal))
                {
                    responseText = $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":\"unauthorized\",\"message\":\"Invalid Ghidra token.\"}}}}\n";
                }
                else
                {
                    Func<int, JsonElement?, string>? handler = null;
                    lock (_lock)
                    {
                        _tcpHandlers.TryGetValue(method, out handler);
                    }

                    if (handler is not null)
                    {
                        responseText = handler(id, args);
                    }
                    else
                    {
                        responseText = $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":\"unknown_method\",\"message\":\"Unknown Ghidra method {method}\"}}}}";
                    }

                    if (!responseText.EndsWith('\n'))
                        responseText += "\n";
                }

                var responseBytes = StrictUtf8.GetBytes(responseText);
                await network.WriteAsync(responseBytes, ct).ConfigureAwait(false);
                await network.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _tcpListener.Stop();
        try { await _tcpListenTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
        await _controlPipeServer.DisposeAsync();

        try
        {
            if (File.Exists(_endpointFilePath))
                File.Delete(_endpointFilePath);
            if (Directory.Exists(_endpointDirectory))
                Directory.Delete(_endpointDirectory, true);
        }
        catch { }

        _cts.Dispose();
    }
}
