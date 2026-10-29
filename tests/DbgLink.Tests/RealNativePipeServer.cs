using System.Buffers;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Tests;

/// <summary>
/// A real Win32 message-mode Named Pipe server simulating the x64dbg native bridge
/// (DbgLink.dp64 / NativePipeServer.cpp) over \\.\pipe\DbgLink.Control.{pid}.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RealNativePipeServer : IAsyncDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly int _pid;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _listenTask;
    private readonly Dictionary<string, Func<int, JsonElement?, string>> _handlers = new(StringComparer.Ordinal);
    private readonly object _lock = new();
    private int _requestCount;
    private Action<NamedPipeServerStream>? _nextConnectionFault;

    public int ProcessId => _pid;
    public string PipeName => _pipeName;
    public int RequestCount => Volatile.Read(ref _requestCount);

    public RealNativePipeServer(int? pid = null)
    {
        _pid = pid ?? (70000 + Random.Shared.Next(1000, 20000));
        _pipeName = $"DbgLink.Control.{_pid}";

        RegisterDefaultHandlers();
        _listenTask = Task.Run(ListenLoopAsync);
    }

    public void RegisterHandler(string method, Func<int, JsonElement?, string> handler)
    {
        lock (_lock)
        {
            _handlers[method] = handler;
        }
    }

    public void InjectFault(Action<NamedPipeServerStream> faultAction)
    {
        lock (_lock)
        {
            _nextConnectionFault = faultAction;
        }
    }

    private void RegisterDefaultHandlers()
    {
        RegisterHandler("ping", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":{_pid},\"debugging\":true,\"capabilities\":{{\"analysisSnapshot\":true}}}}");

        RegisterHandler("GetServerStatus", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":{_pid},\"debugging\":true,\"capabilities\":{{\"analysisSnapshot\":true}}}}");

        RegisterHandler("GetSnapshotState", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"debuggerPid\":{_pid},\"generation\":\"1\",\"debugging\":true,\"running\":false,\"threadId\":1,\"stableRead\":true}}}}");

        RegisterHandler("GetModuleRecords", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"modules\":[{{\"name\":\"test.exe\",\"base\":\"0x140000000\",\"end\":\"0x140050000\",\"path\":\"C:\\\\test.exe\"}}],\"truncated\":false}}}}");

        RegisterHandler("GetAllModulesFromMemMap", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"modules\":[{{\"name\":\"test.exe\",\"base\":\"0x140000000\",\"end\":\"0x140050000\",\"path\":\"C:\\\\test.exe\"}}],\"truncated\":false}}}}");

        RegisterHandler("GetCurrentContext", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"registers\":{{\"rip\":\"0x140001000\",\"rax\":\"0x0\",\"rbx\":\"0x1\",\"rsp\":\"0x7fffffff0000\",\"rbp\":\"0x7fffffff0010\"}},\"threadId\":1,\"status\":\"paused\"}}}}");

        RegisterHandler("GetAllRegisters", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"registers\":{{\"rip\":\"0x140001000\",\"rax\":\"0x0\",\"rbx\":\"0x1\",\"rcx\":\"0x2\",\"rdx\":\"0x3\",\"rsi\":\"0x4\",\"rdi\":\"0x5\",\"rsp\":\"0x7fffffff0000\",\"rbp\":\"0x7fffffff0010\",\"eflags\":\"0x246\"}}}}}}");

        RegisterHandler("GetAllActiveThreads", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"threads\":[{{\"threadId\":1,\"main\":true,\"entry\":\"0x140001000\",\"rip\":\"0x140001000\"}}],\"activeThreadId\":1}}}}");

        RegisterHandler("ListThreads", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"threads\":[{{\"threadId\":1,\"main\":true,\"entry\":\"0x140001000\",\"rip\":\"0x140001000\"}}],\"activeThreadId\":1}}}}");

        RegisterHandler("GetCallStack", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"frames\":[{{\"frame\":0,\"address\":\"0x140001000\",\"from\":\"0x140001000\",\"to\":\"0x140001000\",\"module\":\"test.exe\"}}]}}}}");

        RegisterHandler("GetBacktrace", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"frames\":[{{\"frame\":0,\"address\":\"0x140001000\",\"from\":\"0x140001000\",\"to\":\"0x140001000\",\"module\":\"test.exe\"}}]}}}}");

        RegisterHandler("ReadMemAtAddress", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"bytes\":\"48895C240848896C2410\",\"bytesRead\":10}}}}";
        });

        RegisterHandler("ReadMemoryChunk", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"bytes\":\"48895C240848896C2410\",\"bytesRead\":10}}}}";
        });

        RegisterHandler("ReadDismAtAddress", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"instructions\":[{{\"address\":\"{addr}\",\"instruction\":\"sub rsp, 28h\",\"size\":4}}]}}}}";
        });

        RegisterHandler("ReadDisassemblyChunk", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"instructions\":[{{\"address\":\"{addr}\",\"instruction\":\"sub rsp, 28h\",\"size\":4}}]}}}}";
        });

        RegisterHandler("EvaluateExpression", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"value\":\"0x140001000\",\"valueHex\":\"0x140001000\",\"valueDecimal\":5368713216}}}}");

        RegisterHandler("GetMemoryMap", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"pages\":[{{\"base\":\"0x140000000\",\"size\":\"0x1000\",\"protection\":\"PAGE_READONLY\",\"info\":\"HEADER\"}},{{\"base\":\"0x140001000\",\"size\":\"0x10000\",\"protection\":\"PAGE_EXECUTE_READ\",\"info\":\".text\"}}]}}}}");

        RegisterHandler("FindBytePatternInModule", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"matches\":[\"0x140001000\"]}}}}");

        RegisterHandler("FindStringInModule", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"strings\":[{{\"address\":\"0x140002000\",\"value\":\"test_string\",\"type\":\"ascii\"}}]}}}}");

        RegisterHandler("FindInterestingStrings", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"strings\":[{{\"address\":\"0x140002000\",\"value\":\"test_string\",\"type\":\"ascii\"}}]}}}}");

        RegisterHandler("GetXrefs", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"xrefs\":[{{\"address\":\"0x140001050\",\"type\":\"call\"}}]}}}}");

        RegisterHandler("InspectAddressStructure", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"fields\":[{{\"offset\":0,\"name\":\"magic\",\"value\":\"0x5A4D\"}}]}}}}";
        });

        RegisterHandler("TraceStringReferences", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"references\":[{{\"address\":\"0x140001050\",\"instruction\":\"lea rcx, [0x140002000]\"}}]}}}}");

        RegisterHandler("ReadStringAtAddress", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140002000" : "0x140002000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"value\":\"hello_world\",\"length\":11}}}}";
        });

        RegisterHandler("OpenDebugTarget", (id, args) =>
        {
            var target = args?.TryGetProperty("path", out var p) == true ? p.GetString() ?? "target.exe" : "target.exe";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"openDebugTarget\",\"target\":{JsonSerializer.Serialize(target)},\"pid\":{_pid}}}}}";
        });

        RegisterHandler("SetBreakpoint", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"setBreakpoint\",\"address\":\"{addr}\",\"kind\":\"soft\"}}}}";
        });

        RegisterHandler("ClearBreakpoint", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"clearBreakpoint\",\"address\":\"{addr}\"}}}}";
        });

        RegisterHandler("ListBreakpoints", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"breakpoints\":[{{\"address\":\"0x140001000\",\"enabled\":true,\"kind\":\"soft\"}}]}}}}");

        RegisterHandler("StepInto", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"stepInto\",\"status\":\"paused\"}}}}");

        RegisterHandler("StepOver", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"stepOver\",\"status\":\"paused\"}}}}");

        RegisterHandler("StepOut", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"stepOut\",\"status\":\"paused\"}}}}");

        RegisterHandler("RunDebugger", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"runDebugger\",\"status\":\"running\"}}}}");

        RegisterHandler("PauseDebugger", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"pauseDebugger\",\"status\":\"paused\"}}}}");

        RegisterHandler("ContinueDebugger", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"action\":\"continueDebugger\",\"status\":\"running\"}}}}");

        RegisterHandler("SetRegister", (id, args) =>
        {
            var reg = args?.TryGetProperty("register", out var r) == true ? r.GetString() ?? "rax" : "rax";
            var val = args?.TryGetProperty("value", out var v) == true ? v.GetString() ?? "0x1" : "0x1";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"register\":\"{reg}\",\"value\":\"{val}\"}}}}";
        });

        RegisterHandler("WriteMemory", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"bytesWritten\":4}}}}";
        });

        RegisterHandler("CallFunction", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"returnValue\":\"0x0\"}}}}";
        });

        RegisterHandler("SwitchThread", (id, args) =>
        {
            var tid = args?.TryGetProperty("threadId", out var t) == true ? t.GetInt32() : 1;
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"threadId\":{tid},\"switched\":true}}}}";
        });

        RegisterHandler("SetLabel", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"success\":true}}}}";
        });

        RegisterHandler("SetComment", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"success\":true}}}}";
        });

        RegisterHandler("SetBookmark", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"{addr}\",\"success\":true}}}}";
        });

        RegisterHandler("GetAnalysisSnapshot", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"modules\":[{{\"name\":\"test.exe\",\"base\":\"0x140000000\",\"end\":\"0x140050000\",\"path\":\"C:\\\\test.exe\"}}],\"registers\":{{\"rip\":\"0x140001000\",\"rax\":\"0x0\",\"rbx\":\"0x1\",\"rsp\":\"0x7fffffff0000\",\"rbp\":\"0x7fffffff0010\"}},\"threads\":[{{\"threadId\":1,\"main\":true,\"rip\":\"0x140001000\"}}],\"callStack\":[{{\"frame\":0,\"address\":\"0x140001000\",\"module\":\"test.exe\"}}]}}}}");
    }

    private async Task ListenLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? serverStream = null;
            try
            {
                serverStream = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

                await serverStream.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);

                // Handle this connection in a background task so listen loop can immediately accept next connection
                _ = HandleConnectionAsync(serverStream, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                serverStream?.Dispose();
                break;
            }
            catch
            {
                serverStream?.Dispose();
                await Task.Delay(20, _cts.Token).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                Action<NamedPipeServerStream>? fault = null;
                lock (_lock)
                {
                    if (_nextConnectionFault is not null)
                    {
                        fault = _nextConnectionFault;
                        _nextConnectionFault = null;
                    }
                }

                if (fault is not null)
                {
                    fault(pipe);
                    return;
                }

                Interlocked.Increment(ref _requestCount);

                var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
                using var ms = new MemoryStream();
                try
                {
                    while (true)
                    {
                        var read = await pipe.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                        if (read == 0) break;
                        ms.Write(buffer, 0, read);
                        if (pipe.IsMessageComplete) break;
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }

                if (ms.Length == 0) return;

                var requestBytes = ms.ToArray();
                var newlineIdx = Array.IndexOf(requestBytes, (byte)'\n');
                var length = newlineIdx >= 0 ? newlineIdx : requestBytes.Length;
                var requestJson = StrictUtf8.GetString(requestBytes, 0, length).Trim();

                string responseText;
                try
                {
                    using var doc = JsonDocument.Parse(requestJson);
                    var root = doc.RootElement;
                    var id = root.TryGetProperty("id", out var idProp) && idProp.TryGetInt32(out var parsedId) ? parsedId : 1;
                    var method = root.TryGetProperty("method", out var mProp) ? mProp.GetString() ?? "" : "";
                    JsonElement? args = root.TryGetProperty("params", out var pProp) ? pProp.Clone() : null;

                    Func<int, JsonElement?, string>? handler = null;
                    lock (_lock)
                    {
                        _handlers.TryGetValue(method, out handler);
                    }

                    if (handler is not null)
                    {
                        responseText = handler(id, args);
                    }
                    else
                    {
                        responseText = $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":\"unknown_method\",\"message\":\"Unknown bridge method {method}\"}}}}";
                    }
                }
                catch (Exception ex)
                {
                    responseText = $"{{\"id\":1,\"ok\":false,\"error\":{{\"code\":\"invalid_request\",\"message\":{JsonSerializer.Serialize(ex.Message)}}}}}";
                }

                if (!responseText.EndsWith('\n'))
                    responseText += "\n";

                var responseBytes = StrictUtf8.GetBytes(responseText);
                await pipe.WriteAsync(responseBytes, ct).ConfigureAwait(false);
                await pipe.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();

        // Poke the pipe with a quick connect to break any pending WaitForConnectionAsync if needed
        try
        {
            using var pokeClient = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.None);
            pokeClient.Connect(10);
        }
        catch { }

        try { await _listenTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
        _cts.Dispose();
    }
}
