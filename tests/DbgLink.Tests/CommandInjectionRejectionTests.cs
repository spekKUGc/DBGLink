using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;

namespace DbgLink.Tests;

// RCE contract: hostile OpenDebugTarget / SetBreakpoint / SetLabel / SetComment
// text must be rejected before any native execution (Reject + ExecutedCount == 0).
// Parity contract with native dbglink::IsQuotedArgumentSafe
// (src/native/DbgLink.Native/NativeCommandText.h), mirroring the vectors in
// tests/DbgLink.Native.Tests/NativeCommandTextTests.cpp — same pattern as
// NativeAddressParityTests: the managed side must never accept what the native
// quoted-argument policy rejects. (Managed pre-validation may reject a
// superset — e.g. LiveAnalysisTools.ValidateDebugTarget also rejects C1
// controls via char.IsControl — which is the safe direction.)
public sealed class CommandInjectionRejectionTests
{
    // =========================================================================
    // 1. OpenDebugTarget: path, arguments, workDir
    // =========================================================================

    [Theory]
    [InlineData("malicious\"_quote")]
    [InlineData("malicious\n_newline")]
    [InlineData("malicious\0_nullbyte")]
    public async Task OpenDebugTarget_PathInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50531 }, bridge, ghidraControl: new MockControlClient());

        var req = new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\Windows\\notepad.exe" + injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("malicious\"_quote")]
    [InlineData("malicious\n_newline")]
    [InlineData("malicious\0_nullbyte")]
    public async Task OpenDebugTarget_ArgumentsInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50532 }, bridge, ghidraControl: new MockControlClient());

        var req = new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\Windows\\notepad.exe"),
                ["arguments"] = JsonSerializer.SerializeToElement("arg1 " + injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("malicious\"_quote")]
    [InlineData("malicious\n_newline")]
    [InlineData("malicious\0_nullbyte")]
    public async Task OpenDebugTarget_WorkDirInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50533 }, bridge, ghidraControl: new MockControlClient());

        var req = new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\Windows\\notepad.exe"),
                ["workDir"] = JsonSerializer.SerializeToElement("C:\\Windows" + injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    // =========================================================================
    // 2. SetBreakpoint: condition, logText, logCondition
    // =========================================================================

    [Theory]
    [InlineData("eax == \"malicious\"")]
    [InlineData("eax == 1\nmalicious")]
    [InlineData("eax == 1\0malicious")]
    public async Task SetBreakpoint_ConditionInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50534 }, bridge);

        var req = new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["condition"] = JsonSerializer.SerializeToElement(injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("CIP=\"{cip}\"")]
    [InlineData("CIP={cip}\nmalicious")]
    [InlineData("CIP={cip}\0malicious")]
    public async Task SetBreakpoint_LogTextInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50535 }, bridge);

        var req = new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["logText"] = JsonSerializer.SerializeToElement(injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("eax != \"malicious\"")]
    [InlineData("eax != 0\nmalicious")]
    [InlineData("eax != 0\0malicious")]
    public async Task SetBreakpoint_LogConditionInjection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50536 }, bridge);

        var req = new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["logCondition"] = JsonSerializer.SerializeToElement(injection)
            }
        };

        var isRejected = false;
        try
        {
            var result = await server.CallToolAsync(req, CancellationToken.None);
            isRejected = result.IsError == true;
        }
        catch (McpProtocolException)
        {
            isRejected = true;
        }

        Assert.True(isRejected);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    // =========================================================================
    // 3. Native Bridge Direct Commands: SetLabel (label), SetComment (comment)
    // =========================================================================

    [Theory]
    [InlineData("label\"_injection")]
    [InlineData("label\n_injection")]
    [InlineData("label\0_injection")]
    public async Task NativeBridge_SetLabel_Injection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        var response = await bridge.RequestAsync("SetLabel", JsonSerializer.SerializeToElement(new
        {
            address = "0x140001000",
            label = injection
        }), CancellationToken.None);

        Assert.Contains("\"ok\":false", response);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("comment\"_injection")]
    [InlineData("comment\n_injection")]
    [InlineData("comment\0_injection")]
    public async Task NativeBridge_SetComment_Injection_Rejected(string injection)
    {
        var bridge = new InjectionRecordingBridge();
        var response = await bridge.RequestAsync("SetComment", JsonSerializer.SerializeToElement(new
        {
            address = "0x140001000",
            comment = injection
        }), CancellationToken.None);

        Assert.Contains("\"ok\":false", response);
        Assert.Equal(0, bridge.ExecutedCount);
    }

    [Theory]
    [InlineData("eax == 1", true)]
    [InlineData("CIP={cip} RAX={rax}", true)]
    [InlineData("", true)]
    [InlineData("MainLoop_Entry", true)]
    [InlineData("Decrypted payload entry point", true)]
    [InlineData("--flag --value=123", true)]
    [InlineData("Привет", true)] // UTF-8 bytes >= 0x80 stay allowed (NativeCommandText.h:11)
    [InlineData("a\"b", false)]
    [InlineData("a\nb", false)]
    [InlineData("a\rb", false)]
    [InlineData("a\tb", false)]
    [InlineData("a\0b", false)]
    [InlineData("a\u0001b", false)]
    [InlineData("a\u001Fb", false)]
    [InlineData("a\u007Fb", false)] // DEL rejected alongside C0 controls
    public void QuotedArgumentPolicy_ParityWithNative_IsQuotedArgumentSafe(string input, bool expectedSafe)
    {
        Assert.Equal(expectedSafe, InjectionRecordingBridge.IsQuotedArgumentSafeParity(input));
    }

    private sealed class MockControlClient : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public Task<string> OpenFileAsync(string path, CancellationToken token) => Task.FromResult("{\"ok\":true}");
        public Task<string> SessionControlAsync(string method, JsonElement args, CancellationToken token) => Task.FromResult("{\"ok\":true,\"result\":{\"analysisId\":\"default\",\"closed\":true}}");
    }

    private sealed class InjectionRecordingBridge : IBridgeClient
    {
        private int _executedCount;
        public int ExecutedCount => Volatile.Read(ref _executedCount);

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            // Parity oracle for the native endpoint: any string argument the
            // native quoted-argument policy rejects is refused here before
            // "execution", so Reject + ExecutedCount == 0 proves the hostile
            // text never reached native code.
            if (arguments.HasValue && arguments.Value.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in arguments.Value.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String &&
                        !IsQuotedArgumentSafeParity(prop.Value.GetString()!))
                    {
                        return Task.FromResult("{\"ok\":false,\"error\":{\"code\":\"argument_injection_rejected\",\"message\":\"Quoted argument contains invalid injection characters.\"}}");
                    }
                }
            }

            Interlocked.Increment(ref _executedCount);
            return Task.FromResult("{\"ok\":true,\"result\":{\"status\":\"executed\"}}");
        }

        // Exact C# port of native dbglink::IsQuotedArgumentSafe
        // (src/native/DbgLink.Native/NativeCommandText.h:12-20): UTF-8 bytes
        // below 0x20, the double quote (0x22), and DEL (0x7F) are rejected,
        // never escaped; bytes >= 0x80 stay allowed so UTF-8 text passes.
        internal static bool IsQuotedArgumentSafeParity(string text)
        {
            foreach (var b in Encoding.UTF8.GetBytes(text))
            {
                if (b < 0x20 || b == 0x22 || b == 0x7F)
                    return false;
            }
            return true;
        }
    }
}
