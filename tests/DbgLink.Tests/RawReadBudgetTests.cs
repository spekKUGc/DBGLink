using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
namespace DbgLink.Tests;

/// <summary>
/// Token budget for raw byte reads: a single ReadMemAtAddress / ReadStaticBytes
/// call must stay bounded. Before the 4096-byte cap, byteCount=65536 produced a
/// ~393KB hex dump in one response. Every number below is measured
/// over the real wire stack (Kestrel HTTP + named pipe / TCP); token figures
/// are real cl100k_base BPE counts (see TokenCounter).
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class RawReadBudgetTests
{
    private readonly ITestOutputHelper _output;

    public RawReadBudgetTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Test-fixture hex dump in the native FormatHexDump shape (16 bytes/line).
    /// NOTE (parity): native dbglink::FormatHexDump
    /// (src/native/DbgLink.Native/NativeDebuggerQueries.cpp:62-94) renders the
    /// address with HexAddress — "0x" plus 16 zero-padded uppercase digits on
    /// x64 (src/native/DbgLink.Native/NativeHexFormat.cpp:5-17). This fixture
    /// keeps the short "0x140001000" prefix so the budget numbers below stay
    /// put; the native shape is strictly longer per line, and
    /// HexDump_NativeShape_StaysWithinBudget pins the same bound for it.
    /// </summary>
    private static string HexDump(int byteCount)
    {
        var sb = new StringBuilder(byteCount / 16 * 86);
        for (var offset = 0; offset < byteCount; offset += 16)
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append($"0x140001000");
            sb.Append("  ");
            var line = Math.Min(16, byteCount - offset);
            for (var i = 0; i < line; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append("8B");
            }
            sb.Append(new string(' ', 47 - (line * 3 - 1)));
            sb.Append("  ");
            sb.Append(new string('.', line));
        }
        return sb.ToString();
    }

    [Fact]
    public async Task ReadMem_MaxSingleRead_IsBoundedOverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var dump = HexDump(4096);
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, args) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"0x140001000\",\"bytes\":{JsonSerializer.Serialize(dump)},\"bytesRead\":4096}}}}");

        var text = TextOf(await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new { address = "0x140001000", byteCount = 4096 }));
        _output.WriteLine($"READMEM max chars={text.Length:N0} tokens~{Tok(text):N0} (old 64KB ceiling ~393KB)");
        Assert.Contains("0x140001000", text);
        Assert.True(text.Length < 30_000, $"4096-byte read must stay under 30KB, got {text.Length}");
    }

    [Fact]
    public async Task ReadMem_Oversize_IsRejectedBeforeBackend()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var before = harness.NativePipeServer.RequestCount;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("ReadMemAtAddress",
                new { address = "0x140001000", byteCount = 65536 }));
        _output.WriteLine($"READMEM rejected: {error.Message}");
        Assert.Contains("byteCount", error.Message);
        Assert.Equal(before, harness.NativePipeServer.RequestCount);
    }

    [Fact]
    public async Task ReadStatic_MaxSingleRead_IsBoundedOverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var hex = new string('A', 8192); // 4096 bytes as hex
        harness.Ghidra.RegisterTcpHandler("ReadStaticBytes", (id, _) =>
            $"{{\"id\":{id},\"ok\":true,\"result\":{{\"address\":\"0x140001000\",\"length\":4096,\"hex\":\"{hex}\"}}}}");

        var text = TextOf(await harness.CallToolOverWireAsync("ReadStaticBytes",
            new { address = "0x140001000", length = 4096 }));
        _output.WriteLine($"READSTATIC max chars={text.Length:N0} tokens~{Tok(text):N0} (old 32KB ceiling ~65KB)");
        Assert.Contains(hex[..64], text);
        Assert.True(text.Length < 12_000, $"4096-byte static read must stay under 12KB, got {text.Length}");
    }

    [Fact]
    public async Task ReadStatic_Oversize_IsRejectedBySchema()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge(), new NullGhidra());
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            "{\"address\":\"0x140001000\",\"length\":32769}")!;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = "ReadStaticBytes", Arguments = arguments },
            CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        // The new bridge max is 32768: the boundary value itself validates.
        Assert.Null(server.ValidateArguments("ReadStaticBytes",
            JsonSerializer.Deserialize<JsonElement>("{\"address\":\"0x140001000\",\"length\":32768}")));
    }

    // =========================================================================
    // Parity with native dbglink::HexAddress / FormatHexDump
    // (src/native/DbgLink.Native/NativeHexFormat.cpp:5-17,
    //  src/native/DbgLink.Native/NativeDebuggerQueries.cpp:62-94),
    // same pattern as NativeAddressParityTests: pin the managed expectation
    // to the native wire shape instead of copying it by hand.
    // =========================================================================

    // Exact C# port of native HexAddress on x64: "0x" plus 16 zero-padded
    // uppercase digits (sizeof(uintptr_t)*2, NativeHexFormat.cpp:8).
    private static string NativeHexAddress(ulong address) => $"0x{address:X16}";

    // Exact C# port of native FormatHexDump for one byte array: 16 bytes per
    // line, HexAddress + two spaces + uppercase spaced hex padded to 47 chars
    // + two spaces + ASCII (printable 32..126 verbatim, else '.').
    private static string NativeHexDump(ulong baseAddress, byte[] data)
    {
        const string digits = "0123456789ABCDEF";
        var sb = new StringBuilder();
        for (var offset = 0; offset < data.Length; offset += 16)
        {
            if (sb.Length > 0) sb.Append('\n');
            var count = Math.Min(16, data.Length - offset);
            sb.Append(NativeHexAddress(baseAddress + (ulong)offset));
            sb.Append("  ");
            var hexStart = sb.Length;
            for (var i = 0; i < count; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(digits[data[offset + i] >> 4]);
                sb.Append(digits[data[offset + i] & 0x0F]);
            }
            sb.Append(new string(' ', 47 - (sb.Length - hexStart)));
            sb.Append("  ");
            for (var i = 0; i < count; i++)
            {
                var b = data[offset + i];
                sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }
        }
        return sb.ToString();
    }

    [Theory]
    [InlineData(0UL, "0x0000000000000000")]
    [InlineData(0x140001000UL, "0x0000000140001000")]
    [InlineData(0xFFFFFFFFUL, "0x00000000FFFFFFFF")]
    [InlineData(0xFFFFFFFFFFFFFFFFUL, "0xFFFFFFFFFFFFFFFF")]
    public void HexAddress_ParityWithNative_HexAddress(ulong address, string expected)
    {
        Assert.Equal(expected, NativeHexAddress(address));
    }

    [Fact]
    public void HexDump_ParityWithNative_FormatHexDump_ExactLine()
    {
        // 6 bytes mixing printable (0x48 'H', 0x41 'A', 0x20 ' '),
        // non-printable (0x8B, 0x00) and DEL (0x7F): hex field "48 8B 00 41
        // 7F 20" is 17 chars, padded with 30 spaces to the native width 47;
        // ASCII maps to "H..A. " (0x20 space stays verbatim per native rule).
        var dump = NativeHexDump(0x140001000UL, new byte[] { 0x48, 0x8B, 0x00, 0x41, 0x7F, 0x20 });
        var expected = "0x0000000140001000  48 8B 00 41 7F 20" + new string(' ', 30) + "  H..A. ";
        Assert.Equal(expected, dump);
    }

    [Fact]
    public void HexDump_ParityWithNative_FormatHexDump_Shape()
    {
        var data = new byte[20];
        for (var i = 0; i < data.Length; i++) data[i] = 0x8B;
        var lines = NativeHexDump(0x140001000UL, data).Split('\n');
        Assert.Equal(2, lines.Length); // ceil(20/16)
        // Full 16-byte line: 18 (address) + 2 + 47 (hex) + 2 + 16 (ascii).
        Assert.Equal(18 + 2 + 47 + 2 + 16, lines[0].Length);
        Assert.StartsWith("0x0000000140001000  ", lines[0]);
        Assert.StartsWith("0x0000000140001010  ", lines[1]); // address + 16
        Assert.Equal(new string('.', 16), lines[0][(18 + 2 + 47 + 2)..]);
    }

    [Fact]
    public void HexDump_NativeShape_StaysWithinBudget()
    {
        // The native zero-padded shape is longer per line than the short
        // fixture above; the 4096-byte budget bound must hold for it too.
        var data = new byte[4096];
        for (var i = 0; i < data.Length; i++) data[i] = 0x8B;
        var dump = NativeHexDump(0x140001000UL, data);
        Assert.Equal(256, dump.Split('\n').Length);
        Assert.True(dump.Length < 30_000, $"native-shape 4096-byte dump must stay under 30KB, got {dump.Length}");
    }
}
