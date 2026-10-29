using System.Reflection.PortableExecutable;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// Serious live token-efficiency tests: full wire stack
/// (Kestrel HTTP + Win32 named pipe + Ghidra TCP) with real fixture
/// binaries. Every token count is measured from actual tool responses,
/// not hand-built JSON. Tokens are real cl100k_base BPE counts
/// (see TokenCounter), the same encoding production telemetry counts with.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class LiveTokenEfficiencyTests
{
    private readonly ITestOutputHelper _output;

    public LiveTokenEfficiencyTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private static string FixturePath(string filename)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "artifacts", "fixtures", "x64", filename);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException($"Fixture not found: {filename}");
    }

    private static List<(string Addr, string Val)> ExtractRealStrings(string exePath, int maxItems)
    {
        var bytes = File.ReadAllBytes(exePath);
        byte[] scan = bytes;
        try
        {
            using var stream = File.OpenRead(exePath);
            using var pe = new PEReader(stream);
            var rdata = pe.PEHeaders.SectionHeaders.FirstOrDefault(h => h.Name == ".rdata");
            if (!string.IsNullOrEmpty(rdata.Name) && rdata.SizeOfRawData > 0)
            {
                stream.Seek(rdata.PointerToRawData, SeekOrigin.Begin);
                var buf = new byte[rdata.SizeOfRawData];
                stream.ReadExactly(buf, 0, buf.Length);
                scan = buf;
            }
        }
        catch { }

        var out_ = new List<(string, string)>();
        var sb = new StringBuilder();
        int runStart = 0;
        for (int i = 0; i < scan.Length && out_.Count < maxItems; i++)
        {
            byte b = scan[i];
            if (b >= 32 && b <= 126)
            {
                if (sb.Length == 0) runStart = i;
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= 5)
                    out_.Add(($"0x{0x140000000UL + (ulong)runStart:X}", sb.ToString()));
                sb.Clear();
            }
        }
        if (sb.Length >= 5 && out_.Count < maxItems)
            out_.Add(($"0x{0x140000000UL + (ulong)runStart:X}", sb.ToString()));
        return out_;
    }

    private static void SeedDumpStrings(RealServerHarness harness, List<(string Addr, string Val)> items)
    {
        harness.Ghidra.RegisterTcpHandler("DumpStrings", (id, _) =>
        {
            var rows = string.Join(",", items.Select(it =>
                $"{{\"address\":{JsonSerializer.Serialize(it.Addr)}," +
                $"\"value\":{JsonSerializer.Serialize(it.Val)}," +
                $"\"length\":{it.Val.Length}}}"));
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"strings\":[{rows}],\"count\":{items.Count}}}}}";
        });
    }

    [Fact]
    public async Task Live01_ToolSchema_Tokens_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var tools = await harness.ListToolsOverWireAsync();
        var json = JsonSerializer.Serialize(tools);
        var tok = Tok(json);
        _output.WriteLine($"TOOLS schema={tools.Count} chars={json.Length:N0} tokens~{tok:N0}");
        Assert.True(tools.Count >= 25);
        Assert.True(json.Length > 20_000);
        // Live wire budget: the default (comprehensive) tools/list must stay
        // within the absolute regression caps enforced by TokenRegressionTests.
        Assert.True(json.Length <= 65_000, $"tools/list grew over wire: {json.Length}");
        Assert.True(tok <= 17_600, $"tools/list token budget breached over wire: {tok}");
    }

    [Fact]
    public async Task Live02_Snapshot_ModulesOnVsOff()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var on = TextOf(await harness.CallToolOverWireAsync("GetAnalysisSnapshot",
            new { maxFrames = 8, instructionBytes = 64, stackBytes = 64, includeModules = true }));
        var off = TextOf(await harness.CallToolOverWireAsync("GetAnalysisSnapshot",
            new { maxFrames = 8, instructionBytes = 64, stackBytes = 64, includeModules = false }));
        _output.WriteLine($"SNAPSHOT on={on.Length:N0}B/{Tok(on):N0}tok off={off.Length:N0}B/{Tok(off):N0}tok saved={100.0 * (on.Length - off.Length) / on.Length:F1}%");
        Assert.True(off.Length < on.Length);
        // The modules section must be material: omitting it saves >= 5%
        // (measured ~12% over the harness mocks).
        Assert.True(100.0 * (on.Length - off.Length) / on.Length >= 5.0,
            $"modules-off saves too little: on={on.Length} off={off.Length}");
    }

    [Fact]
    public async Task Live03_TraceUntil_SingleRoundTrip()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var text = TextOf(await harness.CallToolOverWireAsync("TraceUntil",
            new { count = 1, kind = "into", includeModules = false }));
        _output.WriteLine($"TRACEUNTIL chars={text.Length:N0} tokens~{Tok(text):N0}");
        Assert.Contains("schemaVersion", text);
        Assert.True(text.Length < 20_000);
        // A single bulk step over the harness mocks is ~1.6KB: an 8KB cap
        // leaves 5x headroom while catching unbounded trace payloads.
        Assert.True(text.Length <= 8_000, $"TraceUntil grew: {text.Length}");
    }

    [Fact]
    public async Task Live04_BatchStaticQueries_VsSequential()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var t1 = TextOf(await harness.CallToolOverWireAsync("ListSymbols", new { kind = "imports", maxItems = 16 }));
        var t2 = TextOf(await harness.CallToolOverWireAsync("ListSymbols", new { kind = "exports", maxItems = 16 }));
        var t3 = TextOf(await harness.CallToolOverWireAsync("ListFunctions", new { maxItems = 16 }));
        var seqChars = t1.Length + t2.Length + t3.Length;
        var batch = TextOf(await harness.CallToolOverWireAsync("BatchStaticQueries", new
        {
            requests = new object[]
            {
                new { method = "ListSymbols", arguments = new { kind = "imports", maxItems = 16 } },
                new { method = "ListSymbols", arguments = new { kind = "exports", maxItems = 16 } },
                new { method = "ListFunctions", arguments = new { maxItems = 16 } },
            }
        }));
        _output.WriteLine($"STATIC seq=3rt {seqChars:N0}B/{Tok(t1) + Tok(t2) + Tok(t3):N0}tok batch=1rt {batch.Length:N0}B/{Tok(batch):N0}tok");
        using var batchDoc = JsonDocument.Parse(batch);
        var batchNode = batchDoc.RootElement.TryGetProperty("result", out var batchResult) ? batchResult : batchDoc.RootElement;
        Assert.Equal(3, batchNode.GetProperty("results").GetArrayLength());
        // One round trip must not cost more bytes than three: the batch
        // envelope adds only per-row wrappers plus a small outer object, so a
        // generous 2KB overhead bound catches duplication/blowup regressions.
        Assert.True(batch.Length <= seqChars + 2048,
            $"batch {batch.Length} exceeds sequential {seqChars} + 2KB envelope");
    }

    [Fact]
    public async Task Live05_Memory_ReadVsInspectStructure()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var raw = TextOf(await harness.CallToolOverWireAsync("ReadMemAtAddress",
            new { address = "0x140001000", byteCount = 64 }));
        var strukt = TextOf(await harness.CallToolOverWireAsync("InspectAddressStructure",
            new { address = "0x140001000", pointerCount = 4 }));
        _output.WriteLine($"MEM read={raw.Length:N0}B/{Tok(raw):N0}tok struct={strukt.Length:N0}B/{Tok(strukt):N0}tok");
        Assert.False(string.IsNullOrWhiteSpace(raw));
        Assert.False(string.IsNullOrWhiteSpace(strukt));
        // 64-byte reads are ~100B over the mocks: 4KB caps (40x) catch
        // paging/limit regressions without choking on real-world variance.
        Assert.True(raw.Length <= 4_096, $"ReadMemAtAddress grew: {raw.Length}");
        Assert.True(strukt.Length <= 4_096, $"InspectAddressStructure grew: {strukt.Length}");
    }

    [Fact]
    public async Task Live08_BatchClamp_And_BriefDefaults_SaveTokens()
    {
        await using var harness = await RealServerHarness.StartAsync();
        // Echo handler: reports the maxChars the server actually forwarded over TCP.
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var mc = args?.TryGetProperty("maxChars", out var m) == true ? m.GetInt32() : -1;
            return $"{{\"id\":{id},\"ok\":true,\"result\":{{\"function\":\"main\",\"start\":\"0x140001000\",\"size\":64,\"forwardedMaxChars\":{mc},\"decomp\":\"int main() {{ return 0; }}\",\"symbols\":[]}}}}";
        });

        var batch = TextOf(await harness.CallToolOverWireAsync("BatchStaticQueries", new
        {
            requests = new object[]
            {
                new { method = "InspectFunction", arguments = new { function = "main" } },
                new { method = "InspectFunction", arguments = new { function = "main", maxChars = 20000 } },
            }
        }));
        _output.WriteLine($"BATCHCLAMP chars={batch.Length:N0} tok~{Tok(batch):N0}");
        Assert.Contains("\"forwardedMaxChars\":6000", batch);   // omitted budget clamped to triage level
        Assert.Contains("\"forwardedMaxChars\":20000", batch);  // explicit per-item budget honored

        var brief = TextOf(await harness.CallToolOverWireAsync("GetInvestigationBrief", new { function = "main" }));
        _output.WriteLine($"BRIEF chars={brief.Length:N0} tok~{Tok(brief):N0}");
        // The brief honors its 16KB budget: 20KB (budget + envelope slack)
        // fails a budget-ignoring regression while tolerating real variance.
        Assert.True(brief.Length <= 20_000, $"brief exceeded budget: {brief.Length}");
    }

    [Fact]
    public async Task Live06_Triage_RealFixtureRdata()
    {
        var exe = FixturePath("HardenedStressTarget.exe");
        var items = ExtractRealStrings(exe, 200);
        Assert.True(items.Count > 10);
        await using var harness = await RealServerHarness.StartAsync();
        SeedDumpStrings(harness, items);
        var dump = TextOf(await harness.CallToolOverWireAsync("BatchStaticQueries",
            new { requests = new object[] { new { method = "DumpStrings", arguments = new { section = ".rdata", maxItems = 512 } } } }));
        var triage = TextOf(await harness.CallToolOverWireAsync("Triage",
            new { kind = "strings", section = ".rdata", maxItems = 512 }));
        var saved = 100.0 * (dump.Length - triage.Length) / dump.Length;
        _output.WriteLine($"TRIAGE fixture={Path.GetFileName(exe)} strings={items.Count} dump={dump.Length:N0}B/{Tok(dump):N0}tok triage={triage.Length:N0}B/{Tok(triage):N0}tok saved={saved:F1}%");
        _output.WriteLine($"TRIAGE sample: {items[0].Val} | {items[1].Val}");
        Assert.Contains("totalExamined", triage);
        Assert.True(triage.Length < dump.Length);
        // Triage must stay a summary, not a second dump: measured ~95%
        // savings over the fixture, so a 50% floor plus a 2KB absolute cap
        // leaves wide headroom while catching triage-bloat regressions.
        Assert.True(saved >= 50.0, $"triage savings collapsed: {saved:F1}%");
        Assert.True(triage.Length <= 2_048, $"triage grew: {triage.Length}");
    }

    [Fact]
    public async Task Live07_FullSession_TotalTokens()
    {
        var exe = FixturePath("HardenedStressTarget.exe");
        var items = ExtractRealStrings(exe, 200);
        await using var harness = await RealServerHarness.StartAsync();
        SeedDumpStrings(harness, items);

        long totalChars = 0;
        long totalTok = 0;
        int calls = 0;
        async Task<string> Call(string name, object? args = null)
        {
            var reqJson = JsonSerializer.Serialize(new { name, arguments = args ?? new { } });
            var text = TextOf(await harness.CallToolOverWireAsync(name, args));
            totalChars += reqJson.Length + text.Length;
            calls++;
            var tok = Tok(reqJson) + Tok(text);
            totalTok += tok;
            _output.WriteLine($"  {name,-24} req={reqJson.Length,5}B resp={text.Length,6:N0}B tok~{tok,5:N0}");
            return text;
        }

        await Call("GetServerStatus");
        await Call("BatchStaticQueries", new
        {
            requests = new object[]
            {
                new { method = "ListSymbols", arguments = new { kind = "imports", maxItems = 16 } },
                new { method = "ListSymbols", arguments = new { kind = "exports", maxItems = 16 } },
                new { method = "ListFunctions", arguments = new { maxItems = 16 } },
            }
        });
        await Call("GetAnalysisSnapshot", new { maxFrames = 8, instructionBytes = 64, stackBytes = 64, includeModules = false });
        await Call("TraceUntil", new { count = 1, kind = "into", includeModules = false });
        await Call("InspectAddressStructure", new { address = "0x140001000", pointerCount = 4 });
        await Call("ReadMemAtAddress", new { address = "0x140001000", byteCount = 64 });
        await Call("Triage", new { kind = "strings", section = ".rdata", maxItems = 512 });
        await Call("EvaluateExpressions", new { expressions = new[] { "cip" } });

        var tools = await harness.ListToolsOverWireAsync();
        var schemaJson = JsonSerializer.Serialize(tools);
        var schemaTok = Tok(schemaJson);

        _output.WriteLine($"TOTAL session={calls} calls chars={totalChars:N0} tokens~{totalTok:N0} (+schema {schemaJson.Length:N0}B/{schemaTok:N0}tok per turn)");
        Assert.True(totalTok > 0);
        // Full 8-call session is ~1.8k real tokens / ~6KB over the mocks: caps at
        // 5k tokens / 20KB chars (3x) catch per-tool bloat early.
        Assert.True(totalTok < 5_000, $"session token budget breached: {totalTok}");
        Assert.True(totalChars < 20_000, $"session char budget breached: {totalChars}");
    }
}
