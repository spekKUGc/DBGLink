using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
using static DbgLink.Tests.SemiAutoSeeds;

namespace DbgLink.Tests;

/// <summary>
/// Blind-plan verification (3 calls): AnalyzeFunctions digest (no decompilation)
/// + ProbeFunction batch + BatchAnnotate batch over the shared fixture seeds.
/// Found independently by a blind model run; kept as the no-decomp floor:
/// cheaper than the PRE baseline and the decomp recipe, but with weaker
/// static parity (no decompiled bodies).
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class SemiAutoDigestTests
{
    private readonly ITestOutputHelper _output;

    public SemiAutoDigestTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task SemiAuto_Blind_ThreeCalls_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedGhidra(harness);
        SeedNative(harness, new Queue<string>(FixtureProbes.Select(probe => probe.Eval)));

        // Extra mock beyond SeedGhidra/SeedNative: SeedGhidra registers no
        // AnalyzeFunctions handler, and the default Ghidra TCP server answers
        // unknown_method. Minimal C-free digest in the style of
        // AnalyzeFunctionsTests.Wire_digest_indexes_not_found_and_forwards_budgets.
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            var selectors = args?.TryGetProperty("functions", out var fns) == true &&
                fns.ValueKind == JsonValueKind.Array
                ? fns.EnumerateArray().Select(e => e.GetString() ?? "").ToArray()
                : ["0x140001040", "0x140001000", "0x140001080"];
            var names = new[] { "FixtureCallee", "FixtureCaller", "FixtureImportedPid" };
            var entries = new object[]
            {
                new { index = 0, selector = selectors[0], ok = true,
                    function = new { name = names[0], entry = "0x140001040", rva = "0x1040" } },
                new { index = 1, selector = selectors[1], ok = true,
                    function = new { name = names[1], entry = "0x140001000", rva = "0x1000" } },
                new { index = 2, selector = selectors[2], ok = true,
                    function = new { name = names[2], entry = "0x140001080", rva = "0x1080" } },
            };
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    functions = entries,
                    truncated = false,
                    truncatedSections = Array.Empty<string>(),
                },
            });
        });

        var calls = new List<CallStat>();
        async Task<string> CallAsync(string tool, object? arguments, string function)
        {
            var watch = Stopwatch.StartNew();
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var text = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            watch.Stop();
            var tokens = Tok(requestJson) + Tok(text);
            calls.Add(new CallStat(tool, function, requestJson.Length, text.Length, tokens, watch.ElapsedMilliseconds));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={text.Length,6:N0}B tok~{tokens,5:N0} {watch.ElapsedMilliseconds,5}ms");
            return text;
        }

        // 1. Static map without decompilation.
        var analyzeText = await CallAsync("AnalyzeFunctions", new
        {
            functions = new[] { "0x140001040", "0x140001000", "0x140001080" },
            includeDecomp = false,
        }, "analyze");
        using (var doc = JsonDocument.Parse(analyzeText))
        {
            var root = doc.RootElement;
            var result = root.TryGetProperty("result", out var node) ? node : root;
            var fns = result.GetProperty("functions").EnumerateArray().ToArray();
            Assert.Equal(3, fns.Length);
            foreach (var entry in fns)
                Assert.True(entry.GetProperty("ok").GetBoolean());
        }
        var hasDecomp = analyzeText.Contains("decomp", StringComparison.OrdinalIgnoreCase);

        // 2. One probe batch for all three hypotheses.
        var probeText = await CallAsync("ProbeFunction", new
        {
            probes = new object[]
            {
                new { address = "0x140001040", arg1 = "0x5", expected = "22" },
                new { address = "0x140001000", arg1 = "0x0", expected = "0" },
                new { address = "0x140001080", expected = "1234" },
            },
            waitMs = 600,
        }, "probes");
        int matched, executed;
        var stoppedEarly = false;
        using (var doc = JsonDocument.Parse(probeText))
        {
            var root = doc.RootElement;
            var result = root.TryGetProperty("result", out var node) ? node : root;
            matched = result.GetProperty("matched").GetInt32();
            executed = result.GetProperty("executed").GetInt32();
            stoppedEarly = result.TryGetProperty("stoppedEarly", out var stopped) &&
                stopped.ValueKind == JsonValueKind.True;
            foreach (var row in result.GetProperty("results").EnumerateArray())
            {
                Assert.True(row.TryGetProperty("matched", out var m) && m.ValueKind == JsonValueKind.True,
                    $"probe row not matched: {row.GetRawText()}");
                Assert.False(row.TryGetProperty("skipped", out var s) && s.ValueKind == JsonValueKind.True,
                    "a probe row was skipped");
            }
        }

        // 3. One annotate batch: rename + comment per function.
        var annotateText = await CallAsync("BatchAnnotate", new
        {
            operations = new object[]
            {
                new { kind = "rename_function", function = "FixtureCallee", name = "fixture_callee" },
                new { kind = "set_function_comment", function = "FixtureCallee", comment = "callee doubles input" },
                new { kind = "rename_function", function = "FixtureCaller", name = "fixture_caller" },
                new { kind = "set_function_comment", function = "FixtureCaller", comment = "caller wraps callee" },
                new { kind = "rename_function", function = "FixtureImportedPid", name = "fixture_pid" },
                new { kind = "set_function_comment", function = "FixtureImportedPid", comment = "pid helper" },
            },
        }, "annotate");
        var committed = 0;
        using (var doc = JsonDocument.Parse(annotateText))
        {
            var root = doc.RootElement;
            var result = root.TryGetProperty("result", out var node) ? node : root;
            Assert.Equal(6, result.GetProperty("applied").GetInt32());
            Assert.Equal(0, result.GetProperty("failed").GetInt32());
            foreach (var row in result.GetProperty("results").EnumerateArray())
            {
                if (row.GetProperty("committed").GetBoolean() && row.GetProperty("journaled").GetBoolean())
                    committed++;
            }
        }

        var tokensEstimate = calls.Sum(call => call.Tokens);
        _output.WriteLine(
            $"BLIND calls={calls.Count} tokens~{tokensEstimate} " +
            $"matched={matched}/3 executed={executed}/3 committed={committed}/6 " +
            $"stoppedEarly={stoppedEarly} hasDecomp={hasDecomp}");

        Assert.False(stoppedEarly);
        Assert.Equal(3, matched);
        Assert.Equal(3, executed);
        Assert.Equal(6, committed);
        Assert.Equal(3, calls.Count);
        Assert.False(hasDecomp);
    }
}

