using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
using static DbgLink.Tests.SemiAutoSeeds;

namespace DbgLink.Tests;

/// <summary>
/// PRE-semiauto baseline: manual model-style reverse of the three fixture
/// functions over the full wire stack with mocks — map once, then per
/// function InspectFunction (see) -&gt; ProbeFunction (prove live) -&gt;
/// BatchAnnotate (record). Measures tool calls, real cl100k_base BPE tokens
/// and wall-clock time. The semi-auto agent must beat these numbers on the
/// same seeds; the mock fingerprint below guards seed drift.
/// Mock verdicts are staged (eval values pop from a queue in probe order);
/// what is measured is COST on the full success path, not verdict truth.
/// Seeds live in <see cref="SemiAutoSeeds"/>, shared with the recipe scenario.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class SemiAutoBaselineTests
{
    private readonly ITestOutputHelper _output;

    public SemiAutoBaselineTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task ManualReverse_Baseline_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedGhidra(harness);
        SeedNative(harness, new Queue<string>(FixtureProbes.Select(probe => probe.Eval)));

        var calls = new List<CallStat>();
        var wallClock = Stopwatch.StartNew();
        async Task<string> CallAsync(string tool, object? arguments, string function)
        {
            var callWatch = Stopwatch.StartNew();
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var text = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            callWatch.Stop();
            var tokens = Tok(requestJson) + Tok(text);
            calls.Add(new CallStat(tool, function, requestJson.Length, text.Length, tokens, callWatch.ElapsedMilliseconds));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={text.Length,6:N0}B tok~{tokens,5:N0} {callWatch.ElapsedMilliseconds,5}ms");
            return text;
        }

        // Map-first entry: one bounded call, amortized over all functions.
        await CallAsync("GetModuleMap", new { }, "map");

        var matched = 0;
        foreach (var probe in FixtureProbes)
        {
            await CallAsync("InspectFunction", new { function = probe.Name }, probe.Name);
            var probeArgs = new Dictionary<string, object?> { ["address"] = probe.Entry, ["expected"] = probe.Expected, ["waitMs"] = 200 };
            if (!string.IsNullOrEmpty(probe.Arg))
                probeArgs["arg1"] = probe.Arg;
            if (ReadMatched(await CallAsync("ProbeFunction", probeArgs, probe.Name)))
                matched++;
            var annotation = FixtureAnnotations.Single(entry => entry.Name == probe.Name);
            await CallAsync("BatchAnnotate", new
            {
                operations = new object[]
                {
                    new { kind = "rename_function", function = probe.Name, name = annotation.Renamed },
                    new { kind = "set_function_comment", function = probe.Name, comment = annotation.Comment },
                },
            }, probe.Name);
        }
        wallClock.Stop();

        var perFunction = FixtureProbes.Select(probe => new
        {
            function = probe.Name,
            calls = calls.Count(call => call.Function == probe.Name),
            tokens = calls.Where(call => call.Function == probe.Name).Sum(call => call.Tokens),
            wallMs = calls.Where(call => call.Function == probe.Name).Sum(call => call.WallMs),
        }).ToArray();

        var report = new
        {
            schemaVersion = 1,
            scenario = "manual-reverse-fixture",
            policy = "inspect-prove-annotate",
            mockFingerprint = MockFingerprint(),
            functions = FixtureProbes.Select(probe => probe.Name).ToArray(),
            calls = calls.Count,
            callsPerFunction = (double)calls.Count / FixtureProbes.Length,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate = calls.Sum(call => call.Tokens),
            tokensPerFunction = (double)calls.Sum(call => call.Tokens) / FixtureProbes.Length,
            wallMs = wallClock.ElapsedMilliseconds,
            wallMsPerFunction = (double)wallClock.ElapsedMilliseconds / FixtureProbes.Length,
            matchedProbes = matched,
            perFunction,
        };

        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "semi-auto-baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"BASELINE calls={report.calls} calls/function={report.callsPerFunction:F1} " +
            $"tokens~{report.tokensEstimate} ({report.tokensPerFunction:F0}/function) " +
            $"wall={report.wallMs}ms ({report.wallMsPerFunction:F0}ms/function) matched={matched}/{FixtureProbes.Length}");
        _output.WriteLine($"BASELINE artifact={artifactPath}");

        Assert.Equal(10, report.calls);
        Assert.All(perFunction, entry => Assert.Equal(3, entry.calls));
        Assert.Equal(FixtureProbes.Length, matched);
        Assert.True(report.tokensEstimate > 0);
        Assert.True(report.wallMs > 0);
        Assert.True(report.wallMs < 120_000, $"baseline wall time breached: {report.wallMs}ms");
        Assert.True(File.Exists(artifactPath));
    }
}
