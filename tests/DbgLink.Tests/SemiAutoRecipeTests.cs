using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
using static DbgLink.Tests.SemiAutoSeeds;

namespace DbgLink.Tests;

/// <summary>
/// Semi-auto recipe scenario: the same three fixture functions and staged
/// verdicts as the PRE baseline (<see cref="SemiAutoBaselineTests"/>), but
/// composed the batched way — map once, one multi-function brief, one
/// probe batch, one annotate batch. Must beat PRE on calls with identical
/// verdicts and fully applied annotations, on the same seeds (shared
/// <see cref="SemiAutoSeeds"/>); what is measured is COST on the full
/// success path, not verdict truth.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class SemiAutoRecipeTests
{
    private readonly ITestOutputHelper _output;

    public SemiAutoRecipeTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task SemiAuto_Recipe_OverWire()
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

        // 1. Map-first entry, amortized over all functions (same as PRE).
        await CallAsync("GetModuleMap", new { }, "map");

        // 2. One brief for all three functions: static evidence only, full
        // decompilation, no live section (probes below carry the dynamics).
        var briefText = await CallAsync("GetInvestigationBrief", new
        {
            functions = FixtureProbes.Select(probe => probe.Name).ToArray(),
            includeLive = false,
            includeDecomp = true,
            maxChars = 16_000,
        }, "brief");
        var (staticReadyCount, briefFunctions) = ReadBrief(briefText);
        Assert.Equal(FixtureProbes.Length, staticReadyCount);
        Assert.Equal(FixtureProbes.Length, briefFunctions.Length);
        foreach (var probe in FixtureProbes)
        {
            var entry = briefFunctions.Single(item =>
                string.Equals(item.GetProperty("selector").GetString(), probe.Name, StringComparison.Ordinal));
            Assert.True(entry.GetProperty("ok").GetBoolean(), $"brief entry for {probe.Name} is not ok");
            var decompilation = entry.TryGetProperty("decompilation", out var decomp) &&
                decomp.ValueKind == JsonValueKind.String ? decomp.GetString() ?? "" : "";
            Assert.Contains(probe.Name, decompilation, StringComparison.Ordinal);
        }

        // 3. One probe batch for all three hypotheses. The shared waitMs
        // budget covers 3x the PRE per-probe 200ms, so reliability is not
        // traded for batching.
        var probeRows = FixtureProbes.Select(probe =>
        {
            var row = new Dictionary<string, object?> { ["address"] = probe.Entry, ["expected"] = probe.Expected };
            if (!string.IsNullOrEmpty(probe.Arg))
                row["arg1"] = probe.Arg;
            return row;
        }).ToArray();
        var probeText = await CallAsync("ProbeFunction", new { probes = probeRows, waitMs = 600 }, "probes");
        var (batchMatched, batchExecuted, stoppedEarly) = ReadProbeBatch(probeText);
        Assert.False(stoppedEarly);
        Assert.Equal(FixtureProbes.Length, batchMatched);
        Assert.Equal(FixtureProbes.Length, batchExecuted);

        // 4. One annotate batch: rename + comment per function.
        var operations = FixtureProbes.SelectMany(probe =>
        {
            var annotation = FixtureAnnotations.Single(entry => entry.Name == probe.Name);
            return new object[]
            {
                new { kind = "rename_function", function = probe.Name, name = annotation.Renamed },
                new { kind = "set_function_comment", function = probe.Name, comment = annotation.Comment },
            };
        }).ToArray();
        var annotateText = await CallAsync("BatchAnnotate", new { operations }, "annotate");
        var committed = ReadCommitted(annotateText);
        Assert.Equal(2 * FixtureProbes.Length, committed);
        wallClock.Stop();

        var tokensEstimate = calls.Sum(call => call.Tokens);
        var report = new
        {
            schemaVersion = 1,
            scenario = "semi-auto-recipe-fixture",
            policy = "brief3-probebatch3-annotate6",
            mockFingerprint = MockFingerprint(),
            functions = FixtureProbes.Select(probe => probe.Name).ToArray(),
            calls = calls.Count,
            callsPerFunction = (double)calls.Count / FixtureProbes.Length,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate,
            tokensPerFunction = (double)tokensEstimate / FixtureProbes.Length,
            wallMs = wallClock.ElapsedMilliseconds,
            wallMsPerFunction = (double)wallClock.ElapsedMilliseconds / FixtureProbes.Length,
            matchedProbes = batchMatched,
            committedOps = committed,
            staticReadyCount,
        };

        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "semi-auto-recipe.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"RECIPE calls={report.calls} calls/function={report.callsPerFunction:F1} " +
            $"tokens~{report.tokensEstimate} ({report.tokensPerFunction:F0}/function) " +
            $"wall={report.wallMs}ms matched={batchMatched}/{FixtureProbes.Length} committed={committed}");
        _output.WriteLine($"RECIPE artifact={artifactPath}");

        var preTokens = ReadCommittedPreTokens();
        Assert.True(report.calls <= 4, $"recipe took {report.calls} calls, budget is 4");
        // Parity band (repo-standard ±15%, min 25 — same formula as the
        // token-baseline drift bands): batching wins 10→4 calls while tokens
        // tie at +3.4% (brief packet overhead 1548 vs 3×462 static). Turns
        // are the loop's main multiplier; the tie is recorded in the backlog.
        Assert.True(tokensEstimate <= PreBandCeiling(preTokens),
            $"recipe tokens {tokensEstimate} breached the PRE parity band (PRE {preTokens})");
        Assert.True(File.Exists(artifactPath));
    }

    /// <summary>
    /// Pins the committed recipe mirror without the wire stack: schema,
    /// scenario, policy, seed fingerprint and the beaten-baseline numbers,
    /// all read from docs/ only.
    /// </summary>
    [Fact]
    public void SemiAuto_Recipe_Mirror_Matches_Pins()
    {
        var mirrorPath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "semi-auto-recipe.json");
        Assert.True(File.Exists(mirrorPath), $"Recipe mirror is missing: {mirrorPath}. Run the writer Fact, then tools/regen-baseline.ps1.");
        using var document = JsonDocument.Parse(File.ReadAllText(mirrorPath));
        var root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("semi-auto-recipe-fixture", root.GetProperty("scenario").GetString());
        Assert.Equal("brief3-probebatch3-annotate6", root.GetProperty("policy").GetString());
        Assert.Equal(MockFingerprint(), root.GetProperty("mockFingerprint").GetString());
        Assert.True(root.GetProperty("calls").GetInt32() <= 4);
        Assert.Equal(FixtureProbes.Length, root.GetProperty("matchedProbes").GetInt32());
        Assert.Equal(2 * FixtureProbes.Length, root.GetProperty("committedOps").GetInt32());
        Assert.Equal(FixtureProbes.Length, root.GetProperty("staticReadyCount").GetInt32());
        var preTokens = ReadCommittedPreTokens();
        Assert.True(root.GetProperty("tokensEstimate").GetInt32() <= PreBandCeiling(preTokens),
            "committed recipe tokens breached the committed PRE parity band");
    }

    private static int PreBandCeiling(int preTokens) =>
        preTokens + Math.Max(25, (int)(preTokens * 0.15));

    private static (int StaticReadyCount, JsonElement[] Functions) ReadBrief(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        var result = root.TryGetProperty("result", out var node) ? node : root;
        var summary = result.GetProperty("summary");
        var staticReadyCount = summary.GetProperty("staticReadyCount").GetInt32();
        var functions = result.GetProperty("sections").GetProperty("static")
            .GetProperty("functions").EnumerateArray().Select(item => item.Clone()).ToArray();
        return (staticReadyCount, functions);
    }

    private static (int Matched, int Executed, bool StoppedEarly) ReadProbeBatch(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        var result = root.TryGetProperty("result", out var node) ? node : root;
        var matched = result.GetProperty("matched").GetInt32();
        var executed = result.GetProperty("executed").GetInt32();
        var stoppedEarly = result.TryGetProperty("stoppedEarly", out var stopped) &&
            stopped.ValueKind == JsonValueKind.True;
        foreach (var row in result.GetProperty("results").EnumerateArray())
        {
            Assert.True(row.TryGetProperty("matched", out var rowMatched) &&
                rowMatched.ValueKind == JsonValueKind.True, "a probe row did not match");
            Assert.False(row.TryGetProperty("skipped", out var skipped) &&
                skipped.ValueKind == JsonValueKind.True, "a probe row was skipped");
        }
        return (matched, executed, stoppedEarly);
    }

    private static int ReadCommitted(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        // TextOf unwraps the ok/result envelope, so accept the slim-ack
        // result node directly (same fallback as the PRE matched reader).
        var result = root.TryGetProperty("result", out var node) ? node : root;
        if (!result.TryGetProperty("applied", out _))
            Assert.Fail($"annotate response has no slim ack: {text}");
        Assert.Equal(2 * FixtureProbes.Length, result.GetProperty("applied").GetInt32());
        Assert.Equal(0, result.GetProperty("failed").GetInt32());
        var committed = 0;
        foreach (var row in result.GetProperty("results").EnumerateArray())
        {
            if (row.GetProperty("committed").GetBoolean() && row.GetProperty("journaled").GetBoolean())
                committed++;
        }
        return committed;
    }

    private static int ReadCommittedPreTokens()
    {
        var mirrorPath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "semi-auto-baseline.json");
        Assert.True(File.Exists(mirrorPath), $"Committed PRE mirror is missing: {mirrorPath}");
        using var document = JsonDocument.Parse(File.ReadAllText(mirrorPath));
        return document.RootElement.GetProperty("tokensEstimate").GetInt32();
    }
}
