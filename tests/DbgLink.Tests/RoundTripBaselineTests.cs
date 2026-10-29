using System.Runtime.Versioning;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// Round-trip baseline for the DbgLink efficiency program (Wave A + WS7 ratchet).
/// Counts the MINIMUM number of MCP tool calls (round trips) a model needs
/// for representative end-to-end reverse-engineering tasks with CURRENT tools,
/// measured over the full wire stack via RealServerHarness (Kestrel HTTP +
/// Win32 pipe + Ghidra TCP) with mocks (no real x64dbg/Ghidra).
/// Token cost is out of scope: this program is about CALLS/round trips.
/// The writer Fact below regenerates ONLY the gitignored scratch report
/// artifacts/benchmark/roundtrip-baseline.json. The committed mirror
/// docs/reverse-speedup/benchmarks/roundtrip-baseline.json is refreshed
/// deliberately via tools/regen-baseline.ps1 (artifact -> docs copy) and
/// committed — NEVER as a test side effect. Mirror Facts read docs/ only,
/// so a fresh clone (no artifacts/) passes them without running the writer.
/// Per-scenario callsPerTask pins catch regressions and prove
/// future reductions.
/// The FIRST 7 scenarios are the original Wave-A budget and must never grow:
/// RoundTrip_Calls_Never_Exceed_Original_Budget pins their ceilings.
/// New recommended paths are ADDITIVE scenarios (suffixes below), never silent
/// rewrites of the originals.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class RoundTripBaselineTests
{
    private const int SchemaVersion = 1;

    private readonly ITestOutputHelper _output;

    public RoundTripBaselineTests(ITestOutputHelper output) => _output = output;

    private static string FixtureExe()
    {
        var candidate = Path.Combine(RepoRoot(), "artifacts", "fixtures", "x64", "HardenedStressTarget.exe");
        Assert.True(File.Exists(candidate), $"Fixture binary is missing: {candidate}");
        return candidate;
    }

    /// <summary>
    /// Seeds the Ghidra mock with a map-compatible InspectFunction identity
    /// (module path matches the live GetModuleRecords C:\test.exe) and a
    /// minimal CallGraph, plus an XrefsBoth fan-in for the who-calls-x-both
    /// single-call scenario. All other tools use the RealGhidraServers defaults.
    /// </summary>
    private static void SeedRoundTripBackend(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            string function = "main";
            try
            {
                if (args is { ValueKind: JsonValueKind.Object } &&
                    args.Value.TryGetProperty("function", out var selector) &&
                    selector.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(selector.GetString()))
                    function = selector.GetString()!;
            }
            catch (InvalidOperationException) { }
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = "main",
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path = "C:\\test.exe" },
                    },
                    requested = function,
                    decompilation = "int main() { return 0; }",
                    references = new
                    {
                        callers = new[] { new { function = "caller", from = "0x140001050", type = "CALL" } },
                        callees = Array.Empty<object>(),
                    },
                    symbols = Array.Empty<object>(),
                    truncatedSections = Array.Empty<string>(),
                }
            });
        });
        harness.Ghidra.RegisterTcpHandler("CallGraph", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    nodes = new[] { new { name = "main", entry = "0x140001000", rva = "0x1000", instructionCount = 10 } },
                    edges = new[] { new { caller = "0x140001000", callee = "0x140001040", count = 1 } },
                    nodeCount = 1,
                    edgeCount = 1,
                    totalCalls = 1,
                    truncated = false,
                }
            }));
        harness.Ghidra.RegisterTcpHandler("XrefsBoth", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    address = "0x140001040",
                    // Java keeps per-side OBJECTS (contract) with additive flat cursors.
                    to = new
                    {
                        references = new[] { new { from = "0x140001050", type = "CALL", function = new { name = "caller", entry = "0x140001050" } } },
                        truncated = false,
                    },
                    from = new
                    {
                        references = Array.Empty<object>(),
                        truncated = false,
                    },
                    toTruncated = false,
                    fromTruncated = false,
                    truncated = false,
                }
            }));
        harness.Ghidra.RegisterTcpHandler("ListSections", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    source = "ghidra-static",
                    imageBase = "0x140000000",
                    sha256 = "abc123",
                    entryPoint = "0x140001000",
                    entryFunction = new { name = "entry", entry = "0x140001000" },
                    sections = new[]
                    {
                        new { name = ".text", start = "0x140001000", end = "0x140001fff", size = 4096, permissions = "r-x", initialized = true },
                        new { name = ".rdata", start = "0x140002000", end = "0x140002fff", size = 4096, permissions = "r--", initialized = true },
                    },
                    truncated = false,
                }
            }));
        harness.Ghidra.RegisterTcpHandler("ListSymbolsBoth", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    source = "ghidra-static",
                    imageBase = "0x140000000",
                    sha256 = "abc123",
                    imports = new[]
                    {
                        new { name = "CreateFileW", library = "kernel32.dll", address = "EXTERNAL:1", refCount = 2 },
                        new { name = "connect", library = "ws2_32.dll", address = "EXTERNAL:2", refCount = 5 },
                    },
                    exports = new[] { new { name = "DllMain", address = "0x140001000" } },
                    importsTruncated = false,
                    exportsTruncated = false,
                    truncated = false,
                }
            }));
    }

    private sealed record ScenarioBaseline(string Scenario, string Description, int CallsPerTask, string[] Calls);

    private static ScenarioBaseline[] ExpectedScenarios() =>
    [
        // Original Wave-A budget (7 scenarios / 18 calls). Pinned; ceilings in
        // OriginalCeilings() must only move by explicit plan amendment.
        // P3 amendment: annotate-function runs the batch cover (2 calls, was 3).
        // Roundtrip-50 amendment: single-call covers replace multi-call flows
        // (triage-module 4->1 via GetModuleMap, who-calls-x 2->1 via CallGraph,
        // static-to-live 2->1 via MapStatic+liveBytes, function-bytes 2->1 via
        // batch); inspect-value-state and static-to-live-bytes merge into
        // inspect-value-bundle and static-to-live (duplicate intents).
        new("annotate-function", "inspect -> annotate (rename+comment) one function",
            2, ["InspectFunction", "BatchAnnotate"]),
        new("triage-module", "identity + ranked imports/exports/functions + IOC strings in one map call",
            1, ["GetModuleMap"]),
        new("who-calls-x", "caller/callee reachability around X in one graph call",
            1, ["CallGraph"]),
        new("static-to-live", "map a static function to live with live bytes attached",
            1, ["MapStaticFunctionToLive"]),
        new("open-target-ready", "open a target + status until ready",
            2, ["OpenDebugTarget", "GetServerStatus"]),
        new("function-bytes", "inspect a function + read its static bytes in one batch",
            1, ["BatchStaticQueries"]),
        // WS7 additive single-call paths (4 scenarios / 4 calls;
        // static-to-live-bytes merged into static-to-live above).
        new("triage-module-batch", "triage strings + imports(includeExports) + symbols + functions in one static batch",
            1, ["BatchStaticQueries"]),
        new("inspect-value-bundle", "snapshot + expressions + ranges in one bundled call",
            1, ["GetAnalysisSnapshot"]),
        new("who-calls-x-both", "xrefs both directions in one call",
            1, ["Xrefs"]),
        new("open-ghidra-longpoll", "open a Ghidra file with default long-poll wait in one call",
            1, ["OpenGhidraFile"]),
    ];

    /// <summary>
    /// ORIGINAL Wave-A ceilings (round-trip plan §4 item 2). Only moves by
    /// explicit plan amendment with justification; catches increases even if
    /// someone edits ExpectedScenarios() upward.
    /// </summary>
    private static Dictionary<string, int> OriginalCeilings() => new(StringComparer.Ordinal)
    {
        ["annotate-function"] = 2,
        ["triage-module"] = 1,
        ["who-calls-x"] = 1,
        ["static-to-live"] = 1,
        ["open-target-ready"] = 2,
        ["function-bytes"] = 1,
    };

    private const int OriginalTotalCeiling = 8;

    [Fact]
    public async Task RoundTrip_Baseline_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedRoundTripBackend(harness);

        var observed = new List<ScenarioBaseline>();

        async Task<string> CallAsync(List<string> calls, string tool, object? arguments)
        {
            var text = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            calls.Add(tool);
            _output.WriteLine($"  {tool,-22} ok resp={text.Length,6}B");
            return text;
        }

        // 1. annotate-function: inspect -> batch-annotate (rename+comment).
        // P3: single-op RenameFunction/SetFunctionComment are purged; one
        // BatchAnnotate transaction covers both ops.
        {
            var calls = new List<string>();
            harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, _) =>
                $"{{\"id\":{id},\"ok\":true,\"result\":{{\"applied\":2,\"failed\":0,\"results\":[{{\"index\":0,\"kind\":\"rename_function\",\"function\":\"main\",\"name\":\"baseline_main\",\"committed\":true,\"journaled\":true}},{{\"index\":1,\"kind\":\"set_function_comment\",\"function\":\"main\",\"commentChars\":49,\"committed\":true,\"journaled\":true}}]}}}}");
            await CallAsync(calls, "InspectFunction", new { function = "main" });
            await CallAsync(calls, "BatchAnnotate", new
            {
                operations = new object[]
                {
                    new { kind = "rename_function", function = "main", name = "baseline_main" },
                    new { kind = "set_function_comment", function = "main", comment = "Baseline: entry validates input then dispatches." },
                },
            });
            observed.Add(new("annotate-function", "inspect -> annotate (rename+comment) one function", calls.Count, [.. calls]));
        }

        // 2. triage-module: ONE GetModuleMap (identity, ranked
        // imports/exports/functions, IOC strings) instead of 4 singles.
        {
            var calls = new List<string>();
            var mapText = await CallAsync(calls, "GetModuleMap", null);
            Assert.Contains("imports", mapText);
            Assert.Contains("exports", mapText);
            Assert.Contains("functions", mapText);
            observed.Add(new("triage-module", "identity + ranked imports/exports/functions + IOC strings in one map call", calls.Count, [.. calls]));
        }

        // 3. who-calls-x: ONE CallGraph(function, both) neighborhood instead
        // of Xrefs + whole-module graph.
        {
            var calls = new List<string>();
            var graphText = await CallAsync(calls, "CallGraph", new { function = "main", direction = "both" });
            Assert.Contains("edges", graphText);
            Assert.Contains("nodes", graphText);
            observed.Add(new("who-calls-x", "caller/callee reachability around X in one graph call", calls.Count, [.. calls]));
        }

        // 4. static-to-live: ONE MapStaticFunctionToLive with opt-in
        // includeLiveBytes (the live read is attached server-side, no second
        // call). Absorbs the old static-to-live-bytes scenario: same tool,
        // same function, bytes attached instead of read after.
        {
            var calls = new List<string>();
            var mapText = await CallAsync(calls, "MapStaticFunctionToLive", new { function = "main", verifyHash = false, includeLiveBytes = true });
            try
            {
                using var doc = JsonDocument.Parse(mapText);
                var root = doc.RootElement;
                var node = root.TryGetProperty("result", out var result) ? result : root;
                Assert.True(node.TryGetProperty("match", out var match) && match.GetBoolean(),
                    $"MapStaticFunctionToLive did not match with mocks: {mapText}");
                Assert.True(node.TryGetProperty("liveBytes", out _),
                    $"MapStaticFunctionToLive did not attach liveBytes with mocks: {mapText}");
            }
            catch (JsonException ex)
            {
                Assert.Fail($"MapStaticFunctionToLive returned invalid JSON: {ex.Message}");
            }
            observed.Add(new("static-to-live", "map a static function to live with live bytes attached", calls.Count, [.. calls]));
        }

        // 5. inspect-value-state: folded into inspect-value-bundle below (the
        // bundled snapshot call is the same flow in one turn); scenario removed.


        // 6. open-target-ready: open + status.
        {
            var calls = new List<string>();
            await CallAsync(calls, "OpenDebugTarget", new { path = FixtureExe() });
            await CallAsync(calls, "GetServerStatus", null);
            observed.Add(new("open-target-ready", "open a target + status until ready", calls.Count, [.. calls]));
        }

        // 7. function-bytes: ONE BatchStaticQueries (inspect + static bytes).
        {
            var calls = new List<string>();
            var batchText = await CallAsync(calls, "BatchStaticQueries", new
            {
                requests = new object[]
                {
                    new { method = "InspectFunction", arguments = new { function = "main" } },
                    new { method = "ReadStaticBytes", arguments = new { address = "0x140001000", length = 64 } },
                },
            });
            try
            {
                using var doc = JsonDocument.Parse(batchText);
                var root = doc.RootElement;
                var node = root.TryGetProperty("result", out var result) ? result : root;
                Assert.Equal(2, node.GetProperty("results").GetArrayLength());
            }
            catch (JsonException ex)
            {
                Assert.Fail($"BatchStaticQueries returned invalid JSON: {ex.Message}");
            }
            observed.Add(new("function-bytes", "inspect a function + read its static bytes in one batch", calls.Count, [.. calls]));
        }

        // 8. triage-module-batch: ONE BatchStaticQueries carrying
        // Triage(strings) + Triage(imports, includeExports) + ListSymbols(imports)
        // + ListFunctions. (P3: TriageStrings/TriageImports aliases purged;
        // the unified Triage covers both batch rows.)
        {
            var calls = new List<string>();
            var batchText = await CallAsync(calls, "BatchStaticQueries", new
            {
                requests = new object[]
                {
                    new { method = "Triage", arguments = new { kind = "strings", section = ".rdata" } },
                    new { method = "Triage", arguments = new { kind = "imports", includeExports = true } },
                    new { method = "ListSymbols", arguments = new { kind = "imports" } },
                    new { method = "ListFunctions", arguments = new { } },
                },
            });
            try
            {
                using var doc = JsonDocument.Parse(batchText);
                var root = doc.RootElement;
                var node = root.TryGetProperty("result", out var result) ? result : root;
                var rows = node.GetProperty("results");
                Assert.Equal(4, rows.GetArrayLength());
                foreach (var row in rows.EnumerateArray())
                    Assert.True(row.GetProperty("response").GetProperty("ok").GetBoolean(),
                        $"Batch row failed: {row}");
                // MINOR 1 pin: Triage(kind=imports, includeExports:true) must fold the
                // exports summary into the same row (no second ListSymbols call).
                var triageRow = rows.EnumerateArray().ElementAt(1);
                Assert.Equal(1, triageRow.GetProperty("index").GetInt32());
                var triageResult = triageRow.GetProperty("response").GetProperty("result");
                Assert.True(triageResult.TryGetProperty("exports", out var exports) &&
                    exports.ValueKind == JsonValueKind.Array,
                    $"Triage(imports, includeExports:true) is missing the exports array: {batchText}");
            }
            catch (JsonException ex)
            {
                Assert.Fail($"BatchStaticQueries returned invalid JSON: {ex.Message}");
            }
            observed.Add(new("triage-module-batch", "triage strings + imports(includeExports) + symbols + functions in one static batch", calls.Count, [.. calls]));
        }

        // 9. inspect-value-bundle: ONE GetAnalysisSnapshot with
        // includeExpressions + includeRanges.
        {
            var calls = new List<string>();
            var snapshotText = await CallAsync(calls, "GetAnalysisSnapshot", new
            {
                includeExpressions = new[] { "cip", "rax" },
                includeRanges = new[] { new { address = "0x140001000", byteCount = 64 } },
            });
            try
            {
                using var doc = JsonDocument.Parse(snapshotText);
                var root = doc.RootElement;
                // Wire text is the analyzed result payload (dispatcher strips
                // the ok envelope), so accept result-or-root.
                var node = root.TryGetProperty("result", out var result) ? result : root;
                var sections = node.GetProperty("sections");
                Assert.True(sections.TryGetProperty("expressions", out _),
                    $"Snapshot bundle is missing the expressions section: {snapshotText}");
                Assert.True(sections.TryGetProperty("ranges", out _),
                    $"Snapshot bundle is missing the ranges section: {snapshotText}");
            }
            catch (JsonException ex)
            {
                Assert.Fail($"GetAnalysisSnapshot bundle returned invalid JSON: {ex.Message}");
            }
            observed.Add(new("inspect-value-bundle", "snapshot + expressions + ranges in one bundled call", calls.Count, [.. calls]));
        }

        // 10. who-calls-x-both: ONE Xrefs(direction=both).
        {
            var calls = new List<string>();
            var xrefsText = await CallAsync(calls, "Xrefs", new { address = "0x140001040", direction = "both" });
            try
            {
                using var doc = JsonDocument.Parse(xrefsText);
                var root = doc.RootElement;
                // Wire text is the analyzed result payload (dispatcher strips
                // the ok envelope): expect the both-mode {to, from} fan-in.
                var node = root.TryGetProperty("result", out var result) ? result : root;
                Assert.True(node.TryGetProperty("to", out _) && node.TryGetProperty("from", out _),
                    $"Xrefs(both) is missing the to/from fan-in: {xrefsText}");
            }
            catch (JsonException ex)
            {
                Assert.Fail($"Xrefs(both) returned invalid JSON: {ex.Message}");
            }
            observed.Add(new("who-calls-x-both", "xrefs both directions in one call", calls.Count, [.. calls]));
        }

        // 11. static-to-live-bytes: absorbed into static-to-live above (same
        // tool, same function, bytes attached server-side).

        // 12. open-ghidra-longpoll: ONE OpenGhidraFile with the default long-poll
        // waitMs returning the ready import (no GetGhidraOpenStatus follow-up).
        // Last: the import registers its session.
        {
            var calls = new List<string>();
            var openText = await CallAsync(calls, "OpenGhidraFile", new { path = FixtureExe() });
            Assert.Contains("opened", openText);
            observed.Add(new("open-ghidra-longpoll", "open a Ghidra file with default long-poll wait in one call", calls.Count, [.. calls]));
        }

        var expected = ExpectedScenarios();
        Assert.Equal(expected.Length, observed.Count);
        for (var index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index].Scenario, observed[index].Scenario);
            Assert.Equal(expected[index].CallsPerTask, observed[index].CallsPerTask);
            Assert.Equal(expected[index].Calls, observed[index].Calls);
        }

        var report = new
        {
            schemaVersion = SchemaVersion,
            harness = "wire",
            scenarios = observed.Select(scenario => new
            {
                scenario = scenario.Scenario,
                description = scenario.Description,
                callsPerTask = scenario.CallsPerTask,
                calls = scenario.Calls,
            }).ToArray(),
            totals = new
            {
                scenarios = observed.Count,
                calls = observed.Sum(scenario => scenario.CallsPerTask),
            },
        };

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        // Writer regenerates ONLY the gitignored scratch artifact. To refresh
        // the committed mirror, run tools/regen-baseline.ps1 (copies
        // artifacts/benchmark/roundtrip-baseline.json over
        // docs/reverse-speedup/benchmarks/roundtrip-baseline.json) and commit
        // the mirror deliberately. Tests must not write committed files.
        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "roundtrip-baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, json);

        _output.WriteLine($"BASELINE scenarios={report.totals.scenarios} calls={report.totals.calls}");
        foreach (var scenario in observed)
            _output.WriteLine($"  {scenario.Scenario,-20} callsPerTask={scenario.CallsPerTask} [{string.Join(" -> ", scenario.Calls)}]");
        _output.WriteLine($"BASELINE artifact={artifactPath}");
        _output.WriteLine("BASELINE mirror refresh: tools/regen-baseline.ps1 (deliberate copy, then commit)");

        Assert.True(File.Exists(artifactPath));
    }

    /// <summary>
    /// WS7 ratchet (round-trip plan §4 item 2): the ORIGINAL Wave-A ceilings
    /// can only move by explicit plan amendment. Asserts the pinned expectations
    /// AND the committed mirror stay at or under budget per scenario and in
    /// total for the original 7. Wire drift is caught separately by the
    /// equality pin in RoundTrip_Baseline_OverWire; this test needs no harness.
    /// </summary>
    [Fact]
    public void RoundTrip_Calls_Never_Exceed_Original_Budget()
    {
        var ceilings = OriginalCeilings();
        var expected = ExpectedScenarios();

        foreach (var ceiling in ceilings)
        {
            var pinned = expected.First(scenario => scenario.Scenario == ceiling.Key);
            Assert.True(pinned.CallsPerTask <= ceiling.Value,
                $"{ceiling.Key}: pinned {pinned.CallsPerTask} exceeds original budget {ceiling.Value}. " +
                "Only an explicit round-trip plan amendment may raise this.");
        }
        var pinnedOriginalTotal = expected.Where(scenario => ceilings.ContainsKey(scenario.Scenario)).Sum(scenario => scenario.CallsPerTask);
        Assert.True(pinnedOriginalTotal <= OriginalTotalCeiling,
            $"Original total {pinnedOriginalTotal} exceeds original budget {OriginalTotalCeiling}.");

        var mirrorPath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "roundtrip-baseline.json");
        Assert.True(File.Exists(mirrorPath), $"Baseline mirror is missing: {mirrorPath}");
        using var document = JsonDocument.Parse(File.ReadAllText(mirrorPath));
        var scenarios = document.RootElement.GetProperty("scenarios").EnumerateArray().ToArray();
        var mirrorTotal = 0;
        foreach (var ceiling in ceilings)
        {
            var entry = scenarios.FirstOrDefault(scenario =>
                string.Equals(scenario.GetProperty("scenario").GetString(), ceiling.Key, StringComparison.Ordinal));
            Assert.False(entry.ValueKind == JsonValueKind.Undefined, $"Mirror is missing original scenario '{ceiling.Key}'.");
            var calls = entry.GetProperty("callsPerTask").GetInt32();
            mirrorTotal += calls;
            Assert.True(calls <= ceiling.Value,
                $"{ceiling.Key}: mirror {calls} exceeds original budget {ceiling.Value}.");
        }
        Assert.True(mirrorTotal <= OriginalTotalCeiling,
            $"Mirror original total {mirrorTotal} exceeds original budget {OriginalTotalCeiling}.");
    }

    /// <summary>
    /// Pins the committed mirror without opening the wire stack and without
    /// touching the gitignored scratch artifact: schema, scenario order,
    /// ordered tool calls and per-scenario counts, all read from docs/ only.
    /// Self-sufficient on a fresh clone (no artifacts/ needed). After a
    /// deliberate tools/regen-baseline.ps1 copy, this Fact proves the mirror
    /// carries exactly the pinned expectations.
    /// </summary>
    [Fact]
    public void RoundTrip_Baseline_Mirror_Matches_Pins()
    {
        var expected = ExpectedScenarios();
        var path = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "roundtrip-baseline.json");
        Assert.True(File.Exists(path), $"Baseline mirror is missing: {path}");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        Assert.Equal(SchemaVersion, root.GetProperty("schemaVersion").GetInt32());
        var scenarios = root.GetProperty("scenarios").EnumerateArray().ToArray();
        Assert.Equal(expected.Length, scenarios.Length);
        for (var index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index].Scenario, scenarios[index].GetProperty("scenario").GetString());
            Assert.Equal(expected[index].CallsPerTask, scenarios[index].GetProperty("callsPerTask").GetInt32());
            var calls = scenarios[index].GetProperty("calls").EnumerateArray().Select(e => e.GetString()).ToArray();
            Assert.Equal(expected[index].Calls, calls);
        }
        Assert.Equal(expected.Sum(s => s.CallsPerTask), root.GetProperty("totals").GetProperty("calls").GetInt32());
    }
}
