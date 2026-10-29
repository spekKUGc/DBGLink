using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
using static DbgLink.Tests.FixtureSeeds;

namespace DbgLink.Tests;

/// <summary>
/// Baseline harness for the reverse-speedup loop metric (I-01).
/// A naive cheap-agent annotation policy over three fixture functions:
/// for each function InspectFunction -> BatchAnnotate(rename+comment),
/// measured over the full wire stack (Kestrel HTTP + Win32 pipe + Ghidra TCP).
/// (P3: single-op RenameFunction/SetFunctionComment are purged; the naive
/// per-function policy now batches the two annotate ops.)
/// measured over the full wire stack (Kestrel HTTP + Win32 pipe + Ghidra TCP).
/// Every char count comes from the actual wire exchange; token counts are real
/// cl100k_base BPE counts (see TokenCounter), the same encoding production
/// telemetry counts with.
/// The report is written to artifacts/benchmark/reverse-cost-baseline.json
/// and mirrored into docs/reverse-speedup/benchmarks/ by the operator.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ReverseCostBenchmarkTests
{
    private const string Scenario = "annotate-fixture-functions";
    private const string Policy = "naive-per-function";
    private static readonly string[] FixtureFunctionNames = ["FixtureCaller", "FixtureCallee", "FixtureImportedPid"];

    private readonly ITestOutputHelper _output;

    public ReverseCostBenchmarkTests(ITestOutputHelper output) => _output = output;

    private static int Tok(string requestJson, string response)
        => TestWire.Tok(requestJson) + TestWire.Tok(response);

    private static string RepoRoot() => TestWire.RepoRoot();

    // ========================================================================================
    // Seeded Ghidra backend: realistic InspectFunction payload + slim mutation acks
    // ========================================================================================

    private static void SeedFixtureBackend(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var function = args?.GetProperty("function").GetString()
                ?? throw new InvalidOperationException("InspectFunction seed requires a function selector.");
            return JsonSerializer.Serialize(new { id, ok = true, result = BuildInspectResult(function) });
        });
        // BatchAnnotate result shaped like the Java bridge: one indexed row
        // per operation with the applied name/commentChars and journal flags.
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, args) =>
        {
            var operations = args!.Value.GetProperty("operations").EnumerateArray().ToArray();
            var results = new List<Dictionary<string, object>>();
            for (var index = 0; index < operations.Length; index++)
            {
                var operation = operations[index];
                var kind = operation.GetProperty("kind").GetString()!;
                var row = new Dictionary<string, object>
                {
                    ["index"] = index,
                    ["kind"] = kind,
                    ["function"] = "0x140001000",
                    ["ok"] = true,
                    ["committed"] = true,
                    ["journaled"] = true,
                };
                if (kind == "rename_function")
                    row["name"] = operation.GetProperty("name").GetString()!;
                else if (kind == "set_function_comment")
                    row["commentChars"] = operation.GetProperty("comment").GetString()!.Length;
                results.Add(row);
            }
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { success = true, applied = results.Count, failed = 0, results }
            });
        });
    }

    private sealed record FixtureRef(string Name, string Address);

    /// <summary>
    /// Single source of per-function fixture facts: every policy payload
    /// (InspectFunction and the AnalyzeFunctions digest) is built from these,
    /// so decompilation and reference data are never duplicated per policy.
    /// </summary>
    private sealed record FixtureSeed(
        string Entry,
        string Rva,
        string Decompilation,
        FixtureRef[] Callers,
        FixtureRef[] Callees,
        object[] Symbols,
        object[] Strings,
        object[] Constants);

    private static FixtureSeed Seed(string name) => name switch
    {
        "FixtureCaller" => new(
            "0x140001000",
            "0x1000",
            BuildDecompilation(name,
                "uVar7 = (undefined8)FixtureCallee((int)uVar4);",
                "uVar7 = uVar7 + (longlong)(int)(uint)*(undefined2 *)&FixtureUnicodePointer;"),
            [new("main", "0x1400010A0")],
            [new("FixtureCallee", "0x140001040")],
            new object[]
            {
                new { name, address = "0x140001000", kind = "FUNCTION" },
                new { name = "FixtureUnicodePointer", address = "0x140003000", kind = "DATA" },
            },
            new object[] { new { address = "0x140003000", value = "C:\\fixture\\input.txt", length = 20 } },
            new object[] { new { value = "0x2a", count = 3, firstAddress = "0x140001010" } }),
        "FixtureCallee" => new(
            "0x140001040",
            "0x1040",
            BuildDecompilation(name,
                "uVar7 = (undefined8)(iVar3 * 3 + 7);"),
            [new("FixtureCaller", "0x140001010"), new("main", "0x1400010B0")],
            [],
            new object[] { new { name, address = "0x140001040", kind = "FUNCTION" } },
            new object[] { new { address = "0x140003010", value = "callee-out", length = 10 } },
            new object[]
            {
                new { value = "0x3", count = 4, firstAddress = "0x140001058" },
                new { value = "0x7", count = 2, firstAddress = "0x140001060" },
            }),
        "FixtureImportedPid" => new(
            "0x140001080",
            "0x1080",
            BuildDecompilation(name,
                "uVar7 = GetCurrentProcessId();"),
            [new("main", "0x1400010C0")],
            [new("GetCurrentProcessId", "EXTERNAL:0000002A")],
            new object[]
            {
                new { name, address = "0x140001080", kind = "FUNCTION" },
                new { name = "GetCurrentProcessId", address = "EXTERNAL:0000002A", kind = "IMPORT" },
            },
            [],
            new object[] { new { value = "0x20", count = 2, firstAddress = "0x140001090" } }),
        _ => throw new ArgumentException($"No seeded fixture facts for '{name}'.", nameof(name)),
    };

    private static object BuildInspectResult(string name)
    {
        var seed = Seed(name);
        return new
        {
            function = name,
            entry = seed.Entry,
            rva = seed.Rva,
            decompilation = seed.Decompilation,
            references = new
            {
                callers = seed.Callers.Select(c => new { function = c.Name, from = c.Address, type = "CALL" }).ToArray(),
                callees = seed.Callees.Select(c => new { function = c.Name, to = c.Address, type = "CALL" }).ToArray(),
            },
            symbols = seed.Symbols,
            truncatedSections = Array.Empty<string>(),
        };
    }

    /// <summary>
    /// AnalyzeFunctions digest card assembled from the shared per-function
    /// seed: identity, brief callers/callees plus the strings/constants
    /// sections this iteration adds. The real Java digest also carries the C
    /// output (see the packet artifact's mockOmits): calls/function is the
    /// honest figure, tokens/function is optimistic because the mock omits
    /// decompilation, and the real token delta is unknown.
    /// </summary>
    private static object BuildAnalyzeResult(string[] functions)
    {
        var entries = new List<object>();
        for (var index = 0; index < functions.Length; index++)
        {
            var name = functions[index];
            var seed = Seed(name);
            entries.Add(new
            {
                index,
                selector = name,
                ok = true,
                function = new { name, entry = seed.Entry, rva = seed.Rva },
                references = new
                {
                    callers = seed.Callers.Select(c => new { name = c.Name, entry = c.Address }).ToArray(),
                    callees = seed.Callees.Select(c => new { name = c.Name, entry = c.Address }).ToArray(),
                },
                strings = seed.Strings,
                constants = seed.Constants,
            });
        }
        return new
        {
            schemaVersion = 2,
            functions = entries,
            truncated = false,
            truncatedSections = Array.Empty<string>(),
            maxChars = 24_000,
            maxItems = 8,
        };
    }

    /// <summary>
    /// Stable SHA-256 (lowercase hex) of the seeded InspectFunction result
    /// payloads in scenario order. The volatile response id is excluded, so the
    /// value changes only when the mock content drifts from the baseline.
    /// </summary>
    private static string MockFingerprint()
    {
        var payloads = string.Join('\n', FixtureFunctionNames.Select(
            function => JsonSerializer.Serialize(BuildInspectResult(function))));
        return FixtureSeeds.Sha256Hex(payloads);
    }

    // Decompilation listing shape: FixtureSeeds.BuildDecompilation
    // (Support/TestWire.cs), shared with the token baseline so the two
    // suites cannot drift.

    private static string RenamedName(string name) => name switch
    {
        "FixtureCaller" => "fixture_caller",
        "FixtureCallee" => "fixture_callee",
        "FixtureImportedPid" => "fixture_imported_pid",
        _ => throw new ArgumentException($"No rename for '{name}'.", nameof(name)),
    };

    private static string CommentFor(string name) => name switch
    {
        "FixtureCaller" => "Calls FixtureCallee(value) and adds the first UTF-16 unit of FixtureUnicodePointer.",
        "FixtureCallee" => "Returns value * 3 + 7.",
        "FixtureImportedPid" => "Returns GetCurrentProcessId() of the host process.",
        _ => throw new ArgumentException($"No comment for '{name}'.", nameof(name)),
    };

    private sealed record CallStat(string Name, string Function, int RequestChars, int ResponseChars, int Tokens);

    [Fact]
    public async Task NaiveAnnotation_Baseline_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedFixtureBackend(harness);

        var calls = new List<CallStat>();
        async Task CallAsync(string tool, object arguments, string function)
        {
            // The model emits {"name": ..., "arguments": {...}} for tools/call;
            // requestChars counts that envelope, responseChars the returned text,
            // and one real BPE count over both strings is charged per call.
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var response = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            var tokens = Tok(requestJson, response);
            calls.Add(new CallStat(tool, function, requestJson.Length, response.Length, tokens));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={response.Length,6}B tok~{tokens,4}");
        }

        foreach (var function in FixtureFunctionNames)
        {
            await CallAsync("InspectFunction", new { function }, function);
            await CallAsync("BatchAnnotate", new
            {
                operations = new object[]
                {
                    new { kind = "rename_function", function, name = RenamedName(function) },
                    new { kind = "set_function_comment", function, comment = CommentFor(function) },
                },
            }, function);
        }

        var perFunction = FixtureFunctionNames.Select(function => new
        {
            function,
            calls = calls.Count(call => call.Function == function),
            tokens = calls.Where(call => call.Function == function).Sum(call => call.Tokens),
        }).ToArray();

        var report = new
        {
            schemaVersion = 1,
            scenario = Scenario,
            policy = Policy,
            mockFingerprint = MockFingerprint(),
            functions = FixtureFunctionNames,
            calls = calls.Count,
            callsPerFunction = calls.Count / FixtureFunctionNames.Length,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate = calls.Sum(call => call.Tokens),
            perFunction,
        };

        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "reverse-cost-baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"BASELINE calls={report.calls} calls/function={report.callsPerFunction} " +
            $"req={report.requestChars}B resp={report.responseChars}B tokens~{report.tokensEstimate} " +
            $"({(double)report.tokensEstimate / FixtureFunctionNames.Length:F0} tok/function)");
        _output.WriteLine($"BASELINE artifact={artifactPath}");

        Assert.Equal(6, report.calls);
        Assert.All(perFunction, entry => Assert.Equal(2, entry.calls));
        Assert.True(report.tokensEstimate > 0);
        Assert.True(File.Exists(artifactPath));
    }

    // ========================================================================================
    // I-02 batched policy: 3 InspectFunction + 1 BatchAnnotate (3 rename + 3 comment)
    // ========================================================================================

    private const string BatchedPolicy = "batched-per-function";

    /// <summary>
    /// Java-bridge-shaped BatchAnnotate result: one indexed row per operation
    /// with the applied name/commentChars and journal flags, no fat identity.
    /// </summary>
    private static void SeedBatchAnnotateBackend(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, args) =>
        {
            var operations = args!.Value.GetProperty("operations").EnumerateArray().ToArray();
            var results = new List<Dictionary<string, object>>();
            for (var index = 0; index < operations.Length; index++)
            {
                var operation = operations[index];
                var kind = operation.GetProperty("kind").GetString()!;
                var row = new Dictionary<string, object>
                {
                    ["index"] = index,
                    ["kind"] = kind,
                    ["function"] = "0x140001000",
                    ["ok"] = true,
                    ["committed"] = true,
                    ["journaled"] = true,
                };
                if (kind == "rename_function")
                    row["name"] = operation.GetProperty("name").GetString()!;
                else if (kind == "set_function_comment")
                    row["commentChars"] = operation.GetProperty("comment").GetString()!.Length;
                results.Add(row);
            }
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { success = true, applied = results.Count, failed = 0, results }
            });
        });
    }

    [Fact]
    public async Task BatchedAnnotation_CutsCalls_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedFixtureBackend(harness);
        SeedBatchAnnotateBackend(harness);

        var calls = new List<CallStat>();
        async Task CallAsync(string tool, object arguments, string function)
        {
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var response = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            var tokens = Tok(requestJson, response);
            calls.Add(new CallStat(tool, function, requestJson.Length, response.Length, tokens));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={response.Length,6}B tok~{tokens,4}");
        }

        // Same evidence as the baseline policy: inspect every function, then
        // apply every rename and comment in one batched transaction call.
        foreach (var function in FixtureFunctionNames)
            await CallAsync("InspectFunction", new { function }, function);

        var operations = new List<object>();
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "rename_function", function, name = RenamedName(function) });
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "set_function_comment", function, comment = CommentFor(function) });
        await CallAsync("BatchAnnotate", new { operations }, "batch-annotate");

        var baselinePath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "reverse-cost-baseline.json");
        Assert.True(File.Exists(baselinePath), $"Committed baseline JSON is missing: {baselinePath}");
        using var baselineDocument = JsonDocument.Parse(File.ReadAllText(baselinePath));
        var baselineRoot = baselineDocument.RootElement;
        var baselineCalls = baselineRoot.GetProperty("calls").GetInt32();
        var baselineCallsPerFunction = baselineRoot.GetProperty("callsPerFunction").GetDouble();
        var baselineTokens = baselineRoot.GetProperty("tokensEstimate").GetInt32();
        var baselineTokensPerFunction = (double)baselineTokens / FixtureFunctionNames.Length;

        var callsPerFunction = (double)calls.Count / FixtureFunctionNames.Length;
        var tokensEstimate = calls.Sum(call => call.Tokens);
        var tokensPerFunction = (double)tokensEstimate / FixtureFunctionNames.Length;

        var report = new
        {
            schemaVersion = 1,
            scenario = Scenario,
            policy = BatchedPolicy,
            mockFingerprint = MockFingerprint(),
            functions = FixtureFunctionNames,
            batches = 1,
            appliedOperations = operations.Count,
            calls = calls.Count,
            callsPerFunction,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate,
            baseline = new
            {
                calls = baselineCalls,
                callsPerFunction = baselineCallsPerFunction,
                tokensEstimate = baselineTokens,
                tokensPerFunction = baselineTokensPerFunction,
            },
            delta = new
            {
                calls = calls.Count - baselineCalls,
                callsPerFunction = callsPerFunction - baselineCallsPerFunction,
                tokensEstimate = tokensEstimate - baselineTokens,
                tokensPerFunction = tokensPerFunction - baselineTokensPerFunction,
            },
        };

        // The committed baseline is never overwritten; this policy lands in a
        // separate artifact for the orchestrator to compare and archive.
        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "reverse-cost-iter02.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"BATCHED calls={report.calls} calls/function={callsPerFunction:F2} " +
            $"req={report.requestChars}B resp={report.responseChars}B tokens~{tokensEstimate} " +
            $"({tokensPerFunction:F0} tok/function)");
        _output.WriteLine(
            $"BATCHED delta vs baseline: calls {report.calls - baselineCalls:+#;-#;0} " +
            $"(calls/function {callsPerFunction - baselineCallsPerFunction:+0.00;-0.00;0}), " +
            $"tokens/function {tokensPerFunction - baselineTokensPerFunction:+0.0;-0.0;0}");
        _output.WriteLine($"BATCHED artifact={artifactPath}");

        Assert.True(calls.Count < baselineCalls,
            $"Batched policy must beat the baseline call count {baselineCalls}; got {calls.Count}.");
        Assert.True(callsPerFunction <= 2.0,
            $"Batched policy must stay at or below 2 calls/function; got {callsPerFunction:F2}.");
        // Tokens are parity, not a win: the batch envelope carries the same
        // chars in one array, and real BPE charges ~1% more for the combined
        // shape (measured 2028 vs baseline 2007). Guard against blowup, not noise.
        Assert.True(tokensEstimate <= baselineTokens * 1.1,
            $"Batched policy must stay within 10% of baseline tokens {baselineTokens}; got {tokensEstimate}.");
        Assert.True(tokensEstimate > 0);
        Assert.True(File.Exists(artifactPath));
    }

    // ========================================================================================
    // I-03 packet policy: 1 AnalyzeFunctions digest (3 functions with
    // strings/constants/refs) + 1 BatchAnnotate (3 rename + 3 comment)
    // = 2 calls on 3 functions.
    // ========================================================================================

    private const string PacketPolicy = "packet-per-batch";

    private static void SeedAnalyzeFunctionsBackend(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            var functions = args!.Value.GetProperty("functions").EnumerateArray()
                .Select(element => element.GetString()!)
                .ToArray();
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = BuildAnalyzeResult(functions),
            });
        });
    }

    [Fact]
    public async Task PacketAnnotation_CutsCallsAndTokens_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedBatchAnnotateBackend(harness);
        SeedAnalyzeFunctionsBackend(harness);

        var calls = new List<CallStat>();
        async Task CallAsync(string tool, object arguments, string function)
        {
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var response = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            var tokens = Tok(requestJson, response);
            calls.Add(new CallStat(tool, function, requestJson.Length, response.Length, tokens));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={response.Length,6}B tok~{tokens,4}");
        }

        // One digest call carries the inspect evidence for all three functions
        // (strings/constants included); one batched call applies every rename
        // and comment. Two turns cover the full annotation scenario.
        await CallAsync("AnalyzeFunctions", new
        {
            functions = FixtureFunctionNames,
            maxItems = 8,
        }, "digest-3-functions");

        var operations = new List<object>();
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "rename_function", function, name = RenamedName(function) });
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "set_function_comment", function, comment = CommentFor(function) });
        await CallAsync("BatchAnnotate", new { operations }, "batch-annotate");

        var baselinePath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "reverse-cost-baseline.json");
        Assert.True(File.Exists(baselinePath), $"Committed baseline JSON is missing: {baselinePath}");
        using var baselineDocument = JsonDocument.Parse(File.ReadAllText(baselinePath));
        var baselineRoot = baselineDocument.RootElement;
        var baselineCalls = baselineRoot.GetProperty("calls").GetInt32();
        var baselineCallsPerFunction = baselineRoot.GetProperty("callsPerFunction").GetDouble();
        var baselineTokens = baselineRoot.GetProperty("tokensEstimate").GetInt32();
        var baselineTokensPerFunction = (double)baselineTokens / FixtureFunctionNames.Length;

        // batched-per-function (I-02) = 3 InspectFunction + 1 BatchAnnotate.
        // Derived from the policy shape, not from the iter02 artifact: that
        // file is an untracked test output and may not exist yet.
        var batchedCalls = FixtureFunctionNames.Length + 1;

        var callsPerFunction = (double)calls.Count / FixtureFunctionNames.Length;
        var tokensEstimate = calls.Sum(call => call.Tokens);
        var tokensPerFunction = (double)tokensEstimate / FixtureFunctionNames.Length;

        var report = new
        {
            schemaVersion = 1,
            scenario = Scenario,
            policy = PacketPolicy,
            mockFingerprint = MockFingerprint(),
            functions = FixtureFunctionNames,
            batches = 1,
            digestFunctions = FixtureFunctionNames.Length,
            // The digest mock is the card (identity/refs/strings/constants);
            // the real Java response also carries the C output. Consumers must
            // treat the token delta as optimistic until that payload is modeled.
            mockOmits = new[] { "decompilation" },
            appliedOperations = operations.Count,
            calls = calls.Count,
            callsPerFunction,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate,
            baseline = new
            {
                calls = baselineCalls,
                callsPerFunction = baselineCallsPerFunction,
                tokensEstimate = baselineTokens,
                tokensPerFunction = baselineTokensPerFunction,
            },
            batched = new
            {
                calls = batchedCalls,
                callsPerFunction = (double)batchedCalls / FixtureFunctionNames.Length,
            },
            delta = new
            {
                calls = calls.Count - baselineCalls,
                callsPerFunction = callsPerFunction - baselineCallsPerFunction,
                tokensEstimate = tokensEstimate - baselineTokens,
                tokensPerFunction = tokensPerFunction - baselineTokensPerFunction,
            },
        };

        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "reverse-cost-iter03.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"PACKET calls={report.calls} calls/function={callsPerFunction:F2} " +
            $"req={report.requestChars}B resp={report.responseChars}B tokens~{tokensEstimate} " +
            $"({tokensPerFunction:F0} tok/function)");
        _output.WriteLine(
            $"PACKET delta vs baseline: calls {report.calls - baselineCalls:+#;-#;0} " +
            $"(calls/function {callsPerFunction - baselineCallsPerFunction:+0.00;-0.00;0}), " +
            $"tokens/function {tokensPerFunction - baselineTokensPerFunction:+0.0;-0.0;0}");
        _output.WriteLine($"PACKET artifact={artifactPath}");

        Assert.True(calls.Count < batchedCalls,
            $"Packet policy must beat the batched-policy call count {batchedCalls}; got {calls.Count}.");
        Assert.True(callsPerFunction <= 2.0,
            $"Packet policy must stay at or below 2 calls/function; got {callsPerFunction:F2}.");
        Assert.True(tokensEstimate <= baselineTokens,
            $"Packet policy must not cost more tokens than baseline {baselineTokens}; got {tokensEstimate}.");
        Assert.True(tokensEstimate > 0);
        Assert.True(File.Exists(artifactPath));
    }

    // ========================================================================================
    // I-11 honest packet policy: 1 AnalyzeFunctions digest (3 functions WITH
    // decompilation + strings/constants/refs) + 1 BatchAnnotate = 2 calls.
    // Unlike I-03, the mock carries the real digest payload, so the token
    // delta is honest: it is recorded as-is, even if above the baseline.
    // ========================================================================================

    private const string PacketHonestPolicy = "packet-honest";

    /// <summary>
    /// Honest digest card: same identity/refs/strings/constants as the I-03
    /// card plus the real per-function decompilation from the shared seed.
    /// </summary>
    private static object BuildHonestAnalyzeResult(string[] functions)
    {
        var entries = new List<object>();
        for (var index = 0; index < functions.Length; index++)
        {
            var name = functions[index];
            var seed = Seed(name);
            entries.Add(new
            {
                index,
                selector = name,
                ok = true,
                function = new { name, entry = seed.Entry, rva = seed.Rva },
                decompilation = seed.Decompilation,
                references = new
                {
                    callers = seed.Callers.Select(c => new { name = c.Name, entry = c.Address }).ToArray(),
                    callees = seed.Callees.Select(c => new { name = c.Name, entry = c.Address }).ToArray(),
                },
                strings = seed.Strings,
                constants = seed.Constants,
            });
        }
        return new
        {
            schemaVersion = 2,
            functions = entries,
            truncated = false,
            truncatedSections = Array.Empty<string>(),
            maxChars = 24_000,
            maxItems = 8,
        };
    }

    private static void SeedHonestAnalyzeFunctionsBackend(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            var functions = args!.Value.GetProperty("functions").EnumerateArray()
                .Select(element => element.GetString()!)
                .ToArray();
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = BuildHonestAnalyzeResult(functions),
            });
        });
    }

    [Fact]
    public async Task PacketHonestAnnotation_HonestDigest_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedBatchAnnotateBackend(harness);
        SeedHonestAnalyzeFunctionsBackend(harness);

        var calls = new List<CallStat>();
        async Task CallAsync(string tool, object arguments, string function)
        {
            var requestJson = JsonSerializer.Serialize(new { name = tool, arguments });
            var response = TextOf(await harness.CallToolOverWireAsync(tool, arguments));
            var tokens = Tok(requestJson, response);
            calls.Add(new CallStat(tool, function, requestJson.Length, response.Length, tokens));
            _output.WriteLine($"  {function,-18} {tool,-17} req={requestJson.Length,5}B resp={response.Length,6}B tok~{tokens,4}");
        }

        // One honest digest call carries the inspect evidence for all three
        // functions (decompilation + strings/constants included); one batched
        // call applies every rename and comment.
        await CallAsync("AnalyzeFunctions", new
        {
            functions = FixtureFunctionNames,
            maxItems = 8,
        }, "digest-3-functions");

        var operations = new List<object>();
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "rename_function", function, name = RenamedName(function) });
        foreach (var function in FixtureFunctionNames)
            operations.Add(new { kind = "set_function_comment", function, comment = CommentFor(function) });
        await CallAsync("BatchAnnotate", new { operations }, "batch-annotate");

        var baselinePath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "reverse-cost-baseline.json");
        Assert.True(File.Exists(baselinePath), $"Committed baseline JSON is missing: {baselinePath}");
        using var baselineDocument = JsonDocument.Parse(File.ReadAllText(baselinePath));
        var baselineRoot = baselineDocument.RootElement;
        var baselineCalls = baselineRoot.GetProperty("calls").GetInt32();
        var baselineCallsPerFunction = baselineRoot.GetProperty("callsPerFunction").GetDouble();
        var baselineTokens = baselineRoot.GetProperty("tokensEstimate").GetInt32();
        var baselineTokensPerFunction = (double)baselineTokens / FixtureFunctionNames.Length;

        var callsPerFunction = (double)calls.Count / FixtureFunctionNames.Length;
        var tokensEstimate = calls.Sum(call => call.Tokens);
        var tokensPerFunction = (double)tokensEstimate / FixtureFunctionNames.Length;

        var report = new
        {
            schemaVersion = 1,
            scenario = Scenario,
            policy = PacketHonestPolicy,
            mockFingerprint = MockFingerprint(),
            functions = FixtureFunctionNames,
            batches = 1,
            digestFunctions = FixtureFunctionNames.Length,
            // Honest mock: the digest carries decompilation, strings and
            // constants, so nothing is omitted and the token delta is real.
            mockOmits = Array.Empty<string>(),
            appliedOperations = operations.Count,
            calls = calls.Count,
            callsPerFunction,
            requestChars = calls.Sum(call => call.RequestChars),
            responseChars = calls.Sum(call => call.ResponseChars),
            tokensEstimate,
            baseline = new
            {
                calls = baselineCalls,
                callsPerFunction = baselineCallsPerFunction,
                tokensEstimate = baselineTokens,
                tokensPerFunction = baselineTokensPerFunction,
            },
            delta = new
            {
                calls = calls.Count - baselineCalls,
                callsPerFunction = callsPerFunction - baselineCallsPerFunction,
                tokensEstimate = tokensEstimate - baselineTokens,
                tokensPerFunction = tokensPerFunction - baselineTokensPerFunction,
            },
        };

        // The committed baseline is never overwritten; this policy lands in a
        // separate artifact for the orchestrator to compare and archive.
        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "reverse-cost-iter11.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        _output.WriteLine(
            $"PACKET-HONEST calls={report.calls} calls/function={callsPerFunction:F2} " +
            $"req={report.requestChars}B resp={report.responseChars}B tokens~{tokensEstimate} " +
            $"({tokensPerFunction:F0} tok/function)");
        _output.WriteLine(
            $"PACKET-HONEST delta vs baseline: calls {report.calls - baselineCalls:+#;-#;0} " +
            $"(calls/function {callsPerFunction - baselineCallsPerFunction:+0.00;-0.00;0}), " +
            $"tokens/function {tokensPerFunction - baselineTokensPerFunction:+0.0;-0.0;0}");
        _output.WriteLine($"PACKET-HONEST artifact={artifactPath}");

        // Honest metric: only the call shape is asserted (1 packet + 1 batch
        // annotate); every call is already verified error-free by TextOf.
        // The token delta is recorded as-is, even if above the baseline.
        Assert.Equal(2, calls.Count);
        Assert.True(tokensEstimate > 0);
        Assert.True(File.Exists(artifactPath));
    }
}
