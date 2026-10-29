using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using DbgLink.Shared;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Hostile fuzzing and adversarial validation specifically targeting LiveAnalysisTools invariants:
/// - AssessConsistency state machine & debugger race conditions
/// - BuildSnapshotSummary normalization (e.g. x64dbg post-mortem running=true anomaly)
/// - TrimModuleRecordsToBudget memory/char starvation limits
/// - HasAnalysisSnapshotCapability JSON depth and malformed payload resilience
/// - Debug target command-line injection protection (&quot; quotes and control characters)
/// - TraceUntil target mnemonic / address matching edge-cases
/// </summary>
public sealed class LiveAnalysisToolsHostileFuzzTests
{
    // ========================================================================================
    // 1. AssessConsistency: Debugger State Consistency & Race Condition Tests
    // ========================================================================================

    [Fact]
    public void AssessConsistency_NullOrEmptyStates_ReturnsUnavailable()
    {
        var result1 = AnalysisSnapshotSummary.AssessConsistency(null, null);
        Assert.Equal("unavailable", result1["status"]!.GetValue<string>());
        Assert.False(result1["atomic"]!.GetValue<bool>());

        var result2 = AnalysisSnapshotSummary.AssessConsistency(new JsonObject(), new JsonObject());
        Assert.Equal("unavailable", result2["status"]!.GetValue<string>());

        var result3 = AnalysisSnapshotSummary.AssessConsistency(null, CreateValidState());
        Assert.Equal("unavailable", result3["status"]!.GetValue<string>());

        var result4 = AnalysisSnapshotSummary.AssessConsistency(CreateValidState(), null);
        Assert.Equal("unavailable", result4["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-999)]
    public void AssessConsistency_InvalidDebuggerPid_ReturnsUnavailable(int pid)
    {
        var before = CreateValidState();
        before["debuggerPid"] = pid;
        var after = CreateValidState();

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("unavailable", result["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("12.34")]
    [InlineData("-5")]
    [InlineData("")]
    public void AssessConsistency_NonNumericGeneration_ReturnsUnavailable(string gen)
    {
        var before = CreateValidState();
        before["generation"] = gen;
        var after = CreateValidState();

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("unavailable", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_StableReadFalseInEitherState_ReturnsChanged()
    {
        var before = CreateValidState();
        before["stableRead"] = false;
        var after = CreateValidState();

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("changed", result["status"]!.GetValue<string>());

        var before2 = CreateValidState();
        var after2 = CreateValidState();
        after2["stableRead"] = false;

        var result2 = AnalysisSnapshotSummary.AssessConsistency(before2, after2);
        Assert.Equal("changed", result2["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_MismatchedGenerations_ReturnsChanged()
    {
        var before = CreateValidState();
        before["generation"] = "100";
        var after = CreateValidState();
        after["generation"] = "101";

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("changed", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_MismatchedPids_ReturnsChanged()
    {
        var before = CreateValidState();
        before["debuggerPid"] = 1234;
        var after = CreateValidState();
        after["debuggerPid"] = 5678;

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("changed", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_MismatchedThreadId_ReturnsChanged()
    {
        var before = CreateValidState();
        before["threadId"] = 10;
        var after = CreateValidState();
        after["threadId"] = 20;

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("changed", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_NotDebugging_ReturnsNotDebugging()
    {
        var before = CreateValidState();
        before["debugging"] = false;
        var after = CreateValidState();
        after["debugging"] = false;

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("not_debugging", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_TargetRunning_ReturnsRunning()
    {
        var before = CreateValidState();
        before["running"] = true;
        var after = CreateValidState();
        after["running"] = true;

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("running", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_ZeroOrMissingThreadId_DoesNotReturnUnchanged()
    {
        var before = CreateValidState();
        before["threadId"] = 0;
        var after = CreateValidState();
        after["threadId"] = 0;

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.NotEqual("unchanged", result["status"]!.GetValue<string>());
    }

    [Fact]
    public void AssessConsistency_ValidIdenticalPausedState_ReturnsUnchanged()
    {
        var before = CreateValidState();
        var after = CreateValidState();

        var result = AnalysisSnapshotSummary.AssessConsistency(before, after);
        Assert.Equal("unchanged", result["status"]!.GetValue<string>());
        // Token saver: unchanged omits before/after/scope clones, keeps generation+threadId.
        Assert.NotNull(result["generation"]);
        Assert.NotNull(result["threadId"]);
        // Changed states must still carry full before/after for diagnosis.
        var changedAfter = CreateValidState();
        changedAfter["generation"] = "2";
        var changed = AnalysisSnapshotSummary.AssessConsistency(before, changedAfter);
        Assert.Equal("changed", changed["status"]!.GetValue<string>());
        Assert.Null(changed["before"]);
        Assert.NotNull(changed["after"]);
    }

    // ========================================================================================
    // 2. BuildSnapshotSummary: State Transitions & x64dbg Post-Mortem Normalization
    // ========================================================================================

    [Fact]
    public void BuildSnapshotSummary_NormalizesX64DbgPostMortemRunningBug()
    {
        // When debuggee terminates, x64dbg sometimes keeps reporting running=true while debugging=false.
        // BuildSnapshotSummary MUST normalize running to false so AI agent does not try to pause it.
        var state = CreateValidState();
        state["debugging"] = false;
        state["running"] = true;

        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(state, null, "not_debugging");
        Assert.False(summary["running"]!.GetValue<bool>());
        Assert.Equal("not_debugging", summary["consistency"]!.GetValue<string>());
        Assert.Contains("Start or attach", summary["nextAction"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("running", "Pause the debugger")]
    [InlineData("not_debugging", "Start or attach")]
    [InlineData("changed", "Repeat the snapshot after")]
    [InlineData("unavailable", "native debugger bridge is ready")]
    [InlineData("alien_status", "native debugger bridge is ready")]
    public void BuildSnapshotSummary_VariousConsistencyStatuses_ProvidesActionableAdvice(string status, string expectedText)
    {
        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(CreateValidState(), null, status);
        Assert.Contains(expectedText, summary["nextAction"]!.GetValue<string>());
    }

    [Fact]
    public void BuildSnapshotSummary_UnchangedWithErrors_AdvisesReviewingErrors()
    {
        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", errorCount: 3);
        Assert.Contains("Review errors", summary["nextAction"]!.GetValue<string>());
    }

    [Fact]
    public void BuildSnapshotSummary_UnchangedWithTruncation_AdvisesIncreasingBudget()
    {
        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", truncated: true);
        Assert.Contains("higher maxChars", summary["nextAction"]!.GetValue<string>());
    }

    [Fact]
    public void BuildSnapshotSummary_UnchangedClean_AdvisesCorrelation()
    {
        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", errorCount: 0, truncated: false);
        Assert.Contains("Use the snapshot for static/live correlation", summary["nextAction"]!.GetValue<string>());
        Assert.Equal("unchanged", summary["consistency"]!.GetValue<string>());
    }

    [Fact]
    public void BuildSnapshotSummary_TransportSavings_LiveOnlyAtTopLevel()
    {
        // Transport and roundTripsSaved are reported once on the envelope;
        // the summary no longer repeats them.
        var summaryIndividual = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", includeThreads: true, includeModules: true, transport: "individual");
        Assert.Null(summaryIndividual["roundTripsSaved"]);
        Assert.Null(summaryIndividual["transport"]);

        var summaryBatched = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", includeThreads: true, includeModules: true, transport: "batched");
        Assert.Null(summaryBatched["roundTripsSaved"]);
        Assert.Null(summaryBatched["transport"]);
    }

    [Fact]
    public void BuildSnapshotSummary_SectionsTracking_SeparatesIncludedFromOmitted()
    {
        // P0-1 token trim: the summary no longer echoes included/omitted
        // section lists (the sections object itself is authoritative).
        // The skipped list is the only section tracking that remains.
        var sections = new JsonObject
        {
            ["context"] = "CIP=0x140001000",
            ["callStack"] = "frame 0",
            ["modules"] = new JsonObject { ["omitted"] = true, ["reason"] = "response_budget" }
        };

        var summary = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged", sections: sections);

        Assert.Null(summary["includedSections"]);
        Assert.Null(summary["omittedSections"]);
        Assert.Null(summary["skippedSections"]);

        var withSkipped = AnalysisSnapshotSummary.BuildSnapshotSummary(
            CreateValidState(), null, "unchanged",
            skipped: new JsonArray("threads"));
        Assert.Equal("threads", withSkipped["skippedSections"]![0]!.GetValue<string>());
    }

    // ========================================================================================
    // 3. TrimModuleRecordsToBudget: String & Memory Starvation
    // ========================================================================================

    [Fact]
    public void TrimModuleRecordsToBudget_AmpleBudget_RetainsAllRecords()
    {
        var records = new JsonArray
        {
            new JsonObject { ["name"] = "app.exe", ["base"] = "0x140000000", ["size"] = "0x10000" },
            new JsonObject { ["name"] = "ntdll.dll", ["base"] = "0x7FFE00000", ["size"] = "0x20000" }
        };
        var moduleResult = new JsonObject { ["modules"] = records };

        AnalysisSnapshotSummary.TrimModuleRecordsToBudget(moduleResult, records, remainingChars: 10_000);

        Assert.Equal(2, moduleResult["returnedCount"]!.GetValue<int>());
        Assert.Equal(2, records.Count);
        Assert.Null(moduleResult["truncated"]);
    }

    [Fact]
    public void TrimModuleRecordsToBudget_ZeroOrNegativeBudget_ClearsAllAndMarksTruncated()
    {
        var records = new JsonArray
        {
            new JsonObject { ["name"] = "app.exe", ["base"] = "0x140000000" }
        };
        var moduleResult = new JsonObject { ["modules"] = records };

        AnalysisSnapshotSummary.TrimModuleRecordsToBudget(moduleResult, records, remainingChars: 0);

        Assert.Equal(0, moduleResult["returnedCount"]!.GetValue<int>());
        Assert.Empty(records);
        Assert.True(moduleResult["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public void TrimModuleRecordsToBudget_TightBudget_TrimsPartialRecords()
    {
        var records = new JsonArray();
        for (var i = 0; i < 50; i++)
        {
            records.Add(new JsonObject
            {
                ["name"] = $"mod_{i:D3}.dll",
                ["base"] = $"0x{0x10000000 + i * 0x10000:X8}",
                ["size"] = "0x10000"
            });
        }
        var moduleResult = new JsonObject { ["modules"] = records };

        // Provide tight budget that can fit only ~5-10 records
        AnalysisSnapshotSummary.TrimModuleRecordsToBudget(moduleResult, records, remainingChars: 400);

        var returnedCount = moduleResult["returnedCount"]!.GetValue<int>();
        Assert.True(returnedCount > 0 && returnedCount < 50);
        Assert.Equal(returnedCount, records.Count);
        Assert.True(moduleResult["truncated"]!.GetValue<bool>());
    }

    // ========================================================================================
    // 4. HasAnalysisSnapshotCapability: JSON Schema & Resilience
    // ========================================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \t\r\n")]
    [InlineData("{")]
    [InlineData("{capabilities:")]
    [InlineData("{\"capabilities\": null}")]
    [InlineData("{\"capabilities\": []}")]
    [InlineData("{\"capabilities\": \"true\"}")]
    [InlineData("{\"capabilities\": {\"analysisSnapshot\": false}}")]
    [InlineData("{\"capabilities\": {\"analysisSnapshot\": \"true\"}}")] // String instead of bool
    [InlineData("{\"capabilities\": {\"analysisSnapshot\": 1}}")]      // Number instead of bool
    [InlineData("{\"capabilities\": {\"analysisSnapshot\": null}}")]
    public void HasAnalysisSnapshotCapability_InvalidOrFalsePayloads_ReturnsFalse(string? payload)
    {
        Assert.False(AnalysisSnapshotSummary.HasAnalysisSnapshotCapability(payload));
    }

    [Fact]
    public void HasAnalysisSnapshotCapability_ValidTruePayload_ReturnsTrue()
    {
        var payload = "{\"capabilities\": {\"analysisSnapshot\": true, \"other\": 123}}";
        Assert.True(AnalysisSnapshotSummary.HasAnalysisSnapshotCapability(payload));
    }

    [Fact]
    public void HasAnalysisSnapshotCapability_DeeplyNestedPayload_DoesNotThrow()
    {
        // MaxDepth is 8, so an adversarial nested payload must not throw unhandled exception
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < 20; i++) sb.Append("{\"nested\":");
        sb.Append("true");
        for (int i = 0; i < 20; i++) sb.Append('}');

        var result = AnalysisSnapshotSummary.HasAnalysisSnapshotCapability(sb.ToString());
        Assert.False(result);
    }

    // ========================================================================================
    // 5. Debug Target Path & Injection Invariants
    // ========================================================================================

    [Fact]
    public async Task OpenDebugTargetAsync_EmbeddedQuote_RejectedForSafety()
    {
        var context = new AnalysisContext(new DummyBridge(), new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        // x64dbg `init` command interpolation cannot escape quotes: any quotes must be rejected.
        var maliciousArgs = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["path"] = "C:\\Windows\\notepad.exe\" && calc.exe"
        });

        var response = await tools.OpenDebugTargetAsync(maliciousArgs, CancellationToken.None);
        Assert.Contains("debug_target_invalid", response);
    }

    [Fact]
    public async Task OpenDebugTargetAsync_ControlCharactersInArguments_RejectedForSafety()
    {
        var context = new AnalysisContext(new DummyBridge(), new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var maliciousArgs = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["path"] = "C:\\Windows\\notepad.exe",
            ["arguments"] = "arg1\r\n malicious_command"
        });

        var response = await tools.OpenDebugTargetAsync(maliciousArgs, CancellationToken.None);
        Assert.Contains("debug_target_invalid", response);
    }

    [Fact]
    public async Task OpenDebugTargetAsync_NonExistentFile_Rejected()
    {
        var context = new AnalysisContext(new DummyBridge(), new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["path"] = "C:\\Windows\\NonExistentFile_123456789.exe"
        });

        var response = await tools.OpenDebugTargetAsync(args, CancellationToken.None);
        Assert.Contains("debug_target_invalid", response);
    }

    [Fact]
    public async Task OpenDebugTargetAsync_DisallowedExtension_Rejected()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[] { 1, 2, 3 });
            var context = new AnalysisContext(new DummyBridge(), new DummyGhidra());
            var tools = new LiveAnalysisTools(context);

            var args = JsonSerializer.SerializeToElement(new JsonObject
            {
                ["path"] = tempFile // .tmp extension, not .exe or .dll
            });

            var response = await tools.OpenDebugTargetAsync(args, CancellationToken.None);
            Assert.Contains("debug_target_invalid", response);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    // ========================================================================================
    // 6. TraceUntil: Stop Condition & Address Matching
    // ========================================================================================

    [Fact]
    public async Task TraceUntilAsync_NegativeMaxSteps_Rejected()
    {
        var context = new AnalysisContext(new DummyBridge(), new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["maxSteps"] = -5
        });

        var response = await tools.TraceUntilAsync(args, CancellationToken.None);
        Assert.Contains("invalid_argument", response);
    }

    [Fact]
    public async Task TraceUntilAsync_AlreadyAtTargetAddress_StopsImmediately()
    {
        var bridge = new TraceMockBridge
        {
            CurrentAddress = "0x140001050",
            CurrentInstruction = "mov rax, rbx"
        };
        var context = new AnalysisContext(bridge, new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["stopAddress"] = "0x140001050",
            ["maxSteps"] = 10
        });

        var response = await tools.TraceUntilAsync(args, CancellationToken.None);
        Assert.Contains("already_at_target", response);
        Assert.Equal(0, bridge.StepsTaken);
    }

    [Fact]
    public async Task TraceUntilAsync_MnemonicMatchCaseInsensitive_StopsWhenReached()
    {
        var bridge = new TraceMockBridge
        {
            CurrentAddress = "0x140001000",
            CurrentInstruction = "nop",
            TargetInstructionAtStep = "RET"
        };
        var context = new AnalysisContext(bridge, new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["stopAt"] = "ret",
            ["maxSteps"] = 10
        });

        var response = await tools.TraceUntilAsync(args, CancellationToken.None);
        Assert.Contains("matched_mnemonic", response);
        Assert.True(bridge.StepsTaken > 0);
    }

    [Fact]
    public async Task TraceUntilAsync_NativeBridgeEvaluateExpression_MatchesTruthyValueHex()
    {
        var bridge = new TraceMockBridge
        {
            CurrentAddress = "0x140001000",
            CurrentInstruction = "nop",
            EvaluateExpressionResponse = new
            {
                ok = true,
                result = new
                {
                    expression = "rax == 1",
                    valueHex = "0x1",
                    valueUnsigned = "1",
                    valueSigned = "1"
                }
            }
        };
        var context = new AnalysisContext(bridge, new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["condition"] = "rax == 1",
            ["maxSteps"] = 5
        });

        var response = await tools.TraceUntilAsync(args, CancellationToken.None);
        Assert.Contains("matched_condition", response);
    }

    [Fact]
    public async Task TraceUntilAsync_ZeroPaddedHex_DoesNotMatchConditionAsTruthy()
    {
        var bridge = new TraceMockBridge
        {
            CurrentAddress = "0x140001000",
            CurrentInstruction = "nop",
            EvaluateExpressionResponse = new
            {
                ok = true,
                result = new
                {
                    expression = "rax == 1",
                    valueHex = "0x0000000000000000",
                    valueUnsigned = "0",
                    valueSigned = "0"
                }
            }
        };
        var context = new AnalysisContext(bridge, new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["condition"] = "rax == 1",
            ["maxSteps"] = 2
        });

        var response = await tools.TraceUntilAsync(args, CancellationToken.None);
        Assert.DoesNotContain("matched_condition", response);
        Assert.Contains("max_steps_reached", response);
    }

    [Fact]
    public async Task GetAnalysisSnapshotAsync_CompactModules_With_LowBudget_TrimsFoldedModulesConsistently()
    {
        var modules = new JsonArray();
        for (int i = 0; i < 20; i++)
        {
            modules.Add(new JsonObject
            {
                ["name"] = i < 15 ? $"kernel_{i}.dll" : $"user_{i}.dll",
                ["path"] = i < 15 ? $"C:\\Windows\\System32\\kernel_{i}.dll" : $"C:\\App\\user_{i}.dll",
                ["base"] = $"0x{0x7FFE0000 + i * 0x10000:X8}",
                ["end"] = $"0x{0x7FFE0000 + (i + 1) * 0x10000:X8}"
            });
        }

        var bridge = new TraceMockBridge
        {
            ModuleRecordsResponse = new
            {
                ok = true,
                result = new
                {
                    modules = modules
                }
            }
        };
        var context = new AnalysisContext(bridge, new DummyGhidra());
        var tools = new LiveAnalysisTools(context);

        // compactModules is true with ample budget
        var args = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["compactModules"] = true,
            ["includeModules"] = true,
            ["maxChars"] = 10_000
        });

        var response = await tools.GetAnalysisSnapshotAsync(args, CancellationToken.None);
        var node = AnalysisFormatting.ReadBridgeResultNode(response) as JsonObject;
        Assert.NotNull(node);
        var sections = node["sections"] as JsonObject;
        Assert.NotNull(sections);
        var modulesSection = sections["modules"] as JsonObject;
        Assert.NotNull(modulesSection);

        var returnedArr = modulesSection["modules"] as JsonArray;
        Assert.NotNull(returnedArr);
        var rCount = modulesSection["returnedCount"]!.GetValue<int>();
        Assert.Equal(returnedArr.Count, rCount);
    }

    // ========================================================================================
    // Helpers & Mock Bridges
    // ========================================================================================

    private static JsonObject CreateValidState() => new()
    {
        ["debuggerPid"] = 4321,
        ["generation"] = "42",
        ["debugging"] = true,
        ["running"] = false,
        ["stableRead"] = true,
        ["threadId"] = 1u
    };

    private sealed class DummyBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"result\": {}}");
    }

    private sealed class DummyGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"result\": {}}");
    }

    private sealed class TraceMockBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public int StepsTaken { get; private set; }
        public string CurrentAddress { get; set; } = "0x140001000";
        public string CurrentInstruction { get; set; } = "nop";
        public string? TargetInstructionAtStep { get; set; }
        public object? EvaluateExpressionResponse { get; set; }
        public object? ModuleRecordsResponse { get; set; }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (method == "EvaluateExpression" && EvaluateExpressionResponse is not null)
            {
                return Task.FromResult(JsonSerializer.Serialize(EvaluateExpressionResponse));
            }
            if (method == "GetModuleRecords" && ModuleRecordsResponse is not null)
            {
                return Task.FromResult(JsonSerializer.Serialize(ModuleRecordsResponse));
            }
            if (method == "StepInto" || method == "StepOver" || method == "StepOut")
            {
                StepsTaken++;
                if (TargetInstructionAtStep is not null)
                {
                    CurrentInstruction = TargetInstructionAtStep;
                }
                return Task.FromResult("{\"ok\": true, \"result\": {\"stepped\": true}}");
            }
            if (method == "GetSnapshotState")
            {
                return Task.FromResult(JsonSerializer.Serialize(new
                {
                    ok = true,
                    result = new
                    {
                        debuggerPid = 1234,
                        generation = "1",
                        debugging = true,
                        running = false,
                        stableRead = true,
                        threadId = 1
                    }
                }));
            }
            if (method == "ReadDisassemblyChunk")
            {
                return Task.FromResult(JsonSerializer.Serialize(new
                {
                    ok = true,
                    result = new
                    {
                        instructions = new[]
                        {
                            new { address = CurrentAddress, instruction = CurrentInstruction }
                        }
                    }
                }));
            }
            if (method == "GetServerStatus")
            {
                return Task.FromResult("{\"ok\": true, \"capabilities\": {\"analysisSnapshot\": false}}");
            }
            if (method == "GetCurrentContext")
            {
                return Task.FromResult("{\"ok\": true, \"result\": \"CIP=0x140001000 | RAX=0x0\"}");
            }
            if (method == "GetCallStack")
            {
                return Task.FromResult("{\"ok\": true, \"result\": \"frame 0\"}");
            }
            return Task.FromResult("{\"ok\": true, \"result\": {}}");
        }
    }
}
