extern alias Server;
using DbgLink.Server;
using DbgLink.Shared;
using JsonProtocolValidation = Server::DbgLink.Shared.JsonProtocolValidation;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using Xunit.Abstractions;

namespace DbgLink.Tests;

/// <summary>
/// Adversarial fuzzing and robustness regression suite covering edge-case panics,
/// arithmetic overflows, unhandled exceptions, race conditions, and recursion traps.
/// </summary>
public sealed class FuzzAndRobustnessTests
{
    private readonly ITestOutputHelper _output;

    public FuzzAndRobustnessTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // ========================================================================================
    // 1. ADVERSARIAL STRING FUZZING & CORRUPT REGISTER CONTEXT
    // ========================================================================================

    [Fact]
    public void Fuzz_FormatSparseContext_With_Extreme_Anomalous_Strings_MustNeverThrow()
    {
        var malformedInputs = new[]
        {
            "",
            " ",
            "    ",
            "||||||||||||||||||",
            "| | | |",
            "=== === ===",
            "CIP= RAX= RBX=",
            "=0x1000 =0x2000 =",
            "CIP=0x",
            "CIP=0xZZZZZZZZZZZZZZZZ",
            "CIP=0x140001000 | | | RAX=0x0 | STACK: [00]= | DISASM:",
            "CIP=0x140001000 | RAX=0x0 RBX=0x0000000000000000 RCX=0x |",
            "CIP=0x140001000\0RAX=0x0\0RBX=0x1", // Null byte injection
            "CIP=0x140001000 \r\n\t RAX=0x0 \r\n\t RBX=0x0 \r\n\t",
            "CIP=0x140001000 | RAX=0x-1 RBX=0x+0 RCX=0x000000",
            string.Join(" | ", Enumerable.Range(0, 1000).Select(i => $"REG_{i}=0x{i:X}")), // Huge context
            new string('|', 50_000), // Massive delimiter run
            "CIP=0x140001000 | DISASM: " + new string('A', 20_000)
        };

        foreach (var input in malformedInputs)
        {
            var node = (JsonNode)JsonValue.Create(input);
            var ex = Record.Exception(() => AnalysisFormatting.FormatSparseContext(node));
            Assert.Null(ex); // Must never throw ANY exception
        }
    }

    [Fact]
    public void Fuzz_FormatDiffContext_With_Extreme_Anomalous_Strings_MustNeverThrow()
    {
        var dict = new SessionSnapshotState();
        dict.ReplaceRegisters(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CIP"] = "0x140001000",
            ["RAX"] = "0x0",
            [""] = "corrupt",
        });

        var malformedInputs = new[]
        {
            "",
            "|||",
            "CIP=0x140001050",
            "CIP=0x140001050 | RAX=0x0 | DISASM: mov rax, 0",
            "= = = = =",
            "CIP=0x140001050 | =0x0 RAX= RBX=0x14000",
            "CIP=0x140001050\0\0\0\0",
            string.Join(" ", Enumerable.Range(0, 500).Select(i => $"R{i}=0x{i:X}"))
        };

        foreach (var input in malformedInputs)
        {
            var node = (JsonNode)JsonValue.Create(input);
            var ex = Record.Exception(() => AnalysisFormatting.FormatDiffContext(node, dict));
            Assert.Null(ex);
        }
    }

    [Fact]
    public void Fuzz_UpdateLastRegisters_With_Corrupt_Tokens_MustNeverThrow()
    {
        var dict = new SessionSnapshotState();
        var inputs = new[]
        {
            "", "||||", "====", "CIP=0x14000", "A=B=C=D", "   =   ", "RAX=0x0"
        };

        foreach (var input in inputs)
        {
            var node = (JsonNode)JsonValue.Create(input);
            var ex = Record.Exception(() => AnalysisFormatting.UpdateLastRegisters(node, dict));
            Assert.Null(ex);
        }
    }

    // ========================================================================================
    // 2. ARITHMETIC OVERFLOW & 64-BIT ASLR BOUNDARY ATTACKS
    // ========================================================================================

    [Fact]
    public async Task ASLR_RvaOverflow_Past_64Bit_Limit_MustBeRejectedSafely()
    {
        var mockBridge = new FuzzingMockBridge();
        // Target base: 0xFFFFFFFFFFFFF000 (near 64-bit ceiling)
        // RVA: 0x2000 (would wrap around to 0x0000000000000FFF)
        var nearCeilingFunc = new ToolSupport.StaticFunction(
            "OverflowFunc", "0xFFFFFFFFFFFFF000", "HardenedTarget.exe", null, ulong.MaxValue - 16);

        var result = await AddressMapping.BuildLiveMappingAsync(
            mockBridge, nearCeilingFunc, verifyHash: false, CancellationToken.None);

        Assert.False(result["match"]?.GetValue<bool>());
        Assert.NotNull(result["reason"]);
    }

    [Fact]
    public async Task ASLR_Inverted_ModuleRange_EndLessThanBase_MustBeTreatedAsCorrupt()
    {
        var mockBridge = new FuzzingMockBridge
        {
            CustomModuleResponse = """
            {
                "id": 1, "ok": true,
                "result": {
                    "modules": [
                        { "name": "HardenedTarget.exe", "base": "0x140005000", "end": "0x140001000", "path": "C:\\target.exe" }
                    ],
                    "truncated": false
                }
            }
            """
        };

        var staticFunc = new ToolSupport.StaticFunction(
            "main", "0x140001000", "HardenedTarget.exe", null, 0x1000);

        var result = await AddressMapping.BuildLiveMappingAsync(
            mockBridge, staticFunc, verifyHash: false, CancellationToken.None);

        // Inverted range (base > end) is logically impossible, must not match
        Assert.False(result["match"]?.GetValue<bool>());
    }

    [Fact]
    public async Task ASLR_ZeroSized_ModuleRange_MustBeRejected()
    {
        var mockBridge = new FuzzingMockBridge
        {
            CustomModuleResponse = """
            {
                "id": 1, "ok": true,
                "result": {
                    "modules": [
                        { "name": "HardenedTarget.exe", "base": "0x140000000", "end": "0x140000000", "path": "C:\\target.exe" }
                    ],
                    "truncated": false
                }
            }
            """
        };

        var staticFunc = new ToolSupport.StaticFunction(
            "main", "0x140001000", "HardenedTarget.exe", null, 0x1000);

        var result = await AddressMapping.BuildLiveMappingAsync(
            mockBridge, staticFunc, verifyHash: false, CancellationToken.None);

        Assert.False(result["match"]?.GetValue<bool>());
    }

    // ========================================================================================
    // 3. CYCLIC & RECURSIVE POINTER DEREFERENCING TRAPS
    // ========================================================================================

    [Fact]
    public async Task InspectAddressStructure_SelfReferencingPointer_MustNotStackOverflow()
    {
        var mockBridge = new FuzzingMockBridge
        {
            // Address 0x140003000 points to itself! (Infinite loop trap)
            CustomInspectResponse = """
            {
                "id": 1, "ok": true,
                "result": {
                    "address": "0x140003000",
                    "module": "target.exe",
                    "fields": [
                        { "offset": 0, "pointer": "0x140003000", "target": "Self" },
                        { "offset": 8, "pointer": "0x140003000", "target": "SelfAgain" }
                    ]
                }
            }
            """
        };

        using var server = new LocalMcpServer(new ServerConfig { Port = 50401 }, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x140003000"),
                ["pointerCount"] = JsonSerializer.SerializeToElement(8)
            }
        };

        var resp = await server.CallToolAsync(req, CancellationToken.None);
        var respText = string.Join("", resp.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));
        Assert.NotEmpty(respText);
        // Completed successfully without infinite recursion
    }

    // ========================================================================================
    // 4. CALLSTACK FOLDING STRESS & RECURSION BOMB
    // ========================================================================================

    [Fact]
    public void Callstack_Folding_With_10000_Frames_MustCompleteFastWithoutCrash()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Frame 0: 0x140001000 target.exe!main+0x0");
        for (int i = 1; i <= 9998; i++)
        {
            sb.AppendLine($"Frame {i}: 0x7FF8{i % 0xFFFF:X4}000 ntdll.dll!RtlDispatchException+0x{i:X}");
        }
        sb.AppendLine("Frame 9999: 0x140002000 target.exe!end+0x0");

        var text = sb.ToString();
        var node = (JsonNode)JsonValue.Create(text);

        var sw = Stopwatch.StartNew();
        var folded = AnalysisFormatting.FoldCallStackNode(node);
        sw.Stop();

        Assert.NotNull(folded);
        var foldedText = folded!.ToString();
        Assert.True(foldedText.Length < 1000, "10,000 frames must fold into < 1,000 characters");
        Assert.True(sw.ElapsedMilliseconds < 200, $"Folding 10,000 frames took {sw.ElapsedMilliseconds} ms (must be < 200ms)");
    }

    [Fact]
    public void Callstack_Folding_With_Corrupt_Frame_Headers_MustHandleGracefully()
    {
        var corruptCallstack = """
            Frame 0: 0x140001000 target.exe!main
            Frame: CorruptHeaderWithoutNumber
            Frame -99: 0x0 ntdll.dll!NegativeFrame
            NotAFrameAtAll
            Frame 1: 0x7FF800000000 ntdll.dll!ValidSys
            Frame 2: 0x140002000 target.exe!ValidUser
            """;

        var node = (JsonNode)JsonValue.Create(corruptCallstack);
        var ex = Record.Exception(() => AnalysisFormatting.FoldCallStackNode(node));
        Assert.Null(ex);
        var folded = AnalysisFormatting.FoldCallStackNode(node);
        Assert.NotNull(folded);
    }

    // ========================================================================================
    // 5. CHARACTER BUDGET STARVATION (EXTREME LIMITS)
    // ========================================================================================

    [Fact]
    public async Task Snapshot_With_Extremely_Low_Budget_1Char_DoesNotThrow()
    {
        var mockBridge = new FuzzingMockBridge();
        var mockGhidra = new FuzzingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var live = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new
        {
            maxChars = 1 // Extreme starvation: smaller than any single character or tag
        });

        var ex = await Record.ExceptionAsync(async () =>
        {
            await live.GetAnalysisSnapshotAsync(args, CancellationToken.None);
        });

        Assert.Null(ex);
    }

    [Fact]
    public void TrimModuleRecords_With_ZeroRemainingChars_DoesNotThrow()
    {
        var moduleResult = new JsonObject
        {
            ["modules"] = new JsonArray
            {
                new JsonObject { ["name"] = "mod1.dll", ["base"] = "0x1000", ["end"] = "0x2000", ["path"] = "C:\\mod1.dll" },
                new JsonObject { ["name"] = "mod2.dll", ["base"] = "0x3000", ["end"] = "0x4000", ["path"] = "C:\\mod2.dll" }
            }
        };
        var records = (JsonArray)moduleResult["modules"]!;

        var ex = Record.Exception(() => AnalysisSnapshotSummary.TrimModuleRecordsToBudget(moduleResult, records, 0));
        Assert.Null(ex);
        Assert.True(moduleResult["truncated"]?.GetValue<bool>() ?? false);
        Assert.Empty(records);
    }

    // ========================================================================================
    // 6. HIGH-CONCURRENCY CHAOS & RANDOM CANCELLATION
    // ========================================================================================

    [Fact]
    public async Task Concurrent_ChaosMonkey_Stepping_And_Snapshots_Under_Random_Cancellations()
    {
        var mockBridge = new FuzzingMockBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50402 }, mockBridge);

        var tasks = new List<Task>();
        var completedCount = 0;
        var cancelledCount = 0;

        for (int i = 0; i < 30; i++)
        {
            var taskIndex = i;
            tasks.Add(Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource();
                // Random cancellation within 0..10ms
                if (taskIndex % 3 == 0)
                {
                    cts.CancelAfter(Random.Shared.Next(1, 5));
                }

                try
                {
                    var toolName = (taskIndex % 2 == 0) ? "TraceUntil" : "GetAnalysisSnapshot";
                    var req = new CallToolRequestParams
                    {
                        Name = toolName,
                        Arguments = new Dictionary<string, JsonElement>
                        {
                            ["maxFrames"] = JsonSerializer.SerializeToElement(4),
                            ["maxChars"] = JsonSerializer.SerializeToElement(4000)
                        }
                    };

                    var resp = await server.CallToolAsync(req, cts.Token);
                    Interlocked.Increment(ref completedCount);
                }
                catch (OperationCanceledException)
                {
                    Interlocked.Increment(ref cancelledCount);
                }
                catch (Exception)
                {
                    // Bridge cancellation or error handled
                }
            }));
        }

        await Task.WhenAll(tasks);
        _output.WriteLine($"Chaos monkey: completed {completedCount}, cancelled {cancelledCount} without process deadlock");
        Assert.True(completedCount + cancelledCount > 0);
    }

    // ========================================================================================
    // 7. NATIVE BRIDGE BROKEN PIPE & TRUNCATED JSON INJECTION
    // ========================================================================================

    [Fact]
    public void Bridge_TruncatedJson_MustNotCrashServerParser()
    {
        var truncatedPayloads = new[]
        {
            "",
            "{",
            "{\"ok\":",
            "{\"ok\": true",
            "{\"ok\": true, \"result\":",
            "{\"ok\": true, \"result\": {",
            "{\"ok\": true, \"result\": {\"modules\": [",
            "{\"ok\": true, \"result\": {\"modules\": [{\"name\":",
            "{\"ok\": true, \"result\": NaN}",
            "{\"ok\": false}",
            "<xml>Not Json At All</xml>"
        };

        foreach (var payload in truncatedPayloads)
        {
            var ex = Record.Exception(() =>
            {
                var analysis = ToolSupport.AnalyzeBridgeResponse(payload);
                var node = AnalysisFormatting.ReadBridgeResultNode(payload);
                var parsedModules = AddressMapping.ParseModuleRecords(node);
            });
            Assert.Null(ex); // Must gracefully report error/truncated without crashing
        }
    }

    // ========================================================================================
    // 8. TRACEUNTIL BOUNDARY TERMINATION & CONDITION CRASH PREVENTION
    // ========================================================================================

    [Fact]
    public async Task TraceUntil_AlreadyAtTargetAddress_StopsAtStepZero()
    {
        var mockBridge = new FuzzingMockBridge();
        var mockGhidra = new FuzzingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var live = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new
        {
            stopAddress = "0x140001050", // Same as mock initial address
            maxSteps = 20
        });

        var respJson = await live.TraceUntilAsync(args, CancellationToken.None);
        var node = AnalysisFormatting.ReadBridgeResultNode(respJson);
        var trace = node?["trace"];

        Assert.NotNull(trace);
        Assert.Contains("matched_address", trace?["stopReason"]?.GetValue<string>());
        Assert.Equal(0, trace?["stepsTaken"]?.GetValue<int>());
    }

    [Fact]
    public async Task TraceUntil_MaxSteps_Exhausted_Returns_Clean_State()
    {
        var mockBridge = new FuzzingMockBridge();
        var mockGhidra = new FuzzingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var live = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new
        {
            stopAddress = "0x999999999", // Unreachable target
            maxSteps = 5
        });

        var respJson = await live.TraceUntilAsync(args, CancellationToken.None);
        var node = AnalysisFormatting.ReadBridgeResultNode(respJson);
        var trace = node?["trace"];

        Assert.NotNull(trace);
        Assert.Equal("max_steps_reached", trace?["stopReason"]?.GetValue<string>());
        Assert.Equal(5, trace?["stepsTaken"]?.GetValue<int>());
    }

    // ========================================================================================
    // 9. FORMATCOMPACTHEX BOUNDARY & MALICIOUS BYTE STREAMS
    // ========================================================================================

    [Fact]
    public void FormatCompactHex_EmptyAndOddLengths_CalculatesCorrectly()
    {
        Assert.Equal("", AnalysisFormatting.FormatCompactHex(ReadOnlySpan<byte>.Empty));

        var oneZero = new byte[] { 0x00 };
        var oneZeroResult = AnalysisFormatting.FormatCompactHex(oneZero);
        Assert.Contains("* [repeated 1 zero bytes omitted]", oneZeroResult);

        var oneNonZero = new byte[] { 0x5A };
        Assert.Equal("5A", AnalysisFormatting.FormatCompactHex(oneNonZero));

        // 17 bytes (16 bytes zero, 1 byte non-zero)
        var seventeenBytes = new byte[17];
        seventeenBytes[16] = 0xAA;
        var sevResult = AnalysisFormatting.FormatCompactHex(seventeenBytes);
        Assert.Contains("* [repeated 16 zero bytes omitted]", sevResult);
        Assert.Contains("AA", sevResult);

        // 100,000 bytes of zeros
        var bigZeros = new byte[100_000];
        var bigResult = AnalysisFormatting.FormatCompactHex(bigZeros);
        Assert.Equal("* [repeated 100000 zero bytes omitted]", bigResult);
    }

    // ========================================================================================
    // 10. BATCHDEBUGGEROPERATIONS INJECTION & ERROR ISOLATION
    // ========================================================================================

    [Fact]
    public async Task BatchDebuggerOperations_With_Malicious_And_Unknown_Methods_IsSafelyIsolated()
    {
        var mockBridge = new FuzzingMockBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50403 }, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[]
                {
                    new { method = "GetMemoryMap", arguments = new { } },
                    new { method = "DROP TABLE USERS; --", arguments = new { } }, // Malicious injection
                    new { method = "SystemShutdown", arguments = new { } }, // Unauthorized method
                    new { method = "GetMemoryMap", arguments = new { maxItems = 8 } }
                })
            }
        };

        var resp = await server.CallToolAsync(req, CancellationToken.None);
        var respText = string.Join("", resp.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));

        // Unauthorized / injected batch methods are safely caught and isolated at validation
        Assert.True(resp.IsError);
        Assert.Contains("invalid_batch", respText);
        Assert.Contains("DROP TABLE USERS", respText);
    }

    // ========================================================================================
    // 11. JSON RECURSION DEPTH BOMB & DUPLICATE PROPERTY INJECTION
    // ========================================================================================

    [Fact]
    public void JSON_MaxDepthBomb_SafelyCatchesJsonException_WithoutStackOverflow()
    {
        // Construct 70 levels of nested JSON objects: {"a":{"a":...{"ok":true,"result":{"val":1}}...}}}
        var sb = new StringBuilder();
        for (int i = 0; i < 70; i++) sb.Append("{\"nest\":");
        sb.Append("{\"ok\":true,\"result\":{\"target\":123}}");
        for (int i = 0; i < 70; i++) sb.Append('}');
        var deepPayload = sb.ToString();

        // Must catch JsonException (exceeding MaxDepth = 8) and return null without StackOverflowException
        var resultNode = AnalysisFormatting.ReadBridgeResultNode(deepPayload);
        Assert.Null(resultNode);

        // Nested array bomb: [[[[[[[[[{"ok":true,"result":{}}]]]]]]]]]
        var arrayBomb = new string('[', 30) + "{\"ok\":true,\"result\":{}}" + new string(']', 30);
        var arrayResult = AnalysisFormatting.ReadBridgeResultNode(arrayBomb);
        Assert.Null(arrayResult);

        // Duplicate property injection attack at root
        var dupRoot = "{\"ok\": true, \"ok\": false, \"result\": {\"foo\": \"bar\"}}";
        var dupResult = AnalysisFormatting.ReadBridgeResultNode(dupRoot);
        Assert.Null(dupResult);
    }

    [Fact]
    public void JsonProtocolValidation_DeepDuplicateDetection_TraversesFullTree()
    {
        // Level 1 duplicate
        var json1 = JsonDocument.Parse("{\"a\": 1, \"a\": 2}").RootElement;
        Assert.True(JsonProtocolValidation.HasDuplicateProperties(json1));

        // Level 3 duplicate
        var json3 = JsonDocument.Parse("{\"level1\": {\"level2\": {\"dup\": 1, \"dup\": 2}}}").RootElement;
        Assert.True(JsonProtocolValidation.HasDuplicateProperties(json3));

        // Duplicate inside array element
        var jsonArr = JsonDocument.Parse("{\"items\": [1, 2, {\"x\": 10, \"x\": 20}]}").RootElement;
        Assert.True(JsonProtocolValidation.HasDuplicateProperties(jsonArr));

        // Clean hierarchy without duplicates
        var clean = JsonDocument.Parse("{\"a\": 1, \"b\": {\"c\": 2, \"d\": [1, 2, {\"e\": 3}]}}").RootElement;
        Assert.False(JsonProtocolValidation.HasDuplicateProperties(clean));
    }

    // ========================================================================================
    // 12. PATH TRAVERSAL & ILLEGAL PATH BOUNDARIES IN ASLR MAPPING
    // ========================================================================================

    [Fact]
    public async Task ASLR_PathTraversal_And_IllegalPathCharacters_SafelyRejected()
    {
        var mockBridge = new FuzzingMockBridge();
        var maliciousPaths = new[]
        {
            @"..\..\..\..\..\..\..\Windows\System32\cmd.exe",
            @"C:\target.exe/../../etc/passwd",
            @"CON.exe",
            @"C:\test\invalid|pipe*.exe",
            "",
            "   ",
            "C:\\\0nullbyte.exe"
        };

        foreach (var path in maliciousPaths)
        {
            var staticFunc = new ToolSupport.StaticFunction("malicious", "0x1000", path, null, 0x1000);

            // Neither verifyHash=true nor false must throw unhandled exception
            var result = await AddressMapping.BuildLiveMappingAsync(mockBridge, staticFunc, verifyHash: false, CancellationToken.None);
            Assert.False(result["match"]?.GetValue<bool>());

            var hash = await AddressMapping.ComputeBoundedModuleHashAsync(path, CancellationToken.None);
            Assert.Null(hash);
        }
    }

    // ========================================================================================
    // 13. CHECKPOINT STORE HIGH-CONCURRENCY RACE & STORAGE LIMIT EXHAUSTION
    // ========================================================================================

    [Fact]
    public async Task CheckpointStore_HighConcurrency_RaceStressTest()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink_fuzz_chkpt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var storePath = Path.Combine(tempDir, "checkpoints.json");

        try
        {
            var store = new CheckpointStore(storePath);
            var tasks = new List<Task>();

            // 20 parallel worker tasks doing interleaved saves and loads
            for (int w = 0; w < 20; w++)
            {
                var workerId = w;
                tasks.Add(Task.Run(() =>
                {
                    for (int i = 0; i < 5; i++)
                    {
                        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"w_{workerId}_i_{i}"))).ToLowerInvariant();
                        var cp = new McpCheckpoint(
                            sha,
                            $"Title {workerId}-{i}",
                            $"Findings {workerId}",
                            $"Hypotheses {workerId}",
                            $"Verified {workerId}",
                            $"NextStep {workerId}",
                            "Context",
                            "LiveValues",
                            DateTimeOffset.UtcNow,
                            $"sess_{workerId}");

                        store.Save(cp);
                        var loaded = store.Load(sha);
                        Assert.NotNull(loaded);
                        Assert.Equal(sha, loaded!.Sha256);

                        var snapshot = store.LoadSnapshot(sha);
                        Assert.NotNull(snapshot.Checkpoint);
                        Assert.Contains(sha, snapshot.AvailableSha256);
                    }
                }));
            }

            await Task.WhenAll(tasks);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void CheckpointStore_OversizedPayload_ExceedingStorageLimit_ThrowsIOException()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink_fuzz_chkpt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var storePath = Path.Combine(tempDir, "checkpoints.json");

        try
        {
            var store = new CheckpointStore(storePath);

            var exThrown = false;
            for (int i = 0; i < 20; i++)
            {
                var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"big_{i}"))).ToLowerInvariant();
                var bigPayload = new string('X', 25_000); // 25 KB section
                var cp = new McpCheckpoint(
                    sha,
                    $"BigTitle {i}",
                    bigPayload,
                    bigPayload,
                    "Verified",
                    "NextStep",
                    "Context",
                    "LiveValues",
                    DateTimeOffset.UtcNow,
                    "analysis-1");

                try
                {
                    store.Save(cp);
                }
                catch (IOException ioEx) when (ioEx.Message.Contains("storage limit"))
                {
                    exThrown = true;
                    break;
                }
            }

            Assert.True(exThrown, "CheckpointStore must enforce the 256KB total index storage limit.");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // ========================================================================================
    // 14. STRING TRIAGE ADVERSARIAL STREAM & ZERO REDOS BACKTRACKING
    // ========================================================================================

    [Fact]
    public async Task TriageStrings_AdversarialInputs_And_MassiveDataStream_ZeroReDoS()
    {
        var mockBridge = new FuzzingMockBridge();
        var mockGhidra = new FuzzingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var triage = new TriageImportsTools(context);

        // Build 3,000 synthetic strings with adversarial patterns
        var strList = new List<object>();

        // ReDoS trap attempts
        strList.Add(new { address = "0x1000", value = "http://" + new string('a', 500) + "@" + new string('b', 500) + "!" });
        strList.Add(new { address = "0x1010", value = "http://http://http://http://example.com/a/b/c/d" });
        strList.Add(new { address = "0x1020", value = new string('Z', 20_000) }); // Giant non-match

        // Real IOCs
        strList.Add(new { address = "0x1030", value = "https://c2-server.attacker.com/beacon" });
        strList.Add(new { address = "0x1040", value = "192.168.1.50" });
        strList.Add(new { address = "0x1050", value = "powershell.exe -NoProfile -ExecutionPolicy Bypass" });
        strList.Add(new { address = "0x1060", value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" });
        strList.Add(new { address = "0x1070", value = "VirtualProtect" });
        strList.Add(new { address = "0x1080", value = "This program cannot be run in DOS mode" });

        // Benign noise (2,000 items)
        for (int i = 0; i < 2_000; i++)
        {
            strList.Add(new { address = $"0x{0x2000 + i * 16:X}", value = $"StandardApplicationStringNumber_{i}" });
        }

        var payload = JsonSerializer.Serialize(new
        {
            id = 1,
            ok = true,
            result = new { strings = strList }
        });

        mockBridge.CustomResponse = payload;

        var sw = Stopwatch.StartNew();
        var respJson = await triage.TriageStringsAsync(null, CancellationToken.None);
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 1000, $"TriageStrings took {sw.ElapsedMilliseconds} ms (must be < 1000ms)");
        var node = AnalysisFormatting.ReadBridgeResultNode(respJson);
        Assert.NotNull(node);

        var suspiciousCount = node?["suspiciousCount"]?.GetValue<int>() ?? 0;
        Assert.True(suspiciousCount >= 6, $"Expected at least 6 suspicious IOCs, got {suspiciousCount}");

        var iocs = node?["iocs"] as JsonArray;
        Assert.NotNull(iocs);
        var types = iocs!.Select(item => item?["type"]?.GetValue<string>()).ToHashSet();
        Assert.Contains("C2_URL", types);
        Assert.Contains("IP_Address", types);
        Assert.Contains("Command_Execution", types);
        Assert.Contains("Registry_Persistence", types);
        Assert.Contains("Security_Sensitive_API", types);
        Assert.Contains("Crypto_Artifact", types);
    }

    // ========================================================================================
    // 15. SESSION INJECTION & UNAUTHORIZED ANALYSIS ID DEFENSE
    // ========================================================================================

    [Fact]
    public async Task SessionRegistry_And_ToolDispatcher_StrictRejection_Of_MaliciousAnalysisId()
    {
        var mockBridge = new FuzzingMockBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50404 }, mockBridge);

        var maliciousIds = new[]
        {
            "../../malicious",
            "id; rm -rf /",
            "' OR 1=1 --",
            new string('A', 200), // Bounded length overflow (> 128)
            "session\0inject",
            "session with spaces"
        };

        foreach (var badId in maliciousIds)
        {
            var req = new CallToolRequestParams
            {
                Name = "GetAnalysisSnapshot",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["analysisId"] = JsonSerializer.SerializeToElement(badId)
                }
            };

            var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(req, CancellationToken.None));
            Assert.Equal(McpErrorCode.InvalidParams, ex.ErrorCode);
            Assert.Contains("analysisId must be a bounded identifier", ex.Message);
        }

        // Now test a valid format identifier, but not registered in sessions
        var unregisteredReq = new CallToolRequestParams
        {
            Name = "GetAnalysisSnapshot",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["analysisId"] = JsonSerializer.SerializeToElement("unregistered-session-999")
            }
        };

        var notFoundEx = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(unregisteredReq, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, notFoundEx.ErrorCode);
        Assert.Contains("was not found", notFoundEx.Message);
    }

    // ========================================================================================
    // 16. BYTE PATTERN SEARCH FUZZING & STRICT VALIDATION
    // ========================================================================================

    [Fact]
    public void ToolArgumentRules_BytePattern_Adversarial_Fuzzing()
    {
        var schema = new JsonObject
        {
            ["properties"] = new JsonObject
            {
                ["pattern"] = new JsonObject
                {
                    ["type"] = "string",
                    ["x-bytePattern"] = true
                }
            }
        };

        var invalidPatterns = new[]
        {
            "",
            "   ",
            "?? ?? ?? ??", // Pure wildcards forbidden
            "?",
            "48 8B C", // Odd hex nibble
            "48 8B ZZ", // Non-hex
            string.Join(" ", Enumerable.Repeat("90", 257)), // > 256 tokens
            "48 89 5C\n24 90", // Multiline forbidden in single-line pattern
            "48 89 5C \0 90" // Null byte injection
        };

        foreach (var invalid in invalidPatterns)
        {
            var args = JsonSerializer.SerializeToElement(new { pattern = invalid });
            var error = ToolArgumentRules.Validate(schema, args);
            Assert.NotNull(error);
            Assert.Contains("pattern does not satisfy its argument schema", error);
        }

        var validPatterns = new[]
        {
            "48 89 5C 24 ??",
            "48 89 5C 24 90 48 31 C0",
            "90",
            "AA ? BB ?? CC"
        };

        foreach (var valid in validPatterns)
        {
            var args = JsonSerializer.SerializeToElement(new { pattern = valid });
            var error = ToolArgumentRules.Validate(schema, args);
            Assert.Null(error);
        }
    }

    // ========================================================================================
    // 17. ADMISSION QUEUE BURST SATURATION & IMMEDIATE REJECTION
    // ========================================================================================

    [Fact]
    public async Task ToolDispatcher_AdmissionQueue_FullRejection_UnderBurstLoad()
    {
        var tcs = new TaskCompletionSource<string>();
        var mockBridge = new FuzzingMockBridge { CustomResponseTask = tcs.Task };

        // MaxConcurrentRequests = 1, MaxQueuedOperations = 0 -> Admission limit = 1
        var config = new ServerConfig
        {
            Port = 50405,
            MaxConcurrentRequests = 1,
            MaxQueuedOperations = 0
        };

        using var server = new LocalMcpServer(config, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };

        // Launch first request - it will acquire the single slot and wait on tcs
        var task1 = server.CallToolAsync(req, CancellationToken.None);

        // Small delay to ensure task1 entered dispatcher and took the slot
        await Task.Delay(20);

        // Launch second request immediately - queue capacity is completely full!
        var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(req, CancellationToken.None));
        Assert.Equal(McpErrorCode.InternalError, ex.ErrorCode);
        Assert.Contains("Queue full (1 running, 0 queued", ex.Message);
        Assert.Contains("retryAfterMs=2000", ex.Message);

        // Complete task1 cleanly
        tcs.SetResult("{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x1\"}}");
        var resp1 = await task1;
        Assert.False(resp1.IsError);
    }

    // ========================================================================================
    // 18. TOOL DISPATCHER DEADLINE TIMEOUT & STATE RECOVERY
    // ========================================================================================

    [Fact]
    public async Task ToolDispatcher_UnresponsiveBackend_TimesOutCleanly_WithoutResourceLeak()
    {
        var mockBridge = new FuzzingMockBridge
        {
            CustomResponseTask = new TaskCompletionSource<string>().Task // Never completes
        };

        // For EvaluateExpressions, McpToolDispatcher clamps timeout to minimumTimeout (1000ms).
        var config = new ServerConfig
        {
            Port = 50406,
            DefaultToolTimeoutMs = 1000
        };

        using var server = new LocalMcpServer(config, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };

        var sw = Stopwatch.StartNew();
        var result = await server.CallToolAsync(req, CancellationToken.None);
        sw.Stop();

        // A deadline breach is a tool execution failure: reported with
        // isError=true so the client can adjust instead of dropping the session.
        Assert.True(result.IsError);
        Assert.Equal("The tool execution exceeded its bounded deadline.",
            Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content)).Text);
        Assert.True(sw.ElapsedMilliseconds >= 900 && sw.ElapsedMilliseconds < 5000);

        // Verify that semaphores and state were completely cleaned up by executing a responsive tool
        mockBridge.CustomResponseTask = null; // Revert to instant response
        var statusReq = new CallToolRequestParams { Name = "GetServerStatus" };
        var statusResp = await server.CallToolAsync(statusReq, CancellationToken.None);
        Assert.False(statusResp.IsError);
    }

    // ========================================================================================
    // 19. SURROGATE-PAIR TRUNCATION & LONE-SURROGATE CONTEXT FUZZING
    // ========================================================================================

    [Fact]
    public void Fuzz_LimitSnapshotText_SurrogateBoundary_StaysWellFormed()
    {
        // 10 astral code points (each a high+low surrogate pair) framed by ASCII.
        var astral = string.Concat(Enumerable.Repeat("\U00020000", 10));
        var text = "AB" + astral + "CD"; // 26 UTF-16 chars, 16 code points

        foreach (var budget in new[] { 0, 1, 2, 3, 4, 5, 10, 15, 16, 20, 21, 22, 23, 24, 25, 26, 27, 100 })
        {
            var truncated = false;
            string? limited = null;
            var ex = Record.Exception(() => limited = ToolSupport.LimitSnapshotText(text, budget, ref truncated));
            Assert.Null(ex);
            Assert.NotNull(limited);
            Assert.Equal(text.Length > budget, truncated);
            for (int i = 0; i < limited!.Length; i++)
            {
                if (char.IsHighSurrogate(limited[i]))
                    Assert.True(i + 1 < limited.Length && char.IsLowSurrogate(limited[i + 1]),
                        $"Split high surrogate at index {i} (budget {budget})");
                if (char.IsLowSurrogate(limited[i]))
                    Assert.True(i > 0 && char.IsHighSurrogate(limited[i - 1]),
                        $"Split low surrogate at index {i} (budget {budget})");
            }
        }

        // Lone surrogates in the source must not throw either.
        foreach (var hostile in new[] { "AB\uD800CD", "AB\uDC00CD", "\uD800", "\uDC00", "\uD800\uD800\uDC00\uDC00" })
        {
            var truncated = false;
            var ex = Record.Exception(() => ToolSupport.LimitSnapshotText(hostile, 3, ref truncated));
            Assert.Null(ex);
        }
    }

    [Fact]
    public void Fuzz_FormatSparseContext_With_LoneSurrogates_And_Astral_MustNeverThrow()
    {
        var inputs = new[]
        {
            "CIP=0x140001000 | RAX=\uD800 | RBX=0x1", // Lone high surrogate in value
            "CIP=0x140001000 | RAX=\uDC00 | RBX=0x1", // Lone low surrogate in value
            "CIP=0x140001000 | RAX=\U0001F525 RBX=\U00020000 | DISASM: nop", // Astral emoji + CJK-B
            "\uD800\uD800\uDC00\uDC00",
            "CIP=0x140001000 | " + new string('X', 50_000), // Single 50k-char token
            "CIP=0x140001000 | RAX=0x0 | " + string.Concat(Enumerable.Repeat("\U0001F600", 5_000)),
        };

        foreach (var input in inputs)
        {
            var node = (JsonNode)JsonValue.Create(input)!;
            var ex = Record.Exception(() => AnalysisFormatting.FormatSparseContext(node));
            Assert.Null(ex);
        }
    }

    // ========================================================================================
    // 20. FOLD-CALLSTACK NON-STRING JSON KINDS
    // ========================================================================================

    [Fact]
    public void Fuzz_FoldCallStackNode_With_NonString_JsonKinds_MustNeverThrow()
    {
        JsonNode?[] nodes =
        {
            JsonValue.Create(42),
            JsonValue.Create(true),
            new JsonObject { ["callStack"] = "Frame 0: 0x140001000 target.exe!main" },
            new JsonArray { "Frame 0: 0x140001000 target.exe!main", "Frame 1: 0x140002000 target.exe!end" },
            JsonValue.Create(""),
            null,
        };

        foreach (var node in nodes)
        {
            var ex = Record.Exception(() => AnalysisFormatting.FoldCallStackNode(node));
            Assert.Null(ex);
        }
    }

    // ========================================================================================
    // 21. BOM / WHITESPACE / MEGABYTE WIRE PAYLOADS
    // ========================================================================================

    [Fact]
    public void Fuzz_ReadBridgeResultNode_Bom_Whitespace_And_MegabytePayload()
    {
        const string valid = "{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x1\"}}";

        // Leading whitespace / newlines must be tolerated.
        var padded = AnalysisFormatting.ReadBridgeResultNode("  \r\n\t" + valid + "  ");
        Assert.NotNull(padded);

        // BOM prefix must never throw (accept or reject, but no exception escapes).
        JsonNode? bomResult = null;
        var bomEx = Record.Exception(() => bomResult = AnalysisFormatting.ReadBridgeResultNode("\uFEFF" + valid));
        Assert.Null(bomEx);

        // 1 MB string payload parses within a bounded time budget.
        var big = "{\"id\":1,\"ok\":true,\"result\":{\"blob\":\"" + new string('a', 1_000_000) + "\"}}";
        JsonNode? bigResult = null;
        var sw = Stopwatch.StartNew();
        var bigEx = Record.Exception(() => bigResult = AnalysisFormatting.ReadBridgeResultNode(big));
        sw.Stop();
        Assert.Null(bigEx);
        Assert.NotNull(bigResult);
        Assert.True(sw.ElapsedMilliseconds < 2000, $"1 MB payload took {sw.ElapsedMilliseconds} ms (must be < 2000ms)");
    }

    // ========================================================================================
    // 22. HUGE BRIDGE ERROR TRUNCATION
    // ========================================================================================

    [Fact]
    public void Fuzz_AnalyzeBridgeResponse_HugeError_TruncatesWithoutThrow()
    {
        var bigMessage = new string('E', 100_000);
        var payload = "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"boom\",\"message\":\"" + bigMessage + "\"}}";

        var analysis = ToolSupport.AnalyzeBridgeResponse(payload);
        Assert.True(analysis.IsError);
        Assert.EndsWith("...[truncated]", analysis.Text);
        Assert.True(analysis.Text.Length <= Server::DbgLink.Shared.BridgeEnvelope.MaxErrorMessageChars + "...[truncated]".Length,
            $"Error text length {analysis.Text.Length} exceeds the bounded limit");

        // ok:true with a text field surfaces the text verbatim and is not an error.
        var textPayload = "{\"id\":1,\"ok\":true,\"text\":\"cip=0x140001000\"}";
        var textAnalysis = ToolSupport.AnalyzeBridgeResponse(textPayload);
        Assert.False(textAnalysis.IsError);
        Assert.Equal("cip=0x140001000", textAnalysis.Text);
    }

    [Fact]
    public void Fuzz_AnalyzeBridgeResponse_WithoutText_Returns_Raw_Envelope()
    {
        // includeText:false skips text/result extraction: verdict only, raw passthrough.
        const string payload = "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"boom\",\"message\":\"kaput\"}}";
        var analysis = ToolSupport.AnalyzeBridgeResponse(payload, includeText: false);
        Assert.True(analysis.IsError);
        Assert.Equal(payload, analysis.Text);

        const string okPayload = "{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x1\"}}";
        var okAnalysis = ToolSupport.AnalyzeBridgeResponse(okPayload, includeText: false);
        Assert.False(okAnalysis.IsError);
        Assert.Equal(okPayload, okAnalysis.Text);
    }

    // ========================================================================================
    // 23. COMPACT-HEX RUNS, RESPONSE-STRING FALLBACKS, ENVELOPE CLIPPING
    // ========================================================================================

    [Fact]
    public void Fuzz_FormatCompactHex_AlternatingRuns_And_LineWidths()
    {
        static string[] Lines(string text) => text.Replace("\r\n", "\n").Split('\n');

        // Alternating all-zero / non-zero 16-byte lines collapse only the zero runs.
        var alternating = new byte[48];
        for (int i = 16; i < 32; i++) alternating[i] = 0xAA;
        var altLines = Lines(AnalysisFormatting.FormatCompactHex(alternating));
        Assert.Equal(3, altLines.Length);
        Assert.Equal("* [repeated 16 zero bytes omitted]", altLines[0]);
        Assert.Equal(new string('A', 32), altLines[1]);
        Assert.Equal("* [repeated 16 zero bytes omitted]", altLines[2]);

        // Single-byte lines: each zero run is still collapsed.
        var tiny = AnalysisFormatting.FormatCompactHex(new byte[] { 0x00, 0x5A }, maxBytesPerLine: 1);
        Assert.Equal("* [repeated 1 zero bytes omitted]\n5A", tiny.Replace("\r\n", "\n"));

        // Non-multiple tail without any zeros emits plain lines, no markers.
        var tail = Enumerable.Repeat((byte)0xBB, 20).ToArray();
        var tailResult = AnalysisFormatting.FormatCompactHex(tail);
        Assert.DoesNotContain("omitted", tailResult);
        Assert.Equal(2, Lines(tailResult).Length);

        // Zeros in the middle, non-zero at both ends.
        var sandwich = new byte[] { 0x01, 0x00, 0x00, 0x02 };
        Assert.Equal("01\n* [repeated 2 zero bytes omitted]\n02",
            AnalysisFormatting.FormatCompactHex(sandwich, maxBytesPerLine: 1).Replace("\r\n", "\n"));
    }

    [Fact]
    public void Fuzz_ReadResponseString_Fallbacks_NeverThrow()
    {
        using var doc = JsonDocument.Parse(
            "{\"name\":\"main\",\"blank\":\"   \",\"num\":42,\"nil\":null,\"nested\":{\"a\":1}}");
        var root = doc.RootElement;

        Assert.Equal("main", ToolSupport.ReadResponseString(root, "name", "fallback"));
        Assert.Equal("fallback", ToolSupport.ReadResponseString(root, "blank", "fallback"));
        Assert.Equal("fallback", ToolSupport.ReadResponseString(root, "num", "fallback"));
        Assert.Equal("fallback", ToolSupport.ReadResponseString(root, "nil", "fallback"));
        Assert.Equal("fallback", ToolSupport.ReadResponseString(root, "nested", "fallback"));
        Assert.Equal("fallback", ToolSupport.ReadResponseString(root, "missing", "fallback"));

        using var arrDoc = JsonDocument.Parse("[1,2]");
        // Non-object roots fail fast instead of returning a fallback: callers
        // must only pass the object envelopes this helper is designed for.
        Assert.Throws<InvalidOperationException>(() => ToolSupport.ReadResponseString(arrDoc.RootElement, "name", "fallback"));
    }

    [Fact]
    public void Fuzz_BridgeEnvelope_BoundedError_Clips_Long_Messages()
    {
        const int cap = 512; // BridgeEnvelope.MaxErrorMessageChars
        Assert.Equal(cap, Server::DbgLink.Shared.BridgeEnvelope.MaxErrorMessageChars);

        var exact = new string('m', cap);
        using var exactDoc = JsonDocument.Parse(
            Server::DbgLink.Shared.BridgeEnvelope.BoundedError(3, "code", exact));
        var exactMsg = exactDoc.RootElement.GetProperty("error").GetProperty("message").GetString()!;
        Assert.Equal(exact, exactMsg);

        var over = new string('m', cap + 88);
        using var overDoc = JsonDocument.Parse(
            Server::DbgLink.Shared.BridgeEnvelope.BoundedError(4, "boom", over));
        var overRoot = overDoc.RootElement;
        Assert.Equal(4, overRoot.GetProperty("id").GetInt32());
        Assert.Equal("boom", overRoot.GetProperty("error").GetProperty("code").GetString());
        var overMsg = overRoot.GetProperty("error").GetProperty("message").GetString()!;
        Assert.True(overMsg.Length < over.Length, $"Expected clipping, got length {overMsg.Length}");
        Assert.StartsWith(new string('m', cap), overMsg);
        Assert.EndsWith("chars]", overMsg);
    }

    // ========================================================================================
    // 24. TEXT-FORMAT MODULE PARSING (ParseLiveModules) HOSTILE INPUT
    // ========================================================================================

    [Fact]
    public void Fuzz_ParseLiveModules_HostileText_NeverThrows()
    {
        var hostile = new[]
        {
            "",
            "   ",
            "not a module line",
            "base= end=",
            "base=ZZZZ end=0x140010000 name=a.exe path=C:\\a.exe",
            "base=0x140010000 end=0x140000000 name=inv.exe path=C:\\inv.exe", // Inverted range
            "base=0x140000000 end=0x140010000 name= path=C:\\noname.exe", // Blank name
            "base=0x140000000 end=0x140010000 name=nopath.exe path=   ", // Blank path
            "BASE=0x140000000 END=0x140010000 NAME=case.exe PATH=C:\\case.exe", // Uppercase keys
            "base=0x140000000 end=0x140010000 name=noname.exe", // Missing path marker
            "base=0x140000000 end=0x140010000 path=C:\\noname.exe", // Missing name marker
            new string('x', 100_000), // Giant garbage line
            "base=0x140000000 end=0x140010000 name=a.exe path=C:\\a.exe\r", // CR-terminated line
        };

        foreach (var text in hostile)
        {
            IReadOnlyList<ToolSupport.LiveModule>? modules = null;
            var ex = Record.Exception(() => modules = AddressMapping.ParseLiveModules(text));
            Assert.Null(ex);
            Assert.NotNull(modules);
        }

        // Well-formed text line parses exactly.
        var parsed = AddressMapping.ParseLiveModules(
            "base=0x140000000 end=0x140010000 name=good.exe path=C:\\good.exe");
        var single = Assert.Single(parsed);
        Assert.Equal("good.exe", single.Name);
        Assert.Equal(0x140000000UL, single.Base);
        Assert.Equal(0x140010000UL, single.End);

        // Truncation markers anywhere flag the set.
        static bool IsTruncated(string text)
            => ((AddressMapping.LiveModuleCollection)AddressMapping.ParseLiveModules(text)).Truncated;
        Assert.True(IsTruncated("mapTruncated=true"));
        Assert.True(IsTruncated("outputTruncated=true"));
        Assert.True(IsTruncated("...[truncated]"));
    }

    // ========================================================================================
    // 25. GHIDRA ENDPOINT-DISCOVERY FUZZ (RB; managed mirror of GhidraRequestParser)
    // ========================================================================================
    //
    // The Java bridge parses every request with GhidraRequestParser.java:
    // strict object-only JSON, duplicate-field reject, MAX_JSON_DEPTH=16,
    // MAX_JSON_CONTAINER_ENTRIES=512, numerics capped at 128 chars,
    // trailing-data reject. The managed mirror is GhidraClient endpoint
    // discovery (MaxEndpointBytes=8K, duplicate reject, MaxDepth 8, host
    // pinned to 127.0.0.1, port 1..65535, token 16..256 chars without
    // control chars, protocolVersion==1): every hostile endpoint file below
    // must yield ghidra_unavailable — never a throw, never a network
    // contact. x64dbg-native parser shapes (§§7/16/24) are NOT touched here:
    // they belong to the RA track.
    [Fact]
    public async Task GhidraEndpointDiscovery_HostileFiles_Yield_Unavailable_WithoutThrow()
    {
        var token32 = new string('g', 32);
        var cases = new (string Name, string Payload)[]
        {
            ("oversized", new string('x', 9_000)),
            ("empty", ""),
            ("whitespace", "  \r\n\t  "),
            ("non_json", "<xml>not json</xml>"),
            ("array_root", "[1,2,3]"),
            ("null_root", "null"),
            ("number_root", "42"),
            ("string_root", "\"ghidra\""),
            ("duplicate_keys", "{\"host\":\"127.0.0.1\",\"host\":\"0.0.0.0\",\"port\":5000,\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("wrong_host", "{\"host\":\"0.0.0.0\",\"port\":5000,\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("nonstring_host", "{\"host\":123,\"port\":5000,\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("port_zero", "{\"host\":\"127.0.0.1\",\"port\":0,\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("port_huge", "{\"host\":\"127.0.0.1\",\"port\":99999,\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("port_string", "{\"host\":\"127.0.0.1\",\"port\":\"5000\",\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            // 200-digit numeric literal: mirrors the Java 128-char numeric
            // cap from the managed side (TryGetInt32 fails -> reject).
            ("port_bignum", "{\"host\":\"127.0.0.1\",\"port\":" + new string('9', 200) + ",\"protocolVersion\":1,\"token\":\"" + token32 + "\"}"),
            ("protocol_v2", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":2,\"token\":\"" + token32 + "\"}"),
            ("token_short", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":1,\"token\":\"short\"}"),
            ("token_long", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":1,\"token\":\"" + new string('t', 257) + "\"}"),
            ("token_control", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":1,\"token\":\"abc\\n" + token32 + "\"}"),
            ("token_nonstring", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":1,\"token\":{}}"),
            ("deep_nesting", DeepJson(70)),
            ("trailing_data", "{\"host\":\"127.0.0.1\",\"port\":5000,\"protocolVersion\":1,\"token\":\"" + token32 + "\"} TRAILING"),
        };

        foreach (var (name, payload) in cases)
        {
            var directory = Path.Combine(Path.GetTempPath(), "dbglink-ghidra-fuzz-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                await File.WriteAllTextAsync(
                    Path.Combine(directory, "ghidra-bridge-fuzz.json"), payload, Encoding.UTF8);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                string response = "";
                var ex = await Record.ExceptionAsync(async () =>
                    response = await new GhidraClient(directory).RequestAsync(
                        "ListFunctions", null, timeout.Token));
                Assert.Null(ex);
                Assert.Contains("ghidra_unavailable", response);
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
            _output.WriteLine($"endpoint case '{name}' -> ghidra_unavailable");
        }
    }

    // ========================================================================================
    // 26. GHIDRA CONTROL-RESPONSE FUZZ (RB; managed mirror of GhidraRequestParser)
    // ========================================================================================
    //
    // GhidraControlClient.ValidateResponse is the strict-envelope counterpart
    // of the Java parser on the managed side (object-only, duplicate reject,
    // MaxDepth 8, numeric id==1, ok bool, importing-success requires
    // opened+staticReady+bounded fileName+session metadata): hostile inputs
    // must map to ghidra_control_protocol, never throw. Duplicate-key shapes
    // already pinned by JsonProtocolValidationTests (KEEP) are not repeated.
    [Fact]
    public void GhidraControlResponse_HostileEnvelopes_Map_To_ProtocolError_WithoutThrow()
    {
        var deep = DeepJson(70);
        var hostile = new[]
        {
            "",
            "   ",
            "{",
            "{\"id\":1,",
            "{\"id\":1,\"ok\":true,\"result\":{}} TRAILING",
            "[1,2]",
            "null",
            "42",
            "\"ghidra\"",
            deep,
            "{\"id\":\"1\",\"ok\":true,\"result\":{}}",
            "{\"id\":1.5,\"ok\":true,\"result\":{}}",
            "{\"id\":2,\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true,\"fileName\":\"t.dll\"}}",
            "{\"id\":1,\"ok\":\"yes\",\"result\":{}}",
            "{\"id\":1,\"ok\":true}",
            "{\"id\":1,\"ok\":false}",
            "{\"id\":1,\"ok\":false,\"error\":[1,2]}",
            "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true}}",
            "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true,\"fileName\":\"" + new string('f', 261) + "\"}}",
            "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true,\"fileName\":\"bad\\u0000name.dll\"}}",
            "{\"id\":1,\"ok\":true,\"result\":{}}\0",
        };

        foreach (var payload in hostile)
        {
            string result = "";
            var ex = Record.Exception(() => result = GhidraControlClient.ValidateResponse(payload));
            Assert.Null(ex);
            Assert.Contains("ghidra_control_protocol", result);
        }

        // A well-formed ok:false envelope is a *backend* error, not a
        // protocol error: it passes through verbatim even with a 1 MB
        // message (clipping happens downstream in AnalyzeBridgeResponse,
        // pinned by §22). The validator must not throw and must not
        // misclassify it as a protocol violation.
        var bigError = "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"" + new string('m', 1_000_000) + "\"}}";
        string bigResult = "";
        var bigEx = Record.Exception(() => bigResult = GhidraControlClient.ValidateResponse(bigError));
        Assert.Null(bigEx);
        Assert.Equal(bigError, bigResult);

        // BOM prefix: accept-or-reject, but never a throw (same rule as the
        // §21 wire payloads). Which bucket it lands in is parser-defined;
        // crashing is not an option.
        string bomResult = "";
        var bomEx = Record.Exception(() => bomResult = GhidraControlClient.ValidateResponse(
            "\uFEFF{\"id\":1,\"ok\":false,\"error\":{\"code\":\"boom\",\"message\":\"x\"}}"));
        Assert.Null(bomEx);
        Assert.True(
            bomResult.Contains("ghidra_control_protocol") || bomResult.StartsWith("\uFEFF"),
            "BOM-prefixed control responses must be classified, never crash.");

        // Control: a well-formed importing success still passes through verbatim.
        var endpointDirectory = Path.Combine(Path.GetTempPath(), "dbglink-control-fuzz-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(endpointDirectory);
        try
        {
            var valid = JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    opened = true,
                    staticReady = true,
                    fileName = "target.dll",
                    analysisId = "analysis-test",
                    nativePipeName = "DbgLink.Control.42",
                    ghidraEndpointDirectory = endpointDirectory
                }
            });
            Assert.Equal(valid, GhidraControlClient.ValidateResponse(valid));
        }
        finally
        {
            try { Directory.Delete(endpointDirectory, true); } catch { }
        }
    }

    // ========================================================================================
    // 27. GHIDRA TCP-WIRE HOSTILE REPLIES (RB; real loopback against GhidraClient)
    // ========================================================================================
    //
    // Exercises the managed side of the GhidraBridgeServer wire: a hostile
    // Java bridge that answers with truncated JSON, duplicate keys, a wrong
    // id, a missing result, invalid UTF-8 or a >256K frame must surface
    // ghidra_protocol_error without ever throwing out of RequestAsync.
    // Mirrors GhidraBridgeServer caps (MAX_REQUEST_BYTES=1M,
    // MAX_RESPONSE_BYTES=256K, strict token/method dispatch).
    [Fact]
    public async Task GhidraMethodAllowlist_Rejects_UnknownMethods_WithoutEndpointLookup()
    {
        var missing = Path.Combine(Path.GetTempPath(), "dbglink-ghidra-missing-" + Guid.NewGuid().ToString("N"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        foreach (var method in new[] { "NoSuchMethod", "", "LISTFUNCTIONS" })
        {
            var response = await new GhidraClient(missing).RequestAsync(method, null, timeout.Token);
            Assert.Contains("method_not_allowed", response);
        }

        var arrayArgs = JsonSerializer.SerializeToElement(new[] { 1, 2 });
        var badArgs = await new GhidraClient(missing).RequestAsync("ListFunctions", arrayArgs, timeout.Token);
        Assert.Contains("invalid_arguments", badArgs);
    }

    [Fact]
    public async Task GhidraBridge_HostileWireReplies_Surface_ProtocolError_WithoutThrow()
    {
        var bigBlob = new string('z', 300_000);
        var cases = new (string Name, Func<int, byte[]> Reply)[]
        {
            ("truncated", _ => Encoding.UTF8.GetBytes("{\"ok\":true,\"resu")),
            ("duplicate_root", id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{},\"result\":{}}")),
            ("wrong_id", id => Encoding.UTF8.GetBytes("{\"id\":" + (id + 999) + ",\"ok\":true,\"result\":{}}")),
            ("ok_true_no_result", id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":true}")),
            ("ok_false_no_error", id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":false}")),
            ("ok_wrong_type", id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":\"yes\",\"result\":{}}")),
            ("id_as_string", id => Encoding.UTF8.GetBytes("{\"id\":\"" + id + "\",\"ok\":true,\"result\":{}}")),
            ("invalid_utf8", id => CorruptUtf8("{\"id\":" + id + ",\"ok\":true,\"result\":{}}")),
            ("oversized_frame", id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"blob\":\"" + bigBlob + "\"}}")),
        };

        foreach (var (name, reply) in cases)
        {
            string response = "";
            var ex = await Record.ExceptionAsync(async () =>
                response = await SendHostileGhidraReplyAsync(reply));
            Assert.Null(ex);
            Assert.Contains("ghidra_protocol_error", response);
            _output.WriteLine($"wire case '{name}' -> ghidra_protocol_error");
        }

        // Control: a well-formed reply still passes through verbatim.
        var ok = await SendHostileGhidraReplyAsync(
            id => Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"functions\":[]}}"));
        Assert.Contains("\"ok\":true", ok);
    }

    private static string DeepJson(int depth)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < depth; i++) sb.Append("{\"nest\":");
        sb.Append("{\"ok\":true,\"result\":{\"target\":123}}");
        for (int i = 0; i < depth; i++) sb.Append('}');
        return sb.ToString();
    }

    private static byte[] CorruptUtf8(string valid)
    {
        var bytes = Encoding.UTF8.GetBytes(valid + "\n");
        // Replace the first payload byte that is plain ASCII with an invalid
        // standalone continuation byte: strict UTF-8 decode must fail.
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == (byte)'"')
            {
                bytes[i] = 0xFF;
                break;
            }
        }
        return bytes;
    }

    private static async Task<string> SendHostileGhidraReplyAsync(Func<int, byte[]> replyForId)
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-ghidra-wire-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            await File.WriteAllTextAsync(Path.Combine(directory, $"ghidra-bridge-{port}.json"),
                JsonSerializer.Serialize(new { host = "127.0.0.1", port, protocolVersion = 1, token = new string('g', 32) }),
                timeout.Token);
            var backend = Task.Run(async () =>
            {
                using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
                await using var stream = peer.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                var request = await reader.ReadLineAsync(timeout.Token);
                using var doc = JsonDocument.Parse(request!);
                var id = doc.RootElement.GetProperty("id").GetInt32();
                var reply = replyForId(id);
                // The Ghidra wire is newline-delimited (GhidraBridgeServer
                // reads one line per request and answers one line): a reply
                // without the trailing newline is a framing error, not a
                // content error, so the harness always terminates the frame.
                if (reply.Length == 0 || reply[^1] != (byte)'\n')
                {
                    var framed = new byte[reply.Length + 1];
                    Buffer.BlockCopy(reply, 0, framed, 0, reply.Length);
                    framed[^1] = (byte)'\n';
                    reply = framed;
                }
                await stream.WriteAsync(reply, timeout.Token);
                await stream.FlushAsync(timeout.Token);
            }, timeout.Token);
            var response = await new GhidraClient(directory).RequestAsync("ListFunctions", null, timeout.Token);
            await backend;
            return response;
        }
        finally
        {
            listener.Stop();
            try { Directory.Delete(directory, true); } catch { }
        }
    }

    // ========================================================================================
    // MOCK FOR FUZZING
    // ========================================================================================

    private sealed class FuzzingMockBridge : IBridgeClient
    {
        public string? CustomModuleResponse { get; set; }
        public string? CustomInspectResponse { get; set; }
        public string? CustomResponse { get; set; }
        public Task<string>? CustomResponseTask { get; set; }

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                throw new OperationCanceledException(cancellationToken);

            if (CustomResponseTask is not null)
                return CustomResponseTask.WaitAsync(cancellationToken);

            if (CustomResponse is not null)
                return Task.FromResult(CustomResponse);

            switch (method)
            {
                case "GetModuleRecords":
                    if (CustomModuleResponse is not null)
                        return Task.FromResult(CustomModuleResponse);
                    return Task.FromResult("""
                        {
                            "id": 1, "ok": true,
                            "result": {
                                "modules": [
                                    { "name": "HardenedTarget.exe", "base": "0xFFFFFFFFFFFFF000", "end": "0xFFFFFFFFFFFFFFFF", "path": "C:\\target.exe" }
                                ],
                                "truncated": false
                            }
                        }
                        """);

                case "InspectAddressStructure":
                    if (CustomInspectResponse is not null)
                        return Task.FromResult(CustomInspectResponse);
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"address\":\"0x1000\",\"fields\":[]}}");

                case "ReadDisassemblyChunk":
                    return Task.FromResult("""
                        {
                            "id": 1, "ok": true,
                            "result": {
                                "address": "0x140001050",
                                "instructions": [
                                    { "address": "0x140001050", "instruction": "nop" }
                                ]
                            }
                        }
                        """);

                case "GetSnapshotState":
                    return Task.FromResult("""
                        {
                            "id": 1, "ok": true,
                            "result": {
                                "debuggerPid": 12345, "generation": "1", "debugging": true,
                                "running": false, "threadId": 42, "stableRead": true
                            }
                        }
                        """);

                case "GetAnalysisSnapshot":
                    return Task.FromResult("""
                        {
                            "id": 1, "ok": true,
                            "result": {
                                "stateBefore": { "debuggerPid": 12345, "generation": "1", "debugging": true, "running": false, "threadId": 42, "stableRead": true },
                                "stateAfter": { "debuggerPid": 12345, "generation": "1", "debugging": true, "running": false, "threadId": 42, "stableRead": true },
                                "sections": {
                                    "context": "CIP=0x140001050 | RAX=0x0 | DISASM: nop | STACK: [00]=0x0",
                                    "callStack": "Frame 0: 0x140001050 target.exe!main",
                                    "modules": { "modules": [{ "name": "target.exe", "base": "0x140000000", "end": "0x140010000", "path": "C:\\target.exe" }] }
                                }
                            }
                        }
                        """);

                case "StepInto":
                case "StepOver":
                case "StepOut":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"action\":\"step\"}}");

                case "EvaluateExpression":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x0\",\"valueDecimal\":0}}");

                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }

    private sealed class FuzzingMockGhidra : IGhidraClient
    {
        public string? CustomResponse { get; set; }

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (CustomResponse is not null)
                return Task.FromResult(CustomResponse);
            return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":\"ghidra_unavailable\"}");
        }
    }
}
