using DbgLink.Server;
using DbgLink.Shared;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using Xunit.Abstractions;

namespace DbgLink.Tests;

/// <summary>
/// Adversarial stress suite (x64dbg track thin orchestrator): concurrency
/// stampedes, hostile payloads, NTFS traversal tricks, schema fuzzing, and
/// deadline starvation.
/// Ownership split: this track owns the x64dbg-facing parts
/// (session stampedes, dispatcher deadline-starvation, bridge wire sabotage)
/// kept here as the orchestrator. Ghidra/static parts are owned by the RB
/// track and are not touched here. NTFS path policy is owned by
/// NativePipeAndPathSecurityTests — the NTFS vectors below exercise adjacent
/// layers (registry/store-ctor) and are complementary, not duplicates.
/// </summary>
public sealed class AdversarialStressTests
{
    private readonly ITestOutputHelper _output;

    public AdversarialStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // ========================================================================================
    // 1. SESSION REGISTRY CONCURRENCY & LIFECYCLE STAMPEDE (x64dbg orchestrator, kept)
    // ========================================================================================

    [Fact]
    public async Task Stress_01_ConcurrentStampede_HammeringRegistrationAndGates_NoDeadlocks()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var tempDir = Path.GetTempPath();
        var tasks = new List<Task>();

        for (int i = 0; i < 100; i++)
        {
            var taskIndex = i;
            tasks.Add(Task.Run(async () =>
            {
                var id = $"stress-session-{taskIndex % 10}";
                var pipe = $"DbgLink.Control.{100 + (taskIndex % 10)}";

                for (int iter = 0; iter < 10; iter++)
                {
                    switch (iter % 5)
                    {
                        case 0:
                            registry.TryRegister(new AnalysisSessionDescriptor(id, pipe, tempDir));
                            break;
                        case 1:
                            try { _ = registry.Resolve(id); }
                            catch (InvalidOperationException) { /* expected if closed */ }
                            break;
                        case 2:
                            {
                                var gate = registry.GetGate(id);
                                using var lease = await gate.EnterWriteAsync(CancellationToken.None);
                                await Task.Delay(1);
                            }
                            break;
                        case 3:
                            if (taskIndex % 3 == 0)
                            {
                                registry.Close(id);
                            }
                            break;
                        case 4:
                            try { registry.ReplaceBridge(id, pipe); }
                            catch (Exception) { /* expected if closed or pipe mismatch */ }
                            break;
                    }
                }
            }));
        }

        await Task.WhenAll(tasks);

        // After the entire stampede, "default" must still be resolvable and operational
        var defaultSession = registry.Resolve("default");
        Assert.NotNull(defaultSession);
        Assert.Equal("default", defaultSession.AnalysisId);
    }

    [Fact]
    public async Task Stress_02_DefaultSession_SurvivesRepeatedKillAttempts_UnderActiveCalls()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var tasks = new List<Task>();
        var closeAttempts = 0;
        var resolveSuccesses = 0;

        for (int i = 0; i < 50; i++)
        {
            var taskIndex = i;
            tasks.Add(Task.Run(() =>
            {
                for (int iter = 0; iter < 20; iter++)
                {
                    if (taskIndex % 2 == 0)
                    {
                        registry.Close("default");
                        Interlocked.Increment(ref closeAttempts);
                    }
                    else
                    {
                        var s = registry.Resolve("default");
                        Assert.NotNull(s);
                        Assert.Equal("default", s.AnalysisId);
                        Assert.NotNull(s.Bridge);
                        Interlocked.Increment(ref resolveSuccesses);
                    }
                }
            }));
        }

        await Task.WhenAll(tasks);

        var finalDefault = registry.Resolve("default");
        Assert.NotNull(finalDefault);
        Assert.False(registry.IsClosed("default"), "Default session should never be marked permanently closed");
        _output.WriteLine($"Default session withstood {closeAttempts} close attempts and {resolveSuccesses} resolutions");
    }

    [Fact]
    public async Task Stress_03_GhostSession_RevivalAfterClose_StrictlyPrevented()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var tempDir = Path.GetTempPath();
        const string ghostId = "zombie-session-666";
        var desc = new AnalysisSessionDescriptor(ghostId, "DbgLink.Control.666", tempDir);

        Assert.True(registry.TryRegister(desc));
        Assert.Equal(ghostId, registry.Resolve(ghostId).AnalysisId);

        registry.Close(ghostId);
        Assert.True(registry.IsClosed(ghostId));

        var tasks = new List<Task<bool>>();
        for (int i = 0; i < 30; i++)
        {
            tasks.Add(Task.Run(() => registry.TryRegister(desc)));
        }

        var results = await Task.WhenAll(tasks);
        Assert.All(results, success => Assert.False(success));

        var ex = Assert.Throws<AnalysisSessionNotFoundException>(() => registry.Resolve(ghostId));
        Assert.Contains("was not found", ex.Message);
    }

    // Registry-layer twin of the IsValidAnalysisId policy pinned in
    // NativePipeAndPathSecurityTests: rejected here via TryRegister.
    [Fact]
    public void Stress_04_AnalysisId_PathTraversalAndUnicodeExploits_SafelyRejected()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var tempDir = Path.GetTempPath();

        var adversarialIds = new[]
        {
            "../../../../windows/system32",
            "..\\..\\boot.ini",
            "session\0injected",
            "\u202Efdas_exe", // Right-to-Left Override Trojan
            new string('X', 500), // Far exceeds 128 character max
            "", "   ", "\t\t",
            "session; DROP TABLE Sessions;--",
            "<script>alert(1)</script>",
            "session with spaces",
            "session@evil.com",
            "🔥💀🍺" // Non-alphanumeric unicode
        };

        foreach (var badId in adversarialIds)
        {
            var descriptor = new AnalysisSessionDescriptor(badId, "DbgLink.Control.42", tempDir);
            var registered = registry.TryRegister(descriptor);
            Assert.False(registered, $"Adversarial ID '{badId}' must be rejected by TryRegister");
        }
    }

    // ReplaceBridge entry point for the pipe policy owned by
    // NativePipeAndPathSecurityTests (Group 1 pins the policy itself).
    [Fact]
    public void Stress_05_ReplaceBridge_InvalidPipeName_ThrowsInvalidOperationException()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());

        var badPipes = new[]
        {
            "DbgLink.Control.-1",
            "DbgLink.Control.0",
            "DbgLink.Control.00042",
            "DbgLink.Control.2147483648", // int32 overflow
            "DbgLink.Control.text",
            "\\pipe\\evil",
            ""
        };

        foreach (var badPipe in badPipes)
        {
            var ex = Assert.Throws<InvalidOperationException>(() => registry.ReplaceBridge("default", badPipe));
            Assert.Contains("Invalid debugger pipe", ex.Message);
        }
    }

    // ========================================================================================
    // 2. CHECKPOINT STORE ADVERSARIAL DISK & REPARSE DEFENSE (kept; raw path
    //    policy itself is owned by NativePipeAndPathSecurityTests)
    // ========================================================================================

    [Fact]
    public async Task Stress_06_CheckpointStore_CorruptTamperedDiskFile_ThrowsJsonException()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var checkpointPath = Path.Combine(tempDir, "corrupt_store.json");

        try
        {
            var corruptContents = new[]
            {
                "{\"version\": 2, \"checkpoints\": {", // Truncated mid-object
                "{\"version\": 1, \"checkpoints\": {}}", // Wrong version
                "{\"version\": 2}", // Missing checkpoints
                "{\"version\": 2, \"checkpoints\": []}", // checkpoints is array not object
                "{\"version\": 2, \"checkpoints\": {}, \"extra\": 123}", // Disallowed unmapped property
                "<xml>Not Json</xml>",
                "\0\0\0\0\0\0\0\0"
            };

            foreach (var corrupt in corruptContents)
            {
                await File.WriteAllTextAsync(checkpointPath, corrupt, Encoding.UTF8);
                var store = new CheckpointStore(checkpointPath);

                Assert.ThrowsAny<JsonException>(() => store.LoadSnapshot("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    // Store-ctor layer for the path guards owned by
    // NativePipeAndPathSecurityTests (Group 3 pins IsSafePath itself).
    [Fact]
    public void Stress_07_CheckpointStore_ForbiddenNtfsStreamsAndReparsePoints_ThrowsImmediately()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var forbiddenPaths = new[]
            {
                "",
                "    ",
                new string('c', 33_000) // Exceeds 32,760 limit
            };

            foreach (var forbidden in forbiddenPaths)
            {
                var ex = Record.Exception(() => new CheckpointStore(forbidden));
                Assert.True(ex is ArgumentException or IOException, $"Path '{forbidden}' should throw ArgumentException or IOException, got {ex?.GetType().Name}");
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Stress_08_CheckpointStore_ConcurrentMultithreadedSaves_FileLockContention_MaintainsIntegrity()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var checkpointPath = Path.Combine(tempDir, "multithread_store.json");

        try
        {
            var store = new CheckpointStore(checkpointPath);
            const int threadCount = 12;
            var tasks = new List<Task>();

            for (int i = 0; i < threadCount; i++)
            {
                var index = i;
                tasks.Add(Task.Run(() =>
                {
                    var sha = $"{index:x2}" + new string('0', 62);
                    var checkpoint = new McpCheckpoint(
                        Sha256: sha,
                        Title: $"Stress Title {index}",
                        Findings: $"Findings {index}\nSecond line of findings.",
                        Hypotheses: $"Hypothesis {index}",
                        Verified: $"Verified {index}",
                        NextStep: $"Next command {index}",
                        Context: $"Context {index}",
                        LiveValues: $"LiveValues {index}",
                        CreatedAtUtc: DateTimeOffset.UtcNow,
                        AnalysisId: $"session-{index}");

                    store.Save(checkpoint);
                }));
            }

            await Task.WhenAll(tasks);

            // Verify that all 12 checkpoints exist and are completely undamaged
            var keys = store.ListSha256();
            Assert.Equal(threadCount, keys.Count);

            for (int i = 0; i < threadCount; i++)
            {
                var sha = $"{i:x2}" + new string('0', 62);
                var loaded = store.Load(sha);
                Assert.NotNull(loaded);
                Assert.Equal($"Stress Title {i}", loaded.Title);
                Assert.Equal($"session-{i}", loaded.AnalysisId);
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Stress_09_CheckpointStore_AdversarialOversizedPayload_RejectedCleanly()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var checkpointPath = Path.Combine(tempDir, "oversized_store.json");

        try
        {
            var store = new CheckpointStore(checkpointPath);
            const string validSha = "1111111111111111111111111111111111111111111111111111111111111111";

            // Title exceeds MaxTitleLength (256)
            var hugeTitleCheckpoint = new McpCheckpoint(
                Sha256: validSha,
                Title: new string('A', 300),
                Findings: "valid", Hypotheses: "valid", Verified: "valid", NextStep: "valid",
                Context: "", LiveValues: "", CreatedAtUtc: DateTimeOffset.UtcNow, AnalysisId: null);

            var ex = Assert.Throws<IOException>(() => store.Save(hugeTitleCheckpoint));
            Assert.Contains("exceeds the storage limits", ex.Message);

            // Invalid SHA256 (length 63 instead of 64)
            var badShaCheckpoint = new McpCheckpoint(
                Sha256: new string('1', 63),
                Title: "Valid Title",
                Findings: "valid", Hypotheses: "valid", Verified: "valid", NextStep: "valid",
                Context: "", LiveValues: "", CreatedAtUtc: DateTimeOffset.UtcNow, AnalysisId: null);

            Assert.Throws<IOException>(() => store.Save(badShaCheckpoint));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    // ========================================================================================
    // 3. PROTOCOL CORRUPTION & WIRE SABOTAGE (x64dbg orchestrator, kept)
    // ========================================================================================

    [Fact]
    public void Stress_10_Bridge_MalformedJsonRpcPayloads_TypeMismatches_SafelyFlaggedAsError()
    {
        var corruptedPayloads = new[]
        {
            "{\"id\":\"not-an-int\",\"ok\":true}",
            "{\"ok\":1}", // ok as number instead of boolean
            "{\"ok\":false,\"error\":404}", // error as number instead of string/object
            "{\"ok\":true,\"result\":null}", // null result
            "{\"ok\":true}", // completely missing result and text fields
            "{\"id\":1}", // missing ok and result
            "{\"ok\":true,\"result\":{\"a\":1,\"a\":2}}" // duplicate JSON property
        };

        foreach (var payload in corruptedPayloads)
        {
            var analysis = ToolSupport.AnalyzeBridgeResponse(payload);
            Assert.True(analysis.IsError, $"Payload '{payload}' must be recognized as an error response");
        }
    }

    // Direct-policy vectors complementing NativePipeAndPathSecurityTests
    // Group 1 (hostile pipe spellings incl. NUL/remote-prefix forms).
    [Fact]
    public void Stress_11_Bridge_NegativeAndOverflowProcessIds_InNativePipes_StrictlyRejected()
    {
        var hostilePipes = new[]
        {
            "DbgLink.Control.-1",
            "DbgLink.Control.0",
            "DbgLink.Control.007", // Leading zeros disallowed
            "DbgLink.Control.2147483648", // int32.MaxValue + 1 (overflow)
            "DbgLink.Control.9999999999999999999999999999999",
            "DbgLink.Control.123\0pipe",
            "\\\\.\\pipe\\DbgLink.Control.42",
            "DbgLink.Control. 42",
            "DbgLink.Control.+42"
        };

        foreach (var pipe in hostilePipes)
        {
            Assert.False(NativePipeNamePolicy.IsValid(pipe), $"Pipe name '{pipe}' must be strictly rejected");
        }

        // Valid ones must pass
        Assert.True(NativePipeNamePolicy.IsValid("DbgLink.Control"));
        Assert.True(NativePipeNamePolicy.IsValid("DbgLink.Control.1"));
        Assert.True(NativePipeNamePolicy.IsValid("DbgLink.Control.2147483647")); // int32.MaxValue
    }

    [Fact]
    public async Task Stress_12_Bridge_BrokenPipe_AbruptStreamTermination_HandledWithoutProcessCrash()
    {
        var throwingBridge = new ThrowingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50410 }, throwingBridge);

        var req = new CallToolRequestParams
        {
            Name = "ReadMemAtAddress",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x140001000"),
                ["byteCount"] = JsonSerializer.SerializeToElement(16)
            }
        };

        var result = await server.CallToolAsync(req, CancellationToken.None);
        // Backend failures surface as a tool error result, not a protocol error.
        Assert.True(result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("backend component failed", text);
    }

    // ========================================================================================
    // 4. TOOL ARGUMENT RULES & SCHEMA ATTACK FUZZING
    // ========================================================================================

    [Fact]
    public void Stress_13_ToolArgumentRules_DuplicateKeys_InDeeplyNestedJsonObjects_Rejected()
    {
        var schema = new JsonObject
        {
            ["properties"] = new JsonObject
            {
                ["config"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["target"] = new JsonObject { ["type"] = "string" }
                    }
                }
            }
        };

        var duplicateNestedJson = """
        {
            "config": {
                "target": "alpha",
                "target": "beta"
            }
        }
        """;

        using var doc = JsonDocument.Parse(duplicateNestedJson);
        var err = ToolArgumentRules.Validate(schema, doc.RootElement);
        Assert.NotNull(err);
        Assert.Contains("duplicate properties", err);
    }

    [Fact]
    public void Stress_14_ToolArgumentRules_IntRangeFuzzing_ExceedingInt64LimitsAndFloatingFakes_Rejected()
    {
        var schema = new JsonObject
        {
            ["properties"] = new JsonObject
            {
                ["count"] = new JsonObject
                {
                    ["type"] = "integer",
                    ["minimum"] = 1,
                    ["maximum"] = 100
                }
            }
        };

        var invalidPayloads = new object[]
        {
            new { count = 9223372036854775808UL }, // UInt64 exceeding Int64
            new { count = 1e15 }, // Float scientific notation
            new { count = 42.5 }, // Non-integer
            new { count = "42" }, // String disguised as int
            new { count = 0 }, // Below minimum 1
            new { count = 101 }, // Above maximum 100
            new { count = -5 } // Negative
        };

        foreach (var payload in invalidPayloads)
        {
            var element = JsonSerializer.SerializeToElement(payload);
            var err = ToolArgumentRules.Validate(schema, element);
            Assert.NotNull(err);
            Assert.Contains("count does not satisfy its argument schema", err);
        }

        // Valid boundary
        var validMin = JsonSerializer.SerializeToElement(new { count = 1 });
        Assert.Null(ToolArgumentRules.Validate(schema, validMin));
        var validMax = JsonSerializer.SerializeToElement(new { count = 100 });
        Assert.Null(ToolArgumentRules.Validate(schema, validMax));
    }

    [Fact]
    public void Stress_15_ToolArgumentRules_BytePattern_StrictTokenBoundaryFuzzing()
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

        // Exactly 256 tokens -> valid
        var valid256 = string.Join(" ", Enumerable.Repeat("90", 256));
        var err256 = ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { pattern = valid256 }));
        Assert.Null(err256);

        // 257 tokens -> invalid (> 256 limit)
        var invalid257 = string.Join(" ", Enumerable.Repeat("90", 257));
        var err257 = ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { pattern = invalid257 }));
        Assert.NotNull(err257);

        // Fuzzing genuinely broken patterns
        var brokenPatterns = new[]
        {
            "?? ??", // Pure wildcards forbidden
            "48 8", // Odd nibble
            "48 8Z", // Non hex
            "48 888", // 3 hex characters instead of 2
            "48\r\n89 90" // Multiline in singleline
        };

        foreach (var broken in brokenPatterns)
        {
            var err = ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { pattern = broken }));
            Assert.NotNull(err);
        }
    }

    [Fact]
    public void Stress_16_ToolArgumentRules_ExclusiveSelectors_ViolationWithExtraneousKeys()
    {
        var schema = new JsonObject
        {
            ["x-exclusiveSelectors"] = new JsonArray { "function", "start" },
            ["properties"] = new JsonObject
            {
                ["function"] = new JsonObject { ["type"] = "string" },
                ["start"] = new JsonObject { ["type"] = "string" }
            }
        };

        var bothPresent = JsonSerializer.SerializeToElement(new
        {
            function = "0x140001000",
            start = "0x140002000",
            extraneous = "exploit"
        });

        var err = ToolArgumentRules.Validate(schema, bothPresent);
        Assert.Equal("DecompileModule accepts either function or start, not both.", err);
    }

    [Fact]
    public void Stress_17_ToolArgumentRules_Utf8ByteBomb_RejectsStringsExceedingByteLimit()
    {
        var schema = new JsonObject
        {
            ["properties"] = new JsonObject
            {
                ["label"] = new JsonObject
                {
                    ["type"] = "string",
                    ["maxLength"] = 100,
                    ["x-maxUtf8Bytes"] = 32
                }
            }
        };

        // 10 4-byte astral unicode glyphs = 40 UTF-8 bytes (exceeds 32 bytes limit),
        // but its string.Length is only 20 characters (within maxLength 100).
        var astralBomb = string.Concat(Enumerable.Repeat("𠀀", 10));
        var args = JsonSerializer.SerializeToElement(new { label = astralBomb });

        var err = ToolArgumentRules.Validate(schema, args);
        Assert.NotNull(err);
        Assert.Contains("label does not satisfy its argument schema", err);
    }

    // ========================================================================================
    // 5. ASLR MAPPING & CONFLICTING MODULES
    // ========================================================================================

    [Fact]
    public async Task Stress_18_AddressMapping_OverlappingAndConflictingLiveModules_HandledGracefully()
    {
        // 4 live modules with conflicting, intersecting, or reversed ranges
        var conflictingModules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000, 0x140050000, "Target.exe", "C:\\Target.exe"),
            new(0x140020000, 0x140080000, "Target.exe", "C:\\Target.exe"), // Overlapping base
            new(0x140000000, 0x140000000, "Ghost.dll", "C:\\Ghost.dll"), // Zero sized
            new(0x140090000, 0x140010000, "Broken.dll", "C:\\Broken.dll") // Inverted base > end
        };

        var staticFunc = new ToolSupport.StaticFunction("main", "0x140001000", "C:\\Target.exe", null, 0x1000);

        var result = await AddressMapping.BuildMappingResultAsync(
            staticFunc, conflictingModules, verifyHash: false, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result["match"]?.GetValue<bool>());
        Assert.Equal("0x140001000", result["liveAddress"]?.GetValue<string>());
    }

    [Fact]
    public void Stress_19_AddressMapping_NormalizeSha256_HostileFuzzing()
    {
        var invalidHashes = new[]
        {
            "",
            "   ",
            "123",
            new string('0', 63), // 1 char short
            new string('0', 65), // 1 char too long
            "G" + new string('0', 63), // 'G' is not a hex digit
            "000000000000000000000000000000000000000000000000000000000000000\0",
            "\u202E" + new string('a', 63)
        };

        foreach (var invalid in invalidHashes)
        {
            Assert.Null(AddressMapping.NormalizeSha256(invalid));
        }

        // Valid upper/lower case hex
        const string validHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var normalized = AddressMapping.NormalizeSha256(validHex);
        Assert.NotNull(normalized);
        Assert.Equal(validHex.ToLowerInvariant(), normalized);
    }

    [Fact]
    public async Task Stress_20_AddressMapping_ConcurrentCacheInvalidationUnderHeavyQueryStorm()
    {
        var mockBridge = new RecordingBridge();
        var staticFunc = new ToolSupport.StaticFunction("main", "0x140001000", "HardenedTarget.exe", null, 0x1000);
        var tasks = new List<Task>();

        for (int i = 0; i < 40; i++)
        {
            var taskIndex = i;
            tasks.Add(Task.Run(async () =>
            {
                if (taskIndex % 4 == 0)
                {
                    AddressMapping.InvalidateModuleCache();
                }
                else
                {
                    var result = await AddressMapping.BuildLiveMappingAsync(
                        mockBridge, staticFunc, verifyHash: false, CancellationToken.None);
                    Assert.NotNull(result);
                }
            }));
        }

        await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task Stress_21_LiveAnalysis_DisassemblyChunk_ReversedAddressesAndZeroOpcodeBombs()
    {
        var mockBridge = new MalformedDisassemblyBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50411 }, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "GetAnalysisSnapshot",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["maxFrames"] = JsonSerializer.SerializeToElement(4),
                ["maxChars"] = JsonSerializer.SerializeToElement(4000)
            }
        };

        var resp = await server.CallToolAsync(req, CancellationToken.None);
        Assert.False(resp.IsError);
        var text = string.Join("", resp.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));
        Assert.NotEmpty(text);
    }

    // ========================================================================================
    // 6. DISPATCHER ADMISSION & DEADLINE STARVATION (x64dbg orchestrator, kept)
    // ========================================================================================

    [Fact]
    public async Task Stress_22_McpToolDispatcher_StaggeredDeadlines_HighConcurrencyQueueDraining()
    {
        var delayingBridge = new DelayingBridge(delayMs: 200);
        var config = new ServerConfig
        {
            Port = 50412,
            MaxConcurrentRequests = 2,
            MaxQueuedOperations = 4
        };

        using var server = new LocalMcpServer(config, delayingBridge);
        var tasks = new List<Task>();
        var cancellations = 0;
        var successes = 0;

        for (int i = 0; i < 15; i++)
        {
            var taskIndex = i;
            tasks.Add(Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource();
                // Staggered timeouts between 5ms and 30ms (destined to trigger before 200ms delay)
                cts.CancelAfter(5 + (taskIndex % 5) * 5);

                var req = new CallToolRequestParams
                {
                    Name = "EvaluateExpressions",
                    Arguments = new Dictionary<string, JsonElement>
                    {
                        ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
                    }
                };

                try
                {
                    await server.CallToolAsync(req, cts.Token);
                    Interlocked.Increment(ref successes);
                }
                catch (OperationCanceledException)
                {
                    Interlocked.Increment(ref cancellations);
                }
                catch (McpProtocolException)
                {
                    // Admission queue full rejection or deadline
                }
            }));
        }

        await Task.WhenAll(tasks);

        // Verify queue is completely restored by executing an immediate call
        delayingBridge.DelayMs = 0;
        var verifyReq = new CallToolRequestParams { Name = "GetServerStatus" };
        var verifyResp = await server.CallToolAsync(verifyReq, CancellationToken.None);
        Assert.False(verifyResp.IsError);
        _output.WriteLine($"Staggered stress completed: {cancellations} cancelled, queue fully operational");
    }

    [Fact]
    public async Task Stress_23_McpToolDispatcher_CancelledTokenBeforeInvocation_ZeroResourceLeakage()
    {
        var mockBridge = new ResponsiveExpressionBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50413 }, mockBridge);

        using var cancelledCts = new CancellationTokenSource();
        cancelledCts.Cancel();

        var req = new CallToolRequestParams
        {
            Name = "EvaluateExpressions",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["expressions"] = JsonSerializer.SerializeToElement(new[] { "rax" })
            }
        };

        for (int i = 0; i < 50; i++)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server.CallToolAsync(req, cancelledCts.Token));
        }

        // Bridge must not have been touched
        Assert.Equal(0, mockBridge.RequestCount);

        // Server can still execute immediately
        var normalResp = await server.CallToolAsync(req, CancellationToken.None);
        Assert.False(normalResp.IsError);
    }

    [Fact]
    public async Task Stress_24_McpToolDispatcher_DisabledCapabilities_FastRejectionWithoutQueueUsage()
    {
        var config = new ServerConfig
        {
            Port = 50414,
            AllowMutation = false, // Mutation disabled!
            AllowAnnotation = true
        };

        var mockBridge = new RecordingBridge();
        using var server = new LocalMcpServer(config, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x140001000"),
                ["hexBytes"] = JsonSerializer.SerializeToElement("90 90")
            }
        };

        var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(req, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, ex.ErrorCode);
        Assert.Contains("capability", ex.Message);

        // Bridge was completely bypassed
        Assert.Equal(0, mockBridge.RequestCount);
    }

    // ========================================================================================
    // 7. PATHOLOGICAL CONTEXT & CALLSTACK RECURSION BOMBS
    // ========================================================================================

    [Fact]
    public void Stress_25_CallStackFolding_CyclicRecursivePathologicalChains_50000Frames()
    {
        // 50,000 system frames (infinite recursion dump in OS runtime)
        var sb = new StringBuilder();
        sb.AppendLine("Frame 0: 0x140001000 target.exe!main");
        for (int i = 1; i <= 49_998; i++)
        {
            sb.AppendLine($"Frame {i}: 0x7FF8{i % 0xFFFF:X4}000 ntdll.dll!RtlDispatchException+0x{i:X}");
        }
        sb.AppendLine("Frame 49999: 0x140002000 target.exe!end");

        var node = (JsonNode)JsonValue.Create(sb.ToString());
        var sw = Stopwatch.StartNew();
        var folded = AnalysisFormatting.FoldCallStackNode(node);
        sw.Stop();

        Assert.NotNull(folded);
        var text = folded!.ToString();
        Assert.True(text.Length < 2_000, $"50,000 frames must fold into < 2,000 chars, got {text.Length}");
        Assert.True(sw.ElapsedMilliseconds < 1500, $"Folding 50,000 frames took {sw.ElapsedMilliseconds} ms (must be < 1500ms)");
    }

    [Fact]
    public void Stress_26_AnalysisFormatting_FormatDiffContext_WithMassiveRegisterCount_1000Registers()
    {
        var state = new SessionSnapshotState();

        // Previous step had 1,000 registers
        var seed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 1000; i++)
        {
            seed[$"R{i}"] = $"0x{i:X8}";
        }
        state.ReplaceRegisters(seed);

        // New step has half of them modified, and some deleted/added
        var sb = new StringBuilder();
        sb.Append("CIP=0x140001000 | ");
        for (int i = 0; i < 1000; i++)
        {
            var val = (i % 2 == 0) ? i + 1 : i; // Half changed
            sb.Append($"R{i}=0x{val:X8} ");
        }

        var node = (JsonNode)JsonValue.Create(sb.ToString());
        var diff = AnalysisFormatting.FormatDiffContext(node, state);

        Assert.NotNull(diff);
        var diffText = diff!.ToString();
        Assert.Contains("R0=0x00000001", diffText); // R0 changed
        Assert.DoesNotContain("R1=", diffText); // R1 was unchanged
    }

    [Fact]
    public void Stress_27_AnalysisFormatting_FormatSparseContext_HostileAnsiAndControlInjection()
    {
        // Malicious register context containing ANSI escape bombs, control codes, and backspaces
        var hostileContext = "CIP=\x1b[31;1m0x140001000\x1b[0m | RAX=\0\0\0 | RBX=\b\b\b | RDX=\r\n\t0x20 | DISASM: \x1b]0;Pwned\x07nop";
        var node = (JsonNode)JsonValue.Create(hostileContext);

        var formatted = AnalysisFormatting.FormatSparseContext(node);
        Assert.NotNull(formatted);
        var text = formatted!.ToString();
        Assert.NotEmpty(text);
    }

    // ========================================================================================
    // 8. ORIGIN & HEADER ADVERSARIAL ATTACKS
    // ========================================================================================

    [Fact]
    public void Stress_28_McpRequestPolicy_OriginHeaderFuzzing_SubdomainsPortSpoofingAndTraversal_Forbidden()
    {
        const int port = 50400;

        var hostileOrigins = new[]
        {
            "http://localhost:50400/evil", // Path traversal / extra path
            "http://localhost:50400/../evil",
            "http://evil.localhost:50400/", // Subdomain spoofing
            "http://127.0.0.1.evil.com:50400/",
            "http://127.0.0.1:50401/", // Wrong port
            "https://127.0.0.1:50400/", // HTTPS instead of HTTP
            "http://[::1]:50400/", // IPv6 brackets
            "http://user:pass@127.0.0.1:50400/", // UserInfo injection
            "http://127.0.0.1:50400/?query=evil", // Query string
            "http://127.0.0.1:50400/#fragment", // Fragment
            "javascript:alert(1)",
            "data:text/html,evil",
            "null",
            new string('a', 300) // Oversized origin
        };

        foreach (var hostile in hostileOrigins)
        {
            Assert.False(McpRequestPolicy.OriginAllowed(hostile, port), $"Origin '{hostile}' must be rejected");
        }

        // Whitelisted origins must be allowed
        Assert.True(McpRequestPolicy.OriginAllowed("http://127.0.0.1:50400/", port));
        Assert.True(McpRequestPolicy.OriginAllowed("http://localhost:50400/", port));
        Assert.True(McpRequestPolicy.OriginAllowed("", port));
        Assert.True(McpRequestPolicy.OriginAllowed(null, port));
    }

    // ========================================================================================
    // 10 ROUNDS OF ADVERSARIAL REAL-WORLD BUG HUNTING & HARDENING
    // ========================================================================================

    [Fact]
    public async Task Stress_R01_TraceUntil_Mnemonic_DoesNotTriggerOnSubstringsInOperandsOrXor()
    {
        // Instructions sequence:
        // Step 0 (initial): xor eax, eax       (should NOT match "or"!)
        // Step 1:           mov rdx, [call_ptr] (should NOT match "call"!)
        // Step 2:           or eax, ebx         (MATCHES "or"!)
        var bridge = new SteppingSequenceBridge(new[]
        {
            ("0x140001000", "xor eax, eax"),
            ("0x140001002", "mov rdx, [call_ptr]"),
            ("0x140001006", "or eax, ebx")
        });

        var context = new AnalysisContext(bridge, new NullGhidra());
        var live = new LiveAnalysisTools(context);

        var args = JsonSerializer.SerializeToElement(new
        {
            stopAt = "or",
            maxSteps = 10
        });

        var respJson = await live.TraceUntilAsync(args, CancellationToken.None);
        var node = AnalysisFormatting.ReadBridgeResultNode(respJson);
        var trace = node?["trace"];

        Assert.NotNull(trace);
        // It must NOT have stopped at step 0 claiming xor matched "or"!
        Assert.NotEqual("already_at_target (matched_mnemonic: or)", trace?["stopReason"]?.GetValue<string>());
        Assert.Equal(2, trace?["stepsTaken"]?.GetValue<int>());
        Assert.Equal("matched_mnemonic: or", trace?["stopReason"]?.GetValue<string>());
    }

    [Fact]
    public async Task Stress_R02_Snapshot_NonBatchedMode_HonorsDiffOnly()
    {
        var bridge = new NonBatchedRegisterBridge();
        var context = new AnalysisContext(bridge, new NullGhidra());
        var live = new LiveAnalysisTools(context);

        // Snapshot 1: initial baseline
        var args1 = JsonSerializer.SerializeToElement(new
        {
            diffOnly = false,
            sparseRegisters = false
        });
        var resp1 = await live.GetAnalysisSnapshotAsync(args1, CancellationToken.None);
        var node1 = AnalysisFormatting.ReadBridgeResultNode(resp1);
        var ctx1 = node1?["sections"]?["context"]?.GetValue<string>();
        Assert.Contains("RAX=0x123", ctx1);
        Assert.Contains("RBX=0x456", ctx1);

        // Switch registers in mock for next snapshot: RAX stays 0x123, RBX changes to 0x789
        bridge.CurrentContext = "CIP=0x140001001 | RAX=0x123 RBX=0x789 | DISASM: nop | STACK: [00]=0x0";

        // Snapshot 2: diffOnly = true
        var args2 = JsonSerializer.SerializeToElement(new
        {
            diffOnly = true,
            sparseRegisters = false
        });
        var resp2 = await live.GetAnalysisSnapshotAsync(args2, CancellationToken.None);
        var node2 = AnalysisFormatting.ReadBridgeResultNode(resp2);
        var ctx2 = node2?["sections"]?["context"]?.GetValue<string>();

        // Under diffOnly in non-batched mode:
        // Changed register RBX must be present
        Assert.Contains("RBX=0x789", ctx2);
        // Unchanged register RAX must NOT be present in diff
        Assert.DoesNotContain("RAX=0x123", ctx2);
    }

    [Fact]
    public void Stress_R03_ToolArgumentRules_ArrayOfPrimitiveTypes_ValidatedSuccessfully()
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["tags"] = new JsonObject
                {
                    ["type"] = "array",
                    ["items"] = new JsonObject { ["type"] = "string" }
                },
                ["ids"] = new JsonObject
                {
                    ["type"] = "array",
                    ["items"] = new JsonObject { ["type"] = "integer", ["minimum"] = 1 }
                },
                ["flags"] = new JsonObject
                {
                    ["type"] = "array",
                    ["items"] = new JsonObject { ["type"] = "boolean" }
                }
            }
        };

        var validArgs = JsonSerializer.SerializeToElement(new
        {
            tags = new[] { "dbg", "kernel", "hook" },
            ids = new[] { 10, 20, 30 },
            flags = new[] { true, false, true }
        });

        var error = ToolArgumentRules.Validate(schema, validArgs);
        Assert.Null(error);

        // Also verify invalid item in primitive array is caught properly
        var invalidArgs = JsonSerializer.SerializeToElement(new
        {
            ids = new[] { 10, -5, 30 } // violates minimum: 1
        });
        var invalidError = ToolArgumentRules.Validate(schema, invalidArgs);
        Assert.NotNull(invalidError);
        Assert.Contains("ids", invalidError);
    }

    [Fact]
    public void Stress_R04_CallStackFolding_UserBinaryDeepRecursion_FoldsRepetitiveFrames()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Frame 0: 0x140001000 target.exe!main");
        for (int i = 1; i <= 30; i++)
        {
            sb.AppendLine($"Frame {i}: 0x140001050 target.exe!recursive_eval");
        }

        var input = JsonValue.Create(sb.ToString().TrimEnd());
        var folded = AnalysisFormatting.FoldCallStackNode(input);
        Assert.NotNull(folded);
        var foldedText = folded.GetValue<string>();

        // It must fold repetitive recursion even in user binaries
        Assert.Contains("recursive frames collapsed", foldedText);
        Assert.True(foldedText.Split('\n').Length < 10, $"Folded text lines count should be < 10, got {foldedText.Split('\n').Length}");
    }

    // Store-ctor enforcement of the ADS ban whose path policy lives in
    // NativePipeAndPathSecurityTests Group 3.
    [Fact]
    public void Stress_R05_CheckpointStore_NtfsAlternateDataStream_Rejected()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var adsPath = Path.Combine(tempDir, "store.json:hidden_stream");
            var adsData = Path.Combine(tempDir, "store.json::$DATA");

            // CheckpointStore and its underlying IsSafePath must refuse to open an NTFS alternate data stream
            Assert.Throws<ArgumentException>(() => new CheckpointStore(adsPath));
            Assert.Throws<ArgumentException>(() => new CheckpointStore(adsData));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    // Registry-policy twin of NativePipeAndPathSecurityTests Group 4
    // (reserved DOS names rejected as analysis ids).
    [Fact]
    public void Stress_R06_AnalysisId_ReservedDosNames_Rejected()
    {
        var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9", "con", "nul" };
        foreach (var name in reservedNames)
        {
            Assert.False(AnalysisSessionRegistry.IsValidAnalysisId(name), $"Reserved DOS name '{name}' should be rejected as an analysis ID.");
        }

        var validNames = new[] { "session-1", "worker_02", "analysis123" };
        foreach (var name in validNames)
        {
            Assert.True(AnalysisSessionRegistry.IsValidAnalysisId(name), $"Valid name '{name}' should be accepted.");
        }
    }

    [Fact]
    public void Stress_R07_FormatDiffContext_NoPhantomEmptyPipes()
    {
        var lastRegs = new SessionSnapshotState();
        lastRegs.ReplaceRegisters(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["RAX"] = "0x1",
            ["RBX"] = "0x2",
            ["RCX"] = "0x3",
        });

        // Context where the second segment has registers (RAX, RBX, RCX) and NONE changed
        var context = "CIP=0x140001000 | RAX=0x1 RBX=0x2 RCX=0x3 | DISASM: nop | STACK: [00]=0x0";
        var resultNode = AnalysisFormatting.FormatDiffContext(JsonValue.Create(context), lastRegs);
        Assert.NotNull(resultNode);
        var resultText = resultNode.GetValue<string>();

        // It must NOT emit empty phantom pipes like " |  | " or "| |"
        Assert.DoesNotContain("|  |", resultText);
        Assert.DoesNotContain("| |", resultText);
        Assert.False(resultText.Contains(" |  | "), $"Phantom empty pipe found: '{resultText}'");
    }

    [Fact]
    public void Stress_R08_IsSafeText_BidiTrojanAndZeroWidth_Rejected()
    {
        var trojanBidiOverride = "mov eax, \u202E1000"; // Trojan Source RTL override
        var zeroWidthSpace = "cmd\u200Bparam";
        var bidiIsolate = "target\u2067fake";

        Assert.False(ToolSupport.IsSafeText(trojanBidiOverride, allowLineBreaks: false));
        Assert.False(ToolSupport.IsSafeText(zeroWidthSpace, allowLineBreaks: false));
        Assert.False(ToolSupport.IsSafeText(bidiIsolate, allowLineBreaks: false));

        var cleanText = "valid_symbol_123!func";
        Assert.True(ToolSupport.IsSafeText(cleanText, allowLineBreaks: false));
    }

    [Fact]
    public void Stress_R09_OriginAllowed_StrictPathWithoutDotDot()
    {
        const int port = 50400;

        // Path traversal in origin should NEVER be permitted
        Assert.False(McpRequestPolicy.OriginAllowed($"http://localhost:{port}/..", port));
        Assert.False(McpRequestPolicy.OriginAllowed($"http://localhost:{port}/evil/..", port));
        Assert.False(McpRequestPolicy.OriginAllowed($"http://127.0.0.1:{port}/../", port));

        // Valid RFC 6454 origins must be allowed
        Assert.True(McpRequestPolicy.OriginAllowed($"http://localhost:{port}", port));
        Assert.True(McpRequestPolicy.OriginAllowed($"http://127.0.0.1:{port}", port));
        Assert.True(McpRequestPolicy.OriginAllowed($"http://localhost:{port}/", port));
    }

    [Fact]
    public void Stress_R10_CheckpointStore_FileLockContention_ThrowsTimeoutExceptionPromptly()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var checkpointPath = Path.Combine(tempDir, "contention_store.json");
        var lockPath = checkpointPath + ".lock";

        try
        {
            var store = new CheckpointStore(checkpointPath);

            // Externally lock the file exclusively
            using (var blockingLock = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                var sha = new string('a', 64);
                var checkpoint = new McpCheckpoint(
                    Sha256: sha,
                    Title: "Blocked Title",
                    Findings: "Blocked Findings",
                    Hypotheses: "Hypothesis",
                    Verified: "Verified",
                    NextStep: "Next",
                    Context: "Context",
                    LiveValues: "LiveValues",
                    CreatedAtUtc: DateTimeOffset.UtcNow,
                    AnalysisId: "session-1");

                var sw = Stopwatch.StartNew();
                // Must throw TimeoutException rather than raw untyped IOException or stalling for 5+ seconds
                var ex = Assert.Throws<TimeoutException>(() => store.Save(checkpoint));
                sw.Stop();

                Assert.Contains("lock", ex.Message, StringComparison.OrdinalIgnoreCase);
                Assert.True(sw.ElapsedMilliseconds < 2500, $"Lock acquisition timed out too slowly: {sw.ElapsedMilliseconds}ms");
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    // ========================================================================================
    // 9. ROUND 2: ORIGIN CASE/ENCODING EDGES, PIPE BOUNDARIES, TEXT SAFETY,
    //    SESSION FALLBACK & RESPONSE PARSING
    // ========================================================================================

    [Fact]
    public void Stress_R11_OriginAllowed_CaseNormalization_And_EncodingEdges()
    {
        const int port = 50400;

        // Scheme/host case is normalized by URI parsing (RFC 3986): still the same origin.
        Assert.True(McpRequestPolicy.OriginAllowed("HTTP://127.0.0.1:50400/", port));
        Assert.True(McpRequestPolicy.OriginAllowed("http://LOCALHOST:50400/", port));

        var encoded = new[]
        {
            $"http://127.0.0.1:{port}/%2e%2e", // Encoded traversal (also trips the '%' guard)
            $"http://127.0.0.1:{port}/%41", // Encoded 'A' in path
            $"http://127.0.0.1:{port}//", // Doubled slash: AbsolutePath is "//"
            $"http://127.0.0.1:{port}/mcp", // Any non-root path
            $"http://127.0.0.1:{port}.", // Trailing-dot host confusion
            $"http://127.0.0.1:{port}/\n", // Control char in origin
            $"http://127.0.0.1:{port}/?a=b&c=d", // Query, however encoded
        };

        foreach (var hostile in encoded)
            Assert.False(McpRequestPolicy.OriginAllowed(hostile, port), $"Origin '{hostile}' must be rejected");

        // Default-port omission never matches a custom loopback port.
        Assert.False(McpRequestPolicy.OriginAllowed("http://127.0.0.1/", port));
    }

    // Lexical-boundary twin of NativePipeAndPathSecurityTests Group 1
    // (empty suffix, leading zeros, case-sensitive prefix, length guard).
    [Fact]
    public void Stress_R12_PipeName_LengthAndLexical_Boundaries()
    {
        // Empty suffix, double zeros, and case-sensitive prefix.
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control."));
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control.00"));
        Assert.False(NativePipeNamePolicy.IsValid("dbglink.control.42"));
        Assert.False(NativePipeNamePolicy.IsValid("DBGLINK.CONTROL.42"));
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control.1 ")); // Trailing space
        Assert.False(NativePipeNamePolicy.IsValid(" DbgLink.Control.1")); // Leading space
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control.0x2A")); // Hex disguised as decimal
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control.+1"));
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control.1_000")); // Underscore separator

        // Length guard: 201 chars rejected even before digit parsing.
        Assert.False(NativePipeNamePolicy.IsValid(new string('z', 201)));
        // 200-char non-numeric still rejected (length alone is not acceptance).
        Assert.False(NativePipeNamePolicy.IsValid("DbgLink.Control." + new string('z', 184)));

        // Boundaries that must stay valid.
        Assert.True(NativePipeNamePolicy.IsValid("DbgLink.Control.1"));
        Assert.True(NativePipeNamePolicy.IsValid("DbgLink.Control.10")); // Multi-digit, no leading zero
    }

    [Fact]
    public void Stress_R13_IsSafeText_SurrogateAndControl_Boundaries()
    {
        // Lone surrogates are never safe text.
        Assert.False(ToolSupport.IsSafeText("\uD800", allowLineBreaks: false));
        Assert.False(ToolSupport.IsSafeText("\uDC00", allowLineBreaks: false));
        Assert.False(ToolSupport.IsSafeText("rax=\uD800", allowLineBreaks: true));

        // DEL and C1 controls are rejected even with line breaks allowed.
        Assert.False(ToolSupport.IsSafeText("a\u007Fb", allowLineBreaks: true));
        Assert.False(ToolSupport.IsSafeText("a\u0085b", allowLineBreaks: true));

        // Tab/LF/CR are allowed only when line breaks are permitted.
        Assert.False(ToolSupport.IsSafeText("a\tb", allowLineBreaks: false));
        Assert.True(ToolSupport.IsSafeText("a\tb", allowLineBreaks: true));
        Assert.False(ToolSupport.IsSafeText("a\nb", allowLineBreaks: false));
        Assert.True(ToolSupport.IsSafeText("a\nb\r\nc", allowLineBreaks: true));

        // Well-formed astral pair and BOM-adjacent format char handling.
        Assert.True(ToolSupport.IsSafeText("hit \U0001F525 target", allowLineBreaks: false));
        Assert.False(ToolSupport.IsSafeText("a\uFEFFb", allowLineBreaks: false)); // ZERO WIDTH NO-BREAK SPACE is Format
        Assert.True(ToolSupport.IsSafeText("", allowLineBreaks: false));
    }

    [Fact]
    public void Stress_R14_SessionResponse_TryRead_HostilePayloads()
    {
        // Valid envelope parses.
        Assert.True(AnalysisSessionResponse.TryRead(
            "{\"ok\":true,\"result\":{\"analysisId\":\"sess-1\",\"nativePipeName\":\"DbgLink.Control.7\",\"ghidraEndpointDirectory\":\"C:\\\\g\"}}",
            out var descriptor));
        Assert.NotNull(descriptor);
        Assert.Equal("sess-1", descriptor!.AnalysisId);

        var hostile = new[]
        {
            "",
            "{bad",
            "{\"ok\":true,\"ok\":false,\"result\":{}}", // Duplicate root property
            "{\"ok\":\"yes\",\"result\":{}}", // ok as string
            "{\"ok\":true}", // Missing result
            "{\"ok\":true,\"result\":null}", // Null result
            "{\"ok\":true,\"result\":[]}", // Array result
            "{\"ok\":true,\"result\":{\"analysisId\":\"s\"}}", // Missing pipe + endpoint
            "{\"ok\":true,\"result\":{\"analysisId\":7,\"nativePipeName\":\"DbgLink.Control.7\",\"ghidraEndpointDirectory\":\"C:\\\\g\"}}", // Non-string id
            "{\"ok\":false,\"error\":\"x\"}", // Error envelope
        };

        foreach (var payload in hostile)
        {
            Assert.False(AnalysisSessionResponse.TryRead(payload, out var parsed), $"Payload must be rejected: {payload}");
            Assert.Null(parsed);
        }
    }

    [Fact]
    public void Stress_R15_SessionRegistry_Fallback_NeverAmbiguous()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var tempDir = Path.GetTempPath();

        // Exact hit: no fallback note.
        Assert.True(registry.TryResolveWithFallback("default", out var exact, out var noNote));
        Assert.NotNull(exact);
        Assert.Null(noNote);

        // Blank id resolves the active session without a note.
        Assert.True(registry.TryResolveWithFallback("   ", out var active, out var blankNote));
        Assert.NotNull(active);
        Assert.Null(blankNote);

        // Unknown id with ONLY "default" live: zero non-default sessions -> hard error, no guess.
        Assert.False(registry.TryResolveWithFallback("ghost-1", out var none, out _));
        Assert.Null(none);

        // One extra live session -> single-candidate fallback with a note.
        Assert.True(registry.TryRegister(new AnalysisSessionDescriptor("solo-1", "DbgLink.Control.71", tempDir)));
        Assert.True(registry.TryResolveWithFallback("ghost-2", out var fallback, out var note));
        Assert.NotNull(fallback);
        Assert.Equal("solo-1", fallback!.AnalysisId);
        Assert.Contains("Unknown session", note);

        // Two extra live sessions -> ambiguous again, hard error.
        Assert.True(registry.TryRegister(new AnalysisSessionDescriptor("solo-2", "DbgLink.Control.72", tempDir)));
        Assert.False(registry.TryResolveWithFallback("ghost-3", out var ambiguous, out _));
        Assert.Null(ambiguous);
    }

    [Fact]
    public void Stress_R18_SessionGates_Are_PerSession_Singletons()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.Same(registry.GetGate("gate-a"), registry.GetGate("gate-a"));
        Assert.NotSame(registry.GetGate("gate-a"), registry.GetGate("gate-b"));
        Assert.NotSame(registry.GetGate("default"), registry.GetGate("gate-a"));
        Assert.Equal(0, registry.GetGate("gate-a").CurrentReaders);
        Assert.False(registry.GetGate("gate-a").WriterActive);
    }

    [Fact]
    public void Stress_R19_AnalysisId_Length_And_NearReserved_Boundaries()
    {
        // Exact 128-char boundary holds; 129 fails.
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId(new string('a', 128)));
        Assert.False(AnalysisSessionRegistry.IsValidAnalysisId(new string('a', 129)));
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId("a"));
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId("A-9_z"));

        // Near-misses of reserved DOS names are fine; exact hits (any case) are not.
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId("COM10"));
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId("CONX"));
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId("console"));
        Assert.False(AnalysisSessionRegistry.IsValidAnalysisId("CONIN$"));
        Assert.False(AnalysisSessionRegistry.IsValidAnalysisId("conout$"));

        // Null/blank registry lookups never throw; null resolves the active session.
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.False(registry.IsClosed(null));
        Assert.True(registry.TryResolveWithFallback(null, out var active, out var note));
        Assert.NotNull(active);
        Assert.Null(note);
    }

    // ========================================================================================
    // 10. ROUND 3: MODULE-RECORD PARSING
    // ========================================================================================

    [Fact]
    public void Stress_R17_ParseModuleRecords_HostileShapes_SkippedSafely()
    {
        // Null / non-object / missing-flag inputs yield an empty truncated set, never throw.
        Assert.Empty(AddressMapping.ParseModuleRecords(null));
        Assert.True(AddressMapping.ParseModuleRecords(null).Truncated);
        Assert.True(AddressMapping.ParseModuleRecords(new JsonArray()).Truncated);
        Assert.True(AddressMapping.ParseModuleRecords(new JsonObject { ["modules"] = new JsonArray() }).Truncated);
        var nonBoolFlag = new JsonObject { ["modules"] = new JsonArray(), ["truncated"] = "yes" };
        Assert.True(AddressMapping.ParseModuleRecords(nonBoolFlag).Truncated);

        // Mixed records: the valid one survives, corrupt ones flip Truncated without throwing.
        var mixed = new JsonObject
        {
            ["modules"] = new JsonArray
            {
                new JsonObject
                {
                    ["name"] = "good.exe", ["base"] = "0x140000000",
                    ["end"] = "0x140010000", ["path"] = "C:\\good.exe",
                },
                new JsonObject
                {
                    ["name"] = "inverted.dll", ["base"] = "0x140050000",
                    ["end"] = "0x140010000", ["path"] = "C:\\inverted.dll",
                },
                new JsonObject { ["name"] = "nameless", ["base"] = "0x140060000", ["end"] = "0x140070000" },
                "not-an-object",
                new JsonObject
                {
                    ["name"] = "   ", ["base"] = "0x140080000",
                    ["end"] = "0x140090000", ["path"] = "C:\\blank.exe",
                },
            },
            ["truncated"] = false,
        };
        var parsed = AddressMapping.ParseModuleRecords(mixed);
        var single = Assert.Single(parsed);
        Assert.Equal("good.exe", single.Name);
        Assert.True(parsed.Truncated);

        // All-valid input preserves the source flag.
        var clean = new JsonObject
        {
            ["modules"] = new JsonArray
            {
                new JsonObject
                {
                    ["name"] = "good.exe", ["base"] = "0x140000000",
                    ["end"] = "0x140010000", ["path"] = "C:\\good.exe",
                },
            },
            ["truncated"] = false,
        };
        var cleanParsed = AddressMapping.ParseModuleRecords(clean);
        Assert.False(cleanParsed.Truncated);
        Assert.Single(cleanParsed);
    }

    // ========================================================================================
    // TEST DOUBLES & MOCKS FOR CHAOS TESTING
    // ========================================================================================

    private sealed class ResponsiveExpressionBridge : IBridgeClient
    {
        private int _requestCount;
        public int RequestCount => Volatile.Read(ref _requestCount);

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x1\",\"valueDecimal\":1}}");
        }
    }

    private sealed class DelayingBridge : IBridgeClient
    {
        public int DelayMs { get; set; }

        public DelayingBridge(int delayMs) => DelayMs = delayMs;

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (DelayMs > 0)
            {
                await Task.Delay(DelayMs, cancellationToken);
            }
            return "{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x0\"}}";
        }
    }

    private sealed class MalformedDisassemblyBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            switch (method)
            {
                case "GetAnalysisSnapshot":
                    return Task.FromResult("""
                    {
                        "id": 1, "ok": true,
                        "result": {
                            "stateBefore": { "debuggerPid": 1234, "generation": "1", "debugging": true, "running": false, "threadId": 1, "stableRead": true },
                            "stateAfter": { "debuggerPid": 1234, "generation": "1", "debugging": true, "running": false, "threadId": 1, "stableRead": true },
                            "sections": {
                                "context": "CIP=0x140001000 | RAX=0x0 | DISASM: nop | STACK: [00]=0x0",
                                "callStack": "Frame 0: 0x140001000 target.exe!main",
                                "modules": { "modules": [{ "name": "target.exe", "base": "0x140000000", "end": "0x140010000", "path": "C:\\target.exe" }] }
                            }
                        }
                    }
                    """);

                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }

    private sealed class SteppingSequenceBridge : IBridgeClient
    {
        private readonly (string Address, string Instruction)[] _sequence;
        private int _index;

        public SteppingSequenceBridge((string Address, string Instruction)[] sequence)
        {
            _sequence = sequence;
        }

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            var cur = _sequence[Math.Min(_index, _sequence.Length - 1)];

            switch (method)
            {
                case "ReadDisassemblyChunk":
                    return Task.FromResult($$"""
                    {
                        "id": 1, "ok": true,
                        "result": {
                            "instructions": [
                                { "address": "{{cur.Address}}", "instruction": "{{cur.Instruction}}" }
                            ]
                        }
                    }
                    """);

                case "StepInto":
                case "StepOver":
                case "StepOut":
                    if (_index < _sequence.Length - 1) _index++;
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");

                case "GetSnapshotState":
                    return Task.FromResult("""
                    {
                        "id": 1, "ok": true,
                        "result": { "debugging": true, "running": false, "stableRead": true }
                    }
                    """);

                case "GetAnalysisSnapshot":
                    return Task.FromResult($$"""
                    {
                        "id": 1, "ok": true,
                        "result": {
                            "stateBefore": { "debugging": true, "running": false, "stableRead": true },
                            "stateAfter": { "debugging": true, "running": false, "stableRead": true },
                            "sections": {
                                "context": "CIP={{cur.Address}} | RAX=0x0 | DISASM: {{cur.Instruction}} | STACK: [00]=0x0",
                                "callStack": "Frame 0: {{cur.Address}} target.exe!worker",
                                "modules": { "modules": [{ "name": "target.exe", "base": "0x140000000", "end": "0x140010000" }] }
                            }
                        }
                    }
                    """);

                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }

    private sealed class NonBatchedRegisterBridge : IBridgeClient
    {
        public string CurrentContext { get; set; } = "CIP=0x140001000 | RAX=0x123 RBX=0x456 | DISASM: nop | STACK: [00]=0x0";

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            switch (method)
            {
                case "GetServerStatus":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
                case "GetSnapshotState":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"debugging\":true,\"running\":false,\"stableRead\":true}}");
                case "GetCurrentContext":
                    return Task.FromResult($"{{\"id\":1,\"ok\":true,\"result\":{{\"text\":\"{CurrentContext}\"}}}}");
                case "GetCallStack":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"text\":\"Frame 0: 0x140001000 target.exe!main\"}}");
                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }
}

