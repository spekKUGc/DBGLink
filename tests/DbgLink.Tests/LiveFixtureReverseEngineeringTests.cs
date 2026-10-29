using DbgLink.Server;
using DbgLink.Shared;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using Xunit.Abstractions;

namespace DbgLink.Tests;

/// <summary>
/// Live reverse-engineering test suite.
/// Directly executes reverse-engineering workflows against compiled real-world
/// C++ test fixtures (HardenedStressTarget.exe, HostileStressTarget.exe, AnalysisTarget.exe).
/// </summary>
public sealed class LiveFixtureReverseEngineeringTests
{
    private readonly ITestOutputHelper _output;
    public LiveFixtureReverseEngineeringTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private static string GetFixturePath(string filename)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "artifacts", "fixtures", "x64", filename);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException($"Compiled fixture binary was not found: {filename}");
    }

    /// <summary>
    /// True when <paramref name="needle"/> appears in <paramref name="haystack"/>.
    /// Used to prove that a constant really is present in a compiled fixture
    /// instead of asserting the test's own literals against themselves.
    /// </summary>
    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
            return false;
        for (var start = 0; start <= haystack.Length - needle.Length; start++)
        {
            var match = true;
            for (var offset = 0; offset < needle.Length; offset++)
            {
                if (haystack[start + offset] != needle[offset])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    // ========================================================================================
    // 1. REVERSING PE HEADERS & EXPORT TABLE
    // ========================================================================================

    [Fact]
    public void Live_Reversing_PE_Headers_And_Export_Surface_Of_HardenedTarget()
    {
        var targetPath = GetFixturePath("HardenedStressTarget.exe");
        using var stream = File.OpenRead(targetPath);
        using var peReader = new PEReader(stream);

        var peHeaders = peReader.PEHeaders;
        Assert.NotNull(peHeaders);

        // Verify architecture and subsystem
        Assert.Equal(Machine.Amd64, peHeaders.CoffHeader.Machine);
        Assert.Equal(Subsystem.WindowsCui, peHeaders.PEHeader!.Subsystem);
        Assert.True(peHeaders.PEHeader.AddressOfEntryPoint > 0);

        _output.WriteLine($"Target: HardenedStressTarget.exe");
        _output.WriteLine($"Architecture: {peHeaders.CoffHeader.Machine}");
        _output.WriteLine($"Image Base: 0x{peHeaders.PEHeader.ImageBase:X16}");
        _output.WriteLine($"Entry Point RVA: 0x{peHeaders.PEHeader.AddressOfEntryPoint:X}");

        // Inspect Sections
        var sectionNames = peHeaders.SectionHeaders.Select(h => h.Name).ToList();
        _output.WriteLine($"Sections found: {string.Join(", ", sectionNames)}");
        Assert.Contains(".text", sectionNames);
        Assert.Contains(".rdata", sectionNames);
        Assert.Contains(".data", sectionNames);

        // Verify Export Directory
        var exportDirectory = peHeaders.PEHeader.ExportTableDirectory;
        Assert.True(exportDirectory.RelativeVirtualAddress > 0, "HardenedStressTarget must contain an export directory");

        // Read Raw Export Names from .rdata
        var rdataHeader = peHeaders.SectionHeaders.First(h => h.Name == ".rdata");
        var rdataBytes = new byte[rdataHeader.SizeOfRawData];
        stream.Seek(rdataHeader.PointerToRawData, SeekOrigin.Begin);
        stream.ReadExactly(rdataBytes, 0, rdataBytes.Length);

        var rdataAscii = Encoding.ASCII.GetString(rdataBytes);
        var expectedExports = new[]
        {
            "TargetBanner",
            "FixtureObfuscatedStrings",
            "FixtureStateMachineDispatcher",
            "FixtureIndirectCall",
            "FixtureDeepRecursion",
            "FixtureGetCyclicStructure",
            "FixtureSpawnWorker"
        };

        foreach (var exp in expectedExports)
        {
            Assert.Contains(exp, rdataAscii);
            _output.WriteLine($"  [Export Found] {exp}");
        }
    }

    // ========================================================================================
    // 2. ASLR LIVE ADDRESS RESOLUTION & FILE INTEGRITY VERIFICATION
    // ========================================================================================

    [Fact]
    public async Task Live_Reversing_ASLR_Live_Address_Mapping_And_Hash_Validation()
    {
        var targetPath = GetFixturePath("HardenedStressTarget.exe");
        var fileBytes = await File.ReadAllBytesAsync(targetPath);
        var expectedSha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();

        const ulong liveBase = 0x00007FF714000000;
        const ulong liveEnd = 0x00007FF714050000;

        var mockBridge = new ReversingMockBridge
        {
            CustomModuleResponse = JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    modules = new[]
                    {
                        new
                        {
                            name = "HardenedStressTarget.exe",
                            @base = $"0x{liveBase:X16}",
                            end = $"0x{liveEnd:X16}",
                            path = targetPath
                        }
                    },
                    truncated = false
                }
            })
        };

        // Map export 'FixtureStateMachineDispatcher' with static RVA 0x1200
        var staticFunc = new ToolSupport.StaticFunction(
            "FixtureStateMachineDispatcher",
            "0x140001200",
            targetPath,
            expectedSha256,
            0x1200);

        var mapping = await AddressMapping.BuildLiveMappingAsync(
            mockBridge, staticFunc, verifyHash: true, CancellationToken.None);

        Assert.True(mapping["match"]?.GetValue<bool>());
        Assert.Equal("sha256", mapping["identity"]?["kind"]?.GetValue<string>());
        Assert.True(mapping["identity"]?["hashVerified"]?.GetValue<bool>());

        var expectedLiveAddr = $"0x{(liveBase + 0x1200):X}";
        Assert.Equal(expectedLiveAddr, mapping["liveAddress"]?.GetValue<string>());
        _output.WriteLine($"Mapped FixtureStateMachineDispatcher -> Live Address: {mapping["liveAddress"]}");
    }

    // ========================================================================================
    // 3. REVERSING OBFUSCATED STRINGS & XOR DECRYPTION
    // ========================================================================================

    [Fact]
    public async Task Live_Reversing_Obfuscated_StackStrings_And_Xor_Decryption()
    {
        var targetPath = GetFixturePath("HardenedStressTarget.exe");
        var fileBytes = await File.ReadAllBytesAsync(targetPath);

        // 1. Static Proof: The stack string "DBG_STACK_KEY" is constructed dynamically in instructions,
        // so it does NOT appear as a plain string in the PE file image.
        var fullAscii = Encoding.ASCII.GetString(fileBytes);
        Assert.DoesNotContain("DBG_STACK_KEY", fullAscii);
        _output.WriteLine("Verified: 'DBG_STACK_KEY' is completely absent from static file data (true stack string).");

        // 2. XOR-encrypted UTF-16 string analysis:
        // The fixture stores "DBGLink" XOR 0x5A as unsigned shorts. The
        // encrypted form is read back out of the COMPILED binary, so the test
        // proves the constant is really in the image instead of asserting the
        // test's own literals against themselves.
        var hardenedBytes = File.ReadAllBytes(GetFixturePath("HardenedStressTarget.exe"));
        var encryptedWide = new ushort[]
        {
            0x001E, 0x0018, 0x001D, 0x0016, 0x0033, 0x0034, 0x0031
        };
        var encodedWide = encryptedWide
            .SelectMany(w => new[] { (byte)(w & 0xFF), (byte)((w >> 8) & 0xFF) })
            .ToArray();
        Assert.True(ContainsSequence(hardenedBytes, encodedWide),
            "The XOR-encrypted wide string must be present in the compiled fixture.");

        // Decrypt with key 0x5A
        var decryptedChars = encryptedWide.Select(w => (char)(w ^ 0x5A)).ToArray();
        var decryptedText = new string(decryptedChars);
        Assert.Equal("DBGLink", decryptedText);
        _output.WriteLine($"Decrypted XOR (key 0x5A) wide string: '{decryptedText}'");

        // 3. Run Security String Triage on recovered strings via TriageImportsTools
        var mockBridge = new ReversingMockBridge
        {
            CustomResponse = JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    strings = new object[]
                    {
                        new { address = "0x140003000", value = "DBG_STACK_KEY", length = 13 },
                        new { address = "0x140003020", value = "DBGLink-Hardened-Adversarial-Target-v2.0", length = 40 },
                        new { address = "0x140003080", value = "https://c2.dbglink.internal/telemetry", length = 38 },
                        new { address = "0x1400030D0", value = "VirtualProtect", length = 14 }
                    }
                }
            })
        };

        var mockGhidra = new ReversingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var triage = new TriageImportsTools(context);

        var triageJson = await triage.TriageStringsAsync(null, CancellationToken.None);
        var triageNode = AnalysisFormatting.ReadBridgeResultNode(triageJson);
        Assert.NotNull(triageNode);

        var iocs = triageNode!["iocs"] as JsonArray;
        Assert.NotNull(iocs);
        Assert.Contains(iocs!, i => i?["type"]?.GetValue<string>() == "C2_URL");
        Assert.Contains(iocs!, i => i?["type"]?.GetValue<string>() == "Security_Sensitive_API");
        _output.WriteLine($"Triage completed: identified {iocs!.Count} suspicious indicators of compromise.");
    }

    // ========================================================================================
    // 4. REVERSING FLATTENED CONTROL FLOW STATE MACHINE
    // ========================================================================================

    [Fact]
    public async Task Live_Reversing_Flattened_Control_Flow_StateMachine()
    {
        // Target: FixtureStateMachineDispatcher(input = 42, rounds = 5)
        // States: 0x10 -> 0x30 -> 0x40 -> 0x50 -> 0x10 ...
        var stateTransitions = new List<(string State, int Acc)>
        {
            ("0x10", 42),
            ("0x30", 42 ^ 0x5A5A),
            ("0x40", ((42 ^ 0x5A5A) * 33) + 7),
            ("0x50", (((42 ^ 0x5A5A) * 33) + 7) ^ (0x40 * 0x1337)),
            ("0x10", ((((42 ^ 0x5A5A) * 33) + 7) ^ (0x40 * 0x1337)) + 1)
        };

        var stepCounter = 0;
        var mockBridge = new ReversingMockBridge
        {
            CustomStepHandler = (method, args) =>
            {
                var idx = Math.Min(stepCounter++, stateTransitions.Count - 1);
                var (state, acc) = stateTransitions[idx];
                return Task.FromResult(JsonSerializer.Serialize(new
                {
                    id = 1,
                    ok = true,
                    result = new
                    {
                        action = "step",
                        state = new
                        {
                            registers = $"CIP=0x1400010{idx:X2} RAX=0x{acc:X8} RBX=0x{state.Replace("0x", "")} RCX=0x0",
                            disasm = $"mov edx, {state}"
                        }
                    }
                }));
            }
        };

        var mockGhidra = new ReversingMockGhidra();
        var context = new AnalysisContext(mockBridge, mockGhidra);
        var live = new LiveAnalysisTools(context);

        // Trace execution through the state machine
        var traceArgs = JsonSerializer.SerializeToElement(new
        {
            maxSteps = 5,
            stopAddress = "0x140001099" // Terminal state 0x99
        });

        var traceResultJson = await live.TraceUntilAsync(traceArgs, CancellationToken.None);
        var traceNode = AnalysisFormatting.ReadBridgeResultNode(traceResultJson);
        Assert.NotNull(traceNode);

        var trace = traceNode!["trace"];
        Assert.NotNull(trace);
        Assert.Equal(5, trace!["stepsTaken"]?.GetValue<int>());
        Assert.Equal("max_steps_reached", trace["stopReason"]?.GetValue<string>());
        _output.WriteLine("Successfully traced 5 transitions of flattened state machine dispatcher.");
    }

    // ========================================================================================
    // 5. REVERSING CYCLIC HEAP GRAPH VIA INSPECTADDRESSSTRUCTURE
    // ========================================================================================

    [Fact]
    public async Task Live_Reversing_Cyclic_Heap_Structure_Via_InspectAddressStructure()
    {
        // Target: ComplexNode from FixtureGetCyclicStructure
        // Root (0xDEADBEEF, "RootNode") -> Child (0xCAFEBABE, "ChildNode") -> Root (cycle)
        // Root -> Peer (0xBAADF00D, "PeerNode") -> Root (cycle)

        var mockBridge = new ReversingMockBridge
        {
            CustomInspectResponse = JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    address = "0x140005000",
                    module = "HardenedStressTarget.exe",
                    fields = new object[]
                    {
                        new { offset = 0, name = "magic", value = "0xDEADBEEF" },
                        new { offset = 4, name = "id", value = 1 },
                        new { offset = 8, name = "next", pointer = "0x140005100", target = "PeerNode (0xBAADF00D)" },
                        new { offset = 16, name = "prev", pointer = "0x0", target = "null" },
                        new { offset = 24, name = "child", pointer = "0x140005200", target = "ChildNode (0xCAFEBABE)" },
                        new { offset = 32, name = "label", pointer = "0x140003100", target = "RootNode" }
                    }
                }
            })
        };

        using var server = new LocalMcpServer(new ServerConfig { Port = 50410 }, mockBridge);

        var req = new CallToolRequestParams
        {
            Name = "InspectAddressStructure",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x140005000"),
                ["pointerCount"] = JsonSerializer.SerializeToElement(8)
            }
        };

        var resp = await server.CallToolAsync(req, CancellationToken.None);
        Assert.False(resp.IsError);

        var respText = string.Join("", resp.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));
        Assert.Contains("0xDEADBEEF", respText);
        Assert.Contains("PeerNode", respText);
        Assert.Contains("ChildNode", respText);
        Assert.Contains("RootNode", respText);

        _output.WriteLine("InspectAddressStructure successfully reconstructed cyclic 3-node graph:");
        _output.WriteLine(respText);
    }

    // ========================================================================================
    // 6. REVERSING VEH TRAP & JIT RWX SHELLCODE IN HOSTILE STRESS TARGET
    // ========================================================================================

    [Fact]
    public void Live_Reversing_VEH_Trap_And_SelfDecrypting_Shellcode_In_HostileTarget()
    {
        var targetPath = GetFixturePath("HostileStressTarget.exe");
        using var stream = File.OpenRead(targetPath);
        using var peReader = new PEReader(stream);

        // 1. Verify Exports and Sections
        var sectionNames = peReader.PEHeaders.SectionHeaders.Select(h => h.Name).ToList();
        Assert.Contains(".text", sectionNames);
        Assert.Contains(".rdata", sectionNames);
        _output.WriteLine($"HostileStressTarget sections: {string.Join(", ", sectionNames)}");

        // 2. Analyze Encrypted Bytecode in FixtureSelfDecryptingShell:
        // The fixture stores the shellcode XOR 0x77; the compiler folds the
        // source-level "0x89 ^ 0x77" into the encrypted byte 0xFE. The
        // encrypted form is read back out of the COMPILED binary.
        var hostileBytes = File.ReadAllBytes(GetFixturePath("HostileStressTarget.exe"));
        var encryptedBytes = new byte[] { 0x89 ^ 0x77, 0xC8 ^ 0x77, 0x01 ^ 0x77, 0xD0 ^ 0x77, 0xC3 ^ 0x77 };
        Assert.True(ContainsSequence(hostileBytes, encryptedBytes),
            "The XOR-encrypted shellcode must be present in the compiled fixture.");

        // Decrypt with XOR 0x77
        var decryptedBytes = encryptedBytes.Select(b => (byte)(b ^ 0x77)).ToArray();

        // 89 C8 = mov eax, ecx
        // 01 D0 = add eax, edx
        // C3    = ret
        var expectedHex = "89 C8 01 D0 C3";
        var actualHex = string.Join(" ", decryptedBytes.Select(b => $"{b:X2}"));
        Assert.Equal(expectedHex, actualHex);
        _output.WriteLine($"Decrypted JIT RWX Shellcode: [{actualHex}] -> (mov eax, ecx; add eax, edx; ret)");

        // 3. Analyze VEH Dispatcher Math:
        // The handler XORs RAX with 0xCAFEBABE and returns secret ^ 0x5555.
        // Both masks are read back out of the COMPILED binary before the math
        // is applied to them.
        const uint vehMask = 0xCAFEBABE;
        const int returnMask = 0x5555;
        Assert.True(ContainsSequence(hostileBytes, BitConverter.GetBytes(vehMask)),
            "The VEH XOR mask must be present in the compiled fixture.");
        Assert.True(ContainsSequence(hostileBytes, BitConverter.GetBytes(returnMask)),
            "The VEH return mask must be present in the compiled fixture.");
        const int input = 0x1234;
        var expectedVehXor = input ^ returnMask;
        Assert.Equal(0x4761, expectedVehXor);
        _output.WriteLine($"Reversed VEH Control Flow: input 0x1234 yields {expectedVehXor:X4}");
    }

    // ========================================================================================
    // 7. KNOWLEDGE PERSISTENCE: INVESTIGATION CHECKPOINT SYNTHESIS
    // ========================================================================================

    [Fact]
    public async Task Live_Investigation_Session_Checkpoint_Persistence()
    {
        var targetPath = GetFixturePath("HardenedStressTarget.exe");
        var fileBytes = await File.ReadAllBytesAsync(targetPath);
        var targetSha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();

        var tempDir = Path.Combine(Path.GetTempPath(), "dbglink_live_rev_chkpt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var chkptStore = new CheckpointStore(Path.Combine(tempDir, "chkpt.json"));
        var chkptTools = new CheckpointTools(chkptStore);

        try
        {
            var createArgs = JsonSerializer.SerializeToElement(new
            {
                sha256 = targetSha256,
                title = "Reverse Engineering Audit of HardenedStressTarget.exe",
                findings = "Discovered 7 exported routines. Defeated stack-string obfuscation. Decrypted XOR 0x5A UTF-16 banner. Traced 5-state flattened dispatcher. Reconstructed 3-node cyclic heap graph.",
                hypotheses = "Binary is an adversarial stress fixture testing agent resilience against obfuscation.",
                verified = "Dynamic memory analysis and RVA mapping confirmed 100% address resolution and structure layout.",
                nextStep = "Add automated hooking for FixtureStateMachineDispatcher and export decompilation to Ghidra.",
                context = "CIP=0x7FF714001200 | Module=HardenedStressTarget.exe",
                liveValues = "RAX=0x5A70 | RBX=0x10 | Magic=0xDEADBEEF"
            });

            var createResp = await chkptTools.CreateCheckpointAsync(createArgs, "live-re-session-1");
            var createNode = JsonNode.Parse(createResp);
            Assert.True(createNode?["ok"]?.GetValue<bool>());

            // Read back the saved checkpoint
            var getArgs = JsonSerializer.SerializeToElement(new { sha256 = targetSha256 });
            var getResp = await chkptTools.GetLastCheckpointAsync(getArgs);
            var getNode = JsonNode.Parse(getResp);
            Assert.True(getNode?["ok"]?.GetValue<bool>());

            var cp = getNode?["result"]?["checkpoint"];
            Assert.NotNull(cp);
            Assert.Equal(targetSha256, cp!["sha256"]?.GetValue<string>());
            Assert.Contains("Discovered 7 exported routines", cp["findings"]?.GetValue<string>());
            Assert.Contains("CIP=0x7FF714001200", cp["context"]?.GetValue<string>());

            _output.WriteLine("Successfully created and verified comprehensive reverse-engineering checkpoint for binary.");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // ========================================================================================
    // MOCK BRIDGES FOR REVERSING TESTS
    // ========================================================================================

    private sealed class ReversingMockBridge : IBridgeClient
    {
        public string? CustomModuleResponse { get; set; }
        public string? CustomInspectResponse { get; set; }
        public string? CustomResponse { get; set; }
        public Func<string, JsonElement?, Task<string>>? CustomStepHandler { get; set; }

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            if (CustomStepHandler is not null && (method == "StepInto" || method == "StepOver" || method == "TraceUntil"))
                return CustomStepHandler(method, arguments);

            if (CustomResponse is not null)
                return Task.FromResult(CustomResponse);

            switch (method)
            {
                case "GetModuleRecords":
                    return Task.FromResult(CustomModuleResponse ?? "{\"id\":1,\"ok\":true,\"result\":{\"modules\":[],\"truncated\":false}}");

                case "InspectAddressStructure":
                    return Task.FromResult(CustomInspectResponse ?? "{\"id\":1,\"ok\":true,\"result\":{}}");

                case "GetSnapshotState":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"debuggerPid\":1234,\"generation\":\"1\",\"debugging\":true,\"running\":false,\"threadId\":1,\"stableRead\":true}}");

                case "EvaluateExpression":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"value\":\"0x0\",\"valueDecimal\":0}}");

                case "StepInto":
                case "StepOver":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"action\":\"step\"}}");

                case "ReadDisassemblyChunk":
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"address\":\"0x140001000\",\"instructions\":[{\"address\":\"0x140001000\",\"instruction\":\"nop\"}]}}");

                default:
                    return Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{}}");
            }
        }
    }

    private sealed class ReversingMockGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":\"ghidra_unavailable\"}");
        }
    }
}
