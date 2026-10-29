using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;
using static DbgLink.Tests.TestWire;
using static DbgLink.Tests.FixtureSeeds;

namespace DbgLink.Tests;

/// <summary>
/// Authoritative per-tool TOKEN baseline for the DbgLink token-efficiency
/// program. Every tool is called over the real wire stack (Kestrel HTTP +
/// Win32 named pipe + Ghidra TCP) against realistically seeded mocks, and
/// every token count is a real cl100k_base BPE count (see TokenCounter),
/// never bytes/4 or chars/3.7. Later reductions prove against the committed
/// mirror docs/reverse-speedup/benchmarks/token-baseline.json; the
/// artifacts/benchmark copy is gitignored scratch.
/// The writer Fact below regenerates ONLY the scratch artifact. The committed
/// mirror is refreshed deliberately via tools/regen-baseline.ps1 and
/// committed — NEVER as a test side effect. Mirror Facts read docs/ only.
/// Serialized in the shared LiveWire collection: the writer and the ceiling re-measure
/// share the wire harness and the scratch file, so parallel Facts would race.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class TokenBaselineTests
{
    private readonly ITestOutputHelper _output;

    public TokenBaselineTests(ITestOutputHelper output) => _output = output;

    // ========================================================================================
    // Realistic seeds: production-shaped payloads (decompilation, hex dumps,
    // symbol tables, thread/backtrace records, triage corpora). Every mock
    // envelope is built with JsonSerializer so malformed JSON is impossible.
    // ========================================================================================

    // Seeds below use FixtureSeeds.BuildDecompilation (Support/TestWire.cs):
    // the production-shaped listing both this suite and the reverse-cost
    // benchmark seed their mocks with. MockFingerprint stays per-suite (see
    // below): the probes hash different envelopes.

    private static readonly (string Name, string Entry, string Rva, int Size, string Core1, string Core2)[] FixtureFunctions =
    [
        ("FixtureCaller", "0x140001000", "0x1000", 96,
            "uVar7 = (undefined8)FixtureCallee((int)uVar4);",
            "uVar7 = uVar7 + (longlong)(int)(uint)*(undefined2 *)&FixtureUnicodePointer;"),
        ("FixtureCallee", "0x140001040", "0x1040", 64,
            "uVar7 = (undefined8)(iVar3 * 3 + 7);",
            "DAT_140003010 = DAT_140003010 + 1;"),
        ("FixtureImportedPid", "0x140001080", "0x1080", 48,
            "uVar7 = GetCurrentProcessId();",
            "DAT_140003020 = (uint)uVar7;"),
    ];

    private static readonly (string Name, string Library, string Address, int Sites)[] FixtureImports =
    [
        ("VirtualAlloc", "KERNEL32.dll", "EXTERNAL:00000001", 6),
        ("VirtualProtect", "KERNEL32.dll", "EXTERNAL:00000002", 4),
        ("WriteProcessMemory", "KERNEL32.dll", "EXTERNAL:00000003", 3),
        ("CreateRemoteThread", "KERNEL32.dll", "EXTERNAL:00000004", 2),
        ("CreateProcessW", "KERNEL32.dll", "EXTERNAL:00000005", 2),
        ("socket", "WS2_32.dll", "EXTERNAL:00000006", 5),
        ("connect", "WS2_32.dll", "EXTERNAL:00000007", 5),
        ("InternetOpenW", "WININET.dll", "EXTERNAL:00000008", 2),
        ("CryptEncrypt", "ADVAPI32.dll", "EXTERNAL:00000009", 2),
        ("RegSetValueExW", "ADVAPI32.dll", "EXTERNAL:0000000A", 3),
        ("RegCreateKeyExW", "ADVAPI32.dll", "EXTERNAL:0000000B", 2),
        ("IsDebuggerPresent", "KERNEL32.dll", "EXTERNAL:0000000C", 2),
        ("GetProcAddress", "KERNEL32.dll", "EXTERNAL:0000000D", 8),
        ("LoadLibraryW", "KERNEL32.dll", "EXTERNAL:0000000E", 7),
        ("GetCurrentProcessId", "KERNEL32.dll", "EXTERNAL:0000000F", 1),
        ("GetTickCount", "KERNEL32.dll", "EXTERNAL:00000010", 1),
        ("lstrlenW", "KERNEL32.dll", "EXTERNAL:00000011", 1),
        ("memset", "MSVCRT.dll", "EXTERNAL:00000012", 3),
        ("malloc", "MSVCRT.dll", "EXTERNAL:00000013", 2),
        ("ShellExecuteW", "SHELL32.dll", "EXTERNAL:00000014", 1),
        ("CoCreateInstance", "OLE32.dll", "EXTERNAL:00000015", 1),
        ("GetAddrInfoW", "WS2_32.dll", "EXTERNAL:00000016", 2),
        ("HttpSendRequestW", "WININET.dll", "EXTERNAL:00000017", 1),
        ("OutputDebugStringW", "KERNEL32.dll", "EXTERNAL:00000018", 1),
    ];

    private static readonly (string Value, string Addr)[] FixtureStrings =
    [
        ("http://192.168.1.10:8080/update", "0x140003000"),
        ("https://cdn.fixture.example/payload.bin", "0x140003028"),
        ("192.168.1.10", "0x140003050"),
        ("powershell -enc SQBmACgAJABQAFMAVgBvAG8AZgBlAHQAKQA=", "0x140003060"),
        ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "0x1400030A0"),
        ("IsDebuggerPresent", "0x1400030D0"),
        ("CheckRemoteDebuggerPresent", "0x1400030E8"),
        ("This program cannot be run in DOS mode", "0x140003100"),
        ("VirtualProtect", "0x140003128"),
        ("AES", "0x140003138"),
        ("C:\\fixture\\input.txt", "0x140003140"),
        ("callee-out", "0x140003158"),
        ("%s: failed with code %d", "0x140003168"),
        ("FixtureUnicodePointer", "0x140003180"),
        ("MZ", "0x140003198"),
        ("kernel32.dll", "0x1400031A0"),
        ("Enter license key:", "0x1400031B0"),
        ("TODO: remove debug print", "0x1400031C8"),
        ("--verbose", "0x1400031E4"),
        ("config.json", "0x1400031F0"),
        ("reglo", "0x140003200"),
        ("Update available, restart to apply", "0x140003208"),
        ("ws2_32", "0x14000322C"),
        ("GetProcAddress", "0x140003238"),
        ("R6002 floating point support not loaded", "0x140003248"),
        ("runtime error ", "0x140003270"),
        ("hello_world", "0x140003280"),
        ("test_string", "0x140003290"),
        ("Hello Ghidra", "0x1400032A0"),
        ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "0x1400032B0"),
        ("__security_cookie", "0x1400032D4"),
        ("__security_check_cookie", "0x1400032E8"),
        ("nullsub_1", "0x140003300"),
        ("sub_140001000", "0x140003310"),
        ("Unwind version mismatch", "0x140003320"),
        ("CorExitProcess", "0x14000333C"),
        ("mscoree.dll", "0x140003350"),
        ("v4.0.30319", "0x140003360"),
        (".NETFramework,Version=v4.8", "0x140003370"),
        ("Please wait while setup completes", "0x140003390"),
    ];

    private static object[] FixtureImportRows() => FixtureImports.Select(im => (object)new
    {
        name = im.Name,
        library = im.Library,
        address = im.Address,
        refCount = im.Sites,
    }).ToArray();

    private static object[] FixtureExportRows() => new object[]
    {
        new { name = "main", address = "0x140001000" },
        new { name = "FixtureCaller", address = "0x140001000" },
        new { name = "FixtureCallee", address = "0x140001040" },
        new { name = "FixtureImportedPid", address = "0x140001080" },
        new { name = "DllMain", address = "0x1400010C0" },
        new { name = "OnUpdate", address = "0x140001100" },
        new { name = "VerifyLicense", address = "0x140001140" },
        new { name = "DecodePacket", address = "0x140001180" },
    };

    private static object[] FixtureXrefsToRows() => new object[]
    {
        new { from = "0x140001010", type = "CALL", operandIndex = 0, function = new { name = "FixtureCaller", entry = "0x140001000" } },
        new { from = "0x1400010A0", type = "CALL", operandIndex = 0, function = new { name = "main", entry = "0x1400010A0" } },
        new { from = "0x1400010B4", type = "CALL", operandIndex = 0, function = new { name = "main", entry = "0x1400010A0" } },
        new { from = "0x140001200", type = "JUMP", operandIndex = 0, function = new { name = "DispatchTable", entry = "0x140001200" } },
        new { from = "0x140001300", type = "DATA", operandIndex = 1, function = new { name = "Init", entry = "0x140001300" } },
        new { from = "0x140001400", type = "CALL", operandIndex = 0, function = new { name = "Worker", entry = "0x140001400" } },
    };

    private static object[] FixtureXrefsFromRows() => new object[]
    {
        new { from = "0x140001000", to = "0x140001040", type = "CALL", operandIndex = 0, function = new { name = "FixtureCallee", entry = "0x140001040" } },
        new { from = "0x140001000", to = "0x140003000", type = "DATA", operandIndex = 1, function = new { name = "FixtureUnicodePointer", entry = "0x140003000" } },
        new { from = "0x140001010", to = "0x7FF800215000", type = "CALL", operandIndex = 0, symbol = "GetTickCount", function = new { name = "GetTickCount", entry = "0x7FF800215000" } },
    };

    private static (string Name, string Entry, string Rva) MatchFunction(string selector)
    {
        var match = FixtureFunctions.FirstOrDefault(fn =>
            string.Equals(fn.Name, selector, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fn.Entry, selector, StringComparison.OrdinalIgnoreCase));
        return (match.Name ?? selector, match.Entry ?? "0x140001000", match.Rva ?? "0x1000");
    }

    private static string DecompFor(string selector)
    {
        var match = FixtureFunctions.FirstOrDefault(fn =>
            string.Equals(fn.Name, selector, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fn.Entry, selector, StringComparison.OrdinalIgnoreCase));
        return BuildDecompilation(match.Name ?? selector,
            match.Core1 ?? "uVar7 = (undefined8)(longlong)iVar2;",
            match.Core2 ?? "DAT_140003000 = DAT_140003000 + 1;");
    }

    private static void SeedRealisticBackend(RealServerHarness harness)
    {
        // ---- Native debugger bridge: honor byte counts, production-shaped tables ----
        static string HexDump(int bytes)
        {
            var sb = new StringBuilder(bytes * 2);
            for (var i = 0; i < bytes; i++)
                sb.Append(((i * 37 + 11) & 0xFF).ToString("x2"));
            return sb.ToString();
        }

        static int WantBytes(JsonElement? args)
        {
            if (args is { ValueKind: JsonValueKind.Object })
            {
                if (args.Value.TryGetProperty("byteCount", out var bc) && bc.TryGetInt32(out var n))
                    return Math.Clamp(n, 1, 4096);
                if (args.Value.TryGetProperty("length", out var len) && len.TryGetInt32(out var m))
                    return Math.Clamp(m, 1, 4096);
            }
            return 256;
        }

        static string ReadMemResult(int id, JsonElement? args)
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            var n = WantBytes(args);
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { address = addr, bytes = HexDump(n), bytesRead = n },
            });
        }

        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, args) => ReadMemResult(id, args));
        harness.NativePipeServer.RegisterHandler("ReadMemoryChunk", (id, args) => ReadMemResult(id, args));
        harness.NativePipeServer.RegisterHandler("ReadDismAtAddress", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    address = addr,
                    instructions = new object[]
                    {
                        new { address = addr, instruction = "sub rsp, 28h", size = 4 },
                        new { address = "0x140001004", instruction = "mov rcx, cs:FixtureUnicodePointer", size = 7 },
                        new { address = "0x14000100B", instruction = "call FixtureCallee", size = 5 },
                        new { address = "0x140001010", instruction = "add eax, edx", size = 2 },
                    },
                },
            });
        });
        harness.NativePipeServer.RegisterHandler("ReadDisassemblyChunk", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    address = addr,
                    instructions = new object[]
                    {
                        new { address = addr, instruction = "sub rsp, 28h", size = 4 },
                        new { address = "0x140001004", instruction = "mov rcx, cs:FixtureUnicodePointer", size = 7 },
                    },
                },
            });
        });
        var pages = new object[]
        {
            new { @base = "0x140000000", size = "0x1000", protection = "PAGE_READONLY", info = "HEADER" },
            new { @base = "0x140001000", size = "0x10000", protection = "PAGE_EXECUTE_READ", info = ".text" },
            new { @base = "0x140011000", size = "0x8000", protection = "PAGE_READONLY", info = ".rdata" },
            new { @base = "0x140019000", size = "0x4000", protection = "PAGE_READWRITE", info = ".data" },
            new { @base = "0x14001D000", size = "0x2000", protection = "PAGE_READWRITE", info = ".pdata" },
            new { @base = "0x7FF800000000", size = "0x1A0000", protection = "PAGE_EXECUTE_READ", info = "ntdll.dll" },
            new { @base = "0x7FF800200000", size = "0xB0000", protection = "PAGE_EXECUTE_READ", info = "KERNEL32.DLL" },
            new { @base = "0x7FF800400000", size = "0x80000", protection = "PAGE_EXECUTE_READ", info = "KERNELBASE.dll" },
            new { @base = "0x7FFFFFFF0000", size = "0x10000", protection = "PAGE_READWRITE", info = "stack of main thread" },
            new { @base = "0x1A00000000", size = "0x5000", protection = "PAGE_READWRITE", info = "heap" },
            new { @base = "0x7FF800600000", size = "0x60000", protection = "PAGE_EXECUTE_READ", info = "USER32.dll" },
            new { @base = "0x7FF800700000", size = "0x30000", protection = "PAGE_EXECUTE_READ", info = "WS2_32.dll" },
        };
        harness.NativePipeServer.RegisterHandler("GetMemoryMap", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { pages } }));
        var threads = new object[]
        {
            new { threadId = 1, main = true, entry = "0x140001000", rip = "0x14000100B" },
            new { threadId = 2, main = false, entry = "0x7FF800210000", rip = "0x7FF8002150A0" },
            new { threadId = 3, main = false, entry = "0x140001080", rip = "0x140001092" },
            new { threadId = 4, main = false, entry = "0x7FF800610000", rip = "0x7FF800612340" },
        };
        harness.NativePipeServer.RegisterHandler("GetAllActiveThreads", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { threads, activeThreadId = 1 } }));
        harness.NativePipeServer.RegisterHandler("ListThreads", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { threads, activeThreadId = 1 } }));
        var frames = new object[]
        {
            new { frame = 0, address = "0x14000100B", from = "0x140001000", to = "0x14000100B", module = "test.exe" },
            new { frame = 1, address = "0x1400010A0", from = "0x140001090", to = "0x1400010A5", module = "test.exe" },
            new { frame = 2, address = "0x1400010C0", from = "0x1400010B0", to = "0x1400010C8", module = "test.exe" },
            new { frame = 3, address = "0x7FF8002150A0", from = "0x7FF800215000", to = "0x7FF8002150B0", module = "KERNEL32.DLL" },
            new { frame = 4, address = "0x7FF800700100", from = "0x7FF800700000", to = "0x7FF800700120", module = "ntdll.dll" },
            new { frame = 5, address = "0x7FF800700200", from = "0x7FF800700180", to = "0x7FF800700220", module = "ntdll.dll" },
            new { frame = 6, address = "0x140001000", from = "0x140001000", to = "0x140001004", module = "test.exe" },
            new { frame = 7, address = "0x7FF800215100", from = "0x7FF8002150C0", to = "0x7FF800215110", module = "KERNEL32.DLL" },
        };
        harness.NativePipeServer.RegisterHandler("GetCallStack", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { frames } }));
        harness.NativePipeServer.RegisterHandler("GetBacktrace", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { frames } }));
        var modules = new object[]
        {
            new { name = "test.exe", @base = "0x140000000", end = "0x140050000", path = "C:\\test.exe" },
            new { name = "ntdll.dll", @base = "0x7FF800000000", end = "0x7FF8001A0000", path = "C:\\Windows\\System32\\ntdll.dll" },
            new { name = "KERNEL32.DLL", @base = "0x7FF800200000", end = "0x7FF8002B0000", path = "C:\\Windows\\System32\\KERNEL32.DLL" },
            new { name = "KERNELBASE.dll", @base = "0x7FF800400000", end = "0x7FF800480000", path = "C:\\Windows\\System32\\KERNELBASE.dll" },
            new { name = "USER32.dll", @base = "0x7FF800600000", end = "0x7FF800660000", path = "C:\\Windows\\System32\\USER32.dll" },
            new { name = "WS2_32.dll", @base = "0x7FF800700000", end = "0x7FF800730000", path = "C:\\Windows\\System32\\WS2_32.dll" },
        };
        harness.NativePipeServer.RegisterHandler("GetModuleRecords", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { modules, truncated = false } }));
        harness.NativePipeServer.RegisterHandler("GetAllModulesFromMemMap", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { modules, truncated = false } }));
        harness.NativePipeServer.RegisterHandler("InspectAddressStructure", (id, args) =>
        {
            var addr = args?.TryGetProperty("address", out var a) == true ? a.GetString() ?? "0x140001000" : "0x140001000";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    address = addr,
                    fields = new object[]
                    {
                        new { offset = 0, name = "magic", value = "0x5A4D" },
                        new { offset = 8, name = "unicodePtr", value = "0x140003000", pointsTo = "C:\\fixture\\input.txt" },
                        new { offset = 16, name = "vtable", value = "0x140011000" },
                        new { offset = 24, name = "flags", value = "0x2A" },
                    },
                },
            });
        });

        // ---- Ghidra static bridge: production-shaped function/symbol/xref tables ----
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var selector = args?.TryGetProperty("function", out var f) == true ? f.GetString() ?? "main" : "main";
            var (name, entry, rva) = MatchFunction(selector);
            var size = FixtureFunctions.FirstOrDefault(fn => fn.Name == name).Size;
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = name,
                    entry,
                    rva,
                    size,
                    decompilation = DecompFor(selector),
                    references = new
                    {
                        callers = new[] { new { function = "main", from = "0x1400010A0", type = "CALL" } },
                        callees = new[] { new { function = "FixtureCallee", to = "0x140001040", type = "CALL" } },
                    },
                    symbols = new object[]
                    {
                        new { name, address = entry, kind = "FUNCTION" },
                        new { name = "FixtureUnicodePointer", address = "0x140003000", kind = "DATA" },
                    },
                    truncatedSections = Array.Empty<string>(),
                },
            });
        });
        harness.Ghidra.RegisterTcpHandler("AnalyzeFunctions", (id, args) =>
        {
            var names = args is { ValueKind: JsonValueKind.Object } && args.Value.TryGetProperty("functions", out var arr)
                ? arr.EnumerateArray().Select(e => e.GetString() ?? "main").ToArray()
                : ["main"];
            var entries = names.Select((selector, index) =>
            {
                var (name, entry, rva) = MatchFunction(selector);
                return (object)new
                {
                    index,
                    selector,
                    ok = true,
                    function = new { name, entry, rva },
                    decompilation = DecompFor(selector),
                    references = new
                    {
                        callers = new[] { new { name = "main", entry = "0x1400010A0" } },
                        callees = new[] { new { name = "FixtureCallee", entry = "0x140001040" } },
                    },
                    strings = new object[] { new { address = "0x140003000", value = "C:\\fixture\\input.txt", length = 20 } },
                    constants = new object[] { new { value = "0x2a", count = 3, firstAddress = "0x140001010" } },
                };
            }).ToArray();
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
                    maxChars = 24_000,
                    maxItems = 8,
                },
            });
        });
        harness.Ghidra.RegisterTcpHandler("DecompileModule", (id, _) =>
        {
            var functions = FixtureFunctions.Select(fn => (object)new
            {
                name = fn.Name,
                address = fn.Entry,
                rva = fn.Rva,
                size = fn.Size,
                nameQuality = "named",
                decomp = BuildDecompilation(fn.Name, fn.Core1, fn.Core2),
            }).ToArray();
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    summary = new
                    {
                        module = "test.exe",
                        imageBase = "0x140000000",
                        functionCount = 42,
                        returned = functions.Length,
                        truncated = true,
                        nextFunction = "0x1400010C0",
                    },
                    functions,
                },
            });
        });
        harness.Ghidra.RegisterTcpHandler("ListFunctions", (id, args) =>
        {
            // Production shape: counts are opt-in, thunk/range extras stay sparse.
            var includeCounts = args is { ValueKind: JsonValueKind.Object } &&
                args.Value.TryGetProperty("includeCounts", out var countsFlag) &&
                countsFlag.ValueKind == JsonValueKind.True;
            static JsonObject Row(string name, string entry, int size, int? count)
            {
                var row = new JsonObject { ["name"] = name, ["entry"] = entry, ["size"] = size };
                if (count.HasValue) row["instructionCount"] = count.Value;
                return row;
            }
            var rows = new JsonArray();
            foreach (var fn in FixtureFunctions)
                rows.Add(Row(fn.Name, fn.Entry, fn.Size, includeCounts ? 12 : null));
            for (var i = 0; i < 13; i++)
                rows.Add(Row($"FUN_14000{(0x2000 + i * 0x40):x}",
                    $"0x14000{(0x2000 + i * 0x40):X}", 16 + i * 8, includeCounts ? 4 + i : null));
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    functions = rows,
                    count = 16,
                    truncated = true,
                    nextOffset = 16,
                },
            });
        });
        harness.Ghidra.RegisterTcpHandler("ListImports", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { imports = FixtureImportRows(), count = FixtureImports.Length, truncated = false },
            }));
        harness.Ghidra.RegisterTcpHandler("ListExports", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { exports = FixtureExportRows(), count = 8, truncated = false },
            }));
        harness.Ghidra.RegisterTcpHandler("ListSymbolsBoth", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { imports = FixtureImportRows(), exports = FixtureExportRows() },
            }));
        harness.Ghidra.RegisterTcpHandler("XrefsTo", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { references = FixtureXrefsToRows(), truncated = false },
            }));
        harness.Ghidra.RegisterTcpHandler("XrefsFrom", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { references = FixtureXrefsFromRows(), truncated = false },
            }));
        harness.Ghidra.RegisterTcpHandler("XrefsBoth", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { to = FixtureXrefsToRows(), from = FixtureXrefsFromRows(), toTruncated = false, fromTruncated = false, truncated = false },
            }));
        harness.Ghidra.RegisterTcpHandler("DumpStrings", (id, _) =>
        {
            var strings = FixtureStrings.Select(s => (object)new
            {
                address = s.Addr,
                value = s.Value,
                length = s.Value.Length,
            }).ToArray();
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new { strings, count = strings.Length, truncated = false },
            });
        });
        harness.Ghidra.RegisterTcpHandler("GetAnalysisQueue", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 2,
                    queue = new object[]
                    {
                        new { name = "FixtureCallee", entry = "0x140001040", instructionCount = 4, named = true, calleeCount = 0 },
                        new { name = "FixtureImportedPid", entry = "0x140001080", instructionCount = 6, named = true, calleeCount = 0 },
                        new { name = "FUN_140002000", entry = "0x140002000", instructionCount = 9, named = false, calleeCount = 1 },
                        new { name = "FixtureCaller", entry = "0x140001000", instructionCount = 12, named = true, calleeCount = 1 },
                        new { name = "FUN_140002040", entry = "0x140002040", instructionCount = 7, named = false, calleeCount = 2 },
                        new { name = "main", entry = "0x1400010A0", instructionCount = 21, named = true, calleeCount = 3 },
                        new { name = "FUN_140002080", entry = "0x140002080", instructionCount = 5, named = false, calleeCount = 1 },
                        new { name = "DllMain", entry = "0x1400010C0", instructionCount = 8, named = true, calleeCount = 0 },
                    },
                    doneCount = 0,
                    remainingCount = 8,
                    truncated = false,
                },
            }));
        harness.Ghidra.RegisterTcpHandler("CallGraph", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    schemaVersion = 3,
                    nodes = new object[]
                    {
                        new { name = "main", entry = "0x1400010A0", rva = "0x10A0" },
                        new { name = "FixtureCaller", entry = "0x140001000", rva = "0x1000" },
                        new { name = "FixtureCallee", entry = "0x140001040", rva = "0x1040" },
                        new { name = "FixtureImportedPid", entry = "0x140001080", rva = "0x1080" },
                        new { name = "DllMain", entry = "0x1400010C0", rva = "0x10C0" },
                        new { name = "OnUpdate", entry = "0x140001100", rva = "0x1100" },
                        new { name = "VerifyLicense", entry = "0x140001140", rva = "0x1140" },
                        new { name = "DecodePacket", entry = "0x140001180", rva = "0x1180" },
                    },
                    edges = new object[]
                    {
                        new { s = 0, t = 1, n = 2 },
                        new { s = 1, t = 2, n = 3 },
                        new { s = 0, t = 3, n = 1 },
                        new { s = 5, t = 6, n = 1 },
                        new { s = 5, t = 7, n = 4 },
                        new { s = 4, t = 1, n = 1 },
                    },
                    totalCalls = 12,
                    truncated = false,
                },
            }));
    }

    private static string MockFingerprint()
    {
        var probe = string.Join('\n', new[]
        {
            BuildDecompilation("FixtureCaller", "uVar7 = (undefined8)FixtureCallee((int)uVar4);"),
            string.Join(',', FixtureImports.Select(im => im.Library + "!" + im.Name)),
            string.Join(',', FixtureStrings.Select(s => s.Value)),
        });
        return FixtureSeeds.Sha256Hex(probe);
    }

    private sealed record Row(
        string Name, object Arguments,
        int RequestChars, int ResponseChars,
        int RequestTokens, int ResponseTokens, int TotalTokens);

    // Pinned per-tool totalTokens (request + response, real cl100k_base BPE).
    // Band below: growth past the ceiling fails; update pins only when a
    // deliberate payload change lands. Measured 2026-10-10 over the real
    // wire stack against the seeds in this file (mockFingerprint in the
    // artifact proves the seed version).
    // Band centers below may sit slightly above the last measured mirror
    // values (within the ±15% tolerance); that is by design, not drift.
    // HARD CEILINGS are not duplicated here: AssertCeiling reads the
    // committed mirror docs/reverse-speedup/benchmarks/token-baseline.json
    // as the single source (see MirrorCeilingsLazy).
    // 2026-10-10 fixnt update (same run regenerates the mirror): ListSymbols
    // 1119->742 (refCount-by-default mock, no site arrays), Xrefs 264->384
    // (real wire carries function objects + operandIndex; old mock
    // understated), CallGraph 392->288 (v3 indexed {s,t,n} + no default
    // instructionCount), GetAnalysisQueue 347->268 (rva opt-in + dropped
    // totalFunctions/returned/limit echoes).
    // 2026-10-11 x4 update: ProbeFunction returnExpression schema text
    // documents the arch-aware default (rax on x64, eax on x86): tools/list
    // mirror ceilings comprehensive 12526->12534 and wire 13573->13581 (+8).
    // Lean strips property descriptions so its ceiling is untouched; the
    // GetServerStatus accounting fix is token-neutral (digit swaps).
    // 2026-10-25 catalog diet (same run regenerates the mirror): 6 hidden
    // singles (BatchAnnotate/SubmitAnnotations/BatchDebuggerOperations
    // supersets), ~30%+ description trim on the five largest tools plus a
    // broad prose diet, ListAnalysisSessions live-only diet with includeClosed.
    // tools/list:comprehensive 13109->9846, lean 5114->4676, wire 14141->10597.
    // 2026-10-26 snapshot diet (same run regenerates the mirror):
    // instructionBytes default 160->16, readOnly dropped from the envelope,
    // tool prose states the ~5-instruction default (net-negative tokens).
    // GetAnalysisSnapshot 646->642 (wire response -16B readOnly).
    private static readonly Dictionary<string, int> ExpectedTotals = new(StringComparer.Ordinal)
    {
        ["GetServerStatus"] = 325,
        ["GetAnalysisSnapshot"] = 529,
        ["TraceUntil"] = 377,
        ["ReadMemAtAddress"] = 341,
        ["InspectAddressStructure"] = 110,
        ["GetBacktrace"] = 330,
        ["ListThreads"] = 133,
        ["GetMemoryMap"] = 366,
        ["InspectFunction"] = 562,
        ["AnalyzeFunctions"] = 1744,
        ["DecompileModule"] = 1473,
        ["ListFunctions"] = 357,
        ["ListSymbols"] = 742,
        ["Xrefs"] = 384,
        ["CallGraph"] = 288,
        ["GetInvestigationBrief"] = 1051,
        ["Triage"] = 429,
        ["GetAnalysisQueue"] = 268,
        ["ListAnalysisSessions"] = 35,
        ["tools/list:comprehensive"] = 8200,
        ["tools/list:lean"] = 8200,
        ["tools/list:wire"] = 8871,
    };

    private static void AssertBand(string name, int actual)
    {
        if (!ExpectedTotals.TryGetValue(name, out var expected) || expected <= 0)
            return; // measuring run: pins not yet recorded
        var floor = expected - Math.Max(25, (int)(expected * 0.15));
        var ceiling = expected + Math.Max(25, (int)(expected * 0.15));
        Assert.InRange(actual, floor, ceiling);
    }

    // Hard ceiling pins (t2nt ratchet): the committed mirror
    // docs/reverse-speedup/benchmarks/token-baseline.json is the SINGLE source
    // for ceilings (no second hardcoded dict: the old TokenCeilings table
    // drifted from both ExpectedTotals and the mirror — ListSymbols 1119 vs
    // 742, CallGraph 392 vs 288, GetAnalysisQueue 347 vs 268 — and the
    // hardcoded ToolsList numbers drifted from the mirror schema section).
    // Observed wire totals must stay AT or UNDER the mirrored values: any
    // future increase fails. To lower a ceiling, land the deliberate
    // reduction, rerun the writer Fact (regenerates artifacts/ only), copy
    // with tools/regen-baseline.ps1, and commit the mirror; never raise a
    // ceiling to make a change pass. The tolerance-band pins above stay as
    // the drift detector in both directions.
    private static readonly Lazy<Dictionary<string, int>> MirrorCeilingsLazy = new(LoadMirrorCeilings);

    private static Dictionary<string, int> LoadMirrorCeilings()
    {
        var mirrorPath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "token-baseline.json");
        Assert.True(File.Exists(mirrorPath), $"Committed token mirror is missing: {mirrorPath}");
        using var document = JsonDocument.Parse(File.ReadAllText(mirrorPath));
        var root = document.RootElement;
        var ceilings = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var tool in root.GetProperty("tools").EnumerateArray())
            ceilings[tool.GetProperty("name").GetString()!] = tool.GetProperty("totalTokens").GetInt32();
        var schema = root.GetProperty("schema");
        ceilings["tools/list:comprehensive"] = schema.GetProperty("comprehensive").GetProperty("tokens").GetInt32();
        ceilings["tools/list:lean"] = schema.GetProperty("lean").GetProperty("tokens").GetInt32();
        ceilings["tools/list:wire"] = schema.GetProperty("wire").GetProperty("tokens").GetInt32();
        return ceilings;
    }

    private static void AssertCeiling(string name, int actual)
    {
        var ceilings = MirrorCeilingsLazy.Value;
        Assert.True(ceilings.TryGetValue(name, out var ceiling),
            $"No token ceiling pinned for '{name}': the committed mirror has no such entry — add the tool to the baseline instead of shipping unguarded growth.");
        Assert.True(actual <= ceiling,
            $"{name} grew past its token ceiling: observed {actual} > mirrored {ceiling}. " +
            "Only a deliberate, measured change may move the ceiling (regenerate + tools/regen-baseline.ps1 + commit).");
    }

    private static (string Name, object Arguments)[] BaselineCases() =>
    [
        ("GetServerStatus", new { }),
        ("GetAnalysisSnapshot", new { maxFrames = 8, instructionBytes = 64, stackBytes = 64, includeModules = true }),
        ("TraceUntil", new { count = 1, kind = "into", includeModules = false }),
        ("ReadMemAtAddress", new { address = "0x140001000", byteCount = 256 }),
        ("InspectAddressStructure", new { address = "0x140001000", pointerCount = 4 }),
        ("GetBacktrace", new { maxFrames = 8 }),
        ("ListThreads", new { maxItems = 16 }),
        ("GetMemoryMap", new { maxItems = 32 }),
        ("InspectFunction", new { function = "main" }),
        ("AnalyzeFunctions", new { functions = new[] { "main", "0x140001040", "0x140001080" }, maxItems = 8 }),
        ("DecompileModule", new { maxFunctions = 8 }),
        ("ListFunctions", new { maxItems = 16 }),
        ("ListSymbols", new { kind = "both", maxItems = 16 }),
        ("Xrefs", new { address = "0x140001000", direction = "both", maxItems = 8 }),
        ("CallGraph", new { maxNodes = 16, maxEdges = 64 }),
        ("GetInvestigationBrief", new { function = "main" }),
        ("Triage", new { kind = "imports", top = 16 }),
        ("GetAnalysisQueue", new { limit = 8 }),
        ("ListAnalysisSessions", new { }),
    ];

    [Fact]
    public async Task PerTool_TokenBaseline_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedRealisticBackend(harness);

        var cases = BaselineCases();

        var rows = new List<Row>();
        foreach (var (name, arguments) in cases)
        {
            var requestJson = JsonSerializer.Serialize(new { name, arguments });
            var text = TextOf(await harness.CallToolOverWireAsync(name, arguments));
            var reqTok = Tok(requestJson);
            var respTok = Tok(text);
            rows.Add(new Row(name, arguments, requestJson.Length, text.Length, reqTok, respTok, reqTok + respTok));
            _output.WriteLine($"  {name,-24} req={requestJson.Length,5}B/{reqTok,5}tok resp={text.Length,6:N0}B/{respTok,5:N0}tok total={reqTok + respTok,5:N0}tok");
        }

        // FULL tools/list schema: comprehensive + lean profiles in-process
        // (deterministic metadata, bridge-independent) plus the live wire copy.
        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var lean = new LocalMcpServer(new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        var compJson = comp.ListTools().ToJsonString();
        var leanJson = lean.ListTools().ToJsonString();
        var compTok = Tok(compJson);
        var leanTok = Tok(leanJson);
        _output.WriteLine($"SCHEMA comp chars={compJson.Length:N0} tok~{compTok:N0}; lean chars={leanJson.Length:N0} tok~{leanTok:N0}");

        using var wireDoc = await harness.PostRpcAsync("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        var wireSchemaJson = wireDoc.RootElement.GetProperty("result").GetProperty("tools").GetRawText();
        var wireTok = Tok(wireSchemaJson);
        _output.WriteLine($"SCHEMA wire chars={wireSchemaJson.Length:N0} tok~{wireTok:N0} tools={wireDoc.RootElement.GetProperty("result").GetProperty("tools").GetArrayLength()}");

        var report = new
        {
            schemaVersion = 1,
            tool = "token-baseline",
            mockFingerprint = MockFingerprint(),
            tools = rows.Select(r => new
            {
                name = r.Name,
                arguments = r.Arguments,
                requestChars = r.RequestChars,
                responseChars = r.ResponseChars,
                requestTokens = r.RequestTokens,
                responseTokens = r.ResponseTokens,
                totalTokens = r.TotalTokens,
            }).ToArray(),
            schema = new
            {
                comprehensive = new { chars = compJson.Length, tokens = compTok },
                lean = new { chars = leanJson.Length, tokens = leanTok },
                wire = new { chars = wireSchemaJson.Length, tokens = wireTok },
            },
            totals = new
            {
                calls = rows.Count,
                requestChars = rows.Sum(r => r.RequestChars),
                responseChars = rows.Sum(r => r.ResponseChars),
                requestTokens = rows.Sum(r => r.RequestTokens),
                responseTokens = rows.Sum(r => r.ResponseTokens),
                totalTokens = rows.Sum(r => r.TotalTokens),
            },
        };

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        // Writer regenerates ONLY the gitignored scratch artifact. To refresh
        // the committed mirror, run tools/regen-baseline.ps1 (copies
        // artifacts/benchmark/token-baseline.json over
        // docs/reverse-speedup/benchmarks/token-baseline.json) and commit the
        // mirror deliberately. Tests must not write committed files.
        var artifactPath = Path.Combine(RepoRoot(), "artifacts", "benchmark", "token-baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        File.WriteAllText(artifactPath, json);
        _output.WriteLine($"BASELINE session={rows.Count} calls total={report.totals.totalTokens:N0}tok ({report.totals.responseChars:N0}B resp)");
        _output.WriteLine($"BASELINE artifact={artifactPath}");
        _output.WriteLine("BASELINE mirror refresh: tools/regen-baseline.ps1 (deliberate copy, then commit)");

        Assert.Equal(cases.Length, rows.Count);
        Assert.All(rows, r => Assert.True(r.TotalTokens > 0, $"{r.Name} measured zero tokens"));
        Assert.True(File.Exists(artifactPath));
        foreach (var r in rows)
        {
            AssertBand(r.Name, r.TotalTokens);
            AssertCeiling(r.Name, r.TotalTokens);
        }
        AssertBand("tools/list:comprehensive", compTok);
        Assert.Equal(compTok, leanTok);
        AssertBand("tools/list:wire", wireTok);
        AssertCeiling("tools/list:comprehensive", compTok);
        AssertCeiling("tools/list:wire", wireTok);
    }

    [Fact]
    public void ToolsList_TokenCeiling()
    {
        // Every-turn guardrail (additive, never rewrites pins): tools/list is
        // re-sent every turn, so growth past the committed ceiling fails.
        // Ceilings come from the committed mirror (single source); update the
        // mirror downward only when a deliberate schema trim lands.
        // Single standard catalog: lean slot mirrors comprehensive.
        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var lean = new LocalMcpServer(new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        var compTok = Tok(comp.ListTools().ToJsonString());
        var leanTok = Tok(lean.ListTools().ToJsonString());
        var ceilings = MirrorCeilingsLazy.Value;
        _output.WriteLine($"CEILING comp={compTok} lean={leanTok}");
        Assert.Equal(compTok, leanTok);
        Assert.True(compTok <= ceilings["tools/list:comprehensive"], $"standard tools/list grew past ceiling: {compTok}");
    }

    /// <summary>
    /// TOKEN RATCHET (t2nt guardrail): re-measures the full 20-call session
    /// over the real wire stack against the same seeds and asserts every
    /// observed total stays at or under its committed-mirror ceiling (no
    /// artifact writes; the baseline Fact above owns regeneration). Any
    /// future payload growth fails here even when it stays inside the ±15%
    /// bands. Band asserts run alongside as the two-sided drift detector.
    /// </summary>
    [Fact]
    public async Task PerTool_TokenCeiling_OverWire()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedRealisticBackend(harness);

        foreach (var (name, arguments) in BaselineCases())
        {
            var requestJson = JsonSerializer.Serialize(new { name, arguments });
            var text = TextOf(await harness.CallToolOverWireAsync(name, arguments));
            var total = Tok(requestJson) + Tok(text);
            _output.WriteLine($"  CEILING {name,-24} total={total,5:N0}tok (cap {MirrorCeilingsLazy.Value[name],5:N0})");
            AssertBand(name, total);
            AssertCeiling(name, total);
        }

        using var comp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var lean = new LocalMcpServer(new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        var compTok = Tok(comp.ListTools().ToJsonString());
        var leanTok = Tok(lean.ListTools().ToJsonString());
        AssertBand("tools/list:comprehensive", compTok);
        Assert.Equal(compTok, leanTok);
        AssertCeiling("tools/list:comprehensive", compTok);

        using var wireDoc = await harness.PostRpcAsync("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        var wireSchemaJson = wireDoc.RootElement.GetProperty("result").GetProperty("tools").GetRawText();
        var wireTok = Tok(wireSchemaJson);
        AssertBand("tools/list:wire", wireTok);
        AssertCeiling("tools/list:wire", wireTok);
    }

    /// <summary>
    /// TOKEN RATCHET mirror pin (no harness, docs/ only): the committed
    /// mirror carries the pinned tool order, the seed fingerprint matches
    /// (seeds unchanged), and every mirrored total sits inside its
    /// tolerance band. Self-sufficient on a fresh clone (no artifacts/
    /// needed): the ceilings ARE the mirror, so this Fact pins shape and
    /// drift, while the wire Facts above pin growth against it.
    /// </summary>
    [Fact]
    public void TokenBaseline_Mirror_Matches_Pins()
    {
        var mirrorPath = Path.Combine(RepoRoot(), "docs", "reverse-speedup", "benchmarks", "token-baseline.json");
        Assert.True(File.Exists(mirrorPath), $"Baseline mirror is missing: {mirrorPath}");
        var mirrorText = File.ReadAllText(mirrorPath);

        using var document = JsonDocument.Parse(mirrorText);
        var root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("token-baseline", root.GetProperty("tool").GetString());
        Assert.Equal(MockFingerprint(), root.GetProperty("mockFingerprint").GetString());
        var tools = root.GetProperty("tools").EnumerateArray().ToArray();
        Assert.Equal(BaselineCases().Length, tools.Length);
        for (var index = 0; index < tools.Length; index++)
        {
            var name = tools[index].GetProperty("name").GetString()!;
            Assert.Equal(BaselineCases()[index].Name, name);
            AssertBand(name, tools[index].GetProperty("totalTokens").GetInt32());
        }
        var schema = root.GetProperty("schema");
        AssertBand("tools/list:comprehensive", schema.GetProperty("comprehensive").GetProperty("tokens").GetInt32());
        Assert.Equal(
            schema.GetProperty("comprehensive").GetProperty("tokens").GetInt32(),
            schema.GetProperty("lean").GetProperty("tokens").GetInt32());
        AssertBand("tools/list:wire", schema.GetProperty("wire").GetProperty("tokens").GetInt32());
        _output.WriteLine($"MIRROR session={root.GetProperty("totals").GetProperty("totalTokens").GetInt32():N0}tok fingerprint={root.GetProperty("mockFingerprint").GetString()}");
    }

    /// <summary>
    /// Additive opt-in scenario (plan §4 item 3): Triage kind=imports/strings
    /// compact=true over the wire. Flag-off responses are byte-identical to
    /// the baseline shape (constraint #2 regression); flag-on responses carry
    /// legends with integer row codes. Token savings are asserted at bulk
    /// scale (P2-4 pays at top=16+ with repeated strings; at baseline scale
    /// the legend overhead dominates, so only shape is pinned there).
    /// </summary>
    [Fact]
    public async Task Triage_Compact_TokenDelta()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedRealisticBackend(harness);

        // Baseline scale: byte-identity + shape pins (no token direction:
        // the legend costs more than a dozen coded rows save).
        var offOmitted = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "imports", top = 16 }));
        var offFalse = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "imports", top = 16, compact = false }));
        Assert.Equal(offOmitted, offFalse);
        Assert.Contains("KERNEL32.dll", offOmitted);
        var on = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "imports", top = 16, compact = true }));
        Assert.Contains("libraryLegend", on);
        Assert.Contains("categoryLegend", on);
        Assert.Contains("KERNEL32.dll", on); // legend keeps the full strings once
        using (var doc = JsonDocument.Parse(on))
        {
            var result = doc.RootElement.TryGetProperty("result", out var r) ? r : doc.RootElement;
            Assert.True(result.GetProperty("libraryLegend").GetArrayLength() > 0);
            Assert.True(result.GetProperty("categoryLegend").GetArrayLength() > 0);
            foreach (var row in result.GetProperty("imports").EnumerateArray())
            {
                Assert.Equal(JsonValueKind.Number, row.GetProperty("library").ValueKind);
                foreach (var category in row.GetProperty("categories").EnumerateArray())
                    Assert.Equal(JsonValueKind.Number, category.ValueKind);
            }
        }
        _output.WriteLine($"TRIAGE-IMPORTS baseline off={Tok(offOmitted):N0}tok on={Tok(on):N0}tok");

        var stringsOff = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "strings", section = ".rdata", maxItems = 64 }));
        var stringsOffFalse = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "strings", section = ".rdata", maxItems = 64, compact = false }));
        Assert.Equal(stringsOff, stringsOffFalse);
        var stringsOn = TextOf(await harness.CallToolOverWireAsync("Triage", new { kind = "strings", section = ".rdata", maxItems = 64, compact = true }));
        Assert.Contains("typeLegend", stringsOn);
        using (var doc = JsonDocument.Parse(stringsOn))
        {
            var result = doc.RootElement.TryGetProperty("result", out var r) ? r : doc.RootElement;
            Assert.True(result.GetProperty("typeLegend").GetArrayLength() > 0);
            foreach (var row in result.GetProperty("iocs").EnumerateArray())
                Assert.Equal(JsonValueKind.Number, row.GetProperty("type").ValueKind);
        }
        _output.WriteLine($"TRIAGE-STRINGS baseline off={Tok(stringsOff):N0}tok on={Tok(stringsOn):N0}tok");

        // Bulk scale: repeated library/category/type strings amortize the
        // legends, so compact must cost strictly fewer tokens. A FRESH
        // harness per bulk corpus: GhidraClient caches ListImports (1.5s) and
        // DumpStrings (300s) keyed by exact bridge args, so re-registering a
        // mock mid-session would serve stale rows for identical args.
        await using var bulk = await RealServerHarness.StartAsync();
        var libraries = new[] { "KERNEL32.dll", "WS2_32.dll", "ADVAPI32.dll", "WININET.dll" };
        var names = new[] { "CreateRemoteThread", "socket", "RegSetValueExW", "InternetOpenW", "WriteProcessMemory", "connect" };
        var bulkImports = Enumerable.Range(0, 120).Select(i => (object)new
        {
            name = names[i % names.Length] + "_" + i,
            library = libraries[i % libraries.Length],
            address = $"EXTERNAL:{(i + 1):D8}",
            refCount = i % 8,
        }).ToArray();
        bulk.Ghidra.RegisterTcpHandler("ListImports", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { imports = bulkImports, truncated = false } }));
        // Explicit budget: this block measures compact's savings at bulk
        // scale, not the compact default ceiling.
        var bulkOff = TextOf(await bulk.CallToolOverWireAsync("Triage", new { kind = "imports", top = 64, maxItems = 256, maxChars = 30_000 }));
        var bulkOn = TextOf(await bulk.CallToolOverWireAsync("Triage", new { kind = "imports", top = 64, maxItems = 256, maxChars = 30_000, compact = true }));
        using (var dbg = JsonDocument.Parse(bulkOff))
        {
            var r = dbg.RootElement.TryGetProperty("result", out var rr) ? rr : dbg.RootElement;
            _output.WriteLine($"TRIAGE-IMPORTS bulk rows={r.GetProperty("imports").GetArrayLength()} sus={r.GetProperty("suspiciousCount").GetInt32()}");
            Assert.True(r.GetProperty("imports").GetArrayLength() >= 32);
        }
        var bulkOffTotal = Tok(JsonSerializer.Serialize(new { name = "Triage", arguments = new { kind = "imports", top = 64, maxItems = 256, maxChars = 30_000 } })) + Tok(bulkOff);
        var bulkOnTotal = Tok(JsonSerializer.Serialize(new { name = "Triage", arguments = new { kind = "imports", top = 64, maxItems = 256, maxChars = 30_000, compact = true } })) + Tok(bulkOn);
        _output.WriteLine($"TRIAGE-IMPORTS bulk off={bulkOffTotal:N0}tok on={bulkOnTotal:N0}tok saved={100.0 * (bulkOffTotal - bulkOnTotal) / bulkOffTotal:F1}%");
        Assert.True(bulkOnTotal < bulkOffTotal, $"compact saved nothing at bulk scale: off={bulkOffTotal} on={bulkOnTotal}");

        var bulkStrings = Enumerable.Range(0, 200).Select(i => (object)new
        {
            address = $"0x140003{i:X4}",
            value = (i % 6) switch
            {
                0 => $"http://10.0.0.{(i % 250) + 1}:8080/update{i}",
                1 => $"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Entry{i}",
                2 => "IsDebuggerPresent",
                3 => $"192.168.{i % 256}.{(i * 7 + 11) % 256}",
                4 => $"powershell -enc PAYLOAD{i}",
                _ => $"AES session key number {i}",
            },
            length = 20 + i % 40,
        }).ToArray();
        bulk.Ghidra.RegisterTcpHandler("DumpStrings", (id, _) =>
            JsonSerializer.Serialize(new { id, ok = true, result = new { strings = bulkStrings, truncated = false } }));
        var bulkStringsOff = TextOf(await bulk.CallToolOverWireAsync("Triage", new { kind = "strings", section = ".rdata", maxItems = 512 }));
        var bulkStringsOn = TextOf(await bulk.CallToolOverWireAsync("Triage", new { kind = "strings", section = ".rdata", maxItems = 512, compact = true }));
        var bulkStringsOffTotal = Tok(JsonSerializer.Serialize(new { name = "Triage", arguments = new { kind = "strings", section = ".rdata", maxItems = 512 } })) + Tok(bulkStringsOff);
        var bulkStringsOnTotal = Tok(JsonSerializer.Serialize(new { name = "Triage", arguments = new { kind = "strings", section = ".rdata", maxItems = 512, compact = true } })) + Tok(bulkStringsOn);
        _output.WriteLine($"TRIAGE-STRINGS bulk off={bulkStringsOffTotal:N0}tok on={bulkStringsOnTotal:N0}tok saved={100.0 * (bulkStringsOffTotal - bulkStringsOnTotal) / bulkStringsOffTotal:F1}%");
        Assert.True(bulkStringsOnTotal < bulkStringsOffTotal, $"compact saved nothing at bulk scale: off={bulkStringsOffTotal} on={bulkStringsOnTotal}");

        // Unit edge: empty rows still get (empty) legends; never throws.
        var empty = new JsonObject { ["imports"] = new JsonArray() };
        TriageImportsTools.ApplyImportsCompact(empty);
        Assert.Empty(empty["libraryLegend"]!.AsArray());
        Assert.Empty(empty["categoryLegend"]!.AsArray());
    }

    /// <summary>
    /// Telemetry diet shape pin: GetServerStatus drops the redundant lifetime
    /// node (per-process totals live in "total"), telemetry uptimeSeconds
    /// and topSlowest avgMs while keeping the pinned updated clock, p95/max
    /// and counts.
    /// </summary>
    [Fact]
    public async Task GetServerStatus_TelemetryDiet()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedRealisticBackend(harness);
        _ = TextOf(await harness.CallToolOverWireAsync("GetServerStatus", new { }));
        var text = TextOf(await harness.CallToolOverWireAsync("GetServerStatus", new { }));
        using var document = JsonDocument.Parse(text);
        var telemetry = document.RootElement.GetProperty("telemetry");
        Assert.True(telemetry.TryGetProperty("updated", out _));
        Assert.False(telemetry.TryGetProperty("uptimeSeconds", out _));
        Assert.False(telemetry.TryGetProperty("lifetime", out _));
        Assert.True(telemetry.TryGetProperty("total", out _));
        var slowest = telemetry.GetProperty("topSlowest").EnumerateArray().ToArray();
        Assert.NotEmpty(slowest);
        foreach (var row in slowest)
        {
            Assert.False(row.TryGetProperty("avgMs", out _));
            Assert.True(row.TryGetProperty("tool", out _));
            Assert.True(row.TryGetProperty("calls", out _));
            Assert.True(row.TryGetProperty("p95Ms", out _));
            Assert.True(row.TryGetProperty("maxMs", out _));
        }
        _output.WriteLine($"TELEMETRY-DIET chars={text.Length:N0} tok~{Tok(text):N0}");
    }

    /// <summary>
    /// Additive opt-in scenario: WriteMemory drops the bytesHex request echo
    /// by default (old/fat natives) and restores it only with echoBytes=true.
    /// nextAddress stays (small, pinned by Live15).
    /// </summary>
    [Fact]
    public async Task WriteMemory_SlimAck_TokenDelta()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var fatHex = string.Concat(Enumerable.Repeat("90 ", 64)).Trim();
        harness.NativePipeServer.RegisterHandler("WriteMemory", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    action = "writeMemory",
                    address = "0x140001000",
                    bytesWritten = 64,
                    bytesHex = fatHex,
                    nextAddress = "0x140001040",
                },
            }));

        var slim = TextOf(await harness.CallToolOverWireAsync("WriteMemory", new { address = "0x140001000", hexBytes = fatHex }));
        Assert.Contains("bytesWritten", slim);
        Assert.Contains("nextAddress", slim);
        Assert.DoesNotContain("bytesHex", slim);
        Assert.DoesNotContain(fatHex, slim);

        var echo = TextOf(await harness.CallToolOverWireAsync("WriteMemory", new { address = "0x140001000", hexBytes = fatHex, echoBytes = true }));
        Assert.Contains("bytesHex", echo);
        Assert.Contains(fatHex, echo);

        _output.WriteLine($"WRITEMEMORY slim={slim.Length:N0}B/{Tok(slim):N0}tok echo={echo.Length:N0}B/{Tok(echo):N0}tok");
        Assert.True(Tok(slim) < Tok(echo), "slim ack saved nothing over the echo");

        // Unit edges: errors, slim acks and garbage pass through untouched.
        Assert.Equal("not-json", LiveAnalysisTools.SlimWriteMemoryAck("not-json", false));
        const string error = "{\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"bytesHex boom\"}}";
        Assert.Equal(error, LiveAnalysisTools.SlimWriteMemoryAck(error, false));
    }
}

