using System.Runtime.Versioning;
using System.Text.Json;
using static DbgLink.Tests.FixtureSeeds;

namespace DbgLink.Tests;

/// <summary>
/// Shared PRE/recipe seeds for the semi-auto benchmarks: the same three
/// fixture functions, annotations, staged eval queue and mock fingerprint,
/// so the recipe scenario can never silently diverge from the PRE baseline
/// it claims to beat. The Ghidra InspectFunction mock carries a module
/// identity plus per-selector entry/rva: GetInvestigationBrief resolves
/// static identity through TryReadStaticFunction, which requires them.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SemiAutoSeeds
{
    internal sealed record FixtureProbe(string Name, string Entry, string Rva, string Arg, string Expected, string Eval);

    internal static readonly FixtureProbe[] FixtureProbes =
    [
        new("FixtureCallee", "0x140001040", "0x1040", "0x5", "22", "22"),
        new("FixtureCaller", "0x140001000", "0x1000", "0x0", "0", "0"),
        new("FixtureImportedPid", "0x140001080", "0x1080", "", "1234", "1234"),
    ];

    internal static readonly (string Name, string Renamed, string Comment)[] FixtureAnnotations =
    [
        ("FixtureCallee", "fixture_callee", "Proves input handling, returns doubled input."),
        ("FixtureCaller", "fixture_caller", "Calls FixtureCallee and reads a global pointer."),
        ("FixtureImportedPid", "fixture_pid", "Imported pid helper."),
    ];

    internal static string MockFingerprint()
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(
            "semi-auto-v2|brief3-probebatch3-annotate6|eval-queue-22-0-1234|waitMs-600|module-path"));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    internal sealed record CallStat(string Tool, string Function, int RequestChars, int ResponseChars, int Tokens, long WallMs);

    internal static void SeedGhidra(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var function = args?.TryGetProperty("function", out var selector) == true &&
                selector.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(selector.GetString())
                ? selector.GetString()!
                : "FixtureCaller";
            var probe = FixtureProbes.FirstOrDefault(entry => entry.Name == function) ?? FixtureProbes[1];
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = function,
                        entry = probe.Entry,
                        rva = probe.Rva,
                        module = new { path = "C:\\fixture\\AnalysisTarget.exe", sha256 = "abc123" },
                    },
                    decompilation = BuildDecompilation(function, "return 0;"),
                    references = new
                    {
                        callers = new[] { new { function = "main", from = "0x1400010A0", type = "CALL" } },
                        callees = Array.Empty<object>(),
                    },
                },
            });
        });
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
                result = new { success = true, applied = results.Count, failed = 0, results },
            });
        });
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
                        new { name = "connect", library = "ws2_32.dll", address = "EXTERNAL:2", refCount = 5 },
                    },
                    exports = new[] { new { name = "DllMain", address = "0x140001000" } },
                    importsTruncated = false,
                    exportsTruncated = false,
                    truncated = false,
                }
            }));
    }

    internal static void SeedNative(RealServerHarness harness, Queue<string> evalValues)
    {
        harness.NativePipeServer.RegisterHandler("GetSnapshotState", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    debuggerPid = 123,
                    generation = "1",
                    debugging = true,
                    running = false,
                    threadId = 1,
                    stableRead = true,
                    returnValue = new { valueHex = "0x0", valueUnsigned = "0", valueSigned = "0" },
                },
            }));
        harness.NativePipeServer.RegisterHandler("EvaluateExpression", (id, _) =>
        {
            var value = evalValues.Count > 0 ? evalValues.Dequeue() : "0";
            var parsed = long.TryParse(value, out var number) ? number : 0;
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    valueHex = $"0x{parsed:X}",
                    valueUnsigned = $"{parsed}",
                    valueSigned = $"{parsed}",
                },
            });
        });
    }

    internal static bool ReadMatched(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        var node = root.TryGetProperty("result", out var result) ? result : root;
        return node.TryGetProperty("matched", out var matched) &&
            matched.ValueKind == JsonValueKind.True;
    }
}
