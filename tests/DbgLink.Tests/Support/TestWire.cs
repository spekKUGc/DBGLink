using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Shared wire-test helpers: the copy-pasted TextOf / Tok / RepoRoot / Call
// / Args helpers that used to live privately in ~15 test classes.
//
// Two unwrap flavors are kept because call sites disagree on purpose:
//   - TextOf: strict — asserts the tool did NOT return isError (the dominant
//     copy in the baseline/queue/brief suites).
//   - RawText: lenient — unwraps the single text block with no isError pin
//     (the debugger-control/batch/merge suites assert error-ness themselves
//     and also unwrap error results, so the strict pin would break them).
// Do NOT "unify" these two: upgrading a lenient call site to the strict pin
// changes its assertions. New tests should prefer TextOf and use RawText
// only when they unwrap an expected error result.
// ErrorTextOf asserts isError and unwraps (ToolExecutionTests pattern).
// Tok delegates to TokenCounter (single source for cl100k_base counts).
// RepoRoot prefers the nearest .git marker with the artifacts/fixtures
// fallback so artifact paths work in worktrees and clean checkouts.
// Call builds a CallToolRequestParams from a JSON object string
// (BatchCore/BatchToolsHostile/DebuggerAutoPause pattern).
// Args parses the same JSON into the Dictionary form LocalMcpServer
// CallToolAsync takes (LiveDebuggerControl/ListLiveFunctions/ToolMerge pattern).

internal static class TestWire
{
    internal static string TextOf(CallToolResult result)
    {
        Assert.False(result.IsError == true, $"Tool error: {JsonSerializer.Serialize(result)}");
        return Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
    }

    internal static string RawText(CallToolResult result)
        => Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

    internal static string ErrorTextOf(CallToolResult result)
    {
        Assert.True(result.IsError);
        return Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
    }

    internal static int Tok(string? s) => TokenCounter.Count(s);

    internal static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? fixtureFallback = null;
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, ".git")) || Directory.Exists(Path.Combine(dir.FullName, ".git")))
                return dir.FullName;
            fixtureFallback ??= Directory.Exists(Path.Combine(dir.FullName, "artifacts", "fixtures"))
                ? dir.FullName
                : null;
            dir = dir.Parent;
        }
        return fixtureFallback
            ?? throw new DirectoryNotFoundException("Repository root (.git or artifacts/fixtures) was not found above the test binary.");
    }

    internal static CallToolRequestParams Call(string name, string argsJson)
    {
        using var document = JsonDocument.Parse(argsJson);
        var arguments = new Dictionary<string, JsonElement>();
        foreach (var property in document.RootElement.EnumerateObject())
            arguments[property.Name] = property.Value.Clone();
        return new CallToolRequestParams { Name = name, Arguments = arguments };
    }

    internal static Dictionary<string, JsonElement> Args(string json)
        => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
}

// Shared fixture-seed builders: the Ghidra-shaped C listing both the token
// baseline and the reverse-cost benchmark seed their mocks with. Moved here
// verbatim so the two suites cannot drift (a drift used to produce a false
// token signal). MockFingerprint stays per-suite: the two probes hash
// different envelopes (token baseline hashes decomp+imports+strings, the
// reverse-cost harness hashes serialized inspect results), so unifying the
// fingerprint would change pinned values.

internal static class FixtureSeeds
{
    internal static string BuildDecompilation(string name, params string[] core)
    {
        var sb = new StringBuilder(2048);
        void Line(string text) => sb.Append(text).Append('\n');
        Line($"undefined8 {name}(int param_1)");
        Line("");
        Line("{");
        Line("  byte bVar1;");
        Line("  int iVar2;");
        Line("  int iVar3;");
        Line("  uint uVar4;");
        Line("  longlong lVar5;");
        Line("  longlong lVar6;");
        Line("  undefined8 uVar7;");
        Line("  undefined8 *puVar8;");
        Line("  undefined8 local_res8 [4];");
        Line("  undefined1 local_res28;");
        Line("");
        Line("  lVar5 = __security_cookie;");
        Line("  local_res8[0] = 0;");
        Line("  local_res8[1] = 0;");
        Line("  iVar2 = 0;");
        Line("  uVar4 = (uint)param_1;");
        Line("  puVar8 = (undefined8 *)&FixtureUnicodePointer;");
        Line("  if (param_1 == 0) {");
        Line("    return 0;");
        Line("  }");
        Line("  iVar3 = param_1;");
        Line("  do {");
        Line("    bVar1 = *(byte *)((longlong)puVar8 + (longlong)(int)uVar4);");
        Line("    uVar4 = uVar4 & 1;");
        foreach (var text in core)
            Line("    " + text);
        Line("    iVar2 = iVar2 + (int)uVar7 + (int)(uint)bVar1;");
        Line("    iVar3 = iVar3 + -1;");
        Line("  } while (0 < iVar3);");
        Line("  lVar6 = __security_cookie;");
        Line("  if (lVar5 != lVar6) {");
        Line("    /* WARNING: Subroutine does not return */");
        Line("    __security_check_cookie(lVar5 ^ lVar6);");
        Line("  }");
        Line("  local_res28 = 0;");
        Line("  return CONCAT44((int)((ulonglong)local_res8[0] >> 0x20), iVar2);");
        Line("}");
        return sb.ToString();
    }

    internal static string Sha256Hex(string probe)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(probe))).ToLowerInvariant();
}
