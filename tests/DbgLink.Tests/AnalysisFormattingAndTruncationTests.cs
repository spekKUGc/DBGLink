using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

public sealed class AnalysisFormattingAndTruncationTests
{
    // ========================================================================================
    // GROUP 1: SYSTEM MODULE IDENTIFICATION (25 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("ntdll.dll", null, true)]
    [InlineData("kernel32.dll", null, true)]
    [InlineData("KERNEL32.DLL", null, true)]
    [InlineData("kernelbase.dll", null, true)]
    [InlineData("user32.dll", null, true)]
    [InlineData("gdi32.dll", null, true)]
    [InlineData("rpcrt4.dll", null, true)]
    [InlineData("msvcrt.dll", null, true)]
    [InlineData("ucrtbase.dll", null, true)]
    [InlineData("comctl32.dll", null, true)]
    [InlineData("ole32.dll", null, true)]
    [InlineData("shell32.dll", null, true)]
    [InlineData("shlwapi.dll", null, true)]
    [InlineData("ws2_32.dll", null, true)]
    [InlineData("advapi32.dll", null, true)]
    [InlineData("api-ms-win-core-file-l1-1-0.dll", null, true)]
    [InlineData("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL", null, true)]
    [InlineData("ext-ms-win-gdi-draw-l1-1-0.dll", null, true)]
    [InlineData("system_library_mock.dll", null, true)]
    [InlineData("custom.dll", "C:\\Windows\\System32\\custom.dll", true)]
    [InlineData("driver.dll", "C:\\windows\\syswow64\\driver.dll", true)]
    [InlineData("sidebyside.dll", "C:\\Windows\\WinSxS\\x86_test\\sidebyside.dll", true)]
    [InlineData("app.exe", "C:\\Program Files\\App\\app.exe", false)]
    [InlineData("target.dll", "C:\\payloads\\target.dll", false)]
    [InlineData("mygame.exe", null, false)]
    public void IsSystemModule_CorrectlyClassifiesModules(string? name, string? path, bool expectedSystem)
    {
        var isSystem = AnalysisFormatting.IsSystemModule(name, path);
        Assert.Equal(expectedSystem, isSystem);
    }

    [Fact]
    public void IsSystemModule_NullOrEmptyInputs_ReturnsFalse()
    {
        Assert.False(AnalysisFormatting.IsSystemModule(null, null));
        Assert.False(AnalysisFormatting.IsSystemModule("", ""));
        Assert.False(AnalysisFormatting.IsSystemModule(null, ""));
    }

    // ========================================================================================
    // GROUP 2: SYSTEM MODULE OR CALLSTACK FRAME IDENTIFICATION (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("ntdll.dll!RtlUserThreadStart + 0x21", true)]
    [InlineData("kernel32.dll!BaseThreadInitThunk + 0x14", true)]
    [InlineData("KERNEL32.DLL!CreateFileW", true)]
    [InlineData("C:\\Windows\\System32\\user32.dll + 0x1000", true)]
    [InlineData("system_library_frame_stub", true)]
    [InlineData("msvcrt.dll!printf + 0x30", true)]
    [InlineData("ole32.dll!CoInitializeEx", true)]
    [InlineData("ws2_32.dll!recv", true)]
    [InlineData("shell32.dll!ShellExecuteW", true)]
    [InlineData("app.exe!main + 0x45", false)]
    [InlineData("crackme.dll!sub_401230", false)]
    [InlineData("0x00007FF712341000", false)]
    [InlineData("payload.bin!entry", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsSystemModuleOrFrame_ClassifiesCallstackFrames(string? frame, bool expectedSystem)
    {
        var isSystem = AnalysisFormatting.IsSystemModuleOrFrame(frame!);
        Assert.Equal(expectedSystem, isSystem);
    }

    // ========================================================================================
    // GROUP 3: ROBUST JSON NODE READERS (20 Tests)
    // ========================================================================================

    [Fact]
    public void ReadNodeString_ValidString_ReturnsValue()
    {
        var node = new JsonObject { ["name"] = "testValue" };
        Assert.Equal("testValue", AnalysisFormatting.ReadNodeString(node, "name"));
    }

    [Theory]
    [InlineData("{\"number\": 123}", "number")]
    [InlineData("{\"bool\": true}", "bool")]
    [InlineData("{\"arr\": [1,2]}", "arr")]
    [InlineData("{\"obj\": {}}", "obj")]
    [InlineData("{\"nil\": null}", "nil")]
    [InlineData("{}", "missing")]
    public void ReadNodeString_NonStringOrMissing_ReturnsNull(string json, string property)
    {
        var node = JsonNode.Parse(json);
        Assert.Null(AnalysisFormatting.ReadNodeString(node, property));
    }

    [Fact]
    public void ReadNodeInt_ValidInt_ReturnsValue()
    {
        var node = new JsonObject { ["count"] = 42 };
        Assert.Equal(42, AnalysisFormatting.ReadNodeInt(node, "count"));
    }

    [Theory]
    [InlineData("{\"str\": \"abc\"}", "str")]
    [InlineData("{\"bool\": true}", "bool")]
    [InlineData("{\"nil\": null}", "nil")]
    [InlineData("{}", "missing")]
    public void ReadNodeInt_NonIntOrMissing_ReturnsZero(string json, string property)
    {
        var node = JsonNode.Parse(json);
        Assert.Equal(0, AnalysisFormatting.ReadNodeInt(node, property));
    }

    [Fact]
    public void ReadNodeBool_ValidBool_ReturnsValue()
    {
        var node = new JsonObject { ["flag"] = true, ["disabled"] = false };
        Assert.True(AnalysisFormatting.ReadNodeBool(node, "flag"));
        Assert.False(AnalysisFormatting.ReadNodeBool(node, "disabled"));
    }

    [Theory]
    [InlineData("{\"str\": \"true\"}", "str")]
    [InlineData("{\"int\": 1}", "int")]
    [InlineData("{\"nil\": null}", "nil")]
    [InlineData("{}", "missing")]
    public void ReadNodeBool_NonBoolOrMissing_ReturnsFalse(string json, string property)
    {
        var node = JsonNode.Parse(json);
        Assert.False(AnalysisFormatting.ReadNodeBool(node, property));
    }

    [Fact]
    public void ReadNestedNodeInt_ValidHierarchy_ReturnsValue()
    {
        var node = new JsonObject
        {
            ["summary"] = new JsonObject { ["items"] = 99 }
        };
        Assert.Equal(99, AnalysisFormatting.ReadNestedNodeInt(node, "summary", "items"));
        Assert.Equal(0, AnalysisFormatting.ReadNestedNodeInt(node, "summary", "missing"));
        Assert.Equal(0, AnalysisFormatting.ReadNestedNodeInt(node, "missingParent", "items"));
    }

    // ========================================================================================
    // GROUP 4: ADDBOUNDEDSECTION BUDGET ACCOUNTING (15 Tests)
    // ========================================================================================

    [Fact]
    public void AddBoundedSection_ValueFits_SectionAddedWithoutTruncation()
    {
        var sections = new JsonObject();
        var remainingChars = 1000;
        var truncated = false;
        var payload = new JsonObject { ["status"] = "ok", ["code"] = 200 };

        AnalysisFormatting.AddBoundedSection(sections, "details", payload, ref remainingChars, ref truncated);

        Assert.NotNull(sections["details"]);
        Assert.Equal("ok", sections["details"]!["status"]!.GetValue<string>());
        Assert.False(truncated);
        Assert.True(remainingChars < 1000);
    }

    [Fact]
    public void AddBoundedSection_ValueExceedsBudget_SectionOmittedAndTruncatedSet()
    {
        var sections = new JsonObject();
        var remainingChars = 100;
        var truncated = false;
        var largePayload = new JsonObject
        {
            ["data"] = new string('A', 500)
        };

        AnalysisFormatting.AddBoundedSection(sections, "large", largePayload, ref remainingChars, ref truncated);

        Assert.True(truncated);
        var omitted = sections["large"] as JsonObject;
        Assert.NotNull(omitted);
        Assert.True(omitted["omitted"]!.GetValue<bool>());
        Assert.Equal("response_budget", omitted["reason"]!.GetValue<string>());
    }

    [Fact]
    public void AddBoundedSection_NullValue_LeavesSectionsAndBudgetUnchanged()
    {
        var sections = new JsonObject();
        var remainingChars = 500;
        var truncated = false;

        AnalysisFormatting.AddBoundedSection(sections, "missing", null, ref remainingChars, ref truncated);

        Assert.Null(sections["missing"]);
        Assert.Equal(500, remainingChars);
        Assert.False(truncated);
    }

    [Theory]
    [InlineData(100, 10)] // section 1 fits, section 2 might not
    [InlineData(500, 200)]
    [InlineData(2000, 1500)]
    public void AddBoundedSection_SequentialSections_TracksDecreasingBudget(int initialBudget, int payloadLength)
    {
        var sections = new JsonObject();
        var remaining = initialBudget;
        var truncated = false;
        var item1 = new JsonObject { ["val"] = new string('X', payloadLength) };

        AnalysisFormatting.AddBoundedSection(sections, "sec1", item1, ref remaining, ref truncated);

        if (payloadLength + 64 <= initialBudget)
        {
            Assert.False(truncated);
            Assert.Equal(initialBudget - (item1.ToJsonString().Length + 64), remaining);
        }
        else
        {
            Assert.True(truncated);
        }
    }

    // ========================================================================================
    // GROUP 5: LIMITSNAPSHOTTEXT SURROGATE PAIR & TRUNCATION SAFETY (10 Tests)
    // ========================================================================================

    [Fact]
    public void LimitSnapshotText_TextWithinBudget_ReturnsExactText()
    {
        var truncated = false;
        var text = "short string";
        var result = ToolSupport.LimitSnapshotText(text, 50, ref truncated);

        Assert.Equal(text, result);
        Assert.False(truncated);
    }

    [Fact]
    public void LimitSnapshotText_TextExceedingBudget_AppendsTruncationNotice()
    {
        var truncated = false;
        var text = new string('A', 100);
        var result = ToolSupport.LimitSnapshotText(text, 30, ref truncated);

        Assert.True(truncated);
        Assert.EndsWith("\n...[truncated]", result);
        Assert.Equal(30, result.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(10)]
    [InlineData(14)]
    [InlineData(15)]
    public void LimitSnapshotText_BudgetSmallerThanOrEqualSuffix_ReturnsPrefixOfSuffix(int budget)
    {
        var truncated = false;
        var text = "Some longer payload that exceeds very small budget";
        var result = ToolSupport.LimitSnapshotText(text, budget, ref truncated);

        Assert.True(truncated);
        Assert.Equal(budget, result.Length);
        if (budget > 0)
        {
            Assert.Equal("\n...[truncated]"[..budget], result);
        }
    }

    [Fact]
    public void LimitSnapshotText_SurrogatePairAtBoundary_NeverLeavesDanglingSurrogate()
    {
        var truncated = false;
        // Construct string where an emoji is right on the cutoff boundary
        var prefix = new string('A', 16);
        var text = prefix + "😀" + new string('B', 50);
        // Suffix "\n...[truncated]" is 15 chars. If budget = 32, prefixLength = 17.
        // Index 16 is high surrogate, index 17 is low surrogate.
        var result = ToolSupport.LimitSnapshotText(text, 32, ref truncated);

        Assert.True(truncated);
        Assert.DoesNotContain(result, char.IsHighSurrogate);
        Assert.DoesNotContain(result, char.IsLowSurrogate);
        Assert.EndsWith("\n...[truncated]", result);
    }

    [Fact]
    public void LimitSnapshotText_ConsecutiveSurrogates_PreservesWellFormedness()
    {
        var truncated = false;
        var text = "🚀🌟🔥🎉" + new string('Z', 100);
        var result = ToolSupport.LimitSnapshotText(text, 25, ref truncated);

        Assert.True(truncated);
        Assert.True(result.Length <= 25);
        // Verify valid string by UTF-8 encoding without exception
        var bytes = System.Text.Encoding.UTF8.GetBytes(result);
        var decoded = System.Text.Encoding.UTF8.GetString(bytes);
        Assert.Equal(result, decoded);
    }

    // ========================================================================================
    // GROUP 6: ADDCHILDERRORS EXTRACTION & ENRICHMENT (10 Tests)
    // ========================================================================================

    [Fact]
    public void AddChildErrors_NullNodeOrMissingErrors_DoesNotMutateList()
    {
        var errors = new JsonArray();
        AnalysisFormatting.AddChildErrors(errors, "test_sec", null!);
        Assert.Empty(errors);

        AnalysisFormatting.AddChildErrors(errors, "test_sec", new JsonObject());
        Assert.Empty(errors);
    }

    [Theory]
    [InlineData("error_code_1", "detailed failure message")]
    [InlineData("timeout", "bridge response timed out")]
    [InlineData(null, "unspecified error message")]
    public void AddChildErrors_ExtractsStructuredErrors(string? code, string message)
    {
        var errors = new JsonArray();
        var node = new JsonObject
        {
            ["errors"] = new JsonArray
            {
                new JsonObject
                {
                    ["code"] = code,
                    ["message"] = message,
                    ["section"] = "nested_subsystem"
                }
            }
        };

        AnalysisFormatting.AddChildErrors(errors, "main_section", node);

        Assert.Single(errors);
        var errObj = errors[0] as JsonObject;
        Assert.NotNull(errObj);
        Assert.Equal("main_section", errObj["section"]?.GetValue<string>());
        Assert.Equal(code ?? "partial", errObj["code"]?.GetValue<string>());
        Assert.Equal(message, errObj["message"]?.GetValue<string>());
        Assert.Equal("nested_subsystem", errObj["sourceSection"]?.GetValue<string>());
    }

    [Fact]
    public void AddChildErrors_PrimitiveOrNonObjectErrorItem_AddsFallbackError()
    {
        var errors = new JsonArray();
        var node = new JsonObject
        {
            ["errors"] = new JsonArray { "some string error", 404 }
        };

        AnalysisFormatting.AddChildErrors(errors, "parent_sec", node);

        Assert.Equal(2, errors.Count);
        var errObj = errors[0] as JsonObject;
        Assert.NotNull(errObj);
        Assert.Equal("parent_sec", errObj["section"]?.GetValue<string>());
        Assert.Equal("partial", errObj["code"]?.GetValue<string>());
        Assert.Equal("The nested route returned an unspecified error.", errObj["message"]?.GetValue<string>());
    }

    [Fact]
    public void AddChildErrors_LongMessage_TruncatesTo1024()
    {
        var errors = new JsonArray();
        var longMsg = new string('E', 2000);
        var node = new JsonObject
        {
            ["errors"] = new JsonArray
            {
                new JsonObject { ["code"] = "overflow", ["message"] = longMsg }
            }
        };

        AnalysisFormatting.AddChildErrors(errors, "sec", node);

        Assert.Single(errors);
        var msg = (errors[0] as JsonObject)!["message"]?.GetValue<string>();
        Assert.NotNull(msg);
        Assert.True(msg.Length <= 1024);
        Assert.EndsWith("\n...[truncated]", msg);
    }

    [Fact]
    public void FoldCallStackNode_MalformedCollapsedFlag_DoesNotThrow()
    {
        var callStack = JsonNode.Parse("""
            {"frames":[
              {"collapsed":"false","name":"first"},
              {"name":"second"},
              {"name":"third"}
            ]}
            """)!;

        var result = Record.Exception(() => AnalysisFormatting.FoldCallStackNode(callStack));

        Assert.Null(result);
    }

    // ========================================================================================
    // GROUP 7: CALL-STACK TEXT/FRAMES FOLDING (moved from ServerRound2Tests:
    // the folding contract lives with its owner AnalysisFormatting here)
    // ========================================================================================

    [Fact]
    public void CallStack_TextFolding_CollapsesSystemFrames()
    {
        var text = "Frame 0: main+0x10 [test.exe]\nFrame 1: foo [ntdll.dll]\nFrame 2: bar [kernel32.dll]\nFrame 3: baz [test.exe]";
        var folded = AnalysisFormatting.FoldCallStackNode(JsonValue.Create(text));
        var result = Assert.IsAssignableFrom<JsonValue>(folded);
        var collapsed = result.GetValue<string>();
        Assert.Contains("(+2 system frames collapsed", collapsed);
        Assert.Contains("ntdll", collapsed, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Frame 0:", collapsed);
        Assert.Contains("Frame 3:", collapsed);
        Assert.DoesNotContain("Frame 1:", collapsed);
        Assert.DoesNotContain("Frame 2:", collapsed);
    }

    [Fact]
    public void CallStack_TopFrame_IsAlwaysPreserved_EvenWhenSystem()
    {
        // The i > 0 guard keeps frame 0 verbatim: a system dll on top is
        // never folded away, only frames below it collapse.
        var text = "Frame 0: foo [ntdll.dll]\nFrame 1: bar [kernel32.dll]\nFrame 2: baz [test.exe]";
        var folded = AnalysisFormatting.FoldCallStackNode(JsonValue.Create(text));
        var collapsed = Assert.IsAssignableFrom<JsonValue>(folded).GetValue<string>();
        Assert.Contains("Frame 0: foo [ntdll.dll]", collapsed);
        Assert.Contains("Frame 2: baz [test.exe]", collapsed);
        Assert.Contains("(+1 system frames collapsed", collapsed);
        Assert.DoesNotContain("Frame 1:", collapsed);
    }

    [Fact]
    public void CallStack_ShortText_PassesThrough()
    {
        Assert.Null(AnalysisFormatting.FoldCallStackNode(null));
        var two = JsonValue.Create("Frame 0: a\nFrame 1: b");
        Assert.Equal("Frame 0: a\nFrame 1: b", Assert.IsAssignableFrom<JsonValue>(AnalysisFormatting.FoldCallStackNode(two)).GetValue<string>());
    }

    [Fact]
    public void CallStack_FramesArray_CollapsesSystemFrames()
    {
        var node = JsonNode.Parse("{\"frames\": [{\"m\":\"main\"}, {\"m\":\"x ntdll.dll y\"}, {\"m\":\"z kernel32.dll w\"}, {\"m\":\"tail\"}]}");
        var folded = Assert.IsType<JsonObject>(AnalysisFormatting.FoldCallStackNode(node));
        var frames = Assert.IsType<JsonArray>(folded["frames"]);
        // Two consecutive system frames collapse into exactly one marker
        // node: 4 frames -> main + collapsed + tail.
        Assert.Equal(3, frames.Count);
        var collapsed = Assert.IsType<JsonObject>(frames[1]);
        Assert.True(collapsed["collapsed"]!.GetValue<bool>());
        Assert.Equal(2, collapsed["count"]!.GetValue<int>());
        Assert.Contains("ntdll", collapsed["libraries"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
    }
}
