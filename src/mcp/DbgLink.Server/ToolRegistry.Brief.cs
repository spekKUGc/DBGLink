using System.Text.Json;
using System.Text.Json.Nodes;
namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterBriefTools(InvestigationTools investigation)
    {
        Register(new JsonObject
        {
            ["name"] = "GetInvestigationBrief",
            ["description"] = "Inspect up to 4 functions (function XOR functions) with live state and mapped addresses.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["function"] = NonBlankText("Ghidra function address, RVA, or name.", 256),
                    ["functions"] = new JsonObject
                    {
                        ["type"] = "array",
                        ["minItems"] = 1,
                        ["maxItems"] = 4,
                        ["items"] = NonBlankText("Ghidra function address, RVA, or name.", 256),
                        ["description"] = "Up to 4 selectors for one shared-budget brief."
                    },
                    ["maxChars"] = IntRule(16000, 4000, 60000),
                    ["maxTokens"] = IntRule(0, 0, 30000, "Token cap (4 chars/token); 0=off; min 500."),
                    ["maxItems"] = IntRule(16, 1, 64),
                    ["maxFrames"] = IntRule(8, 1, 32),
                    ["verifyHash"] = BoolRule(true),
                    ["includeLive"] = BoolRule(true),
                    ["includeThreads"] = BoolRule(false),
                    ["includeModules"] = BoolRule(false),
                    ["includeDecomp"] = BoolRule(false),
                    ["includeDisassembly"] = BoolRule(false),
                    ["includeReferences"] = BoolRule(true),
                    ["includeSymbols"] = BoolRule(false),
                    ["includeStrings"] = BoolRule(true,
                        "Body-referenced strings (address, value)."),
                    ["includeConstants"] = BoolRule(false,
                        "Scalar operands (value, count, firstAddress)."),
                    ["includeLiveBytes"] = BoolRule(false,
                        "Up to 32 live bytes per function."),
                    ["includeLiveDetail"] = BoolRule(false,
                        "Full live snapshot clone; default is the slim correlation view.")
                },
                ["examples"] = new JsonArray(new JsonObject { ["function"] = "main" }),
                ["additionalProperties"] = false
            }
        },
            call => investigation.GetInvestigationBriefAsync(call.Arguments, call.CancellationToken), ToolCapability.ReadOnly, requiresControl: false, lean: true);
    }
}
