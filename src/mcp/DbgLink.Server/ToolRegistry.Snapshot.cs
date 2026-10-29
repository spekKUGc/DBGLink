using System.Text.Json;
using System.Text.Json.Nodes;
namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterLiveSnapshotTools(LiveAnalysisTools live)
    {
        Register(new JsonObject
        {
            ["name"] = "GetAnalysisSnapshot",
            ["description"] = "Live snapshot: ~5 instructions at RIP, registers, stack, callstack. Raise instructionBytes (max 2048) for a wider window. diffOnly for polls; bundles Eval+ReadMem.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["maxFrames"] = IntRule(8, 1, 64),
                    ["beforeBytes"] = IntRule(16, 0, 256),
                    ["instructionBytes"] = IntRule(16, 1, 2048),
                    ["stackBytes"] = IntRule(64, 0, 2048),
                    ["maxChars"] = IntRule(16000, 2000, 60000),
                    ["maxTokens"] = IntRule(0, 0, 30000, "Token cap (4 chars/token); 0=off; min 500."),
                    ["includeThreads"] = BoolRule(false),
                    ["includeModules"] = BoolRule(false,
                        "Omits module tables; set true for newly loaded modules."),
                    ["compactModules"] = BoolRule(true,
                        "Folds System32 DLLs into a summary, preserving target binaries."),
                    ["includeModulePaths"] = BoolRule(false,
                        "Keeps per-module path; default strips it to name+base+end."),
                    ["compactStack"] = BoolRule(true,
                        "Folds repetitive OS callstack frames."),
                    ["sparseRegisters"] = BoolRule(true,
                        "Omits zero-valued general registers."),
                    ["diffOnly"] = BoolRule(false,
                        "Emits only mutated registers."),
                    ["includeStatus"] = BoolRule(false,
                        "Adds the GetServerStatus section."),
                    ["includeExpressions"] = new JsonObject
                    {
                        ["type"] = "array",
                        ["minItems"] = 1,
                        ["maxItems"] = 16,
                        ["description"] = "1-16 expressions in the same paused window; each returns success/error.",
                        ["items"] = new JsonObject
                        {
                            ["type"] = "string", ["minLength"] = 1, ["maxLength"] = 512,
                            ["description"] = "One x64dbg expression."
                        }
                    },
                    ["includeRanges"] = new JsonObject
                    {
                        ["type"] = "array",
                        ["minItems"] = 1,
                        ["maxItems"] = 8,
                        ["description"] = "1-8 {address, byteCount}; total <=16384B; one bad entry fails only its index.",
                        ["items"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["properties"] = new JsonObject
                            {
                                ["address"] = new JsonObject { ["type"] = "string", ["description"] = "Address or expr, e.g. cip.", ["x-maxUtf8Bytes"] = 256, ["minLength"] = 1, ["x-nonblank"] = true },
                                ["byteCount"] = IntRule(128, 1, 4096)
                            },
                            ["required"] = new JsonArray("address"),
                            ["additionalProperties"] = false
                        }
                    },
                    ["autoPause"] = BoolRule(false, AutoPauseDescription)
                },
                ["examples"] = new JsonArray(new JsonObject { ["maxChars"] = 16_000 }),
                ["additionalProperties"] = false
            }
        },
            call => live.GetAnalysisSnapshotAsync(call.Arguments, call.CancellationToken), ToolCapability.ReadOnly, requiresControl: false, lean: true,
            // autoPause pauses and resumes the debugger, so this call changes
            // the target's state even though the tool is read-only: it must
            // hold the session's exclusive lease, otherwise a concurrent
            // reader can observe a pause it did not ask for and one call's
            // resume can undo another call's pause.
            requiresExclusiveLease: AutoPauseRequiresExclusiveLease);

        Register(new JsonObject
        {
            ["name"] = "TraceUntil",
            ["description"] = "Step count times or until condition/stopAt/stopAddress/maxSteps. Returns final snapshot.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["count"] = IntRule(1, 1, 100, "Steps to take (prefer 1-10); ignored when a stop arg is set."),
                    ["maxSteps"] = IntRule(20, 1, 100, "Max attempts."),
                    ["condition"] = new JsonObject { ["type"] = "string", ["maxLength"] = 128,
                        ["description"] = "C-style stop expression evaluated per step, e.g. 'rax == 0'." },
                    ["stopAt"] = new JsonObject { ["type"] = "string", ["maxLength"] = 32, ["minLength"] = 1, ["x-nonblank"] = true,
                        ["description"] = "Mnemonic substring to stop at, e.g. 'call'." },
                    ["stopAddress"] = new JsonObject { ["type"] = "string", ["maxLength"] = 32, ["minLength"] = 1, ["x-nonblank"] = true,
                        ["description"] = "Hex address to stop at, e.g. '0x140001050'." },
                    ["kind"] = StepKindRule(),
                    ["maxFrames"] = IntRule(8, 1, 64),
                    ["beforeBytes"] = IntRule(16, 0, 256),
                    ["instructionBytes"] = IntRule(16, 1, 2048),
                    ["stackBytes"] = IntRule(64, 0, 2048),
                    ["maxChars"] = IntRule(8000, 2000, 60000),
                    ["includeThreads"] = BoolRule(false),
                    ["includeModules"] = BoolRule(false),
                    ["compactModules"] = BoolRule(true,
                        "Folds system DLLs when includeModules is true."),
                    ["compactStack"] = BoolRule(true,
                        "Folds repetitive OS frames during tracing."),
                    ["sparseRegisters"] = BoolRule(true,
                        "Suppresses zero general-purpose registers."),
                    ["includePath"] = BoolRule(false,
                        "Records each stepped instruction into trace.path."),
                    ["pathFormat"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["enum"] = new JsonArray("compact", "full"),
                        ["default"] = "compact",
                        ["description"] = "trace.path: compact emits address+mnemonic strings, full emits step/address/instruction objects."
                    },
                    ["diffOnly"] = BoolRule(false,
                        "Emits only registers mutated since the previous turn.")
                },
                ["examples"] = new JsonArray(
                    new JsonObject { ["stopAt"] = "call", ["maxSteps"] = 20 },
                    new JsonObject { ["count"] = 1, ["kind"] = "into" }
                ),
                ["additionalProperties"] = false
            }
        }, call => live.TraceUntilAsync(call.Arguments, call.CancellationToken), ToolCapability.Mutation, requiresControl: false, lean: true);
    }
}
