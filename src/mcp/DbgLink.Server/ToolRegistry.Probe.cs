using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>
    /// ProbeFunction: one live call and return-register read, or a batch of
    /// up to 8 hypothesis probes in one model turn. Single mode (address plus
    /// arg1..arg4/expected) is byte-identical to before; batch mode takes
    /// probes[] where each row carries exactly one of address (live) or
    /// function (Ghidra selector, mapped server-side). A faulted probe
    /// hard-stops the batch (later rows report skipped); the top-level waitMs
    /// is a shared pause-wait budget and runAfter=false is single-row only.
    /// </summary>
    private void RegisterProbeFunction(LiveAnalysisTools live)
    {
        var probeRow = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["address"] = AddrRule("Live function entry (live address or expression). Exactly one of address/function."),
                ["function"] = NonBlankText("Ghidra function address, RVA, or name; mapped to live server-side. Exactly one of address/function.", 256),
                ["arg1"] = OptText("First argument (x64 rcx / x86 stack); hex or decimal.", 64),
                ["arg2"] = OptText("Second argument (x64 rdx / x86 stack).", 64),
                ["arg3"] = OptText("Third argument (x64 r8 / x86 stack).", 64),
                ["arg4"] = OptText("Fourth argument (x64 r9 / x86 stack).", 64),
                ["returnExpression"] = NonBlankText("Return register/expression to read. Defaults to rax on x64, eax on x86.", 512),
                ["expected"] = NonBlankText("Expected return value (0x.../decimal).", 64),
            },
            ["additionalProperties"] = false,
        };
        Register(new JsonObject
        {
            ["name"] = "ProbeFunction",
            ["description"] = "Call a live function and read the return register. Args are arg1..arg4 as hex strings ('0x5'), not args/arguments. value is the register read after the injected ret landed; the state fields show the pre-call running status. runAfter=false stages only; executed:true marks a real return. expected (0x.../decimal) is compared, reported as matched. probes[1..8] proves several hypotheses in one call: each row takes address or function (server-mapped), shares waitMs, and a faulted probe stops the batch with later rows skipped.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["address"] = AddrRule("Function entry (live address or expression)."),
                    ["arg1"] = OptText("First argument (x64 rcx / x86 stack); hex or decimal.", 64),
                    ["arg2"] = OptText("Second argument (x64 rdx / x86 stack).", 64),
                    ["arg3"] = OptText("Third argument (x64 r8 / x86 stack).", 64),
                    ["arg4"] = OptText("Fourth argument (x64 r9 / x86 stack).", 64),
                    ["returnExpression"] = NonBlankText("Return register/expression to read. Defaults to rax on x64, eax on x86.", 512),
                    ["expected"] = NonBlankText("Expected return value (0x.../decimal).", 64),
                    ["probes"] = new JsonObject
                    {
                        ["type"] = "array",
                        ["minItems"] = 1,
                        ["maxItems"] = 8,
                        ["items"] = probeRow,
                    },
                    ["runAfter"] = BoolRule(true, "Runs the call and reads the return register; false stages only (single probe only)."),
                    ["waitMs"] = IntRule(LiveAnalysisTools.DefaultProbeWaitMs, 0, LiveAnalysisTools.MaxProbeWaitMs, "Shared pause-wait budget in ms for the batch (0-30000)."),
                    ["verifyHash"] = BoolRule(true, "Verify SHA-256 when resolving function rows to live modules."),
                },
                ["x-requiresAnyOf"] = new JsonArray("address", "probes"),
                ["examples"] = new JsonArray(new JsonObject { ["address"] = "cip" }),
                ["additionalProperties"] = false
            }
        },
            call => live.ProbeBatchAsync(call.Arguments, call.CancellationToken),
            ToolCapability.Mutation, requiresControl: false, lean: true, minimumTimeoutMs: 120_000);
    }
}
