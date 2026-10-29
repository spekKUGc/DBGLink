using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterCallGraph(AnalysisContext context)
    {
        RegisterGhidra(context, new JsonObject
        {
            ["name"] = "CallGraph",
            ["description"] = "Call graph: module/range nodes + caller->callee edges {s,t,n}, or a 1-2 step neighborhood around function. Follow nextStart when truncated; no decompilation.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["module"] = Utf8Text("Active-program path or file name; no external file is opened.", 2048),
                    ["function"] = Utf8Text("Seed function; returns a neighborhood and nextBest. Omit start/end.", 256),
                    ["depth"] = IntRule(1, 1, 2, "Depth 1-2; with function."),
                    ["direction"] = new JsonObject
                    {
                        ["type"] = "string", ["default"] = "both",
                        ["pattern"] = "^(?i)(callers|callees|both)$",
                        ["description"] = "callers|callees|both; with function.",
                    },
                    ["start"] = Utf8Text("Inclusive range start (Ghidra VA).", 256),
                    ["end"] = Utf8Text("Inclusive range end (Ghidra VA).", 256),
                    ["maxNodes"] = IntRule(64, 1, 256, "Node cap; truncated graphs report nextStart."),
                    ["maxEdges"] = IntRule(256, 1, 1024, "Edge cap; truncated graphs keep only the first edges."),
                    ["includeInstructionCount"] = BoolRule(false),
                    ["edgeFormat"] = new JsonObject
                    {
                        ["type"] = "string", ["default"] = "indexed",
                        ["pattern"] = "^(?i)(full|indexed)$",
                        ["description"] = "indexed {s,t,n} (default) or full {caller,callee,count}.",
                    },
                },
                ["additionalProperties"] = false
            },
        }, lean: true, minimumTimeoutMs: 120_000);
    }

    private void RegisterFunctionMapping(AddressMapping mapping) => Register(new JsonObject
    {
        ["name"] = "MapStaticFunctionToLive",
        ["description"] = "Map one Ghidra function to the live module via identity+RVA. includeLiveBytes/includeStaticBytes verify in the same call. For static+live analysis, prefer GetInvestigationBrief.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["function"] = NonBlankText("Ghidra function address, RVA, or name.", 256),
                ["verifyHash"] = BoolRule(true,
                    "Verify SHA-256 when the module path is readable; path identity remains explicit if hashing is unavailable."),
                ["includeLiveBytes"] = BoolRule(false,
                    "Attach up to 32 live bytes at the mapped address via one bounded debugger read. Default false."),
                ["includeStaticBytes"] = BoolRule(false,
                    "Attach up to 32 static image bytes at the function entry via one bounded Ghidra read. Default false.")
            },
            ["required"] = new JsonArray("function"),
            ["additionalProperties"] = false
        }
    },
        call => mapping.MapStaticFunctionToLiveAsync(call.Arguments, call.CancellationToken), ToolCapability.ReadOnly, requiresControl: false, advertised: false);
}
