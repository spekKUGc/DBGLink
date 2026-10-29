using System.Text.Json.Nodes;
namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterTriage(AnalysisContext context)
    {
        var triage = new TriageImportsTools(context);
        Register(new JsonObject
        {
            ["name"] = "Triage",
            ["description"] = "Triage imports (default), strings, or both. kind=imports: risk-ranked imports with refCounts; one ListSymbols(kind=imports) fetch, maxPages>1 auto-pages, offset resumes at nextOffset, maxChars drops lowest-ranked rows. kind=strings: IOC strings; filter/start narrow, reports truncated/nextAddress.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["kind"] = new JsonObject
                    {
                        ["type"] = "string", ["default"] = "imports",
                        ["pattern"] = "^(?i)(imports|strings|both)$",
                        ["description"] = "imports, strings, or both."
                    },
                    ["filter"] = new JsonObject { ["type"] = "string", ["maxLength"] = 256, ["description"] = "Substring filter (imports: ListSymbols substring; strings: substring/'*' glob)." },
                    ["module"] = new JsonObject { ["type"] = "string", ["maxLength"] = 2048, ["description"] = "Module name or path." },
                    ["top"] = IntRule(16, 1, 128, "Max imports; also caps the exports summary (imports only)."),
                    ["maxItems"] = IntRule(256, 1, 512, "Rows per page; omit for per-kind default (256/64)."),
                    ["maxChars"] = IntRule(4000, 1000, 30000, "Budget (imports only); drops lowest-ranked rows."),
                    ["offset"] = IntRule(0, 0, 1_000_000, "Resume from a prior nextOffset (imports only)."),
                    ["maxPages"] = IntRule(1, 1, 8, "Pages auto-followed via nextOffset/nextAddress."),
                    ["includeExports"] = BoolRule(false, "Also return the first top exports (imports only)."),
                    ["compact"] = BoolRule(false, "Dict-encode rows: library/categories/type become indices."),
                    ["section"] = new JsonObject { ["type"] = "string", ["default"] = ".rdata", ["description"] = "Section to triage (strings only)." },
                    ["start"] = new JsonObject { ["type"] = "string", ["maxLength"] = 256, ["description"] = "Ghidra VA to resume from (strings only)." },
                    ["minLength"] = IntRule(4, 2, 256),
                    ["maxScanBytes"] = IntRule(1048576, 4096, 16777216, "Scan budget per page (strings only).")
                },
                ["additionalProperties"] = false
            }
        }, call => triage.TriageAsync(call.Arguments, call.CancellationToken), ToolCapability.ReadOnly, requiresControl: false);
    }
}
