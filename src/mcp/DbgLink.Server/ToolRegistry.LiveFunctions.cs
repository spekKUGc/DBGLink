using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterLiveFunctions(AnalysisContext context) => Register(new JsonObject
    {
        ["name"] = "ListLiveFunctions",
        ["description"] = "Live functions of one loaded module (entry/RVA/name).",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["module"] = Utf8Text("Module name or path; empty selects the module with CIP.", 256),
                ["maxItems"] = IntRule(512, 1, 4096, "Max functions returned."),
            },
            ["additionalProperties"] = false
        }
    }, call => context.Bridge.RequestAsync("GetModuleFunctions", call.Arguments, call.CancellationToken),
        ToolCapability.ReadOnly, requiresControl: false, advertised: false, lean: false);
}
