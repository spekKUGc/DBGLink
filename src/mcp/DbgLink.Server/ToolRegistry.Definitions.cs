using System.Text.Json;
using System.Text.Json.Nodes;
namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    public ToolRegistry(AnalysisContext context, CheckpointTools checkpoints,
        LiveAnalysisTools live, InvestigationTools investigation,
        AddressMapping mapping, GhidraOpenOperations open, SessionControlTools? sessions = null)
    {
        if (sessions is not null) RegisterSessionControl(sessions);
        RegisterStaticQueries(context);
        RegisterModuleMap(context);
        RegisterLiveSnapshotTools(live);
        RegisterBriefTools(investigation);
        RegisterTriage(context);
        RegisterCheckpointTools(checkpoints);
        RegisterGhidraMutations(context);
        RegisterGhidraImport(open);
        RegisterMemoryRead(context, live);
        RegisterStaticInspection(context);
        RegisterAnalysisQueue(context);
        RegisterCallGraph(context);
        RegisterFunctionMapping(mapping);
        RegisterServerStatus(context, open);
        RegisterMemorySearch(context);
        RegisterCoverage(context, live);
        RegisterDebugTarget(live);
        RegisterDebuggerControl(context, live);
        RegisterProbeFunction(live);
        RegisterLiveFunctions(context);
        BuildListTemplates();
    }

    private void RegisterServerStatus(AnalysisContext context, GhidraOpenOperations open) => Register(new JsonObject
    {
        ["name"] = "GetServerStatus",
        ["description"] = "Debugger status, Ghidra readiness, pending imports. Call once; do not poll — verify state changes with GetAnalysisSnapshot. analysisId is optional; omit it to use the active session.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["sections"] = new JsonObject
                {
                    ["type"] = "array",
                    ["description"] = "Telemetry groups.",
                    ["minItems"] = 1,
                    ["maxItems"] = 5,
                    ["items"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["enum"] = new JsonArray("summary", "telemetry", "backends", "sessions", "http"),
                    },
                },
            },
            ["additionalProperties"] = false
        }
    },
        call => ReadServerStatusAsync(context, open, call), ToolCapability.ReadOnly, requiresControl: false, lean: true,
        rawResponse: true);

    private void RegisterMemorySearch(AnalysisContext context)
    {
        Register(new JsonObject
        {
            ["name"] = "InspectAddressStructure",
            ["description"] = "Bounded address facts, bytes, fields, dereferences, xrefs in one call. Lowercase contiguous hex.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["address"] = AddrRule("Address or x64dbg expression such as cip."),
                    ["pointerCount"] = IntRule(8, 0, 64),
                    ["byteCount"] = IntRule(128, 0, 4096),
                    ["stringBytes"] = IntRule(128, 16, 1024),
                    ["includeXrefs"] = BoolRule(true),
                    ["maxXrefs"] = IntRule(32, 1, 256),
                    ["includeAscii"] = BoolRule(false),
                    ["spacedHex"] = BoolRule(false),
                    ["maxScanBytes"] = IntRule(4_194_304, 4096, 67_108_864)
                },
                ["required"] = new JsonArray("address"),
                ["additionalProperties"] = false
            }
        }, call => ExecuteInspectAddressStructureAsync(context, call),
            ToolCapability.ReadOnly, requiresControl: false, lean: true);
    }

    private void RegisterGhidra(AnalysisContext context, JsonObject metadata,
        ToolCapability capability = ToolCapability.ReadOnly, bool lean = false, int minimumTimeoutMs = 1_000, bool advertised = true)
        => Register(metadata, call => context.Ghidra.RequestAsync(call.Name, call.Arguments, call.CancellationToken),
            capability, requiresControl: false, advertised: advertised, lean: lean, minimumTimeoutMs: minimumTimeoutMs);
}
