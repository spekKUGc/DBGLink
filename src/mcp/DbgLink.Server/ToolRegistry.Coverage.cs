using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    // Stack-sampling coverage: forwards to the native SampleCallStacks bridge
    // method, which snapshots the paused call stack on a bounded schedule and
    // aggregates unique module+RVA frames with hit counts (top-N first).
    // Hidden expert tool (still callable, e.g. inside BatchDebuggerOperations):
    // it holds the bridge pipe for up to durationMs (15s max), so it must
    // never sit in the token-critical prompt. Opt-in autoPause pauses a
    // running target for the sample window, then restores the prior run
    // state; otherwise pause the target first (ControlDebuggerExecution
    // action=pause) or drive repeated short calls across manual run/pause steps.
    private void RegisterCoverage(AnalysisContext context, LiveAnalysisTools live) => Register(new JsonObject
    {
        ["name"] = "SampleCallStacks",
        ["description"] = "Sample the paused call stack via BatchDebuggerOperations instead; pause first, or pass autoPause:true.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["intervalMs"] = IntRule(200, 50, 5000, "Pause between stack snapshots in ms."),
                ["durationMs"] = IntRule(2000, 0, 15000, "Sampling window in ms; snapshots stop at min(maxSamples, durationMs/intervalMs+1)."),
                ["maxSamples"] = IntRule(20, 1, 100, "Max stack snapshots to take."),
                ["maxFrames"] = IntRule(32, 1, 128, "Frames read per snapshot."),
                ["topN"] = IntRule(32, 1, 128, "Top aggregated frames to return by hit count."),
                ["module"] = Utf8Text("Optional module name filter; only frames in this module aggregate.", 256),
                ["autoPause"] = BoolRule(false, AutoPauseDescription),
            },
            ["examples"] = new JsonArray(new JsonObject { ["maxSamples"] = 20 }),
            ["additionalProperties"] = false
        }
    }, call => BridgeWithAutoPauseAsync(context, live, call, call.Name), minimumTimeoutMs: 120_000, advertised: false);
}
