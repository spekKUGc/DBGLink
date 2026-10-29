using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private void RegisterSessionControl(SessionControlTools sessions)
    {
        Register(new JsonObject
        {
            ["name"] = "ListAnalysisSessions",
            ["description"] = "List live sessions (file name, arch, running flags, short sha256). includeClosed:true also shows closed sessions; old ids are invalid after replace/close. analysisId is optional; omit it to use the active session.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["includeClosed"] = BoolRule(false, "Closed/restored sessions too.")
                },
                ["additionalProperties"] = false
            }
        }, call => sessions.ListAsync(call.Arguments, call.CancellationToken), requiresControl: true, sessionScope: ToolSessionScope.Global);
        Register(new JsonObject
        {
            ["name"] = "CloseAnalysisSession",
            ["description"] = "Close one session, releasing its slot. Unsaved edits may be discarded. Repeated close is safe.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object", ["additionalProperties"] = false,
                ["required"] = new JsonArray("analysisId")
            }
        }, call => sessions.CloseAsync(call.AnalysisId, call.CancellationToken), ToolCapability.Mutation, requiresControl: true,
            minimumTimeoutMs: 60_000, sessionScope: ToolSessionScope.Closing);
        Register(new JsonObject
        {
            ["name"] = "ReopenAnalysisSession",
            ["description"] = "Reopen one restored session: re-imports its target and returns the NEW analysisId (dead id stays invalid).",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object", ["additionalProperties"] = false,
                ["required"] = new JsonArray("analysisId")
            }
        }, call => sessions.ReopenAsync(call.AnalysisId, call.CancellationToken), ToolCapability.Mutation, requiresControl: true,
            minimumTimeoutMs: 120_000, sessionScope: ToolSessionScope.Closing, registersCompletedSession: true, lean: true);
    }

    private void RegisterGhidraImport(GhidraOpenOperations open)
    {
        Register(new JsonObject
        {
            ["name"] = "OpenGhidraFile",
            ["description"] = "Import one bounded local binary into the isolated Ghidra session (up to 30s; pending:true tracked with GetGhidraOpenStatus); read-only, no scripts.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["analyze"] = BoolRule(true,
                        "False skips auto-analysis; function discovery and decompilation may be incomplete."),
                    ["path"] = NonBlankText("Absolute local path to the binary; validated, copied into the isolated session, imported.", 32_760),
                    ["waitMs"] = IntRule(30000, 0, 30000, "Long-poll wait ms (max 30000); timeout returns pending:true + waitedMs.")
                },
                ["required"] = new JsonArray("path"),
                ["additionalProperties"] = false
            }
        },
            async call => await open.BeginGhidraOpenAsync(call.Arguments!.Value.GetProperty("path").GetString()!,
                !call.Arguments.Value.TryGetProperty("analyze", out var analyze) || analyze.GetBoolean(),
                ToolSupport.ReadArgumentInt(call.Arguments, "waitMs", 30000), call.CancellationToken).ConfigureAwait(false), ToolCapability.ReadOnly, requiresControl: true, lean: true,
            minimumTimeoutMs: 35_000, sessionScope: ToolSessionScope.Global, registersCompletedSession: true);

        Register(new JsonObject
        {
            ["name"] = "GetGhidraOpenStatus",
            ["description"] = "Poll an OpenGhidraFile import; completion carries the program summary and session id. Poll at most every ~2s.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["operationId"] = NonBlankText("Id returned by OpenGhidraFile.", 128),
                    ["waitMs"] = IntRule(0, 0, 30000, "Long-poll wait ms (max 30000); timeout returns pending:true + waitedMs."),
                    ["cancel"] = BoolRule(false, "Cancel instead of polling.")
                },
                ["required"] = new JsonArray("operationId"),
                ["additionalProperties"] = false
            }
        },
            call => ToolSupport.ReadArgumentBool(call.Arguments, "cancel", false)
                ? open.CancelAsync(call.Arguments)
                : open.GetGhidraOpenStatusAsync(call.Arguments, call.CancellationToken), ToolCapability.ReadOnly, requiresControl: true, lean: true,
            minimumTimeoutMs: 35_000, sessionScope: ToolSessionScope.Global, registersCompletedSession: true);
    }

    private void RegisterCheckpointTools(CheckpointTools checkpoints)
    {
        Register(new JsonObject
        {
            ["name"] = "Checkpoint",
            ["description"] = "Checkpoint handoff for one SHA-256: action=create persists findings/hypotheses/verified/nextStep, action=restore loads (fields=summary for previews, full by default).",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["action"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["enum"] = new JsonArray("create", "restore"),
                        ["description"] = "create persists the handoff; restore loads it.",
                    },
                    ["title"] = NonBlankText("Checkpoint title.", 256),
                    ["sha256"] = Sha256Rule("Binary SHA-256; optional for create when this analysisId already saved one."),
                    ["findings"] = MultilineText("Findings.", 32_000),
                    ["hypotheses"] = MultilineText("Unproven hypotheses.", 32_000),
                    ["verified"] = MultilineText("Checked facts.", 32_000),
                    ["nextStep"] = MultilineText("Next concrete action.", 32_000, nonblank: true),
                    ["context"] = MultilineText("Paths, addresses, caveats.", 64_000),
                    ["liveValues"] = MultilineText("Live values; revalidate when restored.", 64_000),
                    ["fields"] = OptText("summary for previews, or full.", 16),
                    ["include"] = new JsonObject { ["type"] = "array", ["items"] = new JsonObject { ["type"] = "string", ["maxLength"] = 32 } },
                    ["maxChars"] = IntRule(2000, 256, 8000, "Preview chars per field."),
                    ["ifNoneMatch"] = OptText("Prior contentHash; returns unchanged:true when equal.", 64),
                    ["includeAllHashes"] = BoolRule(false, "Return all availableSha256; default caps at 8."),
                },
                ["required"] = new JsonArray("action"),
                ["examples"] = new JsonArray(new JsonObject
                {
                    ["action"] = "create",
                    ["sha256"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ["findings"] = "Entry calls the parser after checking input length.",
                    ["nextStep"] = "Inspect the parser's first indirect call."
                }),
                ["additionalProperties"] = false
            }
        },
            call => ToolSupport.ReadArgumentString(call.Arguments, "action") switch
            {
                "create" => checkpoints.CreateCheckpointAsync(call.Arguments, call.AnalysisId),
                "restore" => checkpoints.GetLastCheckpointAsync(call.Arguments),
                _ => Task.FromResult(BridgeEnvelope.Error("invalid_argument",
                    "Checkpoint action must be 'create' or 'restore'. Do not repeat the same call without changing inputs.")),
            },
            ToolCapability.ReadOnly, requiresControl: false, lean: true,
            sessionScope: ToolSessionScope.Global);
    }

    private void RegisterDebugTarget(LiveAnalysisTools live) => Register(new JsonObject
    {
        ["name"] = "OpenDebugTarget",
        ["description"] = "Open a local PE target; auto-selects x32dbg/x64dbg. Replaces the live session.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["path"] = NonBlankText("Absolute local drive .exe/.dll path. UNC/ADS/device rejected, must exist; validated before launch.", 32760),
                ["arguments"] = OptText("Debuggee command line, passed to the debugger init command.", 4096),
                ["workDir"] = OptText("Working directory for the debuggee; defaults to the executable folder.", 32760),
                ["architecture"] = ArchitectureRule()
            },
            ["required"] = new JsonArray("path"),
            ["examples"] = new JsonArray(new JsonObject { ["path"] = "C:\\target\\app.exe" }),
            ["additionalProperties"] = false
        }
    },
        call => live.OpenDebugTargetAsync(call.Arguments, call.CancellationToken), ToolCapability.Mutation, requiresControl: true, lean: true,
        minimumTimeoutMs: 60_000);
}
