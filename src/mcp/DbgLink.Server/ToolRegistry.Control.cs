using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private static readonly HashSet<string> DebuggerBatchMethods = new(StringComparer.Ordinal)
    {
        "ReadMemAtAddress", "InspectAddressStructure",
        "GetMemoryMap", "GetBacktrace", "ListThreads", "ListBreakpoints",
        "SetBreakpoint", "ClearBreakpoint", "SetRegister", "WriteMemory",
        "FindBytePatternInModule",
        // P1-6 fan-out admissions: EvaluateExpressions and GetAnalysisSnapshot
        // are served by the batch local dispatcher (C2); SwitchThread,
        // ListLiveFunctions (translated to GetModuleFunctions) and
        // SampleCallStacks go to the bridge via SendDebuggerAsync.
        "EvaluateExpressions", "SwitchThread", "ListLiveFunctions", "SampleCallStacks",
        "GetAnalysisSnapshot"
    };

    /// <summary>
    /// Batch-only method schemas (P3): these singles are purged from the
    /// top-level registry but stay valid inside BatchDebuggerOperations.
    /// ExecuteBatchAsync validates batch rows against this table when the
    /// method has no top-level registration; the schemas are the exact
    /// objects the removed singles advertised, so row validation is unchanged.
    /// </summary>
    private static readonly Dictionary<string, JsonObject> BatchOnlySchemas = new(StringComparer.Ordinal)
    {
        ["ListBreakpoints"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["offset"] = IntRule(0, 0, 1_000_000, "Page offset."),
                ["maxItems"] = IntRule(32, 1, 128, "Page size."),
            },
            ["required"] = new JsonArray(),
            ["additionalProperties"] = false,
        },
        ["SwitchThread"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["threadId"] = new JsonObject
                {
                    ["type"] = "integer", ["minimum"] = 1, ["maximum"] = 2_147_483_647,
                    ["description"] = "Thread id from ListThreads.",
                },
            },
            ["required"] = new JsonArray("threadId"),
            ["additionalProperties"] = false,
        },
        ["FindBytePatternInModule"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["pattern"] = new JsonObject
                {
                    ["type"] = "string",
                    ["description"] = "Hex byte pattern such as 48 8B ?? ??; at least one exact byte is required.",
                    ["maxLength"] = 1024, ["x-bytePattern"] = true, ["minLength"] = 1, ["x-nonblank"] = true },
                ["module"] = new JsonObject
                {
                    ["type"] = "string",
                    ["description"] = "Module name/path filter; empty selects the module containing CIP, and all scans every image module.",
                    ["default"] = "",
                    ["maxLength"] = 256, ["x-maxUtf8Bytes"] = 256 },
                ["maxResults"] = IntRule(100, 1, 512),
                ["maxScanBytes"] = IntRule(33_554_432, 4096, 67_108_864)
            },
            ["required"] = new JsonArray("pattern"),
            ["additionalProperties"] = false
        },
        // P3: DumpStrings top-level single purged (covered by Triage
        // kind=strings); the batch row keeps the exact advertised rules.
        ["DumpStrings"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["section"] = TextRule("Exact section name, e.g. .rdata. Omit for non-executable blocks."),
                ["start"] = TextRule("Ghidra VA, not live. EXTERNAL ok for Xrefs(to)."),
                ["filter"] = TextRule("Substring or '*' filter."),
                ["minLength"] = IntRule(4, 2, 256),
                ["maxItems"] = IntRule(128, 1, 512),
                ["maxScanBytes"] = IntRule(262_144, 4096, 16_777_216),
                ["includeHex"] = BoolRule(false),
                ["module"] = TextRule("Name/path of the Ghidra program. Does not load a module: use OpenGhidraFile and analysisId.", 2048),
            },
            ["required"] = new JsonArray(),
            ["additionalProperties"] = false
        },
    };

    private void RegisterDebuggerControl(AnalysisContext context, LiveAnalysisTools live)
    {
        void AddBridge(string name, string description, JsonObject properties,
            ToolCapability capability, string[]? required = null, JsonArray? examples = null, bool lean = false, bool advertised = true)
        {
            Register(new JsonObject
            {
                ["name"] = name,
                ["description"] = description,
                ["inputSchema"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = properties,
                    ["required"] = new JsonArray((required ?? []).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
                    ["examples"] = examples ?? new JsonArray(),
                    ["additionalProperties"] = false,
                },
            }, call => context.Bridge.RequestAsync(call.Name, call.Arguments, call.CancellationToken),
                capability, requiresControl: false, advertised: advertised, lean: lean);
        }

        var bpAddress = AddrRule("Live address or expression; static Ghidra addresses do not fit. Omit only with module+rva.");
        var setProps = new JsonObject
        {
            ["address"] = bpAddress,
            ["kind"] = KindRule("Breakpoint kind.",
                "^(?i)(soft|normal|hw|hardware|mem|memory)?$"),
            ["name"] = new JsonObject
            {
                ["type"] = "string", ["maxLength"] = 64,
                ["pattern"] = "^[A-Za-z_$.?][A-Za-z0-9_$.?]*$",
                ["description"] = "Breakpoint name (soft only).",
            },
            ["singleshot"] = BoolRule(false),
            ["hwType"] = KindRule("Hardware type.",
                "^(?i)[xrw]?$"),
            ["hwSize"] = new JsonObject
            {
                ["type"] = "integer", ["default"] = 1, ["minimum"] = 1, ["maximum"] = 8,
                ["x-allowedInts"] = new JsonArray(1, 2, 4, 8),
                ["description"] = "Watch size in bytes; address must be aligned to it.",
            },
            ["memType"] = KindRule("Memory type; covers a whole page.",
                "^(?i)[arwx]?$"),
            ["restore"] = BoolRule(false),
            ["condition"] = BreakpointTextRule("Break condition (non-zero breaks), e.g. 'eax == 1'."),
            ["logText"] = BreakpointTextRule("Log text, e.g. 'CIP={cip}'; logs without pausing."),
            ["logCondition"] = BreakpointTextRule("Log condition."),
            ["module"] = TextRule("Module name, e.g. game.exe.", 512),
            ["rva"] = TextRule("RVA.", 64),
            ["autoPause"] = BoolRule(false, AutoPauseDescription),
        };
        Register(new JsonObject
        {
            ["name"] = "SetBreakpoint",
            ["description"] = "Breakpoint at a LIVE address (cip, 0x...); static Ghidra VAs do not fit: live = moduleBase + RVA. soft=bp; hw needs hwType/hwSize + alignment; mem needs memType, covers a page.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = setProps,
                ["required"] = new JsonArray(),
                ["examples"] = new JsonArray(
                    new JsonObject { ["address"] = "cip" },
                    new JsonObject { ["address"] = "cip", ["kind"] = "hw", ["hwType"] = "x", ["hwSize"] = 1 },
                    new JsonObject { ["module"] = "game.exe", ["rva"] = "0x1000" }),
                ["additionalProperties"] = false
            }
        }, call => ExecuteSetBreakpointAsync(context, live, call),
            ToolCapability.Mutation, requiresControl: false, lean: true);

        var clearProps = new JsonObject
        {
            ["address"] = AddrRule("Address to clear."),
                    ["kind"] = KindRule("Which kind to clear.",
                "^(?i)(soft|normal|hw|hardware|mem|memory|all)?$"),
            ["all"] = BoolRule(false),
            ["autoPause"] = BoolRule(false, AutoPauseDescription),
        };
        Register(new JsonObject
        {
            ["name"] = "ClearBreakpoint",
            ["description"] = "Clear one breakpoint (bc/bphc/bpmc) or a group with all=true. Provide address, or all=true with a kind. Memory breakpoints key by page base.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = clearProps,
                ["required"] = new JsonArray(),
                ["examples"] = new JsonArray(
                    new JsonObject { ["address"] = "cip" },
                    new JsonObject { ["all"] = true, ["kind"] = "soft" }),
                ["additionalProperties"] = false,
            },
        }, call => BridgeWithAutoPauseAsync(context, live, call, "ClearBreakpoint"),
            ToolCapability.Mutation, requiresControl: false, lean: true);

        Register(new JsonObject
        {
            ["name"] = "ControlDebuggerExecution",
            ["description"] = "Resume (action=run) or pause (action=pause); then verify with GetAnalysisSnapshot.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["action"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["enum"] = new JsonArray("run", "pause"),
                        ["description"] = "Resume or pause.",
                    },
                },
                ["required"] = new JsonArray("action"),
                ["examples"] = new JsonArray(
                    new JsonObject { ["action"] = "run" },
                    new JsonObject { ["action"] = "pause" }),
                ["additionalProperties"] = false
            }
        }, async call =>
        {
            var action = ToolSupport.ReadArgumentString(call.Arguments, "action");
            var method = action switch
            {
                "run" => "RunDebugger",
                "pause" => "PauseDebugger",
                _ => throw new ModelContextProtocol.McpProtocolException(
                    "action must be 'run' or 'pause'. Do not repeat the same call without changing inputs.",
                    ModelContextProtocol.McpErrorCode.InvalidParams),
            };
            // Backstop beyond the bridge's own control-plane timeout: a hung
            // run/pause must surface as a readable timeout (state unknown)
            // instead of burning the whole MCP turn. Caller cancellation still
            // propagates so the dispatcher can abort the turn.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(call.CancellationToken);
            timeout.CancelAfter(30_000);
            try
            {
                return await context.Bridge.RequestAsync(method, null, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!call.CancellationToken.IsCancellationRequested)
            {
                return BridgeEnvelope.Error("debugger_control_timeout",
                    $"The debugger did not answer '{method}' within 30s; its running/paused state is unknown. " +
                    "Poll GetAnalysisSnapshot to check state before retrying. Do not repeat run/pause blindly.");
            }
        }, ToolCapability.Mutation, requiresControl: false, lean: true);

        Register(new JsonObject
        {
            ["name"] = "SetRegister",
            ["description"] = "Set a CPU register while paused. Value is hex or decimal.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["register"] = new JsonObject
                    {
                        ["type"] = "string", ["maxLength"] = 32, ["minLength"] = 1, ["x-nonblank"] = true,
                        ["pattern"] = "^[A-Za-z][A-Za-z0-9]*$",
                        ["description"] = "Register name, e.g. rax.",
                    },
                    ["value"] = new JsonObject
                    {
                        ["type"] = "string", ["maxLength"] = 64, ["minLength"] = 1, ["x-nonblank"] = true,
                        ["description"] = "New value, hex or decimal.",
                    },
                    ["autoPause"] = BoolRule(false, AutoPauseDescription),
                },
                ["required"] = new JsonArray("register", "value"),
                ["examples"] = new JsonArray(new JsonObject { ["register"] = "rax", ["value"] = "0x0" }),
                ["additionalProperties"] = false,
            },
        }, call => live.SetRegisterAsync(call.Arguments, call.CancellationToken),
            ToolCapability.Mutation, requiresControl: false, lean: true);

        Register(new JsonObject
        {
            ["name"] = "WriteMemory",
            ["description"] = "Write bytes while paused (max 4096/call). hexBytes accepts \"48 8B\", \"0x48,0x8B\" or \"488B\".",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["address"] = AddrRule("Target address or expression, e.g. cip, csp."),
                    ["hexBytes"] = new JsonObject
                    {
                        ["type"] = "string", ["maxLength"] = 12288, ["minLength"] = 1, ["x-nonblank"] = true,
                        ["x-hexBytes"] = true, ["x-maxBytes"] = 4096,
                        ["description"] = "Bytes to write, e.g. \"90 90\" or \"488B05\".",
                    },
                    ["autoPause"] = BoolRule(false, AutoPauseDescription),
                    ["echoBytes"] = BoolRule(false, "Echoes bytesHex in the ack."),
                },
                ["required"] = new JsonArray("address", "hexBytes"),
                ["examples"] = new JsonArray(new JsonObject { ["address"] = "csp", ["hexBytes"] = "90 90" }),
                ["additionalProperties"] = false,
            },
        }, call => live.WriteMemoryAsync(call.Arguments, call.CancellationToken),
            ToolCapability.Mutation, requiresControl: false, lean: true);

        Register(new JsonObject
        {
            ["name"] = "ListThreads",
            ["description"] = "Threads with tid and cip. Paged via offset/maxItems.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["offset"] = IntRule(0, 0, 1_000_000, "Zero-based index."),
                    ["maxItems"] = IntRule(32, 1, 128, "Page size."),
                    ["autoPause"] = BoolRule(false, AutoPauseDescription),
                },
                ["required"] = new JsonArray(),
                ["examples"] = new JsonArray(),
                ["additionalProperties"] = false,
            },
        }, call => BridgeWithAutoPauseAsync(context, live, call, "ListThreads"),
            ToolCapability.ReadOnly, requiresControl: false,
            requiresExclusiveLease: AutoPauseRequiresExclusiveLease);

        var backtraceProps = new JsonObject
        {
            ["maxFrames"] = IntRule(8, 1, 64, "Frames per page."),
            ["startFrame"] = IntRule(0, 0, 1_000_000, "Zero-based frame index."),
            ["threadId"] = new JsonObject
            {
                ["type"] = "integer", ["minimum"] = 1, ["maximum"] = 2_147_483_647,
                ["description"] = "Debugger thread id from ListThreads.",
            },
            ["autoPause"] = BoolRule(false, AutoPauseDescription),
        };
        Register(new JsonObject
        {
            ["name"] = "GetBacktrace",
            ["description"] = "RBP-walk backtrace for current thread or threadId. Paged via startFrame/maxFrames; nextFrame only when truncated.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = backtraceProps,
                ["required"] = new JsonArray(),
                ["examples"] = new JsonArray(),
                ["additionalProperties"] = false,
            },
        }, call => BridgeWithAutoPauseAsync(context, live, call, "GetBacktrace"),
            ToolCapability.ReadOnly, requiresControl: false,
            requiresExclusiveLease: AutoPauseRequiresExclusiveLease);

        Register(new JsonObject
        {
            ["name"] = "EvaluateExpressions",
            ["description"] = "Evaluate 1-16 x64dbg expressions in one round trip. Each item returns its own success/error; nextIndex continues.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["expressions"] = new JsonObject
                    {
                        ["type"] = "array", ["minItems"] = 1, ["maxItems"] = 16,
                        ["items"] = new JsonObject
                        {
                            ["type"] = "string", ["minLength"] = 1, ["maxLength"] = 512,
                            ["description"] = "One x64dbg expression, e.g. cip."
                        },
                        ["description"] = "Expressions to evaluate."
                    }
                },
                ["required"] = new JsonArray("expressions"),
                ["additionalProperties"] = false
            }
        }, call => ExecuteExpressionsAsync(call, context.Bridge.RequestAsync),
            ToolCapability.ReadOnly, requiresControl: false, lean: true);

        AddBridge("GetMemoryMap",
            "Memory layout and page protections (short codes; fullProtect for long form).",
            new JsonObject
            {
                ["executableOnly"] = BoolRule(false),
                ["rwxOnly"] = BoolRule(false),
                ["fullProtect"] = BoolRule(false),
                ["type"] = KindRule("Memory type filter.", "^(?i)(all|private|image|mapped)?$"),
                ["offset"] = IntRule(0, 0, 1_000_000, "Zero-based page offset."),
                ["maxItems"] = IntRule(32, 1, 128, "Page size.")
            }, ToolCapability.ReadOnly, [],
            new JsonArray());

        Register(new JsonObject
        {
            ["name"] = "BatchDebuggerOperations",
            ["description"] = "1-16 debugger ops in one round trip: requests:[{method:\"ReadMemAtAddress\",arguments:{address:\"cip\",byteCount:64}}]. Mixed families rejected by index; autoPause applies to the whole batch.",
            ["inputSchema"] = BatchInputSchema("An allowed debugger tool name.")
        }, call => ExecuteBatchAsync(call, SendDebuggerAsync(context), DebuggerBatchMethods,
            static method => string.Equals(method, "EvaluateExpression", StringComparison.Ordinal)
                ? "Batch contains unsupported method 'EvaluateExpression': use top-level EvaluateExpressions."
                : $"Batch contains unsupported method '{method}'.",
            deadlineMilliseconds: 60_000, rejectNestedAnalysisId: true,
            localDispatch: LocalDebuggerDispatch(context, live)),
            ToolCapability.Mutation, requiresControl: false, lean: true);
    }

    /// <summary>
    /// Bridge sender for BatchDebuggerOperations (P1-6): the historical
    /// context.Bridge.RequestAsync path plus two batch-only adaptations.
    /// Per-item autoPause stays rejected (C3 pauses once per batch via the
    /// batch-level flag): Batch.cs rejects WriteMemory/SetRegister up front,
    /// and the read/breakpoint tools below gained a top-level autoPause flag,
    /// so reject it here before it leaks to the bridge as an unknown
    /// property. ListLiveFunctions is translated to its GetModuleFunctions
    /// bridge method, matching the top-level tool executor.
    /// </summary>
    private static Func<string, JsonElement?, CancellationToken, Task<string>> SendDebuggerAsync(AnalysisContext context)
        => (method, arguments, token) =>
        {
            if (arguments is { ValueKind: JsonValueKind.Object } &&
                arguments.Value.TryGetProperty("autoPause", out _) &&
                method is "ReadMemAtAddress" or "GetBacktrace" or "ListThreads" or
                    "SampleCallStacks" or "SetBreakpoint" or "ClearBreakpoint")
                throw new ModelContextProtocol.McpProtocolException(
                    $"autoPause is not supported inside a batch; call {method} directly with autoPause:true or set autoPause on the batch.",
                    ModelContextProtocol.McpErrorCode.InvalidParams);
            if (string.Equals(method, "ListLiveFunctions", StringComparison.Ordinal))
                return context.Bridge.RequestAsync("GetModuleFunctions", arguments, token);
            return context.Bridge.RequestAsync(method, arguments, token);
        };

    /// <summary>
    /// Local dispatcher for BatchDebuggerOperations (C2): methods served
    /// in-process instead of over the bridge pipe. EvaluateExpressions reuses
    /// the top-level fan-out (one EvaluateExpression bridge call per unique
    /// expression); GetAnalysisSnapshot reuses the live snapshot core
    /// (including its includeExpressions/includeRanges bundle). Per-item
    /// autoPause is rejected, not stripped: the batch-level flag (C3) is the
    /// only pause scope inside a batch. Anything outside LocalBatchMethods
    /// never reaches here (ExecuteBatchAsync picks the sender).
    /// </summary>
    private Func<string, JsonElement?, CancellationToken, Task<string>> LocalDebuggerDispatch(
        AnalysisContext context, LiveAnalysisTools live)
        => (method, arguments, token) =>
        {
            if (string.Equals(method, "EvaluateExpressions", StringComparison.Ordinal))
                return ExecuteExpressionsAsync(
                    new ToolInvocation("EvaluateExpressions", arguments, null, token),
                    context.Bridge.RequestAsync);
            if (string.Equals(method, "GetAnalysisSnapshot", StringComparison.Ordinal))
            {
                if (arguments is { ValueKind: JsonValueKind.Object } &&
                    arguments.Value.TryGetProperty("autoPause", out _))
                    throw new ModelContextProtocol.McpProtocolException(
                        "autoPause is not supported inside a batch; call GetAnalysisSnapshot directly with autoPause:true or set autoPause on the batch.",
                        ModelContextProtocol.McpErrorCode.InvalidParams);
                return live.GetAnalysisSnapshotAsync(arguments, token);
            }
            throw new ModelContextProtocol.McpProtocolException(
                $"Batch local dispatch got unexpected method '{DisplayMethod(method)}'.",
                ModelContextProtocol.McpErrorCode.InvalidParams);
        };

    /// <summary>
    /// Opt-in autoPause bridge call for the debugger read/breakpoint tools in
    /// this file (P2-9/P3-15 via C1): absent/false is the historical bridge
    /// passthrough with the MCP-only flag stripped (byte-identical when
    /// absent); true pauses a running target via
    /// LiveAnalysisTools.ExecuteReadWithAutoPauseAsync, which restores the
    /// prior run state and reports honest pause/resume errors.
    /// </summary>
    private static Task<string> BridgeWithAutoPauseAsync(
        AnalysisContext context, LiveAnalysisTools live, ToolInvocation call, string bridgeMethod)
    {
        if (!ToolSupport.ReadArgumentBool(call.Arguments, "autoPause", false))
            return context.Bridge.RequestAsync(bridgeMethod, StripAutoPause(call.Arguments), call.CancellationToken);
        return live.ExecuteReadWithAutoPauseAsync(bridgeMethod, StripAutoPause(call.Arguments), call.CancellationToken);
    }

    /// <summary>
    /// Strip the MCP-only autoPause flag before forwarding to the native
    /// bridge (which knows nothing about it). Absent stays the same
    /// reference so the historical path is byte-for-byte unchanged. Shared
    /// with LiveAnalysisTools.StripAutoPauseArgument (one implementation, so
    /// the two call sites cannot drift).
    /// </summary>
    private static JsonElement? StripAutoPause(JsonElement? arguments)
        => LiveAnalysisTools.StripAutoPauseArgument(arguments);

    /// <summary>
    /// Direct fan-out to the bridge: one "EvaluateExpression" bridge call per
    /// unique expression (bridge method name unchanged), with the same
    /// order-preserving, byte-bounded result envelope as ExecuteBatchAsync.
    /// </summary>
    private async Task<string> ExecuteExpressionsAsync(ToolInvocation call,
        Func<string, JsonElement?, CancellationToken, Task<string>> send)
    {
        if (call.Arguments is not JsonElement args || args.ValueKind != JsonValueKind.Object ||
            !args.TryGetProperty("expressions", out var list) || list.ValueKind != JsonValueKind.Array)
            return BridgeEnvelope.Error("invalid_argument",
                "expressions must be an array of 1-16 x64dbg expressions.");
        var expressions = list.EnumerateArray().ToArray();
        if (expressions.Length is < 1 or > 16)
            return BridgeEnvelope.Error("invalid_argument",
                "expressions must contain 1-16 items.");
        var texts = new string[expressions.Length];
        for (var i = 0; i < expressions.Length; i++)
        {
            var text = expressions[i].ValueKind == JsonValueKind.String ? expressions[i].GetString() : null;
            if (string.IsNullOrWhiteSpace(text) || text.Length > 512)
                return BridgeEnvelope.Error("invalid_argument",
                    $"expressions[{i}] must be a non-blank string up to 512 chars. Do not repeat the same call without changing inputs.");
            texts[i] = text!;
        }
        // Telemetry: sub-expression mix (first-seen order), same as batch fan-out.
        call.Detail = DescribeBatchMix(Enumerable.Repeat("EvaluateExpression", texts.Length));

        var results = new JsonArray();
        var used = 0;
        var index = 0;
        var reason = "";
        var failed = false;
        var dedup = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        // Leave time to return partial results before the outer MCP deadline.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(call.CancellationToken);
        deadline.CancelAfter(60_000);
        for (; index < texts.Length; index++)
        {
            var key = "EvaluateExpression\n{\"expression\":\"" + NormalizeExpression(texts[index]) + "\"}";
            JsonNode? parsed;
            if (dedup.TryGetValue(key, out var cached))
            {
                parsed = cached?.DeepClone();
            }
            else
            {
                string raw;
                try
                {
                    var itemArgs = ToolSupport.ToJsonElement(new JsonObject { ["expression"] = texts[index] });
                    raw = await send("EvaluateExpression", itemArgs, deadline.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!call.CancellationToken.IsCancellationRequested)
                {
                    reason = "deadline";
                    break;
                }
                catch (ModelContextProtocol.McpException exception)
                {
                    // Executor-level rejections become per-item errors, not fan-out killers.
                    // Clip to 256 chars: index+method are already in the row envelope.
                    var msg = exception.Message;
                    if (msg.Length > 256) msg = msg[..256] + "...[truncated]";
                    raw = BridgeEnvelope.Error("batch_item_error",
                        $"Request #{index} ('EvaluateExpression'): {msg}");
                }
                try
                {
                    parsed = JsonNode.Parse(raw);
                }
                catch (JsonException)
                {
                    parsed = JsonValue.Create(raw);
                }
                dedup[key] = parsed?.DeepClone();
            }
            var row = new JsonObject
            {
                ["index"] = index,
                ["response"] = parsed
            };
            var size = Encoding.UTF8.GetByteCount(row.ToJsonString());
            if (used + size > 200_000)
            {
                reason = "output_limit";
                break;
            }
            failed |= row["response"]?["ok"]?.GetValue<bool>() != true;
            results.Add(row);
            used += size;
        }
        var complete = index >= texts.Length;
        return new JsonObject
        {
            ["ok"] = true,
            ["result"] = BuildEvalEnvelope(failed || !complete, results, !complete, complete ? null : (int?)index, reason)
        }.ToJsonString();
    }

    private static JsonObject BuildEvalEnvelope(bool partial, JsonArray results, bool truncated, int? nextIndex, string reason)
    {
        var envelope = new JsonObject
        {
            ["partial"] = partial,
            ["results"] = results,
            ["truncated"] = truncated,
        };
        if (nextIndex.HasValue)
            envelope["nextIndex"] = nextIndex.Value;
        if (!string.IsNullOrEmpty(reason))
            envelope["stopReason"] = reason;
        return envelope;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\s+")]
    private static partial System.Text.RegularExpressions.Regex WhitespaceRun();

    private static string NormalizeExpression(string expression)
    {
        // Same normalization the batch dedup key used: "rax, RAX, rax "
        // collapse to one backend call. Shared compiled regex: the previous
        // per-call Regex.Replace re-parsed the pattern on every expression.
        var normalized = expression.Trim().ToLowerInvariant();
        return WhitespaceRun().Replace(normalized, " ");
    }

    /// <summary>
    /// SetBreakpoint with address-shape flexibility: a live address passes
    /// straight through, while module+rva is resolved against the debugger's
    /// loaded modules. Backend failures are enriched with the module table so
    /// agents fix the address instead of repeating the call. Opt-in autoPause
    /// (P3-15 via C1) pauses a running target to ARM the breakpoint, then
    /// restores the prior run state only: it never runs to the breakpoint and
    /// never flips a paused target to running.
    /// </summary>
    private async Task<string> ExecuteSetBreakpointAsync(AnalysisContext context, LiveAnalysisTools live, ToolInvocation call)
    {
        var autoPause = ToolSupport.ReadArgumentBool(call.Arguments, "autoPause", false);
        var args = StripAutoPause(call.Arguments);
        var address = ToolSupport.ReadArgumentString(args, "address");
        if (string.IsNullOrWhiteSpace(address))
        {
            var module = ToolSupport.ReadArgumentString(args, "module");
            var rvaText = ToolSupport.ReadArgumentString(args, "rva");
            if (string.IsNullOrWhiteSpace(module) || string.IsNullOrWhiteSpace(rvaText))
                throw new ModelContextProtocol.McpProtocolException(
                    "SetBreakpoint needs a live debugger address, or module+rva (e.g. module=game.exe rva=0x1000). " +
                    "Ghidra static addresses do not fit: live = moduleBase + RVA. " +
                    "Do not repeat the same call without changing inputs.",
                    ModelContextProtocol.McpErrorCode.InvalidParams);
            address = await ResolveModuleRvaAsync(context, module!, rvaText!, call.CancellationToken).ConfigureAwait(false);
            var rewritten = JsonNode.Parse(args?.GetRawText() ?? "{}")!.AsObject();
            rewritten["address"] = address;
            rewritten.Remove("module");
            rewritten.Remove("rva");
            args = ToolSupport.ToJsonElement(rewritten);
        }
        if (!autoPause)
        {
            var direct = await context.Bridge.RequestAsync("SetBreakpoint", args, call.CancellationToken).ConfigureAwait(false);
            return await EnrichBreakpointErrorAsync(context, direct, call.CancellationToken).ConfigureAwait(false);
        }
        var armed = await live.ExecuteReadWithAutoPauseAsync("SetBreakpoint", args, call.CancellationToken).ConfigureAwait(false);
        return await EnrichBreakpointErrorAsync(context, armed, call.CancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ResolveModuleRvaAsync(AnalysisContext context, string module, string rvaText, CancellationToken token)
    {
        if (!TryParseRva(rvaText, out var rva))
            throw new ModelContextProtocol.McpProtocolException(
                $"rva '{TruncateForError(rvaText)}' is not 0x... hex or decimal. " +
                "Do not repeat the same call without changing inputs.",
                ModelContextProtocol.McpErrorCode.InvalidParams);
        var modules = await ReadDebuggerModulesAsync(context, token).ConfigureAwait(false);
        if (modules is null)
            throw new ModelContextProtocol.McpProtocolException(
                "Could not list debugger modules to resolve module+rva.",
                ModelContextProtocol.McpErrorCode.InternalError);
        foreach (var record in modules)
        {
            if (MatchesModule(record, module))
            {
                try
                {
                    var address = checked(record.Base + rva);
                    return $"0x{address:X}";
                }
                catch (OverflowException)
                {
                    throw new ModelContextProtocol.McpProtocolException(
                        $"rva 0x{rva:X} overflows module '{record.Name}' base 0x{record.Base:X}.",
                        ModelContextProtocol.McpErrorCode.InvalidParams);
                }
            }
        }
        throw new ModelContextProtocol.McpProtocolException(
            $"Module '{TruncateForError(module)}' is not loaded. Loaded modules: {DescribeModules(modules)}. " +
            "Use an exact loaded name, or pass a live address instead. Do not repeat the same call without changing inputs.",
            ModelContextProtocol.McpErrorCode.InvalidParams);
    }

    private static async Task<string> EnrichBreakpointErrorAsync(AnalysisContext context, string raw, CancellationToken token)
    {
        try
        {
            if (!ToolSupport.AnalyzeBridgeResponse(raw, includeText: true).IsError)
                return raw;
            // Only real backend error envelopes get the module table: anything
            // else passes through untouched (and costs no extra bridge call).
            var root = JsonNode.Parse(raw)?.AsObject();
            if (root?["error"] is not JsonObject error || error["message"] is not JsonValue)
                return raw;
            var message = error["message"]!.GetValue<string>();
            if (message.Contains("Loaded modules:", StringComparison.Ordinal))
                return raw;
            // Input-hygiene rejections (injection/invalid arguments) describe the
            // request text, not the address: enriching them would waste a bridge
            // call and bypass no-backend-call guarantees. The autoPause
            // machinery errors (pause/resume/state) describe run-state handling,
            // not the address either: leave them byte-identical so the honest
            // error (and its no-resume state accounting) stays unambiguous.
            var code = BridgeClient.TryParseErrorCode(raw) ?? "";
            if (code.Contains("injection", StringComparison.OrdinalIgnoreCase) ||
                code.Equals("invalid_argument", StringComparison.OrdinalIgnoreCase) ||
                code is "snapshot_state_unreadable" or "debugger_pause_failed" or
                    "debugger_running_timeout" or "debugger_resume_failed")
                return raw;
            var modules = await ReadDebuggerModulesAsync(context, token).ConfigureAwait(false);
            if (modules is null || modules.Count == 0)
                return raw;
            error["message"] = $"{message} Loaded modules: {DescribeModules(modules)}. " +
                "The address must be a live debugger address (live = moduleBase + RVA); " +
                "Ghidra static addresses do not fit. Do not repeat without changing inputs.";
            return root.ToJsonString();
        }
        catch
        {
            return raw;
        }
    }

    private static async Task<IReadOnlyList<ToolSupport.LiveModule>?> ReadDebuggerModulesAsync(AnalysisContext context, CancellationToken token)
    {
        try
        {
            // Bounded lookup: the module table is only enrichment for error
            // messages / module+rva resolution, so it must never consume the
            // full bridge budget. Timeout falls back to the unenriched path.
            // The table is shared per session, so repeated lookups are free.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(15_000);
            return await AddressMapping.ReadCachedModuleTableAsync(
                context.Bridge,
                callToken => context.Bridge.RequestAsync("GetModuleRecords", null, callToken),
                timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static bool MatchesModule(ToolSupport.LiveModule record, string module)
    {
        if (record.Name.Equals(module, StringComparison.OrdinalIgnoreCase))
            return true;
        string? fileName = null;
        try { fileName = Path.GetFileName(record.Path); } catch { }
        if (!string.IsNullOrEmpty(fileName) && fileName.Equals(module, StringComparison.OrdinalIgnoreCase))
            return true;
        return record.Path.Equals(module, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// InspectAddressStructure with a static-image fallback. Agents work from
    /// Ghidra static VAs (imageBase + RVA), but the live target sits at an
    /// ASLR base, so a static address reads as unreadable ([Bytes]/[Pointers]
    /// read=false) instead of failing loudly. On that exact shape the handler
    /// retries once as live = moduleBase + (staticVA - imageBase) and returns
    /// the live bytes plus a one-line [StaticRemap] note. Anything else (live
    /// addresses, expressions, errors, non-text shapes) passes through
    /// byte-identical, and every remap failure returns the original response.
    /// </summary>
    private async Task<string> ExecuteInspectAddressStructureAsync(AnalysisContext context, ToolInvocation call)
    {
        var raw = await context.Bridge.RequestAsync(
            "InspectAddressStructure", call.Arguments, call.CancellationToken).ConfigureAwait(false);
        try
        {
            return await TryStaticAddressRemapAsync(context, call, raw).ConfigureAwait(false) ?? raw;
        }
        catch (OperationCanceledException) when (call.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return raw;
        }
    }

    private static async Task<string?> TryStaticAddressRemapAsync(
        AnalysisContext context, ToolInvocation call, string raw)
    {
        // Only native text replies carry the [Bytes]/[Pointers] read markers;
        // JSON result shapes (and bridge errors) pass through untouched.
        if (ToolSupport.AnalyzeBridgeResponse(raw, includeText: true) is not { IsError: false, Text: var text } ||
            !HasUnreadableStructure(text))
            return null;
        var addressText = ToolSupport.ReadArgumentString(call.Arguments, "address");
        if (!AddressMapping.TryParseAddress(addressText, out var staticVa))
            return null;
        var (fileName, imageBase) = await ReadGhidraProgramIdentityAsync(
            context, call.CancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(fileName) || imageBase is null || staticVa < imageBase)
            return null;
        var rva = staticVa - imageBase.Value;
        var modules = await ReadDebuggerModulesAsync(context, call.CancellationToken).ConfigureAwait(false);
        if (modules is null)
            return null;
        ToolSupport.LiveModule? match = null;
        foreach (var record in modules)
        {
            if (MatchesModule(record, fileName!))
            {
                match = record;
                break;
            }
        }
        if (match is null)
            return null;
        ulong liveAddr;
        try
        {
            liveAddr = checked(match.Base + rva);
        }
        catch (OverflowException)
        {
            return null;
        }
        if (liveAddr >= match.End)
            return null;
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(call.Arguments?.GetRawText() ?? "");
        }
        catch (JsonException)
        {
            return null;
        }
        if (node is not JsonObject retryObj)
            return null;
        retryObj["address"] = $"0x{liveAddr:X}";
        var retryRaw = await context.Bridge.RequestAsync(
            "InspectAddressStructure", ToolSupport.ToJsonElement(retryObj),
            call.CancellationToken).ConfigureAwait(false);
        if (ToolSupport.AnalyzeBridgeResponse(retryRaw, includeText: true) is not
            { IsError: false, Text: var retryText } ||
            !HasReadableStructure(retryText))
            return null;
        var note = $"[StaticRemap] {addressText} looks like a static image address " +
            $"(imageBase 0x{imageBase.Value:X}); retried as live 0x{liveAddr:X} " +
            $"({match.Name}+0x{rva:X}). Prefer live = moduleBase + RVA.";
        return AppendNoteToTextEnvelope(retryRaw, note) ?? retryRaw;
    }

    private static async Task<(string? FileName, ulong? ImageBase)> ReadGhidraProgramIdentityAsync(
        AnalysisContext context, CancellationToken token)
    {
        try
        {
            var raw = await context.Ghidra.RequestAsync("status", null, token).ConfigureAwait(false);
            if (AnalysisFormatting.ReadBridgeResultNode(raw) is JsonObject result &&
                result["program"] is JsonObject program)
            {
                string? fileName = null;
                if (program["fileName"] is JsonValue nameValue &&
                    nameValue.TryGetValue<string>(out var name))
                    fileName = name;
                ulong? imageBase = null;
                if (program["imageBase"] is JsonValue baseValue &&
                    baseValue.TryGetValue<string>(out var baseText) &&
                    AddressMapping.TryParseAddress(baseText, out var parsed))
                    imageBase = parsed;
                return (fileName, imageBase);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
        }
        return (null, null);
    }

    private static bool StructureLineMatches(string text, string prefix, string suffix)
    {
        // Native emits e.g. "[Bytes] byteCount=128 read=false" on its own
        // line; stringRead=false on a pointee line must not match.
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').TrimEnd();
            if (line.StartsWith(prefix, StringComparison.Ordinal) &&
                line.EndsWith(suffix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static bool HasUnreadableStructure(string text) =>
        StructureLineMatches(text, "[Bytes]", "read=false") &&
        StructureLineMatches(text, "[Pointers]", "read=false");

    private static bool HasReadableStructure(string text) =>
        StructureLineMatches(text, "[Bytes]", "read=true") &&
        StructureLineMatches(text, "[Pointers]", "read=true");

    private static string? AppendNoteToTextEnvelope(string raw, string note)
    {
        try
        {
            if (JsonNode.Parse(raw) is JsonObject root &&
                root["ok"]?.GetValue<bool>() == true &&
                root["text"] is JsonValue textValue &&
                textValue.TryGetValue<string>(out var body))
            {
                root["text"] = body + "\n" + note;
                return root.ToJsonString();
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
        }
        return null;
    }

    private static string DescribeModules(IReadOnlyList<ToolSupport.LiveModule> modules)
    {
        var parts = new List<string>();
        var chars = 0;
        foreach (var record in modules.Take(16))
        {
            var part = $"{record.Name}=0x{record.Base:X}";
            if (chars + part.Length > 800)
            {
                parts.Add($"(+{modules.Count - parts.Count} more)");
                break;
            }
            parts.Add(part);
            chars += part.Length;
        }
        return string.Join(" ", parts);
    }

    private static bool TryParseRva(string? text, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var clean = text.Trim();
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            clean = clean[2..];
        if (clean.Length == 0 || clean.Length > 16)
            return false;
        return ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    private static string TruncateForError(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        var clean = new string(text.Where(c => !char.IsControl(c)).ToArray());
        return clean.Length > 128 ? clean[..128] : clean;
    }

    private void RegisterMemoryRead(AnalysisContext context, LiveAnalysisTools live) => Register(new JsonObject
    {
        ["name"] = "ReadMemAtAddress",
        ["description"] = "Memory as lowercase hex (max 4096/call; byteCount not length/size). includeAscii/spacedHex add extras.",
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["address"] = new JsonObject { ["type"] = "string", ["description"] = "Address or expr, e.g. cip.", ["x-maxUtf8Bytes"] = 256, ["minLength"] = 1, ["x-nonblank"] = true },
                ["byteCount"] = IntRule(64, 1, 4096),
                ["includeAscii"] = BoolRule(false),
                ["spacedHex"] = BoolRule(false),
                ["includeUtf16"] = BoolRule(false, "Decode the bytes as UTF-16LE text up to NUL (adds utf16)."),
                ["autoPause"] = BoolRule(false, AutoPauseDescription),
                ["ranges"] = new JsonObject
                {
                    ["type"] = "array",
                    ["minItems"] = 1,
                    ["maxItems"] = 8,
                    ["description"] = "Up to 8 {address, byteCount}; total ≤16384B. One bad entry fails only its index.",
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
                }
            },
            ["x-requiresAnyOf"] = new JsonArray("address", "ranges"),
            ["additionalProperties"] = false
        }
    }, call => ReadMemoryAsync(context, live, call), lean: true,
        requiresExclusiveLease: AutoPauseRequiresExclusiveLease);

    /// <summary>
    /// ReadMemAtAddress with an optional managed decode: includeUtf16 appends
    /// the bytes as UTF-16LE text (stopping at NUL) so an agent reading a wide
    /// string does not have to hand-decode hex. The flag is MCP-only and is
    /// stripped before the bridge, which rejects unknown fields.
    /// </summary>
    private static async Task<string> ReadMemoryAsync(AnalysisContext context, LiveAnalysisTools live, ToolInvocation call)
    {
        var wantsUtf16 = ToolSupport.ReadArgumentBool(call.Arguments, "includeUtf16", false);
        var forward = StripAutoPause(wantsUtf16 ? WithoutKey(call.Arguments, "includeUtf16") : call.Arguments);
        var raw = ToolSupport.ReadArgumentBool(call.Arguments, "autoPause", false)
            ? await live.ExecuteReadWithAutoPauseAsync(call.Name, forward, call.CancellationToken).ConfigureAwait(false)
            : await context.Bridge.RequestAsync(call.Name, forward, call.CancellationToken).ConfigureAwait(false);
        return wantsUtf16 ? AppendUtf16(raw) : raw;
    }

    /// <summary>Adds a "utf16" field decoded from the hex "bytes" of a read.</summary>
    private static string AppendUtf16(string raw)
    {
        try
        {
            var root = JsonNode.Parse(raw);
            if (root?["ok"]?.GetValue<bool>() != true || root["result"] is not JsonObject result)
                return raw;
            if (result["bytes"] is not JsonValue value ||
                !value.TryGetValue<string>(out var hex) || string.IsNullOrEmpty(hex) ||
                hex.Length % 2 != 0)
                return raw;
            var bytes = new byte[hex.Length / 2];
            for (var index = 0; index < bytes.Length; index++)
            {
                if (!byte.TryParse(hex.AsSpan(index * 2, 2), NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture, out bytes[index]))
                    return raw;
            }
            var text = new StringBuilder(bytes.Length / 2);
            for (var index = 0; index + 1 < bytes.Length; index += 2)
            {
                var unit = (char)(bytes[index] | bytes[index + 1] << 8);
                if (unit == 0)
                    break;
                text.Append(unit);
                if (text.Length >= 256)
                    break;
            }
            result["utf16"] = text.ToString();
            return root.ToJsonString(ToolSupport.WireJsonOptions);
        }
        catch (JsonException) { return raw; }
        catch (ArgumentException) { return raw; }
    }
}

