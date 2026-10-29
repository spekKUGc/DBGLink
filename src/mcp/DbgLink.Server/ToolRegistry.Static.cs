using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    private static readonly HashSet<string> StaticBatchMethods = new(StringComparer.Ordinal)
    {
        "DumpStrings", "ReadStaticBytes", "Xrefs", "ListSymbols", "ListFunctions", "InspectFunction",
        "AnalyzeFunctions", "DecompileModule", "CallGraph",
        "TriageStrings", "TriageImports", "Triage", "GetAnalysisQueue"
    };

    private void RegisterStaticQueries(AnalysisContext context)
    {
        void Add(string name, string description, JsonObject properties, string[] required, bool advertised = true, string[]? requiresAnyOf = null, bool exclusiveAddressRanges = false)
        {
            properties["module"] = TextRule("Name/path of the Ghidra program. Does not load a module: use OpenGhidraFile and analysisId.", 2048);
            var schema = new JsonObject
            {
                ["type"] = "object", ["properties"] = properties,
                ["required"] = new JsonArray(required.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
                ["additionalProperties"] = false
            };
            if (requiresAnyOf is { Length: > 0 })
                schema["x-requiresAnyOf"] = new JsonArray(requiresAnyOf.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
            if (exclusiveAddressRanges)
                schema["x-exclusiveAddressRanges"] = true;
            Register(new JsonObject
            {
                ["name"] = name, ["description"] = description,
                ["inputSchema"] = schema
            }, call => SendStaticAsync(context)(call.Name, call.Arguments, call.CancellationToken), advertised: advertised, minimumTimeoutMs: 120_000);
        }
        JsonObject Page() => new()
        {
            ["offset"] = IntRule(0, 0, 1_000_000), ["maxItems"] = IntRule(128, 1, 128)
        };
        // Xrefs accepts the EXTERNAL:<offset> literals ListSymbols emits for imports
        // (direction=to; direction=both accepts them on the to side, the from side
        // honestly returns no rows). The Java address() resolver falls back to the
        // external symbol table / EXTERNAL space when parseAddress does not
        // round-trip EXTERNAL, so the literal resolves to the same Address object
        // ListSymbols used and sees the same reference-table rows as refCount.
        const string va = "Ghidra VA, not live. EXTERNAL ok for Xrefs(to).";
        const string filter = "Substring or '*' filter.";
        Add("ReadStaticBytes", "Image bytes as lowercase hex. Max 32768/call; page via address+length. ranges[]: up to 8 chunks, exclusive with address/length.", new()
        {
            ["address"] = TextRule(va), ["length"] = IntRule(256, 1, 32768),
            ["ranges"] = new JsonObject
            {
                ["type"] = "array", ["minItems"] = 1, ["maxItems"] = 8,
                ["description"] = "Up to 8 {address, length}; total ≤16384B. One bad entry fails only its index.",
                ["items"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["address"] = TextRule(va),
                        ["length"] = IntRule(128, 1, 4096)
                    },
                    ["required"] = new JsonArray("address"),
                    ["additionalProperties"] = false
                }
            }
        }, [], requiresAnyOf: ["address", "ranges"], exclusiveAddressRanges: true);
        var xrefs = Page();
        xrefs["maxItems"] = IntRule(16, 1, 128);
        xrefs["address"] = TextRule(va);
        xrefs["callsOnly"] = new JsonObject { ["type"] = "boolean", ["default"] = false };
        xrefs["direction"] = new JsonObject
        {
            ["type"] = "string", ["default"] = "to",
            ["pattern"] = "^(?i)(to|from|both)$",
            ["description"] = "Direction."
        };
        xrefs["offsetTo"] = IntRule(0, 0, 1_000_000, "Both-mode to-side offset; defaults to offset.");
        xrefs["offsetFrom"] = IntRule(0, 0, 1_000_000, "Both-mode from-side offset; defaults to offset.");
        xrefs["maxItemsTo"] = IntRule(16, 1, 128, "Both-mode to-side page size; defaults to maxItems.");
        xrefs["maxItemsFrom"] = IntRule(16, 1, 128, "Both-mode from-side page size; defaults to maxItems.");
        Register(new JsonObject
        {
            ["name"] = "Xrefs", ["description"] = "Static refs to/from an address with source functions. direction=both returns {to,from}; follow nextOffset.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object", ["properties"] = xrefs,
                ["required"] = new JsonArray("address", "direction"),
                ["additionalProperties"] = false
            }
        }, call =>
        {
            var method = ResolveXrefsMethod(call.Arguments);
            return context.Ghidra.RequestAsync(method, WithoutKey(call.Arguments, "direction"), call.CancellationToken);
        }, minimumTimeoutMs: 120_000);
        var symbols = Page(); symbols["filter"] = TextRule(filter);
        symbols["kind"] = new JsonObject
        {
            ["type"] = "string", ["default"] = "imports",
            ["pattern"] = "^(?i)(imports|exports|both)$",
            ["description"] = "Which to list."
        };
        symbols["maxSites"] = IntRule(0, 0, 32, "Cap on referenceSites; explicit 0 is refCount-only (>0 opts in alone). Omit for cap 8. Not for kind=exports.");
        symbols["includeSites"] = BoolRule(false, "Adds referenceSites, capped by maxSites; explicit maxSites:0 omits sites.");
        symbols["offsetImports"] = IntRule(0, 0, 1_000_000, "Both-mode imports-side offset; defaults to offset.");
        symbols["offsetExports"] = IntRule(0, 0, 1_000_000, "Both-mode exports-side offset; defaults to offset.");
        symbols["maxItemsImports"] = IntRule(128, 1, 128, "Both-mode imports-side page size; defaults to maxItems.");
        symbols["maxItemsExports"] = IntRule(128, 1, 128, "Both-mode exports-side page size; defaults to maxItems.");
        symbols["compact"] = BoolRule(false);
        Register(new JsonObject
        {
            ["name"] = "ListSymbols", ["description"] = "List imports/exports; imports carry refCount, sites opt-in via includeSites/maxSites. Follow nextOffset; compact:true -> {columns,rows}.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object", ["properties"] = symbols,
                ["required"] = new JsonArray("kind"),
                ["additionalProperties"] = false
            }
        }, call => SendStaticAsync(context)(call.Name, call.Arguments, call.CancellationToken),
            minimumTimeoutMs: 120_000);
        var functions = Page();
        functions["start"] = TextRule("Range start. " + va);
        functions["end"] = TextRule("Range end. " + va);
        functions["filter"] = TextRule(filter);
        functions["overlapping"] = new JsonObject { ["type"] = "boolean", ["default"] = true,
            ["description"] = "True: body intersects range. False: entry lies in range. size counts body bytes." };
        functions["compact"] = BoolRule(false);
        functions["includeCounts"] = BoolRule(false, "Instruction/branch counts.");
        Add("ListFunctions", "Index functions: sparse rows (name, entry, size). Follow nextOffset; compact:true -> {columns,rows}.", functions, []);

        Register(new JsonObject
        {
            ["name"] = "BatchStaticQueries",
            ["description"] = "1-16 static reads in one round trip: requests:[{method:\"ListFunctions\",arguments:{maxItems:16}}]. Mixed families rejected by index; follow nextIndex/nextOffset.",
            ["inputSchema"] = BatchInputSchema("An allowed static read tool name.")
        }, call => ExecuteBatchAsync(call, SendStaticAsync(context), StaticBatchMethods,
            static method => $"Batch contains '{method}', which is not a static read query. " +
                "Send debugger operations via BatchDebuggerOperations instead. " +
                "Do not poll: each batch is atomic; resume truncated batches at nextIndex and paged reads at nextOffset.",
            deadlineMilliseconds: 110_000, rejectNestedAnalysisId: true,
            localDispatch: LocalStaticAsync(context), parallelReads: true),
            lean: true, minimumTimeoutMs: 120_000);
    }

    /// <summary>
    /// P0-1 local fan-out (round-trip plan C2): triage composites and the
    /// analysis queue run in-process; every other admitted method keeps the
    /// bridge sender. Only called for methods in LocalBatchMethods, so the
    /// fallback is unreachable defense-in-depth, never a routing decision.
    /// </summary>
    private static Func<string, JsonElement?, CancellationToken, Task<string>> LocalStaticAsync(AnalysisContext context)
    {
        var triage = new TriageImportsTools(context);
        var send = SendStaticAsync(context);
        return (method, arguments, token) => method switch
        {
            "TriageStrings" => triage.TriageStringsAsync(arguments, token),
            "TriageImports" => triage.TriageImportsAsync(arguments, token),
            "Triage" => triage.TriageAsync(arguments, token),
            "GetAnalysisQueue" => ExecuteAnalysisQueueAsync(context, arguments, token),
            _ => send(method, arguments, token),
        };
    }

    private static Func<string, JsonElement?, CancellationToken, Task<string>> SendStaticAsync(AnalysisContext context)
        => (method, arguments, token) =>
        {
            if (string.Equals(method, "Xrefs", StringComparison.Ordinal))
            {
                return context.Ghidra.RequestAsync(ResolveXrefsMethod(arguments), WithoutKey(arguments, "direction"), token);
            }
            if (string.Equals(method, "ListSymbols", StringComparison.Ordinal))
            {
                var (bridge, args) = ResolveSymbolsRequest(arguments);
                return RequestRowsAsync(context.Ghidra, bridge, args, ["imports", "exports"], token);
            }
            if (string.Equals(method, "ListFunctions", StringComparison.Ordinal))
            {
                return RequestRowsAsync(context.Ghidra, method, arguments, ["functions"], token);
            }
            return context.Ghidra.RequestAsync(method, arguments, token);
        };

    /// <summary>
    /// P5: the compact flag is a server-side presentation choice. Strip it
    /// before the bridge (whose schemas reject unknown fields), then rewrite
    /// only the named row arrays when the caller opted in.
    /// </summary>
    private static async Task<string> RequestRowsAsync(
        IGhidraClient ghidra, string method, JsonElement? arguments,
        string[] arrayKeys, CancellationToken cancellationToken)
    {
        var compact = ToolSupport.ReadArgumentBool(arguments, "compact", false);
        var forwarded = WithoutKey(arguments, "compact");
        var raw = await ghidra.RequestAsync(method, forwarded, cancellationToken).ConfigureAwait(false);
        return compact ? ToolPresentation.Compact(raw, arrayKeys) : raw;
    }

    /// <summary>Single Xrefs routing rule for the direct tool and the static
    /// batch sender: trims the direction so a padded value such as " from "
    /// still routes to XrefsFrom. Unknown values fall back to XrefsTo.</summary>
    private static string ResolveXrefsMethod(JsonElement? arguments)
    {
        var direction = (ToolSupport.ReadArgumentString(arguments, "direction") ?? "to").Trim();
        return string.Equals(direction, "from", StringComparison.OrdinalIgnoreCase) ? "XrefsFrom"
            : string.Equals(direction, "both", StringComparison.OrdinalIgnoreCase) ? "XrefsBoth" : "XrefsTo";
    }

    /// <summary>Single ListSymbols routing rule for the direct tool and the
    /// static batch sender: trims the kind so " exports " no longer misroutes
    /// to ListImports, and strips the imports-only site knobs for exports.</summary>
    private static (string Method, JsonElement? Arguments) ResolveSymbolsRequest(JsonElement? arguments)
    {
        var kind = (ToolSupport.ReadArgumentString(arguments, "kind") ?? "imports").Trim();
        var isExport = string.Equals(kind, "exports", StringComparison.OrdinalIgnoreCase);
        var isBoth = string.Equals(kind, "both", StringComparison.OrdinalIgnoreCase);
        var args = WithoutKey(arguments, "kind");
        if (isExport)
        {
            args = WithoutKey(args, "maxSites");
            args = WithoutKey(args, "includeSites");
        }
        return (isBoth ? "ListSymbolsBoth" : isExport ? "ListExports" : "ListImports", args);
    }

    private static JsonElement? WithoutKey(JsonElement? arguments, string key)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object })
            return arguments;
        // Fast path: skip the JsonNode parse/reserialize round-trip when the
        // selector key is absent (the common case for already-canonical calls).
        if (!arguments.Value.TryGetProperty(key, out _))
            return arguments;
        var node = JsonNode.Parse(arguments.Value.GetRawText())!.AsObject();
        node.Remove(key);
        return JsonSerializer.SerializeToElement(node);
    }

    private void RegisterStaticInspection(AnalysisContext context)
    {
        RegisterGhidra(context, new JsonObject
        {
            ["name"] = "InspectFunction",
            ["description"] = "Decompile one function with callers/callees/xrefs.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["function"] = NonBlankText("Ghidra function address, RVA, or name.", 256),
                    ["maxChars"] = IntRule(16000, 1000, 120000),
                    ["maxItems"] = IntRule(16, 1, 512),
                    ["includeDecomp"] = BoolRule(true),
                    ["includeDisassembly"] = BoolRule(false),
                    ["includeReferences"] = BoolRule(true),
                    ["includeSymbols"] = BoolRule(false),
                    ["includeStrings"] = BoolRule(false,
                        "Include body-referenced strings (address, value)."),
                    ["includeConstants"] = BoolRule(false,
                        "Include scalar operands (value, count, firstAddress).")
                },
                ["required"] = new JsonArray("function"),
                ["examples"] = new JsonArray(new JsonObject { ["function"] = "main" }),
                ["additionalProperties"] = false
            }
        }, lean: true, minimumTimeoutMs: 120_000);

        RegisterGhidra(context, new JsonObject
        {
            ["name"] = "AnalyzeFunctions",
            ["description"] = "Digest 1-8 functions: identity, callers/callees, strings, constants; C only with includeDecomp:true. functions XOR start; one shared budget. Follow nextIndex/nextStart.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["functions"] = new JsonObject
                    {
                        ["type"] = "array",
                        ["minItems"] = 1,
                        ["maxItems"] = 8,
                        ["items"] = NonBlankText("Ghidra function address, RVA, or name.", 256)
                    },
                    ["start"] = Utf8Text("Ordered slice from an entry/RVA/name; returns maxFunctions functions. Mutually exclusive with functions.", 256),
                    ["maxFunctions"] = IntRule(8, 1, 8, "Slice size for start mode."),
                    ["maxChars"] = IntRule(24000, 1000, 120000),
                    ["maxItems"] = IntRule(4, 1, 32, "Per-function section cap."),
                    ["includeComments"] = BoolRule(false),
                    ["includePrototype"] = BoolRule(false),
                    ["includeDecomp"] = BoolRule(false,
                        "Decompiled C per function. false returns the C-free digest and skips the decompiler.")
                },
                ["examples"] = new JsonArray(new JsonObject
                {
                    ["functions"] = new JsonArray("main", "0x140001040")
                }),
                ["additionalProperties"] = false
            }
        }, lean: true, minimumTimeoutMs: 120_000);

        RegisterGhidra(context, new JsonObject
        {
            ["name"] = "DecompileModule",
            ["description"] = "Bounded Ghidra decompilation for the active module, address-ordered. Read summary for identity, counts, next step.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["module"] = Utf8Text("Active-program path or file name; no external file is opened.", 2048),
                    ["start"] = Utf8Text("Inclusive entry/RVA/name to continue an address-ordered slice; use nextFunction.", 256),
                    ["maxFunctions"] = IntRule(8, 1, 128,
                        "Upper bound, not a guaranteed count; the shared 30-second budget may return a partial slice. Continue with start=nextFunction."),
                    ["maxChars"] = IntRule(24000, 1000, 120000),
                    ["includePrototype"] = BoolRule(false)
                },
                ["examples"] = new JsonArray(new JsonObject { ["maxFunctions"] = 8 }),
                ["additionalProperties"] = false }
            },
            minimumTimeoutMs: 120_000);
    }
}
