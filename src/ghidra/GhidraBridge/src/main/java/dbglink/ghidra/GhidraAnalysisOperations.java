package dbglink.ghidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import static dbglink.ghidra.GhidraBridgeServer.*;

final class GhidraAnalysisOperations {
    // The module listing is a decompilation sample, not an analysis card:
    // skip the per-function instruction walk that only InspectFunction needs.
    static final int DECOMPILE_HEAD_FLAGS =
        GhidraAnalysisFormatting.HEAD_RVA | GhidraAnalysisFormatting.HEAD_ANALYSIS_LEAN;

    private final Supplier<Program> programSupplier;
    private final GhidraDecompiler decompiler = new GhidraDecompiler();

    GhidraAnalysisOperations(Supplier<Program> programSupplier) {
        this.programSupplier = programSupplier;
    }

    void close() {
        decompiler.close();
    }

    JsonObject status() {
        JsonObject result = new JsonObject();
        Program program = programSupplier.get();
        result.addProperty("protocolVersion", PROTOCOL_VERSION);
        result.addProperty("available", program != null);
        result.addProperty("endpoint", "127.0.0.1");
        if (program != null) {
            result.addProperty("executablePath", clipped(
                GhidraAnalysisFormatting.displayExecutablePath(program),
                2048));
            result.addProperty("sha256", clipped(program.getExecutableSHA256(), 128));
            result.addProperty("minAddress", program.getMinAddress().toString());
            result.addProperty("maxAddress", program.getMaxAddress().toString());
            result.add("program", GhidraAnalysisFormatting.programSummary(program));
        }
        return result;
    }

    JsonObject inspectFunction(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, INSPECT_FIELDS, "InspectFunction");
        String selector = requiredString(params, "function", MAX_SELECTOR_CHARS);
        // One function, not a module: the compact defaults keep the C output
        // useful without paying for 32 rows per reference side.
        int maxChars = boundedInt(params, "maxChars", 16_000, 1_000, MAX_CHARS);
        int maxItems = boundedInt(params, "maxItems", 16, 1, MAX_ITEMS);
        boolean includeDecomp = boundedBoolean(params, "includeDecomp", true);
        boolean includeDisassembly = boundedBoolean(params, "includeDisassembly", false);
        boolean includeReferences = boundedBoolean(params, "includeReferences", true);
        boolean includeSymbols = boundedBoolean(params, "includeSymbols", false);
        boolean includeStrings = boundedBoolean(params, "includeStrings", false);
        boolean includeConstants = boundedBoolean(params, "includeConstants", false);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        Function function = resolveFunction(program, selector);
        GhidraOutputBudget budget = new GhidraOutputBudget(maxChars);
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 2);
        result.add("function", GhidraAnalysisFormatting.functionIdentity(program, function));

        if (includeDecomp) {
            JsonObject decompilation = decompiler.decompile(program, function, budget);
            // function.prototype already carries the signature; shipping the
            // same string again inside the C block doubled it on every card.
            decompilation.remove("signature");
            result.add("decompilation", decompilation);
        }
        if (includeDisassembly) {
            result.add("disassembly", GhidraAnalysisFormatting.disassembly(program, function, maxItems, budget));
        }
        if (includeReferences) {
            result.add("references", GhidraAnalysisFormatting.references(program, function, maxItems, budget));
        }
        if (includeSymbols) {
            JsonObject symbolsAndTypes = GhidraAnalysisFormatting.symbolsAndTypes(function, maxItems, budget);
            result.add("symbols", symbolsAndTypes.get("symbols"));
            result.add("types", symbolsAndTypes.get("types"));
        }
        if (includeStrings) {
            result.add("strings", GhidraAnalysisFormatting.functionStrings(program, function, maxItems, budget));
        }
        if (includeConstants) {
            result.add("constants", GhidraAnalysisFormatting.functionConstants(program, function, maxItems, budget));
        }
        if (includeDecomp && includeDisassembly) {
            result.add("fidelity", fidelityCheck(program, function, result.getAsJsonArray("disassembly")));
        }
        result.addProperty("truncated", budget.truncated);
        if (budget.truncated) {
            result.add("truncatedSections", budget.truncatedSections());
            result.addProperty("continuation", "Repeat with higher maxItems/maxChars; disable unneeded include flags to focus the response.");
        }
        result.addProperty("maxChars", maxChars);
        result.addProperty("maxItems", maxItems);
        result.add("summary", inspectSummary(
            function,
            result,
            includeDecomp,
            includeDisassembly,
            includeReferences,
            includeSymbols,
            includeStrings,
            includeConstants,
            budget));
        return result;
    }

    JsonObject decompileModule(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, DECOMPILE_MODULE_FIELDS, "DecompileModule");
        String moduleSelector = optionalString(params, "module", 2_048);
        String functionSelector = optionalString(params, "function", MAX_SELECTOR_CHARS);
        String startSelector = optionalString(params, "start", MAX_SELECTOR_CHARS);
        if (!functionSelector.isEmpty() && !startSelector.isEmpty()) {
            throw new BridgeFailure("invalid_argument", "function and start cannot be used together");
        }
        int maxFunctions = boundedInt(
            params,
            "maxFunctions",
            DEFAULT_MAX_FUNCTIONS,
            1,
            MAX_MODULE_FUNCTIONS
        );
        int maxChars = boundedInt(params, "maxChars", DEFAULT_MAX_CHARS, 1_000, MAX_CHARS);
        boolean includePrototype = boundedBoolean(params, "includePrototype", false);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        if (!matchesActiveModule(program, moduleSelector)) {
            throw new BridgeFailure("module_not_found", "module selector does not match the active Ghidra program");
        }

        GhidraOutputBudget budget = new GhidraOutputBudget(maxChars);
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 2);
        result.add("module", moduleIdentity(program));
        if (!functionSelector.isEmpty()) {
            result.addProperty("selector", functionSelector);
        }
        if (!startSelector.isEmpty()) {
            result.addProperty("start", startSelector);
        }
        result.addProperty("maxFunctions", maxFunctions);
        result.addProperty("maxChars", maxChars);

        JsonArray functions = new JsonArray();
        Iterator<Function> iterator;
        if (!functionSelector.isEmpty()) {
            iterator = List.of(resolveFunction(program, functionSelector)).iterator();
        }
        else if (!startSelector.isEmpty()) {
            Function startFunction = resolveFunction(program, startSelector);
            iterator = program.getFunctionManager().getFunctions(startFunction.getEntryPoint(), true);
        }
        else {
            iterator = program.getFunctionManager().getFunctions(true);
        }
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        int scannedFunctions = 0;
        boolean timedOut = false;
        while (iterator.hasNext() && functions.size() < maxFunctions && budget.remaining > 0) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0 || (requestMonitor.get() != null && requestMonitor.get().isCancelled())) {
                timedOut = true;
                break;
            }

            Function function = iterator.next();
            scannedFunctions++;
            JsonObject entry = GhidraAnalysisFormatting.functionHead(
                program,
                function,
                DECOMPILE_HEAD_FLAGS |
                    (includePrototype ? GhidraAnalysisFormatting.HEAD_PROTOTYPE : 0),
                "signature");
            // The module listing charges the shared output budget for the text
            // it emits; the head only clips, so recharge name/signature here
            // in the historical take order (name first, then signature).
            // addProperty replaces the value in place, so key order is unchanged.
            entry.addProperty("name", budget.take(entry.get("name").getAsString()));
            if (includePrototype) {
                entry.addProperty("signature", budget.take(entry.get("signature").getAsString()));
            }

            int timeoutSeconds = (int)Math.max(
                1,
                Math.min(
                    MAX_DECOMP_SECONDS,
                    (remaining + TimeUnit.SECONDS.toNanos(1) - 1) / TimeUnit.SECONDS.toNanos(1)
                )
            );
            JsonObject decompilation = decompiler.decompile(program, function, budget, timeoutSeconds);
            entry.add("decompilation", decompilation);
            functions.add(entry);
            if ("timeout".equals(decompilation.get("status").getAsString())) {
                timedOut = true;
                break;
            }
        }

        boolean hasMoreFunctions = iterator.hasNext();
        Function nextFunction = hasMoreFunctions ? iterator.next() : null;
        boolean functionLimitReached = functionSelector.isEmpty() && functions.size() >= maxFunctions && hasMoreFunctions;
        boolean outputBudgetReached = budget.remaining <= 0 && hasMoreFunctions;
        result.add("functions", functions);
        result.addProperty("scannedFunctions", scannedFunctions);
        result.addProperty("includedFunctions", functions.size());
        result.addProperty("timedOut", timedOut);
        result.addProperty(
            "truncated",
            budget.truncated || timedOut || functionLimitReached || outputBudgetReached
        );
        if (nextFunction != null) {
            result.addProperty("nextFunction", nextFunction.getEntryPoint().toString());
        }
        result.add("summary", moduleSummary(functions, functionSelector, nextFunction != null));
        return result;
    }

    /**
     * Read-only internal call graph for the active module or an address
     * range: function nodes (name/entry/rva/instructionCount) plus aggregated
     * caller-to-callee edges with per-pair call counts. Bounded by
     * maxNodes/maxEdges with a nextStart continuation cursor.
     * Edges default to integer-indexed {s, t, n} (schemaVersion 3 token win);
     * pass edgeFormat=full for the legacy {caller, callee, count} shape.
     */
    JsonObject callGraph(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, CALLGRAPH_FIELDS, "CallGraph");
        String moduleSelector = optionalString(params, "module", 2_048);
        String functionText = optionalString(params, "function", MAX_SELECTOR_CHARS);
        int depth = boundedInt(params, "depth", 1, 1, 2);
        String direction = optionalString(params, "direction", 16).toLowerCase(java.util.Locale.ROOT);
        if (!direction.isEmpty() && !direction.equals("callers") && !direction.equals("callees")
            && !direction.equals("both")) {
            throw new BridgeFailure("invalid_argument", "direction must be \"callers\", \"callees\" or \"both\"");
        }
        String startText = optionalString(params, "start", MAX_SELECTOR_CHARS);
        String endText = optionalString(params, "end", MAX_SELECTOR_CHARS);
        int maxNodes = boundedInt(params, "maxNodes", DEFAULT_CALLGRAPH_NODES, 1, MAX_CALLGRAPH_NODES);
        int maxEdges = boundedInt(params, "maxEdges", DEFAULT_CALLGRAPH_EDGES, 1, MAX_CALLGRAPH_EDGES);
        boolean includeInstructionCount = boundedBoolean(params, "includeInstructionCount", false);
        String edgeFormat = optionalString(params, "edgeFormat", 16);
        if (!edgeFormat.isEmpty() && !edgeFormat.equals("indexed") && !edgeFormat.equals("full")) {
            throw new BridgeFailure("invalid_argument", "edgeFormat must be \"indexed\" or \"full\"");
        }

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        if (!matchesActiveModule(program, moduleSelector)) {
            throw new BridgeFailure("module_not_found", "module selector does not match the active Ghidra program");
        }

        if (!functionText.isEmpty()) {
            if (!startText.isEmpty() || !endText.isEmpty()) {
                throw new BridgeFailure("invalid_argument",
                    "function selects a neighborhood; omit start/end (use depth/direction to bound it)");
            }
            Function seed = resolveFunction(program, functionText);
            JsonObject graph = GhidraAnalysisFormatting.callGraphNeighborhood(
                program,
                seed,
                depth,
                direction.isEmpty() ? "both" : direction,
                maxNodes,
                maxEdges,
                includeInstructionCount,
                edgeFormat);
            return callGraphNeighborhoodResult(program, seed, graph);
        }

        Address start = startText.isEmpty() ? program.getMinAddress() : GhidraStaticQueries.address(program, startText);
        Address end = endText.isEmpty() ? program.getMaxAddress() : GhidraStaticQueries.address(program, endText);
        if (!start.getAddressSpace().equals(end.getAddressSpace()) || start.compareTo(end) > 0) {
            throw new BridgeFailure("invalid_argument", "start and end must form an inclusive range in one address space");
        }

        JsonObject graph = GhidraAnalysisFormatting.callGraph(program, start, end, maxNodes, maxEdges, includeInstructionCount, edgeFormat);
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 3);
        JsonObject module = new JsonObject();
        module.addProperty("path", clipped(
            GhidraAnalysisFormatting.displayExecutablePath(program),
            2_048));
        module.addProperty("imageBase", program.getImageBase().toString());
        result.add("module", module);
        result.add("nodes", graph.getAsJsonArray("nodes"));
        result.add("edges", graph.getAsJsonArray("edges"));
        result.addProperty("totalCalls", graph.get("totalCalls").getAsInt());
        result.addProperty("truncated", graph.get("truncated").getAsBoolean());
        if (graph.has("nextStart")) {
            result.addProperty("nextStart", graph.get("nextStart").getAsString());
        }
        if (graph.has("continuation")) {
            result.addProperty("continuation", graph.get("continuation").getAsString());
        }
        if (graph.has("scanLimited")) {
            result.addProperty("scanLimited", true);
        }
        if (graph.get("timedOut").getAsBoolean()) {
            result.addProperty("timedOut", true);
        }
        result.add("summary", callGraphSummary(result, graph));
        return result;
    }

    private static JsonObject callGraphSummary(JsonObject result, JsonObject graph) {
        JsonObject summary = new JsonObject();
        summary.addProperty("nodeCount", result.getAsJsonArray("nodes").size());
        summary.addProperty("edgeCount", result.getAsJsonArray("edges").size());
        summary.addProperty("totalCalls", result.get("totalCalls").getAsInt());
        summary.addProperty("truncated", result.get("truncated").getAsBoolean());
        summary.addProperty(
            "nextAction",
            graph.has("nextStart")
                ? "Repeat CallGraph with start set to nextStart to continue the address-ordered slice."
                : result.get("truncated").getAsBoolean()
                    ? "Repeat CallGraph with higher maxEdges or a narrower start/end range."
                    : "Use InspectFunction on one node for decompilation and live mapping.");
        return summary;
    }

    /**
     * Neighborhood envelope: the seed identity plus a BFS-bounded induced
     * graph and a risk-ranked nextBest list. schemaVersion 4 is only used in
     * this mode; the historical range graph stays at 3.
     */
    private static JsonObject callGraphNeighborhoodResult(Program program, Function seed, JsonObject graph) {
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 4);
        result.addProperty("mode", "neighborhood");
        JsonObject module = new JsonObject();
        module.addProperty("path", clipped(
            GhidraAnalysisFormatting.displayExecutablePath(program),
            2_048));
        module.addProperty("imageBase", program.getImageBase().toString());
        result.add("module", module);
        result.add("seed", GhidraAnalysisFormatting.functionHead(
            program, seed, GhidraAnalysisFormatting.HEAD_RVA, null));
        result.add("nodes", graph.getAsJsonArray("nodes"));
        result.add("edges", graph.getAsJsonArray("edges"));
        result.addProperty("totalCalls", graph.get("totalCalls").getAsInt());
        result.addProperty("truncated", graph.get("truncated").getAsBoolean());
        result.add("nextBest", graph.getAsJsonArray("nextBest"));
        if (graph.has("frontier")) {
            result.add("frontier", graph.getAsJsonArray("frontier"));
        }
        if (graph.has("frontierTruncated")) {
            result.addProperty("frontierTruncated", true);
        }
        if (graph.has("continuation")) {
            result.addProperty("continuation", graph.get("continuation").getAsString());
        }
        if (graph.has("scanLimited")) {
            result.addProperty("scanLimited", true);
        }
        if (graph.has("timedOut")) {
            result.addProperty("timedOut", true);
        }
        result.add("summary", callGraphNeighborhoodSummary(result));
        return result;
    }

    private static JsonObject callGraphNeighborhoodSummary(JsonObject result) {
        JsonObject summary = new JsonObject();
        summary.addProperty("nodeCount", result.getAsJsonArray("nodes").size());
        summary.addProperty("edgeCount", result.getAsJsonArray("edges").size());
        summary.addProperty("totalCalls", result.get("totalCalls").getAsInt());
        summary.addProperty("truncated", result.get("truncated").getAsBoolean());
        JsonArray nextBest = result.getAsJsonArray("nextBest");
        if (nextBest.size() > 0) {
            JsonObject top = nextBest.get(0).getAsJsonObject();
            String entry = top.has("entry") ? top.get("entry").getAsString() : "";
            summary.addProperty("nextAction",
                "InspectFunction " + entry
                    + " with includeDecomp:false, or use it as the next CallGraph seed.");
        }
        else if (result.get("truncated").getAsBoolean()) {
            summary.addProperty("nextAction",
                "Continue from a frontier entry as function, or increase maxNodes/maxEdges.");
        }
        else {
            summary.addProperty("nextAction", "No neighbors matched the requested direction.");
        }
        return summary;
    }

    static JsonObject inspectSummary(
        Function function,
        JsonObject result,
        boolean includeDecomp,
        boolean includeDisassembly,
        boolean includeReferences,
        boolean includeSymbols,
        boolean includeStrings,
        boolean includeConstants,
        GhidraOutputBudget budget
    ) {
        // The identity and analysis already live in result.function; the
        // summary only adds the counters and the next-step hint.
        JsonObject summary = new JsonObject();
        JsonArray includedSections = new JsonArray();
        if (includeDecomp) {
            includedSections.add("decompilation");
            JsonElement decompilation = result.get("decompilation");
            summary.addProperty("decompilationStatus",
                decompilation != null && decompilation.isJsonObject() && decompilation.getAsJsonObject().has("status")
                    ? decompilation.getAsJsonObject().get("status").getAsString()
                    : "unknown");
        }
        else {
            summary.addProperty("decompilationStatus", "not_requested");
        }
        if (includeDisassembly) includedSections.add("disassembly");
        if (includeReferences) {
            includedSections.add("references");
            JsonElement references = result.get("references");
            if (references != null && references.isJsonObject()) {
                JsonObject referenceObject = references.getAsJsonObject();
                addArrayCount(summary, referenceObject, "callers", "callersReturned");
                addArrayCount(summary, referenceObject, "callees", "calleesReturned");
                addArrayCount(summary, referenceObject, "xrefsTo", "xrefsToReturned");
                addArrayCount(summary, referenceObject, "xrefsFrom", "xrefsFromReturned");
            }
        }
        if (includeSymbols) {
            includedSections.add("symbols");
            includedSections.add("types");
        }
        if (includeStrings) {
            includedSections.add("strings");
            addArrayCount(summary, result, "strings", "stringsReturned");
        }
        if (includeConstants) {
            includedSections.add("constants");
            addArrayCount(summary, result, "constants", "constantsReturned");
        }
        summary.add("includedSections", includedSections);
        summary.addProperty("truncated", budget.truncated);
        summary.addProperty(
            "nextAction",
            budget.truncated
                ? "Repeat InspectFunction with higher maxItems/maxChars or disable optional sections."
                : "Map this function to the live debugger with MapStaticFunctionToLive when correlation is needed.");
        return summary;
    }

    private static void addArrayCount(JsonObject target, JsonObject source, String propertyName, String summaryName) {
        JsonElement value = source.get(propertyName);
        if (value != null && value.isJsonArray()) {
            target.addProperty(summaryName, value.getAsJsonArray().size());
        }
    }

    /**
     * Digest of 1-8 functions in one call: identity, decompilation, short
     * callers/callees, referenced strings and significant constants. Explicit
     * selectors keep their order and report resolution failures per index
     * while the remaining selectors still run; start mode walks functions in
     * address order for continuation. One shared output budget cuts later
     * entries; truncatedSections names the sections it touched.
     */
    JsonObject analyzeFunctions(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, ANALYZE_FUNCTIONS_FIELDS, "AnalyzeFunctions");
        JsonElement functionsElement = params.get("functions");
        String startSelector = optionalString(params, "start", MAX_SELECTOR_CHARS);
        boolean explicitSelectors = functionsElement != null && !functionsElement.isJsonNull();
        if (explicitSelectors && !startSelector.isEmpty()) {
            throw new BridgeFailure("invalid_argument", "functions and start cannot be used together");
        }
        List<String> selectors = new ArrayList<>();
        if (explicitSelectors) {
            if (!functionsElement.isJsonArray()) {
                throw new BridgeFailure("invalid_argument", "functions must be an array");
            }
            JsonArray requested = functionsElement.getAsJsonArray();
            if (requested.isEmpty()) {
                throw new BridgeFailure("missing_argument", "functions must not be empty");
            }
            if (requested.size() > MAX_ANALYZE_FUNCTIONS) {
                throw new BridgeFailure("argument_out_of_range", "functions is outside the allowed range");
            }
            for (int index = 0; index < requested.size(); index++) {
                JsonElement element = requested.get(index);
                if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
                    throw new BridgeFailure("invalid_argument", "functions[" + index + "] must be a string");
                }
                String selector = element.getAsString();
                validateTextCharacters(selector, "functions[" + index + "]", false);
                selector = selector.trim();
                if (selector.isEmpty()) {
                    throw new BridgeFailure("invalid_argument", "functions[" + index + "] must not be empty");
                }
                if (selector.length() > MAX_SELECTOR_CHARS) {
                    throw new BridgeFailure("argument_too_long",
                        "functions[" + index + "] exceeds the character limit");
                }
                selectors.add(selector);
            }
        }
        else if (startSelector.isEmpty()) {
            throw new BridgeFailure("missing_argument", "functions or start is required");
        }

        int maxFunctions = boundedInt(params, "maxFunctions", DEFAULT_MAX_FUNCTIONS, 1, MAX_ANALYZE_FUNCTIONS);
        int maxChars = boundedInt(params, "maxChars", DEFAULT_MAX_CHARS, 1_000, MAX_CHARS);
        int maxItems = boundedInt(params, "maxItems", DEFAULT_ANALYZE_ITEMS, 1, MAX_ANALYZE_ITEMS);
        boolean includeComments = boundedBoolean(params, "includeComments", false);
        boolean includePrototype = boundedBoolean(params, "includePrototype", false);
        boolean includeDecomp = boundedBoolean(params, "includeDecomp", false);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        GhidraOutputBudget budget = new GhidraOutputBudget(maxChars);
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 2);
        result.add("module", moduleIdentity(program));
        // maxChars/maxItems are caller inputs, not results: the caller already
        // knows what it sent, and the echo only grew every digest response.

        JsonArray entries = new JsonArray();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        boolean timedOut = false;
        int nextIndex = -1;
        Function nextFunction = null;
        if (explicitSelectors) {
            for (int index = 0; index < selectors.size(); index++) {
                boolean cancelled = requestMonitor.get() != null && requestMonitor.get().isCancelled();
                if (budget.remaining <= 0 || System.nanoTime() >= deadline || cancelled) {
                    timedOut = System.nanoTime() >= deadline || cancelled;
                    nextIndex = index;
                    break;
                }
                String selector = selectors.get(index);
                Function function;
                try {
                    function = resolveFunction(program, selector);
                }
                catch (BridgeFailure failure) {
                    JsonObject row = new JsonObject();
                    row.addProperty("index", index);
                    row.addProperty("selector", clipped(selector, MAX_SELECTOR_CHARS));
                    row.addProperty("ok", false);
                    row.addProperty("code", "not_found");
                    row.addProperty("message", clipped(failure.getMessage(), 256));
                    entries.add(row);
                    continue;
                }
                JsonObject entry = analyzeFunctionEntry(
                    program, function, maxItems, budget, deadline, includePrototype, includeComments, includeDecomp);
                entries.add(entry);
                if (decompilationTimedOut(entry)) {
                    timedOut = true;
                    if (index + 1 < selectors.size()) {
                        nextIndex = index + 1;
                    }
                    break;
                }
            }
        }
        else {
            Function startFunction = resolveFunction(program, startSelector);
            Iterator<Function> iterator = program.getFunctionManager().getFunctions(
                startFunction.getEntryPoint(), true);
            while (iterator.hasNext() && entries.size() < maxFunctions) {
                long remaining = deadline - System.nanoTime();
                boolean cancelled = requestMonitor.get() != null && requestMonitor.get().isCancelled();
                if (remaining <= 0 || budget.remaining <= 0 || cancelled) {
                    timedOut = remaining <= 0 || cancelled;
                    break;
                }
                Function function = iterator.next();
                JsonObject entry = analyzeFunctionEntry(
                    program, function, maxItems, budget, deadline, includePrototype, includeComments, includeDecomp);
                entries.add(entry);
                if (decompilationTimedOut(entry)) {
                    timedOut = true;
                    break;
                }
            }
            if (iterator.hasNext()) {
                nextFunction = iterator.next();
            }
        }

        result.add("functions", entries);
        // Triage shortcut: rows whose names came from a known origin (FID
        // database, PDB/DWARF, imports) can be skipped first; DEFAULT-named
        // rows still need review. not_found rows carry no function object.
        int libraryMatched = 0;
        for (JsonElement element : entries) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject row = element.getAsJsonObject();
            JsonElement functionElement = row.get("function");
            if (functionElement != null && functionElement.isJsonObject()) {
                JsonElement source = functionElement.getAsJsonObject().get("nameSource");
                if (source != null && source.isJsonPrimitive() &&
                    ("ANALYSIS".equals(source.getAsString()) || "IMPORTED".equals(source.getAsString()))) {
                    libraryMatched++;
                }
            }
        }
        result.addProperty("libraryMatched", libraryMatched);
        result.addProperty("truncated", budget.truncated || timedOut || nextIndex >= 0 || nextFunction != null);
        result.add("truncatedSections", budget.truncatedSections());
        if (timedOut) {
            result.addProperty("timedOut", true);
        }
        // Cursor-only continuation: nextIndex/nextStart already say where to
        // resume, so no prose travels with them.
        if (nextIndex >= 0) {
            result.addProperty("nextIndex", nextIndex);
        }
        if (nextFunction != null) {
            result.addProperty("nextStart", nextFunction.getEntryPoint().toString());
        }
        return result;
    }

    private JsonObject analyzeFunctionEntry(
        Program program,
        Function function,
        int maxItems,
        GhidraOutputBudget budget,
        long deadline,
        boolean includePrototype,
        boolean includeComments,
        boolean includeDecomp
    ) throws BridgeFailure {
        // Success entries stay sparse: order matches the request selectors and
        // module identity hoists to the envelope. Only failures carry
        // index/selector/ok/code/message.
        JsonObject entry = new JsonObject();
        entry.add("function", GhidraAnalysisFormatting.functionDigest(program, function, includePrototype, includeComments));
        if (includeDecomp) {
            long remaining = Math.max(0, deadline - System.nanoTime());
            int timeoutSeconds = (int)Math.max(
                1,
                Math.min(MAX_DECOMP_SECONDS, (remaining + TimeUnit.SECONDS.toNanos(1) - 1) / TimeUnit.SECONDS.toNanos(1))
            );
            entry.add("decompilation", decompiler.decompile(program, function, budget, timeoutSeconds));
        }
        entry.add("references", GhidraAnalysisFormatting.referencesBrief(program, function, maxItems, budget));
        entry.add("strings", GhidraAnalysisFormatting.functionStrings(program, function, maxItems, budget));
        entry.add("constants", GhidraAnalysisFormatting.functionConstants(program, function, maxItems, budget));
        return entry;
    }

    /** Decompilation is optional; a digest entry has no decompilation object at all. */
    private static boolean decompilationTimedOut(JsonObject entry) {
        JsonElement decompilation = entry.get("decompilation");
        return decompilation != null && decompilation.isJsonObject() &&
            "timeout".equals(decompilation.getAsJsonObject().get("status").getAsString());
    }

    /**
     * Bottom-up worklist: the next N functions leaves-first (callees before
     * callers) with short identity metadata. Read-only; no persistence.
     * Skips EXTERNAL imports like the listings do; ties break by body size,
     * then name, so the order is deterministic.
     */
    JsonObject analysisQueue(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, ANALYSIS_QUEUE_FIELDS, "AnalysisQueue");
        int limit = boundedInt(params, "limit", DEFAULT_MAX_FUNCTIONS, 1, 64);
        String moduleSelector = optionalString(params, "module", 2_048);
        boolean includeRva = boundedBoolean(params, "includeRva", false);
        boolean excludeAnnotated = true;
        JsonElement excludeElement = params.get("excludeAnnotated");
        if (excludeElement != null) {
            if (!excludeElement.isJsonPrimitive() || !excludeElement.getAsJsonPrimitive().isBoolean()) {
                throw new BridgeFailure("invalid_argument", "excludeAnnotated must be a boolean");
            }
            excludeAnnotated = excludeElement.getAsBoolean();
        }

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        if (!matchesActiveModule(program, moduleSelector)) {
            throw new BridgeFailure("module_not_found", "module selector does not match the active Ghidra program");
        }

        // SEC-C J2: bounded leaves-first scan. The historical path walked every
        // function, ran a full body scan per function, materialized all rows,
        // sorted, then applied the limit. That is quadratic on large programs.
        // This keeps the same emitted keys and the same leaves-first order for
        // normal inputs (fully scanned, no cap/deadline hit) while bounding
        // work: an examined-functions cap, a candidate cap, a per-request
        // deadline, and top-N heap selection without unbounded row storage.
        final int maxQueueExaminedFunctions = 20_000;
        final int maxQueueCandidateRows = 5_000;
        long queueDeadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        java.util.Set<String> annotated =
            excludeAnnotated ? DbgLinkAnnotationJournal.annotatedFunctionEntries(program) : null;
        boolean hasAnnotated = annotated != null && !annotated.isEmpty();
        Comparator<JsonObject> leavesFirst = Comparator
            .comparingInt((JsonObject row) -> row.has("calleeCount") ? row.get("calleeCount").getAsInt() : 0)
            .thenComparingInt(row -> row.has("instructionCount") ? row.get("instructionCount").getAsInt() : Integer.MAX_VALUE)
            .thenComparing(row -> row.has("name") ? row.get("name").getAsString() : "");
        PriorityQueue<JsonObject> top =
            new PriorityQueue<>(Math.max(1, limit + 1), leavesFirst.reversed());
        int doneCount = 0;
        int totalMatched = 0;
        int examined = 0;
        boolean scanCapped = false;
        boolean queueTimedOut = false;
        Iterator<Function> functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            if (examined >= maxQueueExaminedFunctions || totalMatched >= maxQueueCandidateRows) {
                scanCapped = true;
                break;
            }
            if (System.nanoTime() >= queueDeadlineNanos) {
                queueTimedOut = true;
                break;
            }
            // Every row scans the body twice (countInstructions + callee scan):
            // poll cancellation per function so an aborted request stops here
            // instead of walking the whole program under programLock.
            GhidraStaticQueries.checkCancelled();
            Function function = functions.next();
            examined++;
            boolean external;
            try {
                external = function.isExternal();
            }
            catch (RuntimeException exception) {
                external = false;
            }
            if (external) {
                continue;
            }
            if (System.nanoTime() >= queueDeadlineNanos) {
                queueTimedOut = true;
                break;
            }
            int calleeCount =
                GhidraAnalysisFormatting.countDistinctCallees(program, function, queueDeadlineNanos);
            if (System.nanoTime() >= queueDeadlineNanos) {
                // The row above carries a partial callee count; still use it
                // but stop the scan here so one huge body cannot stall the list.
                queueTimedOut = true;
                JsonObject partialRow = GhidraAnalysisFormatting.analysisQueueRow(
                    program, function, calleeCount, includeRva);
                if (!(hasAnnotated && doneContains(annotated, partialRow))) {
                    totalMatched++;
                    offerQueueTop(top, partialRow, leavesFirst, limit);
                }
                else {
                    doneCount++;
                }
                break;
            }
            JsonObject row = GhidraAnalysisFormatting.analysisQueueRow(
                program, function, calleeCount, includeRva);
            if (hasAnnotated && doneContains(annotated, row)) {
                doneCount++;
                continue;
            }
            totalMatched++;
            offerQueueTop(top, row, leavesFirst, limit);
        }
        List<JsonObject> best = new ArrayList<>(top);
        GhidraAnalysisFormatting.sortQueueLeavesFirst(best);

        JsonArray queue = new JsonArray();
        for (int index = 0; index < best.size() && queue.size() < limit; index++) {
            queue.add(best.get(index));
        }
        JsonObject result = new JsonObject();
        result.addProperty("schemaVersion", 2);
        result.add("queue", queue);
        result.addProperty("doneCount", doneCount);
        result.addProperty("remainingCount", totalMatched);
        boolean truncated = totalMatched > queue.size() || scanCapped || queueTimedOut;
        result.addProperty("truncated", truncated);
        if (truncated) {
            result.addProperty("continuation",
                "Repeat with a higher limit (max 64) to see more of the leaves-first worklist.");
        }
        if (queueTimedOut) {
            result.addProperty("timedOut", true);
        }
        if (scanCapped) {
            result.addProperty("scanLimited", true);
        }
        return result;
    }

    private static boolean doneContains(java.util.Set<String> done, JsonObject row) {
        try {
            return row.has("entry") && done.contains(row.get("entry").getAsString());
        }
        catch (RuntimeException exception) {
            return false;
        }
    }

    private static void offerQueueTop(
        PriorityQueue<JsonObject> top,
        JsonObject row,
        Comparator<JsonObject> leavesFirst,
        int limit
    ) {
        if (top.size() < limit) {
            top.add(row);
        }
        else if (!top.isEmpty() && leavesFirst.compare(row, top.peek()) < 0) {
            top.poll();
            top.add(row);
        }
    }

    /**
     * Apply the same annotation batch as BatchAnnotate and report durable
     * progress: every applied operation is journaled, and that journal is the
     * progress record GetAnalysisQueue consults to stop re-suggesting
     * already-annotated functions across restarts.
     */
    JsonObject submitAnnotations(JsonObject params) throws BridgeFailure {
        JsonObject result = batchAnnotate(params);
        Program program = programSupplier.get();
        if (program != null) {
            JsonObject progress = new JsonObject();
            progress.addProperty("doneCount",
                DbgLinkAnnotationJournal.annotatedFunctionEntries(program).size());
            result.add("progress", progress);
        }
        return result;
    }

    /**
     * Cross-check decompilation against the listing so a decompiler that drops
     * statements or call arguments is detectable instead of silently trusted.
     */
    private static JsonObject fidelityCheck(Program program, Function function, JsonArray disassembly) {
        JsonObject fidelity = new JsonObject();
        int instructionCount = GhidraAnalysisFormatting.countInstructions(program, function);
        if (instructionCount >= 0) fidelity.addProperty("instructionCount", instructionCount);
        int returned = disassembly == null ? 0 : disassembly.size();
        fidelity.addProperty("disassembledCount", returned);
        if (instructionCount >= 0) {
            fidelity.addProperty("disassemblyComplete", returned >= instructionCount);
            // The static caution only travels when the disassembly is actually
            // short: a complete listing needs no warning prose.
            if (returned < instructionCount) {
                fidelity.addProperty("note",
                    "The decompiler can omit statements, stores or call arguments that the listing contains. " +
                    "Compare the decompilation against these disassembly rows before treating the C output as complete; " +
                    "re-run with higher maxItems when disassemblyComplete is false.");
            }
        }
        return fidelity;
    }

    /**
     * Only the slice verdict lives here. Identity, format, architecture,
     * compiler and functionCount are already in module.summary; scannedFunctions
     * and truncated are top-level. Copying them here doubled every response
     * without adding a reachable fact.
     */
    static JsonObject moduleSummary(JsonArray functions, String functionSelector, boolean hasNext) {
        JsonObject summary = new JsonObject();
        summary.addProperty("returnedFunctions", functions.size());
        summary.addProperty(
            "nextAction",
            hasNext
                ? "Repeat DecompileModule with start set to nextFunction to continue the slice."
                : functions.isEmpty()
                    ? "No functions matched the selected module or function selector."
                    : functionSelector.isEmpty()
                        ? "Inspect one returned function with InspectFunction for references and live mapping."
                        : "Use the returned function and decompilation as the current static evidence.");
        return summary;
    }

    private static JsonObject moduleIdentity(Program program) {
        JsonObject module = new JsonObject();
        module.addProperty("path", clipped(
            GhidraAnalysisFormatting.displayExecutablePath(program),
            2_048));
        module.addProperty("sha256", clipped(program.getExecutableSHA256(), 128));
        module.addProperty("imageBase", program.getImageBase().toString());
        module.addProperty("minAddress", program.getMinAddress().toString());
        module.addProperty("maxAddress", program.getMaxAddress().toString());
        module.add("summary", GhidraAnalysisFormatting.programSummary(program));
        return module;
    }

    /**
     * Shared journal envelope {kind, entry|function}: function-scoped
     * mutations address by entry, variable-scoped ones by function. Callers
     * add the mutation payload with the same keys and clips as the
     * single-tool paths so replay covers batched and single mutations alike.
     */
    private static JsonObject journalEntryFor(String kind, Function function, boolean functionScoped) {
        JsonObject journalEntry = new JsonObject();
        journalEntry.addProperty("kind", kind);
        journalEntry.addProperty(functionScoped ? "function" : "entry", function.getEntryPoint().toString());
        return journalEntry;
    }

    JsonObject renameFunction(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, RENAME_FUNCTION_FIELDS, "RenameFunction");
        String selector = requiredString(params, "function", MAX_SELECTOR_CHARS);
        String newName = requiredString(params, "name", MAX_SYMBOL_NAME_CHARS);
        validateSymbolName(newName);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        Function function = resolveFunction(program, selector);
        String previousName = function.getName();
        int transaction = program.startTransaction("DBGLink RenameFunction");
        boolean committed = false;
        try {
            applyRenameFunction(program, function, newName);
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }

        JsonObject journalEntry = journalEntryFor("rename_function", function, false);
        journalEntry.addProperty("name", clipped(function.getName(), MAX_SYMBOL_NAME_CHARS));
        boolean journaled = DbgLinkAnnotationJournal.record(program, journalEntry);

        JsonObject result = new JsonObject();
        decompiler.close();
        result.addProperty("operation", "RenameFunction");
        result.addProperty("committed", true);
        result.addProperty("journaled", journaled);
        result.addProperty("previousName", clipped(previousName, MAX_SYMBOL_NAME_CHARS));
        result.addProperty("name", clipped(function.getName(), MAX_SYMBOL_NAME_CHARS));
        result.add("function", GhidraAnalysisFormatting.functionIdentity(program, function));
        return result;
    }

    /**
     * Rename one already-resolved function after the global-name conflict
     * check. Does not open or commit a transaction; callers own that so
     * BatchAnnotate can share a single undo step.
     */
    private static void applyRenameFunction(Program program, Function function, String newName)
        throws BridgeFailure {
        for (Function existing : program.getListing().getGlobalFunctions(newName)) {
            if (!existing.getEntryPoint().equals(function.getEntryPoint())) {
                throw new BridgeFailure("mutation_conflict",
                    "another function already uses '" + clipped(newName, MAX_SYMBOL_NAME_CHARS) +
                    "': " + existing.getEntryPoint() +
                    " (" + clipped(existing.getName(), MAX_SYMBOL_NAME_CHARS) +
                    "); pick a different name or rename that function first");
            }
        }
        try {
            function.setName(newName, SourceType.USER_DEFINED);
        }
        catch (DuplicateNameException | InvalidInputException exception) {
            throw new BridgeFailure("mutation_conflict", "function name could not be applied");
        }
    }

    JsonObject setFunctionComment(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, SET_FUNCTION_COMMENT_FIELDS, "SetFunctionComment");
        String selector = requiredString(params, "function", MAX_SELECTOR_CHARS);
        String comment = boundedText(params, "comment", MAX_COMMENT_CHARS, true);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        Function function = resolveFunction(program, selector);
        String previousComment = function.getComment();
        int transaction = program.startTransaction("DBGLink SetFunctionComment");
        boolean committed = false;
        try {
            applySetFunctionComment(function, comment);
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }

        JsonObject journalEntry = journalEntryFor("set_function_comment", function, false);
        journalEntry.addProperty("comment", clipped(function.getComment(), MAX_COMMENT_CHARS));
        boolean journaled = DbgLinkAnnotationJournal.record(program, journalEntry);

        JsonObject result = new JsonObject();
        decompiler.close();
        result.addProperty("operation", "SetFunctionComment");
        result.addProperty("committed", true);
        result.addProperty("journaled", journaled);
        result.addProperty("previousComment", clipped(previousComment, MAX_COMMENT_CHARS));
        result.addProperty("comment", clipped(function.getComment(), MAX_COMMENT_CHARS));
        result.add("function", GhidraAnalysisFormatting.functionIdentity(program, function));
        return result;
    }

    /**
     * Set or clear one function comment. Does not open or commit a
     * transaction; callers own that so BatchAnnotate can share one undo step.
     */
    private static void applySetFunctionComment(Function function, String comment) {
        function.setComment(comment);
    }

    /**
     * Shared live symbol-name check, reused by journal replay (SEC-C J4) so
     * activation cannot persist a name the live RenameFunction would reject.
     */
    static void validateSymbolName(String name) throws BridgeFailure {
        if (!name.matches("[A-Za-z_$?][A-Za-z0-9_$?]*")) {
            throw new BridgeFailure("invalid_argument", "name must be a simple Ghidra symbol name");
        }
    }

    JsonObject renameVariable(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, RENAME_VARIABLE_FIELDS, "RenameVariable");
        String functionSelector = requiredString(params, "function", MAX_SELECTOR_CHARS);
        String variableSelector = requiredString(params, "variable", MAX_SYMBOL_NAME_CHARS);
        String newName = requiredString(params, "name", MAX_SYMBOL_NAME_CHARS);
        validateSymbolName(newName);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        Function function = resolveFunction(program, functionSelector);
        int transaction = program.startTransaction("DBGLink RenameVariable");
        boolean committed = false;
        JsonObject applied;
        try {
            applied = applyRenameVariable(program, function, variableSelector, newName);
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }

        JsonObject journalEntry = journalEntryFor("rename_variable", function, true);
        journalEntry.addProperty("variable", clipped(variableSelector, MAX_SYMBOL_NAME_CHARS));
        journalEntry.addProperty("name", clipped(newName, MAX_SYMBOL_NAME_CHARS));
        boolean journaled = DbgLinkAnnotationJournal.record(program, journalEntry);

        JsonObject result = new JsonObject();
        decompiler.close();
        result.addProperty("operation", "RenameVariable");
        result.addProperty("committed", true);
        result.addProperty("journaled", journaled);
        result.addProperty("previousName", clipped(variableSelector, MAX_SYMBOL_NAME_CHARS));
        result.addProperty("name", clipped(newName, MAX_SYMBOL_NAME_CHARS));
        if (applied.has("resolvedFrom")) {
            result.addProperty("resolvedFrom", applied.get("resolvedFrom").getAsString());
        }
        result.add("variable", applied.getAsJsonObject("variable"));
        return result;
    }

    /**
     * Rename a variable in the program database, falling back to the
     * decompiler local symbols when the database has no such variable. Does
     * not open or commit a transaction; callers own that so BatchAnnotate can
     * share a single undo step. Returns {variable} plus
     * resolvedFrom=decompiler when the fallback applied the rename.
     */
    private JsonObject applyRenameVariable(Program program, Function function, String variableSelector, String newName)
        throws BridgeFailure {
        Variable variable;
        try {
            variable = resolveVariable(function, variableSelector);
        }
        catch (BridgeFailure failure) {
            if (!"variable_not_found".equals(failure.code)) throw failure;
            JsonObject applied = new JsonObject();
            applied.add("variable", decompiler.renameDecompilerVariable(program, function, variableSelector, newName));
            applied.addProperty("resolvedFrom", "decompiler");
            return applied;
        }
        for (Variable existing : function.getAllVariables()) {
            if (existing != variable && newName.equals(existing.getName())) {
                throw new BridgeFailure("mutation_conflict", "another variable already uses the requested name");
            }
        }
        try {
            variable.setName(newName, SourceType.USER_DEFINED);
        }
        catch (DuplicateNameException | InvalidInputException exception) {
            throw new BridgeFailure("mutation_conflict", "variable name could not be applied");
        }
        JsonObject applied = new JsonObject();
        applied.add("variable", variableIdentity(variable));
        return applied;
    }

    JsonObject setVariableType(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, SET_VARIABLE_TYPE_FIELDS, "SetVariableType");
        String functionSelector = requiredString(params, "function", MAX_SELECTOR_CHARS);
        String variableSelector = requiredString(params, "variable", MAX_SYMBOL_NAME_CHARS);
        String typeSelector = boundedText(params, "type", MAX_SELECTOR_CHARS, false);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        Function function = resolveFunction(program, functionSelector);
        int transaction = program.startTransaction("DBGLink SetVariableType");
        boolean committed = false;
        JsonObject applied;
        try {
            applied = applySetVariableType(program, function, variableSelector, typeSelector);
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }

        JsonObject journalEntry = journalEntryFor("set_variable_type", function, true);
        journalEntry.addProperty("variable", clipped(variableSelector, MAX_SYMBOL_NAME_CHARS));
        journalEntry.addProperty("type", applied.get("type").getAsString());
        boolean journaled = DbgLinkAnnotationJournal.record(program, journalEntry);

        JsonObject result = new JsonObject();
        decompiler.close();
        result.addProperty("operation", "SetVariableType");
        result.addProperty("committed", true);
        result.addProperty("journaled", journaled);
        result.addProperty("previousType", applied.get("previousType").getAsString());
        result.addProperty("type", applied.get("type").getAsString());
        result.add("variable", applied.getAsJsonObject("variable"));
        return result;
    }

    /**
     * Resolve and apply one variable type. Does not open or commit a
     * transaction; callers own that so BatchAnnotate can share a single undo
     * step. Returns {previousType, type, variable} where type is the resolved
     * path name journal replay resolves again.
     */
    private static JsonObject applySetVariableType(
        Program program,
        Function function,
        String variableSelector,
        String typeSelector
    ) throws BridgeFailure {
        Variable variable = resolveVariable(function, variableSelector);
        DataType dataType = resolveDataType(program, typeSelector);
        if (dataType == null) {
            throw new BridgeFailure("type_not_found", "requested data type was not found");
        }
        String previousType = variable.getDataType() == null ? "" : variable.getDataType().getPathName();
        try {
            variable.setDataType(dataType, SourceType.USER_DEFINED);
        }
        catch (InvalidInputException exception) {
            throw new BridgeFailure("mutation_failed", "variable type could not be applied");
        }
        JsonObject applied = new JsonObject();
        applied.addProperty("previousType", clipped(previousType, MAX_SELECTOR_CHARS));
        DataType currentType = variable.getDataType();
        applied.addProperty("type", clipped(
            currentType == null ? "" : currentType.getPathName(),
            MAX_SELECTOR_CHARS));
        applied.add("variable", variableIdentity(variable));
        return applied;
    }

    private static final Set<String> BATCH_RENAME_FUNCTION_FIELDS = Set.of("kind", "function", "name");
    private static final Set<String> BATCH_SET_FUNCTION_COMMENT_FIELDS = Set.of("kind", "function", "comment");
    private static final Set<String> BATCH_RENAME_VARIABLE_FIELDS = Set.of("kind", "function", "variable", "name");
    private static final Set<String> BATCH_SET_VARIABLE_TYPE_FIELDS = Set.of("kind", "function", "variable", "type");
    private static final Set<String> BATCH_CREATE_FUNCTION_FIELDS = Set.of("kind", "function", "name");

    /**
     * Apply up to MAX_BATCH_ANNOTATE_OPERATIONS rename/comment/vartype
     * operations in order inside one transaction. The envelope is validated
     * before the transaction opens; a per-operation BridgeFailure is reported
     * by index and the remaining operations still run. Every successful
     * operation is journaled with the same entry format as its single-tool
     * counterpart so replay covers batched and single mutations alike.
     * Journal entries are buffered and written only after the transaction
     * commits, so a rolled-back batch leaves no replay entries behind.
     */
    JsonObject batchAnnotate(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, BATCH_ANNOTATE_FIELDS, "BatchAnnotate");
        JsonElement operationsElement = params.get("operations");
        if (operationsElement == null || !operationsElement.isJsonArray()) {
            throw new BridgeFailure("missing_argument", "operations must be an array");
        }
        JsonArray operations = operationsElement.getAsJsonArray();
        if (operations.isEmpty()) {
            throw new BridgeFailure("missing_argument", "operations must not be empty");
        }
        if (operations.size() > MAX_BATCH_ANNOTATE_OPERATIONS) {
            throw new BridgeFailure("argument_out_of_range", "operations is outside the allowed range");
        }
        List<BatchAnnotateOperation> parsed = new ArrayList<>(operations.size());
        for (int index = 0; index < operations.size(); index++) {
            JsonElement element = operations.get(index);
            if (!element.isJsonObject()) {
                throw new BridgeFailure("invalid_argument", "operations[" + index + "] must be an object");
            }
            try {
                parsed.add(parseBatchAnnotateOperation(element.getAsJsonObject()));
            }
            catch (BridgeFailure failure) {
                throw new BridgeFailure(
                    failure.code,
                    "operations[" + index + "]: " + clipped(failure.getMessage(), 256));
            }
        }

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        JsonArray results = new JsonArray();
        List<BatchAnnotateOutcome> journalPending = new ArrayList<>();
        int applied = 0;
        int failed = 0;
        int transaction = program.startTransaction("DBGLink BatchAnnotate");
        boolean committed = false;
        try {
            for (int index = 0; index < parsed.size(); index++) {
                BatchAnnotateOperation operation = parsed.get(index);
                try {
                    BatchAnnotateOutcome outcome = applyBatchAnnotateOperation(program, operation, index);
                    results.add(outcome.row);
                    journalPending.add(outcome);
                    applied++;
                }
                catch (BridgeFailure failure) {
                    JsonObject row = new JsonObject();
                    row.addProperty("index", index);
                    row.addProperty("kind", operation.kind);
                    row.addProperty("function", clipped(operation.function, MAX_SELECTOR_CHARS));
                    row.addProperty("ok", false);
                    row.addProperty("code", clipped(failure.code, 64));
                    row.addProperty("message", clipped(failure.getMessage(), 256));
                    results.add(row);
                    failed++;
                }
            }
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }
        // Journal only after the shared transaction committed. If an
        // unexpected failure rolled it back, replay must not resurrect a
        // mutation that never reached the database.
        for (BatchAnnotateOutcome outcome : journalPending) {
            outcome.row.addProperty("journaled",
                outcome.journalEntry != null && DbgLinkAnnotationJournal.record(program, outcome.journalEntry));
        }
        decompiler.close();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("applied", applied);
        result.addProperty("failed", failed);
        result.add("results", results);
        return result;
    }

    private static BatchAnnotateOperation parseBatchAnnotateOperation(JsonObject operation) throws BridgeFailure {
        String kind = requiredString(operation, "kind", 32);
        return switch (kind) {
            case "rename_function" -> {
                rejectUnknownFields(operation, BATCH_RENAME_FUNCTION_FIELDS, "BatchAnnotate");
                String function = requiredString(operation, "function", MAX_SELECTOR_CHARS);
                String name = requiredString(operation, "name", MAX_SYMBOL_NAME_CHARS);
                validateSymbolName(name);
                yield new BatchAnnotateOperation(kind, function, name, null, null, null);
            }
            case "set_function_comment" -> {
                rejectUnknownFields(operation, BATCH_SET_FUNCTION_COMMENT_FIELDS, "BatchAnnotate");
                yield new BatchAnnotateOperation(kind,
                    requiredString(operation, "function", MAX_SELECTOR_CHARS),
                    null,
                    boundedText(operation, "comment", MAX_COMMENT_CHARS, true),
                    null,
                    null);
            }
            case "rename_variable" -> {
                rejectUnknownFields(operation, BATCH_RENAME_VARIABLE_FIELDS, "BatchAnnotate");
                String function = requiredString(operation, "function", MAX_SELECTOR_CHARS);
                String variable = requiredString(operation, "variable", MAX_SYMBOL_NAME_CHARS);
                String name = requiredString(operation, "name", MAX_SYMBOL_NAME_CHARS);
                validateSymbolName(name);
                yield new BatchAnnotateOperation(kind, function, name, null, variable, null);
            }
            case "set_variable_type" -> {
                rejectUnknownFields(operation, BATCH_SET_VARIABLE_TYPE_FIELDS, "BatchAnnotate");
                String function = requiredString(operation, "function", MAX_SELECTOR_CHARS);
                String variable = requiredString(operation, "variable", MAX_SYMBOL_NAME_CHARS);
                String type = boundedText(operation, "type", MAX_SELECTOR_CHARS, false);
                yield new BatchAnnotateOperation(kind, function, null, null, variable, type);
            }
            case "create_function" -> {
                rejectUnknownFields(operation, BATCH_CREATE_FUNCTION_FIELDS, "BatchAnnotate");
                String entry = requiredString(operation, "function", MAX_SELECTOR_CHARS);
                String name = optionalString(operation, "name", MAX_SYMBOL_NAME_CHARS);
                if (!name.isEmpty()) {
                    validateSymbolName(name);
                }
                yield new BatchAnnotateOperation(kind, entry, name, null, null, null);
            }
            default -> throw new BridgeFailure("invalid_argument",
                "kind must be rename_function, set_function_comment, rename_variable, set_variable_type or create_function");
        };
    }

    private BatchAnnotateOutcome applyBatchAnnotateOperation(Program program, BatchAnnotateOperation operation, int index)
        throws BridgeFailure {
        switch (operation.kind) {
            case "rename_function" -> {
                Function function = resolveFunction(program, operation.function);
                applyRenameFunction(program, function, operation.name);
                JsonObject journalEntry = journalEntryFor("rename_function", function, false);
                journalEntry.addProperty("name", clipped(function.getName(), MAX_SYMBOL_NAME_CHARS));
                JsonObject row = batchOperationResult(function, operation, index);
                row.addProperty("name", clipped(function.getName(), MAX_SYMBOL_NAME_CHARS));
                return new BatchAnnotateOutcome(row, journalEntry);
            }
            case "set_function_comment" -> {
                Function function = resolveFunction(program, operation.function);
                applySetFunctionComment(function, operation.comment);
                JsonObject journalEntry = journalEntryFor("set_function_comment", function, false);
                journalEntry.addProperty("comment", clipped(function.getComment(), MAX_COMMENT_CHARS));
                JsonObject row = batchOperationResult(function, operation, index);
                String comment = function.getComment();
                row.addProperty("commentChars", comment == null ? 0 : comment.length());
                return new BatchAnnotateOutcome(row, journalEntry);
            }
            case "rename_variable" -> {
                Function function = resolveFunction(program, operation.function);
                JsonObject applied = applyRenameVariable(program, function, operation.variable, operation.name);
                JsonObject journalEntry = journalEntryFor("rename_variable", function, true);
                journalEntry.addProperty("variable", clipped(operation.variable, MAX_SYMBOL_NAME_CHARS));
                journalEntry.addProperty("name", clipped(operation.name, MAX_SYMBOL_NAME_CHARS));
                JsonObject row = batchOperationResult(function, operation, index);
                row.addProperty("variable", clipped(operation.variable, MAX_SYMBOL_NAME_CHARS));
                row.addProperty("name", clipped(
                    applied.getAsJsonObject("variable").get("name").getAsString(),
                    MAX_SYMBOL_NAME_CHARS));
                return new BatchAnnotateOutcome(row, journalEntry);
            }
            case "set_variable_type" -> {
                Function function = resolveFunction(program, operation.function);
                JsonObject applied = applySetVariableType(program, function, operation.variable, operation.type);
                JsonObject journalEntry = journalEntryFor("set_variable_type", function, true);
                journalEntry.addProperty("variable", clipped(operation.variable, MAX_SYMBOL_NAME_CHARS));
                journalEntry.addProperty("type", applied.get("type").getAsString());
                JsonObject row = batchOperationResult(function, operation, index);
                row.addProperty("variable", clipped(operation.variable, MAX_SYMBOL_NAME_CHARS));
                row.addProperty("type", applied.get("type").getAsString());
                return new BatchAnnotateOutcome(row, journalEntry);
            }
            case "create_function" -> {
                Address entry = GhidraStaticQueries.address(program, operation.function);
                Function existing = program.getFunctionManager().getFunctionAt(entry);
                if (existing == null) {
                    existing = program.getFunctionManager().getFunctionContaining(entry);
                }
                if (existing != null) {
                    JsonObject row = batchOperationResult(existing, operation, index);
                    row.addProperty("alreadyDefined", true);
                    row.addProperty("committed", false);
                    return new BatchAnnotateOutcome(row, null);
                }
                TaskMonitor monitor = requestMonitor.get() != null ? requestMonitor.get() : TaskMonitor.DUMMY;
                Function created = defineFunction(program, entry, operation.name, monitor);
                JsonObject journalEntry = journalEntryFor("create_function", created, false);
                // Replay an unnamed creation as unnamed too, so Ghidra assigns the
                // current generated name instead of pinning an old FUN_* label.
                journalEntry.addProperty("name", clipped(operation.name, MAX_SYMBOL_NAME_CHARS));
                JsonObject createdRow = batchOperationResult(created, operation, index);
                createdRow.addProperty("alreadyDefined", false);
                createdRow.addProperty("name", clipped(created.getName(), MAX_SYMBOL_NAME_CHARS));
                return new BatchAnnotateOutcome(createdRow, journalEntry);
            }
            default -> throw new BridgeFailure("invalid_argument", "unsupported BatchAnnotate kind");
        }
    }

    private static JsonObject batchOperationResult(Function function, BatchAnnotateOperation operation, int index) {
        JsonObject row = new JsonObject();
        row.addProperty("index", index);
        row.addProperty("kind", operation.kind);
        row.addProperty("function", function.getEntryPoint().toString());
        row.addProperty("ok", true);
        row.addProperty("committed", true);
        return row;
    }

    private static final class BatchAnnotateOutcome {
        final JsonObject row;
        final JsonObject journalEntry;

        BatchAnnotateOutcome(JsonObject row, JsonObject journalEntry) {
            this.row = row;
            this.journalEntry = journalEntry;
        }
    }

    private static final class BatchAnnotateOperation {
        final String kind;
        final String function;
        final String name;
        final String comment;
        final String variable;
        final String type;

        BatchAnnotateOperation(String kind, String function, String name, String comment, String variable, String type) {
            this.kind = kind;
            this.function = function;
            this.name = name;
            this.comment = comment;
            this.variable = variable;
            this.type = type;
        }
    }

    /**
     * Flush the active program to its project file so renames, comments and
     * created functions survive a Ghidra restart. The project itself lives in
     * the launcher-owned isolated session, so cross-session durability still
     * comes from the annotation journal, which replays on reimport.
     */
    JsonObject saveProgram(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, SAVE_PROGRAM_FIELDS, "SaveProgram");
        String moduleSelector = optionalString(params, "module", 2_048);

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }
        if (!matchesActiveModule(program, moduleSelector)) {
            throw new BridgeFailure("module_not_found", "module selector does not match the active Ghidra program");
        }

        boolean hadUnsavedChanges = program.isChanged();
        TaskMonitor monitor = requestMonitor.get() != null ? requestMonitor.get() : TaskMonitor.DUMMY;
        try {
            program.save("DBGLink SaveProgram", monitor);
        }
        catch (IOException | CancelledException exception) {
            throw new BridgeFailure("save_failed", "Ghidra program could not be saved to its project file");
        }

        JsonObject result = new JsonObject();
        result.addProperty("operation", "SaveProgram");
        result.addProperty("saved", true);
        result.addProperty("hadUnsavedChanges", hadUnsavedChanges);
        result.add("program", GhidraAnalysisFormatting.programSummary(program));
        return result;
    }

    static DataType resolveDataType(Program program, String selector) throws BridgeFailure {
        DataTypeManager programManager = program.getDataTypeManager();
        DataType dataType = findDataType(programManager, selector);
        if (dataType != null) {
            return dataType;
        }

        DataType builtIn = findDataType(BuiltInDataTypeManager.getDataTypeManager(), selector);
        return builtIn == null ? null : builtIn.clone(programManager);
    }

    private static DataType findDataType(DataTypeManager manager, String selector) throws BridgeFailure {
        DataType dataType = manager.getDataType(selector);
        if (dataType == null && !selector.startsWith("/")) {
            dataType = manager.getDataType("/" + selector);
        }
        if (dataType != null) {
            return dataType;
        }

        DataType match = null;
        Iterator<DataType> dataTypes = manager.getAllDataTypes();
        int scanned = 0;
        while (dataTypes.hasNext() && scanned++ < MAX_TYPE_SCAN_ITEMS) {
            DataType candidate = dataTypes.next();
            if (!selector.equals(candidate.getName()) && !selector.equals(candidate.getDisplayName())) {
                continue;
            }
            if (match != null && !match.getPathName().equals(candidate.getPathName())) {
                throw new BridgeFailure("type_ambiguous", "type selector matched more than one data type");
            }
            match = candidate;
        }
        if (dataTypes.hasNext()) {
            throw new BridgeFailure("type_scan_limited", "data type search exceeded its scan limit");
        }
        return match;
    }

    private static Variable resolveVariable(Function function, String selector) throws BridgeFailure {
        Variable match = null;
        for (Variable variable : function.getAllVariables()) {
            if (!variable.isValid() || !selector.equals(variable.getName())) {
                continue;
            }
            if (match != null) {
                throw new BridgeFailure("ambiguous_variable", "variable selector matched more than one variable");
            }
            match = variable;
        }
        if (match == null) {
            throw new BridgeFailure("variable_not_found", "variable selector was not found");
        }
        return match;
    }

    private static JsonObject variableIdentity(Variable variable) {
        JsonObject result = new JsonObject();
        result.addProperty("name", clipped(variable.getName(), MAX_SYMBOL_NAME_CHARS));
        result.addProperty("storage", clipped(String.valueOf(variable.getVariableStorage()), 512));
        DataType dataType = variable.getDataType();
        if (dataType != null) {
            result.addProperty("type", clipped(dataType.getPathName(), MAX_SELECTOR_CHARS));
            result.addProperty("length", dataType.getLength());
        }
        return result;
    }

    /**
     * Resolve a selector to a function, or explain precisely why not: an
     * address with code but no function says so (and points at CreateFunction),
     * a name miss names the selector. "function selector was not found" alone
     * left callers blind on live code reached only through tables.
     */
    static Function resolveFunction(Program program, String selector) throws BridgeFailure {
        FunctionManager functionManager = program.getFunctionManager();
        Address[] parsed = null;
        try {
            parsed = program.parseAddress(selector);
            if (parsed != null) {
                for (Address address : parsed) {
                    Function atAddress = functionManager.getFunctionAt(address);
                    if (atAddress != null) {
                        return atAddress;
                    }
                    Function containing = functionManager.getFunctionContaining(address);
                    if (containing != null) {
                        return containing;
                    }
                }
            }
        }
        catch (RuntimeException ignored) {
            // Name lookup below produces the user-facing error.
            parsed = null;
        }

        List<Function> matches = program.getListing().getGlobalFunctions(selector);
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.size() > 1) {
            throw new BridgeFailure("ambiguous_function", "use an entry address for an overloaded function name");
        }
        if (parsed != null && parsed.length > 0) {
            Address address = parsed[0];
            boolean mapped;
            boolean hasInstruction = false;
            try {
                mapped = program.getMemory().contains(address);
                hasInstruction = mapped && program.getListing().getInstructionAt(address) != null;
            }
            catch (RuntimeException exception) {
                mapped = false;
            }
            throw new BridgeFailure("function_not_found",
                "No function is defined at " + address + (mapped
                    ? (hasInstruction
                        ? "; code exists there - use CreateFunction to define the function"
                        : "; the address is mapped but has no defined instructions")
                    : "; the address is not mapped in this program"));
        }
        throw new BridgeFailure("function_not_found",
            "'" + clipped(selector, 96) +
            "' matched no global function name; check ListFunctions with a filter or pass a function entry address");
    }

    /**
     * Define a function at an entry address, disassembling undefined code when
     * needed. Does not open or commit a transaction; callers own that so journal
     * replay can batch many definitions into one undo step.
     */
    static Function defineFunction(Program program, Address entry, String name, TaskMonitor monitor)
        throws BridgeFailure {
        FunctionManager functionManager = program.getFunctionManager();
        Function existing = functionManager.getFunctionAt(entry);
        if (existing != null) {
            return existing;
        }
        if (!program.getMemory().contains(entry)) {
            throw new BridgeFailure("invalid_address", "address is not mapped in this program");
        }
        if (program.getListing().getInstructionAt(entry) == null) {
            DisassembleCommand disassemble = new DisassembleCommand(entry, null, true);
            if (!disassemble.applyTo(program, monitor)) {
                throw new BridgeFailure("create_function_failed",
                    "no code could be disassembled at the address" + statusSuffix(disassemble.getStatusMsg()));
            }
        }
        AddressSetView body = CreateFunctionCmd.getFunctionBody(program, entry, monitor);
        if (body == null || body.isEmpty()) {
            throw new BridgeFailure("create_function_failed",
                "Ghidra could not determine function boundaries at the address");
        }
        CreateFunctionCmd command = name.isEmpty()
            ? new CreateFunctionCmd(entry)
            : new CreateFunctionCmd(name, entry, body, SourceType.USER_DEFINED);
        if (!command.applyTo(program, monitor)) {
            throw new BridgeFailure("create_function_failed",
                "Ghidra could not define a function at the address" + statusSuffix(command.getStatusMsg()));
        }
        Function created = functionManager.getFunctionAt(entry);
        if (created == null) {
            throw new BridgeFailure("create_function_failed", "function was not created at the address");
        }
        // summary.functionCount changed; the next status/digest must recount.
        GhidraAnalysisFormatting.invalidateProgramSummary(program);
        return created;
    }

    private static String statusSuffix(String status) {
        return status == null || status.isBlank() ? "" : ": " + clipped(status, 200);
    }

    JsonObject createFunction(JsonObject params) throws BridgeFailure {
        rejectUnknownFields(params, CREATE_FUNCTION_FIELDS, "CreateFunction");
        String selector = requiredString(params, "address", MAX_SELECTOR_CHARS);
        String name = optionalString(params, "name", MAX_SYMBOL_NAME_CHARS);
        if (!name.isEmpty()) {
            validateSymbolName(name);
        }

        Program program = programSupplier.get();
        if (program == null) {
            throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        }

        Address entry = GhidraStaticQueries.address(program, selector);
        Function existing = program.getFunctionManager().getFunctionAt(entry);
        if (existing == null) {
            existing = program.getFunctionManager().getFunctionContaining(entry);
        }
        if (existing != null) {
            JsonObject defined = new JsonObject();
            defined.addProperty("operation", "CreateFunction");
            defined.addProperty("committed", false);
            defined.addProperty("alreadyDefined", true);
            defined.addProperty("journaled", false);
            defined.add("function", GhidraAnalysisFormatting.functionIdentity(program, existing));
            return defined;
        }

        TaskMonitor monitor = requestMonitor.get() != null ? requestMonitor.get() : TaskMonitor.DUMMY;
        int transaction = program.startTransaction("DBGLink CreateFunction");
        boolean committed = false;
        Function created;
        try {
            created = defineFunction(program, entry, name, monitor);
            committed = true;
        }
        finally {
            program.endTransaction(transaction, committed);
        }

        JsonObject journalEntry = new JsonObject();
        journalEntry.addProperty("kind", "create_function");
        journalEntry.addProperty("entry", created.getEntryPoint().toString());
        // Replay an unnamed creation as unnamed too, so Ghidra assigns the
        // current generated name instead of pinning an old FUN_* label.
        journalEntry.addProperty("name", clipped(name, MAX_SYMBOL_NAME_CHARS));
        boolean journaled = DbgLinkAnnotationJournal.record(program, journalEntry);

        JsonObject result = new JsonObject();
        decompiler.close();
        result.addProperty("operation", "CreateFunction");
        result.addProperty("committed", true);
        result.addProperty("alreadyDefined", false);
        result.addProperty("journaled", journaled);
        result.add("function", GhidraAnalysisFormatting.functionIdentity(program, created));
        return result;
    }
}
