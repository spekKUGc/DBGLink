package dbglink.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Regression checks for the riskiest unverified layer (iterations 2-3):
 * BatchAnnotate rollback (no journal on abort), per-op indexed errors and
 * AnalyzeFunctions (per-index not_found, nextIndex/nextStart continuation,
 * shared output budget). Proxy-based; no GUI or imported program required.
 */
final class GhidraBatchAnnotateChecks {
    private static final String SHA =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T)Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }

    private static <T> T iterator(Class<T> type, List<?> rows) {
        var iterator = rows.iterator();
        return proxy(type, (p, m, a) -> switch (m.getName()) {
            case "hasNext" -> iterator.hasNext();
            case "next" -> iterator.next();
            case "iterator" -> p;
            default -> throw new AssertionError(m);
        });
    }

    private static JsonObject args(String json) {
        return JsonParser.parseString(json).getAsJsonObject();
    }

    private static Symbol symbol(SourceType source) {
        return proxy(Symbol.class, (p, m, a) -> switch (m.getName()) {
            case "getSource" -> source;
            default -> throw new AssertionError(m);
        });
    }

    /** Mutable function state shared by the program fixture proxies. */
    private static final class Fixture {
        final AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        final Address first = space.getAddress(0x30001000);
        final Address second = space.getAddress(0x30002000);
        final String[] names = {"FuncA", "FuncB"};
        final String[] comments = {"", ""};
        final SourceType[] sources = {SourceType.DEFAULT, SourceType.DEFAULT};
        final AtomicBoolean explodeSecondRename = new AtomicBoolean(false);
        final AtomicReference<Boolean> endCommitted = new AtomicReference<>(null);
        int setNameCalls;
        int listFunctionCalls;

        Function function(Address entry, int slot) {
            return proxy(Function.class, (p, m, a) -> switch (m.getName()) {
                case "getName" -> names[slot];
                case "getEntryPoint" -> entry;
                case "getBody" -> null;
                case "isThunk", "isExternal" -> false;
                case "getSymbol" -> symbol(sources[slot]);
                case "setName" -> {
                    setNameCalls++;
                    if (slot == 1 && explodeSecondRename.get()) throw new RuntimeException("boom");
                    names[slot] = (String)a[0];
                    yield null;
                }
                case "getComment" -> comments[slot];
                case "setComment" -> { comments[slot] = (String)a[0]; yield null; }
                default -> throw new AssertionError(m);
            });
        }

        Program program(List<Function> ordered) {
            FunctionManager functions = proxy(FunctionManager.class, (p, m, a) -> switch (m.getName()) {
                case "getFunctionAt", "getFunctionContaining" -> {
                    Address at = (Address)a[0];
                    Function match = null;
                    for (Function candidate : ordered) {
                        if (candidate.getEntryPoint().equals(at)) match = candidate;
                    }
                    yield match;
                }
                case "getFunctions" -> {
                    listFunctionCalls++;
                    yield iterator(FunctionIterator.class, ordered);
                }
                default -> throw new AssertionError(m);
            });
            Listing listing = proxy(Listing.class, (p, m, a) -> switch (m.getName()) {
                case "getGlobalFunctions" -> {
                    String wanted = (String)a[0];
                    List<Function> matches = new ArrayList<>();
                    for (Function candidate : ordered) {
                        if (candidate.getName().equals(wanted)) matches.add(candidate);
                    }
                    yield matches;
                }
                case "getInstructionAt" -> null;
                case "getInstructions" -> iterator(
                    ghidra.program.model.listing.InstructionIterator.class, List.of());
                case "getCodeUnits" -> iterator(
                    ghidra.program.model.listing.CodeUnitIterator.class, List.of());
                default -> throw new AssertionError(m);
            });
            Memory memory = proxy(Memory.class, (p, m, a) -> switch (m.getName()) {
                case "contains" -> false;
                default -> throw new AssertionError(m);
            });
            ghidra.program.model.symbol.ReferenceManager references =
                proxy(ghidra.program.model.symbol.ReferenceManager.class, (p, m, a) -> switch (m.getName()) {
                    case "getReferencesTo" -> iterator(
                        ghidra.program.model.symbol.ReferenceIterator.class, List.of());
                    default -> throw new AssertionError(m);
                });
            return proxy(Program.class, (p, m, a) -> switch (m.getName()) {
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                case "toString" -> "FixtureProgram";
                case "getExecutableSHA256" -> SHA;
                case "getExecutablePath" -> "C:/hw.dll";
                case "getExecutableFormat" -> "PE";
                case "getImageBase", "getMinAddress" -> space.getAddress(0x30000000);
                case "getMaxAddress" -> space.getAddress(0x3000FFFF);
                case "getLanguage", "getLanguageID", "getCompiler", "getCompilerSpec" -> null;
                case "parseAddress" -> new Address[] {
                    space.getAddress(Long.parseUnsignedLong(
                        ((String)a[0]).replace("0x", ""), 16))};
                case "getFunctionManager" -> functions;
                case "getListing" -> listing;
                case "getMemory" -> memory;
                case "getReferenceManager" -> references;
                case "startTransaction" -> 1;
                case "endTransaction" -> { endCommitted.set((Boolean)a[1]); yield false; }
                default -> throw new AssertionError(m);
            });
        }
    }

    private static Path freshJournalDir() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-batch-checks");
        DbgLinkAnnotationJournal.directoryOverride = directory;
        return directory;
    }

    /** One success, one per-op failure, one more success: order kept, rest still run. */
    private static void batchPerOpIndexedErrors() throws Exception {
        Path directory = freshJournalDir();
        try {
            Fixture fixture = new Fixture();
            Function first = fixture.function(fixture.first, 0);
            Function second = fixture.function(fixture.second, 1);
            GhidraAnalysisOperations operations =
                new GhidraAnalysisOperations(() -> fixture.program(List.of(first, second)));
            JsonObject result = operations.batchAnnotate(args("""
                {"operations": [
                  {"kind": "rename_function", "function": "FuncA", "name": "GoodName"},
                  {"kind": "rename_function", "function": "NoSuchFn", "name": "Other"},
                  {"kind": "set_function_comment", "function": "FuncB", "comment": "hi"}
                ]}"""));
            check(result.get("applied").getAsInt() == 2, "Applied count wrong");
            check(result.get("failed").getAsInt() == 1, "Failed count wrong");
            JsonArray rows = result.getAsJsonArray("results");
            check(rows.size() == 3, "Per-op rows lost");
            check(rows.get(0).getAsJsonObject().get("ok").getAsBoolean(), "First op failed");
            JsonObject failed = rows.get(1).getAsJsonObject();
            check(!failed.get("ok").getAsBoolean(), "Failing op reported ok");
            check(failed.get("index").getAsInt() == 1, "Failing op index lost");
            check(failed.has("code") && failed.has("message"), "Failing op lost code/message");
            check(rows.get(2).getAsJsonObject().get("ok").getAsBoolean(), "Op after failure skipped");
            check(Boolean.TRUE.equals(fixture.endCommitted.get()), "Shared transaction did not commit");
            check("GoodName".equals(fixture.names[0]), "Rename not applied");
            check("hi".equals(fixture.comments[1]), "Comment after failure not applied");
            check(Files.readAllLines(directory.resolve(SHA + ".jsonl")).size() == 2,
                "Journal must hold exactly the two successful ops");
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = null;
        }
    }

    /** An unexpected failure rolls the shared transaction back and journals nothing. */
    private static void batchRollbackWritesNoJournal() throws Exception {
        Path directory = freshJournalDir();
        try {
            Fixture fixture = new Fixture();
            fixture.explodeSecondRename.set(true);
            Function first = fixture.function(fixture.first, 0);
            Function second = fixture.function(fixture.second, 1);
            GhidraAnalysisOperations operations =
                new GhidraAnalysisOperations(() -> fixture.program(List.of(first, second)));
            boolean aborted = false;
            try {
                operations.batchAnnotate(args("""
                    {"operations": [
                      {"kind": "rename_function", "function": "FuncA", "name": "GoodName"},
                      {"kind": "rename_function", "function": "FuncB", "name": "Kaboom"}
                    ]}"""));
            }
            catch (RuntimeException expected) {
                aborted = true;
            }
            check(aborted, "Unexpected failure did not abort the batch");
            check(Boolean.FALSE.equals(fixture.endCommitted.get()), "Aborted batch did not roll back");
            check(Files.notExists(directory.resolve(SHA + ".jsonl")), "Rolled-back batch left journal entries");
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = null;
        }
    }

    /** Envelope mistakes abort the whole batch and name the offending index. */
    private static void batchEnvelopeIndexedError() throws Exception {
        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first)));
        try {
            operations.batchAnnotate(args("""
                {"operations": [
                  {"kind": "rename_function", "function": "FuncA", "name": "GoodName"},
                  {"kind": "rename_function", "function": "FuncA"}
                ]}"""));
            throw new AssertionError("Envelope mistake accepted");
        }
        catch (BridgeFailure expected) {
            check(expected.getMessage().contains("operations[1]"), "Envelope error lost its index");
        }
        try {
            operations.batchAnnotate(args("{\"operations\": []}"));
            throw new AssertionError("Empty batch accepted");
        }
        catch (BridgeFailure expected) {
            check("missing_argument".equals(expected.code), "Wrong empty-batch code");
        }
    }

    /** create_function on a defined entry reports alreadyDefined without journaling. */
    private static void batchCreateFunctionAlreadyDefined() throws Exception {
        Path directory = freshJournalDir();
        try {
            Fixture fixture = new Fixture();
            Function first = fixture.function(fixture.first, 0);
            GhidraAnalysisOperations operations =
                new GhidraAnalysisOperations(() -> fixture.program(List.of(first)));
            JsonObject result = operations.batchAnnotate(args("""
                {"operations": [
                  {"kind": "create_function", "function": "30001000", "name": "NewFunc"}
                ]}"""));
            check(result.get("applied").getAsInt() == 1, "Create batch not applied");
            check(result.get("failed").getAsInt() == 0, "Create batch failed");
            JsonObject row = result.getAsJsonArray("results").get(0).getAsJsonObject();
            check(row.get("ok").getAsBoolean(), "Create row not ok");
            check(!row.get("committed").getAsBoolean(), "Defined entry reported committed");
            check(row.get("alreadyDefined").getAsBoolean(), "Defined entry lost alreadyDefined");
            check(!row.get("journaled").getAsBoolean(), "Defined entry journaled");
            check(Files.notExists(directory.resolve(SHA + ".jsonl")), "Defined entry left journal entries");
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = null;
        }
    }

    /** functions+start conflict, missing selector pair and non-string entry. */
    private static void analyzeValidation() throws Exception {
        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first)));
        try {
            operations.analyzeFunctions(args("{\"functions\": [\"FuncA\"], \"start\": \"FuncA\"}"));
            throw new AssertionError("functions+start accepted");
        }
        catch (BridgeFailure expected) {
            check("invalid_argument".equals(expected.code), "Wrong conflict code");
        }
        try {
            operations.analyzeFunctions(args("{}"));
            throw new AssertionError("Missing selectors accepted");
        }
        catch (BridgeFailure expected) {
            check("missing_argument".equals(expected.code), "Wrong missing-selector code");
        }
        try {
            operations.analyzeFunctions(args("{\"functions\": [42]}"));
            throw new AssertionError("Non-string selector accepted");
        }
        catch (BridgeFailure expected) {
            check("invalid_argument".equals(expected.code), "Wrong non-string code");
        }
    }

    /** Unknown selectors report per-index not_found rows; later selectors still run. */
    private static void analyzeNotFoundPerIndex() throws Exception {
        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first)));
        JsonObject result =
            operations.analyzeFunctions(args("{\"functions\": [\"NoSuchA\", \"NoSuchB\"]}"));
        JsonArray rows = result.getAsJsonArray("functions");
        check(rows.size() == 2, "not_found rows lost");
        for (int index = 0; index < 2; index++) {
            JsonObject row = rows.get(index).getAsJsonObject();
            check(row.get("index").getAsInt() == index, "Row order/index broken");
            check(!row.get("ok").getAsBoolean(), "Missing function reported ok");
            check("not_found".equals(row.get("code").getAsString()), "Wrong missing code");
        }
        check("NoSuchA".equals(rows.get(0).getAsJsonObject().get("selector").getAsString()),
            "Selector not echoed");
        check(!result.get("truncated").getAsBoolean(), "All-failure digest incorrectly truncated");
    }

    private static TaskMonitor cancelledMonitor() {
        return proxy(TaskMonitor.class, (p, m, a) -> switch (m.getName()) {
            case "isCancelled" -> true;
            case "toString" -> "cancelled";
            default -> {
                Class<?> type = m.getReturnType();
                if (!type.isPrimitive()) yield null;
                if (type == boolean.class) yield false;
                if (type == long.class) yield 0L;
                if (type == int.class) yield 0;
                yield null;
            }
        });
    }

    /** A cancelled request stops before the first selector and offers nextIndex. */
    private static void analyzeNextIndexOnCancel() throws Exception {
        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first)));
        GhidraBridgeServer.requestMonitor.set(cancelledMonitor());
        try {
            JsonObject result =
                operations.analyzeFunctions(args("{\"functions\": [\"FuncA\", \"FuncB\"]}"));
            check(result.getAsJsonArray("functions").size() == 0, "Cancelled digest ran entries");
            check(result.get("nextIndex").getAsInt() == 0, "nextIndex missing");
            check(result.get("timedOut").getAsBoolean(), "Cancellation not reported");
            check(result.get("truncated").getAsBoolean(), "Cancelled digest not truncated");
            check(!result.has("continuation"), "Cancelled digest must be cursor-only");
            check(result.getAsJsonObject("module").has("summary"), "Digest lost its hoisted module identity");
        }
        finally {
            GhidraBridgeServer.requestMonitor.remove();
        }
    }

    /** Start mode under cancellation still offers the address-ordered nextStart. */
    private static void analyzeStartModeNextStartOnCancel() throws Exception {
        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        Function second = fixture.function(fixture.second, 1);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first, second)));
        GhidraBridgeServer.requestMonitor.set(cancelledMonitor());
        try {
            JsonObject result = operations.analyzeFunctions(
                args("{\"start\": \"0x30001000\", \"maxFunctions\": 8}"));
            check(result.getAsJsonArray("functions").size() == 0, "Cancelled scan ran entries");
            check(result.has("nextStart"), "Start scan lost nextStart");
            check(fixture.first.toString().equals(result.get("nextStart").getAsString()),
                "nextStart points past the slice head");
        }
        finally {
            GhidraBridgeServer.requestMonitor.remove();
        }
    }

    /**
     * The digest is the compact view: no per-function instruction walk, no
     * echoed request knobs, and the 4-item default. The full identity card
     * keeps both the count and the walk.
     */
    private static void analyzeDigestIsLean() throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address entry = space.getAddress(0x30001000);
        AtomicBoolean listingTouched = new AtomicBoolean(false);
        AddressSetView body = proxy(AddressSetView.class, (p, m, a) -> switch (m.getName()) {
            case "getNumAddresses" -> 16L;
            default -> throw new AssertionError(m);
        });
        Listing listing = proxy(Listing.class, (p, m, a) -> {
            listingTouched.set(true);
            return iterator(
                ghidra.program.model.listing.InstructionIterator.class,
                List.of(
                    proxy(ghidra.program.model.listing.Instruction.class, (p2, m2, a2) -> null),
                    proxy(ghidra.program.model.listing.Instruction.class, (p2, m2, a2) -> null)));
        });
        Function function = proxy(Function.class, (p, m, a) -> switch (m.getName()) {
            case "getName" -> "FuncA";
            case "getEntryPoint" -> entry;
            case "getBody" -> body;
            case "getSymbol" -> symbol(SourceType.ANALYSIS);
            case "getProgram" -> proxy(Program.class, (p3, m3, a3) -> switch (m3.getName()) {
                case "getListing" -> listing;
                default -> throw new AssertionError(m3);
            });
            case "isThunk", "isExternal" -> false;
            default -> throw new AssertionError(m);
        });
        Program program = proxy(Program.class, (p, m, a) -> switch (m.getName()) {
            case "getImageBase" -> space.getAddress(0x30000000);
            case "getListing" -> listing;
            default -> throw new AssertionError(m);
        });

        JsonObject digest = GhidraAnalysisFormatting.functionDigest(program, function, false, false);
        check(!listingTouched.get(), "AnalyzeFunctions digest walked the listing");
        check("ANALYSIS".equals(digest.get("nameSource").getAsString()), "Digest lost the symbol provenance");
        check(!digest.getAsJsonObject("analysis").has("instructionCount"),
            "AnalyzeFunctions digest kept instructionCount");
        check(digest.getAsJsonObject("analysis").get("bodyBytes").getAsInt() == 16,
            "AnalyzeFunctions digest lost bodyBytes");

        JsonObject card = GhidraAnalysisFormatting.functionAnalysis(function, true);
        check(listingTouched.get(), "Full card skipped the instruction walk");
        check(card.get("instructionCount").getAsInt() == 2, "Full card lost instructionCount");

        Fixture fixture = new Fixture();
        Function first = fixture.function(fixture.first, 0);
        Program fixtureProgram = fixture.program(List.of(first));
        GhidraAnalysisOperations operations = new GhidraAnalysisOperations(() -> fixtureProgram);
        JsonObject result = operations.analyzeFunctions(args("{\"functions\": [\"FuncA\"]}"));
        check(!result.has("maxChars") && !result.has("maxItems"),
            "AnalyzeFunctions echoed request knobs");
        int listedOnce = fixture.listFunctionCalls;
        operations.analyzeFunctions(args("{\"functions\": [\"FuncA\"]}"));
        check(fixture.listFunctionCalls == listedOnce,
            "Program summary recounted the function table on the second call");
        check(!result.getAsJsonArray("functions").get(0).getAsJsonObject()
            .getAsJsonObject("function").getAsJsonObject("analysis").has("instructionCount"),
            "Wire digest kept instructionCount");
        check(GhidraBridgeServer.DEFAULT_ANALYZE_ITEMS == 4,
            "AnalyzeFunctions default items drifted");
    }

    /**
     * The module listing is a decompilation sample: LEAN analysis and a
     * summary that does not repeat module.summary or top-level counters.
     */
    private static void decompileModuleShapeIsLean() {
        check((GhidraAnalysisOperations.DECOMPILE_HEAD_FLAGS
            & GhidraAnalysisFormatting.HEAD_ANALYSIS) == 0,
            "DecompileModule still walks the listing for instructionCount");
        check((GhidraAnalysisOperations.DECOMPILE_HEAD_FLAGS
            & GhidraAnalysisFormatting.HEAD_ANALYSIS_LEAN) != 0,
            "DecompileModule lost its analysis block");

        JsonArray functions = new JsonArray();
        functions.add(new JsonObject());
        JsonObject summary = GhidraAnalysisOperations.moduleSummary(functions, "", false);
        check(summary.size() == 2 && summary.has("returnedFunctions") && summary.has("nextAction"),
            "DecompileModule summary repeats module.summary or top-level counters");
        check(summary.get("returnedFunctions").getAsInt() == 1, "returnedFunctions lost");
    }

    /** InspectFunction summary only carries the counters and the hint. */
    private static void inspectSummaryIsLean() {
        JsonObject result = new JsonObject();
        result.add("function", new JsonObject());
        JsonObject summary = GhidraAnalysisOperations.inspectSummary(
            null, result, true, false, false, false, false, false,
            new GhidraOutputBudget(16_000));
        check(!summary.has("name") && !summary.has("entry") && !summary.has("rva") && !summary.has("analysis"),
            "InspectFunction summary repeats the function identity");
        check(summary.has("decompilationStatus"), "InspectFunction summary lost decompilationStatus");
        check(summary.has("nextAction"), "InspectFunction summary lost nextAction");
    }

    /** The shared output budget cuts AnalyzeFunctions sections instead of failing. */
    private static void analyzeBudgetTruncation() {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address callerEntry = space.getAddress(0x30005000);
        Address targetEntry = space.getAddress(0x30006000);
        Function caller = proxy(Function.class, (p, m, a) -> switch (m.getName()) {
            case "getName" -> "main";
            case "getEntryPoint" -> callerEntry;
            default -> throw new AssertionError(m);
        });
        Function target = proxy(Function.class, (p, m, a) -> switch (m.getName()) {
            case "getBody" -> null;
            case "getEntryPoint" -> targetEntry;
            default -> throw new AssertionError(m);
        });
        ghidra.program.model.symbol.Reference incoming =
            proxy(ghidra.program.model.symbol.Reference.class, (p, m, a) -> switch (m.getName()) {
                case "getFromAddress" -> callerEntry;
                default -> throw new AssertionError(m);
            });
        FunctionManager manager = proxy(FunctionManager.class, (p, m, a) -> switch (m.getName()) {
            case "getFunctionContaining" -> caller;
            default -> throw new AssertionError(m);
        });
        ghidra.program.model.symbol.ReferenceManager references = proxy(
            ghidra.program.model.symbol.ReferenceManager.class, (p, m, a) -> switch (m.getName()) {
                case "getReferencesTo" -> iterator(
                    ghidra.program.model.symbol.ReferenceIterator.class, List.of(incoming));
                default -> throw new AssertionError(m);
            });
        Listing listing = proxy(Listing.class, (p, m, a) -> switch (m.getName()) {
            case "getCodeUnits" -> iterator(
                ghidra.program.model.listing.CodeUnitIterator.class, List.of());
            default -> throw new AssertionError(m);
        });
        Program program = proxy(Program.class, (p, m, a) -> switch (m.getName()) {
            case "getFunctionManager" -> manager;
            case "getReferenceManager" -> references;
            case "getListing" -> listing;
            default -> throw new AssertionError(m);
        });
        GhidraOutputBudget budget = new GhidraOutputBudget(0);
        JsonObject brief = GhidraAnalysisFormatting.referencesBrief(program, target, 8, budget);
        check(brief.getAsJsonArray("callers").size() == 0, "Exhausted budget emitted rows");
        check(budget.truncated, "Exhausted budget not flagged");
        check(budget.truncatedSections().toString().contains("references.callers"), "Budget cut unnamed");
    }

    /** libraryMatched counts ANALYSIS/IMPORTED rows so triage can skip them first. */
    private static void analyzeFunctionsLibraryMatched() throws Exception {
        Fixture fixture = new Fixture();
        fixture.sources[0] = SourceType.ANALYSIS;
        Function first = fixture.function(fixture.first, 0);
        Function second = fixture.function(fixture.second, 1);
        GhidraAnalysisOperations operations =
            new GhidraAnalysisOperations(() -> fixture.program(List.of(first, second)));
        JsonObject result = operations.analyzeFunctions(args("{\"functions\": [\"FuncA\", \"FuncB\"]}"));
        JsonArray rows = result.getAsJsonArray("functions");
        check(rows.size() == 2, "Digest rows lost");
        check("ANALYSIS".equals(rows.get(0).getAsJsonObject().getAsJsonObject("function")
            .get("nameSource").getAsString()), "ANALYSIS row lost provenance");
        check("DEFAULT".equals(rows.get(1).getAsJsonObject().getAsJsonObject("function")
            .get("nameSource").getAsString()), "DEFAULT row lost provenance");
        check(result.get("libraryMatched").getAsInt() == 1, "libraryMatched miscounted");
    }

    static void run() throws Exception {
        batchPerOpIndexedErrors();
        System.out.println("BatchAnnotate per-operation error checks passed.");
        batchRollbackWritesNoJournal();
        System.out.println("BatchAnnotate rollback journal checks passed.");
        batchEnvelopeIndexedError();
        System.out.println("BatchAnnotate envelope checks passed.");
        batchCreateFunctionAlreadyDefined();
        System.out.println("BatchAnnotate create_function checks passed.");
        analyzeValidation();
        analyzeNotFoundPerIndex();
        System.out.println("AnalyzeFunctions not_found checks passed.");
        analyzeNextIndexOnCancel();
        analyzeStartModeNextStartOnCancel();
        System.out.println("AnalyzeFunctions continuation checks passed.");
        analyzeBudgetTruncation();
        System.out.println("AnalyzeFunctions budget checks passed.");
        analyzeDigestIsLean();
        System.out.println("AnalyzeFunctions lean digest checks passed.");
        analyzeFunctionsLibraryMatched();
        System.out.println("AnalyzeFunctions libraryMatched checks passed.");
        decompileModuleShapeIsLean();
        System.out.println("DecompileModule lean shape checks passed.");
        inspectSummaryIsLean();
        System.out.println("InspectFunction lean summary checks passed.");
        System.out.println("Batch/analyze regression checks passed.");
    }
}
