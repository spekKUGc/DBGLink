package dbglink.ghidra;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Iterator;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

/** Regression checks using Ghidra interfaces; no GUI or imported program required. */
public final class GhidraFormattingChecks {
    private static <T> T stub(Class<T> type, Map<String, Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (proxy, method, args) -> {
                if (values.containsKey(method.getName())) return values.get(method.getName());
                throw new AssertionError("Unexpected call: " + method);
            }));
    }

    private static <T> T iterator(Class<T> type, List<?> values) {
        Iterator<?> iterator = values.iterator();
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (proxy, method, args) -> switch (method.getName()) {
                case "hasNext" -> iterator.hasNext();
                case "next" -> iterator.next();
                case "iterator" -> proxy;
                default -> throw new AssertionError(method);
            }));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final Address ADDRESS = stub(Address.class, Map.of("toString", "140001000"));
    private static final Function FUNCTION = stub(Function.class,
        new java.util.HashMap<>() {{ put("getBody", null); put("getEntryPoint", ADDRESS); }});

    private static void disassembly(int available, int limit, int chars, boolean truncated) {
        Instruction instruction = stub(Instruction.class,
            Map.of("getAddress", ADDRESS, "getMnemonicString", "RET", "toString", "RET"));
        Listing listing = stub(Listing.class, Map.of("getInstructions",
            iterator(InstructionIterator.class, java.util.Collections.nCopies(available, instruction))));
        Program program = stub(Program.class, Map.of("getListing", listing));
        GhidraOutputBudget budget = new GhidraOutputBudget(chars);
        JsonArray result = GhidraAnalysisFormatting.disassembly(program, FUNCTION, limit, budget);
        check(budget.truncated == truncated, "Incorrect instruction completeness");
        if (chars > 0) check(result.size() == Math.min(available, limit), "Incorrect instruction count");
        if (truncated) check(budget.truncatedSections().toString().contains("disassembly"), "Missing section");
    }

    private static void outgoingReferences(int available, int limit, boolean truncated) {
        Reference ref = stub(Reference.class, Map.of(
            "getFromAddress", ADDRESS, "getToAddress", ADDRESS,
            "getReferenceType", RefType.READ, "getSource", SourceType.DEFAULT, "getOperandIndex", 0));
        CodeUnit unit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            java.util.Collections.nCopies(available, ref).toArray(Reference[]::new)));
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> {
                if (method.getName().equals("getCodeUnits"))
                    return iterator(CodeUnitIterator.class, List.of(unit));
                throw new AssertionError(method);
            });
        ReferenceManager manager = stub(ReferenceManager.class,
            Map.of("getReferencesTo", iterator(ReferenceIterator.class, List.of())));
        Program program = stub(Program.class, Map.of("getListing", listing,
            "getReferenceManager", manager, "getFunctionManager", stub(FunctionManager.class, Map.of())));
        GhidraOutputBudget budget = new GhidraOutputBudget(10000);
        var result = GhidraAnalysisFormatting.references(program, FUNCTION, limit, budget);
        check(result.getAsJsonArray("xrefsFrom").size() == Math.min(available, limit), "Incorrect xref count");
        check(budget.truncated == truncated, "Incorrect xref completeness at last code unit");
    }

    /**
     * Function-card strings come from data references only: duplicates
     * collapse, UTF-16 is decoded, and unmapped/non-printable targets are
     * skipped instead of failing the card.
     */
    private static void functionStrings() {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x30000000);
        byte[] memory = new byte[64];
        byte[] ascii = "hello\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(ascii, 0, memory, 4, ascii.length);
        byte[] wide = "wide\0".getBytes(StandardCharsets.UTF_16LE);
        System.arraycopy(wide, 0, memory, 16, wide.length);

        MemoryBlock block = (MemoryBlock) Proxy.newProxyInstance(MemoryBlock.class.getClassLoader(),
            new Class<?>[] { MemoryBlock.class }, (proxy, method, args) -> switch (method.getName()) {
                case "isInitialized" -> true;
                case "getStart" -> base;
                case "getSize" -> (long) memory.length;
                case "getBytes" -> {
                    byte[] dest = (byte[]) args[1];
                    System.arraycopy(memory, (int) ((Address) args[0]).subtract(base), dest, 0, dest.length);
                    yield dest.length;
                }
                default -> throw new AssertionError(method);
            });
        Memory mem = stub(Memory.class, Map.of("getBlock", block));
        Reference asciiRef = stub(Reference.class, Map.of(
            "getReferenceType", RefType.READ, "getToAddress", base.add(4)));
        Reference wideRef = stub(Reference.class, Map.of(
            "getReferenceType", RefType.READ, "getToAddress", base.add(16)));
        Reference blankRef = stub(Reference.class, Map.of(
            "getReferenceType", RefType.READ, "getToAddress", base.add(40)));
        CodeUnit unit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            new Reference[] { asciiRef, asciiRef, wideRef, blankRef }));
        Listing listing = stub(Listing.class, Map.of("getCodeUnits",
            iterator(CodeUnitIterator.class, List.of(unit))));
        Function function = stub(Function.class, new java.util.HashMap<>() {{
            put("getBody", null);
            put("getEntryPoint", ADDRESS);
        }});
        Program program = stub(Program.class, Map.of("getMemory", mem, "getListing", listing));
        GhidraOutputBudget budget = new GhidraOutputBudget(10000);
        JsonArray result = GhidraAnalysisFormatting.functionStrings(program, function, 8, budget);
        check(result.size() == 2, "Data-reference strings lost or duplicated");
        check(result.get(0).getAsJsonObject().get("value").getAsString().equals("hello"), "ASCII string wrong");
        check(!result.get(0).getAsJsonObject().has("length"), "Derivable string length must stay omitted");
        check(result.get(1).getAsJsonObject().get("value").getAsString().equals("wide"), "UTF-16 string wrong");
    }

    /**
     * Function-card constants aggregate scalar operands, drop trivial values
     * (0, 1, all ones) and sort by descending count.
     */
    private static void functionConstants() {
        Instruction repeated = stub(Instruction.class, Map.of(
            "getAddress", ADDRESS, "getNumOperands", 1, "getScalar", new Scalar(32, 0x2aL)));
        Instruction mixed = (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getAddress" -> ADDRESS;
                case "getNumOperands" -> 3;
                case "getScalar" -> switch ((int) args[0]) {
                    case 0 -> new Scalar(32, 0x2aL);
                    case 1 -> new Scalar(32, 0x7L);
                    default -> new Scalar(32, 1L);
                };
                default -> throw new AssertionError(method);
            });
        Instruction trivial = stub(Instruction.class, Map.of(
            "getAddress", ADDRESS, "getNumOperands", 2, "getScalar", new Scalar(64, -1L)));
        Listing listing = stub(Listing.class, Map.of("getInstructions",
            iterator(InstructionIterator.class, List.of(repeated, mixed, trivial))));
        Program program = stub(Program.class, Map.of("getListing", listing));
        GhidraOutputBudget budget = new GhidraOutputBudget(10000);
        JsonArray result = GhidraAnalysisFormatting.functionConstants(program, FUNCTION, 8, budget);
        check(result.size() == 2, "Constants lost or trivial values kept");
        JsonObject first = result.get(0).getAsJsonObject();
        check(first.get("value").getAsString().equals("0x2a"), "Constant order/value wrong");
        check(first.get("count").getAsInt() == 2, "Constant count wrong");
        check(first.get("firstAddress").getAsString().equals(ADDRESS.toString()), "Constant first address wrong");
        check(result.get(1).getAsJsonObject().get("value").getAsString().equals("0x7"), "Second constant wrong");
    }

    /** The AnalyzeFunctions brief keeps caller/callee summaries but no xref rows. */
    private static void referencesBrief() {
        Address callerEntry = stub(Address.class, Map.of("toString", "140001000"));
        Address calleeEntry = stub(Address.class, Map.of("toString", "140001040"));
        Function caller = stub(Function.class, Map.of("getName", "main", "getEntryPoint", callerEntry));
        Function callee = stub(Function.class, Map.of("getName", "FixtureCallee", "getEntryPoint", calleeEntry));
        Function target = stub(Function.class, new java.util.HashMap<>() {{
            put("getBody", null);
            put("getEntryPoint", callerEntry);
        }});
        FunctionManager manager = stub(FunctionManager.class, Map.of(
            "getFunctionContaining", caller, "getFunctionAt", callee));
        Reference incoming = stub(Reference.class, Map.of("getFromAddress", callerEntry));
        Reference call = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getToAddress", calleeEntry));
        CodeUnit unit = stub(CodeUnit.class, Map.of("getReferencesFrom", new Reference[] { call }));
        Listing listing = stub(Listing.class, Map.of("getCodeUnits",
            iterator(CodeUnitIterator.class, List.of(unit))));
        ReferenceManager references = stub(ReferenceManager.class, Map.of("getReferencesTo",
            iterator(ReferenceIterator.class, List.of(incoming))));
        Program program = stub(Program.class, Map.of(
            "getFunctionManager", manager, "getListing", listing, "getReferenceManager", references));
        GhidraOutputBudget budget = new GhidraOutputBudget(10000);
        JsonObject result = GhidraAnalysisFormatting.referencesBrief(program, target, 8, budget);
        check(result.getAsJsonArray("callers").size() == 1, "Brief caller missing");
        check(result.getAsJsonArray("callees").size() == 1, "Brief callee missing");
        check(result.getAsJsonArray("callers").get(0).getAsJsonObject().get("name").getAsString().equals("main"),
            "Brief caller name wrong");
        check(result.getAsJsonArray("callees").get(0).getAsJsonObject().get("name").getAsString().equals("FixtureCallee"),
            "Brief callee name wrong");
    }

    /**
     * The analysis queue is leaves-first: functions that call nothing sort
     * before their callers; ties break by body size, then name.
     */
    private static void analysisQueueOrder() {
        JsonObject leaf = new JsonObject();
        leaf.addProperty("name", "leaf");
        leaf.addProperty("calleeCount", 0);
        leaf.addProperty("instructionCount", 20);
        JsonObject mid = new JsonObject();
        mid.addProperty("name", "mid");
        mid.addProperty("calleeCount", 1);
        mid.addProperty("instructionCount", 5);
        JsonObject root = new JsonObject();
        root.addProperty("name", "root");
        root.addProperty("calleeCount", 2);
        root.addProperty("instructionCount", 5);
        java.util.List<JsonObject> rows = new java.util.ArrayList<>(List.of(root, mid, leaf));
        GhidraAnalysisFormatting.sortQueueLeavesFirst(rows);
        check(rows.get(0).get("name").getAsString().equals("leaf"), "Queue leaf must come first");
        check(rows.get(1).get("name").getAsString().equals("mid"), "Queue caller must come after its callee");
        check(rows.get(2).get("name").getAsString().equals("root"), "Queue root must come last");
    }

    /**
     * AnalysisQueue envelope: limit echo, total/returned counts, truncation +
     * continuation, leaves-first row order, unknown-argument rejection and
     * module_not_found. Row shape/order sorting itself is covered by
     * analysisQueueOrder().
     */
    private static void analysisQueueEnvelope() throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x10000000);
        Address leafEntry = base.add(0x1000);
        Address rootEntry = base.add(0x1040);
        final String sha = "ab".repeat(32);

        Function leaf = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "leaf");
            put("getEntryPoint", leafEntry);
            put("getBody", new AddressSet(leafEntry, leafEntry.add(15)));
            put("isThunk", false);
            put("isExternal", false);
            put("getProgram", null);
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Function root = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "root");
            put("getEntryPoint", rootEntry);
            put("getBody", new AddressSet(rootEntry, rootEntry.add(15)));
            put("isThunk", false);
            put("isExternal", false);
            put("getProgram", null);
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.ANALYSIS)));
        }});
        FunctionManager manager = (FunctionManager) Proxy.newProxyInstance(
            FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getFunctions" -> iterator(FunctionIterator.class, List.of(root, leaf));
                case "getFunctionAt" -> null;
                default -> throw new AssertionError(method);
            });
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getInstructions" -> iterator(InstructionIterator.class, List.of());
                case "getCodeUnits" -> iterator(CodeUnitIterator.class, List.of());
                default -> throw new AssertionError(method);
            });
        Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getFunctionManager" -> manager;
                case "getListing" -> listing;
                case "getImageBase", "getMinAddress" -> base;
                case "getMaxAddress" -> base.add(0xFFFF);
                case "getExecutableSHA256" -> sha;
                case "getExecutablePath" -> "C:/target.dll";
                default -> throw new AssertionError(method);
            });

        GhidraAnalysisOperations operations = new GhidraAnalysisOperations(() -> program);
        JsonObject envelope = operations.analysisQueue(JsonParser.parseString("{\"limit\":1}").getAsJsonObject());
        check(envelope.get("schemaVersion").getAsInt() == 2, "AnalysisQueue envelope version wrong");
        check(envelope.getAsJsonArray("queue").size() == 1, "AnalysisQueue limit ignored");
        check(!envelope.has("totalFunctions"), "AnalysisQueue must drop the totalFunctions echo");
        check(!envelope.has("returned"), "AnalysisQueue must drop the returned echo");
        check(!envelope.has("limit"), "AnalysisQueue must drop the limit echo");
        check(envelope.get("truncated").getAsBoolean(), "AnalysisQueue truncation missing");
        check(envelope.get("continuation").getAsString().contains("higher limit"),
            "AnalysisQueue continuation missing");
        check(envelope.getAsJsonArray("queue").get(0).getAsJsonObject().get("name").getAsString().equals("leaf"),
            "AnalysisQueue must be leaves-first");
        JsonObject leafRow = envelope.getAsJsonArray("queue").get(0).getAsJsonObject();
        check(!leafRow.has("rva"), "Queue rva must be opt-in");
        check("DEFAULT".equals(leafRow.get("nameSource").getAsString()), "Queue row lost the name provenance");
        JsonObject withRva = operations.analysisQueue(
            JsonParser.parseString("{\"limit\":1,\"includeRva\":true}").getAsJsonObject());
        check(withRva.getAsJsonArray("queue").get(0).getAsJsonObject().has("rva"), "includeRva lost the rva");
        try {
            operations.analysisQueue(JsonParser.parseString("{\"bogus\":1}").getAsJsonObject());
            throw new AssertionError("AnalysisQueue accepted an unknown argument");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("unknown_argument"), "Wrong AnalysisQueue unknown-arg error");
        }
        try {
            operations.analysisQueue(JsonParser.parseString("{\"module\":\"other.dll\"}").getAsJsonObject());
            throw new AssertionError("AnalysisQueue accepted a foreign module");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("module_not_found"), "Wrong AnalysisQueue module error");
        }

        // Durable progress: a journal entry for a function makes GetAnalysisQueue
        // skip it (excludeAnnotated default true) and report doneCount.
        java.nio.file.Path journalDir = java.nio.file.Files.createTempDirectory("dbglink-progress");
        java.nio.file.Path journalFile = journalDir.resolve(sha + ".jsonl");
        try {
            DbgLinkAnnotationJournal.directoryOverride = journalDir;
            java.nio.file.Files.write(journalFile,
                ("{\"kind\":\"rename_function\",\"entry\":\"" + leafEntry + "\"}\n")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            JsonObject filtered = operations.analysisQueue(JsonParser.parseString("{}").getAsJsonObject());
            check(filtered.get("doneCount").getAsInt() == 1, "AnalysisQueue must count the annotated function as done");
            check(filtered.get("remainingCount").getAsInt() == 1, "AnalysisQueue must drop the annotated function");
            check(filtered.getAsJsonArray("queue").size() == 1, "AnalysisQueue must not re-suggest an annotated function");
            check(filtered.getAsJsonArray("queue").get(0).getAsJsonObject().get("name").getAsString().equals("root"),
                "AnalysisQueue remaining row wrong");
            JsonObject unfiltered = operations.analysisQueue(
                JsonParser.parseString("{\"excludeAnnotated\":false}").getAsJsonObject());
            check(unfiltered.get("doneCount").getAsInt() == 0, "excludeAnnotated=false must not count done");
            check(unfiltered.getAsJsonArray("queue").size() == 2, "excludeAnnotated=false must keep every row");
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = null;
            try {
                java.nio.file.Files.deleteIfExists(journalFile);
                java.nio.file.Files.deleteIfExists(journalDir);
            }
            catch (java.io.IOException ignored) {
                // Temp cleanup is best-effort.
            }
        }
    }

    /** CallGraph aggregates caller-to-callee call sites, caps nodes/edges and continues by nextStart. */
    private static void callGraph() throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x10000000);
        Address callerEntry = base.add(0x1000);
        Address calleeEntry = base.add(0x1040);
        Address otherEntry = base.add(0x1080);

        Reference callToCallee = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getToAddress", calleeEntry));
        Reference callToOther = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getToAddress", otherEntry));
        Reference dataRef = stub(Reference.class, Map.of(
            "getReferenceType", RefType.READ, "getToAddress", base.add(0x2000)));
        CodeUnit callerUnit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            new Reference[] { callToCallee, callToCallee, callToOther, dataRef }));

        Function caller = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "FixtureCaller");
            put("getEntryPoint", callerEntry);
            put("getBody", new AddressSet(callerEntry, callerEntry.add(31)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Function callee = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "FixtureCallee");
            put("getEntryPoint", calleeEntry);
            put("getBody", new AddressSet(calleeEntry, calleeEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.ANALYSIS)));
        }});
        Function other = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "FixtureOther");
            put("getEntryPoint", otherEntry);
            put("getBody", new AddressSet(otherEntry, otherEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Map<Address, Function> byEntry = Map.of(callerEntry, caller, calleeEntry, callee, otherEntry, other);
        FunctionManager manager = (FunctionManager) java.lang.reflect.Proxy.newProxyInstance(
            FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getFunctions" -> iterator(FunctionIterator.class, List.of(caller, callee, other));
                case "getFunctionAt" -> byEntry.get(args[0]);
                default -> throw new AssertionError(method);
            });
        Listing listing = (Listing) java.lang.reflect.Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getCodeUnits" -> {
                    AddressSetView body = (AddressSetView) args[0];
                    if (body.contains(callerEntry)) {
                        yield iterator(CodeUnitIterator.class, List.of(callerUnit));
                    }
                    yield iterator(CodeUnitIterator.class, List.of());
                }
                case "getInstructions" -> iterator(InstructionIterator.class, List.of());
                default -> throw new AssertionError(method);
            });
        Program program = stub(Program.class, new java.util.HashMap<>() {{
            put("getFunctionManager", manager);
            put("getListing", listing);
            put("getImageBase", base);
        }});

        JsonObject full = GhidraAnalysisFormatting.callGraph(program, base, base.add(0xFFFF), 256, 1024, false);
        check(full.getAsJsonArray("nodes").size() == 3, "CallGraph nodes lost");
        JsonObject node = full.getAsJsonArray("nodes").get(0).getAsJsonObject();
        check(node.get("name").getAsString().equals("FixtureCaller"), "CallGraph node name wrong");
        check(node.get("entry").getAsString().equals(callerEntry.toString()), "CallGraph node entry wrong");
        check(!node.has("instructionCount"), "CallGraph node instruction count must be opt-in");
        check(!full.has("nodeCount") && !full.has("edgeCount"), "Derivable node/edge counts must stay omitted");
        JsonArray edges = full.getAsJsonArray("edges");
        check(edges.size() == 2, "CallGraph edges lost or data refs counted as calls");
        JsonObject first = edges.get(0).getAsJsonObject();
        check(first.get("s").getAsInt() == 0, "CallGraph edge source index wrong");
        check(first.get("t").getAsInt() == 1, "CallGraph edge target index wrong");
        check(first.get("n").getAsInt() == 2, "CallGraph call counts wrong");
        check(!first.has("caller") && !first.has("callee") && !first.has("count"), "CallGraph edges must be integer-indexed");
        JsonObject second = edges.get(1).getAsJsonObject();
        check(second.get("s").getAsInt() == 0 && second.get("t").getAsInt() == 2 && second.get("n").getAsInt() == 1,
            "CallGraph second edge wrong");
        check(full.get("totalCalls").getAsInt() == 3, "CallGraph total call count wrong");
        check(!full.get("truncated").getAsBoolean(), "Complete graph incorrectly truncated");

        JsonObject counted = GhidraAnalysisFormatting.callGraph(program, base, base.add(0xFFFF), 256, 1024, true);
        check(counted.getAsJsonArray("nodes").get(0).getAsJsonObject().has("instructionCount"),
            "includeInstructionCount lost the counts");

        JsonObject capped = GhidraAnalysisFormatting.callGraph(program, base, base.add(0xFFFF), 2, 1024, false);
        check(capped.getAsJsonArray("nodes").size() == 2, "CallGraph node cap ignored");
        check(capped.get("truncated").getAsBoolean(), "Missing node continuation");
        check(capped.get("nextStart").getAsString().equals(otherEntry.toString()), "CallGraph continuation cursor wrong");
        check(!capped.has("continuation"), "Cursor continuation must be cursor-only");

        JsonObject edgeCapped = GhidraAnalysisFormatting.callGraph(program, base, base.add(0xFFFF), 256, 1, false);
        check(edgeCapped.getAsJsonArray("edges").size() == 1, "CallGraph edge cap ignored");
        check(edgeCapped.get("truncated").getAsBoolean(), "Missing edge continuation");
        check(!edgeCapped.has("nextStart"), "Edge-only truncation must not report nextStart");

        JsonObject slice = GhidraAnalysisFormatting.callGraph(program, calleeEntry, base.add(0xFFFF), 256, 1024, false);
        check(slice.getAsJsonArray("nodes").size() == 2, "CallGraph range slice lost nodes");
        check(slice.getAsJsonArray("edges").size() == 0, "CallGraph range slice kept out-of-range edges");
        check(!slice.get("truncated").getAsBoolean(), "Range slice incorrectly truncated");

        JsonObject legacy = GhidraAnalysisFormatting.callGraph(program, base, base.add(0xFFFF), 256, 1024, false, "full");
        JsonArray legacyEdges = legacy.getAsJsonArray("edges");
        check(legacyEdges.size() == 2, "CallGraph full edges lost");
        JsonObject legacyFirst = legacyEdges.get(0).getAsJsonObject();
        check(legacyFirst.get("caller").getAsString().equals(callerEntry.toString()), "CallGraph full caller wrong");
        check(legacyFirst.get("callee").getAsString().equals(calleeEntry.toString()), "CallGraph full callee wrong");
        check(legacyFirst.get("count").getAsInt() == 2, "CallGraph full count wrong");
        check(!legacyFirst.has("s") && !legacyFirst.has("t") && !legacyFirst.has("n"), "CallGraph full edges leaked indexed keys");
        JsonObject legacySecond = legacyEdges.get(1).getAsJsonObject();
        check(legacySecond.get("caller").getAsString().equals(callerEntry.toString())
            && legacySecond.get("callee").getAsString().equals(otherEntry.toString())
            && legacySecond.get("count").getAsInt() == 1, "CallGraph full second edge wrong");

        Program fullProgram = (Program) java.lang.reflect.Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getFunctionManager" -> manager;
                case "getListing" -> listing;
                case "getImageBase", "getMinAddress" -> base;
                case "getMaxAddress" -> base.add(0xFFFF);
                case "getExecutableSHA256" -> "test-hash";
                case "getExecutablePath" -> "C:/target.dll";
                case "parseAddress" -> new Address[] {
                    space.getAddress(Long.parseUnsignedLong(((String) args[0]).replace("0x", ""), 16)) };
                default -> throw new AssertionError(method);
            });
        GhidraAnalysisOperations operations = new GhidraAnalysisOperations(() -> fullProgram);
        JsonObject result = operations.callGraph(JsonParser.parseString("{}").getAsJsonObject());
        check(result.get("schemaVersion").getAsInt() == 3, "CallGraph envelope version wrong");
        check(result.getAsJsonArray("nodes").size() == 3, "CallGraph envelope nodes lost");
        check(result.getAsJsonObject("summary").get("totalCalls").getAsInt() == 3, "CallGraph envelope summary wrong");
        check(result.getAsJsonObject("summary").get("nodeCount").getAsInt() == 3, "CallGraph summary node count wrong");
        check(result.getAsJsonObject("summary").get("edgeCount").getAsInt() == 2, "CallGraph summary edge count wrong");
        check(result.getAsJsonObject("module").get("path").getAsString().equals("C:/target.dll"),
            "CallGraph module identity wrong");
        check(!result.getAsJsonObject("module").has("sha256"), "CallGraph must drop the module sha256 echo");
        check(!result.has("start") && !result.has("end") && !result.has("maxNodes") && !result.has("maxEdges"),
            "CallGraph must drop input echoes");
        check(!result.has("nodeCount") && !result.has("edgeCount"), "CallGraph must drop derivable counts");
        JsonObject indexedDefault = result.getAsJsonArray("edges").get(0).getAsJsonObject();
        check(indexedDefault.has("s") && indexedDefault.has("t") && indexedDefault.has("n"), "CallGraph default edges must stay indexed");
        JsonObject fullResult = operations.callGraph(JsonParser.parseString("{\"edgeFormat\":\"full\"}").getAsJsonObject());
        check(fullResult.get("schemaVersion").getAsInt() == 3, "CallGraph full envelope version wrong");
        JsonObject fullEdge = fullResult.getAsJsonArray("edges").get(0).getAsJsonObject();
        check(fullEdge.has("caller") && fullEdge.has("callee") && fullEdge.has("count"), "edgeFormat=full lost legacy keys");
        check(!fullEdge.has("s") && !fullEdge.has("t") && !fullEdge.has("n"), "edgeFormat=full leaked indexed keys");
        check(fullEdge.get("count").getAsInt() == 2, "edgeFormat=full count wrong");
        JsonObject indexedExplicit = operations.callGraph(JsonParser.parseString("{\"edgeFormat\":\"indexed\"}").getAsJsonObject());
        check(indexedExplicit.getAsJsonArray("edges").get(0).getAsJsonObject().has("s"), "edgeFormat=indexed lost indexed keys");
        try {
            operations.callGraph(JsonParser.parseString("{\"edgeFormat\":\"matrix\"}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted a bad edgeFormat");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("invalid_argument"), "Wrong CallGraph edgeFormat error");
        }
        try {
            operations.callGraph(JsonParser.parseString("{\"bogus\":1}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted an unknown argument");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("unknown_argument"), "Wrong CallGraph envelope error");
        }
        try {
            operations.callGraph(JsonParser.parseString("{\"start\":\"10001080\",\"end\":\"10001000\"}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted an inverted range");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("invalid_argument"), "Wrong CallGraph range error");
        }
        try {
            operations.callGraph(JsonParser.parseString("{\"maxNodes\":257}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted maxNodes past its cap");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("argument_out_of_range"), "Wrong CallGraph node limit error");
        }
        try {
            operations.callGraph(JsonParser.parseString("{\"maxEdges\":1025}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted maxEdges past its cap");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("argument_out_of_range"), "Wrong CallGraph edge limit error");
        }
        try {
            operations.callGraph(JsonParser.parseString("{\"module\":\"other.dll\"}").getAsJsonObject());
            throw new AssertionError("CallGraph accepted a foreign module");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("module_not_found"), "Wrong CallGraph module error");
        }
    }

    /** AnalyzeFunctions digest gates prototype/comment; empty comments stay omitted even when requested. */
    private static void functionDigestOptIns() {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x10000000);
        Address entry = base.add(0x1000);
        Function withComment = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "Named");
            put("getEntryPoint", entry);
            put("getBody", null);
            put("isThunk", false);
            put("isExternal", false);
            put("getPrototypeString", "void Named()");
            put("getComment", "triage note");
            put("getProgram", null);
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.ANALYSIS)));
        }});
        Function withoutComment = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "Named");
            put("getEntryPoint", entry);
            put("getBody", null);
            put("isThunk", false);
            put("isExternal", false);
            put("getPrototypeString", "void Named()");
            put("getComment", "");
            put("getProgram", null);
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Program program = stub(Program.class, new java.util.HashMap<>() {{
            put("getImageBase", base);
            put("getListing", stub(Listing.class, Map.of("getInstructions",
                iterator(InstructionIterator.class, List.of()))));
        }});
        JsonObject slim = GhidraAnalysisFormatting.functionDigest(program, withComment, false, false);
        check(!slim.has("prototype"), "Digest prototype must be opt-in");
        check(!slim.has("comment"), "Digest comment must be opt-in");
        check("ANALYSIS".equals(slim.get("nameSource").getAsString()), "Digest lost the ANALYSIS provenance");
        JsonObject gated = GhidraAnalysisFormatting.functionDigest(program, withComment, true, true);
        check(gated.get("prototype").getAsString().equals("void Named()"), "includePrototype lost the signature");
        check(gated.get("comment").getAsString().equals("triage note"), "includeComments lost the comment");
        JsonObject emptyComment = GhidraAnalysisFormatting.functionDigest(program, withoutComment, false, true);
        check(!emptyComment.has("comment"), "Empty comment must stay omitted even when requested");
        check(emptyComment.has("analysis"), "Digest lost its analysis block");
    }

    /** callGraphNode and DecompileModule entries omit rva when it is null (EXTERNAL space), like functionDigest. */
    private static void callGraphNodeRvaOmit() {
        AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        AddressSpace external = new GenericAddressSpace("EXTERNAL", 32, AddressSpace.TYPE_RAM, 1);
        Address base = ram.getAddress(0x10000000);
        Address outside = external.getAddress(0x1000);
        Function foreign = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "Imported");
            put("getEntryPoint", outside);
            put("getBody", null);
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.IMPORTED)));
        }});
        Program program = stub(Program.class, new java.util.HashMap<>() {{
            put("getImageBase", base);
            put("getListing", stub(Listing.class, Map.of("getInstructions",
                iterator(InstructionIterator.class, List.of()))));
        }});
        JsonObject node = GhidraAnalysisFormatting.callGraphNode(program, foreign, false);
        check(!node.has("rva"), "callGraphNode must omit null rva");
        check(node.get("entry").getAsString().equals(outside.toString()), "callGraphNode lost its entry");
    }

    /** SEC-C J5: UNC/extended prefixes and ".." are rejected as input paths. */
    private static void frontendUncRejected() throws Exception {
        var parse = DbgLinkFrontEndPlugin.class.getDeclaredMethod("parseInputPath", String.class);
        parse.setAccessible(true);
        var safe = DbgLinkFrontEndPlugin.class.getDeclaredMethod("isSafeInputPath", java.nio.file.Path.class);
        safe.setAccessible(true);

        check(parse.invoke(null, (Object) null) == null, "Null input path accepted");
        check(parse.invoke(null, "\\\\server\\share\\file.exe") == null, "UNC backslash path accepted");
        check(parse.invoke(null, "//server/share/file.exe") == null, "UNC slash path accepted");
        check(parse.invoke(null, "\\\\?\\C:\\file.exe") == null, "Extended-path prefix accepted");
        check(parse.invoke(null, "C:\\a\\..\\b\\file.exe") == null, "Dot-dot segment accepted");
        check(parse.invoke(null, "../outside.exe") == null, "Relative dot-dot accepted");

        java.nio.file.Path unc = java.nio.file.Path.of("//server/share/file.exe");
        check(Boolean.FALSE.equals(safe.invoke(null, unc)), "UNC path passed isSafeInputPath");

        // A real local temp file still parses (POSIX absolute on fixtures).
        java.nio.file.Path valid = java.nio.file.Files.createTempFile("dbglink-input", ".bin");
        try {
            check(parse.invoke(null, valid.toString()) != null, "Valid local input path rejected");
        }
        finally {
            java.nio.file.Files.deleteIfExists(valid);
        }
    }

    /**
     * Coverage G3: device-name parity with the .NET/native layers plus the
     * remaining UNC spellings. DOS device segments die at every position, in
     * any case, with or without an extension or trailing dots/spaces;
     * {@code \\.\} / {@code //?/} extended prefixes and drive-relative
     * {@code C:evil} spellings die before absolutization.
     */
    private static void frontendDeviceAndVariantsRejected() throws Exception {
        var parse = DbgLinkFrontEndPlugin.class.getDeclaredMethod("parseInputPath", String.class);
        parse.setAccessible(true);
        var safe = DbgLinkFrontEndPlugin.class.getDeclaredMethod("isSafeInputPath", java.nio.file.Path.class);
        safe.setAccessible(true);
        var rawDevice = DbgLinkFrontEndPlugin.class.getDeclaredMethod(
            "containsReservedDeviceSegment", String.class);
        rawDevice.setAccessible(true);
        var driveRelative = DbgLinkFrontEndPlugin.class.getDeclaredMethod(
            "isDriveRelativeRawPath", String.class);
        driveRelative.setAccessible(true);

        // Extended/device UNC variants (covered by the UNC gate on Windows and
        // rejected as non-absolute on POSIX fixtures alike).
        check(parse.invoke(null, "\\\\.\\C:\\file.exe") == null, "Device-prefix path accepted");
        check(parse.invoke(null, "//?/C:/file.exe") == null, "Slash device-prefix path accepted");
        check(parse.invoke(null, "\\??\\C:\\file.exe") == null, "NT \\??\\ prefix accepted");
        // Drive-relative spellings resolve against the CWD once absolutized.
        check(parse.invoke(null, "C:evil.exe") == null, "Drive-relative path accepted");
        check(parse.invoke(null, "C:") == null, "Bare drive-relative accepted");
        check(parse.invoke(null, "C:foo\\bar.exe") == null, "Drive-relative nested path accepted");
        check(Boolean.TRUE.equals(driveRelative.invoke(null, "C:evil")), "Drive-relative not detected");
        check(Boolean.FALSE.equals(driveRelative.invoke(null, "C:\\evil")), "Drive root flagged relative");
        check(Boolean.FALSE.equals(driveRelative.invoke(null, "C:/evil")), "Drive slash root flagged relative");

        // Raw device-segment parity (.NET LocalPathPolicy / native IsDosDeviceStem).
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\CON\\a.exe")), "CON segment missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:/dir/nul.txt")), "NUL with extension missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\dir\\COM1")), "COM1 segment missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\dir\\lpt9.log")), "LPT9 case/extension missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\dir\\AUX:stream")), "AUX ADS stem missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\dir\\CON ")), "Trailing-space device missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\dir\\COM1.")), "Trailing-dot device missed");
        check(Boolean.TRUE.equals(rawDevice.invoke(null, "C:\\CONIN$\\a.exe")), "CONIN$ missed");
        check(Boolean.FALSE.equals(rawDevice.invoke(null, "C:\\dir\\file.txt")), "Clean path flagged");
        check(Boolean.FALSE.equals(rawDevice.invoke(null, "C:\\dir\\COM10\\a.exe")), "COM10 flagged as device");
        check(Boolean.FALSE.equals(rawDevice.invoke(null, "C:\\dir\\console\\a.exe")), "console flagged as device");
        check(parse.invoke(null, "C:\\COM1\\a.exe") == null, "COM1 path accepted");

        // OS-independent Path gate: an existing device-named file is still
        // rejected while its clean sibling parses.
        java.nio.file.Path sandbox = java.nio.file.Files.createTempDirectory("dbglink-devices");
        java.nio.file.Path deviceFile = sandbox.resolve("nul.txt");
        java.nio.file.Path cleanFile = sandbox.resolve("ok.bin");
        java.nio.file.Files.write(deviceFile, new byte[] {1});
        java.nio.file.Files.write(cleanFile, new byte[] {1});
        try {
            check(parse.invoke(null, deviceFile.toString()) == null, "Device-named file accepted");
            check(Boolean.FALSE.equals(safe.invoke(null, deviceFile)), "Device file passed isSafeInputPath");
            check(parse.invoke(null, cleanFile.toString()) != null, "Clean sibling rejected");
            check(Boolean.TRUE.equals(safe.invoke(null, cleanFile)), "Clean sibling failed isSafeInputPath");
        }
        finally {
            java.nio.file.Files.deleteIfExists(deviceFile);
            java.nio.file.Files.deleteIfExists(cleanFile);
            java.nio.file.Files.deleteIfExists(sandbox);
        }
    }

    /** SEC-C J9: bidi/format controls are rejected in validated bridge text. */
    private static void bidiControlsRejected() throws Exception {
        String bidi = "hi" + new String(Character.toChars(0x202E)) + "there";
        try {
            GhidraBridgeServer.validateTextCharacters(bidi, "comment", true);
            throw new AssertionError("Bidi override accepted in comment");
        }
        catch (BridgeFailure expected) {
            check("invalid_argument".equals(expected.code), "Wrong bidi error code");
        }
        try {
            GhidraBridgeServer.validateTextCharacters(bidi, "name", false);
            throw new AssertionError("Bidi override accepted in name");
        }
        catch (BridgeFailure expected) {
            check("invalid_argument".equals(expected.code), "Wrong bidi name error code");
        }
        // Coverage G15: every blocklisted format control is rejected in both
        // names and comments (zero-width/invisible/bidi isolates).
        int[] blocklisted = {0x200B, 0x200F, 0x2066, 0x00AD, 0xFEFF};
        for (int codePoint : blocklisted) {
            String sample = "a" + new String(Character.toChars(codePoint)) + "b";
            try {
                GhidraBridgeServer.validateTextCharacters(sample, "name", false);
                throw new AssertionError(
                    "Blocklisted U+" + Integer.toHexString(codePoint) + " accepted in name");
            }
            catch (BridgeFailure expected) {
                check("invalid_argument".equals(expected.code), "Wrong blocklist name error code");
            }
            try {
                GhidraBridgeServer.validateTextCharacters(sample, "comment", true);
                throw new AssertionError(
                    "Blocklisted U+" + Integer.toHexString(codePoint) + " accepted in comment");
            }
            catch (BridgeFailure expected) {
                check("invalid_argument".equals(expected.code), "Wrong blocklist comment error code");
            }
        }
        // Plain text still passes.
        GhidraBridgeServer.validateTextCharacters("Valid_Name123", "name", false);
        GhidraBridgeServer.validateTextCharacters("line one\nline two", "comment", true);
    }

    /**
     * Coverage G15: boundedInt gates. Missing keys take the default, in-range
     * edges pass, and out-of-range/non-integer spellings fail with the
     * documented codes without changing any emitted shape.
     */
    private static void boundedIntChecks() throws Exception {
        JsonObject missing = JsonParser.parseString("{}").getAsJsonObject();
        check(GhidraBridgeServer.boundedInt(missing, "maxItems", 32, 1, 512) == 32,
            "boundedInt default lost");
        JsonObject edges = JsonParser.parseString("{\"a\":1,\"b\":512}").getAsJsonObject();
        check(GhidraBridgeServer.boundedInt(edges, "a", 32, 1, 512) == 1, "boundedInt min edge rejected");
        check(GhidraBridgeServer.boundedInt(edges, "b", 32, 1, 512) == 512, "boundedInt max edge rejected");
        for (String json : new String[] {"{\"v\":0}", "{\"v\":513}", "{\"v\":-1}"}) {
            try {
                GhidraBridgeServer.boundedInt(JsonParser.parseString(json).getAsJsonObject(), "v", 32, 1, 512);
                throw new AssertionError("Out-of-range boundedInt accepted: " + json);
            }
            catch (BridgeFailure expected) {
                check("argument_out_of_range".equals(expected.code), "Wrong boundedInt range code");
            }
        }
        for (String json : new String[] {"{\"v\":\"3\"}", "{\"v\":true}", "{\"v\":1.5}", "{\"v\":\"01\"}"}) {
            try {
                GhidraBridgeServer.boundedInt(JsonParser.parseString(json).getAsJsonObject(), "v", 32, 1, 512);
                throw new AssertionError("Non-integer boundedInt accepted: " + json);
            }
            catch (BridgeFailure expected) {
                check("invalid_argument".equals(expected.code), "Wrong boundedInt type code");
            }
        }
    }

    /**
     * CallGraph neighborhood: BFS depth/direction, exact induced-edge counts,
     * node/edge caps with frontier, and sensitive-name nextBest ranking. No
     * decompiler is involved.
     */
    private static void callGraphNeighborhood() throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x10000000);
        Address mainEntry = base.add(0x1000);
        Address decryptEntry = base.add(0x1100);
        Address helperEntry = base.add(0x1200);
        Address aesEntry = base.add(0x1300);
        Address callerEntry = base.add(0x1400);

        Function main = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "main");
            put("getEntryPoint", mainEntry);
            put("getBody", new AddressSet(mainEntry, mainEntry.add(31)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Function decrypt = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "DecryptPayload");
            put("getEntryPoint", decryptEntry);
            put("getBody", new AddressSet(decryptEntry, decryptEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Function helper = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "FIXTURE_Helper");
            put("getEntryPoint", helperEntry);
            put("getBody", new AddressSet(helperEntry, helperEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});
        Function aes = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "AES_Init");
            put("getEntryPoint", aesEntry);
            put("getBody", new AddressSet(aesEntry, aesEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.ANALYSIS)));
        }});
        Function caller = stub(Function.class, new java.util.HashMap<>() {{
            put("getName", "entry_caller");
            put("getEntryPoint", callerEntry);
            put("getBody", new AddressSet(callerEntry, callerEntry.add(15)));
            put("getSymbol", stub(Symbol.class, Map.of("getSource", SourceType.DEFAULT)));
        }});

        java.util.Map<Address, Function> byEntry = new java.util.HashMap<>();
        byEntry.put(mainEntry, main);
        byEntry.put(decryptEntry, decrypt);
        byEntry.put(helperEntry, helper);
        byEntry.put(aesEntry, aes);
        byEntry.put(callerEntry, caller);

        Reference mainToDecrypt = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getFromAddress", mainEntry, "getToAddress", decryptEntry));
        Reference mainToHelper1 = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getFromAddress", mainEntry, "getToAddress", helperEntry));
        Reference mainToHelper2 = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getFromAddress", mainEntry, "getToAddress", helperEntry));
        Reference decryptToAes = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getFromAddress", decryptEntry, "getToAddress", aesEntry));
        Reference callerToMain = stub(Reference.class, Map.of(
            "getReferenceType", RefType.UNCONDITIONAL_CALL, "getFromAddress", callerEntry, "getToAddress", mainEntry));

        CodeUnit mainUnit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            new Reference[] { mainToDecrypt, mainToHelper1, mainToHelper2 }));
        CodeUnit decryptUnit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            new Reference[] { decryptToAes }));
        CodeUnit callerUnit = stub(CodeUnit.class, Map.of("getReferencesFrom",
            new Reference[] { callerToMain }));
        CodeUnit emptyUnit = stub(CodeUnit.class, Map.of("getReferencesFrom", new Reference[0]));
        java.util.Map<Address, CodeUnit> units = new java.util.HashMap<>();
        units.put(mainEntry, mainUnit);
        units.put(decryptEntry, decryptUnit);
        units.put(callerEntry, callerUnit);
        units.put(helperEntry, emptyUnit);
        units.put(aesEntry, emptyUnit);

        java.util.Map<Address, List<Reference>> incoming = new java.util.HashMap<>();
        incoming.put(mainEntry, List.of(callerToMain));
        incoming.put(decryptEntry, List.of(mainToDecrypt));
        incoming.put(helperEntry, List.of(mainToHelper1, mainToHelper2));
        incoming.put(aesEntry, List.of(decryptToAes));

        FunctionManager manager = (FunctionManager) java.lang.reflect.Proxy.newProxyInstance(
            FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getFunctionAt" -> byEntry.get(args[0]);
                case "getFunctionContaining" -> {
                    Address address = (Address) args[0];
                    Function match = null;
                    for (java.util.Map.Entry<Address, Function> candidate : byEntry.entrySet()) {
                        if (((AddressSetView) candidate.getValue().getBody()).contains(address)) {
                            match = candidate.getValue();
                            break;
                        }
                    }
                    yield match;
                }
                default -> throw new AssertionError(method);
            });

        Listing listing = (Listing) java.lang.reflect.Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getCodeUnits" -> {
                    AddressSetView body = (AddressSetView) args[0];
                    CodeUnit match = null;
                    for (java.util.Map.Entry<Address, CodeUnit> candidate : units.entrySet()) {
                        if (body.contains(candidate.getKey())) {
                            match = candidate.getValue();
                            break;
                        }
                    }
                    yield iterator(CodeUnitIterator.class, match == null ? List.of() : List.of(match));
                }
                case "getInstructions" -> iterator(InstructionIterator.class, List.of());
                default -> throw new AssertionError(method);
            });

        ReferenceManager references = (ReferenceManager) java.lang.reflect.Proxy.newProxyInstance(
            ReferenceManager.class.getClassLoader(), new Class<?>[] { ReferenceManager.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getReferencesTo" -> iterator(ReferenceIterator.class,
                    incoming.getOrDefault((Address) args[0], List.of()));
                default -> throw new AssertionError(method);
            });

        Program program = (Program) java.lang.reflect.Proxy.newProxyInstance(
            Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getFunctionManager" -> manager;
                case "getListing" -> listing;
                case "getReferenceManager" -> references;
                case "getImageBase", "getMinAddress" -> base;
                case "getMaxAddress" -> base.add(0xFFFF);
                case "getExecutablePath" -> "C:/fixture.dll";
                case "getExecutableSHA256" -> "fixture-hash";
                case "parseAddress" -> new Address[] {
                    space.getAddress(Long.parseUnsignedLong(((String) args[0]).replace("0x", ""), 16)) };
                default -> throw new AssertionError(method);
            });

        JsonObject both = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 2, "both", 16, 16, false, "indexed");
        check(both.getAsJsonArray("nodes").size() == 5, "Neighborhood both lost nodes");
        check(both.getAsJsonArray("edges").size() == 4, "Neighborhood both lost edges");
        check(both.get("totalCalls").getAsInt() == 5, "Neighborhood call count wrong");
        check(!both.get("truncated").getAsBoolean(), "Complete neighborhood incorrectly truncated");
        JsonArray best = both.getAsJsonArray("nextBest");
        check(best.size() == 4, "Neighborhood nextBest must exclude the seed");
        check(best.get(0).getAsJsonObject().get("name").getAsString().equals("DecryptPayload"),
            "Sensitive neighbor must rank first");
        boolean sawDepthTwo = false;
        for (int i = 0; i < best.size(); i++) {
            if (best.get(i).getAsJsonObject().get("name").getAsString().equals("AES_Init")) {
                sawDepthTwo = true;
                check(best.get(i).getAsJsonObject().get("depth").getAsInt() == 2, "Depth-2 node marked wrong");
            }
        }
        check(sawDepthTwo, "Neighborhood missed depth-2 node");

        JsonObject callees = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 1, "callees", 16, 16, false, "indexed");
        check(callees.getAsJsonArray("nodes").size() == 3, "Callees-only direction leaked callers");
        check(callees.getAsJsonArray("edges").size() == 2, "Callees-only edge set wrong");

        JsonObject callers = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 1, "callers", 16, 16, false, "indexed");
        check(callers.getAsJsonArray("nodes").size() == 2, "Callers-only direction leaked callees");
        check(callers.getAsJsonArray("edges").size() == 1, "Callers-only edge set wrong");

        JsonObject capped = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 2, "both", 2, 16, false, "indexed");
        check(capped.getAsJsonArray("nodes").size() == 2, "Neighborhood node cap ignored");
        check(capped.get("truncated").getAsBoolean(), "Neighborhood node cap not marked truncated");
        check(capped.getAsJsonArray("frontier").size() == 1, "Neighborhood frontier lost");

        JsonObject edgeCapped = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 1, "both", 16, 1, false, "indexed");
        check(edgeCapped.getAsJsonArray("edges").size() == 1, "Neighborhood edge cap ignored");
        check(edgeCapped.get("truncated").getAsBoolean(), "Neighborhood edge cap not marked truncated");

        JsonObject full = GhidraAnalysisFormatting.callGraphNeighborhood(
            program, main, 1, "callees", 16, 16, false, "full");
        check(full.getAsJsonArray("edges").get(0).getAsJsonObject().has("caller"),
            "Neighborhood full edge shape lost");

        GhidraAnalysisOperations operations = new GhidraAnalysisOperations(() -> program);
        JsonObject envelope = operations.callGraph(JsonParser.parseString(
            "{\"function\":\"0x10001000\",\"depth\":2,\"direction\":\"both\"}").getAsJsonObject());
        check(envelope.get("schemaVersion").getAsInt() == 4, "Neighborhood envelope version wrong");
        check(envelope.get("mode").getAsString().equals("neighborhood"), "Neighborhood mode missing");
        check(envelope.getAsJsonObject("seed").get("name").getAsString().equals("main"),
            "Neighborhood seed identity wrong");
        check(envelope.getAsJsonArray("nextBest").size() == 4, "Neighborhood envelope nextBest lost");
        check(envelope.getAsJsonObject("summary").get("nextAction").getAsString().contains("InspectFunction"),
            "Neighborhood summary must point at nextBest");
    }

    public static void main(String[] args) throws Exception {
        GhidraRequestDeadlineChecks.run();
        GhidraCancellationChecks.run();
        GhidraStaticQueryChecks.run();
        GhidraJournalChecks.run();
        GhidraBatchAnnotateChecks.run();
        disassembly(3, 1, 1000, true);
        disassembly(3, 3, 1000, false);
        disassembly(0, 3, 1000, false);
        disassembly(3, 3, 0, true);
        outgoingReferences(3, 1, true);
        outgoingReferences(3, 3, false);
        outgoingReferences(0, 1, false);
        functionStrings();
        functionConstants();
        referencesBrief();
        analysisQueueOrder();
        analysisQueueEnvelope();
        callGraph();
        callGraphNeighborhood();
        functionDigestOptIns();
        callGraphNodeRvaOmit();
        frontendUncRejected();
        frontendDeviceAndVariantsRejected();
        bidiControlsRejected();
        boundedIntChecks();
        System.out.println("Ghidra formatting regression checks passed.");
    }
}
