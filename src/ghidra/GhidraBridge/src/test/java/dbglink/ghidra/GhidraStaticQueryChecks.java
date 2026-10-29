package dbglink.ghidra;

import com.google.gson.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

final class GhidraStaticQueryChecks {
    private static final AddressSpace SPACE = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
    private static final Address BASE = SPACE.getAddress(0x10000000);
    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T)Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }
    private static <T> T iterator(Class<T> type, List<?> rows) {
        Iterator<?> it = rows.iterator();
        return proxy(type, (p,m,a) -> switch(m.getName()) {
            case "hasNext" -> it.hasNext(); case "next" -> it.next(); case "iterator" -> p;
            default -> throw new AssertionError(m);
        });
    }
    private static JsonObject args(String json) { return JsonParser.parseString(json).getAsJsonObject(); }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }

    static void run() throws Exception {
        byte[] memory = new byte[140000];
        System.arraycopy("first mixer\0".getBytes(StandardCharsets.US_ASCII), 0, memory, 20, 12);
        byte[] crossing = "Miles audio boundary\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(crossing, 0, memory, 65530, crossing.length);
        byte[] wide = "AIL_waveOutOpen\0".getBytes(StandardCharsets.UTF_16LE);
        System.arraycopy(wide, 0, memory, 131060, wide.length);
        MemoryBlock block = proxy(MemoryBlock.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> ".rdata"; case "isInitialized" -> true; case "isExecute" -> false;
            case "isRead" -> true; case "isWrite" -> false;
            case "getStart" -> BASE; case "getEnd" -> BASE.add(memory.length - 1); case "getSize" -> (long)memory.length;
            case "getBytes" -> { byte[] dest = (byte[])a[1]; System.arraycopy(memory, (int)((Address)a[0]).subtract(BASE), dest, 0, dest.length); yield dest.length; }
            default -> throw new AssertionError(m);
        });
        Memory mem = proxy(Memory.class, (p,m,a) -> switch(m.getName()) {
            case "getBlocks" -> new MemoryBlock[] {block};
            case "getBytes" -> {
                byte[] dest = (byte[])a[1]; int at = (int)((Address)a[0]).subtract(BASE);
                if (at < 0 || at + dest.length > memory.length) throw new MemoryAccessException("unmapped");
                System.arraycopy(memory, at, dest, 0, dest.length); yield dest.length;
            }
            default -> throw new AssertionError(m);
        });
        Address entry = BASE.add(0x1000);
        Function owner = proxy(Function.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> "Mixer"; case "getEntryPoint" -> entry;
            case "getBody" -> new AddressSet(entry, entry.add(31)); case "isThunk" -> false;
            default -> throw new AssertionError(m);
        });
        FunctionManager fm = proxy(FunctionManager.class, (p,m,a) -> switch(m.getName()) {
            case "getFunctionAt" -> entry.equals(a[0]) ? owner : null;
            case "getFunctionContaining" -> owner;
            case "getFunctionsOverlapping" -> ((AddressSetView)a[0]).intersects(owner.getBody()) ? List.of(owner).iterator() : List.of().iterator();
            case "getFunctions" -> iterator(FunctionIterator.class, ((AddressSetView)a[0]).contains(entry) ? List.of(owner) : List.of());
            default -> throw new AssertionError(m);
        });
        Instruction plain = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getFlowType" -> RefType.FALL_THROUGH;
            default -> throw new AssertionError(m);
        });
        Instruction jump = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getFlowType" -> RefType.UNCONDITIONAL_JUMP;
            default -> throw new AssertionError(m);
        });
        Instruction call = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getFlowType" -> RefType.CONDITIONAL_CALL;
            default -> throw new AssertionError(m);
        });
        Listing listing = proxy(Listing.class, (p,m,a) -> switch(m.getName()) {
            case "getInstructions" -> iterator(InstructionIterator.class, List.of(plain, jump, plain, call));
            default -> throw new AssertionError(m);
        });
        Reference ref = proxy(Reference.class, (p,m,a) -> switch(m.getName()) {
            case "getFromAddress" -> entry.add(2); case "getToAddress" -> BASE.add(20);
            case "getReferenceType" -> RefType.READ; case "getOperandIndex" -> 1;
            default -> throw new AssertionError(m);
        });
        ReferenceManager rm = proxy(ReferenceManager.class, (p,m,a) -> switch(m.getName()) {
            case "getReferencesTo" -> iterator(ReferenceIterator.class, List.of(ref, ref));
            case "getReferenceSourceIterator" -> iterator(AddressIterator.class, List.of(entry));
            case "getReferencesFrom" -> new Reference[] {ref};
            default -> throw new AssertionError(m);
        });
        Symbol imported = proxy(Symbol.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> "AIL_waveOutOpen"; case "getAddress" -> BASE.add(100);
            default -> throw new AssertionError(m);
        });
        Symbol entrySymbol = proxy(Symbol.class, (p,m,a) -> switch(m.getName()) {
            case "getSymbolType" -> SymbolType.FUNCTION;
            case "getAddress" -> entry;
            default -> throw new AssertionError(m);
        });
        SymbolTable table = proxy(SymbolTable.class, (p,m,a) -> switch(m.getName()) {
            case "getExternalSymbols" -> iterator(SymbolIterator.class, List.of(imported));
            case "getExternalEntryPointIterator" -> iterator(AddressIterator.class, List.of(entry));
            case "getSymbols" -> iterator(SymbolIterator.class, List.of(entrySymbol));
            case "getPrimarySymbol" -> imported;
            default -> throw new AssertionError(m);
        });
        ExternalLocation external = proxy(ExternalLocation.class, (p,m,a) -> switch(m.getName()) {
            case "getLibraryName" -> "mss32.dll";
            default -> throw new AssertionError(m);
        });
        ExternalManager externals = proxy(ExternalManager.class, (p,m,a) -> switch(m.getName()) {
            case "getExternalLocation" -> external;
            default -> throw new AssertionError(m);
        });
        Program program = proxy(Program.class, (p,m,a) -> switch(m.getName()) {
            case "getMemory" -> mem; case "getImageBase", "getMinAddress" -> BASE;
            case "getMaxAddress" -> BASE.add(memory.length - 1); case "getExecutableSHA256" -> "test-hash";
            case "getExecutablePath" -> "C:/hw.dll"; case "getFunctionManager" -> fm; case "getReferenceManager" -> rm;
            case "getSymbolTable" -> table; case "getExternalManager" -> externals;
            case "getListing" -> listing;
            case "parseAddress" -> new Address[] {SPACE.getAddress(Long.parseUnsignedLong(((String)a[0]).replace("0x", ""), 16))};
            default -> throw new AssertionError(m);
        });
        GhidraStaticQueries queries = new GhidraStaticQueries(() -> program);
        JsonObject imports = queries.execute("ListImports", args("{\"filter\":\"AIL_*\"}"));
        check(imports.getAsJsonArray("imports").size() == 1, "Import name filtering failed");
        check(!imports.has("sha256"), "ListImports must drop the sha256 echo");
        JsonObject importRow = imports.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(importRow.get("library").getAsString().equals("mss32.dll"), "Import library lost");
        check(importRow.get("refCount").getAsInt() == 2, "Import refCount wrong");
        check(!importRow.has("referenceSites"), "referenceSites must be opt-in");
        check(!importRow.has("referencesTruncated"), "referencesTruncated must be opt-in");
        JsonObject importsSites = queries.execute("ListImports", args("{\"filter\":\"AIL_*\",\"includeSites\":true}"));
        JsonObject sitesRow = importsSites.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(sitesRow.getAsJsonArray("referenceSites").size() == 2, "Import linkage missing");
        check(sitesRow.get("refCount").getAsInt() == 2, "Import refCount lost with sites");
        check(!sitesRow.get("referencesTruncated").getAsBoolean(), "Complete site list flagged truncated");
        JsonObject importsCapped = queries.execute("ListImports", args("{\"filter\":\"AIL_*\",\"maxSites\":1}"));
        JsonObject cappedRow = importsCapped.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(cappedRow.getAsJsonArray("referenceSites").size() == 1, "Explicit maxSites ignored");
        check(cappedRow.get("referencesTruncated").getAsBoolean(), "Capped site list missing truncation flag");
        check(cappedRow.get("refCount").getAsInt() == 2, "Capped refCount wrong");
        // Schema parity: an explicit maxSites:0 is refCount-only even with
        // includeSites:true (omitted maxSites with includeSites:true keeps the
        // default cap 8 above). Omitted-vs-explicit 0 is load-bearing.
        JsonObject importsExplicitZero = queries.execute("ListImports", args("{\"filter\":\"AIL_*\",\"includeSites\":true,\"maxSites\":0}"));
        JsonObject zeroRow = importsExplicitZero.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(!zeroRow.has("referenceSites"), "Explicit maxSites:0 must be refCount-only");
        check(!zeroRow.has("referencesTruncated"), "Explicit maxSites:0 must omit the truncation flag");
        check(zeroRow.get("refCount").getAsInt() == 2, "Explicit-zero refCount wrong");
        check(queries.execute("ListExports", args("{}")).getAsJsonArray("exports").size() == 1, "Export missing");
        JsonObject all = queries.execute("DumpStrings", args("{}"));
        check(all.getAsJsonArray("strings").size() == 3, "ASCII/UTF16 chunk-boundary strings lost or duplicated");
        check(!all.get("truncated").getAsBoolean(), "Complete scan incorrectly truncated");
        JsonArray allRows = all.getAsJsonArray("strings");
        JsonObject asciiRow = allRows.get(0).getAsJsonObject();
        check(!asciiRow.has("hex"), "DumpStrings hex must be opt-in");
        check(!asciiRow.has("byteLength"), "DumpStrings byteLength must go");
        check(!asciiRow.has("encoding"), "ASCII encoding must stay omitted");
        check(!asciiRow.has("stringTruncated"), "Short strings must omit stringTruncated");
        check(asciiRow.get("section").getAsString().equals(".rdata"), "Unfiltered rows lost their section");
        check(allRows.get(2).getAsJsonObject().get("encoding").getAsString().equals("utf-16le"), "UTF-16 encoding lost");
        JsonObject hexed = queries.execute("DumpStrings", args("{\"filter\":\"first mixer\",\"includeHex\":true}"));
        check(hexed.getAsJsonArray("strings").get(0).getAsJsonObject().has("hex"), "includeHex lost the bytes");
        JsonObject sectioned = queries.execute("DumpStrings", args("{\"section\":\".rdata\",\"maxItems\":1}"));
        check(sectioned.get("section").getAsString().equals(".rdata"), "Uniform section must hoist");
        check(!sectioned.getAsJsonArray("strings").get(0).getAsJsonObject().has("section"), "Hoisted section repeated per row");
        JsonObject page = queries.execute("DumpStrings", args("{\"maxItems\":1}"));
        check(page.get("truncated").getAsBoolean(), "Missing string continuation");
        JsonObject continuation = new JsonObject(); continuation.addProperty("start", page.get("nextAddress").getAsString());
        check(queries.execute("DumpStrings", continuation).getAsJsonArray("strings").size() == 2, "String cursor lost a row");
        JsonObject budget = queries.execute("DumpStrings", args("{\"maxScanBytes\":65536}"));
        check(budget.getAsJsonArray("strings").size() == 2, "Crossing ASCII string missing");
        continuation.addProperty("start", budget.get("nextAddress").getAsString());
        check(queries.execute("DumpStrings", continuation).getAsJsonArray("strings").size() == 1, "Crossing string duplicated");
        JsonObject single = queries.execute("ReadStaticBytes", args("{\"address\":\"10000014\",\"length\":5}"));
        check(single.get("hex").getAsString().equals("6669727374"), "Wrong bytes");
        check(!single.has("sha256"), "ReadStaticBytes must drop the sha256 echo");
        try { queries.execute("ReadStaticBytes", args("{\"address\":\"100222df\",\"length\":32}")); throw new AssertionError("Unmapped bytes accepted"); }
        catch (BridgeFailure expected) { check(expected.code.equals("memory_unavailable"), "Wrong memory error"); }
        JsonObject xrefs = queries.execute("XrefsTo", args("{\"address\":\"10000014\",\"maxItems\":1}"));
        check(xrefs.get("nextOffset").getAsInt() == 1, "Wrong xref cursor");
        check(!xrefs.has("sha256"), "XrefsTo must drop the sha256 echo");
        JsonObject xrefRow = xrefs.getAsJsonArray("references").get(0).getAsJsonObject();
        check(xrefRow.has("function"), "Missing xref function");
        check(!xrefRow.has("to"), "To-rows must omit the constant target");
        check(xrefRow.get("operandIndex").getAsInt() == 1, "Xref operand index lost");
        JsonObject xrefFn = xrefRow.getAsJsonObject("function");
        check(xrefFn.has("name") && xrefFn.has("entry") && !xrefFn.has("size") && !xrefFn.has("minAddress"),
            "Xref function block not slim");
        check(queries.execute("XrefsTo", args("{\"address\":\"10000014\",\"offset\":1}")).getAsJsonArray("references").size() == 1, "Xref cursor duplicate/loss");
        check(queries.execute("XrefsTo", args("{\"address\":\"10000014\",\"callsOnly\":true}")).getAsJsonArray("references").isEmpty(), "Call filter ignored");
        check(queries.execute("ListFunctions", args("{\"start\":\"10001010\",\"end\":\"10001040\"}")).getAsJsonArray("functions").size() == 1, "Body intersection missed");
        check(queries.execute("ListFunctions", args("{\"start\":\"10001010\",\"end\":\"10001040\",\"overlapping\":false}")).getAsJsonArray("functions").isEmpty(), "Entry filter ignored");
        check(GhidraStaticQueries.matches("AIL_waveOutOpen", "ail_*") && GhidraStaticQueries.matches("foo_bar_foo", "*foo"), "Glob filter broken");
        JsonObject funcRow = queries.execute("ListFunctions", args("{\"start\":\"10001010\",\"end\":\"10001040\"}"))
            .getAsJsonArray("functions").get(0).getAsJsonObject();
        check(!funcRow.has("instructionCount") && !funcRow.has("branchCount"),
            "ListFunctions counts must be opt-in");
        JsonObject countedRow = queries.execute("ListFunctions",
            args("{\"start\":\"10001010\",\"end\":\"10001040\",\"includeCounts\":true}"))
            .getAsJsonArray("functions").get(0).getAsJsonObject();
        check(countedRow.get("instructionCount").getAsInt() == 4, "ListFunctions instructionCount wrong");
        check(countedRow.get("branchCount").getAsInt() == 2, "ListFunctions branchCount wrong");
        check(!funcRow.has("complexity"), "ListFunctions must not aggregate a complexity score");
        check(!funcRow.has("thunk"), "False thunk must stay omitted");
        check(!funcRow.has("rangeCount"), "Single-range rangeCount must stay omitted");
        check(!funcRow.has("minAddress"), "minAddress equal to entry must stay omitted");
        check(funcRow.has("maxAddress"), "Distinct maxAddress lost");
        check(funcRow.has("size"), "Body size lost");
        JsonObject sections = queries.execute("ListSections", args("{}"));
        check(sections.get("entryPoint").getAsString().equals(entry.toString()), "ListSections entry point lost");
        check(sections.getAsJsonObject("entryFunction").get("name").getAsString().equals("Mixer"),
            "ListSections entry function lost");
        JsonArray sectionRows = sections.getAsJsonArray("sections");
        check(sectionRows.size() == 1, "ListSections lost a memory block");
        JsonObject sectionRow = sectionRows.get(0).getAsJsonObject();
        check(sectionRow.get("name").getAsString().equals(".rdata"), "Section name lost");
        check(sectionRow.get("permissions").getAsString().equals("r--"), "Section permissions wrong");
        check(!sections.get("truncated").getAsBoolean(), "Complete section list truncated");
        JsonObject sectionsCapped = queries.execute("ListSections", args("{\"maxSections\":1}"));
        check(!sectionsCapped.get("truncated").getAsBoolean(), "Exact section cap flagged truncated");
        try {
            queries.execute("ListSections", args("{\"maxSections\":0}"));
            throw new AssertionError("maxSections 0 accepted");
        }
        catch (BridgeFailure expected) {
            check(expected.code.equals("argument_out_of_range"), "Wrong maxSections error");
        }
        bothAndRangesChecks(queries);
        complexityNullChecks();
        fallbackScanChecks();
        externalLiteralChecks();
        System.out.println("Static query regression checks passed.");
    }

    /**
     * P0-4/P2-10 fan-in: XrefsBoth nests the two single-direction result
     * objects (to.references/from.references plus per-side cursors) with
     * flattened top-level cursors alongside, ListSymbolsBoth nests both
     * symbol pages with per-side cursors, and ReadStaticBytes ranges reads up
     * to 8 chunks with sparse success rows, per-index errors and a whole-call
     * total cap.
     */
    private static void bothAndRangesChecks(GhidraStaticQueries queries) throws Exception {
        JsonObject both = queries.execute("XrefsBoth", args("{\"address\":\"10000014\"}"));
        // Address.toString() omits the space prefix in Ghidra 12.x, so compare
        // against the parsed address instead of a hardcoded "ram:" string.
        check(both.get("address").getAsString().equals(BASE.add(20).toString()), "XrefsBoth lost its address");
        // Contract shape: per-side result OBJECTS (pre-flatten nesting) plus
        // flattened top-level cursors for convenience.
        check(both.getAsJsonObject("to").getAsJsonArray("references").size() == 2, "XrefsBoth to side lost rows");
        check(both.getAsJsonObject("from").getAsJsonArray("references").size() == 1, "XrefsBoth from side lost rows");
        check(!both.getAsJsonObject("to").get("truncated").getAsBoolean(), "XrefsBoth to object incorrectly truncated");
        check(!both.getAsJsonObject("from").get("truncated").getAsBoolean(), "XrefsBoth from object incorrectly truncated");
        check(!both.has("toTruncated") && !both.has("fromTruncated"),
            "XrefsBoth must leave per-side truncation to the nested objects");
        for (String duplicate : new String[] { "source", "imageBase", "sha256", "address" }) {
            check(!both.getAsJsonObject("to").has(duplicate),
                "XrefsBoth to side repeats " + duplicate);
            check(!both.getAsJsonObject("from").has(duplicate),
                "XrefsBoth from side repeats " + duplicate);
        }
        check(!both.get("truncated").getAsBoolean(), "XrefsBoth incorrectly truncated");
        check(!both.has("nextOffsetTo"), "XrefsBoth reported a cursor without truncation");
        check(!both.has("nextOffsetFrom"), "XrefsBoth reported a from cursor without truncation");
        JsonObject bothToRow = both.getAsJsonObject("to").getAsJsonArray("references").get(0).getAsJsonObject();
        check(bothToRow.has("from") && bothToRow.has("type"), "Nested to-row lost from/type");
        check(!bothToRow.has("to"), "Nested to-rows must omit the constant target");
        JsonObject bothFromRow = both.getAsJsonObject("from").getAsJsonArray("references").get(0).getAsJsonObject();
        check(bothFromRow.has("from") && bothFromRow.has("to") && bothFromRow.has("type"), "Nested from-row lost from/to/type");
        JsonObject bothPaged = queries.execute("XrefsBoth", args("{\"address\":\"10000014\",\"maxItemsTo\":1}"));
        check(!bothPaged.has("toTruncated") && !bothPaged.has("fromTruncated"),
            "XrefsBoth must leave per-side truncation to the nested objects");
        check(bothPaged.get("nextOffsetTo").getAsInt() == 1, "XrefsBoth per-side cursor wrong");
        check(bothPaged.getAsJsonObject("to").get("truncated").getAsBoolean(), "Nested to object lost its truncation");
        check(bothPaged.getAsJsonObject("to").get("nextOffset").getAsInt() == 1, "Nested to object lost its cursor");
        check(!bothPaged.getAsJsonObject("from").get("truncated").getAsBoolean(), "Nested from object leaked truncation");
        check(!bothPaged.has("nextOffsetFrom"), "XrefsBoth leaked a cursor across sides");
        check(bothPaged.get("truncated").getAsBoolean(), "XrefsBoth top-level truncated must OR the sides");

        JsonObject symbols = queries.execute("ListSymbolsBoth", args("{\"filter\":\"AIL_*\"}"));
        check(symbols.getAsJsonArray("imports").size() == 1, "ListSymbolsBoth imports lost");
        check(symbols.getAsJsonArray("exports").size() == 1, "ListSymbolsBoth exports lost");
        check(!symbols.has("importsTruncated") && !symbols.has("exportsTruncated"),
            "ListSymbolsBoth must leave per-side truncation to the nextOffset cursors");
        check(!symbols.has("sha256"), "ListSymbolsBoth must drop the sha256 echo");
        check(!symbols.get("truncated").getAsBoolean(), "ListSymbolsBoth top-level truncation wrong");
        check(!symbols.has("nextOffsetImports"), "ListSymbolsBoth reported a cursor without truncation");
        JsonObject bothImportRow = symbols.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(bothImportRow.get("refCount").getAsInt() == 2, "ListSymbolsBoth imports lost refCount");
        check(!bothImportRow.has("referenceSites"), "ListSymbolsBoth sites must stay opt-in");
        JsonObject symbolsSites = queries.execute("ListSymbolsBoth", args("{\"filter\":\"AIL_*\",\"includeSites\":true}"));
        JsonObject sitesBothRow = symbolsSites.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(sitesBothRow.getAsJsonArray("referenceSites").size() == 2, "ListSymbolsBoth includeSites passthrough lost");
        check(sitesBothRow.get("refCount").getAsInt() == 2, "ListSymbolsBoth refCount lost with sites");
        JsonObject symbolsCapped = queries.execute("ListSymbolsBoth", args("{\"filter\":\"AIL_*\",\"maxSites\":1}"));
        JsonObject cappedBothRow = symbolsCapped.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(cappedBothRow.getAsJsonArray("referenceSites").size() == 1, "ListSymbolsBoth maxSites passthrough ignored");
        check(cappedBothRow.get("referencesTruncated").getAsBoolean(), "ListSymbolsBoth capped sites missing truncation flag");
        JsonObject symbolsExplicitZero = queries.execute("ListSymbolsBoth", args("{\"filter\":\"AIL_*\",\"includeSites\":true,\"maxSites\":0}"));
        JsonObject zeroBothRow = symbolsExplicitZero.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(!zeroBothRow.has("referenceSites"), "ListSymbolsBoth explicit maxSites:0 must be refCount-only");
        check(zeroBothRow.get("refCount").getAsInt() == 2, "ListSymbolsBoth explicit-zero refCount wrong");

        JsonObject ranged = queries.execute("ReadStaticBytes",
            args("{\"ranges\":[{\"address\":\"10000014\",\"length\":5},{\"address\":\"100222df\",\"length\":4}]}"));
        JsonArray chunks = ranged.getAsJsonArray("ranges");
        check(chunks.size() == 2, "Ranges lost a chunk");
        JsonObject goodChunk = chunks.get(0).getAsJsonObject();
        check(goodChunk.get("hex").getAsString().equals("6669727374"), "Ranges chunk bytes wrong");
        check(!goodChunk.has("index"), "Ok ranges chunk must omit its derivable index");
        check(!goodChunk.has("length"), "Ok ranges chunk must omit its derivable length");
        check(!ranged.has("sha256"), "ReadStaticBytes ranges must drop the sha256 echo");
        JsonObject badChunk = chunks.get(1).getAsJsonObject();
        check(badChunk.get("ok").getAsBoolean() == false, "Bad ranges chunk did not fail its index");
        check(badChunk.get("index").getAsInt() == 1, "Bad ranges chunk lost its index");
        check(badChunk.get("code").getAsString().equals("memory_unavailable"), "Bad ranges chunk code wrong");
        check(ranged.get("partial").getAsBoolean(), "Ranges partial flag missing");
        try {
            queries.execute("ReadStaticBytes", args(
                "{\"ranges\":[{\"address\":\"10000014\",\"length\":4096},{\"address\":\"10000014\",\"length\":4096},{\"address\":\"10000014\",\"length\":4096},{\"address\":\"10000014\",\"length\":4096},{\"address\":\"10000014\",\"length\":4096}]}"));
            throw new AssertionError("Ranges total cap accepted");
        }
        catch (BridgeFailure expected) { check(expected.code.equals("argument_out_of_range"), "Wrong ranges total-cap error"); }
        try {
            queries.execute("ReadStaticBytes", args("{\"address\":\"10000014\",\"ranges\":[{\"address\":\"10000014\"}]}"));
            throw new AssertionError("Ranges+address accepted");
        }
        catch (BridgeFailure expected) { check(expected.code.equals("invalid_argument"), "Wrong ranges exclusivity error"); }
        try {
            queries.execute("ReadStaticBytes", args("{\"ranges\":[]}"));
            throw new AssertionError("Empty ranges accepted");
        }
        catch (BridgeFailure expected) { check(expected.code.equals("argument_out_of_range"), "Wrong empty-ranges error"); }
    }

    /**
     * An unreadable listing must not fail ListFunctions: the two routing
     * counts are null instead of failing the row.
     */
    private static void complexityNullChecks() throws Exception {
        Function broken = proxy(Function.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> "Broken"; case "getEntryPoint" -> BASE.add(0x2000);
            case "getBody" -> new AddressSet(BASE.add(0x2000), BASE.add(0x200F)); case "isThunk" -> false;
            default -> throw new AssertionError(m);
        });
        FunctionManager brokenFm = proxy(FunctionManager.class, (p,m,a) -> switch(m.getName()) {
            case "getFunctionsOverlapping" -> List.of(broken).iterator();
            case "getFunctions" -> List.of(broken).iterator();
            default -> throw new AssertionError(m);
        });
        Program brokenProgram = proxy(Program.class, (p,m,a) -> switch(m.getName()) {
            case "getImageBase", "getMinAddress" -> BASE;
            case "getMaxAddress" -> BASE.add(0xFFFF); case "getExecutableSHA256" -> "broken-hash";
            case "getFunctionManager" -> brokenFm;
            case "getListing" -> { throw new RuntimeException("no listing"); }
            case "parseAddress" -> new Address[] {SPACE.getAddress(Long.parseUnsignedLong(((String)a[0]).replace("0x", ""), 16))};
            default -> throw new AssertionError(m);
        });
        GhidraStaticQueries brokenQueries = new GhidraStaticQueries(() -> brokenProgram);
        JsonObject brokenRow = brokenQueries.execute("ListFunctions", args("{\"includeCounts\":true}"))
            .getAsJsonArray("functions").get(0).getAsJsonObject();
        check(!brokenRow.has("instructionCount"), "instructionCount must be omitted when the listing cannot be read");
        check(!brokenRow.has("branchCount"), "branchCount must be omitted when the listing cannot be read");
    }

    /**
     * An empty reference table must not mean "no references": XrefsTo/XrefsFrom
     * fall back to a bounded scan of instruction flows, address scalars and
     * stored pointers, and report that scan honestly.
     */
    private static void fallbackScanChecks() throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address base = space.getAddress(0x20000000);
        long size = 65536;
        Address target = base.add(0x1000);
        Address fromJump = base.add(0x2000);
        Address fromCall = base.add(0x2010);
        Address fromScalar = base.add(0x2020);
        Address fromTail = base.add(0x2030);
        Address callee = base.add(0x3000);
        Address ownerEntry = base.add(0x1F00);
        Address ownerEnd = base.add(0x2100);

        byte[] memory = new byte[(int)size];
        long pointer = target.getOffset();
        int pointerAt = 0x4000;
        memory[pointerAt] = (byte)pointer;
        memory[pointerAt + 1] = (byte)(pointer >> 8);
        memory[pointerAt + 2] = (byte)(pointer >> 16);
        memory[pointerAt + 3] = (byte)(pointer >> 24);

        MemoryBlock block = proxy(MemoryBlock.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> ".text"; case "isInitialized" -> true; case "isExecute" -> true;
            case "getStart" -> base; case "getEnd" -> base.add(size - 1); case "getSize" -> size;
            case "getBytes" -> { byte[] dest = (byte[])a[1];
                int from = (int)((Address)a[0]).subtract(base);
                if (from < 0 || from + dest.length > memory.length) throw new MemoryAccessException("unmapped");
                System.arraycopy(memory, from, dest, 0, dest.length); yield dest.length; }
            default -> throw new AssertionError(m);
        });
        Memory mem = proxy(Memory.class, (p,m,a) -> switch(m.getName()) {
            case "getBlocks" -> new MemoryBlock[] {block};
            default -> throw new AssertionError(m);
        });
        Function owner = proxy(Function.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> "ScanOwner"; case "getEntryPoint" -> ownerEntry;
            case "getBody" -> new AddressSet(ownerEntry, ownerEnd); case "isThunk" -> false;
            default -> throw new AssertionError(m);
        });
        FunctionManager fm = proxy(FunctionManager.class, (p,m,a) -> switch(m.getName()) {
            case "getFunctionContaining" -> {
                Address addr = (Address)a[0];
                yield addr.compareTo(ownerEntry) >= 0 && addr.compareTo(ownerEnd) <= 0 ? owner : null;
            }
            case "getFunctionAt" -> ((Address)a[0]).equals(ownerEntry) ? owner : null;
            case "getFunctionCount" -> 1;
            default -> throw new AssertionError(m);
        });
        Instruction jump = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getAddress" -> fromJump; case "getFlows" -> new Address[] {target};
            case "getFlowType" -> RefType.UNCONDITIONAL_JUMP; case "getNumOperands" -> 0;
            default -> throw new AssertionError(m);
        });
        Instruction call = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getAddress" -> fromCall; case "getFlows" -> new Address[] {target};
            case "getFlowType" -> RefType.UNCONDITIONAL_CALL; case "getNumOperands" -> 0;
            default -> throw new AssertionError(m);
        });
        Instruction immediate = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getAddress" -> fromScalar; case "getFlows" -> new Address[0];
            case "getNumOperands" -> 1; case "getScalar" -> new Scalar(32, target.getOffset());
            default -> throw new AssertionError(m);
        });
        Instruction tail = proxy(Instruction.class, (p,m,a) -> switch(m.getName()) {
            case "getAddress" -> fromTail; case "getFlows" -> new Address[] {callee};
            case "getFlowType" -> RefType.UNCONDITIONAL_CALL; case "getNumOperands" -> 0;
            default -> throw new AssertionError(m);
        });
        List<Instruction> instructions = List.of(jump, call, immediate, tail);
        Listing list = proxy(Listing.class, (p,m,a) -> switch(m.getName()) {
            case "getInstructions" -> iterator(InstructionIterator.class, instructions);
            default -> throw new AssertionError(m);
        });
        ReferenceManager rm = proxy(ReferenceManager.class, (p,m,a) -> switch(m.getName()) {
            case "getReferencesTo" -> iterator(ReferenceIterator.class, List.of());
            case "getReferenceSourceIterator" -> iterator(AddressIterator.class, List.of());
            case "getReferencesFrom" -> new Reference[0];
            default -> throw new AssertionError(m);
        });
        SymbolTable table = proxy(SymbolTable.class, (p,m,a) -> switch(m.getName()) {
            case "getPrimarySymbol" -> null;
            default -> throw new AssertionError(m);
        });
        Program program = proxy(Program.class, (p,m,a) -> switch(m.getName()) {
            case "getMemory" -> mem; case "getImageBase", "getMinAddress" -> base;
            case "getMaxAddress" -> base.add(size - 1); case "getExecutableSHA256" -> "scan-fallback-hash";
            case "getExecutablePath" -> "C:/scan.dll"; case "getFunctionManager" -> fm;
            case "getReferenceManager" -> rm; case "getListing" -> list; case "getSymbolTable" -> table;
            case "parseAddress" -> new Address[] {
                space.getAddress(Long.parseUnsignedLong(((String)a[0]).replace("0x", ""), 16))};
            default -> throw new AssertionError(m);
        });
        GhidraStaticQueries queries = new GhidraStaticQueries(() -> program);

        JsonObject xrefs = queries.execute("XrefsTo", args("{\"address\":\"20001000\"}"));
        check(xrefs.get("fallbackScan").getAsBoolean(), "Empty reference table did not trigger a scan");
        check(xrefs.get("scanComplete").getAsBoolean(), "Small fixture scan reported incomplete");
        check(xrefs.get("scannedInstructions").getAsInt() == 4, "Instruction scan bound misreported");
        check(xrefs.get("scannedBytes").getAsLong() == size, "Memory scan bound misreported");
        JsonArray rows = xrefs.getAsJsonArray("references");
        check(rows.size() == 4, "Flow/scalar/pointer rows lost: " + rows.size());
        JsonObject flow = rows.get(0).getAsJsonObject();
        check(flow.get("from").getAsString().equals(fromJump.toString()), "Jump source address wrong");
        check(!flow.has("to"), "Scan to-rows must omit the constant target");
        check(flow.get("type").getAsString().contains("JUMP"), "Jump flow type wrong");
        check(flow.has("function"), "Scan row lost its containing function");
        JsonObject flowFn = flow.getAsJsonObject("function");
        check(flowFn.has("name") && flowFn.has("entry") && !flowFn.has("size"),
            "Scan function block not slim");
        JsonObject callRow = rows.get(1).getAsJsonObject();
        check(GhidraStaticQueries.isCallType(callRow.get("type").getAsString()),
            "Call flow type not derivable as a call");
        check(!callRow.has("call"), "Derivable call flag must stay omitted");
        check(callRow.get("from").getAsString().equals(fromCall.toString()), "Call source address wrong");
        JsonObject scalarRow = rows.get(2).getAsJsonObject();
        check("SCALAR".equals(scalarRow.get("type").getAsString()), "Address scalar reference missing");
        check(scalarRow.get("operandIndex").getAsInt() == 0, "Scalar operand index lost");
        JsonObject pointerRow = rows.get(3).getAsJsonObject();
        check("POINTER".equals(pointerRow.get("type").getAsString()), "Stored pointer reference missing");
        check(pointerRow.get("from").getAsString().equals(base.add(0x4000).toString()), "Pointer address wrong");

        JsonArray callRows = queries.execute("XrefsTo", args("{\"address\":\"20001000\",\"callsOnly\":true}"))
            .getAsJsonArray("references");
        check(callRows.size() == 1, "callsOnly ignored scan rows: " + callRows.size());
        check(GhidraStaticQueries.isCallType(callRows.get(0).getAsJsonObject().get("type").getAsString()),
            "Non-call row survived callsOnly");

        // Offset paging reuses the cached scan instead of rescanning the image.
        JsonObject firstPage = queries.execute("XrefsTo", args("{\"address\":\"20001000\",\"maxItems\":2}"));
        check(firstPage.get("truncated").getAsBoolean(), "Scan page did not report more rows");
        check(firstPage.get("nextOffset").getAsInt() == 2, "Scan page cursor wrong");
        JsonObject secondPage = queries.execute(
            "XrefsTo", args("{\"address\":\"20001000\",\"maxItems\":2,\"offset\":2}"));
        JsonArray rest = secondPage.getAsJsonArray("references");
        check(rest.size() == 2, "Scan page continuation lost rows: " + rest.size());
        check("SCALAR".equals(rest.get(0).getAsJsonObject().get("type").getAsString()), "Scan page order broken");

        JsonObject from = queries.execute("XrefsFrom", args("{\"address\":\"20001f00\"}"));
        check(from.get("fallbackScan").getAsBoolean(), "XrefsFrom did not fall back to instruction flows");
        check(from.get("scannedInstructions").getAsInt() == 4, "XrefsFrom instruction count wrong");
        check(from.get("functionName").getAsString().equals("ScanOwner"), "XrefsFrom lost its function");
        JsonArray outgoing = from.getAsJsonArray("references");
        check(outgoing.size() == 3, "Outgoing flow rows lost: " + outgoing.size());
        check(from.get("fallbackScan").getAsBoolean(), "XrefsFrom scan origin lost");
        JsonArray outgoingCalls = queries.execute(
            "XrefsFrom", args("{\"address\":\"20001f00\",\"callsOnly\":true}")).getAsJsonArray("references");
        check(outgoingCalls.size() == 2, "XrefsFrom callsOnly ignored scan rows: " + outgoingCalls.size());
    }

    /**
     * Schema/behavior parity: ListSymbols emits EXTERNAL:&lt;offset&gt; literals for
     * imports and the Xrefs schema promises direction=to accepts them, so XrefsTo
     * (and the to side of XrefsBoth) must resolve the literal to the same
     * EXTERNAL-space Address even when parseAddress does not round-trip EXTERNAL
     * space. The mock below simulates that gap: parseAddress returns null for the
     * EXTERNAL literal, forcing the external-symbol/address-space fallback.
     */
    private static void externalLiteralChecks() throws Exception {
        AddressSpace externalSpace = new GenericAddressSpace("EXTERNAL", 32, AddressSpace.TYPE_RAM, 1);
        Address externalAddr = externalSpace.getAddress(1);
        // Live ListSymbols emits qualified EXTERNAL:<offset> literals (e.g.
        // EXTERNAL:00000001). A standalone GenericAddressSpace renders bare hex
        // in unit tests (real DefaultAddressFactory qualifies non-default
        // spaces), so the literal is built manually; the fixture symbol still
        // lives in EXTERNAL space so reference-table equality holds.
        String literal = "EXTERNAL:00000001";
        check(externalAddr.getOffset() == 1, "EXTERNAL fixture offset wrong");
        Address ramBase = SPACE.getAddress(0x10000000);
        Address fromAddr = ramBase.add(0x200);
        Reference ref = proxy(Reference.class, (p, m, a) -> switch (m.getName()) {
            case "getFromAddress" -> fromAddr; case "getToAddress" -> externalAddr;
            case "getReferenceType" -> RefType.READ; case "getOperandIndex" -> 0;
            default -> throw new AssertionError(m);
        });
        ReferenceManager rm = proxy(ReferenceManager.class, (p, m, a) -> switch (m.getName()) {
            case "getReferencesTo" -> {
                Address target = (Address) a[0];
                yield iterator(ReferenceIterator.class,
                    target != null && target.equals(externalAddr) ? List.of(ref) : List.of());
            }
            case "getReferenceSourceIterator" -> iterator(AddressIterator.class, List.of());
            case "getReferencesFrom" -> new Reference[0];
            default -> throw new AssertionError(m);
        });
        Symbol imported = proxy(Symbol.class, (p, m, a) -> switch (m.getName()) {
            case "getName" -> "SomeImport"; case "getAddress" -> externalAddr;
            default -> throw new AssertionError(m);
        });
        SymbolTable table = proxy(SymbolTable.class, (p, m, a) -> switch (m.getName()) {
            case "getExternalSymbols" -> iterator(SymbolIterator.class, List.of(imported));
            case "getPrimarySymbol" -> imported;
            default -> throw new AssertionError(m);
        });
        FunctionManager fm = proxy(FunctionManager.class, (p, m, a) -> switch (m.getName()) {
            case "getFunctionAt" -> null; case "getFunctionContaining" -> null;
            case "getFunctionCount" -> 0;
            default -> throw new AssertionError(m);
        });
        AddressFactory factory = proxy(AddressFactory.class, (p, m, a) -> switch (m.getName()) {
            case "getAddressSpace" -> "EXTERNAL".equals(a[0]) ? externalSpace : null;
            default -> throw new AssertionError(m);
        });
        ExternalManager externals = proxy(ExternalManager.class, (p, m, a) -> switch (m.getName()) {
            case "getExternalLocation" -> null;
            default -> throw new AssertionError(m);
        });
        Program program = proxy(Program.class, (p, m, a) -> switch (m.getName()) {
            case "getMemory" -> proxy(Memory.class, (pp, mm, aa) -> switch (mm.getName()) {
                case "getBlocks" -> new MemoryBlock[0];
                default -> throw new AssertionError(mm);
            });
            case "getImageBase", "getMinAddress" -> ramBase;
            case "getMaxAddress" -> ramBase.add(0xFFF); case "getExecutableSHA256" -> "external-hash";
            case "getFunctionManager" -> fm; case "getReferenceManager" -> rm;
            case "getSymbolTable" -> table; case "getAddressFactory" -> factory;
            case "getExternalManager" -> externals;
            case "getListing" -> proxy(Listing.class, (pp, mm, aa) -> switch (mm.getName()) {
                case "getInstructions" -> iterator(InstructionIterator.class, List.of());
                default -> throw new AssertionError(mm);
            });
            // Simulate Ghidra versions where parseAddress does not round-trip
            // EXTERNAL space: ram literals parse, EXTERNAL literals do not.
            case "parseAddress" -> {
                String selector = (String) a[0];
                if (selector != null && selector.trim().toUpperCase(java.util.Locale.ROOT).startsWith("EXTERNAL:")) yield null;
                yield new Address[] {SPACE.getAddress(Long.parseUnsignedLong(selector.replace("0x", ""), 16))};
            }
            default -> throw new AssertionError(m);
        });
        GhidraStaticQueries queries = new GhidraStaticQueries(() -> program);
        JsonObject imports = queries.execute("ListImports", args("{}"));
        check(imports.getAsJsonArray("imports").size() == 1, "EXTERNAL import missing");
        JsonObject importRow = imports.getAsJsonArray("imports").get(0).getAsJsonObject();
        check(importRow.get("refCount").getAsInt() == 1, "EXTERNAL import refCount wrong");
        JsonObject payload = new JsonObject();
        payload.addProperty("address", literal);
        JsonObject xrefs = queries.execute("XrefsTo", payload);
        check(xrefs.getAsJsonArray("references").size() == 1, "XrefsTo rejected the EXTERNAL literal ListSymbols emits");
        check(xrefs.getAsJsonArray("references").get(0).getAsJsonObject().get("from").getAsString().equals(fromAddr.toString()),
            "XrefsTo EXTERNAL row lost its from address");
        JsonObject bothPayload = new JsonObject();
        bothPayload.addProperty("address", literal);
        JsonObject both = queries.execute("XrefsBoth", bothPayload);
        check(both.getAsJsonObject("to").getAsJsonArray("references").size() == 1, "XrefsBoth to side rejected EXTERNAL");
        check(both.getAsJsonObject("from").getAsJsonArray("references").isEmpty(), "XrefsBoth from side must be empty for EXTERNAL");
    }
}
