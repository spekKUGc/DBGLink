package dbglink.ghidra;

import com.google.gson.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import static dbglink.ghidra.GhidraBridgeServer.*;

/** Queries against the imported image; never depend on a live debugger. */
final class GhidraStaticQueries {
    static final Set<String> METHODS = Set.of("DumpStrings", "ReadStaticBytes", "XrefsTo", "XrefsFrom", "XrefsBoth",
        "ListImports", "ListExports", "ListSymbolsBoth", "ListFunctions", "ListSections");

    // Fallback scan bounds. Ghidra's reference table can be empty for a target
    // (unanalyzed code, table-driven dispatch); XrefsTo/XrefsFrom then scan the
    // listing and memory instead of silently returning no rows. The scan is
    // bounded by time, instruction count and byte count, and reports honestly
    // through scanComplete when a bound stopped it.
    private static final long SCAN_DEADLINE_NANOS = 8_000_000_000L;
    private static final int SCAN_MAX_CODE_UNITS = 5_000_000;
    private static final int SCAN_MAX_BYTES = 128 * 1024 * 1024;
    private static final int SCAN_MAX_MATCHES = 2_048;
    private static final int SCAN_CACHE_ENTRIES = 32;
    private static final int SCAN_CHUNK_BYTES = 1024 * 1024;

    /** Contiguous lowercase hex (M4 token policy): no spaces, no uppercase. */
    private static final HexFormat HEX = HexFormat.ofDelimiter("").withLowerCase();

    /** Fallback rows per program/target so offset paging does not rescan the image. */
    private static final class ScanResult {
        final List<JsonObject> rows;
        final boolean complete;
        final int instructions;
        final long bytes;
        ScanResult(List<JsonObject> rows, boolean complete, int instructions, long bytes) {
            this.rows = rows;
            this.complete = complete;
            this.instructions = instructions;
            this.bytes = bytes;
        }
    }

    private static final Map<String, ScanResult> SCAN_CACHE =
        new LinkedHashMap<>(16, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, ScanResult> eldest) {
                return size() > SCAN_CACHE_ENTRIES;
            }
        };

    private final Supplier<Program> supplier;
    GhidraStaticQueries(Supplier<Program> supplier) { this.supplier = supplier; }

    JsonObject execute(String method, JsonObject args) throws BridgeFailure {
        Program program = supplier.get();
        if (program == null) throw new BridgeFailure("program_unavailable", "no active Ghidra program");
        if (!matchesActiveModule(program, optionalString(args, "module", 2048)))
            throw new BridgeFailure("module_not_found", "module does not match the selected Ghidra program; use OpenGhidraFile and analysisId");
        checkCancelled();
        return switch (method) {
            case "ReadStaticBytes" -> bytes(program, args);
            case "DumpStrings" -> strings(program, args);
            case "XrefsTo" -> xrefs(program, args);
            case "XrefsFrom" -> xrefsFrom(program, args);
            case "XrefsBoth" -> xrefsBoth(program, args);
            case "ListFunctions" -> functions(program, args);
            case "ListSections" -> sections(program, args);
            case "ListImports", "ListExports" -> symbols(program, args, method.equals("ListImports"));
            case "ListSymbolsBoth" -> symbolsBoth(program, args);
            default -> throw new BridgeFailure("method_not_allowed", "unsupported static query");
        };
    }

    static void checkCancelled() throws BridgeFailure {
        if (requestMonitor.get() != null && requestMonitor.get().isCancelled())
            throw new BridgeFailure("ghidra_timeout", "Static query cancelled");
    }

    static Address address(Program program, String text) throws BridgeFailure {
        // Always a Ghidra VA, including qualified EXTERNAL addresses, never an implicit RVA.
        // Decision (schema/behavior parity): the Xrefs schema promises that
        // direction=to accepts the EXTERNAL:<offset> literals ListSymbols emits,
        // so address() must resolve them even when program.parseAddress does not
        // round-trip EXTERNAL space on this Ghidra version. The fallback below
        // resolves an EXTERNAL: literal against the external symbol table (and
        // the EXTERNAL address space), returning the same EXTERNAL-space Address
        // ListSymbols used, so XrefsTo sees the same reference-table rows that
        // produced refCount. Only direction=to is meaningful for EXTERNAL
        // (imports have incoming refs, no outgoing flows); direction=from/both
        // accept the literal but honestly return no from-side rows.
        String trimmed = text == null ? "" : text.trim();
        Address[] parsed = null;
        try {
            parsed = program.parseAddress(trimmed);
        } catch (RuntimeException ignored) { }
        if (parsed != null && parsed.length == 1) return parsed[0];
        if (parsed != null && parsed.length > 1) {
            StringBuilder candidates = new StringBuilder();
            for (int index = 0; index < parsed.length && index < 3; index++) {
                if (index > 0) candidates.append(", ");
                candidates.append(parsed[index]);
            }
            throw new BridgeFailure("invalid_address",
                "'" + clipped(trimmed, 64) + "' resolves to " + parsed.length +
                " Ghidra addresses (" + candidates + "); pass one exact virtual address");
        }
        if (isExternalLiteral(trimmed)) {
            Address external = resolveExternal(program, trimmed);
            if (external != null) return external;
        }
        throw new BridgeFailure("invalid_address",
            "'" + clipped(trimmed, 64) + "' is not an unambiguous Ghidra virtual address " +
            "(not a live VA, RVA or file offset; qualified EXTERNAL addresses are accepted)");
    }

    /** True for ListSymbols-style EXTERNAL:<hex-offset> literals (e.g. EXTERNAL:00000001). */
    private static boolean isExternalLiteral(String text) {
        if (text.length() < 10) return false; // shortest real literal is EXTERNAL:0
        int colon = text.indexOf(':');
        if (colon <= 0) return false;
        if (!text.substring(0, colon).trim().equalsIgnoreCase("EXTERNAL")) return false;
        String offset = text.substring(colon + 1).trim();
        if (offset.isEmpty() || offset.length() > 16) return false;
        for (int index = 0; index < offset.length(); index++) {
            char c = offset.charAt(index);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }

    /**
     * Resolve an EXTERNAL: literal without relying on parseAddress round-tripping
     * EXTERNAL space. Prefers the EXTERNAL address space directly, then falls back
     * to the external symbol table so the returned Address is the same object
     * ListSymbols emitted (reference-table equality holds). Returns null when the
     * literal cannot be resolved; the caller then reports invalid_address.
     * Defensive against test doubles: proxy mocks throw AssertionError for
     * unimplemented methods, so every probe catches Throwable, never Error-only.
     */
    private static Address resolveExternal(Program program, String text) throws BridgeFailure {
        String hex = text.substring(text.indexOf(':') + 1).trim();
        try {
            AddressSpace space = program.getAddressFactory().getAddressSpace("EXTERNAL");
            if (space != null) {
                try {
                    return space.getAddress(Long.parseUnsignedLong(hex, 16));
                } catch (RuntimeException ignored) { }
            }
        } catch (Throwable ignored) { }
        try {
            Iterator<?> symbols = program.getSymbolTable().getExternalSymbols();
            while (symbols.hasNext()) {
                checkCancelled();
                Object item = symbols.next();
                if (item instanceof Symbol symbol) {
                    Address candidate = symbol.getAddress();
                    if (candidate != null && candidate.toString().equalsIgnoreCase(text.trim())) return candidate;
                }
            }
        } catch (BridgeFailure failure) {
            throw failure;
        } catch (Throwable ignored) { }
        return null;
    }

    private static JsonObject result(Program program) {
        JsonObject result = new JsonObject();
        result.addProperty("source", "ghidra-static");
        result.addProperty("imageBase", program.getImageBase().toString());
        result.addProperty("sha256", program.getExecutableSHA256());
        return result;
    }

    /** One fully-mapped read: the whole range must be initialized and mapped,
     * otherwise the caller reports memory_unavailable. Shared by the single
     * and ranges paths so both views agree on what "readable" means. */
    private static byte[] readMappedBytes(Program program, Address start, int length) throws BridgeFailure {
        byte[] data = new byte[length];
        try {
            start.addNoWrap(length - 1);
            int read = program.getMemory().getBytes(start, data);
            if (read != length) throw new BridgeFailure("memory_unavailable", "The whole range must be initialized and mapped in Ghidra");
        } catch (MemoryAccessException | AddressOverflowException e) {
            throw new BridgeFailure("memory_unavailable", "The whole range must be initialized and mapped in Ghidra");
        }
        return data;
    }

    private static JsonObject bytes(Program p, JsonObject a) throws BridgeFailure {
        if (a.has("ranges")) return bytesRanges(p, a);
        rejectUnknownFields(a, Set.of("module", "address", "length"), "ReadStaticBytes");
        Address start = address(p, requiredString(a, "address", 256));
        int length = boundedInt(a, "length", 256, 1, 32768);
        byte[] data = readMappedBytes(p, start, length);
        JsonObject r = result(p);
        r.remove("sha256");
        r.addProperty("address", start.toString());
        r.addProperty("length", length);
        r.addProperty("hex", HEX.formatHex(data));
        return r;
    }

    /**
     * P2-10 ranges mode: up to 8 {address, length} chunks in one call, total
     * at most 16384 bytes, mirroring the ReadMemAtAddress ranges contract.
     * The 4096 per-chunk cap stays (only the call count drops, never the
     * per-chunk budget) and ranges is exclusive with address/length, the
     * same XOR shape AnalyzeFunctions uses for functions/start. One bad
     * chunk fails only its index with an honest per-index error; breaching
     * the entry count or the total budget fails the whole call, same as the
     * live ranges path.
     */
    private static JsonObject bytesRanges(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "address", "length", "ranges"), "ReadStaticBytes");
        if (a.has("address") || a.has("length"))
            throw new BridgeFailure("invalid_argument", "ranges cannot be used together with address/length");
        JsonElement rangesElement = a.get("ranges");
        if (rangesElement == null || !rangesElement.isJsonArray())
            throw new BridgeFailure("invalid_argument", "ranges must be an array");
        JsonArray ranges = rangesElement.getAsJsonArray();
        if (ranges.size() < 1 || ranges.size() > 8)
            throw new BridgeFailure("argument_out_of_range", "ranges is outside the allowed range");
        List<RangeSpec> specs = new ArrayList<>(ranges.size());
        long total = 0;
        for (int index = 0; index < ranges.size(); index++) {
            RangeSpec spec = parseRangeSpec(ranges.get(index), index);
            specs.add(spec);
            if (spec.errorCode == null) total += spec.length;
        }
        if (total > 16384)
            throw new BridgeFailure("argument_out_of_range", "ReadStaticBytes total length across ranges must not exceed 16384");
        JsonArray rows = new JsonArray();
        boolean partial = false;
        for (RangeSpec spec : specs) {
            if (spec.errorCode != null) {
                JsonObject row = new JsonObject();
                row.addProperty("index", spec.index);
                if (!spec.addressText.isEmpty()) row.addProperty("address", clipped(spec.addressText, 256));
                row.addProperty("ok", false);
                row.addProperty("code", spec.errorCode);
                row.addProperty("message", clipped(spec.errorMessage, 256));
                rows.add(row);
                partial = true;
                continue;
            }
            Address start;
            try {
                start = address(p, spec.addressText);
            }
            catch (BridgeFailure failure) {
                JsonObject row = new JsonObject();
                row.addProperty("index", spec.index);
                row.addProperty("address", clipped(spec.addressText, 256));
                row.addProperty("length", spec.length);
                row.addProperty("ok", false);
                row.addProperty("code", failure.code);
                row.addProperty("message", clipped(failure.getMessage(), 256));
                rows.add(row);
                partial = true;
                continue;
            }
            byte[] data;
            try {
                data = readMappedBytes(p, start, spec.length);
            }
            catch (BridgeFailure failure) {
                JsonObject row = new JsonObject();
                row.addProperty("index", spec.index);
                row.addProperty("address", start.toString());
                row.addProperty("length", spec.length);
                row.addProperty("ok", false);
                row.addProperty("code", failure.code);
                row.addProperty("message", clipped(failure.getMessage(), 256));
                rows.add(row);
                partial = true;
                continue;
            }
            // Success rows stay sparse: the array position is the index and
            // hex.length()/2 is the length. Error rows keep index/length so a
            // failed chunk is still attributable to its request entry.
            JsonObject row = new JsonObject();
            row.addProperty("address", start.toString());
            row.addProperty("hex", HEX.formatHex(data));
            rows.add(row);
        }
        JsonObject r = result(p);
        r.remove("sha256");
        r.add("ranges", rows);
        r.addProperty("partial", partial);
        r.addProperty("truncated", false);
        return r;
    }

    /** One validated ranges entry: either readable (addressText+length) or a
     * per-index error (errorCode+errorMessage). Structural problems never
     * throw: the entry fails, not the call. */
    private static final class RangeSpec {
        int index;
        String addressText = "";
        int length = 128;
        String errorCode;
        String errorMessage;
    }

    private static RangeSpec parseRangeSpec(JsonElement element, int index) {
        RangeSpec spec = new RangeSpec();
        spec.index = index;
        if (element == null || !element.isJsonObject()) {
            spec.errorCode = "invalid_argument";
            spec.errorMessage = "ranges[" + index + "] must be an object";
            return spec;
        }
        JsonObject entry = element.getAsJsonObject();
        for (String field : entry.keySet()) {
            if (!field.equals("address") && !field.equals("length")) {
                spec.errorCode = "unknown_argument";
                spec.errorMessage = "unsupported ranges[" + index + "] argument";
                return spec;
            }
        }
        JsonElement addressElement = entry.get("address");
        if (addressElement == null || !addressElement.isJsonPrimitive()
            || !addressElement.getAsJsonPrimitive().isString()
            || addressElement.getAsString().trim().isEmpty()) {
            spec.errorCode = "missing_argument";
            spec.errorMessage = "ranges[" + index + "].address must be a string";
            return spec;
        }
        spec.addressText = addressElement.getAsString();
        if (spec.addressText.length() > 256) {
            spec.errorCode = "argument_too_long";
            spec.errorMessage = "ranges[" + index + "].address exceeds the character limit";
            return spec;
        }
        if (!entry.has("length")) {
            spec.length = 128;
            return spec;
        }
        JsonElement lengthElement = entry.get("length");
        if (lengthElement == null || !lengthElement.isJsonPrimitive()
            || !lengthElement.getAsJsonPrimitive().isNumber()) {
            spec.errorCode = "invalid_argument";
            spec.errorMessage = "ranges[" + index + "].length must be an integer";
            return spec;
        }
        try {
            String raw = lengthElement.getAsString();
            if (!isIntegerLiteral(raw)) throw new NumberFormatException("not a plain integer");
            int parsed = Integer.parseInt(raw);
            if (parsed < 1 || parsed > 4096) {
                spec.errorCode = "argument_out_of_range";
                spec.errorMessage = "ranges[" + index + "].length is outside the allowed range";
                return spec;
            }
            spec.length = parsed;
        }
        catch (NumberFormatException exception) {
            spec.errorCode = "invalid_argument";
            spec.errorMessage = "ranges[" + index + "].length must be an integer";
        }
        return spec;
    }

    private static int optionalInt(JsonObject object, String name, int fallback, int min, int max)
        throws BridgeFailure {
        if (!object.has(name)) return fallback;
        return boundedInt(object, name, fallback, min, max);
    }

    private static JsonObject function(Function f) {
        // Sparse ListFunctions row: the slim name/entry base plus the fields
        // that distinguish one range (a single-range non-thunk function
        // starting at its entry only carries size).
        JsonObject r = GhidraAnalysisFormatting.slimFunction(f, null);
        String entry = r.get("entry").getAsString();
        String minAddress = f.getBody().getMinAddress().toString();
        if (!minAddress.equals(entry)) r.addProperty("minAddress", minAddress);
        String maxAddress = f.getBody().getMaxAddress().toString();
        if (!maxAddress.equals(entry)) r.addProperty("maxAddress", maxAddress);
        r.addProperty("size", f.getBody().getNumAddresses());
        if (f.getBody().getNumAddressRanges() != 1) r.addProperty("rangeCount", f.getBody().getNumAddressRanges());
        if (f.isThunk()) r.addProperty("thunk", true);
        return r;
    }

    /** Slim xref embedding: the row already carries addresses, so only the owner name/entry travel. */
    private static JsonObject functionRef(Function f) {
        return GhidraAnalysisFormatting.slimFunction(f, null);
    }

    /**
     * Routing counts for ListFunctions rows: instructions in the body and how
     * many of them transfer control (call or jump, conditional or not). This
     * is listing truth, not an aggregate score: callers rank with the two
     * raw numbers. Bounded by MAX_BODY_CODE_UNITS; null when the body cannot
     * be read or the bound is hit. Never throws; cancellation propagates.
     */
    private static void addComplexity(Program program, JsonObject row, Function function) throws BridgeFailure {
        try {
            AddressSetView body = function.getBody();
            if (body == null) {
                return;
            }
            Iterator<Instruction> instructions = program.getListing().getInstructions(body, true);
            int total = 0, branches = 0;
            while (instructions.hasNext()) {
                if (total >= MAX_BODY_CODE_UNITS) {
                    return;
                }
                if ((total & 1023) == 0) checkCancelled();
                Instruction instruction = instructions.next();
                total++;
                if (isBranch(instruction)) branches++;
            }
            row.addProperty("instructionCount", total);
            // Absent means zero (the Map ranker already reads absent as 0).
            if (branches > 0) row.addProperty("branchCount", branches);
        }
        catch (RuntimeException exception) {
            // Unreadable listings omit the routing counts instead of failing the row.
        }
    }

    private static boolean isBranch(Instruction instruction) {
        try {
            FlowType flow = instruction.getFlowType();
            return flow != null && (flow.isCall() || flow.isJump());
        }
        catch (RuntimeException exception) {
            return false;
        }
    }

    /** Offset refers to examined database rows, not matched rows, so filters make progress. */
    private static final class Page {
        final JsonArray rows = new JsonArray();
        final int offset, limit;
        int position, chars;
        boolean stopped;
        Page(JsonObject a) throws BridgeFailure {
            this(a, 128);
        }
        Page(JsonObject a, int defaultLimit) throws BridgeFailure {
            offset = boundedInt(a, "offset", 0, 0, 1000000);
            limit = boundedInt(a, "maxItems", defaultLimit, 1, MAX_PAGE_ITEMS);
        }
        boolean add(JsonObject row) {
            int size = JSON.toJson(row).getBytes(StandardCharsets.UTF_8).length;
            if (rows.size() >= limit || chars + size > 100000) { stopped = true; return false; }
            rows.add(row); chars += size; return true;
        }
        JsonObject finish(Program p, String field, boolean more) {
            JsonObject r = result(p);
            r.add(field, rows);
            r.addProperty("truncated", more);
            if (more) r.addProperty("nextOffset", position);
            return r;
        }
    }

    private static JsonObject xrefs(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "address", "callsOnly", "offset", "maxItems"), "XrefsTo");
        Address target = address(p, requiredString(a, "address", 256));
        boolean callsOnly = boundedBoolean(a, "callsOnly", false);
        Page page = new Page(a, 16);
        ReferenceIterator refs = p.getReferenceManager().getReferencesTo(target);
        int scanned = 0;
        int refDbRows = 0;
        while (refs.hasNext()) {
            checkCancelled();
            if (page.position < page.offset) { refs.next(); page.position++; refDbRows++; continue; }
            if (scanned++ >= 100000) break;
            Reference ref = refs.next();
            refDbRows++;
            if (!callsOnly || ref.getReferenceType().isCall()) {
                JsonObject row = new JsonObject();
                row.addProperty("from", ref.getFromAddress().toString());
                row.addProperty("type", ref.getReferenceType().toString());
                row.addProperty("operandIndex", ref.getOperandIndex());
                Function owner = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (owner != null) row.add("function", functionRef(owner));
                if (!page.add(row)) break;
            }
            page.position++;
        }
        // An empty reference table is not proof that nothing references the
        // target: unanalyzed code and table-driven dispatch never register
        // references. Fall back to a bounded listing/memory scan so reachability
        // checks get real rows instead of a silently empty list.
        boolean fallback = refDbRows == 0;
        boolean scanComplete = true;
        int scanInstructions = 0;
        long scanBytes = 0;
        if (fallback) {
            ScanResult scan = scanForReferencesTo(p, target);
            scanComplete = scan.complete;
            scanInstructions = scan.instructions;
            scanBytes = scan.bytes;
            for (JsonObject row : scan.rows) {
                checkCancelled();
                if (page.position < page.offset) { page.position++; continue; }
                if (callsOnly && !isCallType(row.has("type") ? row.get("type").getAsString() : null)) { page.position++; continue; }
                if (!page.add(row)) break;
                page.position++;
            }
        }
        boolean more = page.stopped ||
            (!fallback && refs.hasNext()) ||
            (fallback && !scanComplete);
        JsonObject r = page.finish(p, "references", more);
        // The caller already targets one address; the program hash does not
        // route references and only doubled the page.
        r.remove("sha256");
        r.addProperty("address", target.toString());
        if (fallback) {
            r.addProperty("fallbackScan", true);
            r.addProperty("scanComplete", scanComplete);
            r.addProperty("scannedInstructions", scanInstructions);
            r.addProperty("scannedBytes", scanBytes);
        }
        return r;
    }

    private static String scanKey(Program p) {
        return p.getExecutableSHA256() + "|" + p.getImageBase() + "|" +
            p.getFunctionManager().getFunctionCount();
    }

    /** Call-ness derived from the reference/flow type name (every call type name contains CALL). */
    static boolean isCallType(String type) {
        return type != null && type.toUpperCase(Locale.ROOT).contains("CALL");
    }

    /**
     * Fallback-scan row for XrefsTo: `to` is always the queried target and
     * call-ness is derivable from `type`, so neither travels. The top-level
     * fallbackScan flag marks scan origin instead of a per-row source.
     */
    private static JsonObject scanRow(Program p, Address from, String type, int operandIndex) {
        JsonObject row = new JsonObject();
        row.addProperty("from", from.toString());
        row.addProperty("type", type);
        if (operandIndex >= 0) row.addProperty("operandIndex", operandIndex);
        Function owner = p.getFunctionManager().getFunctionContaining(from);
        if (owner != null) row.add("function", functionRef(owner));
        return row;
    }

    /**
     * Find references to a target the reference table does not know about:
     * direct flow targets and address scalars in every instruction, plus
     * absolute pointers stored in initialized memory. Bounded by deadline,
     * instruction count and byte count; every bound is reported through
     * scanComplete instead of being hidden.
     */
    private static ScanResult scanForReferencesTo(Program p, Address target) throws BridgeFailure {
        String key = "to|" + scanKey(p) + "|" + target;
        synchronized (SCAN_CACHE) {
            ScanResult cached = SCAN_CACHE.get(key);
            if (cached != null) return cached;
        }

        List<JsonObject> rows = new ArrayList<>();
        Set<String> seenFrom = new HashSet<>();
        long deadline = System.nanoTime() + SCAN_DEADLINE_NANOS;
        boolean complete = true;
        int instructions = 0;
        long dataBytes = 0;

        InstructionIterator iterator = p.getListing().getInstructions(true);
        boolean scanScalars = target.isMemoryAddress();
        while (iterator.hasNext()) {
            if (rows.size() >= SCAN_MAX_MATCHES || instructions >= SCAN_MAX_CODE_UNITS ||
                System.nanoTime() >= deadline) {
                complete = false;
                break;
            }
            if ((instructions & 1023) == 0) checkCancelled();
            Instruction instruction = iterator.next();
            instructions++;
            Address from = instruction.getAddress();
            boolean matched = false;
            for (Address flow : instruction.getFlows()) {
                if (flow != null && flow.equals(target)) {
                    rows.add(scanRow(p, from, instruction.getFlowType().toString(), -1));
                    seenFrom.add(from.toString());
                    matched = true;
                    break;
                }
            }
            if (matched || !scanScalars) continue;
            int operands = instruction.getNumOperands();
            for (int index = 0; index < operands; index++) {
                Scalar scalar = instruction.getScalar(index);
                if (scalar != null && scalar.getUnsignedValue() == target.getOffset()) {
                    rows.add(scanRow(p, from, "SCALAR", index));
                    seenFrom.add(from.toString());
                    break;
                }
            }
        }

        if (complete && scanScalars) {
            long offset = target.getOffset();
            byte n0 = (byte) offset, n1 = (byte) (offset >> 8), n2 = (byte) (offset >> 16), n3 = (byte) (offset >> 24);
            boolean requireHigh = (offset >>> 32) != 0;
            byte h0 = (byte) (offset >> 32), h1 = (byte) (offset >> 40), h2 = (byte) (offset >> 48), h3 = (byte) (offset >> 56);
            outer:
            for (MemoryBlock block : p.getMemory().getBlocks()) {
                if (!block.isInitialized()) continue;
                long position = 0;
                while (position < block.getSize()) {
                    if (dataBytes >= SCAN_MAX_BYTES || rows.size() >= SCAN_MAX_MATCHES ||
                        System.nanoTime() >= deadline) {
                        complete = false;
                        break outer;
                    }
                    checkCancelled();
                    int count = (int) Math.min(SCAN_CHUNK_BYTES, block.getSize() - position);
                    // Read 7 bytes past the window so pointers crossing a chunk
                    // boundary are still matched exactly once.
                    int readLength = (int) Math.min((long) count + 7, block.getSize() - position);
                    byte[] data = new byte[readLength];
                    try {
                        if (block.getBytes(block.getStart().add(position), data) != readLength) {
                            complete = false;
                            break outer;
                        }
                    }
                    catch (MemoryAccessException exception) {
                        complete = false;
                        break outer;
                    }
                    for (int index = 0; index < count && index + 4 <= readLength; index++) {
                        if (data[index] != n0 || data[index + 1] != n1 ||
                            data[index + 2] != n2 || data[index + 3] != n3) continue;
                        if (requireHigh) {
                            if (index + 8 > readLength ||
                                data[index + 4] != h0 || data[index + 5] != h1 ||
                                data[index + 6] != h2 || data[index + 7] != h3) continue;
                        }
                        Address from = block.getStart().add(position + index);
                        if (!seenFrom.add(from.toString())) continue;
                        rows.add(scanRow(p, from, "POINTER", -1));
                        if (rows.size() >= SCAN_MAX_MATCHES) {
                            complete = false;
                            break outer;
                        }
                    }
                    position += count;
                    dataBytes += count;
                }
            }
        }

        ScanResult result = new ScanResult(rows, complete, instructions, dataBytes);
        // A match-limit result is deterministic and worth caching; only
        // deadline/cancellation stops force a rescan.
        if (complete || rows.size() >= SCAN_MAX_MATCHES) {
            synchronized (SCAN_CACHE) {
                SCAN_CACHE.put(key, result);
            }
        }
        return result;
    }

    private static JsonObject xrefsFrom(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "address", "callsOnly", "offset", "maxItems"), "XrefsFrom");
        Address target = address(p, requiredString(a, "address", 256));
        boolean callsOnly = boundedBoolean(a, "callsOnly", false);
        Page page = new Page(a, 16);
        Function fn = p.getFunctionManager().getFunctionAt(target);
        if (fn == null) {
            fn = p.getFunctionManager().getFunctionContaining(target);
        }
        List<Reference> refList = new ArrayList<>();
        if (fn != null) {
            AddressIterator sources = p.getReferenceManager().getReferenceSourceIterator(fn.getBody(), true);
            while (sources.hasNext()) {
                Reference[] arr = p.getReferenceManager().getReferencesFrom(sources.next());
                if (arr != null) {
                    Collections.addAll(refList, arr);
                }
            }
        } else {
            Reference[] arr = p.getReferenceManager().getReferencesFrom(target);
            if (arr != null) {
                Collections.addAll(refList, arr);
            }
        }
        Iterator<Reference> refs = refList.iterator();
        int scanned = 0;
        while (refs.hasNext()) {
            checkCancelled();
            if (page.position < page.offset) { refs.next(); page.position++; continue; }
            if (scanned++ >= 100000) break;
            Reference ref = refs.next();
            if (!callsOnly || ref.getReferenceType().isCall()) {
                JsonObject row = new JsonObject();
                row.addProperty("from", ref.getFromAddress().toString());
                row.addProperty("to", ref.getToAddress().toString());
                row.addProperty("type", ref.getReferenceType().toString());
                row.addProperty("operandIndex", ref.getOperandIndex());
                Symbol s = p.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                if (s != null) {
                    row.addProperty("symbol", s.getName());
                }
                Function targetFn = p.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (targetFn != null) {
                    row.add("function", functionRef(targetFn));
                }
                if (!page.add(row)) break;
            }
            page.position++;
        }
        // Empty reference table: derive outgoing flows from the listing so
        // direct callees/jump targets stay visible for reachability checks.
        boolean fallback = refList.isEmpty() && fn != null;
        boolean scanComplete = true;
        int scanInstructions = 0;
        if (fallback) {
            List<JsonObject> rows = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            long deadline = System.nanoTime() + SCAN_DEADLINE_NANOS;
            InstructionIterator iterator = p.getListing().getInstructions(fn.getBody(), true);
            while (iterator.hasNext()) {
                if (rows.size() >= SCAN_MAX_MATCHES || scanInstructions >= SCAN_MAX_CODE_UNITS ||
                    System.nanoTime() >= deadline) {
                    scanComplete = false;
                    break;
                }
                if ((scanInstructions & 1023) == 0) checkCancelled();
                Instruction instruction = iterator.next();
                scanInstructions++;
                for (Address flow : instruction.getFlows()) {
                    if (flow == null || !seen.add(instruction.getAddress() + "->" + flow)) continue;
                    JsonObject row = new JsonObject();
                    row.addProperty("from", instruction.getAddress().toString());
                    row.addProperty("to", flow.toString());
                    row.addProperty("type", instruction.getFlowType().toString());
                    Symbol symbol = p.getSymbolTable().getPrimarySymbol(flow);
                    if (symbol != null) row.addProperty("symbol", clipped(symbol.getName(), 512));
                    Function targetFn = p.getFunctionManager().getFunctionAt(flow);
                    if (targetFn != null) row.add("function", functionRef(targetFn));
                    rows.add(row);
                }
            }
            for (JsonObject row : rows) {
                checkCancelled();
                if (page.position < page.offset) { page.position++; continue; }
                if (callsOnly && !isCallType(row.has("type") ? row.get("type").getAsString() : null)) { page.position++; continue; }
                if (!page.add(row)) break;
                page.position++;
            }
        }
        boolean more = page.stopped ||
            (!fallback && refs.hasNext()) ||
            (fallback && !scanComplete);
        JsonObject r = page.finish(p, "references", more);
        // The caller already targets one address; the program hash does not
        // route references and only doubled the page.
        r.remove("sha256");
        r.addProperty("address", target.toString());
        if (fn != null) {
            r.addProperty("functionName", fn.getName());
        }
        if (fallback) {
            r.addProperty("fallbackScan", true);
            r.addProperty("scanComplete", scanComplete);
            r.addProperty("scannedInstructions", scanInstructions);
        }
        return r;
    }

    /**
     * P0-4 who-calls-x in one call: the two existing single-direction paths
     * fan in here with synthesized per-side paging args. Each side keeps its
     * full result OBJECT ({references, truncated, nextOffset?, address,
     * fallbackScan/scanComplete honesty flags}) verbatim under to/from so
     * pre-flatten consumers keep working (to.references, to.truncated,
     * to.nextOffset); the flattened top-level cursors (toTruncated/
     * fromTruncated, nextOffsetTo/nextOffsetFrom, truncated as the OR of both
     * sides) stay as a convenience so new callers need not dig into the
     * nested envelopes. offset/maxItems are the shared defaults;
     * offsetTo/offsetFrom/maxItemsTo/maxItemsFrom win per side, so multi-hop
     * walks page each direction independently. The nested envelopes repeat
     * the source/imageBase/sha256 echoes (kept verbatim for contract
     * compatibility); the row-level token wins (slim function refs, omitted
     * constant targets) are unaffected.
     */
    private static JsonObject xrefsBoth(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "address", "callsOnly", "offset", "maxItems",
            "offsetTo", "offsetFrom", "maxItemsTo", "maxItemsFrom"), "XrefsBoth");
        String addressText = requiredString(a, "address", 256);
        boolean callsOnly = boundedBoolean(a, "callsOnly", false);
        int offset = boundedInt(a, "offset", 0, 0, 1000000);
        int maxItems = boundedInt(a, "maxItems", 16, 1, MAX_PAGE_ITEMS);
        int offsetTo = optionalInt(a, "offsetTo", offset, 0, 1000000);
        int offsetFrom = optionalInt(a, "offsetFrom", offset, 0, 1000000);
        int maxItemsTo = optionalInt(a, "maxItemsTo", maxItems, 1, MAX_PAGE_ITEMS);
        int maxItemsFrom = optionalInt(a, "maxItemsFrom", maxItems, 1, MAX_PAGE_ITEMS);
        String module = optionalString(a, "module", 2048);

        JsonObject toArgs = new JsonObject();
        JsonObject fromArgs = new JsonObject();
        if (!module.isEmpty()) {
            toArgs.addProperty("module", module);
            fromArgs.addProperty("module", module);
        }
        toArgs.addProperty("address", addressText);
        fromArgs.addProperty("address", addressText);
        if (callsOnly) {
            toArgs.addProperty("callsOnly", true);
            fromArgs.addProperty("callsOnly", true);
        }
        toArgs.addProperty("offset", offsetTo);
        toArgs.addProperty("maxItems", maxItemsTo);
        fromArgs.addProperty("offset", offsetFrom);
        fromArgs.addProperty("maxItems", maxItemsFrom);

        JsonObject to = xrefs(p, toArgs);
        JsonObject from = xrefsFrom(p, fromArgs);
        // Contract-preserving envelope: nest the per-side result objects
        // verbatim (to.references, to.truncated, to.nextOffset, ...) and keep
        // the flattened top-level cursors alongside for convenience.
        JsonObject r = result(p);
        r.addProperty("address", address(p, addressText).toString());
        // The nested pages repeat identity already present at the top level;
        // their cursors and references are the only facts that differ.
        for (String duplicate : List.of("source", "imageBase", "sha256", "address")) {
            to.remove(duplicate);
            from.remove(duplicate);
        }
        r.add("to", to);
        r.add("from", from);
        // The nested sides carry truncated already; the top-level OR is the
        // only extra bit worth stating.
        if (to.has("nextOffset")) r.addProperty("nextOffsetTo", to.get("nextOffset").getAsInt());
        if (from.has("nextOffset")) r.addProperty("nextOffsetFrom", from.get("nextOffset").getAsInt());
        r.addProperty("truncated", to.get("truncated").getAsBoolean() ||
            from.get("truncated").getAsBoolean());
        boolean toScan = to.has("fallbackScan") && to.get("fallbackScan").getAsBoolean();
        boolean fromScan = from.has("fallbackScan") && from.get("fallbackScan").getAsBoolean();
        if (toScan || fromScan) {
            r.addProperty("fallbackScan", true);
            r.addProperty("scanComplete",
                (!toScan || to.get("scanComplete").getAsBoolean())
                && (!fromScan || from.get("scanComplete").getAsBoolean()));
            r.addProperty("scannedInstructions",
                (toScan ? to.get("scannedInstructions").getAsInt() : 0)
                + (fromScan ? from.get("scannedInstructions").getAsInt() : 0));
            if (toScan && to.has("scannedBytes")) r.addProperty("scannedBytes", to.get("scannedBytes").getAsLong());
        }
        if (from.has("functionName")) r.addProperty("functionName", from.get("functionName").getAsString());
        return r;
    }

    /**
     * P2-10 triage-module in one call: the two existing symbol paths fan in
     * here with synthesized per-side paging args. Each side keeps its own
     * array, truncated flag and nextOffset cursor (nextOffsetImports /
     * nextOffsetExports); truncated is the OR of both sides. ListImports rows
     * always carry refCount; referenceSites is opt-in via includeSites=true
     * (default cap 8 when maxSites is omitted) or an explicit maxSites &gt; 0.
     * An explicit maxSites:0 is refCount-only even with includeSites:true, so
     * callers can request counts without sites. maxSites/includeSites pass
     * through to the imports side only; exports rows never carry sites.
     */
    private static JsonObject symbolsBoth(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "filter", "offset", "maxItems", "maxSites", "includeSites",
            "offsetImports", "offsetExports", "maxItemsImports", "maxItemsExports"), "ListSymbolsBoth");
        String filter = optionalString(a, "filter", 256);
        String module = optionalString(a, "module", 2048);
        int offset = boundedInt(a, "offset", 0, 0, 1000000);
        int maxItems = boundedInt(a, "maxItems", 128, 1, MAX_PAGE_ITEMS);
        int maxSites = boundedInt(a, "maxSites", 0, 0, 32);
        boolean includeSites = boundedBoolean(a, "includeSites", false);
        int offsetImports = optionalInt(a, "offsetImports", offset, 0, 1000000);
        int offsetExports = optionalInt(a, "offsetExports", offset, 0, 1000000);
        int maxItemsImports = optionalInt(a, "maxItemsImports", maxItems, 1, MAX_PAGE_ITEMS);
        int maxItemsExports = optionalInt(a, "maxItemsExports", maxItems, 1, MAX_PAGE_ITEMS);

        JsonObject importsArgs = new JsonObject();
        JsonObject exportsArgs = new JsonObject();
        if (!module.isEmpty()) {
            importsArgs.addProperty("module", module);
            exportsArgs.addProperty("module", module);
        }
        if (!filter.isEmpty()) {
            importsArgs.addProperty("filter", filter);
            exportsArgs.addProperty("filter", filter);
        }
        importsArgs.addProperty("offset", offsetImports);
        importsArgs.addProperty("maxItems", maxItemsImports);
        if (a.has("maxSites")) importsArgs.addProperty("maxSites", maxSites);
        if (includeSites) importsArgs.addProperty("includeSites", true);
        exportsArgs.addProperty("offset", offsetExports);
        exportsArgs.addProperty("maxItems", maxItemsExports);

        JsonObject imports = symbols(p, importsArgs, true);
        JsonObject exports = symbols(p, exportsArgs, false);
        JsonObject r = result(p);
        r.remove("sha256");
        r.add("imports", imports.getAsJsonArray("imports"));
        r.add("exports", exports.getAsJsonArray("exports"));
        // The per-side cursor is the truncation signal: a present
        // nextOffsetImports/Exports means that side has more rows. The
        // redundant importsTruncated/exportsTruncated booleans doubled the
        // envelope without adding a fact.
        if (imports.has("nextOffset")) r.addProperty("nextOffsetImports", imports.get("nextOffset").getAsInt());
        if (exports.has("nextOffset")) r.addProperty("nextOffsetExports", exports.get("nextOffset").getAsInt());
        r.addProperty("truncated", imports.get("truncated").getAsBoolean() ||
            exports.get("truncated").getAsBoolean());
        return r;
    }

    private static JsonObject functions(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "start", "end", "filter", "overlapping", "offset", "maxItems",
            "includeCounts"), "ListFunctions");
        String startText = optionalString(a, "start", 256), endText = optionalString(a, "end", 256);
        Address start = startText.isEmpty() ? p.getMinAddress() : address(p, startText);
        Address end = endText.isEmpty() ? p.getMaxAddress() : address(p, endText);
        if (!start.getAddressSpace().equals(end.getAddressSpace()) || start.compareTo(end) > 0)
            throw new BridgeFailure("invalid_argument", "start and end must form an inclusive range in one address space");
        boolean overlap = boundedBoolean(a, "overlapping", true);
        AddressSet range = new AddressSet(start, end);
        Iterator<Function> it = overlap ? p.getFunctionManager().getFunctionsOverlapping(range)
            : p.getFunctionManager().getFunctions(range, true);
        String filter = optionalString(a, "filter", 256);
        // Counts need a full listing walk per row, so they are opt-in. The
        // module map asks for them when it risk-ranks functions.
        boolean includeCounts = boundedBoolean(a, "includeCounts", false);
        Page page = new Page(a);
        int scanned = 0;
        while (it.hasNext()) {
            checkCancelled();
            if (page.position < page.offset) { it.next(); page.position++; continue; }
            if (scanned++ >= 100000) break;
            // Stop before paying for a row that cannot fit the page.
            if (page.rows.size() >= page.limit) { page.stopped = true; break; }
            Function f = it.next();
            if (!matches(f.getName(), filter)) { page.position++; continue; }
            JsonObject row = function(f);
            if (includeCounts) addComplexity(p, row, f);
            if (!page.add(row)) break;
            page.position++;
        }
        return page.finish(p, "functions", page.stopped || it.hasNext());
    }

    /**
     * Memory-block layout plus the image entry point. Sections are the cheap
     * packer signal (writable+executable, tiny .text, empty .rdata) and the
     * entry function anchors map-first navigation without a decompiler pass.
     */
    private static JsonObject sections(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "maxSections"), "ListSections");
        int maxSections = boundedInt(a, "maxSections", 32, 1, 128);
        JsonObject r = result(p);
        Address entryPoint = imageEntryPoint(p);
        if (entryPoint != null) {
            r.addProperty("entryPoint", entryPoint.toString());
            Function entryFunction = p.getFunctionManager().getFunctionAt(entryPoint);
            if (entryFunction != null) r.add("entryFunction", function(entryFunction));
        }
        JsonArray rows = new JsonArray();
        boolean truncated = false;
        for (MemoryBlock block : p.getMemory().getBlocks()) {
            checkCancelled();
            if (rows.size() >= maxSections) { truncated = true; break; }
            JsonObject row = new JsonObject();
            row.addProperty("name", clipped(block.getName(), 128));
            row.addProperty("start", block.getStart().toString());
            row.addProperty("end", block.getEnd().toString());
            row.addProperty("size", block.getSize());
            row.addProperty("permissions",
                (block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-") + (block.isExecute() ? "x" : "-"));
            row.addProperty("initialized", block.isInitialized());
            rows.add(row);
        }
        r.add("sections", rows);
        r.addProperty("truncated", truncated);
        return r;
    }

    /**
     * The image entry point. Program has no getEntryPoint(); the PE loader
     * names it "entry", while the external-entry-point table also contains
     * exports (address-ordered, so its first row is not reliably the entry).
     * Prefer the loader symbol and fall back to the table for formats that do
     * not name it.
     */
    private static Address imageEntryPoint(Program p) {
        SymbolIterator named = p.getSymbolTable().getSymbols("entry");
        while (named.hasNext()) {
            Symbol symbol = named.next();
            SymbolType type = symbol.getSymbolType();
            if ((type == SymbolType.FUNCTION || type == SymbolType.LABEL) && symbol.getAddress() != null)
                return symbol.getAddress();
        }
        AddressIterator entries = p.getSymbolTable().getExternalEntryPointIterator();
        return entries.hasNext() ? entries.next() : null;
    }

    static boolean matches(String value, String filter) {
        // Case-insensitive glob with '*' only; a plain string is a substring query.
        String text = value.toLowerCase(Locale.ROOT), needle = filter.toLowerCase(Locale.ROOT);
        if (!needle.contains("*")) return text.contains(needle);
        int at = 0, pattern = 0, star = -1, retry = 0;
        while (at < text.length()) {
            if (pattern < needle.length() && needle.charAt(pattern) == '*') { star = pattern++; retry = at; }
            else if (pattern < needle.length() && needle.charAt(pattern) == text.charAt(at)) { at++; pattern++; }
            else if (star >= 0) { pattern = star + 1; at = ++retry; }
            else return false;
        }
        while (pattern < needle.length() && needle.charAt(pattern) == '*') pattern++;
        return pattern == needle.length();
    }

    private static JsonObject symbols(Program p, JsonObject a, boolean imports) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "filter", "offset", "maxItems", "maxSites", "includeSites"), imports ? "ListImports" : "ListExports");
        String filter = optionalString(a, "filter", 256);
        int maxSites = boundedInt(a, "maxSites", 0, 0, 32);
        boolean includeSites = boundedBoolean(a, "includeSites", false);
        Iterator<?> it = imports ? p.getSymbolTable().getExternalSymbols()
            : p.getSymbolTable().getExternalEntryPointIterator();
        Page page = new Page(a);
        int scanned = 0;
        while (it.hasNext()) {
            checkCancelled();
            if (page.position < page.offset) { it.next(); page.position++; continue; }
            if (scanned++ >= 100000) break;
            Object item = it.next();
            Address addr = imports ? ((Symbol)item).getAddress() : (Address)item;
            Symbol symbol = imports ? (Symbol)item : p.getSymbolTable().getPrimarySymbol(addr);
            String name = symbol == null ? addr.toString() : symbol.getName();
            if (matches(name, filter)) {
                JsonObject row = new JsonObject();
                row.addProperty("name", clipped(name, 512));
                row.addProperty("address", addr.toString());
                if (imports) {
                    ExternalLocation location = p.getExternalManager().getExternalLocation(symbol);
                    row.addProperty("library", location == null ? "" : clipped(location.getLibraryName(), 512));
                    // EXTERNAL address identifies the symbol; reference sites
                    // (IAT slots and thunks) are opt-in via includeSites=true
                    // (default cap 8 when maxSites is omitted) or an explicit
                    // maxSites > 0. An explicit maxSites:0 is refCount-only even
                    // with includeSites:true. The count always travels; the full
                    // list is one XrefsTo away, flagged by referencesTruncated.
                    // Omitted maxSites vs explicit 0 is load-bearing: the bridge
                    // cannot default 0 to 8 once the caller said 0 explicitly.
                    boolean hasMaxSites = a.has("maxSites");
                    boolean wantSites = hasMaxSites ? maxSites > 0 : includeSites;
                    int siteCap = maxSites > 0 ? maxSites : 8;
                    JsonArray sites = wantSites ? new JsonArray() : null;
                    ReferenceIterator refs = p.getReferenceManager().getReferencesTo(addr);
                    int refCount = 0;
                    while (refs.hasNext()) {
                        checkCancelled();
                        Reference ref = refs.next();
                        refCount++;
                        if (sites != null && sites.size() < siteCap) {
                            sites.add(ref.getFromAddress().toString());
                        }
                    }
                    row.addProperty("refCount", refCount);
                    if (sites != null) {
                        row.add("referenceSites", sites);
                        row.addProperty("referencesTruncated", refCount > sites.size());
                    }
                }
                if (!page.add(row)) break;
            }
            page.position++;
        }
        JsonObject r = page.finish(p, imports ? "imports" : "exports", page.stopped || it.hasNext());
        // The symbol listing never routes on the program hash; source and
        // imageBase identify the page, and the hash only doubled every page.
        r.remove("sha256");
        return r;
    }

    private static boolean printable(int b) { return b >= 32 && b <= 126; }

    /** One decoded printable run: text, exclusive end offset in the buffer, byte width. */
    static final class DecodedString {
        final String text;
        final int end;
        final int width;

        DecodedString(String text, int end, int width) {
            this.text = text;
            this.end = end;
            this.width = width;
        }
    }

    /** Byte width of a string starting at data[index]: 2 for UTF-16LE. */
    static int stringWidth(byte[] data, int index, int limit) {
        return index + 1 < limit && data[index + 1] == 0 ? 2 : 1;
    }

    /**
     * Decode the NUL-terminated printable string beginning at data[index] if
     * one starts there; null when the byte is not printable. Width is 2 for
     * UTF-16LE (second byte NUL). The scan stops at a non-printable byte, at
     * the limit, or after 1024 bytes, mirroring DumpStrings. Shared with the
     * function card's data-reference string reader so the two never drift.
     *
     * <p>Callers scanning every byte of a buffer must run the cheap
     * printable/width/predecessor checks first: decoding interior positions of
     * a long printable run would otherwise make the scan quadratic.</p>
     */
    static DecodedString decodeStringAt(byte[] data, int index, int limit) {
        if (index < 0 || index >= limit || !printable(data[index] & 255)) return null;
        int width = stringWidth(data, index, limit);
        int end = index;
        while (end + width <= limit && end - index < 1024 && printable(data[end] & 255) &&
            (width == 1 || data[end + 1] == 0)) {
            end += width;
        }
        return new DecodedString(
            new String(data, index, end - index, width == 1 ? StandardCharsets.US_ASCII : StandardCharsets.UTF_16LE),
            end,
            width);
    }

    private static JsonObject strings(Program p, JsonObject a) throws BridgeFailure {
        rejectUnknownFields(a, Set.of("module", "section", "start", "filter", "minLength", "maxItems", "maxScanBytes", "includeHex"), "DumpStrings");
        String section = optionalString(a, "section", 256), filter = optionalString(a, "filter", 256);
        String startText = optionalString(a, "start", 256);
        boolean includeHex = boundedBoolean(a, "includeHex", false);
        Address start = startText.isEmpty() ? p.getMinAddress() : address(p, startText);
        int minimum = boundedInt(a, "minLength", 4, 2, 256);
        int limit = boundedInt(a, "maxItems", 128, 1, MAX_PAGE_ITEMS);
        int remaining = boundedInt(a, "maxScanBytes", 1048576, 4096, 16777216);
        JsonArray rows = new JsonArray();
        int scanned = 0, outputBytes = 0;
        Address next = null;
        boolean foundSection = section.isEmpty();
        outer: for (MemoryBlock block : p.getMemory().getBlocks()) {
            if (!section.isEmpty() && !block.getName().equalsIgnoreCase(section)) continue;
            foundSection = true;
            if (!block.isInitialized() || (section.isEmpty() && block.isExecute()) || block.getEnd().compareTo(start) < 0) continue;
            long offset = block.getStart().compareTo(start) < 0 ? start.subtract(block.getStart()) : 0;
            while (offset < block.getSize()) {
                checkCancelled();
                if (remaining == 0) { next = block.getStart().add(offset); break outer; }
                int count = (int)Math.min(Math.min(65536, remaining), block.getSize() - offset);
                int prefix = (int)Math.min(2, offset);
                int readSize = (int)Math.min(count + prefix + 1026L, block.getSize() - offset + prefix);
                byte[] data = new byte[readSize];
                try {
                    if (block.getBytes(block.getStart().add(offset - prefix), data) != readSize)
                        throw new MemoryAccessException("short read");
                } catch (MemoryAccessException e) {
                    throw new BridgeFailure("memory_unavailable", "Cannot read initialized static memory block");
                }
                for (int i = prefix; i < prefix + count; i++) {
                    if ((i & 4095) == 0) checkCancelled();
                    // Cheap rejection of interior positions before the O(string)
                    // decode: a long printable run must stay a linear scan.
                    if (!printable(data[i] & 255)) continue;
                    int width = stringWidth(data, i, data.length);
                    if (width == 1 && i > 0 && printable(data[i - 1] & 255)) continue;
                    if (width == 2 && i >= 2 && printable(data[i - 2] & 255) && data[i - 1] == 0) continue;
                    DecodedString decoded = decodeStringAt(data, i, data.length);
                    if (decoded == null) continue;
                    int end = decoded.end;
                    if ((end - i) / width < minimum) continue;
                    String value = decoded.text;
                    if (!matches(value, filter)) continue;
                    JsonObject row = new JsonObject();
                    row.addProperty("address", block.getStart().add(offset + i - prefix).toString());
                    // A section filter makes section uniform: it hoists to the
                    // envelope instead of repeating on every row.
                    if (section.isEmpty()) row.addProperty("section", clipped(block.getName(), 256));
                    if (decoded.width != 1) row.addProperty("encoding", "utf-16le");
                    row.addProperty("text", value);
                    if (includeHex) row.addProperty("hex", HEX.formatHex(data, i, end));
                    if (end - i >= 1024) row.addProperty("stringTruncated", true);
                    int size = JSON.toJson(row).getBytes(StandardCharsets.UTF_8).length;
                    if (rows.size() == limit || outputBytes + size > 100000) {
                        next = block.getStart().add(offset + i - prefix);
                        scanned += i - prefix;
                        break outer;
                    }
                    rows.add(row); outputBytes += size;
                }
                offset += count; remaining -= count; scanned += count;
            }
        }
        if (!foundSection) throw new BridgeFailure("section_not_found", "No memory block matches section");
        JsonObject r = result(p);
        if (!section.isEmpty()) r.addProperty("section", clipped(section, 256));
        r.add("strings", rows);
        r.addProperty("scannedBytes", scanned);
        r.addProperty("truncated", next != null);
        if (next != null) r.addProperty("nextAddress", next.toString());
        return r;
    }
}
