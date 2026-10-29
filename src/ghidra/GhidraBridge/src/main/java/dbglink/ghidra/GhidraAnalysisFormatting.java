package dbglink.ghidra;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import static dbglink.ghidra.GhidraBridgeServer.*;

final class GhidraAnalysisFormatting {

    private static final String DISPLAY_FILE_ENV = "DBGLINK_GHIDRA_DISPLAY_FILE";
    private static final int MAX_DISPLAY_PATH_CHARS = 32_760;
    private static final int MAX_FUNCTION_STRING_CHARS = 128;
    // Two bytes per character plus the NUL so UTF-16LE width detection and
    // the 128-character clip both fit in one bounded read.
    private static final int MAX_FUNCTION_STRING_BYTES = MAX_FUNCTION_STRING_CHARS * 2 + 2;

    // Opt-in sections of the shared function-identity prefix.
    static final int HEAD_PROTOTYPE = 1;
    static final int HEAD_COMMENT = 2;
    static final int HEAD_RVA = 4;
    static final int HEAD_ANALYSIS = 8;
    // Digest analysis keeps size/kind but skips the per-function listing walk
    // that only the full InspectFunction card needs for instructionCount.
    static final int HEAD_ANALYSIS_LEAN = 16;

    /**
     * Shared function-identity prefix: clipped name plus entry always, then
     * the flagged opt-ins in a fixed order (rva, prototype, comment,
     * analysis) so every view emits the same bytes for the same flags.
     * Prototype and comment clip at 512/4096 chars like the historical
     * builders. Rva and comment stay omitted when absent; callers that need
     * unconditional keys (functionIdentity's nullable rva and always-present
     * prototype/comment) add those themselves. A null prototypeKey means
     * "prototype"; DecompileModule passes "signature".
     */
    static JsonObject functionHead(Program program, Function function, int flags, String prototypeKey) {
        Address entry = function.getEntryPoint();
        JsonObject head = new JsonObject();
        head.addProperty("name", clipped(function.getName(), 512));
        head.addProperty("entry", entry.toString());
        // Provenance for triage: ANALYSIS/IMPORTED names came from a known
        // origin (FID database, PDB/DWARF, imports) and can be skipped first;
        // DEFAULT names still need a human/model. USER_DEFINED ones are done.
        head.addProperty("nameSource", symbolSourceName(function));
        if ((flags & HEAD_RVA) != 0) {
            String rvaValue = rva(program, entry);
            if (rvaValue != null) head.addProperty("rva", rvaValue);
        }
        if ((flags & HEAD_PROTOTYPE) != 0) {
            head.addProperty(prototypeKey == null ? "prototype" : prototypeKey,
                clipped(function.getPrototypeString(true, true), 4096));
        }
        if ((flags & HEAD_COMMENT) != 0) {
            String comment = function.getComment();
            if (comment != null && !comment.isEmpty()) head.addProperty("comment", clipped(comment, 4096));
        }
        if ((flags & HEAD_ANALYSIS) != 0) {
            head.add("analysis", functionAnalysis(function, true));
        }
        else if ((flags & HEAD_ANALYSIS_LEAN) != 0) {
            head.add("analysis", functionAnalysis(function, false));
        }
        return head;
    }

    /**
     * Where the function name came from: DEFAULT (auto-generated, still
     * needs review), ANALYSIS (FID database, PDB/DWARF — known origin, skip
     * first), IMPORTED (thunks), USER_DEFINED (already annotated, done).
     * Never throws: an unreadable symbol degrades to "unknown".
     */
    static String symbolSourceName(Function function) {
        try {
            var symbol = function.getSymbol();
            if (symbol == null) {
                return "unknown";
            }
            return clipped(symbol.getSource().name(), 32);
        }
        catch (RuntimeException exception) {
            return "unknown";
        }
    }

    static JsonObject functionIdentity(Program program, Function function) {
        // Unconditional keys stay here: rva travels even when null (JsonNull,
        // which the live mapper reads as an explicit absent rva) and
        // prototype/comment always travel, even empty.
        JsonObject identity = functionHead(program, function, 0, null);
        Address entry = function.getEntryPoint();
        identity.addProperty("rva", rva(program, entry));
        identity.addProperty("prototype", clipped(function.getPrototypeString(true, true), 4096));
        identity.addProperty("comment", clipped(function.getComment(), 4096));
        identity.add("analysis", functionAnalysis(function));

        JsonObject module = new JsonObject();
        module.addProperty("path", clipped(displayExecutablePath(program), 2048));
        module.addProperty("sha256", clipped(program.getExecutableSHA256(), 128));
        module.addProperty("imageBase", program.getImageBase().toString());
        // No duplicate rva here: functionIdentity already carries the same rva at top level,
        // and AddressMapping.TryReadStaticFunction prefers function.rva (module.rva is only a fallback).
        module.add("summary", programSummary(program));
        identity.add("module", module);
        return identity;
    }


    /**
     * Slim per-entry digest for AnalyzeFunctions: identity plus analysis, no
     * repeated module/summary block (that hoists to the envelope once).
     * Prototype and comment are opt-in; an empty comment stays omitted even
     * when requested.
     */
    static JsonObject functionDigest(Program program, Function function, boolean includePrototype, boolean includeComments) {
        int flags = HEAD_RVA | HEAD_ANALYSIS_LEAN
            | (includePrototype ? HEAD_PROTOTYPE : 0)
            | (includeComments ? HEAD_COMMENT : 0);
        return functionHead(program, function, flags, null);
    }

    /**
     * Program identity and size metadata is stable for an open Program, but
     * countImageFunctions walks the whole function table. Cache the finished
     * summary per Program (weak keys so a closed program is collectable) and
     * hand out copies because callers embed it in their own result objects.
     */
    private static final java.util.Map<Program, JsonObject> PROGRAM_SUMMARY_CACHE =
        java.util.Collections.synchronizedMap(new java.util.WeakHashMap<>());

    static JsonObject programSummary(Program program) {
        JsonObject cached;
        synchronized (PROGRAM_SUMMARY_CACHE) {
            cached = PROGRAM_SUMMARY_CACHE.get(program);
        }
        if (cached != null) {
            return cached.deepCopy();
        }
        JsonObject summary = computeProgramSummary(program);
        synchronized (PROGRAM_SUMMARY_CACHE) {
            PROGRAM_SUMMARY_CACHE.put(program, summary);
        }
        return summary.deepCopy();
    }

    /** Called after a mutation that can change functionCount. */
    static void invalidateProgramSummary(Program program) {
        synchronized (PROGRAM_SUMMARY_CACHE) {
            PROGRAM_SUMMARY_CACHE.remove(program);
        }
    }

    private static JsonObject computeProgramSummary(Program program) {
        JsonObject summary = new JsonObject();
        String path = displayExecutablePath(program);
        summary.addProperty("fileName", fileName(path));
        summary.addProperty("format", safeText(program.getExecutableFormat(), "unknown", 512));
        summary.addProperty("sha256", clipped(program.getExecutableSHA256(), 128));
        summary.addProperty("imageBase", program.getImageBase().toString());
        summary.addProperty("minAddress", program.getMinAddress().toString());
        summary.addProperty("maxAddress", program.getMaxAddress().toString());

        try {
            summary.addProperty("architecture", safeText(
                displayArchitecture(program), "unknown", 256));
            summary.addProperty("language", safeText(
                String.valueOf(program.getLanguage().getLanguageDescription()), "unknown", 512));
            summary.addProperty("languageId", safeText(String.valueOf(program.getLanguageID()), "unknown", 256));
        }
        catch (RuntimeException exception) {
            summary.addProperty("architecture", "unknown");
            summary.addProperty("language", "unknown");
            summary.addProperty("languageId", "unknown");
        }

        try {
            summary.addProperty("compiler", safeText(program.getCompiler(), "unknown", 512));
        }
        catch (RuntimeException exception) {
            summary.addProperty("compiler", "unknown");
        }

        try {
            summary.addProperty("compilerSpec", safeText(
                String.valueOf(program.getCompilerSpec().getCompilerSpecID()), "unknown", 256));
        }
        catch (RuntimeException exception) {
            summary.addProperty("compilerSpec", "unknown");
        }

        try {
            summary.addProperty("functionCount", Math.max(0, countImageFunctions(program)));
        }
        catch (RuntimeException exception) {
            summary.addProperty("functionCount", 0);
        }

        // FID provenance: user-attached Function ID databases (ApplyFidb,
        // DBGLINK_FIDB) name library functions before analysis. Presence is
        // the signal — absent when no database is attached, so sessions
        // without FID pay no extra bytes.
        try {
            java.util.List<ghidra.feature.fid.db.FidFile> userFid =
                ghidra.feature.fid.db.FidFileManager.getInstance().getUserAddedFiles();
            com.google.gson.JsonArray fidDatabases = new com.google.gson.JsonArray();
            if (userFid != null) {
                for (ghidra.feature.fid.db.FidFile fid : userFid) {
                    if (fid != null) {
                        fidDatabases.add(clipped(fid.getBaseName(), 256));
                    }
                }
            }
            if (!fidDatabases.isEmpty()) {
                summary.addProperty("fidApplied", true);
                summary.add("fidDatabases", fidDatabases);
            }
        }
        catch (RuntimeException | LinkageError ignored) {
            // No FID state readable (mocked programs, stripped installs):
            // summary simply carries no provenance, like a no-FID session.
        }
        return summary;
    }

    /**
     * Functions defined in the loaded image, excluding EXTERNAL-space imports.
     * FunctionManager.getFunctionCount includes external functions, which the
     * default ListFunctions range (program min..max) never returns, so reporting
     * the raw total makes the summary disagree with every listing.
     */
    static int countImageFunctions(Program program) {
        int count = 0;
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            boolean external;
            try {
                external = function.isExternal();
            }
            catch (RuntimeException exception) {
                external = false;
            }
            if (!external) {
                count++;
            }
        }
        return count;
    }


    /**
     * Project-vocabulary architecture (x86/x64 by bitness, matching debugger
     * sessions): Ghidra uses the "x86" processor for both 32- and 64-bit code,
     * which disagreed with the live session (x64) for the same binary.
     */
    static String displayArchitecture(Program program) {
        String processor = String.valueOf(program.getLanguage().getProcessor());
        String languageId = String.valueOf(program.getLanguageID());
        if (processor.equalsIgnoreCase("x86")) {
            String id = languageId.toLowerCase(java.util.Locale.ROOT);
            if (id.contains(":64:") || id.endsWith(":64")) {
                return "x64";
            }
            return "x86";
        }
        return processor;
    }

    static String displayExecutablePath(Program program) {
        String configured = System.getenv(DISPLAY_FILE_ENV);
        if (configured != null && !configured.isBlank() &&
            configured.length() <= MAX_DISPLAY_PATH_CHARS &&
            configured.chars().noneMatch(Character::isISOControl)) {
            return configured;
        }
        String executable = program.getExecutablePath();
        return executable == null ? "" : executable;
    }


    static JsonObject functionAnalysis(Function function) {
        return functionAnalysis(function, true);
    }

    static JsonObject functionAnalysis(Function function, boolean includeInstructionCount) {
        JsonObject analysis = new JsonObject();
        String name = function.getName();
        boolean generatedName = isGeneratedName(name);
        analysis.addProperty("nameKind", generatedName ? "generated" : "named");
        analysis.addProperty("hasUsefulName", !generatedName);
        try {
            analysis.addProperty("isThunk", function.isThunk());
        }
        catch (RuntimeException exception) {
            analysis.addProperty("isThunk", false);
        }
        try {
            analysis.addProperty("isExternal", function.isExternal());
        }
        catch (RuntimeException exception) {
            analysis.addProperty("isExternal", false);
        }
        try {
            if (function.getBody() != null) {
                analysis.addProperty("bodyBytes", function.getBody().getNumAddresses());
            }
        }
        catch (RuntimeException exception) {
            // Function metadata should never make an otherwise valid result fail.
        }
        if (includeInstructionCount) {
            try {
                int instructionCount = countInstructions(function.getProgram(), function);
                if (instructionCount >= 0) {
                    analysis.addProperty("instructionCount", instructionCount);
                }
            }
            catch (RuntimeException exception) {
                // Instruction counts are best-effort metadata.
            }
        }
        return analysis;
    }

    /**
     * Listing truth for a function body: how many instructions actually exist,
     * so decompiler output can be cross-checked instead of trusted blindly.
     * Returns -1 when the body or listing cannot be read, or when the
     * MAX_BODY_CODE_UNITS bound is hit (the exact count is unknown then;
     * callers omit the field instead of showing a saturated number).
     */
    static int countInstructions(Program program, Function function) {
        try {
            if (function.getBody() == null) {
                return -1;
            }
            java.util.Iterator<Instruction> instructions =
                program.getListing().getInstructions(function.getBody(), true);
            int count = 0;
            while (instructions.hasNext()) {
                instructions.next();
                if (++count >= MAX_BODY_CODE_UNITS) {
                    return -1;
                }
            }
            return count;
        }
        catch (RuntimeException exception) {
            return -1;
        }
    }


    private static boolean isGeneratedName(String name) {
        if (name == null || name.isBlank()) {
            return true;
        }
        return name.matches("(?:FUN|SUB|LAB|THUNK)_[0-9A-Fa-f]+") ||
            name.startsWith("switch_") || name.startsWith("caseD_");
    }


    private static String fileName(String path) {
        if (path == null || path.isBlank()) {
            return "unknown";
        }
        int separator = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return separator >= 0 && separator + 1 < path.length()
            ? path.substring(separator + 1)
            : path;
    }


    private static String safeText(String value, String fallback, int maxChars) {
        return value == null || value.isBlank() ? fallback : clipped(value, maxChars);
    }


    static JsonArray disassembly(Program program, Function function, int maxItems, GhidraOutputBudget budget) {
        JsonArray result = new JsonArray();
        // Iterate the body rather than adjacent addresses: functions can have disjoint ranges.
        var instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            if (result.size() >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("disassembly");
                break;
            }
            Instruction instruction = instructions.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", instruction.getAddress().toString());
            row.addProperty("text", budget.take(instruction.toString()));
            result.add(row);
        }
        return result;
    }


    /**
     * Sink for distinct call targets; return false to stop the scan when the
     * caller already recorded its own limit (maxItems/budget truncation).
     */
    private interface CallTargetSink {
        boolean accept(Function called);
    }

    /** Terminal state of one body walk: every flag maps to a historical
     * callee property/truncation mark at the call site, so emitted bytes are
     * unchanged. */
    private static final class CalleeScan {
        boolean timedOut;
        boolean limited;
        boolean error;
        boolean scanLimited;
    }

    /**
     * Shared call-target walk over the function body: call-type references
     * only, bounded by MAX_BODY_CODE_UNITS, with a caller-supplied deadline.
     * Non-function targets are skipped; loop-body failures set error instead
     * of throwing, but an unreadable listing (getCodeUnits) and the trailing
     * scan-limit probe propagate exactly like the historical loops. The
     * callGraph edge aggregation keeps its own pair-counting walk.
     */
    private static CalleeScan forEachCallTarget(
        Program program,
        Function function,
        long deadlineNanos,
        CallTargetSink sink
    ) {
        CalleeScan scan = new CalleeScan();
        FunctionManager functionManager = program.getFunctionManager();
        CodeUnitIterator units = program.getListing().getCodeUnits(function.getBody(), true);
        int scanned = 0;
        boolean stopped = false;
        try {
            while (units.hasNext() && scanned++ < MAX_BODY_CODE_UNITS &&
                !scan.timedOut && !stopped) {
                if (System.nanoTime() >= deadlineNanos) {
                    scan.timedOut = true;
                    break;
                }
                CodeUnit unit = units.next();
                for (Reference reference : unit.getReferencesFrom()) {
                    if (System.nanoTime() >= deadlineNanos) {
                        scan.timedOut = true;
                        break;
                    }
                    if (!reference.getReferenceType().isCall()) {
                        continue;
                    }
                    Function called = functionManager.getFunctionAt(reference.getToAddress());
                    if (called != null && !sink.accept(called)) {
                        scan.limited = true;
                        stopped = true;
                        break;
                    }
                }
            }
        }
        catch (RuntimeException exception) {
            scan.error = true;
        }
        if (scanned >= MAX_BODY_CODE_UNITS && units.hasNext()) {
            scan.scanLimited = true;
        }
        return scan;
    }

    /** The same walk without a deadline, for the queue counter. */
    private static CalleeScan forEachCallTarget(Program program, Function function, CallTargetSink sink) {
        return forEachCallTarget(program, function, Long.MAX_VALUE, sink);
    }

    static JsonObject references(Program program, Function function, int maxItems, GhidraOutputBudget budget) {
        JsonObject result = new JsonObject();
        ReferenceManager referenceManager = program.getReferenceManager();
        FunctionManager functionManager = program.getFunctionManager();

        JsonArray callers = new JsonArray();
        JsonArray xrefsTo = new JsonArray();
        ReferenceIterator incoming = referenceManager.getReferencesTo(function.getEntryPoint());
        Set<String> seenCallers = new HashSet<>();
        int incomingCount = 0;
        while (incoming.hasNext() && incomingCount < maxItems && budget.remaining > 0) {
            Reference reference = incoming.next();
            addReference(xrefsTo, reference, budget);
            if (budget.remaining <= 0) {
                budget.markTruncated("references.callers");
                break;
            }
            Function caller = functionManager.getFunctionContaining(reference.getFromAddress());
            if (caller != null && seenCallers.add(caller.getEntryPoint().toString())) {
                addFunctionSummary(callers, caller, budget);
            }
            incomingCount++;
        }
        if (incoming.hasNext()) {
            budget.markTruncated("references.xrefsTo");
            budget.markTruncated("references.callers");
        }
        result.add("callers", callers);
        result.add("xrefsTo", xrefsTo);

        JsonArray callees = new JsonArray();
        Set<String> seenCallees = new HashSet<>();
        int[] calleeCount = new int[1];
        long calleeDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        CalleeScan calleeScan = forEachCallTarget(program, function, calleeDeadline, called -> {
            if (!seenCallees.add(called.getEntryPoint().toString())) {
                return true;
            }
            if (calleeCount[0] >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("references.callees");
                return false;
            }
            addFunctionSummary(callees, called, budget);
            calleeCount[0]++;
            return true;
        });
        if (calleeScan.error) {
            result.addProperty("calleesError", "could not enumerate called functions");
            budget.markTruncated("references.callees");
        }
        if (calleeScan.timedOut) {
            result.addProperty("calleesTimedOut", true);
            budget.markTruncated("references.callees");
        }
        if (calleeScan.scanLimited) {
            result.addProperty("calleesScanLimited", true);
            budget.markTruncated("references.callees");
        }
        result.add("callees", callees);

        JsonArray xrefsFrom = new JsonArray();
        CodeUnitIterator units = program.getListing().getCodeUnits(function.getBody(), true);
        int scannedUnits = 0;
        int outgoingCount = 0;
        boolean outgoingLimited = false;
        while (units.hasNext() && scannedUnits++ < MAX_BODY_CODE_UNITS && !outgoingLimited) {
            CodeUnit unit = units.next();
            for (Reference reference : unit.getReferencesFrom()) {
                if (outgoingCount >= maxItems || budget.remaining <= 0) {
                    budget.markTruncated("references.xrefsFrom");
                    outgoingLimited = true;
                    break;
                }
                outgoingCount++;
                addReference(xrefsFrom, reference, budget);
            }
        }
        result.add("xrefsFrom", xrefsFrom);
        if (scannedUnits >= MAX_BODY_CODE_UNITS && units.hasNext()) {
            result.addProperty("scanLimited", true);
            budget.markTruncated("references.xrefsFrom");
        }
        return result;
    }


    /**
     * Short caller/callee digest for AnalyzeFunctions: function summaries
     * only, no per-reference rows. Mirrors the references() scan bounds and
     * call definition so both views agree on what counts as a caller/callee.
     */
    static JsonObject referencesBrief(Program program, Function function, int maxItems, GhidraOutputBudget budget) {
        JsonObject result = new JsonObject();
        FunctionManager functionManager = program.getFunctionManager();

        JsonArray callers = new JsonArray();
        Set<String> seenCallers = new HashSet<>();
        ReferenceIterator incoming = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
        int incomingCount = 0;
        while (incoming.hasNext() && incomingCount++ < MAX_BODY_CODE_UNITS) {
            if (callers.size() >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("references.callers");
                break;
            }
            Reference reference = incoming.next();
            Function caller = functionManager.getFunctionContaining(reference.getFromAddress());
            if (caller != null && seenCallers.add(caller.getEntryPoint().toString())) {
                addFunctionSummary(callers, caller, budget);
            }
        }
        if (incoming.hasNext()) {
            budget.markTruncated("references.callers");
        }
        result.add("callers", callers);

        JsonArray callees = new JsonArray();
        Set<String> seenCallees = new HashSet<>();
        int[] calleeCount = new int[1];
        long calleeDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        CalleeScan calleeScan = forEachCallTarget(program, function, calleeDeadline, called -> {
            if (!seenCallees.add(called.getEntryPoint().toString())) {
                return true;
            }
            if (calleeCount[0] >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("references.callees");
                return false;
            }
            addFunctionSummary(callees, called, budget);
            calleeCount[0]++;
            return true;
        });
        if (calleeScan.error) {
            result.addProperty("calleesError", "could not enumerate called functions");
            budget.markTruncated("references.callees");
        }
        if (calleeScan.timedOut || calleeScan.limited) {
            budget.markTruncated("references.callees");
        }
        if (calleeScan.scanLimited) {
            result.addProperty("calleesScanLimited", true);
            budget.markTruncated("references.callees");
        }
        result.add("callees", callees);
        return result;
    }


    /**
     * Strings referenced by the function body's data references:
     * {address, value} per referenced NUL-terminated string; the length is
     * derivable from value and stays omitted (token policy). Reads are
     * bounded and nullable: unmapped targets, non-printable bytes and read
     * failures are skipped instead of failing the card. The decoder is shared
     * with DumpStrings so the two views never drift.
     */
    static JsonArray functionStrings(Program program, Function function, int maxItems, GhidraOutputBudget budget) {
        JsonArray result = new JsonArray();
        Set<String> seen = new HashSet<>();
        CodeUnitIterator units = program.getListing().getCodeUnits(function.getBody(), true);
        int scanned = 0;
        boolean limited = false;
        try {
            while (units.hasNext() && scanned++ < MAX_BODY_CODE_UNITS && !limited) {
                CodeUnit unit = units.next();
                for (Reference reference : unit.getReferencesFrom()) {
                    if (!reference.getReferenceType().isData()) {
                        continue;
                    }
                    Address to = reference.getToAddress();
                    if (to == null || !seen.add(to.toString())) {
                        continue;
                    }
                    if (result.size() >= maxItems || budget.remaining <= 0) {
                        budget.markTruncated("strings");
                        limited = true;
                        break;
                    }
                    JsonObject row = referencedString(program, to, budget);
                    if (row != null) {
                        result.add(row);
                    }
                }
            }
            if (units.hasNext()) {
                budget.markTruncated("strings");
            }
        }
        catch (RuntimeException exception) {
            budget.markTruncated("strings");
        }
        return result;
    }


    private static JsonObject referencedString(Program program, Address address, GhidraOutputBudget budget) {
        MemoryBlock block = program.getMemory().getBlock(address);
        if (block == null || !block.isInitialized()) {
            return null;
        }
        long offset;
        try {
            offset = address.subtract(block.getStart());
        }
        catch (RuntimeException exception) {
            return null;
        }
        if (offset < 0 || offset >= block.getSize()) {
            return null;
        }
        int available = (int)Math.min(MAX_FUNCTION_STRING_BYTES, block.getSize() - offset);
        if (available < 1) {
            return null;
        }
        byte[] data = new byte[available];
        try {
            if (block.getBytes(address, data) != available) {
                return null;
            }
        }
        catch (MemoryAccessException | RuntimeException exception) {
            return null;
        }
        GhidraStaticQueries.DecodedString decoded = GhidraStaticQueries.decodeStringAt(data, 0, available);
        if (decoded == null) {
            return null;
        }
        String emitted = budget.take(clipped(decoded.text, MAX_FUNCTION_STRING_CHARS));
        JsonObject row = new JsonObject();
        row.addProperty("address", address.toString());
        row.addProperty("value", emitted);
        return row;
    }


    /**
     * Significant scalar operands in the function body: {value, count,
     * firstAddress} sorted by descending count. Trivial values (0, 1, all
     * ones) are dropped because nearly every function carries them.
     */
    static JsonArray functionConstants(Program program, Function function, int maxItems, GhidraOutputBudget budget) {
        Map<Long, JsonObject> stats = new HashMap<>();
        int scanned = 0;
        try {
            var instructions = program.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext() && scanned++ < MAX_BODY_CODE_UNITS) {
                Instruction instruction = instructions.next();
                int operands = instruction.getNumOperands();
                for (int index = 0; index < operands; index++) {
                    Scalar scalar = instruction.getScalar(index);
                    if (scalar == null) {
                        continue;
                    }
                    long value = scalar.getUnsignedValue();
                    if (isTrivialConstant(value, scalar.bitLength())) {
                        continue;
                    }
                    JsonObject stat = stats.get(value);
                    if (stat == null) {
                        stat = new JsonObject();
                        stat.addProperty("value", "0x" + Long.toUnsignedString(value, 16));
                        stat.addProperty("count", 0);
                        stat.addProperty("firstAddress", instruction.getAddress().toString());
                        stats.put(value, stat);
                    }
                    stat.addProperty("count", stat.get("count").getAsInt() + 1);
                }
            }
            if (instructions.hasNext()) {
                budget.markTruncated("constants");
            }
        }
        catch (RuntimeException exception) {
            budget.markTruncated("constants");
        }

        List<Map.Entry<Long, JsonObject>> sorted = new ArrayList<>(stats.entrySet());
        sorted.sort(Comparator
            .<Map.Entry<Long, JsonObject>>comparingInt(entry -> entry.getValue().get("count").getAsInt())
            .reversed()
            .thenComparingLong(entry -> entry.getKey()));
        JsonArray result = new JsonArray();
        for (Map.Entry<Long, JsonObject> entry : sorted) {
            if (result.size() >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("constants");
                break;
            }
            result.add(entry.getValue());
        }
        return result;
    }


    private static boolean isTrivialConstant(long value, int bitLength) {
        if (value == 0 || value == 1) {
            return true;
        }
        if (bitLength > 0 && bitLength < 64) {
            return value == (1L << bitLength) - 1;
        }
        return value == -1L;
    }


    static JsonObject symbolsAndTypes(Function function, int maxItems, GhidraOutputBudget budget) {
        JsonObject result = new JsonObject();
        JsonArray symbols = new JsonArray();
        JsonArray types = new JsonArray();
        Set<String> seenSymbols = new HashSet<>();
        Set<String> seenTypes = new HashSet<>();

        for (Symbol symbol : function.getProgram().getSymbolTable().getSymbols(function.getEntryPoint())) {
            if (symbols.size() >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("symbols");
                break;
            }
            addSymbol(symbols, symbol, budget, seenSymbols);
        }

        addType(types, function.getReturnType(), budget, seenTypes);
        Variable[] variables = function.getAllVariables();
        int variableCount = 0;
        for (Variable variable : variables) {
            if (variableCount++ >= maxItems || types.size() >= maxItems || budget.remaining <= 0) {
                budget.markTruncated("symbols");
                budget.markTruncated("types");
                break;
            }
            if (symbols.size() < maxItems && variable.getSymbol() != null) {
                addSymbol(symbols, variable.getSymbol(), budget, seenSymbols);
            } else if (variable.getSymbol() != null) {
                budget.markTruncated("symbols");
            }
            addType(types, variable.getDataType(), budget, seenTypes);
        }

        result.add("symbols", symbols);
        result.add("types", types);
        return result;
    }


    /**
     * Slim per-entry function ref: the row already carries addresses, so only
     * the owner name/entry travel. A null budget means the caller pages
     * without an output budget (static queries) and the name travels
     * uncharged; otherwise the name is charged like every other emitted
     * string.
     */
    static JsonObject slimFunction(Function function, GhidraOutputBudget budget) {
        JsonObject summary = new JsonObject();
        String name = clipped(function.getName(), 512);
        summary.addProperty("name", budget == null ? name : budget.take(name));
        summary.addProperty("entry", function.getEntryPoint().toString());
        return summary;
    }

    static void addFunctionSummary(JsonArray target, Function function, GhidraOutputBudget budget) {
        if (budget.remaining <= 0) {
            return;
        }
        target.add(slimFunction(function, budget));
    }


    static void addReference(JsonArray target, Reference reference, GhidraOutputBudget budget) {
        if (budget.remaining <= 0) {
            return;
        }
        JsonObject row = new JsonObject();
        row.addProperty("from", reference.getFromAddress().toString());
        row.addProperty("to", reference.getToAddress().toString());
        row.addProperty("type", budget.take(String.valueOf(reference.getReferenceType())));
        if (reference.getOperandIndex() != 0) row.addProperty("operandIndex", reference.getOperandIndex());
        target.add(row);
    }


    static void addSymbol(
        JsonArray target,
        Symbol symbol,
        GhidraOutputBudget budget,
        Set<String> seen
    ) {
        if (budget.remaining <= 0) {
            return;
        }
        String key = symbol.getAddress() + "\u0000" + symbol.getName();
        if (!seen.add(key)) {
            return;
        }
        JsonObject row = new JsonObject();
        row.addProperty("name", budget.take(clipped(symbol.getName(), 512)));
        row.addProperty("address", symbol.getAddress().toString());
        row.addProperty("kind", budget.take(String.valueOf(symbol.getSymbolType())));
        target.add(row);
    }


    static void addType(
        JsonArray target,
        ghidra.program.model.data.DataType dataType,
        GhidraOutputBudget budget,
        Set<String> seen
    ) {
        if (dataType == null) {
            return;
        }
        if (budget.remaining <= 0) {
            return;
        }
        String typeName = dataType.getDisplayName();
        if (!seen.add(typeName) || target.size() >= MAX_ITEMS) {
            return;
        }
        JsonObject row = new JsonObject();
        row.addProperty("name", budget.take(clipped(typeName, 512)));
        row.addProperty("path", budget.take(clipped(dataType.getPathName(), 1024)));
        row.addProperty("length", dataType.getLength());
        target.add(row);
    }


    /**
     * One bottom-up worklist row: identity plus body size, name quality and
     * the distinct callee count the leaves-first order sorts by. The rva is
     * opt-in (derivable from entry plus the image base).
     */
    static JsonObject analysisQueueRow(Program program, Function function, int calleeCount, boolean includeRva) {
        JsonObject row = functionHead(program, function, includeRva ? HEAD_RVA : 0, null);
        int instructionCount = countInstructions(program, function);
        if (instructionCount >= 0) {
            row.addProperty("instructionCount", instructionCount);
        }
        row.addProperty("named", functionAnalysis(function).get("hasUsefulName").getAsBoolean());
        row.addProperty("calleeCount", calleeCount);
        return row;
    }

    /**
     * Distinct functions called from the body: the leaves-first key. Mirrors
     * the referencesBrief callee scan (call refs only, same body bound) so the
     * queue agrees with the digest view on what counts as a callee.
     */
    static int countDistinctCallees(Program program, Function function) {
        return countDistinctCallees(program, function, Long.MAX_VALUE);
    }

    /**
     * SEC-C J2: deadline-aware overload for the analysis-queue scan. The
     * unbounded historical walk is preserved when the deadline is
     * {@link Long#MAX_VALUE}; the queue passes its per-request deadline so a
     * single huge body cannot stall the worklist past its budget. A timed-out
     * scan returns the distinct callees observed so far.
     */
    static int countDistinctCallees(Program program, Function function, long deadlineNanos) {
        try {
            if (function.getBody() == null) {
                return 0;
            }
            Set<String> seen = new HashSet<>();
            forEachCallTarget(program, function, deadlineNanos, called -> {
                seen.add(called.getEntryPoint().toString());
                return true;
            });
            return seen.size();
        }
        catch (RuntimeException exception) {
            return 0;
        }
    }

    /**
     * Leaves-first worklist order: fewest callees first, then smallest body,
     * then name for a deterministic tie-break.
     */
    static void sortQueueLeavesFirst(List<JsonObject> rows) {
        rows.sort(Comparator
            .comparingInt((JsonObject row) -> row.has("calleeCount") ? row.get("calleeCount").getAsInt() : 0)
            .thenComparingInt(row -> row.has("instructionCount") ? row.get("instructionCount").getAsInt() : Integer.MAX_VALUE)
            .thenComparing(row -> row.has("name") ? row.get("name").getAsString() : ""));
    }
    static JsonObject callGraphNode(Program program, Function function, boolean includeInstructionCount) {
        JsonObject node = functionHead(program, function, HEAD_RVA, null);
        if (includeInstructionCount) {
            int instructionCount = countInstructions(program, function);
            if (instructionCount >= 0) {
                node.addProperty("instructionCount", instructionCount);
            }
        }
        return node;
    }


    private static boolean inCallGraphRange(Function function, Address start, Address end) {
        try {
            Address entry = function.getEntryPoint();
            if (entry == null || !entry.hasSameAddressSpace(start)) {
                return false;
            }
            return entry.compareTo(start) >= 0 && entry.compareTo(end) <= 0;
        }
        catch (RuntimeException exception) {
            return false;
        }
    }


    private static boolean isCallGraphCancelled() {
        TaskMonitor monitor = requestMonitor.get();
        return monitor != null && monitor.isCancelled();
    }


    /**
     * Internal call graph over the address-ordered functions whose entry lies
     * in [start, end]: nodes carry identity plus opt-in listing instruction
     * counts, edges aggregate caller-to-callee call sites with per-pair
     * counts. Calls to functions outside the node set are not emitted, so the
     * graph stays closed and bounded; nodes past maxNodes and edges past
     * maxEdges truncate with a nextStart continuation cursor instead of
     * failing. Edges default to integer node indices {s, t, n};
     * edgeFormat=full emits the legacy {caller, callee, count} entry strings.
     */
    static JsonObject callGraph(Program program, Address start, Address end, int maxNodes, int maxEdges,
        boolean includeInstructionCount) {
        return callGraph(program, start, end, maxNodes, maxEdges, includeInstructionCount, "indexed");
    }

    static JsonObject callGraph(Program program, Address start, Address end, int maxNodes, int maxEdges,
        boolean includeInstructionCount, String edgeFormat) {
        JsonArray nodes = new JsonArray();
        Map<String, Integer> indexByEntry = new HashMap<>();
        List<Function> ordered = new ArrayList<>();
        FunctionManager manager = program.getFunctionManager();
        Iterator<Function> functions = manager.getFunctions(true);
        Function nextFunction = null;
        // The deadline covers node collection too: callGraphNode scans the
        // body, so an aborted request must not keep scanning to maxNodes.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        boolean timedOut = false;
        while (functions.hasNext()) {
            if (System.nanoTime() >= deadline || isCallGraphCancelled()) {
                timedOut = true;
                if (functions.hasNext()) {
                    nextFunction = functions.next();
                }
                break;
            }
            Function function = functions.next();
            if (!inCallGraphRange(function, start, end)) {
                continue;
            }
            if (ordered.size() >= maxNodes) {
                nextFunction = function;
                break;
            }
            indexByEntry.put(function.getEntryPoint().toString(), ordered.size());
            ordered.add(function);
            nodes.add(callGraphNode(program, function, includeInstructionCount));
        }

        Map<String, int[]> edgeCounts = new LinkedHashMap<>();
        boolean scanLimited = false;
        int totalCalls = 0;
        for (Function caller : ordered) {
            if (System.nanoTime() >= deadline || isCallGraphCancelled()) {
                timedOut = true;
                break;
            }
            Address callerEntry;
            try {
                callerEntry = caller.getEntryPoint();
            }
            catch (RuntimeException exception) {
                scanLimited = true;
                continue;
            }
            AddressSetView body;
            try {
                body = caller.getBody();
            }
            catch (RuntimeException exception) {
                scanLimited = true;
                continue;
            }
            if (body == null) {
                continue;
            }
            CodeUnitIterator units;
            try {
                units = program.getListing().getCodeUnits(body, true);
            }
            catch (RuntimeException exception) {
                scanLimited = true;
                continue;
            }
            int scannedUnits = 0;
            try {
                while (units.hasNext()) {
                    if (System.nanoTime() >= deadline || isCallGraphCancelled()) {
                        timedOut = true;
                        break;
                    }
                    if (scannedUnits++ >= MAX_BODY_CODE_UNITS) {
                        scanLimited = true;
                        break;
                    }
                    CodeUnit unit = units.next();
                    Reference[] outgoing;
                    try {
                        outgoing = unit.getReferencesFrom();
                    }
                    catch (RuntimeException exception) {
                        scanLimited = true;
                        break;
                    }
                    for (Reference reference : outgoing) {
                        if (!reference.getReferenceType().isCall()) {
                            continue;
                        }
                        Function callee;
                        try {
                            callee = manager.getFunctionAt(reference.getToAddress());
                        }
                        catch (RuntimeException exception) {
                            continue;
                        }
                        if (callee == null) {
                            continue;
                        }
                        String calleeEntry;
                        try {
                            calleeEntry = callee.getEntryPoint().toString();
                        }
                        catch (RuntimeException exception) {
                            continue;
                        }
                        if (!indexByEntry.containsKey(calleeEntry)) {
                            continue;
                        }
                        String key = callerEntry + "\0" + calleeEntry;
                        int[] slot = edgeCounts.get(key);
                        if (slot == null) {
                            slot = new int[] {
                                indexByEntry.get(callerEntry.toString()),
                                indexByEntry.get(calleeEntry),
                                0
                            };
                            edgeCounts.put(key, slot);
                        }
                        slot[2]++;
                        totalCalls++;
                    }
                }
            }
            catch (RuntimeException exception) {
                scanLimited = true;
            }
            if (timedOut) {
                break;
            }
        }

        JsonArray edges = new JsonArray();
        boolean fullEdges = "full".equals(edgeFormat);
        for (Map.Entry<String, int[]> entry : edgeCounts.entrySet()) {
            if (edges.size() >= maxEdges) {
                break;
            }
            int[] slot = entry.getValue();
            JsonObject edge = new JsonObject();
            if (fullEdges) {
                int split = entry.getKey().indexOf('\0');
                edge.addProperty("caller", entry.getKey().substring(0, split));
                edge.addProperty("callee", entry.getKey().substring(split + 1));
                edge.addProperty("count", slot[2]);
            }
            else {
                edge.addProperty("s", slot[0]);
                edge.addProperty("t", slot[1]);
                edge.addProperty("n", slot[2]);
            }
            edges.add(edge);
        }
        boolean edgeLimitReached = edgeCounts.size() > edges.size();
        boolean truncated = nextFunction != null || edgeLimitReached || timedOut;

        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("totalCalls", totalCalls);
        result.addProperty("timedOut", timedOut);
        if (scanLimited) {
            result.addProperty("scanLimited", true);
        }
        result.addProperty("truncated", truncated);
        if (nextFunction != null) {
            result.addProperty("nextStart", nextFunction.getEntryPoint().toString());
        }
        else if (truncated) {
            result.addProperty("continuation",
                "Repeat with higher maxEdges or a narrower start/end range.");
        }
        return result;
    }


    private static final String[] NEIGHBOR_RISK_TOKENS = {
        "crypt", "cipher", "decrypt", "encrypt", "pack", "unpack", "inject", "hook",
        "shell", "exec", "connect", "download", "upload", "persist", "antidebug",
        "vmdetect", "auth", "password", "token", "license", "config", "command", "dispatch"
    };

    /**
     * BFS neighborhood around one seed: expand through the requested edges
     * (callers, callees or both), cap the induced node/edge set, and rank the
     * discovered nodes so the caller gets a next-best list without touching
     * the decompiler. Discovery never scans the whole address space; each
     * expanded body is bounded by MAX_BODY_CODE_UNITS and the shared
     * MAX_DECOMP_SECONDS deadline.
     */
    static JsonObject callGraphNeighborhood(Program program, Function seed, int depth, String direction,
        int maxNodes, int maxEdges, boolean includeInstructionCount, String edgeFormat) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        boolean wantCallers = !"callees".equals(direction);
        boolean wantCallees = !"callers".equals(direction);

        List<Function> ordered = new ArrayList<>();
        Map<String, Integer> indexByEntry = new LinkedHashMap<>();
        Map<String, Integer> depthByEntry = new LinkedHashMap<>();
        Map<String, NeighborCallees> calleeCache = new HashMap<>();
        List<FrontierEntry> frontier = new ArrayList<>();
        Set<String> frontierSeen = new HashSet<>();
        JsonArray nodes = new JsonArray();
        boolean nodeLimited = false;
        boolean timedOut = false;
        boolean scanLimited = false;

        String seedEntry;
        try {
            seedEntry = seed.getEntryPoint().toString();
        }
        catch (RuntimeException exception) {
            throw new IllegalArgumentException("seed function has no readable entry point", exception);
        }
        ordered.add(seed);
        indexByEntry.put(seedEntry, 0);
        depthByEntry.put(seedEntry, 0);
        nodes.add(callGraphNode(program, seed, includeInstructionCount));

        List<Function> layer = new ArrayList<>();
        layer.add(seed);
        for (int d = 1; d <= depth && !layer.isEmpty() && !nodeLimited; d++) {
            List<Function> next = new ArrayList<>();
            Set<String> nextSeen = new HashSet<>();
            for (Function current : layer) {
                if (timedOut || System.nanoTime() >= deadline) {
                    timedOut = true;
                    break;
                }
                String currentEntry;
                try {
                    currentEntry = current.getEntryPoint().toString();
                }
                catch (RuntimeException exception) {
                    scanLimited = true;
                    continue;
                }

                if (wantCallees) {
                    NeighborCallees summary = neighborCallees(program, current, deadline, calleeCache);
                    timedOut |= summary.timedOut;
                    scanLimited |= summary.scanLimited;
                    for (Map.Entry<String, Function> target : summary.functions.entrySet()) {
                        if (ordered.size() >= maxNodes) {
                            nodeLimited = true;
                            addFrontier(frontier, frontierSeen, target.getValue(), d);
                            break;
                        }
                        addNeighbor(target.getKey(), target.getValue(), d, ordered, indexByEntry,
                            depthByEntry, nodes, next, nextSeen, program, includeInstructionCount);
                    }
                    if (nodeLimited) {
                        break;
                    }
                }

                if (wantCallers) {
                    ReferenceIterator incoming;
                    try {
                        incoming = program.getReferenceManager().getReferencesTo(current.getEntryPoint());
                    }
                    catch (RuntimeException exception) {
                        scanLimited = true;
                        incoming = null;
                    }
                    int scanned = 0;
                    while (incoming != null && incoming.hasNext() && scanned++ < MAX_BODY_CODE_UNITS) {
                        if (System.nanoTime() >= deadline) {
                            timedOut = true;
                            break;
                        }
                        Reference reference;
                        try {
                            reference = incoming.next();
                        }
                        catch (RuntimeException exception) {
                            scanLimited = true;
                            break;
                        }
                        if (!reference.getReferenceType().isCall()) {
                            continue;
                        }
                        Function caller;
                        try {
                            caller = program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                            if (caller == null) {
                                caller = program.getFunctionManager().getFunctionAt(reference.getFromAddress());
                            }
                        }
                        catch (RuntimeException exception) {
                            scanLimited = true;
                            continue;
                        }
                        if (caller == null) {
                            continue;
                        }
                        String callerEntry;
                        try {
                            callerEntry = caller.getEntryPoint().toString();
                        }
                        catch (RuntimeException exception) {
                            scanLimited = true;
                            continue;
                        }
                        if (callerEntry.equals(currentEntry)) {
                            continue;
                        }
                        if (ordered.size() >= maxNodes) {
                            nodeLimited = true;
                            addFrontier(frontier, frontierSeen, caller, d);
                            break;
                        }
                        addNeighbor(callerEntry, caller, d, ordered, indexByEntry,
                            depthByEntry, nodes, next, nextSeen, program, includeInstructionCount);
                    }
                    if (nodeLimited) {
                        break;
                    }
                }
            }
            if (timedOut) {
                break;
            }
            layer = next;
        }

        // Build the induced edge set once. Scanning every included node's
        // outgoing calls (instead of mixing outgoing and incoming walks)
        // keeps counts exact when direction=both and avoids double counting.
        Map<String, int[]> edgeCounts = new LinkedHashMap<>();
        int totalCalls = 0;
        boolean edgeLimited = false;
        for (int i = 0; i < ordered.size(); i++) {
            if (timedOut || System.nanoTime() >= deadline) {
                timedOut = true;
                break;
            }
            Function caller = ordered.get(i);
            String callerEntry;
            try {
                callerEntry = caller.getEntryPoint().toString();
            }
            catch (RuntimeException exception) {
                scanLimited = true;
                continue;
            }
            NeighborCallees summary = neighborCallees(program, caller, deadline, calleeCache);
            timedOut |= summary.timedOut;
            scanLimited |= summary.scanLimited;
            for (Map.Entry<String, Integer> target : summary.counts.entrySet()) {
                Integer targetIndex = indexByEntry.get(target.getKey());
                if (targetIndex == null) {
                    continue;
                }
                totalCalls += target.getValue();
                String key = callerEntry + "\0" + target.getKey();
                int[] slot = edgeCounts.get(key);
                if (slot == null) {
                    if (edgeCounts.size() >= maxEdges) {
                        edgeLimited = true;
                        continue;
                    }
                    slot = new int[] { i, targetIndex, 0 };
                    edgeCounts.put(key, slot);
                }
                slot[2] += target.getValue();
            }
        }

        JsonArray edges = new JsonArray();
        boolean fullEdges = "full".equals(edgeFormat);
        for (Map.Entry<String, int[]> entry : edgeCounts.entrySet()) {
            int[] slot = entry.getValue();
            JsonObject edge = new JsonObject();
            if (fullEdges) {
                int split = entry.getKey().indexOf('\0');
                edge.addProperty("caller", entry.getKey().substring(0, split));
                edge.addProperty("callee", entry.getKey().substring(split + 1));
                edge.addProperty("count", slot[2]);
            }
            else {
                edge.addProperty("s", slot[0]);
                edge.addProperty("t", slot[1]);
                edge.addProperty("n", slot[2]);
            }
            edges.add(edge);
        }

        boolean truncated = nodeLimited || edgeLimited || timedOut;
        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("totalCalls", totalCalls);
        result.addProperty("truncated", truncated);
        result.add("nextBest", neighborNextBest(program, ordered, depthByEntry, edgeCounts));
        if (nodeLimited) {
            JsonArray frontierRows = new JsonArray();
            for (FrontierEntry entry : frontier) {
                JsonObject row = functionHead(program, entry.function, HEAD_RVA, null);
                row.addProperty("depth", entry.depth);
                frontierRows.add(row);
            }
            result.add("frontier", frontierRows);
            if (frontier.size() >= 8) {
                result.addProperty("frontierTruncated", true);
            }
        }
        if (timedOut) {
            result.addProperty("timedOut", true);
        }
        if (scanLimited) {
            result.addProperty("scanLimited", true);
        }
        if (truncated) {
            result.addProperty("continuation", nodeLimited
                ? "Repeat with higher maxNodes or use one frontier entry as the next seed."
                : edgeLimited
                    ? "Repeat with higher maxEdges or depth=1."
                    : "Narrow direction/depth or retry.");
        }
        return result;
    }

    private static void addNeighbor(String entry, Function function, int depth,
        List<Function> ordered, Map<String, Integer> indexByEntry,
        Map<String, Integer> depthByEntry, JsonArray nodes, List<Function> next,
        Set<String> nextSeen, Program program, boolean includeInstructionCount) {
        Integer existing = indexByEntry.get(entry);
        if (existing != null) {
            if (depthByEntry.get(entry) == depth && nextSeen.add(entry)) {
                next.add(function);
            }
            return;
        }
        int index = ordered.size();
        indexByEntry.put(entry, index);
        depthByEntry.put(entry, depth);
        ordered.add(function);
        nodes.add(callGraphNode(program, function, includeInstructionCount));
        if (nextSeen.add(entry)) {
            next.add(function);
        }
    }

    private static void addFrontier(List<FrontierEntry> frontier, Set<String> seen, Function function, int depth) {
        try {
            String entry = function.getEntryPoint().toString();
            if (seen.add(entry) && frontier.size() < 8) {
                frontier.add(new FrontierEntry(function, depth));
            }
        }
        catch (RuntimeException ignored) {
            // A candidate we cannot name is not useful as a continuation seed.
        }
    }

    private static NeighborCallees neighborCallees(Program program, Function function,
        long deadline, Map<String, NeighborCallees> cache) {
        String key;
        try {
            key = function.getEntryPoint().toString();
        }
        catch (RuntimeException exception) {
            key = "?";
        }
        NeighborCallees cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        NeighborCallees summary = new NeighborCallees();
        CalleeScan scan = forEachCallTarget(program, function, deadline, called -> {
            String entry;
            try {
                entry = called.getEntryPoint().toString();
            }
            catch (RuntimeException exception) {
                return true;
            }
            summary.functions.putIfAbsent(entry, called);
            summary.counts.merge(entry, 1, Integer::sum);
            return true;
        });
        summary.timedOut = scan.timedOut;
        summary.scanLimited = scan.scanLimited || scan.error || scan.limited;
        cache.put(key, summary);
        return summary;
    }

    private static JsonArray neighborNextBest(Program program, List<Function> ordered,
        Map<String, Integer> depthByEntry, Map<String, int[]> edgeCounts) {
        Map<String, Integer> degree = new HashMap<>();
        for (int[] slot : edgeCounts.values()) {
            String source = entryAt(ordered, slot[0]);
            String target = entryAt(ordered, slot[1]);
            degree.merge(source, slot[2], Integer::sum);
            degree.merge(target, slot[2], Integer::sum);
        }

        List<JsonObject> rows = new ArrayList<>();
        for (int i = 1; i < ordered.size(); i++) {
            Function function = ordered.get(i);
            String entry;
            String name;
            try {
                entry = function.getEntryPoint().toString();
                name = function.getName();
            }
            catch (RuntimeException exception) {
                continue;
            }
            int depth = depthByEntry.getOrDefault(entry, 1);
            List<String> reasons = new ArrayList<>();
            int score = -15 * depth;
            if (isSensitiveNeighborName(name)) {
                score += 40;
                reasons.add("sensitive-name");
            }
            if (isGeneratedName(name)) {
                score += 10;
                reasons.add("unnamed");
            }
            int degreeValue = degree.getOrDefault(entry, 0);
            score += Math.min(30, degreeValue * 2);
            if (degreeValue > 0) {
                reasons.add("degree=" + degreeValue);
            }
            if (depth == 1) {
                reasons.add("depth=1");
            }
            JsonObject row = functionHead(program, function, HEAD_RVA, null);
            row.addProperty("depth", depth);
            row.addProperty("risk", score);
            row.addProperty("why", reasons.isEmpty() ? "neighbor" : String.join(",", reasons));
            rows.add(row);
        }
        rows.sort(Comparator
            .comparingInt((JsonObject row) -> -row.get("risk").getAsInt())
            .thenComparingInt(row -> row.get("depth").getAsInt())
            .thenComparing(row -> row.get("entry").getAsString()));
        JsonArray result = new JsonArray();
        for (int i = 0; i < rows.size() && i < 5; i++) {
            result.add(rows.get(i));
        }
        return result;
    }

    private static String entryAt(List<Function> functions, int index) {
        try {
            return functions.get(index).getEntryPoint().toString();
        }
        catch (RuntimeException exception) {
            return "";
        }
    }

    private static boolean isSensitiveNeighborName(String name) {
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        for (String token : NEIGHBOR_RISK_TOKENS) {
            if (lower.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static final class NeighborCallees {
        final Map<String, Function> functions = new LinkedHashMap<>();
        final Map<String, Integer> counts = new LinkedHashMap<>();
        boolean timedOut;
        boolean scanLimited;
    }

    private static final class FrontierEntry {
        final Function function;
        final int depth;

        FrontierEntry(Function function, int depth) {
            this.function = function;
            this.depth = depth;
        }
    }


}
