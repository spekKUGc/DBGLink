package dbglink.ghidra;

import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

import static dbglink.ghidra.GhidraBridgeServer.*;

final class GhidraDecompiler {
    /**
     * One decompile process per calling thread.
     *
     * <p>A {@link DecompInterface} owns a single decompile process whose
     * {@code decompileFunction} is {@code synchronized}, so one shared instance
     * serialises every decompile — which is exactly what the bridge used to do.
     * Ghidra's own {@code ParallelDecompiler} parallelises the opposite way: it
     * hands each worker thread its own {@link DecompInterface} for the same
     * program. That is the pattern used here.</p>
     *
     * <p>The connection executor is a fixed pool ({@code MAX_CONNECTION_WORKERS}
     * threads) and queued connections are rejected rather than waiting, so at
     * most that many decompile processes ever exist.</p>
     *
     * <p>Safety comes from the bridge read/write lock, not from this class:
     * every reader holds the read lock, and every mutation holds the write lock
     * and calls {@link #close()}. The two are mutually exclusive, so a
     * decompiler process is never disposed while a reader could still be using
     * it. That is also why a cancelled read must discard only its own entry
     * ({@link #discardCurrent()}) instead of everybody's.</p>
     */
    private static final class Entry {
        private DecompInterface decompiler;
        private Program decompilerProgram;
    }

    // Registry of every live entry, needed because close() must reach the
    // thread-locals of all connection workers. Only close() mutates entries;
    // readers only add their own, and add/remove on a concurrent set is safe.
    private final Set<Entry> live = ConcurrentHashMap.newKeySet();
    private final ThreadLocal<Entry> current = ThreadLocal.withInitial(Entry::new);

    JsonObject decompile(Program program, Function function, GhidraOutputBudget budget) throws BridgeFailure {
        return decompile(program, function, budget, MAX_DECOMP_SECONDS);
    }

    JsonObject decompile(
        Program program,
        Function function,
        GhidraOutputBudget budget,
        int timeoutSeconds
    ) throws BridgeFailure {
        TaskMonitor parent = requestMonitor.get();
        if (parent != null && parent.isCancelled())
            throw new BridgeFailure("ghidra_timeout", "Request cancelled");
        Entry entry = decompilerFor(program);
        TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(
            timeoutSeconds,
            TimeUnit.SECONDS,
            parent == null ? TaskMonitor.DUMMY : parent
        );
        JsonObject result = new JsonObject();
        try {
            DecompileResults decompileResults = entry.decompiler.decompileFunction(function, timeoutSeconds, monitor);
            if (decompileResults == null || !decompileResults.decompileCompleted()) {
                result.addProperty("status", monitor.didTimeout() ? "timeout" : "failed");
                result.addProperty("error", clipped(
                    decompileResults == null ? "no decompile result" : decompileResults.getErrorMessage(),
                    512
                ));
                return result;
            }

            if (decompileResults.getDecompiledFunction() == null) {
                result.addProperty("status", "failed");
                result.addProperty("error", "decompiler returned no C output");
                return result;
            }

            result.addProperty("status", "ok");
            result.addProperty("signature", budget.take(decompileResults.getDecompiledFunction().getSignature()));
            result.addProperty("code", budget.take(decompileResults.getDecompiledFunction().getC()));
            return result;
        }
        catch (RuntimeException exception) {
            result.addProperty("status", "failed");
            result.addProperty("error", "decompiler operation failed");
            return result;
        }
        finally {
            monitor.finished();
            // The cancelled decompile process is this thread's only; yanking a
            // process another reader is using would fail that reader's call.
            if (monitor.isCancelled())
                discardCurrent();
        }
    }

    /**
     * Rename a variable that only exists in the decompiler local symbols, for
     * example a stack local Ghidra has not materialized in the database yet.
     * Does not open or commit a transaction; callers own that so BatchAnnotate
     * can share a single undo step. Returns the applied variable identity.
     */
    JsonObject renameDecompilerVariable(Program program, Function function, String selector, String name)
        throws BridgeFailure {
        GhidraStaticQueries.checkCancelled();
        Entry entry = decompilerFor(program);
        TaskMonitor parent = requestMonitor.get();
        TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(MAX_DECOMP_SECONDS, TimeUnit.SECONDS,
            parent == null ? TaskMonitor.DUMMY : parent);
        try {
            DecompileResults decoded = entry.decompiler.decompileFunction(function, MAX_DECOMP_SECONDS, monitor);
            if (monitor.isCancelled()) throw new BridgeFailure("ghidra_timeout", "Variable lookup cancelled");
            if (decoded == null || !decoded.decompileCompleted() || decoded.getHighFunction() == null)
                throw new BridgeFailure("decompiler_unavailable", "Cannot resolve decompiler variables for this function");
            HighSymbol selected = null;
            var symbols = decoded.getHighFunction().getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (selector.equals(symbol.getName())) {
                    if (selected != null) throw new BridgeFailure("ambiguous_variable", "More than one decompiler variable has this name");
                    selected = symbol;
                } else if (name.equals(symbol.getName())) {
                    throw new BridgeFailure("mutation_conflict", "Another decompiler variable already uses the requested name");
                }
            }
            if (selected == null) throw new BridgeFailure("variable_not_found", "Variable was not found in the database or decompiler local symbols");
            GhidraStaticQueries.checkCancelled();
            try {
                HighFunctionDBUtil.updateDBVariable(selected, name, null, SourceType.USER_DEFINED);
            } catch (DuplicateNameException | InvalidInputException exception) {
                throw new BridgeFailure("mutation_conflict", "Decompiler variable name could not be saved to the program");
            }
            JsonObject variable = new JsonObject();
            variable.addProperty("name", name);
            variable.addProperty("storage", clipped(String.valueOf(selected.getStorage()), 512));
            return variable;
        } finally {
            monitor.finished();
            // Runs under the write lock: every other reader is excluded, so
            // invalidating all of them is safe and the next read rebuilds them
            // against the edited program.
            close();
        }
    }

    /**
     * Dispose every decompile process and forget them, so the next read builds
     * fresh ones. Called only with the write lock held (mutations and bridge
     * shutdown), where no reader can be inside a decompile.
     */
    void close() {
        for (Entry entry : Set.copyOf(live)) {
            entry.decompiler.dispose();
            entry.decompiler = null;
            entry.decompilerProgram = null;
        }
        live.clear();
    }

    /// Dispose only the calling thread's entry. Used by a cancelled read, which
    /// holds the read lock and therefore cannot see the other threads' entries.
    private void discardCurrent() {
        discard(current.get());
    }

    private void discard(Entry entry) {
        if (entry.decompiler == null)
            return;
        live.remove(entry);
        entry.decompiler.dispose();
        entry.decompiler = null;
        entry.decompilerProgram = null;
    }

    /// The current thread's decompiler for {@code program}, rebuilt when the
    /// program changed or when a mutation invalidated it. Runs with the read lock
    /// held, so the entry cannot be disposed underneath this call.
    private Entry decompilerFor(Program program) throws BridgeFailure {
        Entry entry = current.get();
        if (entry.decompiler != null && entry.decompilerProgram == program) {
            return entry;
        }
        discard(entry);
        DecompInterface fresh = new DecompInterface();
        try {
            if (!fresh.openProgram(program)) {
                throw new BridgeFailure("decompiler_unavailable", "Ghidra decompiler could not open the program");
            }
            entry.decompiler = fresh;
            entry.decompilerProgram = program;
            live.add(entry);
        }
        catch (Exception failure) {
            // BridgeFailure is checked, so the old catch (RuntimeException)
            // missed the decompiler_unavailable throw above and leaked the
            // native decompile process. Catch both and rethrow precisely.
            fresh.dispose();
            throw failure;
        }
        return entry;
    }
}
