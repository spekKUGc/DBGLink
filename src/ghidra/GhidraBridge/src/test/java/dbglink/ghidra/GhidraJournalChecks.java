package dbglink.ghidra;

import com.google.gson.JsonObject;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Regression checks for the durable annotation journal: a rename recorded in
 * one program instance must replay on a later, different program object for
 * the same binary (the case a restarted launcher session actually produces),
 * exactly once per activation and again after the program is closed.
 */
final class GhidraJournalChecks {
    private static final String SHA =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T)Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }

    /** Fresh proxies every call: replay must not depend on the original object. */
    private static Program program(AddressSpace space, List<String> applied) {
        Address entry = space.getAddress(0x30001000);
        Function function = proxy(Function.class, (p,m,a) -> switch(m.getName()) {
            case "getName" -> "OldName";
            case "getEntryPoint" -> entry;
            case "getComment" -> "";
            case "setComment" -> { applied.add("comment:" + a[0]); yield null; }
            case "setName" -> { applied.add((String)a[0]); yield null; }
            default -> throw new AssertionError(m);
        });
        FunctionManager functions = proxy(FunctionManager.class, (p,m,a) -> switch(m.getName()) {
            case "getFunctionAt", "getFunctionContaining" -> ((Address)a[0]).equals(entry) ? function : null;
            default -> throw new AssertionError(m);
        });
        Listing listing = proxy(Listing.class, (p,m,a) -> switch(m.getName()) {
            case "getGlobalFunctions" -> List.of();
            default -> throw new AssertionError(m);
        });
        return proxy(Program.class, (p,m,a) -> switch(m.getName()) {
            case "hashCode" -> System.identityHashCode(p);
            case "equals" -> p == a[0];
            case "toString" -> "proxy-program";
            case "getExecutableSHA256" -> SHA;
            case "getExecutablePath" -> "C:/hw.dll";
            case "parseAddress" -> new Address[] {
                space.getAddress(Long.parseUnsignedLong(((String)a[0]).replace("0x", ""), 16))};
            case "getFunctionManager" -> functions;
            case "getListing" -> listing;
            case "startTransaction" -> 1;
            case "endTransaction" -> false;
            default -> throw new AssertionError(m);
        });
    }

    /**
     * SEC-C J4: over-long journal lines are skipped without OOM and a valid
     * entry beside them still replays. An over-long single record is also
     * refused at write time so one hostile entry cannot bloat the file.
     */
    private static void journalLineCap() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-linecap");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();

            JsonObject huge = new JsonObject();
            huge.addProperty("kind", "rename_function");
            huge.addProperty("entry", "30001000");
            huge.addProperty("name", "A".repeat(70 * 1024));
            check(!DbgLinkAnnotationJournal.record(program(space, applied), huge),
                "Over-long journal entry was stored");

            Path journal = directory.resolve(SHA + ".jsonl");
            StringBuilder hostile = new StringBuilder("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"");
            hostile.append("B".repeat(70 * 1024));
            hostile.append("\"}\n");
            Files.write(journal, hostile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            JsonObject good = new JsonObject();
            good.addProperty("kind", "rename_function");
            good.addProperty("entry", "30001000");
            good.addProperty("name", "GoodName");
            check(DbgLinkAnnotationJournal.record(program(space, applied), good), "Valid entry was not stored");

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("GoodName").equals(applied), "Line-cap replay lost the valid entry: " + applied);
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal line-cap checks passed.");
    }

    /**
     * SEC-C J4: replay reuses the live validators. Invalid symbol names, an
     * over-long comment, an over-long type selector and bidi controls are all
     * skipped; only the valid rename applies.
     */
    private static void replayValidatorReuse() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-validators");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            StringBuilder lines = new StringBuilder();
            lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"bad-name!\"}\n");
            lines.append("{\"kind\":\"set_function_comment\",\"entry\":\"30001000\",\"comment\":\"")
                .append("C".repeat(9_000)).append("\"}\n");
            lines.append("{\"kind\":\"set_variable_type\",\"function\":\"30001000\",\"variable\":\"x\",\"type\":\"")
                .append("T".repeat(300)).append("\"}\n");
            lines.append("{\"kind\":\"set_function_comment\",\"entry\":\"30001000\",\"comment\":\"hi‮there\"}\n");
            lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"ValidName\"}\n");
            Files.write(journal, lines.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("ValidName").equals(applied), "Validator reuse replay applied invalid entries: " + applied);
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal validator-reuse checks passed.");
    }

    /**
     * Coverage G15: replay reuses the live validators for the remaining
     * mutation kinds. An invalid rename_variable name, an invalid
     * create_function name and a control-character comment are all skipped;
     * an already-defined create_function stays a liveness no-op and the valid
     * rename still applies.
     */
    private static void replayValidatorReuseExtended() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-validators-ext");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            StringBuilder lines = new StringBuilder();
            lines.append("{\"kind\":\"rename_variable\",\"function\":\"30001000\",\"variable\":\"oldVar\",\"name\":\"bad-name!\"}\n");
            lines.append("{\"kind\":\"create_function\",\"entry\":\"30002000\",\"name\":\"bad-name!\"}\n");
            lines.append("{\"kind\":\"set_function_comment\",\"entry\":\"30001000\",\"comment\":\"hi\\u0001there\"}\n");
            lines.append("{\"kind\":\"create_function\",\"entry\":\"30001000\",\"name\":\"ValidCreate\"}\n");
            lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"ExtendedValid\"}\n");
            Files.write(journal, lines.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("ExtendedValid").equals(applied),
                "Extended validator reuse applied invalid entries: " + applied);
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal extended validator-reuse checks passed.");
    }

    /**
     * Coverage G15: a crash-truncated tail (partial line with no newline) is
     * skipped, not fatal, and the complete entry beside it still replays.
     */
    private static void journalTruncatedTail() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-tail");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            String content = "{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"TailName\"}\n" +
                "{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"Truncated";
            Files.write(journal, content.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("TailName").equals(applied), "Truncated tail broke replay: " + applied);
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal truncated-tail checks passed.");
    }

    /**
     * Coverage G15: rotation bounds growth. Past 2 MB the active file rolls
     * to "<sha>.jsonl.1" and the new entry starts a fresh active file.
     */
    private static void journalRotation() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-rotation");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            byte[] filler = "x".repeat(2_100_000).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Files.write(journal, filler);

            JsonObject rename = new JsonObject();
            rename.addProperty("kind", "rename_function");
            rename.addProperty("entry", "30001000");
            rename.addProperty("name", "RotatedName");
            check(DbgLinkAnnotationJournal.record(program(space, applied), rename),
                "Entry was not journaled after rotation");
            Path backup = directory.resolve(SHA + ".jsonl.1");
            check(Files.isRegularFile(backup), "Rotation did not keep a backup file");
            check(Files.size(backup) == filler.length, "Rotation backup lost bytes");
            List<String> active = Files.readAllLines(journal, java.nio.charset.StandardCharsets.UTF_8);
            check(active.size() == 1 && active.get(0).contains("RotatedName"),
                "Rotated active file must hold only the new entry");
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal rotation checks passed.");
    }

    /**
     * Coverage G15: the 20k entry cap. 20,005 small valid entries replay only
     * the first 20,000 in file order (oldest win).
     */
    private static void journalEntryCap() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-entrycap");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            StringBuilder lines = new StringBuilder(1_500_000);
            for (int index = 0; index < 20_005; index++) {
                lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"N")
                    .append(index).append("\"}\n");
            }
            Files.write(journal, lines.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(applied.size() == 20_000, "Entry cap replay kept " + applied.size() + " entries");
            check("N0".equals(applied.get(0)) && "N19999".equals(applied.get(19_999)),
                "Entry cap must keep the oldest entries in order");
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal entry-cap checks passed.");
    }

    /**
     * Coverage G15: the 8 MB scan cap with lines under the 64 KB line cap.
     * Padded (extra-field) valid entries keep every line parseable, so only
     * the byte cap can drop the tail: the first entries apply and the last
     * written name never replays.
     */
    private static void journalScanCap() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-scancap");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            String pad = "A".repeat(60 * 1024);
            StringBuilder lines = new StringBuilder(13_000_000);
            for (int index = 0; index < 200; index++) {
                lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"S")
                    .append(index).append("\",\"pad\":\"").append(pad).append("\"}\n");
            }
            Files.write(journal, lines.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(!applied.isEmpty() && applied.size() < 200,
                "Scan cap replay kept " + applied.size() + " of 200 entries");
            check("S0".equals(applied.get(0)), "Scan cap must keep the oldest entries first");
            check(!applied.contains("S199"), "Scan cap must drop entries past 8 MB");
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal scan-cap checks passed.");
    }

    /**
     * Coverage G15: the create_function replay cap stays bounded. Forty
     * already-defined creates plus one rename must complete promptly with the
     * rename applied, and the cap constant must remain 32.
     */
    private static void journalCreateFunctionCap() throws Exception {
        java.lang.reflect.Field cap =
            DbgLinkAnnotationJournal.class.getDeclaredField("MAX_CREATE_FUNCTION_REPLAY");
        cap.setAccessible(true);
        check(cap.getInt(null) == 32, "Create-function replay cap changed");
        Path directory = Files.createTempDirectory("dbglink-journal-createcap");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();
            Path journal = directory.resolve(SHA + ".jsonl");
            StringBuilder lines = new StringBuilder();
            for (int index = 0; index < 40; index++) {
                lines.append("{\"kind\":\"create_function\",\"entry\":\"30001000\",\"name\":\"Capped")
                    .append(index).append("\"}\n");
            }
            lines.append("{\"kind\":\"rename_function\",\"entry\":\"30001000\",\"name\":\"AfterCreates\"}\n");
            Files.write(journal, lines.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("AfterCreates").equals(applied),
                "Create-function cap broke later entries: " + applied);
            DbgLinkAnnotationJournal.forget(reopened);
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal create-function cap checks passed.");
    }

    static void run() throws Exception {
        Path directory = Files.createTempDirectory("dbglink-journal-checks");
        Path previous = DbgLinkAnnotationJournal.directoryOverride;
        DbgLinkAnnotationJournal.directoryOverride = directory;
        try {
            AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            List<String> applied = new ArrayList<>();

            JsonObject rename = new JsonObject();
            rename.addProperty("kind", "rename_function");
            rename.addProperty("entry", "30001000");
            rename.addProperty("name", "NewName");
            check(DbgLinkAnnotationJournal.record(program(space, applied), rename), "Rename was not journaled");
            check(applied.isEmpty(), "Recording must not touch the program");
            Path journal = directory.resolve(SHA + ".jsonl");
            check(Files.isRegularFile(journal), "Journal file was not created for the program SHA-256");

            Program reopened = program(space, applied);
            DbgLinkAnnotationJournal.replay(reopened);
            check(List.of("NewName").equals(applied), "Replay did not restore the rename: " + applied);

            DbgLinkAnnotationJournal.replay(reopened);
            check(applied.size() == 1, "Replay ran twice for one activation: " + applied.size());

            DbgLinkAnnotationJournal.forget(reopened);
            DbgLinkAnnotationJournal.replay(reopened);
            check(applied.size() == 2, "Closing a program did not allow replay on reimport: " + applied.size());
        }
        finally {
            DbgLinkAnnotationJournal.directoryOverride = previous;
        }
        System.out.println("Annotation journal regression checks passed.");
        journalLineCap();
        replayValidatorReuse();
        replayValidatorReuseExtended();
        journalTruncatedTail();
        journalRotation();
        journalEntryCap();
        journalScanCap();
        journalCreateFunctionCap();
    }
}
