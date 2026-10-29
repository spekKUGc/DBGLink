package dbglink.ghidra;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static dbglink.ghidra.GhidraBridgeServer.JSON;

/**
 * Durable journal of DBGLink annotations, keyed by the program's SHA-256.
 *
 * <p>Launcher-owned Ghidra sessions are re-imported from scratch, so renames
 * and comments made through the bridge used to die with the session; users
 * replayed hand-maintained rename lists after every restart. Every mutation is
 * appended here and replayed once per program activation. Replay is
 * best-effort and idempotent: entries that no longer resolve are skipped, not
 * fatal, so a stale journal can never block program activation.</p>
 */
final class DbgLinkAnnotationJournal {
    private static final int MAX_REPLAY_ENTRIES = 20_000;
    // SEC-C J4: bound journal memory and activation CPU. Single lines over
    // 64 KB are skipped (crash-truncated or hostile), only the first 8 MB of
    // the file are inspected per activation, the file rotates past 2 MB, and
    // create_function replay is capped so activation cannot hang.
    static final int MAX_JOURNAL_LINE_BYTES = 64 * 1024;
    private static final long MAX_JOURNAL_FILE_BYTES = 2L * 1024 * 1024;
    private static final long MAX_JOURNAL_SCAN_BYTES = 8L * 1024 * 1024;
    private static final int MAX_CREATE_FUNCTION_REPLAY = 32;
    private static final long REPLAY_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(15);
    private static final Map<Program, Boolean> REPLAYED =
        Collections.synchronizedMap(new WeakHashMap<>());

    /** Test seam; production uses %LOCALAPPDATA%\DBGLink\annotations. */
    static volatile Path directoryOverride;

    private DbgLinkAnnotationJournal() { }

    static boolean record(Program program, JsonObject entry) {
        try {
            Path file = journalFile(program);
            if (file == null) {
                return false;
            }
            JsonObject line = entry.deepCopy();
            line.addProperty("ts", System.currentTimeMillis());
            byte[] bytes = (JSON.toJson(line) + "\n").getBytes(StandardCharsets.UTF_8);
            // SEC-C J6: cap single-entry growth; huge comments are already
            // clipped by the live paths, so an over-long line is hostile.
            if (bytes.length > MAX_JOURNAL_LINE_BYTES) {
                return false;
            }
            Path parent = file.getParent();
            if (parent != null) {
                ensureSafePath(parent);
                Files.createDirectories(parent);
                ensureSafePath(parent);
                applyOwnerOnlyDirectoryPermissionsBestEffort(parent);
            }
            // Don't follow links on append: a symlinked journal would divert
            // renames to an attacker file, and a reparse/other node is never
            // a plain journal. Fail closed (skip the write, keep the live
            // mutation). Residual TOCTOU: re-checked immediately before the
            // append; see ensureSafePath.
            if (Files.isSymbolicLink(file) ||
                (Files.exists(file, LinkOption.NOFOLLOW_LINKS) &&
                 !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))) {
                return false;
            }
            // SEC-C J6: cap journal growth with rotation. Past 2 MB the active
            // file rolls to "<sha>.jsonl.1" (replacing any prior backup) and a
            // fresh file starts; activation reads the active file plus nothing
            // else, so growth stays bounded at ~2x the cap plus one entry.
            try {
                if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) &&
                    journalSize(file) > MAX_JOURNAL_FILE_BYTES) {
                    Path backup = file.resolveSibling(file.getFileName() + ".1");
                    try {
                        // A symlinked or non-regular backup would divert the
                        // rotation; remove it and move onto a fresh name.
                        if (Files.isSymbolicLink(backup) ||
                            (Files.exists(backup, LinkOption.NOFOLLOW_LINKS) &&
                             !Files.isRegularFile(backup, LinkOption.NOFOLLOW_LINKS))) {
                            Files.deleteIfExists(backup);
                        }
                        if (parent != null) {
                            ensureSafePath(parent);
                        }
                        if (Files.isSymbolicLink(file)) {
                            return false;
                        }
                        Files.move(file, backup, StandardCopyOption.REPLACE_EXISTING);
                    }
                    catch (Exception moveFailed) {
                        return false;
                    }
                }
            }
            catch (Exception sizeCheckFailed) {
                // Best-effort size gate; the append below still applies the
                // per-line cap.
            }
            if (Files.isSymbolicLink(file) ||
                (Files.exists(file, LinkOption.NOFOLLOW_LINKS) &&
                 !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))) {
                return false;
            }
            Files.write(
                file,
                bytes,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
            applyOwnerOnlyFilePermissionsBestEffort(file);
            return true;
        }
        catch (Exception exception) {
            // The mutation already committed; persistence is best-effort.
            return false;
        }
    }

    /** Replay the journal for this program once per activation. */
    static void replay(Program program) {
        synchronized (REPLAYED) {
            if (REPLAYED.containsKey(program)) {
                return;
            }
        }
        try {
            Path file = journalFile(program);
            if (file == null || Files.isSymbolicLink(file) ||
                !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return;
            }
            List<JsonObject> entries = readEntries(file);
            if (entries.isEmpty()) {
                return;
            }
            int applied = 0;
            int createdFunctions = 0;
            long replayDeadline = System.nanoTime() + REPLAY_BUDGET_NANOS;
            int transaction = program.startTransaction("DBGLink annotation journal replay");
            boolean committed = false;
            try {
                for (JsonObject entry : entries) {
                    try {
                        // SEC-C J4: budget create_function replay so a hostile
                        // journal cannot hang activation in disassembly.
                        if ("create_function".equals(text(entry, "kind"))) {
                            if (createdFunctions >= MAX_CREATE_FUNCTION_REPLAY ||
                                System.nanoTime() >= replayDeadline) {
                                continue;
                            }
                            createdFunctions++;
                        }
                        if (apply(program, entry)) {
                            applied++;
                        }
                    }
                    catch (Exception ignored) {
                        // One stale entry must not block the rest.
                    }
                }
                committed = applied > 0;
            }
            finally {
                program.endTransaction(transaction, committed);
            }
            if (applied > 0) {
                Msg.info(DbgLinkAnnotationJournal.class,
                    "DBGLink replayed " + applied + " annotation(s) from the journal for " +
                    program.getExecutablePath());
            }
        }
        catch (RuntimeException exception) {
            Msg.warn(DbgLinkAnnotationJournal.class,
                "DBGLink annotation journal replay failed: " + exception.getMessage());
        }
        finally {
            synchronized (REPLAYED) {
                REPLAYED.put(program, Boolean.TRUE);
            }
        }
    }

    /** The program object is gone; a future import must replay again. */
    static void forget(Program program) {
        synchronized (REPLAYED) {
            REPLAYED.remove(program);
        }
    }

    /** Canonical function-entry strings recorded by the journal (progress).
     *  The bridge always journals {@code getEntryPoint().toString()}, so a raw
     *  string match against GetAnalysisQueue rows is exact. Best-effort: an
     *  unreadable journal means no exclusions. */
    static java.util.Set<String> annotatedFunctionEntries(Program program) {
        java.util.Set<String> entries = new java.util.HashSet<>();
        try {
            Path file = journalFile(program);
            if (file == null || Files.isSymbolicLink(file) ||
                !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return entries;
            }
            for (JsonObject entry : readEntries(file)) {
                String byEntry = text(entry, "entry");
                if (!byEntry.isEmpty()) {
                    entries.add(byEntry);
                }
                String byFunction = text(entry, "function");
                if (!byFunction.isEmpty()) {
                    entries.add(byFunction);
                }
            }
        }
        catch (RuntimeException ignored) {
            // Progress is best-effort.
        }
        return entries;
    }

    private static Path journalFile(Program program) {
        String sha = program.getExecutableSHA256();
        if (sha == null || !sha.matches("[0-9a-fA-F]{64}")) {
            return null;
        }
        return directory().resolve(sha.toLowerCase(Locale.ROOT) + ".jsonl");
    }

    private static Path directory() {
        // The launcher redirects LOCALAPPDATA into the shared Ghidra cache for
        // its own files, so the journal must not derive from it: wiping the
        // documented troubleshooting target (GhidraCache) would silently take
        // every rename with it. The launcher passes the real annotations
        // directory explicitly; LOCALAPPDATA stays as the fallback.
        String configured = System.getenv("DBGLINK_ANNOTATIONS_DIR");
        if (configured != null && !configured.isBlank()) {
            try {
                String trimmed = configured.trim();
                // Reject network trust-boundary and escape spellings before
                // touching the filesystem, mirroring GhidraEndpointSecurity.
                if (isUncRawPath(trimmed) || hasDotDotSegment(trimmed)) {
                    throw new IOException("DBGLink annotations directory is not a safe local path");
                }
                Path candidate = Path.of(trimmed).toAbsolutePath().normalize();
                if (isUncNormalizedPath(candidate) || hasDotDotSegment(candidate)) {
                    throw new IOException("DBGLink annotations directory is not a safe local path");
                }
                ensureSafePath(candidate);
                Files.createDirectories(candidate);
                ensureSafePath(candidate);
                applyOwnerOnlyDirectoryPermissionsBestEffort(candidate);
                return candidate;
            }
            catch (IOException | RuntimeException ignored) {
                // Fall through to the default location below.
            }
        }
        Path override = directoryOverride;
        if (override != null) {
            return override;
        }
        String localAppData = System.getenv("LOCALAPPDATA");
        return localAppData != null && !localAppData.isBlank()
            ? Path.of(localAppData, "DBGLink", "annotations")
            : Path.of(System.getProperty("user.home", "."), ".dbglink", "annotations");
    }

    private static boolean isUncRawPath(String rawTrimmed) {
        return rawTrimmed.startsWith("\\\\") || rawTrimmed.startsWith("//");
    }

    private static boolean hasDotDotSegment(String rawTrimmed) {
        for (String segment : rawTrimmed.split("[/\\\\]+")) {
            if ("..".equals(segment)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasDotDotSegment(Path normalized) {
        for (Path part : normalized) {
            if ("..".equals(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUncNormalizedPath(Path normalized) {
        String text = normalized.toString();
        return text.startsWith("\\\\") || text.startsWith("//");
    }

    /**
     * Mirror of {@code GhidraEndpointSecurity.ensureSafePath} for the journal
     * directory: every existing component from the candidate up to the root
     * must not be a symlink or a non-file/dir reparse point. Check-time
     * validation only; callers revalidate after creating directories and
     * immediately before the append, and never open a symlinked journal file.
     * A full open-by-handle (O_NOFOLLOW per-component) traversal is a
     * documented follow-up, as with the endpoint file.
     */
    private static void ensureSafePath(Path path) throws IOException {
        Path current = path.toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isSymbolicLink(current)) {
                throw new IOException("DBGLink annotations path contains a symbolic link");
            }
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                BasicFileAttributes attributes = Files.readAttributes(
                    current,
                    BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS
                );
                if (attributes.isOther()) {
                    throw new IOException("DBGLink annotations path contains an unsupported reparse point");
                }
            }
            current = current.getParent();
        }
    }

    /** NOFOLLOW size probe so the rotation gate never follows a link. */
    private static long journalSize(Path file) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
            file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return attributes.size();
    }

    /** Best-effort 0600 for the journal file (owner-only, like the endpoint). */
    private static void applyOwnerOnlyFilePermissionsBestEffort(Path file) {
        try {
            PosixFileAttributeView posix =
                Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (posix != null) {
                try {
                    Files.setPosixFilePermissions(
                        file,
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                    return;
                }
                catch (UnsupportedOperationException ignored) {
                    // Fall through to the Windows ACL path.
                }
            }
            AclFileAttributeView aclView =
                Files.getFileAttributeView(file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (aclView == null) {
                return;
            }
            UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
            Set<AclEntryPermission> filePermissions = EnumSet.of(
                AclEntryPermission.READ_DATA,
                AclEntryPermission.WRITE_DATA,
                AclEntryPermission.APPEND_DATA,
                AclEntryPermission.READ_NAMED_ATTRS,
                AclEntryPermission.WRITE_NAMED_ATTRS,
                AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES,
                AclEntryPermission.READ_ACL,
                AclEntryPermission.SYNCHRONIZE);
            List<AclEntry> restricted = new ArrayList<>(2);
            restricted.add(AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(filePermissions)
                .build());
            try {
                UserPrincipalLookupService lookup =
                    file.getFileSystem().getUserPrincipalLookupService();
                UserPrincipal system = null;
                try {
                    system = lookup.lookupPrincipalByName("NT AUTHORITY\\SYSTEM");
                }
                catch (RuntimeException | IOException ignored) {
                    try {
                        system = lookup.lookupPrincipalByName("SYSTEM");
                    }
                    catch (RuntimeException | IOException ignored2) {
                        system = null;
                    }
                }
                if (system != null && !system.getName().equals(owner.getName())) {
                    restricted.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(system)
                        .setPermissions(filePermissions)
                        .build());
                }
            }
            catch (RuntimeException ignored) {
                // SYSTEM is a convenience grant; the owner entry is the requirement.
            }
            aclView.setAcl(restricted);
        }
        catch (IOException | RuntimeException ignored) {
            // Persistence is best-effort; a journal that cannot be locked down
            // still holds no auth token, only annotation text.
        }
    }

    /** Best-effort 0700 for the journal directory (owner-only). */
    private static void applyOwnerOnlyDirectoryPermissionsBestEffort(Path directory) {
        try {
            PosixFileAttributeView posix =
                Files.getFileAttributeView(directory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (posix != null) {
                try {
                    Files.setPosixFilePermissions(
                        directory,
                        EnumSet.of(PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE));
                    return;
                }
                catch (UnsupportedOperationException ignored) {
                    // Fall through to the Windows ACL path.
                }
            }
            AclFileAttributeView aclView =
                Files.getFileAttributeView(directory, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (aclView == null) {
                return;
            }
            UserPrincipal owner = Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS);
            Set<AclEntryPermission> directoryPermissions = EnumSet.of(
                AclEntryPermission.READ_DATA,
                AclEntryPermission.WRITE_DATA,
                AclEntryPermission.APPEND_DATA,
                AclEntryPermission.EXECUTE,
                AclEntryPermission.DELETE_CHILD,
                AclEntryPermission.READ_NAMED_ATTRS,
                AclEntryPermission.WRITE_NAMED_ATTRS,
                AclEntryPermission.READ_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES,
                AclEntryPermission.DELETE,
                AclEntryPermission.READ_ACL,
                AclEntryPermission.WRITE_ACL,
                AclEntryPermission.WRITE_OWNER,
                AclEntryPermission.SYNCHRONIZE);
            List<AclEntry> restricted = new ArrayList<>(2);
            restricted.add(AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(directoryPermissions)
                .build());
            try {
                UserPrincipalLookupService lookup =
                    directory.getFileSystem().getUserPrincipalLookupService();
                UserPrincipal system = null;
                try {
                    system = lookup.lookupPrincipalByName("NT AUTHORITY\\SYSTEM");
                }
                catch (RuntimeException | IOException ignored) {
                    try {
                        system = lookup.lookupPrincipalByName("SYSTEM");
                    }
                    catch (RuntimeException | IOException ignored2) {
                        system = null;
                    }
                }
                if (system != null && !system.getName().equals(owner.getName())) {
                    restricted.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(system)
                        .setPermissions(directoryPermissions)
                        .build());
                }
            }
            catch (RuntimeException ignored) {
                // SYSTEM is a convenience grant; the owner entry is the requirement.
            }
            aclView.setAcl(restricted);
        }
        catch (IOException | RuntimeException ignored) {
            // Best-effort hardening only.
        }
    }

    /**
     * SEC-C J4: OOM-safe journal scan. Reads at most
     * {@code MAX_JOURNAL_SCAN_BYTES} from the file prefix (oldest entries win),
     * skips lines over {@code MAX_JOURNAL_LINE_BYTES} without materializing
     * them, and caps the replay list. Splits the byte stream on LF (safe: no
     * UTF-8 trail byte equals 0x0A) so a single huge line without a newline
     * can never force a multi-gigabyte String allocation.
     */
    private static List<JsonObject> readEntries(Path file) {
        List<JsonObject> entries = new ArrayList<>();
        // Never open a symlinked or non-regular journal: the caller re-checks,
        // but readEntries is also reached from annotatedFunctionEntries, so
        // gate here too. Residual TOCTOU documented at ensureSafePath.
        try {
            if (Files.isSymbolicLink(file) ||
                !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return entries;
            }
        }
        catch (RuntimeException earlyExit) {
            return entries;
        }
        try (InputStream input = Files.newInputStream(file)) {
            byte[] chunk = new byte[8192];
            ByteArrayOutputStream lineBytes = new ByteArrayOutputStream(4096);
            boolean skippingLongLine = false;
            long totalBytes = 0;
            boolean capped = false;
            while (!capped && entries.size() < MAX_REPLAY_ENTRIES) {
                int read = input.read(chunk);
                if (read == -1) {
                    break;
                }
                for (int index = 0; index < read; index++) {
                    if (totalBytes >= MAX_JOURNAL_SCAN_BYTES) {
                        capped = true;
                        break;
                    }
                    totalBytes++;
                    byte value = chunk[index];
                    if (value == '\n') {
                        if (!skippingLongLine) {
                            byte[] raw = lineBytes.toByteArray();
                            int length = raw.length;
                            if (length > 0 && raw[length - 1] == '\r') {
                                length--;
                            }
                            if (length > 0) {
                                if (length <= MAX_JOURNAL_LINE_BYTES) {
                                    String line;
                                    try {
                                        line = new String(raw, 0, length, StandardCharsets.UTF_8);
                                    }
                                    catch (RuntimeException malformed) {
                                        line = "";
                                    }
                                    if (!line.isBlank()) {
                                        try {
                                            JsonElement element = JsonParser.parseString(line);
                                            if (element.isJsonObject()) {
                                                entries.add(element.getAsJsonObject());
                                                if (entries.size() >= MAX_REPLAY_ENTRIES) {
                                                    break;
                                                }
                                            }
                                        }
                                        catch (JsonParseException ignored) {
                                            // A truncated line from a crash is skipped, not fatal.
                                        }
                                    }
                                }
                                // Over-long complete lines are skipped (see below).
                            }
                        }
                        lineBytes.reset();
                        skippingLongLine = false;
                        continue;
                    }
                    if (skippingLongLine) {
                        continue;
                    }
                    if (lineBytes.size() >= MAX_JOURNAL_LINE_BYTES) {
                        // Over-long line: drop the buffer and drain to the next
                        // newline without storing.
                        skippingLongLine = true;
                        lineBytes.reset();
                        continue;
                    }
                    lineBytes.write(value);
                }
            }
            // A trailing partial line without a newline (crash-truncated tail)
            // is skipped, not fatal, matching the historical parse-failure path.
        }
        catch (Exception ignored) {
            // Missing/unreadable journals simply replay nothing.
        }
        return entries;
    }

    private static String text(JsonObject entry, String name) {
        JsonElement value = entry.get(name);
        return value == null || !value.isJsonPrimitive() ? "" : value.getAsString();
    }

    private static Function functionAt(Program program, String text) {
        if (text.isEmpty()) {
            return null;
        }
        try {
            Address[] parsed = program.parseAddress(text);
            if (parsed != null) {
                for (Address address : parsed) {
                    Function function = program.getFunctionManager().getFunctionAt(address);
                    if (function == null) {
                        function = program.getFunctionManager().getFunctionContaining(address);
                    }
                    if (function != null) {
                        return function;
                    }
                }
            }
        }
        catch (RuntimeException ignored) {
            // Unresolvable addresses are skipped.
        }
        return null;
    }

    /**
     * Apply one entry in journal order; returns true when state changed or already matched.
     * SEC-C J4: replay reuses the SAME validators as the live paths (symbol
     * regex, 8192 comment cap, 256 type cap, bidi/format rejection). A journal
     * entry that the live tool would reject is skipped, not applied, so a
     * hostile or stale journal cannot persist invalid state.
     */
    private static boolean apply(Program program, JsonObject entry) throws BridgeFailure {
        String kind = text(entry, "kind");
        switch (kind) {
            case "rename_function" -> {
                Function function = functionAt(program, text(entry, "entry"));
                if (function == null) {
                    return false;
                }
                String name = text(entry, "name").trim();
                if (name.isEmpty() || name.length() > GhidraBridgeServer.MAX_SYMBOL_NAME_CHARS) {
                    return false;
                }
                try {
                    GhidraBridgeServer.validateTextCharacters(name, "name", false);
                    GhidraAnalysisOperations.validateSymbolName(name);
                }
                catch (BridgeFailure invalid) {
                    return false;
                }
                if (function.getName().equals(name)) {
                    return true;
                }
                for (Function existing : program.getListing().getGlobalFunctions(name)) {
                    if (!existing.getEntryPoint().equals(function.getEntryPoint())) {
                        return false;
                    }
                }
                try {
                    function.setName(name, SourceType.USER_DEFINED);
                }
                catch (DuplicateNameException | InvalidInputException exception) {
                    return false;
                }
                return true;
            }
            case "set_function_comment" -> {
                Function function = functionAt(program, text(entry, "entry"));
                if (function == null) {
                    return false;
                }
                String comment = text(entry, "comment");
                if (comment.length() > GhidraBridgeServer.MAX_COMMENT_CHARS) {
                    return false;
                }
                try {
                    GhidraBridgeServer.validateTextCharacters(comment, "comment", true);
                }
                catch (BridgeFailure invalid) {
                    return false;
                }
                String current = function.getComment() == null ? "" : function.getComment();
                if (!current.equals(comment)) {
                    function.setComment(comment);
                }
                return true;
            }
            case "create_function" -> {
                Function function = functionAt(program, text(entry, "entry"));
                if (function != null) {
                    return true;
                }
                String name = text(entry, "name").trim();
                if (!name.isEmpty()) {
                    if (name.length() > GhidraBridgeServer.MAX_SYMBOL_NAME_CHARS) {
                        return false;
                    }
                    try {
                        GhidraBridgeServer.validateTextCharacters(name, "name", false);
                        GhidraAnalysisOperations.validateSymbolName(name);
                    }
                    catch (BridgeFailure invalid) {
                        return false;
                    }
                }
                Address[] parsed = program.parseAddress(text(entry, "entry"));
                if (parsed == null || parsed.length == 0) {
                    return false;
                }
                TaskMonitor monitor = GhidraBridgeServer.requestMonitor.get() != null
                    ? GhidraBridgeServer.requestMonitor.get()
                    : TaskMonitor.DUMMY;
                GhidraAnalysisOperations.defineFunction(program, parsed[0], name, monitor);
                return true;
            }
            case "rename_variable" -> {
                Function function = functionAt(program, text(entry, "function"));
                if (function == null) {
                    return false;
                }
                String previous = text(entry, "variable").trim();
                String name = text(entry, "name").trim();
                if (previous.isEmpty() || name.isEmpty() ||
                    previous.length() > GhidraBridgeServer.MAX_SYMBOL_NAME_CHARS ||
                    name.length() > GhidraBridgeServer.MAX_SYMBOL_NAME_CHARS) {
                    return false;
                }
                try {
                    GhidraBridgeServer.validateTextCharacters(previous, "variable", false);
                    GhidraBridgeServer.validateTextCharacters(name, "name", false);
                    GhidraAnalysisOperations.validateSymbolName(name);
                }
                catch (BridgeFailure invalid) {
                    return false;
                }
                for (Variable variable : function.getAllVariables()) {
                    if (!variable.isValid()) {
                        continue;
                    }
                    if (name.equals(variable.getName())) {
                        return true;
                    }
                    if (previous.equals(variable.getName())) {
                        try {
                            variable.setName(name, SourceType.USER_DEFINED);
                        }
                        catch (DuplicateNameException | InvalidInputException exception) {
                            return false;
                        }
                        return true;
                    }
                }
                return false;
            }
            case "set_variable_type" -> {
                Function function = functionAt(program, text(entry, "function"));
                if (function == null) {
                    return false;
                }
                String variableName = text(entry, "variable").trim();
                String typeSelector = text(entry, "type");
                if (variableName.isEmpty() || typeSelector.isEmpty() ||
                    variableName.length() > GhidraBridgeServer.MAX_SYMBOL_NAME_CHARS ||
                    typeSelector.length() > GhidraBridgeServer.MAX_SELECTOR_CHARS) {
                    return false;
                }
                try {
                    GhidraBridgeServer.validateTextCharacters(variableName, "variable", false);
                    GhidraBridgeServer.validateTextCharacters(typeSelector, "type", true);
                }
                catch (BridgeFailure invalid) {
                    return false;
                }
                Variable target = null;
                for (Variable variable : function.getAllVariables()) {
                    if (variable.isValid() && variableName.equals(variable.getName())) {
                        target = variable;
                        break;
                    }
                }
                if (target == null) {
                    return false;
                }
                DataType dataType;
                try {
                    dataType = GhidraAnalysisOperations.resolveDataType(program, typeSelector);
                }
                catch (BridgeFailure unresolved) {
                    return false;
                }
                if (dataType == null) {
                    return false;
                }
                String current = target.getDataType() == null ? "" : target.getDataType().getPathName();
                if (current.equals(typeSelector)) {
                    return true;
                }
                try {
                    target.setDataType(dataType, SourceType.USER_DEFINED);
                }
                catch (InvalidInputException exception) {
                    return false;
                }
                return true;
            }
            default -> {
                return false;
            }
        }
    }
}
