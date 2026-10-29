package dbglink.ghidra;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

/**
 * Controlled launcher integration for the Ghidra front end.
 *
 * <p>The launcher creates a bounded project with the selected input file and
 * sets the two opt-in environment variables below.  This plugin then opens
 * only that imported project file in the default Ghidra tool and adds the
 * fixed DBGLink program plugin.  It never interprets a script, class name, or
 * command supplied by MCP.</p>
 */
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "DBGLink",
    category = "DBGLink",
    shortDescription = "DBGLink controlled project activation",
    description = "Opens one launcher-selected Ghidra project file in the default tool."
)
public final class DbgLinkFrontEndPlugin extends Plugin implements ApplicationLevelPlugin, ProjectListener {

    private static final String AUTO_OPEN_ENV = "DBGLINK_GHIDRA_AUTO_OPEN";
    private static final String INPUT_FILE_ENV = "DBGLINK_GHIDRA_INPUT_FILE";
    private static final String ANALYZE_ENV = "DBGLINK_GHIDRA_ANALYZE";
    private static final String ENABLED_VALUE = "1";
    private static final String DISABLED_VALUE = "0";
    private static final String PROGRAM_PLUGIN_CLASS = "dbglink.ghidra.DbgLinkGhidraPlugin";
    private static final int MAX_PROJECT_FILES = 10_000;
    private static final int MAX_VISITED_ENTRIES = 50_000;
    private static final int MAX_PATH_LENGTH = 32_760;
    /**
     * SEC-C J5 / coverage G3: DOS device stems rejected per path component, in
     * parity with the .NET ({@code LocalPathPolicy}) and native
     * ({@code IsDosDeviceStem}) layers. Any position, any case, with or
     * without an extension or trailing dots/spaces ({@code CON},
     * {@code nul.txt}, {@code COM1.}, {@code AUX:stream}).
     */
    private static final Set<String> RESERVED_DEVICE_NAMES = Set.of(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "CONIN$", "CONOUT$");

    private final AtomicBoolean activationScheduled = new AtomicBoolean();
    private final AtomicBoolean activationFinished = new AtomicBoolean();
    private FrontEndTool frontEndTool;
    private String requestedFileName;

    public DbgLinkFrontEndPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();

        if (!ENABLED_VALUE.equals(System.getenv(AUTO_OPEN_ENV))) {
            return;
        }

        Msg.debug(this, "DBGLink controlled activation plugin initialized.");

        if (!(tool instanceof FrontEndTool)) {
            Msg.error(this, "DBGLink controlled activation requires the Ghidra front end tool.");
            return;
        }

        String configuredPath = System.getenv(INPUT_FILE_ENV);
        Path inputPath = parseInputPath(configuredPath);
        if (inputPath == null) {
            Msg.error(this, "DBGLink controlled activation received an invalid input path.");
            return;
        }

        frontEndTool = (FrontEndTool) tool;
        requestedFileName = inputPath.getFileName().toString();
        frontEndTool.addProjectListener(this);

        Project activeProject = frontEndTool.getProjectManager().getActiveProject();
        if (activeProject != null) {
            scheduleActivation(activeProject);
        }
    }

    @Override
    public void projectOpened(Project project) {
        Msg.debug(this, "DBGLink controlled activation observed a project open.");
        scheduleActivation(project);
    }

    @Override
    public void projectClosed(Project project) {
        // The next project is not opened implicitly.  The launcher owns the
        // one-shot selection and must start a new session for another file.
    }

    @Override
    protected void dispose() {
        // A project-open callback may already be queued on the Swing event
        // thread.  Make that callback a no-op once the plugin is disposed.
        activationFinished.set(true);
        activationScheduled.set(true);
        if (frontEndTool != null) {
            frontEndTool.removeProjectListener(this);
            frontEndTool = null;
        }
        super.dispose();
    }

    private void scheduleActivation(Project project) {
        if (activationFinished.get() || !activationScheduled.compareAndSet(false, true)) {
            return;
        }

        SwingUtilities.invokeLater(() -> activateProject(project));
    }

    private void activateProject(Project project) {
        Msg.debug(this, "DBGLink controlled activation is resolving the selected program.");
        if (activationFinished.get() || project == null || project.isClosed()) {
            activationScheduled.set(false);
            return;
        }

        try {
            Msg.debug(this, "DBGLink controlled activation is enumerating the imported project.");
            List<DomainFile> matches = findInputFiles(project.getProjectData());
            Msg.debug(this, "DBGLink controlled activation found " + matches.size() + " matching project file(s).");
            if (matches.size() != 1) {
                Msg.error(this, "DBGLink controlled activation expected one imported input file, found " + matches.size() + ".");
                activationFinished.set(true);
                return;
            }

            ToolServices toolServices = project.getToolServices();
            Msg.debug(this, "DBGLink controlled activation obtained project tool services.");
            if (toolServices == null) {
                Msg.error(this, "DBGLink controlled activation could not access Ghidra tool services.");
                activationFinished.set(true);
                return;
            }

            Msg.debug(this, "DBGLink controlled activation is launching the default program tool.");
            if (DISABLED_VALUE.equals(System.getenv(ANALYZE_ENV))) {
                suppressAnalysisPrompt(matches.get(0));
            }
            PluginTool programTool = toolServices.launchDefaultTool(matches);
            Msg.debug(this, "DBGLink controlled activation returned from the default program tool launch.");
            if (programTool == null) {
                Msg.error(this, "DBGLink controlled activation could not launch the default Ghidra tool.");
                activationFinished.set(true);
                return;
            }

            addProgramPlugin(programTool);
            activationFinished.set(true);
            Msg.info(this, "DBGLink opened the launcher-selected Ghidra program.");
        }
        catch (RuntimeException exception) {
            Msg.error(this, "DBGLink controlled activation failed: " + exception.getClass().getSimpleName());
            activationFinished.set(true);
        }
    }

    private void addProgramPlugin(PluginTool programTool) {
        for (Plugin managedPlugin : programTool.getManagedPlugins()) {
            if (PROGRAM_PLUGIN_CLASS.equals(managedPlugin.getClass().getName())) {
                return;
            }
        }

        try {
            programTool.addPlugin(PROGRAM_PLUGIN_CLASS);
        }
        catch (PluginException exception) {
            throw new IllegalStateException("DBGLink program plugin could not be loaded", exception);
        }
    }

    /**
     * Fast imports skip headless analysis, so the program is unanalyzed with
     * "ask to analyze" still enabled. Opening it in the program tool would
     * raise a modal Yes/No dialog that nobody can answer in the hidden
     * launcher-owned window, and the bridge would never start. Pre-mark the
     * program instead so it opens silently; analysis can still run later.
     */
    private void suppressAnalysisPrompt(DomainFile file) {
        DomainObject domainObject = null;
        try {
            domainObject = file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
            if (domainObject instanceof Program program &&
                GhidraProgramUtilities.shouldAskToAnalyze(program)) {
                GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
                if (domainObject.canSave()) {
                    domainObject.save("DBGLink suppress analysis prompt for fast import", TaskMonitor.DUMMY);
                }
                Msg.info(this, "DBGLink disabled the analysis prompt for the fast-imported program.");
            }
        }
        catch (VersionException | IOException | CancelledException exception) {
            Msg.warn(this, "DBGLink could not suppress the analysis prompt: " +
                exception.getClass().getSimpleName());
        }
        finally {
            if (domainObject != null) {
                domainObject.release(this);
            }
        }
    }

    private List<DomainFile> findInputFiles(ProjectData projectData) {
        List<DomainFile> matches = new ArrayList<>();
        if (projectData == null) {
            return matches;
        }

        collectFiles(projectData.getRootFolder(), matches, new SearchBudget());
        return matches;
    }

    private void collectFiles(DomainFolder folder, List<DomainFile> matches, SearchBudget budget) {
        if (folder == null || matches.size() >= MAX_PROJECT_FILES || budget.exhausted()) {
            return;
        }

        // Keep the traversal iterative.  A project can contain arbitrarily
        // deep folders, and the entry budget should not be defeated by the
        // Java call stack before it has a chance to stop the walk.
        Deque<FolderFrame> pending = new ArrayDeque<>();
        pending.push(new FolderFrame(folder));
        while (!pending.isEmpty()) {
            if (matches.size() >= MAX_PROJECT_FILES || budget.exhausted()) {
                return;
            }

            FolderFrame frame = pending.peek();
            if (!frame.filesVisited) {
                frame.filesVisited = true;
                for (DomainFile file : frame.folder.getFiles()) {
                    if (matches.size() >= MAX_PROJECT_FILES || !budget.visitFile()) {
                        return;
                    }
                    if (matchesRequestedFile(file)) {
                        matches.add(file);
                    }
                }
                frame.children = frame.folder.getFolders();
            }

            if (frame.children == null || frame.nextChild >= frame.children.length) {
                pending.pop();
                continue;
            }

            DomainFolder child = frame.children[frame.nextChild++];
            if (!budget.visitFolder()) {
                return;
            }
            if (child != null) {
                pending.push(new FolderFrame(child));
            }
        }
    }

    private static final class FolderFrame {
        private final DomainFolder folder;
        private DomainFolder[] children;
        private int nextChild;
        private boolean filesVisited;

        private FolderFrame(DomainFolder folder) {
            this.folder = folder;
        }
    }

    private boolean matchesRequestedFile(DomainFile file) {
        if (!requestedFileName.equalsIgnoreCase(file.getName())) {
            return false;
        }

        // The launcher imports exactly one staged file into a fresh, isolated
        // project.  Ghidra's metadata is not a stable source-path identity:
        // some versions expose the import directory, some expose no path,
        // and some normalize the staged path differently.  Use the exact
        // filename as the project identity and let the caller reject any
        // duplicate matches before opening a program tool.
        return true;
    }

    private static Path parseInputPath(String configuredPath) {
        if (configuredPath == null || configuredPath.isBlank() || configuredPath.length() > MAX_PATH_LENGTH) {
            return null;
        }

        // SEC-C J5: reject UNC/extended prefixes, drive-relative spellings and
        // ".." before touching the filesystem. The launcher stages a local
        // file; network paths widen the trust boundary to a remote host,
        // drive-relative spellings (C:evil) resolve against the process CWD,
        // and ".." enables directory escape. DOS device segments resolve to
        // devices, not files, so they die here too (parity with .NET/native).
        String rawTrimmed = configuredPath.trim();
        if (isUncRawPath(rawTrimmed) || isExtendedPrefixRawPath(rawTrimmed) ||
            isDriveRelativeRawPath(rawTrimmed) || hasDotDotSegment(rawTrimmed) ||
            containsReservedDeviceSegment(rawTrimmed)) {
            return null;
        }

        try {
            Path path = Path.of(configuredPath).toAbsolutePath().normalize();
            if (isUncNormalizedPath(path) || hasDotDotSegment(path) ||
                containsReservedDeviceSegment(path) || !isLocalAbsolutePath(path)) {
                return null;
            }
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                !isSafeInputPath(path) || path.getFileName() == null || path.getFileName().toString().isBlank()) {
                return null;
            }
            return path;
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    /**
     * SEC-C J5: UNC and extended-path prefixes (network trust boundary).
     * Covers {@code \\server\share}, {@code \\?\...}, {@code \\.\...} and the
     * forward-slash forms ({@code //server/share}, {@code //?/...}).
     */
    private static boolean isUncRawPath(String rawTrimmed) {
        return rawTrimmed.startsWith("\\\\") || rawTrimmed.startsWith("//");
    }

    /**
     * Coverage G3: NT extended/device prefixes spelled out. The UNC gate above
     * already catches the doubled-separator forms; this additionally catches
     * the single-rooted NT form ({@code \??\C:\...}) which starts with one
     * backslash, and documents the {@code \\.\} / {@code //?/} intent.
     */
    private static boolean isExtendedPrefixRawPath(String rawTrimmed) {
        String upper = rawTrimmed.toUpperCase(Locale.ROOT);
        return upper.startsWith("\\\\.\\") || upper.startsWith("\\\\?\\") ||
            upper.startsWith("//./") || upper.startsWith("//?/") ||
            upper.startsWith("\\??\\") || upper.startsWith("/??/") ||
            upper.startsWith("\\??/") || upper.startsWith("/??\\");
    }

    /**
     * Coverage G3: drive-relative spellings ({@code C:evil}, {@code C:},
     * {@code C:foo\bar}) resolve against the per-drive CWD once absolutized,
     * laundering the local-absolute gate below. Reject the raw spelling
     * before {@code toAbsolutePath} runs. A bare {@code X:\...}/{@code X:/...}
     * root is not drive-relative.
     */
    private static boolean isDriveRelativeRawPath(String rawTrimmed) {
        if (rawTrimmed.length() < 2 || !Character.isLetter(rawTrimmed.charAt(0)) ||
            rawTrimmed.charAt(1) != ':') {
            return false;
        }
        return rawTrimmed.length() == 2 ||
            (rawTrimmed.charAt(2) != '\\' && rawTrimmed.charAt(2) != '/');
    }

    /**
     * Coverage G3: per-component DOS device scan shared by the raw and
     * normalized gates. Mirrors {@code LocalPathPolicy} (.NET) and
     * {@code PathHasDosDeviceComponent} (native): trailing dots/spaces are
     * ignored by Windows, and the stem ends at the first {@code .},
     * {@code :} or space, so {@code NUL.txt}, {@code CON }, {@code COM1.} and
     * {@code AUX:stream} all resolve to devices. Matching is ASCII
     * case-insensitive; non-ASCII stems are never devices. Extended-prefix
     * {@code ?} segments are not devices.
     */
    private static boolean isReservedDeviceStem(String stem) {
        if (stem.length() < 3 || stem.length() > 7) {
            return false;
        }
        for (int index = 0; index < stem.length(); index++) {
            if (stem.charAt(index) > 127) {
                return false;
            }
        }
        return RESERVED_DEVICE_NAMES.contains(stem.toUpperCase(Locale.ROOT));
    }

    private static boolean isReservedDeviceSegment(String segment) {
        String name = segment.trim();
        if (name.isEmpty()) {
            return false;
        }
        int end = name.length();
        while (end > 0 && (name.charAt(end - 1) == '.' || name.charAt(end - 1) == ' ')) {
            end--;
        }
        String stripped = name.substring(0, end);
        if (stripped.isEmpty()) {
            return false;
        }
        int stemEnd = 0;
        while (stemEnd < stripped.length()) {
            char current = stripped.charAt(stemEnd);
            if (current == '.' || current == ':' || current == ' ') {
                break;
            }
            stemEnd++;
        }
        String stem = stripped.substring(0, stemEnd);
        if (stem.isEmpty() || stem.equals("?") || stem.equals("$")) {
            return false;
        }
        return isReservedDeviceStem(stem);
    }

    private static boolean containsReservedDeviceSegment(String rawTrimmed) {
        for (String segment : rawTrimmed.split("[/\\\\]+")) {
            if (!segment.isEmpty() && isReservedDeviceSegment(segment)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsReservedDeviceSegment(Path normalized) {
        for (Path part : normalized) {
            if (isReservedDeviceSegment(part.toString())) {
                return true;
            }
        }
        return false;
    }

    /** True when any '/'- or '\'-separated segment is exactly "..". */
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
     * SEC-C J5: local absolute paths only. On Windows this means a drive-letter
     * absolute ({@code C:\...}); single-backslash-rooted, UNC and device paths
     * are rejected. On other OSes (unit fixtures) any POSIX absolute path
     * without a UNC prefix qualifies.
     */
    private static boolean isLocalAbsolutePath(Path normalized) {
        if (normalized == null || !normalized.isAbsolute()) {
            return false;
        }
        String text = normalized.toString();
        if (text.startsWith("\\\\") || text.startsWith("//")) {
            return false;
        }
        String os = System.getProperty("os.name", "");
        boolean windows = os.toLowerCase(Locale.ROOT).contains("win");
        if (windows) {
            return text.length() >= 3 &&
                Character.isLetter(text.charAt(0)) &&
                text.charAt(1) == ':' &&
                (text.charAt(2) == '\\' || text.charAt(2) == '/');
        }
        return text.startsWith("/");
    }

    private static boolean isSafeInputPath(Path path) {
        try {
            // Defense in depth with parseInputPath: UNC, "..", DOS device
            // segments and non-local absolutes are rejected here too.
            // Residual TOCTOU: this is a check-then-use validation; an
            // attacker with write access to the staging directory could swap
            // a component between validation and open. The launcher owns the
            // staging directory, and an open-by-handle (O_NOFOLLOW
            // per-component) traversal is a documented follow-up.
            if (path == null || !path.isAbsolute() ||
                isUncNormalizedPath(path) || hasDotDotSegment(path) ||
                containsReservedDeviceSegment(path) || !isLocalAbsolutePath(path)) {
                return false;
            }
            Path current = path;
            while (current != null) {
                BasicFileAttributes attributes = Files.readAttributes(
                    current,
                    BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS
                );
                if (attributes.isSymbolicLink() || attributes.isOther()) {
                    return false;
                }
                current = current.getParent();
            }
            return true;
        }
        catch (java.io.IOException | RuntimeException exception) {
            return false;
        }
    }

    private static final class SearchBudget {
        private int visitedEntries;

        private boolean visitFile() {
            if (exhausted()) {
                return false;
            }
            visitedEntries++;
            return true;
        }

        private boolean visitFolder() {
            if (exhausted()) {
                return false;
            }
            visitedEntries++;
            return true;
        }

        private boolean exhausted() {
            return visitedEntries >= MAX_VISITED_ENTRIES;
        }
    }
}
