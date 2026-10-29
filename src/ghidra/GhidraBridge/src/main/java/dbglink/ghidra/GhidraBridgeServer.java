package dbglink.ghidra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

/**
 * Small, bounded loopback bridge for the Ghidra Program API. Connections may
 * be read concurrently, while Program API operations remain serialized.
 *
 * <p>The protocol is deliberately JSON-lines and allowlisted. It is not an
 * RPC shell and never accepts a Ghidra script or class name from the client.</p>
 */
public final class GhidraBridgeServer implements AutoCloseable {

    static final Gson JSON = new GsonBuilder().disableHtmlEscaping().create();
    static final SecureRandom RANDOM = new SecureRandom();

    static final int PROTOCOL_VERSION = 1;
    static final int MAX_REQUEST_BYTES = 1024 * 1024;
    static final int MAX_RESPONSE_BYTES = 256 * 1024;
    static final int MAX_TOKEN_CHARS = 256;
    static final int MAX_SELECTOR_CHARS = 256;
    static final int MAX_DECOMP_SECONDS = 30;
    static final int REQUEST_READ_TIMEOUT_MILLISECONDS = 2_000;
    static final int MAX_BODY_CODE_UNITS = 100_000;
    static final int DEFAULT_MAX_ITEMS = 32;
    // Raised from 128: complete bodies of ~1.5 KB functions need several
    // hundred disassembly/reference rows before their char budget runs out.
    static final int MAX_ITEMS = 512;
    static final int MAX_PAGE_ITEMS = 512;
    static final int DEFAULT_MAX_CHARS = 24_000;
    static final int MAX_CHARS = 120_000;
    static final int DEFAULT_MAX_FUNCTIONS = 8;
    static final int MAX_MODULE_FUNCTIONS = 128;
    // AnalyzeFunctions is a per-call digest: at most 8 functions with at most
    // 32 strings/constants/references each, so a single turn stays bounded.
    static final int MAX_ANALYZE_FUNCTIONS = 8;
    static final int DEFAULT_ANALYZE_ITEMS = 4;
    static final int MAX_ANALYZE_ITEMS = 32;
    static final int MAX_CALLGRAPH_NODES = 256;
    static final int MAX_CALLGRAPH_EDGES = 1024;
    static final int DEFAULT_CALLGRAPH_NODES = 64;
    static final int DEFAULT_CALLGRAPH_EDGES = 256;
    static final int MAX_SYMBOL_NAME_CHARS = 128;
    static final int MAX_COMMENT_CHARS = 8_192;
    static final int MAX_BATCH_ANNOTATE_OPERATIONS = 16;
    static final int MAX_JSON_DEPTH = 16;
    static final int MAX_JSON_CONTAINER_ENTRIES = 512;
    static final int MAX_TYPE_SCAN_ITEMS = 100_000;
    static final int RESPONSE_WRITE_TIMEOUT_MILLISECONDS = 5_000;
    static final int MAX_CONNECTION_WORKERS = 4;
    static final int MAX_PENDING_CONNECTIONS = 16;
    private static final ThreadLocal<byte[]> REQUEST_CHUNK =
        ThreadLocal.withInitial(() -> new byte[4096]);
    private static final ThreadLocal<ReusableByteArrayOutputStream> REQUEST_BUFFER =
        ThreadLocal.withInitial(() -> new ReusableByteArrayOutputStream(4096));

    static final Set<String> INSPECT_FIELDS = Set.of(
        "function",
        "maxChars",
        "maxItems",
        "includeDecomp",
        "includeDisassembly",
        "includeReferences",
        "includeSymbols",
        "includeStrings",
        "includeConstants"
    );
    static final Set<String> ANALYZE_FUNCTIONS_FIELDS = Set.of(
        "functions",
        "start",
        "maxFunctions",
        "maxChars",
        "maxItems",
        "includeComments",
        "includePrototype",
        "includeDecomp"
    );
    static final Set<String> ANALYSIS_QUEUE_FIELDS = Set.of(
        "limit",
        "module",
        "excludeAnnotated",
        "includeRva"
    );
    static final Set<String> DECOMPILE_MODULE_FIELDS = Set.of(
        "module",
        "function",
        "start",
        "maxFunctions",
        "maxChars",
        "includePrototype"
    );
    static final Set<String> CALLGRAPH_FIELDS = Set.of(
        "module",
        "function",
        "depth",
        "direction",
        "start",
        "end",
        "maxNodes",
        "maxEdges",
        "includeInstructionCount",
        "edgeFormat"
    );
    static final Set<String> CREATE_FUNCTION_FIELDS = Set.of("address", "name");
    static final Set<String> SAVE_PROGRAM_FIELDS = Set.of("module");
    static final Set<String> RENAME_FUNCTION_FIELDS = Set.of("function", "name");
    static final Set<String> SET_FUNCTION_COMMENT_FIELDS = Set.of("function", "comment");
    static final Set<String> RENAME_VARIABLE_FIELDS = Set.of("function", "variable", "name");
    static final Set<String> SET_VARIABLE_TYPE_FIELDS = Set.of("function", "variable", "type");
    static final Set<String> BATCH_ANNOTATE_FIELDS = Set.of("operations");

    private final GhidraAnalysisOperations analysis;
    private final GhidraStaticQueries staticQueries;
    /**
     * Read/write split over the Ghidra Program API. Read-only methods
     * (status, InspectFunction, AnalyzeFunctions, GetAnalysisQueue,
     * DecompileModule, CallGraph and every static query) take the read lock, so
     * several clients are served at once instead of queueing behind each other.
     * Only the mutation methods take the write lock, which is also what keeps a
     * rename or comment from overlapping a decompile that is reading the same
     * program.
     *
     * <p>Everything that is not a proven read-only method takes the write lock:
     * an unrecognised method must never be allowed to run concurrently with a
     * mutation.</p>
     */
    private final ReentrantReadWriteLock programLock = new ReentrantReadWriteLock();
    private final AtomicBoolean closed = new AtomicBoolean(true);
    private volatile long lifecycleGeneration;

    private ServerSocket listener;
    private Thread acceptThread;
    private Path endpointPath;
    private String token;
    private volatile byte[] tokenBytes;
    private ThreadPoolExecutor connectionExecutor;
    private ThreadPoolExecutor responseWriterExecutor;
    private final Set<Socket> activeSockets = ConcurrentHashMap.newKeySet();

    public GhidraBridgeServer(Supplier<Program> programSupplier) {
        this.analysis = new GhidraAnalysisOperations(programSupplier);
        this.staticQueries = new GhidraStaticQueries(programSupplier);
    }

    public synchronized void start() throws IOException {
        if (!closed.get()) {
            return;
        }

        int requestedPort = GhidraEndpointSecurity.readPort();
        String newToken = GhidraEndpointSecurity.readToken();
        ServerSocket newListener = new ServerSocket(
            requestedPort,
            16,
            InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 })
        );
        boolean endpointWritten = false;

        try {
            token = newToken;
            tokenBytes = newToken.getBytes(StandardCharsets.UTF_8);
            endpointPath = GhidraEndpointSecurity.createEndpointPath();
            GhidraEndpointSecurity.writeEndpoint(endpointPath, newListener.getLocalPort(), token);
            endpointWritten = true;
            listener = newListener;
            connectionExecutor = createBoundedExecutor("DBGLink-Ghidra-Bridge-Connection");
            responseWriterExecutor = createBoundedExecutor("DBGLink-Ghidra-Bridge-Writer");
            closed.set(false);
            long generation = ++lifecycleGeneration;
            acceptThread = new Thread(() -> acceptLoop(generation), "DBGLink-Ghidra-Bridge");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }
        catch (IOException | RuntimeException exception) {
            ThreadPoolExecutor executor = connectionExecutor;
            connectionExecutor = null;
            if (executor != null) {
                executor.shutdownNow();
            }
            ThreadPoolExecutor writerExecutor = responseWriterExecutor;
            responseWriterExecutor = null;
            if (writerExecutor != null) {
                writerExecutor.shutdownNow();
            }
            try {
                newListener.close();
            }
            catch (IOException ignored) {
                // Preserve the original startup failure.
            }
            if (endpointWritten && endpointPath != null && GhidraEndpointSecurity.isSafePath(endpointPath)) {
                try {
                    Files.deleteIfExists(endpointPath);
                }
                catch (IOException ignored) {
                    // Preserve the original startup failure and leave the
                    // stale endpoint harmless because the token is discarded below.
                }
            }
            listener = null;
            closed.set(true);
            endpointPath = null;
            token = null;
            tokenBytes = null;
            throw exception;
        }
    }

    @Override
    public synchronized void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        lifecycleGeneration++;

        ServerSocket listenerSocket = listener;
        listener = null;
        if (listenerSocket != null) {
            try {
                listenerSocket.close();
            }
            catch (IOException ignored) {
                // The bridge is already shutting down.
            }
        }

        Thread thread = acceptThread;
        acceptThread = null;
        if (thread != null) {
            thread.interrupt();
            if (thread != Thread.currentThread()) {
                try {
                    thread.join(RESPONSE_WRITE_TIMEOUT_MILLISECONDS);
                }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        closeActiveSockets();

        ThreadPoolExecutor executor = connectionExecutor;
        connectionExecutor = null;
        if (executor != null) {
            executor.shutdownNow();
            try {
                executor.awaitTermination(RESPONSE_WRITE_TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        ThreadPoolExecutor writerExecutor = responseWriterExecutor;
        responseWriterExecutor = null;
        if (writerExecutor != null) {
            writerExecutor.shutdownNow();
            try {
                writerExecutor.awaitTermination(RESPONSE_WRITE_TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        closeActiveSockets();

        // The write lock excludes every in-flight reader before the decompile
        // processes are disposed, exactly as the object monitor did before.
        programLock.writeLock().lock();
        try {
            analysis.close();
        }
        finally {
            programLock.writeLock().unlock();
        }

        Path endpoint = endpointPath;
        endpointPath = null;
        token = null;
        tokenBytes = null;
        if (endpoint != null) {
            try {
                if (GhidraEndpointSecurity.isSafePath(endpoint)) {
                    Files.deleteIfExists(endpoint);
                }
            }
            catch (IOException ignored) {
                // A stale endpoint is harmless; the token is no longer valid.
            }
        }
    }

    private void acceptLoop(long generation) {
        while (!closed.get() && lifecycleGeneration == generation) {
            try {
                ServerSocket currentListener = listener;
                if (currentListener == null) {
                    break;
                }
                Socket socket = currentListener.accept();
                if (closed.get() || lifecycleGeneration != generation) {
                    socket.close();
                    break;
                }

                activeSockets.add(socket);
                try {
                    ThreadPoolExecutor executor = connectionExecutor;
                    if (executor == null) {
                        throw new RejectedExecutionException("bridge is stopping");
                    }
                    executor.execute(() -> {
                        try {
                            handleConnection(socket);
                        }
                        catch (RuntimeException exception) {
                            // A malformed client must not terminate a worker.
                        }
                        finally {
                            activeSockets.remove(socket);
                        }
                    });
                }
                catch (RejectedExecutionException exception) {
                    activeSockets.remove(socket);
                    try {
                        socket.close();
                    }
                    catch (IOException ignored) {
                        // The client is already being rejected.
                    }
                }
            }
            catch (IOException exception) {
                if (closed.get() || lifecycleGeneration != generation) {
                    break;
                }
                // A transient accept failure must not permanently disable the
                // bridge. Avoid a hot retry loop if the socket is unhealthy.
                try {
                    Thread.sleep(50);
                }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            catch (RuntimeException exception) {
                if (!closed.get() && lifecycleGeneration == generation) {
                    // A malformed client must not kill the bridge accept loop,
                    // and a transient runtime failure must not cause a hot retry loop.
                    try {
                        Thread.sleep(50);
                    }
                    catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
    }

    private static ThreadPoolExecutor createBoundedExecutor(String threadName) {
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, threadName);
            thread.setDaemon(true);
            return thread;
        };
        return new ThreadPoolExecutor(
            MAX_CONNECTION_WORKERS,
            MAX_CONNECTION_WORKERS,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(MAX_PENDING_CONNECTIONS),
            factory,
            new ThreadPoolExecutor.AbortPolicy()
        );
    }

    private void closeActiveSockets() {
        for (Socket socket : activeSockets) {
            try {
                socket.close();
            }
            catch (IOException ignored) {
                // The connection is already being torn down.
            }
        }
    }

    private void handleConnection(Socket socket) {
        // SEC-C J3: the request deadline runs from arrival (accept), not from
        // dispatch. Queued requests share the same 30 s budget; already-expired
        // arrivals are dropped without touching Program APIs.
        long arrivalNanos = System.nanoTime();
        try (socket) {
            // Decompilation happens after the complete request is parsed and
            // does not require an unauthenticated client to hold the input
            // socket open for the entire decompiler deadline.
            socket.setSoTimeout(REQUEST_READ_TIMEOUT_MILLISECONDS);
            String line;
            try {
                line = readLineLimited(socket, MAX_REQUEST_BYTES);
            }
            catch (IOException exception) {
                writeResponse(socket, errorResponse(
                    JsonNull.INSTANCE,
                    "invalid_request",
                    "request could not be read within the bridge limits"
                ));
                return;
            }
            if (line == null) {
                return;
            }

            JsonObject response;
            try {
                response = dispatch(GhidraRequestParser.parseRequest(line), socket, arrivalNanos);
            }
            catch (BridgeFailure exception) {
                response = errorResponse(JsonNull.INSTANCE, exception.code, exception.getMessage());
            }
            catch (IOException | JsonParseException | IllegalStateException exception) {
                response = errorResponse(JsonNull.INSTANCE, "invalid_json", "request is not valid JSON");
            }
            catch (RuntimeException exception) {
                response = errorResponse(JsonNull.INSTANCE, "bridge_error", "bridge request failed");
            }

            writeResponse(socket, response);
        }
        catch (IOException ignored) {
            // The client may disconnect while the response is being written.
        }
    }

    static final ThreadLocal<TaskMonitor> requestMonitor = new ThreadLocal<>();

    /**
     * Method names served entirely from read-only state. Derived: the static
     * queries come from the owner of that allowlist ({@link
     * GhidraStaticQueries#METHODS}) so the two cannot drift, and the analysis
     * side lists its reads explicitly. Anything not here — mutations and any
     * unrecognised method — takes the write lock.
     */
    private static final Set<String> READ_ONLY_METHODS = readOnlyMethods();

    private static Set<String> readOnlyMethods() {
        Set<String> readOnly = new java.util.HashSet<>(GhidraStaticQueries.METHODS);
        readOnly.add("status");
        readOnly.add("InspectFunction");
        readOnly.add("AnalyzeFunctions");
        readOnly.add("GetAnalysisQueue");
        readOnly.add("DecompileModule");
        readOnly.add("CallGraph");
        return Collections.unmodifiableSet(readOnly);
    }

    private JsonObject dispatch(JsonObject request, Socket socket) throws BridgeFailure, IOException {
        return dispatch(request, socket, System.nanoTime());
    }

    private JsonObject dispatch(JsonObject request, Socket socket, long arrivalNanos)
        throws BridgeFailure, IOException {
        JsonElement id = request.has("id") ? request.get("id") : JsonNull.INSTANCE;
        validateId(id);

        String presentedToken = requiredString(request, "token", MAX_TOKEN_CHARS);
        if (!GhidraEndpointSecurity.constantTimeEquals(tokenBytes, presentedToken)) {
            return errorResponse(id, "unauthorized", "invalid bridge token");
        }

        String method = requiredString(request, "method", 64);
        JsonObject params = new JsonObject();
        if (request.has("params")) {
            JsonElement paramsElement = request.get("params");
            if (!paramsElement.isJsonObject()) {
                throw new BridgeFailure("invalid_params", "params must be a JSON object");
            }
            params = paramsElement.getAsJsonObject();
        }

        // SEC-C J3: queue time shares the arrival deadline. An arrival that
        // already exhausted its 30 s budget is dropped before touching Program
        // APIs; otherwise the monitor is armed with the remaining budget so a
        // queued waiter cannot outlive arrival + MAX_DECOMP_SECONDS.
        long deadlineNanos = arrivalNanos + TimeUnit.SECONDS.toNanos(MAX_DECOMP_SECONDS);
        if (System.nanoTime() >= deadlineNanos) {
            return errorResponse(id, "ghidra_timeout", "Request expired while queued");
        }
        long remainingNanos = Math.max(1L, deadlineNanos - System.nanoTime());
        long remainingMillis = Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
        TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(remainingMillis, TimeUnit.MILLISECONDS);
        requestMonitor.set(monitor);
        java.util.concurrent.atomic.AtomicBoolean finished = new java.util.concurrent.atomic.AtomicBoolean();
        Thread disconnectWatcher = new Thread(() -> {
            try {
                while (!finished.get()) {
                    try {
                        // Protocol permits one request per connection. EOF means cancellation.
                        socket.getInputStream().read();
                        if (!finished.get()) monitor.cancel();
                        return;
                    }
                    catch (java.net.SocketTimeoutException ignored) { }
                }
            }
            catch (IOException ignored) {
                if (!finished.get()) monitor.cancel();
            }
        }, "DBGLink-Ghidra-Cancellation");
        disconnectWatcher.setDaemon(true);
        // SEC-C J3: the deadline runs from arrival, so the remaining budget is
        // whatever is left of the arrival + MAX_DECOMP_SECONDS window.
        boolean readOnly = READ_ONLY_METHODS.contains(method);
        // Read-only methods share the read lock; everything else — including an
        // unrecognised method — is held to the write lock so it can never overlap
        // a mutation. ReadLock and WriteLock are sibling types with no common
        // supertype, so the unlock below is chosen from the same flag that picks
        // the gate.
        //
        // ReentrantReadWriteLock has no blocking, cancellable acquire. A read lock
        // is never blocked by other readers, and a write lock can only wait on
        // read methods that are themselves bounded by MAX_DECOMP_SECONDS, so the
        // arrival deadline armed above still bounds the whole request.
        JsonObject response;
        try {
            socket.setSoTimeout(100);
            disconnectWatcher.start();
            if (readOnly) {
                programLock.readLock().lock();
            }
            else {
                programLock.writeLock().lock();
            }
            try {
                if (monitor.isCancelled()) return errorResponse(id, "ghidra_timeout", "Request cancelled");
                if (System.nanoTime() >= deadlineNanos) {
                    return errorResponse(id, "ghidra_timeout", "Request expired while queued");
                }
                response = switch (method) {
                    case "status" -> successResponse(id, analysis.status());
                    case "InspectFunction" -> successResponse(id, analysis.inspectFunction(params));
                    case "AnalyzeFunctions" -> successResponse(id, analysis.analyzeFunctions(params));
                    case "GetAnalysisQueue" -> successResponse(id, analysis.analysisQueue(params));
                    case "SubmitAnnotations" -> successResponse(id, analysis.submitAnnotations(params));
                    case "DecompileModule" -> successResponse(id, analysis.decompileModule(params));
                    case "CallGraph" -> successResponse(id, analysis.callGraph(params));
                    case "CreateFunction" -> successResponse(id, analysis.createFunction(params));
                    case "RenameFunction" -> successResponse(id, analysis.renameFunction(params));
                    case "SetFunctionComment" -> successResponse(id, analysis.setFunctionComment(params));
                    case "RenameVariable" -> successResponse(id, analysis.renameVariable(params));
                    case "SetVariableType" -> successResponse(id, analysis.setVariableType(params));
                    case "BatchAnnotate" -> successResponse(id, analysis.batchAnnotate(params));
                    case "SaveProgram" -> successResponse(id, analysis.saveProgram(params));
                    default -> GhidraStaticQueries.METHODS.contains(method)
                        ? successResponse(id, staticQueries.execute(method, params))
                        : errorResponse(id, "method_not_allowed", "method is not allowlisted");
                };
            }
            finally {
                if (readOnly) {
                    programLock.readLock().unlock();
                }
                else {
                    programLock.writeLock().unlock();
                }
            }
            // A client that disconnected mid-handler must not be told its read
            // succeeded. With the queue removed the handler may already have
            // finished by the time the disconnect watcher cancels the monitor,
            // so the cancellation is also honoured here, not only before the
            // switch. This keeps "abandoned in-flight request is cancelled"
            // true for reads that now run concurrently instead of waiting.
            if (monitor.isCancelled()) {
                return errorResponse(id, "ghidra_timeout", "Request cancelled");
            }
            return response;
        }
        catch (BridgeFailure exception) {
            return errorResponse(id, exception.code, exception.getMessage());
        }
        catch (RuntimeException exception) {
            return errorResponse(id, "program_api_error", "Ghidra Program API operation failed");
        }
        finally {
            finished.set(true);
            monitor.finished();
            requestMonitor.remove();
        }
    }

    static void rejectUnknownFields(JsonObject object, Set<String> allowed, String method)
        throws BridgeFailure {
        for (String field : object.keySet()) {
            if (!allowed.contains(field)) {
                throw new BridgeFailure("unknown_argument", "unsupported " + method + " argument");
            }
        }
    }

    static int boundedInt(JsonObject object, String name, int defaultValue, int min, int max)
        throws BridgeFailure {
        if (!object.has(name)) {
            return defaultValue;
        }
        JsonElement value = object.get(name);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            throw new BridgeFailure("invalid_argument", name + " must be an integer");
        }
        try {
            String raw = value.getAsString();
            if (!isIntegerLiteral(raw)) {
                throw new BridgeFailure("invalid_argument", name + " must be an integer");
            }
            int parsed = Integer.parseInt(raw);
            if (parsed < min || parsed > max) {
                throw new BridgeFailure("argument_out_of_range", name + " is outside the allowed range");
            }
            return parsed;
        }
        catch (NumberFormatException exception) {
            throw new BridgeFailure("invalid_argument", name + " must be an integer");
        }
    }

    static boolean boundedBoolean(JsonObject object, String name, boolean defaultValue)
        throws BridgeFailure {
        if (!object.has(name)) {
            return defaultValue;
        }
        JsonElement value = object.get(name);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw new BridgeFailure("invalid_argument", name + " must be a boolean");
        }
        return value.getAsBoolean();
    }

    static String requiredString(JsonObject object, String name, int maxChars) throws BridgeFailure {
        JsonElement value = object.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new BridgeFailure("missing_argument", name + " must be a string");
        }
        String text = value.getAsString();
        validateTextCharacters(text, name, false);
        text = text.trim();
        if (text.isEmpty()) {
            throw new BridgeFailure("missing_argument", name + " must not be empty");
        }
        if (text.length() > maxChars) {
            throw new BridgeFailure("argument_too_long", name + " exceeds the character limit");
        }
        return text;
    }

    static String boundedText(JsonObject object, String name, int maxChars, boolean allowEmpty)
        throws BridgeFailure {
        JsonElement value = object.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new BridgeFailure("missing_argument", name + " must be a string");
        }
        String text = value.getAsString();
        if (!allowEmpty && text.isEmpty()) {
            throw new BridgeFailure("missing_argument", name + " must not be empty");
        }
        if (text.length() > maxChars) {
            throw new BridgeFailure("argument_too_long", name + " exceeds the character limit");
        }
        validateTextCharacters(text, name, true);
        return text;
    }

    static String optionalString(JsonObject object, String name, int maxChars) throws BridgeFailure {
        if (!object.has(name) || object.get(name).isJsonNull()) {
            return "";
        }
        JsonElement value = object.get(name);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new BridgeFailure("invalid_argument", name + " must be a string");
        }
        String text = value.getAsString();
        validateTextCharacters(text, name, false);
        text = text.trim();
        if (text.length() > maxChars) {
            throw new BridgeFailure("argument_too_long", name + " exceeds the character limit");
        }
        return text;
    }

    static boolean matchesActiveModule(Program program, String selector) {
        if (selector == null || selector.isBlank()) {
            return true;
        }
        String normalizedSelector = selector.replace('\\', '/');
        String actualExecutable = program.getExecutablePath();
        String displayExecutable = GhidraAnalysisFormatting.displayExecutablePath(program);
        String normalizedExecutable = actualExecutable == null ? "" : actualExecutable.replace('\\', '/');
        String normalizedDisplayExecutable = displayExecutable.replace('\\', '/');
        if (normalizedSelector.equalsIgnoreCase(normalizedExecutable) ||
            normalizedSelector.equalsIgnoreCase(normalizedDisplayExecutable)) {
            return true;
        }
        // A selector containing a path is authoritative. Falling back to a
        // basename here can silently resolve the wrong binary when two
        // modules share a filename.
        if (normalizedSelector.indexOf('/') >= 0) {
            return false;
        }
        int separator = normalizedSelector.lastIndexOf('/');
        String selectorName = separator >= 0 ? normalizedSelector.substring(separator + 1) : normalizedSelector;
        separator = normalizedExecutable.lastIndexOf('/');
        String executableName = separator >= 0 ? normalizedExecutable.substring(separator + 1) : normalizedExecutable;
        separator = normalizedDisplayExecutable.lastIndexOf('/');
        String displayExecutableName = separator >= 0
            ? normalizedDisplayExecutable.substring(separator + 1)
            : normalizedDisplayExecutable;
        return !selectorName.isBlank() &&
            (selectorName.equalsIgnoreCase(executableName) ||
             selectorName.equalsIgnoreCase(displayExecutableName));
    }

    static boolean isIntegerLiteral(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        int index = value.charAt(0) == '-' ? 1 : 0;
        if (index == value.length()) {
            return false;
        }
        if (value.charAt(index) == '0' && index + 1 < value.length()) {
            return false;
        }
        for (; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < '0' || character > '9') {
                return false;
            }
        }
        return true;
    }

    static void validateTextCharacters(String text, String name, boolean allowLineBreaks)
        throws BridgeFailure {
        for (int offset = 0; offset < text.length();) {
            int codePoint = text.codePointAt(offset);
            int charCount = Character.charCount(codePoint);
            if (codePoint >= 0xD800 && codePoint <= 0xDFFF) {
                throw new BridgeFailure("invalid_argument", name + " contains invalid Unicode text");
            }
            if (Character.isISOControl(codePoint) &&
                !(allowLineBreaks && (codePoint == '\n' || codePoint == '\r' || codePoint == '\t'))) {
                throw new BridgeFailure("invalid_argument", name + " contains a control character");
            }
            if (isBlockedBidiOrFormatControl(codePoint)) {
                throw new BridgeFailure(
                    "invalid_argument", name + " contains a bidirectional or formatting control character");
            }
            offset += charCount;
        }
    }

    /**
     * SEC-C J9: bidi overrides/isolates and invisible format controls enable
     * display spoofing in names and comments (e.g. U+202E flips the rendered
     * order, U+FEFF/U+200B hide text). All validated bridge text rejects them;
     * comments allow only \n \r \t among controls.
     */
    private static boolean isBlockedBidiOrFormatControl(int codePoint) {
        if (codePoint == 0x00AD || codePoint == 0x061C || codePoint == 0xFEFF || codePoint == 0x2060) {
            return true;
        }
        if (codePoint >= 0x200B && codePoint <= 0x200F) {
            return true;
        }
        if (codePoint >= 0x202A && codePoint <= 0x202E) {
            return true;
        }
        if (codePoint >= 0x2066 && codePoint <= 0x2069) {
            return true;
        }
        return false;
    }

    private static void validateId(JsonElement id) throws BridgeFailure {
        if (id == null || id.isJsonNull()) {
            throw new BridgeFailure("missing_argument", "id is required");
        }
        if (!id.isJsonPrimitive()) {
            throw new BridgeFailure("invalid_argument", "id must be a string or number");
        }
        JsonPrimitive primitive = id.getAsJsonPrimitive();
        if ((!primitive.isString() && !primitive.isNumber()) || id.toString().length() > 128) {
            throw new BridgeFailure("invalid_argument", "id must be a bounded string or number");
        }
    }

    private static JsonObject successResponse(JsonElement id, JsonElement result) {
        JsonObject response = new JsonObject();
        response.add("id", id == null ? JsonNull.INSTANCE : id);
        response.addProperty("ok", true);
        response.add("result", result == null ? JsonNull.INSTANCE : result);
        return response;
    }

    private static JsonObject errorResponse(JsonElement id, String code, String message) {
        JsonObject response = new JsonObject();
        response.add("id", id == null ? JsonNull.INSTANCE : id);
        response.addProperty("ok", false);
        JsonObject error = new JsonObject();
        error.addProperty("code", clipped(code, 64));
        error.addProperty("message", clipped(message, 512));
        response.add("error", error);
        return response;
    }

    private void writeResponse(Socket socket, JsonObject response) throws IOException {
        String serialized = JSON.toJson(response);
        byte[] bytes = serialized.getBytes(StandardCharsets.UTF_8);
        if (bytes.length + 1 > MAX_RESPONSE_BYTES) {
            serialized = JSON.toJson(errorResponse(
                response.get("id"),
                "response_too_large",
                "response exceeded the bridge byte limit"
            ));
            bytes = serialized.getBytes(StandardCharsets.UTF_8);
        }

        final byte[] responseBytes = bytes;
        OutputStream output = socket.getOutputStream();
        FutureTask<Void> writeTask = new FutureTask<>(() -> {
            output.write(responseBytes);
            output.write('\n');
            output.flush();
            return null;
        });
        ThreadPoolExecutor executor = responseWriterExecutor;
        if (executor == null) {
            throw new IOException("bridge response writer is stopping");
        }
        try {
            executor.execute(writeTask);
        }
        catch (RejectedExecutionException exception) {
            throw new IOException("bridge response writer queue is full", exception);
        }
        try {
            writeTask.get(RESPONSE_WRITE_TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
        }
        catch (TimeoutException exception) {
            writeTask.cancel(true);
            try {
                socket.close();
            }
            catch (IOException ignored) {
                // The write is already being abandoned.
            }
            throw new IOException("bridge response write exceeded its deadline", exception);
        }
        catch (InterruptedException exception) {
            writeTask.cancel(true);
            try {
                socket.close();
            }
            catch (IOException ignored) {
                // The write is already being abandoned.
            }
            Thread.currentThread().interrupt();
            throw new IOException("bridge response write was interrupted", exception);
        }
        catch (java.util.concurrent.CancellationException exception) {
            throw new IOException("bridge response write was cancelled", exception);
        }
        catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("bridge response write failed", cause);
        }
    }

    static String readLineLimited(Socket socket, int maxBytes) throws IOException {
        InputStream input = socket.getInputStream();
        long deadline = System.nanoTime() +
            TimeUnit.MILLISECONDS.toNanos(REQUEST_READ_TIMEOUT_MILLISECONDS);
        ReusableByteArrayOutputStream buffer = REQUEST_BUFFER.get();
        buffer.reset();
        byte[] chunk = REQUEST_CHUNK.get();
        boolean readAny = false;
        boolean terminated = false;
        int read;
        while (true) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                throw new java.net.SocketTimeoutException("request read deadline exceeded");
            }
            socket.setSoTimeout((int)Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
            read = input.read(chunk);
            if (System.nanoTime() >= deadline) {
                throw new java.net.SocketTimeoutException("request read deadline exceeded");
            }
            if (read == -1) break;
            if (read == 0) {
                continue;
            }
            readAny = true;
            int newline = -1;
            for (int index = 0; index < read; index++) {
                if (chunk[index] == '\n') {
                    newline = index;
                    break;
                }
            }

            int count = newline >= 0 ? newline : read;
            if (buffer.size() > maxBytes - count) {
                throw new IOException("request too large");
            }
            buffer.write(chunk, 0, count);
            if (newline >= 0) {
                if (newline + 1 != read) {
                    throw new IOException("request contains trailing bytes after its newline terminator");
                }
                terminated = true;
                break;
            }
        }
        if (!readAny && buffer.size() == 0) {
            return null;
        }
        if (!terminated) {
            throw new IOException("request is missing its newline terminator");
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(buffer.buffer(), 0, buffer.length()))
                .toString();
        }
        catch (CharacterCodingException exception) {
            throw new IOException("request encoding is invalid", exception);
        }
    }

    private static final class ReusableByteArrayOutputStream extends ByteArrayOutputStream {
        ReusableByteArrayOutputStream(int initialSize) {
            super(initialSize);
        }

        byte[] buffer() {
            return buf;
        }

        int length() {
            return count;
        }
    }

    static String rva(Program program, Address address) {
        Address imageBase = program.getImageBase();
        if (!address.hasSameAddressSpace(imageBase)) {
            return null;
        }
        if (address.compareTo(imageBase) < 0) {
            return null;
        }
        try {
            return "0x" + Long.toUnsignedString(address.subtract(imageBase), 16);
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    static String clipped(String value, int maxChars) {
        if (value == null || maxChars <= 0) {
            return "";
        }
        if (value.length() <= maxChars) {
            return value;
        }

        int prefixLength = Math.max(0, maxChars - 1);
        if (prefixLength > 0 && Character.isHighSurrogate(value.charAt(prefixLength - 1))) {
            prefixLength--;
        }
        return value.substring(0, prefixLength) + "…";
    }

}
