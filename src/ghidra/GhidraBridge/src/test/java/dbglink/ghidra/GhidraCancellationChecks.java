package dbglink.ghidra;

import com.google.gson.JsonObject;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/// Concurrency contract of the bridge read/write gate.
///
/// <p>Reads used to be serialised by a one-permit semaphore: a second read-only
/// request waited behind the first. It now shares the read lock, so two
/// read-only dispatches are inside their handlers at the same time — that is
/// what the {@code bothInside} latch proves.</p>
///
/// <p>What must keep holding, and what this checks, is that a client which
/// disconnects mid-handler is cancelled instead of answered, and that the gate
/// is released afterwards so the next request is served.</p>
final class GhidraCancellationChecks {
    static void run() throws Exception {
        // The first two reads park in the handler until their request monitor is
        // cancelled, which is what makes "both inside at once" observable. Any
        // later read returns immediately, so the release check stays honest.
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch bothInside = new CountDownLatch(2);
        AtomicInteger seen = new AtomicInteger();
        GhidraBridgeServer server = new GhidraBridgeServer(() -> {
            if (seen.incrementAndGet() > 2) {
                return null;
            }
            entered.countDown();
            bothInside.countDown();
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (!GhidraBridgeServer.requestMonitor.get().isCancelled()) {
                if (System.nanoTime() > until) throw new AssertionError("Disconnect did not cancel request");
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            return null;
        });
        String token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var field = GhidraBridgeServer.class.getDeclaredField("tokenBytes");
        field.setAccessible(true);
        field.set(server, token.getBytes(StandardCharsets.UTF_8));
        var dispatch = GhidraBridgeServer.class.getDeclaredMethod("dispatch", JsonObject.class, Socket.class);
        dispatch.setAccessible(true);
        JsonObject request = new JsonObject();
        request.addProperty("id", 1);
        request.addProperty("token", token);
        request.addProperty("method", "status");
        ExecutorService worker = Executors.newFixedThreadPool(2);
        try (ServerSocket listener = new ServerSocket(0, 2, InetAddress.getLoopbackAddress());
              Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
              Socket accepted = listener.accept()) {
            Future<?> running = worker.submit(() -> {
                try { dispatch.invoke(server, request, accepted); }
                catch (Exception e) { throw new RuntimeException(e); }
                if (GhidraBridgeServer.requestMonitor.get() != null) throw new AssertionError("Monitor leaked");
            });
            if (!entered.await(2, TimeUnit.SECONDS)) throw new AssertionError("Request did not start");
            try (Socket queued = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
                 Socket queuedAccepted = listener.accept()) {
                Future<JsonObject> waiting = worker.submit(() -> (JsonObject) dispatch.invoke(server, request, queuedAccepted));

                // New contract: the second read is not queued behind the first,
                // so both are inside the handler at the same time.
                if (!bothInside.await(2, TimeUnit.SECONDS))
                    throw new AssertionError("Read-only requests did not run concurrently");

                // Old contract, unchanged: a client that disconnects while its
                // request is in flight is cancelled instead of answered.
                queued.close();
                JsonObject cancelled = waiting.get(2, TimeUnit.SECONDS);
                if (!cancelled.getAsJsonObject("error").get("code").getAsString().equals("ghidra_timeout"))
                    throw new AssertionError("Abandoned queued request was not cancelled");
            }
            client.close();
            running.get(4, TimeUnit.SECONDS);
            try (Socket next = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
                 Socket nextAccepted = listener.accept()) {
                JsonObject recovered = (JsonObject) dispatch.invoke(server, request, nextAccepted);
                if (!recovered.get("ok").getAsBoolean()) throw new AssertionError("Gate not released");
            }
        }
        finally { worker.shutdownNow(); }
    }
}
