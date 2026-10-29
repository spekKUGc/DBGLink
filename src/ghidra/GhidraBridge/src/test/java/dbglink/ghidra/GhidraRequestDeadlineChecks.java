package dbglink.ghidra;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

final class GhidraRequestDeadlineChecks {
    static void run() throws Exception {
        var workers = Executors.newSingleThreadExecutor();
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
             Socket accepted = listener.accept()) {
            // Every byte arrives within the idle timeout, but the whole request never completes.
            var reader = workers.submit(() -> {
                try {
                    GhidraBridgeServer.readLineLimited(accepted, 1024);
                    throw new AssertionError("An unterminated request was accepted");
                }
                catch (SocketTimeoutException expected) { return true; }
            });
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
            while (!reader.isDone() && System.nanoTime() < until) {
                client.getOutputStream().write(' ');
                client.getOutputStream().flush();
                Thread.sleep(100);
            }
            if (!reader.isDone()) throw new AssertionError("Slow input extended the request deadline");
            reader.get(1, TimeUnit.SECONDS);
        }
        finally { workers.shutdownNow(); }

        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
             Socket accepted = listener.accept()) {
            client.getOutputStream().write("{}\n".getBytes(StandardCharsets.UTF_8));
            if (!"{}".equals(GhidraBridgeServer.readLineLimited(accepted, 1024)))
                throw new AssertionError("A complete request was rejected");
        }
    }
}
