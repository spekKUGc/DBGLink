using System.Net;
using System.Net.Sockets;

namespace DbgLink.Tests;

/// <summary>
/// Thread-safe allocator of free loopback TCP ports for the tests that really
/// bind sockets (Kestrel via <c>LocalMcpServer.RunAsync</c> / <c>Program.RunAsync</c>:
/// <see cref="RealServerHarness"/>, the SDK <c>TestHost</c>, <c>ServerLifetimeTests</c>).
/// Candidates are probed on 127.0.0.1 inside 50500-50999 — clear of the contractual
/// default 50301, the verify-e2e base 50317 and the 504xx security-test ports — so
/// parallel test hosts and parallel test runs do not collide.
/// A probe-then-bind race is still theoretically possible; callers retry the bind
/// on <see cref="IOException"/>. Config-only tests never bind: they keep using
/// the default-port constant and must not allocate here.
/// </summary>
internal static class TestPortAllocator
{
    private const int MinPort = 50500;
    private const int MaxPort = 50999;
    private static readonly object Sync = new();
    private static readonly Random Rng = new();

    public static int GetFreePort()
    {
        lock (Sync)
        {
            var start = Rng.Next(MinPort, MaxPort + 1);
            for (var offset = 0; offset <= MaxPort - MinPort; offset++)
            {
                var candidate = MinPort + ((start - MinPort + offset) % (MaxPort - MinPort + 1));
                if (TryClaim(candidate, out var port))
                    return port;
            }
        }

        // Range exhausted (extremely unlikely): fall back to an OS-assigned ephemeral port.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static bool TryClaim(int candidate, out int port)
    {
        port = 0;
        try
        {
            using var listener = new TcpListener(IPAddress.Loopback, candidate);
            listener.Start();
            listener.Stop();
            port = candidate;
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
