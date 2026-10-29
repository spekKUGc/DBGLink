using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class GhidraClientCacheTests
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

    [Fact]
    public async Task InspectFunction_RepeatedAfterTwoSeconds_ServedFromCache()
    {
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits);
            var bytes = StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{}}\n");
            await stream.WriteAsync(bytes, cts.Token);
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var args = JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement;
            var first = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"ok\":true", first);
            await Task.Delay(TimeSpan.FromMilliseconds(2100), cts.Token);
            var second = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"ok\":true", second);
            await serve;
            Assert.Equal(1, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task RenameFunction_InvalidatesStaticCache()
    {
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            for (var i = 0; i < 3; i++)
            {
                using var peer = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = peer.GetStream();
                var body = await ReadRequestLineAsync(stream);
                Interlocked.Increment(ref hits);
                using var doc = JsonDocument.Parse(body);
                var id = doc.RootElement.GetProperty("id").GetInt32();
                var bytes = StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{}}\n");
                await stream.WriteAsync(bytes, cts.Token);
            }
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var args = JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement;
            await client.RequestAsync("InspectFunction", args, cts.Token);
            await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Equal(1, Volatile.Read(ref hits));
            var rename = JsonDocument.Parse("{\"address\":\"00401000\",\"name\":\"f\"}").RootElement;
            await client.RequestAsync("RenameFunction", rename, cts.Token);
            await client.RequestAsync("InspectFunction", args, cts.Token);
            await serve;
            Assert.Equal(3, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task NewEndpointDirectory_MissesCache()
    {
        var dir1 = NewDir();
        var dir2 = NewDir();
        using var listener1 = new TcpListener(System.Net.IPAddress.Loopback, 0);
        using var listener2 = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener1.Start();
        listener2.Start();
        var port1 = ((System.Net.IPEndPoint)listener1.LocalEndpoint).Port;
        var port2 = ((System.Net.IPEndPoint)listener2.LocalEndpoint).Port;
        WriteEndpoint(dir1, port1);
        WriteEndpoint(dir2, port2);
        var hits1 = 0;
        var hits2 = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve1 = Task.Run(async () =>
        {
            using var peer = await listener1.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits1);
            await stream.WriteAsync(StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"n\":1}}\n"), cts.Token);
        }, cts.Token);
        var serve2 = Task.Run(async () =>
        {
            using var peer = await listener2.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits2);
            await stream.WriteAsync(StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"n\":2}}\n"), cts.Token);
        }, cts.Token);
        try
        {
            var args = JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement;
            var first = await new GhidraClient(dir1).RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"n\":1", first);
            var second = await new GhidraClient(dir2).RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"n\":2", second);
            await Task.WhenAll(serve1, serve2);
            Assert.Equal(1, Volatile.Read(ref hits1));
            Assert.Equal(1, Volatile.Read(ref hits2));
        }
        finally
        {
            listener1.Stop();
            listener2.Stop();
            Directory.Delete(dir1, true);
            Directory.Delete(dir2, true);
        }
    }

    [Fact]
    public async Task SameClient_SeesNewEndpointFile_AsMiss()
    {
        var dir = NewDir();
        using var listener1 = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener1.Start();
        var port1 = ((System.Net.IPEndPoint)listener1.LocalEndpoint).Port;
        WriteEndpoint(dir, port1);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var hits1 = 0;
        var serve1 = Task.Run(async () =>
        {
            using var peer = await listener1.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits1);
            await stream.WriteAsync(StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"v\":1}}\n"), cts.Token);
        }, cts.Token);
        using var listener2 = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener2.Start();
        var port2 = ((System.Net.IPEndPoint)listener2.LocalEndpoint).Port;
        var hits2 = 0;
        var serve2 = Task.Run(async () =>
        {
            using var peer = await listener2.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits2);
            await stream.WriteAsync(StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"v\":2}}\n"), cts.Token);
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var args = JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement;
            var first = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"v\":1", first);
            await serve1;
            listener1.Stop();
            WriteEndpoint(dir, port2, overwrite: true);
            await Task.Delay(TimeSpan.FromMilliseconds(5100), cts.Token);
            var second = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"v\":2", second);
            await serve2;
            Assert.Equal(1, Volatile.Read(ref hits1));
            Assert.Equal(1, Volatile.Read(ref hits2));
        }
        finally
        {
            try { listener1.Stop(); } catch { }
            listener2.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task NonAllowlistedMethods_AreNeverCached()
    {
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                using var peer = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = peer.GetStream();
                var id = await ReadRequestIdAsync(stream);
                Interlocked.Increment(ref hits);
                await stream.WriteAsync(StrictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{}}\n"), cts.Token);
            }
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var denied1 = await client.RequestAsync("NotARealMethod", null, cts.Token);
            var denied2 = await client.RequestAsync("NotARealMethod", null, cts.Token);
            Assert.Contains("method_not_allowed", denied1);
            Assert.Contains("method_not_allowed", denied2);
            Assert.Equal(0, Volatile.Read(ref hits));
            await client.RequestAsync("CreateFunction", JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement, cts.Token);
            await client.RequestAsync("CreateFunction", JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement, cts.Token);
            await serve;
            Assert.Equal(2, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task ErrorEnvelope_IsNotCached_NextCallHitsBackend()
    {
        // A transient bridge error (program_unavailable etc.) must not poison
        // the 300s static cache: the second identical call has to reach the
        // backend and observe the recovered result.
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                using var peer = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = peer.GetStream();
                var id = await ReadRequestIdAsync(stream);
                Interlocked.Increment(ref hits);
                var body = i == 0
                    ? "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"program_unavailable\",\"message\":\"no active program\"}}\n"
                    : "{\"id\":" + id + ",\"ok\":true,\"result\":{\"recovered\":true}}\n";
                await stream.WriteAsync(StrictUtf8.GetBytes(body), cts.Token);
            }
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var args = JsonDocument.Parse("{\"address\":\"00401000\"}").RootElement;
            var first = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"ok\":false", first);
            var second = await client.RequestAsync("InspectFunction", args, cts.Token);
            Assert.Contains("\"ok\":true", second);
            await serve;
            Assert.Equal(2, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task AnalysisQueue_is_durable_and_annotation_invalidates_it()
    {
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            for (var i = 0; i < 3; i++)
            {
                using var peer = await listener.AcceptTcpClientAsync(cts.Token);
                await using var stream = peer.GetStream();
                var id = await ReadRequestIdAsync(stream);
                Interlocked.Increment(ref hits);
                var body = i == 1
                    ? "{\"id\":" + id + ",\"ok\":true,\"result\":{}}"
                    : "{\"id\":" + id + ",\"ok\":true,\"result\":{\"queue\":[],\"doneCount\":0}}";
                await stream.WriteAsync(StrictUtf8.GetBytes(body + "\n"), cts.Token);
            }
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var queueArgs = JsonDocument.Parse("{\"limit\":8}").RootElement;
            var first = await client.RequestAsync("GetAnalysisQueue", queueArgs, cts.Token);
            var second = await client.RequestAsync("GetAnalysisQueue", queueArgs, cts.Token);
            Assert.Equal(first, second);
            Assert.Equal(1, Volatile.Read(ref hits));

            await client.RequestAsync("RenameFunction",
                JsonDocument.Parse("{\"address\":\"00401000\",\"name\":\"f\"}").RootElement, cts.Token);
            await client.RequestAsync("GetAnalysisQueue", queueArgs, cts.Token);
            await serve;
            Assert.Equal(3, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    [Theory]
    [InlineData("DecompileModule")]
    [InlineData("CallGraph")]
    [InlineData("ListSymbolsBoth")]
    public async Task Expensive_static_reads_are_durable_cached(string method)
    {
        var dir = NewDir();
        using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        WriteEndpoint(dir, port);
        var hits = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serve = Task.Run(async () =>
        {
            using var peer = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = peer.GetStream();
            var id = await ReadRequestIdAsync(stream);
            Interlocked.Increment(ref hits);
            await stream.WriteAsync(StrictUtf8.GetBytes(
                "{\"id\":" + id + ",\"ok\":true,\"result\":{\"functions\":[]}}\n"), cts.Token);
        }, cts.Token);
        try
        {
            var client = new GhidraClient(dir);
            var first = await client.RequestAsync(method, null, cts.Token);
            await Task.Delay(TimeSpan.FromMilliseconds(2100), cts.Token);
            var second = await client.RequestAsync(method, null, cts.Token);
            await serve;
            Assert.Equal(first, second);
            Assert.Equal(1, Volatile.Read(ref hits));
        }
        finally
        {
            listener.Stop();
            Directory.Delete(dir, true);
        }
    }

    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dbglink-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void WriteEndpoint(string dir, int port, bool overwrite = false)
    {
        foreach (var old in Directory.GetFiles(dir, "ghidra-bridge-*.json"))
            File.Delete(old);
        File.WriteAllText(Path.Combine(dir, overwrite ? "ghidra-bridge-b.json" : "ghidra-bridge-a.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('b', 32) + "\"}");
    }

    private static async Task<int> ReadRequestIdAsync(Stream stream)
        => JsonDocument.Parse(await ReadRequestLineAsync(stream)).RootElement.GetProperty("id").GetInt32();

    private static async Task<string> ReadRequestLineAsync(Stream stream)
    {
        var buffer = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(one, CancellationToken.None);
            if (read == 0) throw new IOException("EOF waiting for request line.");
            if (one[0] == (byte)'\n') break;
            buffer.Add(one[0]);
        }
        return StrictUtf8.GetString(buffer.ToArray());
    }
}
