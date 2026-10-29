using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class GhidraClientTests
{
    /// <summary>
    /// Up to the bridge's own connection-worker count (4) run at the same time,
    /// and a caller cancelled while queued for a slot never opens a connection.
    /// The old client held a single slot, so this test used to assert that the
    /// second request stayed local — that is exactly the serialisation that was
    /// removed.
    /// </summary>
    [Fact]
    public async Task Parallel_reads_reach_Ghidra_and_a_cancelled_waiter_never_connects()
    {
        using var directory = TempDir.Create("dbglink-endpoint-");
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var arrived = new CountdownEvent(4);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            await File.WriteAllTextAsync(Path.Combine(directory, "ghidra-bridge-test.json"),
                JsonSerializer.Serialize(new { host = "127.0.0.1", port, protocolVersion = 1, token = new string('a', 32) }));
            var backend = Task.Run(async () =>
            {
                try
                {
                    while (!timeout.IsCancellationRequested)
                    {
                        var peer = await listener.AcceptTcpClientAsync(timeout.Token);
                        _ = Task.Run(async () =>
                        {
                            using (peer)
                            {
                                await using var stream = peer.GetStream();
                                using var reader = new StreamReader(stream, leaveOpen: true);
                                var request = await reader.ReadLineAsync(timeout.Token);
                                using var doc = JsonDocument.Parse(request!);
                                arrived.Signal();
                                await release.Task.WaitAsync(timeout.Token);
                                var response = Encoding.UTF8.GetBytes(
                                    "{\"id\":" + doc.RootElement.GetProperty("id").GetInt32() + ",\"ok\":true,\"result\":{}}\n");
                                await stream.WriteAsync(response, timeout.Token);
                            }
                        }, timeout.Token);
                    }
                }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
                catch (SocketException) { }
            }, timeout.Token);

            var client = new GhidraClient(directory);
            var inFlight = new[]
            {
                client.RequestAsync("ListImports", null, timeout.Token),
                client.RequestAsync("ListExports", null, timeout.Token),
                client.RequestAsync("ListFunctions", null, timeout.Token),
                client.RequestAsync("DumpStrings", null, timeout.Token),
            };
            Assert.True(arrived.Wait(TimeSpan.FromSeconds(10)),
                "fewer than four Ghidra reads ran in parallel; the client is serialising requests");

            using var cancelled = new CancellationTokenSource();
            var abandoned = client.RequestAsync("XrefsTo", null, cancelled.Token);
            await Task.Delay(150);
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoned);
            Assert.False(listener.Pending());

            release.SetResult();
            Assert.All(await Task.WhenAll(inFlight), response => Assert.Contains("\"ok\":true", response));
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Request_ignores_an_endpoint_with_non_string_host_or_token()
    {
        using var directory = TempDir.Create("dbglink-endpoint-");
        await File.WriteAllTextAsync(
            Path.Combine(directory, "ghidra-bridge-invalid.json"),
            "{\"host\":123,\"port\":5000,\"protocolVersion\":1,\"token\":{}}" );

        var response = await new GhidraClient(directory).RequestAsync(
            "status",
            null,
            CancellationToken.None);

        Assert.Contains("ghidra_unavailable", response);
    }

    // Moved from ServerRound2Tests: the client-caching contract lives with
    // its owner GhidraClient here.
    [Fact]
    public async Task StatusResponses_AreCachedAfterFirstRequest()
    {
        var strictUtf8 = new System.Text.UTF8Encoding(false, true);
        using var dir = TempDir.Create("dbglink-endpoint-");
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-cache.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('a', 32) + "\"}");
        var hits = 0;
        var serveTask = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                using var peer = await listener.AcceptTcpClientAsync();
                await using var stream = peer.GetStream();
                var id = await ReadCachedRequestIdAsync(stream, strictUtf8);
                Interlocked.Increment(ref hits);
                var bytes = strictUtf8.GetBytes("{\"id\":" + id + ",\"ok\":true,\"result\":{\"connected\":true}}\n");
                await stream.WriteAsync(bytes);
            }
        });
        var client = new GhidraClient(dir);
        var first = await client.RequestAsync("status", null, CancellationToken.None);
        Assert.Contains("connected", first);
        var second = await client.RequestAsync("status", null, CancellationToken.None);
        Assert.Contains("connected", second);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try { await serveTask.WaitAsync(cts.Token); } catch (OperationCanceledException) { }
        Assert.Equal(1, Volatile.Read(ref hits));
    }

    private static async Task<int> ReadCachedRequestIdAsync(Stream stream, System.Text.Encoding encoding)
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
        using var doc = System.Text.Json.JsonDocument.Parse(encoding.GetString(buffer.ToArray()));
        return doc.RootElement.GetProperty("id").GetInt32();
    }

    /// <summary>Loopback Ghidra bridge answering scripted per-method responses
    /// in connection order. Serves exactly <paramref name="maxHits"/>
    /// connections, then completes; the responder sees (method, id, paramsJson).</summary>
    private static async Task<int> WithScriptedGhidraAsync(
        int maxHits,
        Func<string, int, string?, string> respond,
        Func<GhidraClient, Task> test)
    {
        using var directory = TempDir.Create("dbglink-cand-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var hits = 0;
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            await File.WriteAllTextAsync(Path.Combine(directory, "ghidra-bridge-test.json"),
                JsonSerializer.Serialize(new { host = "127.0.0.1", port, protocolVersion = 1, token = new string('a', 32) }), timeout.Token);
            var backend = Task.Run(async () =>
            {
                for (var i = 0; i < maxHits; i++)
                {
                    using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
                    await using var stream = peer.GetStream();
                    using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                    var line = await reader.ReadLineAsync(timeout.Token);
                    using var doc = JsonDocument.Parse(line!);
                    var root = doc.RootElement;
                    var id = root.GetProperty("id").GetInt32();
                    var method = root.GetProperty("method").GetString() ?? "";
                    string? args = root.TryGetProperty("params", out var p) ? p.GetRawText() : null;
                    var body = respond(method, id, args);
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(body + "\n"), timeout.Token);
                    Interlocked.Increment(ref hits);
                }
            }, timeout.Token);
            await test(new GhidraClient(directory));
            await backend.WaitAsync(timeout.Token);
            return Volatile.Read(ref hits);
        }
        finally { listener.Stop(); }
    }

    private static JsonElement? Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    [Fact]
    public async Task Both_bridge_methods_are_allowlisted_cached_and_reach_ghidra()
    {
        // XrefsBoth/ListSymbolsBoth are first-class static reads: allowlisted,
        // cacheable (second identical call costs no new connection), and
        // forwarded with the caller's params intact.
        string? seenParams = null;
        var hits = await WithScriptedGhidraAsync(1,
            (method, id, args) =>
            {
                if (method == "XrefsBoth") seenParams = args;
                return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"source\":\"ghidra-static\"}}";
            },
            async client =>
            {
                var first = await client.RequestAsync("XrefsBoth", Args("{\"address\":\"0x1000\"}"), CancellationToken.None);
                Assert.Contains("\"ok\":true", first);
                var second = await client.RequestAsync("XrefsBoth", Args("{\"address\":\"0x1000\"}"), CancellationToken.None);
                Assert.Contains("\"ok\":true", second);
            });
        Assert.Equal(1, hits);
        Assert.Contains("0x1000", seenParams);
    }

    [Fact]
    public async Task ListSymbolsBoth_reaches_ghidra()
    {
        var hits = await WithScriptedGhidraAsync(1,
            (method, id, _) => "{\"id\":" + id + ",\"ok\":true,\"result\":{\"imports\":[],\"exports\":[]}}",
            async client =>
            {
                var response = await client.RequestAsync("ListSymbolsBoth", Args("{\"filter\":\"AIL\"}"), CancellationToken.None);
                Assert.Contains("\"ok\":true", response);
            });
        Assert.Equal(1, hits);
    }

    [Fact]
    public async Task Function_not_found_error_gains_candidates()
    {
        string? lookupParams = null;
        string response = "";
        var hits = await WithScriptedGhidraAsync(2,
            (method, id, args) =>
            {
                if (method == "InspectFunction")
                    return "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"function_not_found\",\"message\":\"'mainn' matched no global function name\"}}";
                lookupParams = args;
                return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"functions\":[{\"name\":\"main\",\"entry\":\"0x140001000\"},{\"name\":\"mainCRTStartup\",\"entry\":\"0x140001020\"}],\"truncated\":false}}";
            },
            async client =>
            {
                response = await client.RequestAsync("InspectFunction", Args("{\"function\":\"mainn\"}"), CancellationToken.None);
            });
        Assert.Equal(2, hits);
        using var doc = JsonDocument.Parse(response);
        var root = doc.RootElement;
        Assert.Equal(1, root.GetProperty("id").GetInt32());
        Assert.False(root.GetProperty("ok").GetBoolean());
        var error = root.GetProperty("error");
        Assert.Equal("function_not_found", error.GetProperty("code").GetString());
        var candidates = error.GetProperty("candidates").EnumerateArray().ToArray();
        Assert.Equal(2, candidates.Length);
        Assert.Equal("main", candidates[0].GetProperty("name").GetString());
        Assert.Equal("0x140001000", candidates[0].GetProperty("entry").GetString());
        var message = error.GetProperty("message").GetString() ?? "";
        Assert.Contains("main", message);
        Assert.Contains("mainCRTStartup", message);
        // The lookup reuses the failed selector as a ListFunctions filter.
        Assert.Contains("mainn", lookupParams);
    }

    [Fact]
    public async Task Ambiguous_function_error_gains_candidates()
    {
        string response = "";
        var hits = await WithScriptedGhidraAsync(2,
            (method, id, _) => method == "InspectFunction"
                ? "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"ambiguous_function\",\"message\":\"use an entry address\"}}"
                : "{\"id\":" + id + ",\"ok\":true,\"result\":{\"functions\":[{\"name\":\"overload\",\"entry\":\"0x140001000\"}],\"truncated\":false}}",
            async client =>
            {
                response = await client.RequestAsync("InspectFunction", Args("{\"function\":\"overload\"}"), CancellationToken.None);
            });
        Assert.Equal(2, hits);
        using var doc = JsonDocument.Parse(response);
        var error = doc.RootElement.GetProperty("error");
        Assert.Equal("ambiguous_function", error.GetProperty("code").GetString());
        Assert.Single(error.GetProperty("candidates").EnumerateArray());
    }

    [Fact]
    public async Task Candidates_skipped_when_lookup_finds_nothing()
    {
        // Empty lookup: the original error passes through byte-identical, no
        // candidates field, no message rewrite.
        string response = "";
        var hits = await WithScriptedGhidraAsync(2,
            (method, id, _) => method == "InspectFunction"
                ? "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"function_not_found\",\"message\":\"nope\"}}"
                : "{\"id\":" + id + ",\"ok\":true,\"result\":{\"functions\":[],\"truncated\":false}}",
            async client =>
            {
                response = await client.RequestAsync("InspectFunction", Args("{\"function\":\"zzz_no_such_fn\"}"), CancellationToken.None);
            });
        Assert.Equal(2, hits);
        Assert.Equal("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"function_not_found\",\"message\":\"nope\"}}", response);
    }

    [Fact]
    public async Task Other_error_codes_pass_through_without_lookup()
    {
        string response = "";
        var hits = await WithScriptedGhidraAsync(1,
            (method, id, _) => "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"bad\"}}",
            async client =>
            {
                response = await client.RequestAsync("InspectFunction", Args("{\"function\":\"main\"}"), CancellationToken.None);
            });
        Assert.Equal(1, hits);
        Assert.Equal("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"bad\"}}", response);
    }
}
