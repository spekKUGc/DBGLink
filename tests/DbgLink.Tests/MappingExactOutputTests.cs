using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit;
using static DbgLink.Tests.TestWire;

namespace DbgLink.Tests;

/// <summary>
/// Exact-output assertions over AddressMapping helpers. Pinning every key,
/// name and boundary kills the string/arithmetic/equality mutants that
/// behavior-only tests leave alive.
/// </summary>
public sealed class MappingExactOutputTests
{
    [Fact]
    public void ModuleJson_PinsAllKeysAndFormats()
    {
        var json = AddressMapping.ModuleJson(new ToolSupport.LiveModule(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe"));
        Assert.Equal("{\"name\":\"t.exe\",\"base\":\"0x140000000\",\"end\":\"0x140010000\",\"path\":\"C:\\\\app\\\\t.exe\"}",
            json.ToJsonString());
    }

    [Fact]
    public void BuildModuleCandidates_PinsOrderAndCap()
    {
        var modules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000UL, 0x140010000UL, "a.exe", "C:\\a.exe"),
            new(0x150000000UL, 0x150010000UL, "b.exe", "C:\\b.exe"),
        };
        var candidates = AddressMapping.BuildModuleCandidates(modules);
        Assert.Equal(2, candidates.Count);
        Assert.Equal("a.exe", candidates[0]!["name"]!.GetValue<string>());
        Assert.Equal("0x140000000", candidates[0]!["base"]!.GetValue<string>());
        Assert.Equal("0x140010000", candidates[0]!["end"]!.GetValue<string>());
        Assert.Equal("C:\\a.exe", candidates[0]!["path"]!.GetValue<string>());
        Assert.Equal("b.exe", candidates[1]!["name"]!.GetValue<string>());
    }

    [Fact]
    public void TryReadStaticFunction_PinsEveryField()
    {
        const string sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var raw = "{\"result\": {\"function\": {\"name\": \"main\", \"entry\": \"0x140001000\", \"rva\": \"0x1000\", \"module\": {\"path\": \"C:\\\\app\\\\t.exe\", \"sha256\": \"" + sha + "\"}}}}";
        Assert.True(AddressMapping.TryReadStaticFunction(raw, out var function, out var error));
        Assert.Equal("", error);
        Assert.Equal("main", function.Name);
        Assert.Equal("0x140001000", function.Entry);
        Assert.Equal("C:\\app\\t.exe", function.Path);
        Assert.Equal(sha, function.Sha256);
        Assert.Equal(0x1000UL, function.Rva);
    }

    [Fact]
    public async Task BuildMappingResult_PinsMatchDocument()
    {
        var staticFunction = new ToolSupport.StaticFunction("main", "0x140001000", "C:\\app\\t.exe", null, 0x1000);
        var modules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe"),
        };
        var result = await AddressMapping.BuildMappingResultAsync(staticFunction, modules, verifyHash: false, CancellationToken.None);
        Assert.True(result["match"]!.GetValue<bool>());
        Assert.Equal("0x140001000", result["liveAddress"]!.GetValue<string>());
        Assert.Equal("0x1000", result["rva"]!.GetValue<string>());
        Assert.Equal(1, result["candidateCount"]!.GetValue<int>());
        Assert.False(result["modulesTruncated"]!.GetValue<bool>());
        Assert.Equal("path", result["identity"]!["kind"]!.GetValue<string>());
        // The full path/hash live once on staticFunction; identity only adds
        // how the match was decided.
        Assert.False(result["identity"]!.AsObject().ContainsKey("path"));
        Assert.False(result["identity"]!.AsObject().ContainsKey("sha256"));
        Assert.False(result["identity"]!["hashVerified"]!.GetValue<bool>());
        Assert.Equal("t.exe", result["module"]!["name"]!.GetValue<string>());
        Assert.Equal("0x140000000", result["module"]!["base"]!.GetValue<string>());
        Assert.False(result["module"]!.AsObject().ContainsKey("path"));
        Assert.Equal("C:\\app\\t.exe", result["staticFunction"]!["path"]!.GetValue<string>());
    }

    [Fact]
    public async Task Shared_hash_cache_serves_match_without_reread()
    {
        // The multi-brief loop shares one hash cache across selectors: a
        // pre-populated entry must match even though the file never exists.
        // A per-call cache would miss, read nothing, and fall back to "path".
        const string fakePath = "C:\\no\\such\\module.dll";
        var hex = new string('b', 64);
        var modules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000UL, 0x140010000UL, "module.dll", fakePath),
        };
        var cache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            [AddressMapping.NormalizeIdentityPath(fakePath)] = hex,
        };
        var function = new ToolSupport.StaticFunction("f", "0x140000000", fakePath, hex, 0x1000);
        var match = await AddressMapping.FindModuleMatchAsync(function, modules, true, CancellationToken.None, cache);
        Assert.NotNull(match);
        Assert.Equal("sha256", match.IdentityKind);
        Assert.True(match.HashVerified);
    }

    [Fact]
    public void ParseModuleRecords_PinsModulesAndTruncation()
    {
        var node = JsonNode.Parse("{\"modules\": [{\"base\": \"0x140000000\", \"end\": \"0x140010000\", \"name\": \"t.exe\", \"path\": \"C:\\\\t.exe\"}], \"truncated\": false}");
        var parsed = AddressMapping.ParseModuleRecords(node);
        var collection = Assert.IsType<AddressMapping.LiveModuleCollection>(parsed);
        Assert.False(collection.Truncated);
        var single = Assert.Single(parsed);
        Assert.Equal(0x140000000UL, single.Base);
        Assert.Equal(0x140010000UL, single.End);
        Assert.Equal("t.exe", single.Name);
        Assert.Equal("C:\\t.exe", single.Path);
    }

    [Fact]
    public void ParseModuleText_PinsNameWithSpaces()
    {
        var text = "base=0x140000000 end=0x140010000 name=My App path=C:\\Program Files\\app.exe\n";
        var parsed = AddressMapping.ParseLiveModules(text);
        var single = Assert.Single(parsed);
        Assert.Equal("My App", single.Name);
        Assert.Equal("C:\\Program Files\\app.exe", single.Path);
        Assert.Equal(0x140000000UL, single.Base);
    }

    [Theory]
    [InlineData("base=0xABC end=0xDEF foo=1", "base", 0xABCUL)]
    [InlineData("base=0xABC end=0xDEF", "end", 0xDEFUL)]
    [InlineData("base=0xABC end=0xDEF", "missing", null)]
    public void TryReadHexField_PinsValues(string line, string field, ulong? expected)
    {
        var ok = AddressMapping.TryReadHexField(line, field, out var value);
        Assert.Equal(expected.HasValue, ok);
        if (expected.HasValue) Assert.Equal(expected.Value, value);
    }

    [Theory]
    [InlineData("C:\\a\\b\\c.dll", "c.dll")]
    [InlineData("C:/a/b/c.dll", "c.dll")]
    [InlineData("nodirs.dll", "nodirs.dll")]
    [InlineData("", "")]
    public void FileName_PinsExtraction(string path, string expected)
    {
        Assert.Equal(expected, AddressMapping.FileName(path));
    }

    [Theory]
    [InlineData("\"C:\\app\\t.exe\" trailing", "C:\\APP\\T.EXE\" TRAILING")]
    [InlineData("\\\\C:\\app\\t.exe", "\\\\C:\\APP\\T.EXE")]
    public void NormalizeIdentityPath_PinsEdgeCases(string input, string expected)
    {
        Assert.Equal(expected, AddressMapping.NormalizeIdentityPath(input));
    }

    [Fact]
    public void NormalizeSha256_PinsLowercasing()
    {
        var upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        Assert.Equal(upper.ToLowerInvariant(), AddressMapping.NormalizeSha256(upper));
        Assert.Null(AddressMapping.NormalizeSha256(upper.ToLowerInvariant() + "00"));
        Assert.Null(AddressMapping.NormalizeSha256(""));
        Assert.Null(AddressMapping.NormalizeSha256(null));
    }

    [Fact]
    public void FormatAddress_PinsUppercaseHex()
    {
        Assert.Equal("0x0", AddressMapping.FormatAddress(0));
        Assert.Equal("0xDEADBEEF", AddressMapping.FormatAddress(0xDEADBEEFUL));
        Assert.Equal("0xFFFFFFFFFFFFFFFF", AddressMapping.FormatAddress(ulong.MaxValue));
    }

    [Fact]
    public async Task FindModuleMatch_SameFileNameWithoutHash_SkipsWhenHashRequired()
    {
        var staticFunction = new ToolSupport.StaticFunction("main", "0x140001000", "D:\\other\\t.exe", new string('1', 64), 0x1000);
        var modules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe"),
        };
        Assert.Null(await AddressMapping.FindModuleMatchAsync(staticFunction, modules, verifyHash: true, CancellationToken.None));
        Assert.Null(await AddressMapping.FindModuleMatchAsync(staticFunction, modules, verifyHash: false, CancellationToken.None));
    }

    // =====================================================================
    // P1-5: opt-in byte enrichment pins (tiny caps, honest misses, hint shape).
    // =====================================================================

    [Fact]
    public void MapByteSampleLength_IsTinyAndBounded()
    {
        Assert.Equal(32, AddressMapping.MapByteSampleLength);
        Assert.InRange(AddressMapping.MapByteSampleLength, 1, 64);
    }

    [Fact]
    public async Task AttachBreakpointHint_PinsTripleShape()
    {
        var modules = new List<ToolSupport.LiveModule>
        {
            new(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe"),
        };
        var function = new ToolSupport.StaticFunction("main", "0x140001000", "C:\\app\\t.exe", null, 0x1000);
        var mapping = await AddressMapping.BuildMappingResultAsync(function, modules, verifyHash: false, CancellationToken.None);
        AddressMapping.AttachBreakpointHint(mapping, function);
        Assert.Equal("{\"module\":\"t.exe\",\"rva\":\"0x1000\",\"liveAddress\":\"0x140001000\"}",
            mapping["breakpointHint"]!.ToJsonString());
    }

    [Fact]
    public async Task AttachMapBytesAsync_MissKeepsReasonWithoutSamples()
    {
        var function = new ToolSupport.StaticFunction("main", "0x140001000", "C:\\missing.dll", null, 0x1000);
        var miss = await AddressMapping.BuildMappingResultAsync(
            function,
            new List<ToolSupport.LiveModule> { new(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe") },
            verifyHash: false, CancellationToken.None);
        Assert.Equal("module_identity_not_found", miss["reason"]!.GetValue<string>());

        await AddressMapping.AttachMapBytesAsync(
            new ErrorBridge(), new ErrorGhidra(), function, miss,
            includeLiveBytes: true, includeStaticBytes: true, CancellationToken.None);

        Assert.False(miss["match"]!.GetValue<bool>());
        Assert.Equal("module_identity_not_found", miss["reason"]!.GetValue<string>());
        Assert.Null(miss["liveBytes"]);
        Assert.Null(miss["staticBytes"]);
        Assert.Null(miss["breakpointHint"]);
    }

    [Fact]
    public async Task AttachMapBytesAsync_ByteFailureKeepsMatchWithErrorNodes()
    {
        var function = new ToolSupport.StaticFunction("main", "0x140001000", "C:\\app\\t.exe", null, 0x1000);
        var mapping = await AddressMapping.BuildMappingResultAsync(
            function,
            new List<ToolSupport.LiveModule> { new(0x140000000UL, 0x140010000UL, "t.exe", "C:\\app\\t.exe") },
            verifyHash: false, CancellationToken.None);

        await AddressMapping.AttachMapBytesAsync(
            new ErrorBridge(), new ErrorGhidra(), function, mapping,
            includeLiveBytes: true, includeStaticBytes: true, CancellationToken.None);

        // Read-only enrichment never fails the map: the match stands and each
        // failed sample is a per-field error, while the hint still lands.
        Assert.True(mapping["match"]!.GetValue<bool>());
        Assert.Equal("live_bytes_unavailable", mapping["liveBytes"]!["code"]!.GetValue<string>());
        Assert.Equal("static_bytes_unavailable", mapping["staticBytes"]!["code"]!.GetValue<string>());
        Assert.Equal("t.exe", mapping["breakpointHint"]!["module"]!.GetValue<string>());
    }

    private sealed class ErrorBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"denied\",\"message\":\"no\"}}");
    }

    private sealed class ErrorGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"denied\",\"message\":\"no\"}}");
    }
}

/// <summary>
/// P1-5 MapStaticFunctionToLive over the real wire stack: default responses
/// carry no byte enrichment, opt-in flags attach bounded samples plus the
/// breakpoint hint in the same call, and misses stay honest.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class MapBytesEnrichmentTests
{
    private static JsonElement ResultOf(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement.Clone();
        return root.TryGetProperty("result", out var result) ? result.Clone() : root;
    }

    private static void SeedIdentities(RealServerHarness harness)
    {
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            var selector = args?.TryGetProperty("function", out var f) == true ? f.GetString() ?? "" : "";
            var path = selector == "missing" ? "C:\\missing.dll" : "C:\\test.exe";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path, sha256 = "" },
                    },
                },
            });
        });
    }

    [Fact]
    public async Task Map_default_response_has_no_byte_enrichment()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedIdentities(harness);

        var text = TextOf(await harness.CallToolOverWireAsync("MapStaticFunctionToLive", new { function = "main" }));
        var result = ResultOf(text);
        Assert.True(result.GetProperty("match").GetBoolean());
        Assert.Equal("0x140001000", result.GetProperty("liveAddress").GetString());
        Assert.DoesNotContain("liveBytes", text);
        Assert.DoesNotContain("staticBytes", text);
        Assert.DoesNotContain("breakpointHint", text);
        // One copy of the module path/hash: staticFunction. Identity only
        // reports how the match was decided.
        Assert.True(result.GetProperty("staticFunction").TryGetProperty("path", out _));
        Assert.False(result.GetProperty("identity").TryGetProperty("path", out _));
        Assert.False(result.GetProperty("identity").TryGetProperty("sha256", out _));
        Assert.False(result.GetProperty("module").TryGetProperty("path", out _));
        var calls = result.GetProperty("bridgeCalls");
        Assert.Equal(1, calls.GetProperty("ghidra").GetInt32());
        Assert.Equal(1, calls.GetProperty("native").GetInt32());
    }

    [Fact]
    public async Task Map_repeat_reuses_static_identity_and_module_table()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var inspectCalls = 0;
        var moduleCalls = 0;
        harness.Ghidra.RegisterTcpHandler("InspectFunction", (id, args) =>
        {
            Interlocked.Increment(ref inspectCalls);
            var selector = args?.TryGetProperty("function", out var f) == true ? f.GetString() ?? "" : "";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    function = new
                    {
                        name = selector,
                        entry = "0x140001000",
                        rva = "0x1000",
                        module = new { path = "C:\\test.exe", sha256 = "" },
                    },
                },
            });
        });
        harness.NativePipeServer.RegisterHandler("GetModuleRecords", (id, _) =>
        {
            Interlocked.Increment(ref moduleCalls);
            return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"modules\":[{\"base\":\"0x140000000\"," +
                "\"end\":\"0x140010000\",\"name\":\"test.exe\",\"path\":\"C:\\\\test.exe\"}],\"truncated\":false}}";
        });

        var first = ResultOf(TextOf(await harness.CallToolOverWireAsync(
            "MapStaticFunctionToLive", new { function = "main", verifyHash = false })));
        Assert.Equal(1, inspectCalls);
        Assert.Equal(1, moduleCalls);
        Assert.Equal(1, first.GetProperty("bridgeCalls").GetProperty("ghidra").GetInt32());
        Assert.Equal(1, first.GetProperty("bridgeCalls").GetProperty("native").GetInt32());

        var second = ResultOf(TextOf(await harness.CallToolOverWireAsync(
            "MapStaticFunctionToLive", new { function = "main", verifyHash = false })));
        Assert.True(second.GetProperty("match").GetBoolean());
        // Warm: neither the Ghidra identity nor the module table is re-read.
        Assert.Equal(1, inspectCalls);
        Assert.Equal(1, moduleCalls);
        Assert.Equal(0, second.GetProperty("bridgeCalls").GetProperty("ghidra").GetInt32());
        Assert.Equal(0, second.GetProperty("bridgeCalls").GetProperty("native").GetInt32());

        // A debugger reopen invalidates the module table but not the static
        // identity: one native re-fetch, still no Ghidra call.
        AddressMapping.InvalidateModuleCache();
        var third = ResultOf(TextOf(await harness.CallToolOverWireAsync(
            "MapStaticFunctionToLive", new { function = "main", verifyHash = false })));
        Assert.Equal(1, inspectCalls);
        Assert.Equal(2, moduleCalls);
        Assert.Equal(0, third.GetProperty("bridgeCalls").GetProperty("ghidra").GetInt32());
        Assert.Equal(1, third.GetProperty("bridgeCalls").GetProperty("native").GetInt32());
    }

    [Fact]
    public async Task Map_bytes_opt_in_attaches_bounded_samples_and_hint()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedIdentities(harness);
        var liveReads = new List<string>();
        var staticReads = new List<string>();
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, args) =>
        {
            lock (liveReads)
                liveReads.Add(args?.GetRawText() ?? "");
            return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"address\":\"0x140001000\",\"bytes\":\"AA BB\",\"bytesRead\":2}}";
        });
        harness.Ghidra.RegisterTcpHandler("ReadStaticBytes", (id, args) =>
        {
            lock (staticReads)
                staticReads.Add(args?.GetRawText() ?? "");
            return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"address\":\"0x140001000\",\"length\":32,\"hex\":\"AABB\"}}";
        });

        var text = TextOf(await harness.CallToolOverWireAsync("MapStaticFunctionToLive",
            new { function = "main", verifyHash = false, includeLiveBytes = true, includeStaticBytes = true }));
        var result = ResultOf(text);
        Assert.True(result.GetProperty("match").GetBoolean());
        Assert.Equal("AA BB", result.GetProperty("liveBytes").GetProperty("bytes").GetString());
        Assert.Equal("AABB", result.GetProperty("staticBytes").GetProperty("hex").GetString());
        var hint = result.GetProperty("breakpointHint");
        Assert.Equal("test.exe", hint.GetProperty("module").GetString());
        Assert.Equal("0x1000", hint.GetProperty("rva").GetString());
        Assert.Equal("0x140001000", hint.GetProperty("liveAddress").GetString());

        // Strict tiny caps: one bounded read per side, at the mapped addresses.
        var liveArgs = Assert.Single(liveReads);
        Assert.Contains("0x140001000", liveArgs);
        Assert.Contains("32", liveArgs);
        var staticArgs = Assert.Single(staticReads);
        Assert.Contains("0x140001000", staticArgs);
        Assert.Contains("32", staticArgs);
    }

    [Fact]
    public async Task Map_bytes_on_miss_keeps_reason_without_samples_or_reads()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedIdentities(harness);
        var liveReads = 0;
        var staticReads = 0;
        harness.NativePipeServer.RegisterHandler("ReadMemAtAddress", (id, _) =>
        {
            Interlocked.Increment(ref liveReads);
            return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"address\":\"0x0\",\"bytes\":\"AA\",\"bytesRead\":1}}";
        });
        harness.Ghidra.RegisterTcpHandler("ReadStaticBytes", (id, _) =>
        {
            Interlocked.Increment(ref staticReads);
            return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"address\":\"0x0\",\"length\":1,\"hex\":\"AA\"}}";
        });

        var text = TextOf(await harness.CallToolOverWireAsync("MapStaticFunctionToLive",
            new { function = "missing", verifyHash = false, includeLiveBytes = true, includeStaticBytes = true }));
        var result = ResultOf(text);
        Assert.False(result.GetProperty("match").GetBoolean());
        Assert.Equal("module_identity_not_found", result.GetProperty("reason").GetString());
        Assert.DoesNotContain("liveBytes", text);
        Assert.DoesNotContain("staticBytes", text);
        Assert.DoesNotContain("breakpointHint", text);
        Assert.Equal(0, liveReads);
        Assert.Equal(0, staticReads);
    }

    [Fact]
    public async Task Map_rejects_non_boolean_byte_flags()
    {
        await using var harness = await RealServerHarness.StartAsync();
        SeedIdentities(harness);

        await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("MapStaticFunctionToLive",
                new { function = "main", includeLiveBytes = "yes" }));
        await Assert.ThrowsAsync<McpProtocolException>(() =>
            harness.CallToolOverWireAsync("MapStaticFunctionToLive",
                new { function = "main", includeStaticBytes = 1 }));
    }
}
