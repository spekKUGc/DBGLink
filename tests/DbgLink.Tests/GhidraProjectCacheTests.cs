using DbgLink.Launcher.Core;

namespace DbgLink.Tests;

/// <summary>
/// The durable Ghidra project cache must stay correct while being bounded:
/// content/extension/options form the key, hits slide the TTL, and the least
/// recently used entry goes first. These tests use a fake clock so expiry and
/// eviction are deterministic instead of sleep-based.
/// </summary>
public sealed class GhidraProjectCacheTests : IDisposable
{
    private static readonly string ShaA = new('a', 64);
    private static readonly string ShaB = new('b', 64);
    private static readonly string ExtA = new('1', 64);
    private static readonly string ExtB = new('2', 64);

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "dbglink-gpc-root-" + Guid.NewGuid().ToString("N"));
    private readonly string _source =
        Path.Combine(Path.GetTempPath(), "dbglink-gpc-src-" + Guid.NewGuid().ToString("N"));
    private readonly string _destination =
        Path.Combine(Path.GetTempPath(), "dbglink-gpc-dst-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private GhidraProjectCache NewCache(
        TimeSpan? ttl = null, int? maxEntries = null, long? maxBytes = null) =>
        new(_root, ttl, maxEntries, maxBytes, () => _now);

    private string ProjectSource(string name)
    {
        var directory = Path.Combine(_source, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "program.prp"), name);
        File.WriteAllBytes(Path.Combine(directory, "program.pdb"), new byte[64]);
        return directory;
    }

    [Fact]
    public void Store_then_restore_is_a_hit_and_copies_the_project()
    {
        var cache = NewCache();
        var key = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        cache.Store(key, ProjectSource("one"));

        _now = _now.AddMinutes(5);
        var destination = Path.Combine(_destination, "restored");
        Assert.True(cache.TryRestore(key, destination, out var reason));
        Assert.Equal("hit", reason);
        Assert.Equal("one", File.ReadAllText(Path.Combine(destination, "program.prp")));
        Assert.Equal(64, new FileInfo(Path.Combine(destination, "program.pdb")).Length);
        Assert.Equal(1, cache.Hits);
        Assert.Equal(0, cache.Misses);
        Assert.True(File.Exists(Path.Combine(_root, key, GhidraProjectCache.MarkerName)));
        Assert.True(File.Exists(Path.Combine(_root, "cache-stats.json")));
    }

    [Fact]
    public void Default_cache_holds_a_full_corpus_round_without_eviction()
    {
        var cache = NewCache();
        for (var index = 0; index < 20; index++)
        {
            cache.Store(
                GhidraProjectCache.ComposeKey(
                    index.ToString("x64"), analyze: true, fidbHash: null, ExtA),
                ProjectSource("corpus-" + index));
        }

        Assert.Equal(0, cache.Evictions);
        Assert.Equal(20, Directory.EnumerateDirectories(_root).Count());
    }

    [Fact]
    public void Statistics_accumulate_across_cache_instances()
    {
        var key = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        var first = NewCache();
        first.Store(key, ProjectSource("stats"));
        Assert.True(first.TryRestore(key, Path.Combine(_destination, "stats"), out _));

        // A new launcher process must continue the durable hit/miss counters
        // instead of overwriting them with its own zero-based values.
        var second = NewCache();
        Assert.Equal(1, second.Hits);
        Assert.Equal(0, second.Misses);
        Assert.False(second.TryRestore(
            GhidraProjectCache.ComposeKey(ShaB, analyze: true, fidbHash: null, ExtA),
            Path.Combine(_destination, "missing"), out _));
        Assert.Equal(1, second.Hits);
        Assert.Equal(1, second.Misses);

        var third = NewCache();
        Assert.Equal(1, third.Hits);
        Assert.Equal(1, third.Misses);
    }

    [Fact]
    public void Extension_analysis_mode_and_fidb_are_part_of_the_key()
    {
        var plain = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        var noAnalysis = GhidraProjectCache.ComposeKey(ShaA, analyze: false, fidbHash: null, ExtA);
        var otherExtension = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtB);
        var fidb = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: "0123456789abcdef", ExtA);

        Assert.StartsWith("v2-", plain, StringComparison.Ordinal);
        Assert.NotEqual(plain, noAnalysis);
        Assert.NotEqual(plain, otherExtension);
        Assert.NotEqual(plain, fidb);
    }

    [Fact]
    public void Invalid_marker_is_a_miss_and_removes_the_entry()
    {
        var cache = NewCache();
        var key = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        cache.Store(key, ProjectSource("invalid"));

        File.WriteAllText(Path.Combine(_root, key, GhidraProjectCache.MarkerName), "stale");
        Assert.False(cache.TryRestore(key, Path.Combine(_destination, "invalid"), out var reason));
        Assert.Equal("invalid_marker", reason);
        Assert.Equal(1, cache.Misses);
        Assert.False(Directory.Exists(Path.Combine(_root, key)));
    }

    [Fact]
    public void Expired_entry_is_a_miss()
    {
        var cache = NewCache(ttl: TimeSpan.FromDays(1));
        var key = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        cache.Store(key, ProjectSource("expired"));

        _now = _now.AddDays(2);
        Assert.False(cache.TryRestore(key, Path.Combine(_destination, "expired"), out var reason));
        Assert.Equal("expired", reason);
        Assert.Equal(1, cache.Misses);
        Assert.False(Directory.Exists(Path.Combine(_root, key)));
    }

    [Fact]
    public void Lru_evicts_the_least_recently_used_entry()
    {
        var cache = NewCache(maxEntries: 2, maxBytes: long.MaxValue);
        var a = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        var b = GhidraProjectCache.ComposeKey(ShaB, analyze: true, fidbHash: null, ExtA);
        var c = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: "f", ExtA);

        cache.Store(a, ProjectSource("a"));
        _now = _now.AddMinutes(1);
        cache.Store(b, ProjectSource("b"));
        _now = _now.AddMinutes(1);
        Assert.True(cache.TryRestore(a, Path.Combine(_destination, "a"), out _));
        _now = _now.AddMinutes(1);
        cache.Store(c, ProjectSource("c"));

        Assert.True(Directory.Exists(Path.Combine(_root, a)));
        Assert.False(Directory.Exists(Path.Combine(_root, b)));
        Assert.True(Directory.Exists(Path.Combine(_root, c)));
        Assert.Equal(1, cache.Evictions);
    }

    [Fact]
    public void ClearRoot_removes_every_cache_entry_and_reports_the_bytes()
    {
        var cache = NewCache();
        var a = GhidraProjectCache.ComposeKey(ShaA, analyze: true, fidbHash: null, ExtA);
        var b = GhidraProjectCache.ComposeKey(ShaB, analyze: true, fidbHash: null, ExtA);
        cache.Store(a, ProjectSource("clear-a"));
        cache.Store(b, ProjectSource("clear-b"));

        var cleared = GhidraProjectCache.ClearRoot(_root);

        Assert.Equal(2, cleared.Entries);
        Assert.True(cleared.Bytes > 0);
        Assert.Empty(Directory.EnumerateDirectories(_root));
    }

    public void Dispose()
    {
        foreach (var directory in new[] { _root, _source, _destination })
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
