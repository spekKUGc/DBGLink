using System.Text.Json;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Durable cache of analyzed Ghidra projects. The key includes the content
/// hash, analysis mode, FIDB selection and the installed extension hash, so a
/// tool change can never reuse a project produced by older bridge code.
/// Entries expire after a sliding TTL and the least recently used ones are
/// evicted once the cache exceeds its entry or byte budget.
/// </summary>
internal sealed class GhidraProjectCache
{
    internal const int SchemaVersion = 2;
    internal const string MarkerName = ".dbglink-cache-complete";
    internal static readonly TimeSpan DefaultTtl = TimeSpan.FromDays(30);
    // A real corpus round is 10-20 binaries, and a full reverse session can
    // revisit more than one round. The byte budget remains the hard guard;
    // 16 entries was evicting useful projects while using only a fraction of
    // the 8 GB budget.
    internal const int DefaultMaxEntries = 64;
    internal const long DefaultMaxBytes = 8L * 1024 * 1024 * 1024;
    private const long MaxProjectBytes = 1_024L * 1024 * 1024;
    private const int MaxProjectEntries = 100_000;
    private const string StatsFileName = "cache-stats.json";
    private static readonly TimeSpan OrphanMaxAge = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly string _root;
    private readonly TimeSpan _ttl;
    private readonly int _maxEntries;
    private readonly long _maxBytes;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action<string>? _report;
    private readonly object _gate = new();

    internal GhidraProjectCache(
        string root,
        TimeSpan? ttl = null,
        int? maxEntries = null,
        long? maxBytes = null,
        Func<DateTimeOffset>? clock = null,
        Action<string>? report = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        _root = Path.GetFullPath(root);
        _ttl = ttl ?? DefaultTtl;
        _maxEntries = Math.Max(1, maxEntries ?? DefaultMaxEntries);
        _maxBytes = Math.Max(1, maxBytes ?? DefaultMaxBytes);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _report = report;
        LoadStats();
    }

    internal long Hits { get; private set; }
    internal long Misses { get; private set; }
    internal long Evictions { get; private set; }
    internal long EvictedBytes { get; private set; }

    internal static string ComposeKey(
        string sha256, bool analyze, string? fidbHash, string extensionSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        var key = $"v{SchemaVersion}-{sha256}";
        if (!analyze) key += "-noanalysis";
        if (!string.IsNullOrWhiteSpace(fidbHash)) key += "-fid-" + fidbHash;
        if (!string.IsNullOrWhiteSpace(extensionSha256)) key += "-ext-" + extensionSha256;
        return key;
    }

    internal bool TryRestore(string key, string destination, out string reason)
    {
        var directory = Path.Combine(_root, key);
        var now = _clock();
        if (!TryReadMarker(directory, key, out var marker))
        {
            reason = Directory.Exists(directory) ? "invalid_marker" : "missing";
            if (Directory.Exists(directory))
                TryDeleteDirectory(directory);
            RecordMiss();
            return false;
        }

        if (now - marker.Timestamp > _ttl)
        {
            TryDeleteDirectory(directory);
            reason = "expired";
            RecordMiss();
            return false;
        }

        try
        {
            CopyProjectDirectory(directory, destination);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            TryDeleteDirectory(directory);
            reason = "unreadable";
            RecordMiss();
            return false;
        }

        // Sliding TTL: using an entry makes it fresh again. The project bytes
        // do not change, so the marker's size stays authoritative for LRU.
        try { WriteMarker(directory, key, marker.Bytes, now); }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException) { }

        lock (_gate)
        {
            Hits++;
        }
        PersistStats();
        _report?.Invoke($"Ghidra project cache hit ({ShortKey(key)}).");
        reason = "hit";
        return true;
    }

    internal void Store(string key, string sourceDirectory)
    {
        var now = _clock();
        var directory = Path.Combine(_root, key);
        var staging = directory + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            Directory.CreateDirectory(_root);
            var bytes = CopyProjectDirectory(sourceDirectory, staging);
            WriteMarker(staging, key, bytes, now);
            if (!Directory.Exists(directory))
                Directory.Move(staging, directory);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            _report?.Invoke("Ghidra project caching was skipped; the analysis result is still usable.");
            return;
        }
        finally
        {
            TryDeleteDirectory(staging);
        }

        Evict();
    }

    /// <summary>
    /// Reclaims expired, legacy and orphaned entries, then applies the LRU
    /// budget. The newest entry is always kept: a single project that exceeds
    /// the byte budget is still better than no cache at all.
    /// </summary>
    internal void Evict()
    {
        if (!Directory.Exists(_root))
            return;

        var now = _clock();
        var entries = new List<Entry>();
        try
        {
            foreach (var directory in Directory.EnumerateDirectories(_root))
            {
                var name = Path.GetFileName(directory);
                if (name.Contains(".tmp-", StringComparison.Ordinal))
                {
                    ReclaimOldOrphan(directory, now);
                    continue;
                }

                if (!TryReadMarker(directory, name, out var marker))
                {
                    // Legacy plain-text markers (pre-v2) and corrupt entries are
                    // reclaimed after a grace period so a concurrent writer is safe.
                    ReclaimOldOrphan(directory, now);
                    continue;
                }

                if (now - marker.Timestamp > _ttl)
                {
                    TryDeleteDirectory(directory);
                    RecordEviction(marker.Bytes);
                    continue;
                }

                entries.Add(new Entry(directory, marker.Bytes, marker.Timestamp));
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            return;
        }

        entries.Sort(static (left, right) => left.Timestamp.CompareTo(right.Timestamp));
        var totalBytes = entries.Sum(entry => entry.Bytes);
        while ((entries.Count > _maxEntries || totalBytes > _maxBytes) && entries.Count > 1)
        {
            var oldest = entries[0];
            entries.RemoveAt(0);
            TryDeleteDirectory(oldest.Directory);
            totalBytes -= oldest.Bytes;
            RecordEviction(oldest.Bytes);
        }

        if (entries.Count == 1 && entries[0].Bytes > _maxBytes)
            _report?.Invoke("A single cached Ghidra project exceeds the cache budget; keeping the newest entry.");
    }

    internal static string? DefaultRoot()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localApplicationData)
            ? null
            : Path.Combine(localApplicationData, "DBGLink", "GhidraProjects");
    }

    internal static GhidraCacheClearResult ClearRoot(string root)
    {
        if (!Directory.Exists(root))
            return new GhidraCacheClearResult(0, 0);

        var entries = 0;
        var bytes = 0L;
        try
        {
            foreach (var markerPath in Directory.EnumerateFiles(root, MarkerName, SearchOption.AllDirectories))
            {
                entries++;
                var entryDirectory = Path.GetDirectoryName(markerPath)!;
                try
                {
                    var marker = JsonSerializer.Deserialize<Marker>(
                        File.ReadAllText(markerPath), JsonOptions);
                    bytes += marker is { Bytes: > 0 } ? marker.Bytes : DirectorySize(entryDirectory);
                }
                catch (JsonException) { bytes += DirectorySize(entryDirectory); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var directory in Directory.EnumerateDirectories(root))
            {
                if (PathSafety.IsReparseFree(directory))
                    TryDeleteDirectory(directory);
            }

            var stats = Path.Combine(root, StatsFileName);
            if (File.Exists(stats))
                File.Delete(stats);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // Best effort: a locked directory is reported by the next stats read.
        }

        return new GhidraCacheClearResult(entries, bytes);
    }

    private static string ShortKey(string key) =>
        key.Length <= 24 ? key : key[..24] + "…";

    private static long DirectorySize(string directory)
    {
        var total = 0L;
        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                var info = new FileInfo(file);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0)
                    total += info.Length;
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
        }
        return total;
    }

    private void RecordMiss()
    {
        lock (_gate)
        {
            Misses++;
        }
        PersistStats();
    }

    private void RecordEviction(long bytes)
    {
        lock (_gate)
        {
            Evictions++;
            EvictedBytes += Math.Max(0, bytes);
        }
        PersistStats();
    }

    private void LoadStats()
    {
        try
        {
            var path = Path.Combine(_root, StatsFileName);
            if (!File.Exists(path) || new FileInfo(path).Length > 4 * 1024)
                return;
            var stats = JsonSerializer.Deserialize<Stats>(File.ReadAllText(path), JsonOptions);
            if (stats is null || stats.Schema != SchemaVersion)
                return;
            Hits = Math.Max(0, stats.Hits);
            Misses = Math.Max(0, stats.Misses);
            Evictions = Math.Max(0, stats.Evictions);
            EvictedBytes = Math.Max(0, stats.EvictedBytes);
        }
        catch (JsonException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (ArgumentException) { }
        catch (NotSupportedException) { }
    }

    private void PersistStats()
    {
        try
        {
            Directory.CreateDirectory(_root);
            var json = JsonSerializer.Serialize(new
            {
                schema = SchemaVersion,
                hits = Hits,
                misses = Misses,
                evictions = Evictions,
                evictedBytes = EvictedBytes,
                updatedUtc = _clock()
            }, JsonOptions);
            var path = Path.Combine(_root, StatsFileName);
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, json);
            File.Move(temporary, path, overwrite: true);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // Metrics are diagnostic only; never fail an import because they
            // could not be written (read-only profile, AV lock, ...).
        }
    }

    private void ReclaimOldOrphan(string directory, DateTimeOffset now)
    {
        try
        {
            if (now.UtcDateTime - Directory.GetLastWriteTimeUtc(directory) > OrphanMaxAge)
                TryDeleteDirectory(directory);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void WriteMarker(string directory, string key, long bytes, DateTimeOffset timestamp)
    {
        var marker = new Marker { Key = key, Bytes = bytes, Timestamp = timestamp };
        var path = Path.Combine(directory, MarkerName);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(marker, JsonOptions));
        File.Move(temporary, path, overwrite: true);
    }

    private static bool TryReadMarker(string directory, string key, out Marker marker)
    {
        marker = new Marker();
        try
        {
            var path = Path.Combine(directory, MarkerName);
            if (!File.Exists(path) || new FileInfo(path).Length > 512)
                return false;
            var parsed = JsonSerializer.Deserialize<Marker>(File.ReadAllText(path), JsonOptions);
            if (parsed is null ||
                !string.Equals(parsed.Key, key, StringComparison.Ordinal) ||
                parsed.Bytes < 0)
                return false;
            marker = parsed;
            return true;
        }
        catch (JsonException) { return false; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    private static long CopyProjectDirectory(string source, string destination)
    {
        if (!Directory.Exists(source))
            throw new InvalidDataException("The cached Ghidra project directory is missing.");
        if (!PathSafety.IsReparseFree(source) || !PathSafety.IsReparseFree(destination))
            throw new InvalidDataException("Ghidra project cache path contains a reparse point.");
        Directory.CreateDirectory(destination);

        var sourceRoot = Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var destinationRoot = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var totalBytes = 0L;
        var entries = 0;
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            if (++entries > MaxProjectEntries ||
                (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The Ghidra project cache contains too many or linked entries.");
            var relative = Path.GetRelativePath(sourceRoot, directory);
            var target = Path.GetFullPath(Path.Combine(destination, relative));
            if (!target.StartsWith(destinationRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The Ghidra project cache escaped its destination.");
            Directory.CreateDirectory(target);
        }

        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            if (++entries > MaxProjectEntries ||
                (File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The Ghidra project cache contains too many or linked entries.");
            var info = new FileInfo(file);
            if (info.Length < 0 || info.Length > MaxProjectBytes - totalBytes)
                throw new InvalidDataException("The Ghidra project cache exceeds its size limit.");
            totalBytes += info.Length;
            var relative = Path.GetRelativePath(sourceRoot, file);
            var target = Path.GetFullPath(Path.Combine(destination, relative));
            if (!target.StartsWith(destinationRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The Ghidra project cache escaped its destination.");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }

        return totalBytes;
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path) && PathSafety.IsReparseFree(path))
                Directory.Delete(path, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed class Marker
    {
        public string Key { get; set; } = "";
        public long Bytes { get; set; }
        public DateTimeOffset Timestamp { get; set; }
    }

    private sealed class Stats
    {
        public int Schema { get; set; }
        public long Hits { get; set; }
        public long Misses { get; set; }
        public long Evictions { get; set; }
        public long EvictedBytes { get; set; }
    }

    private readonly record struct Entry(string Directory, long Bytes, DateTimeOffset Timestamp);
}

public readonly record struct GhidraCacheClearResult(int Entries, long Bytes);
