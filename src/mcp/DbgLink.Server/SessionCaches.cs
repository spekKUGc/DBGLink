using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace DbgLink.Server;

/// <summary>
/// One cache layer: owns the process-wide static caches (typed handles, TTL
/// constants in one place) with a single <see cref="InvalidateAll"/> plus the
/// specific invalidation a caller legitimately needs (target open/switch).
/// Call sites keep keys, TTLs and semantics; the same concurrent structures
/// are reused internally, so no new locking is introduced.
/// <para/>
/// Deliberately NOT moved here: GhidraClient's response/endpoint caches
/// (per-session instances entangled with its lock, generation counter and
/// endpoint discovery — sharing them statically would risk cross-session
/// poisoning) and LiveAnalysisTools' rejected-target/snapshot tables
/// (per-instance, scoped to the current AnalysisContext). Their TTL
/// constants are centralized below instead; Ghidra mutation-clearing stays
/// on the existing ClearResponseCache path.
/// </summary>
internal static class SessionCaches
{
    // Per-cache TTL constants in one place (values unchanged).
    public const int ModuleCacheTtlSeconds = 5;
    public const int ModuleTableTtlSeconds = 5;
    public const int StaticIdentityTtlSeconds = 30;
    public const int StaticIdentityCacheCap = 512;
    // Ghidra per-client cache TTLs (storage stays in GhidraClient).
    public const int GhidraEndpointCacheMilliseconds = 5_000;
    public const int GhidraResponseCacheMilliseconds = 1_500;
    public const int GhidraStaticResponseCacheMilliseconds = 300_000;
    public const int GhidraMaxCachedResponses = 32;
    public const int GhidraMaxCachedResponseChars = 128 * 1024;
    // LiveAnalysisTools limits (storage stays per LiveAnalysisTools instance).
    public const int RejectedTargetLimit = 64;
    public static readonly TimeSpan RejectedTargetTtl = TimeSpan.FromMinutes(10);
    public const int SnapshotStateLimit = 32;

    /// <summary>One timestamped dictionary with TTL get/set. Cap of 0 means
    /// unbounded (no pruning); a positive cap prunes expired entries on set,
    /// matching the old static-identity behavior.</summary>
    internal sealed class TtlCache<T> where T : notnull
    {
        private readonly ConcurrentDictionary<string, (long timestampTicks, T value)> _entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly int _ttlSeconds;
        private readonly int _cap;

        public TtlCache(int ttlSeconds, int cap = 0)
        {
            _ttlSeconds = ttlSeconds;
            _cap = cap;
        }

        public bool TryGet(string key, long now, [NotNullWhen(true)] out T? value)
        {
            if (_entries.TryGetValue(key, out var entry) &&
                now - entry.timestampTicks < Stopwatch.Frequency * _ttlSeconds)
            {
                value = entry.value;
                return true;
            }
            value = default;
            return false;
        }

        public void Set(string key, long now, T value)
        {
            if (_cap > 0)
                Prune(now);
            _entries[key] = (now, value);
        }

        public void Clear() => _entries.Clear();

        private void Prune(long now)
        {
            if (_entries.Count < _cap)
                return;
            foreach (var (key, entry) in _entries)
                if (now - entry.timestampTicks >= Stopwatch.Frequency * _ttlSeconds)
                    _entries.TryRemove(key, out _);
        }
    }

    internal static TtlCache<AddressMapping.LiveModuleCollection> ModuleCollections { get; } = new(ModuleCacheTtlSeconds);
    internal static TtlCache<IReadOnlyList<ToolSupport.LiveModule>> ModuleTables { get; } = new(ModuleTableTtlSeconds);
    internal static TtlCache<ToolSupport.StaticFunction> StaticIdentities { get; } = new(StaticIdentityTtlSeconds, StaticIdentityCacheCap);

    /// <summary>Target open/switch hook: a reopened target gets a fresh
    /// module table (and usually a new base).</summary>
    internal static void InvalidateModuleCaches()
    {
        ModuleCollections.Clear();
        ModuleTables.Clear();
    }

    internal static void InvalidateStaticIdentity() => StaticIdentities.Clear();

    internal static void InvalidateAll()
    {
        InvalidateModuleCaches();
        InvalidateStaticIdentity();
    }
}
