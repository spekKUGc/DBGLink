namespace DbgLink.Server;

/// <summary>Why the telemetry sink disabled itself.</summary>
internal enum TelemetryDisableReason { None, DiskFull, NoPermission, PathNotFound, IoError }

/// <summary>
/// Health of the local telemetry sink, surfaced through /metrics so a
/// degraded sink is visible instead of silently swallowing its failures.
///
/// This replaces the store contracts that used to live in the
/// DbgLink.Server.Telemetry namespace: that layer (ITelemetryStore, IRotator,
/// IStoreFileCompressor, SizeAndDailyRotator, GzipOldGenerationsCompressor,
/// NullTelemetryStore) had no live implementation and was never reached from
/// the product code.
/// </summary>
internal sealed record TelemetrySinkHealth(
    bool Enabled,
    TelemetryDisableReason DisableReason,
    int QueuedLines,
    long DroppedLines,
    long Flushes,
    long Rotations,
    long Compressions,
    long FlushErrors,
    long Errors,
    string? LastError);
