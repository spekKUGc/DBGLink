using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// FileProtection diagnostics: a protection failure must surface through
/// the onError callback instead of failing silently, and the call itself
/// must never throw. A missing path is the deterministic cross-platform
/// trigger (a read-only directory would still succeed on Windows, and
/// stripping ACLs could lock the CI worker out of cleanup).
/// </summary>
public sealed class FileProtectionTests
{
    [Fact]
    public void ProtectDirectory_MissingPath_ReportsWithoutThrowing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "dbglink-nodir-" + Guid.NewGuid().ToString("N"), "sub");
        string? reason = null;
        var error = Record.Exception(() => FileProtection.ProtectDirectory(missing, value => reason = value));
        Assert.Null(error);
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void ProtectFile_MissingPath_ReportsWithoutThrowing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "dbglink-nofile-" + Guid.NewGuid().ToString("N") + ".json");
        string? reason = null;
        var error = Record.Exception(() => FileProtection.ProtectFile(missing, value => reason = value));
        Assert.Null(error);
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void ProtectDirectory_ExistingPath_SucceedsSilently()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-dir-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var calls = 0;
            var error = Record.Exception(() => FileProtection.ProtectDirectory(directory, _ => calls++));
            Assert.Null(error);
            Assert.Equal(0, calls);
        }
        finally
        {
            Directory.Delete(directory);
        }
    }

    /// <summary>
    /// A healthy sink run (create + log + flush + digest) must not move the
    /// process-wide protection-error counter: onError fires only on real
    /// failures (see the missing-path Facts above), never on success.
    /// Delta-based, not absolute: the counter is process-wide and parallel
    /// telemetry failure-path tests may note errors concurrently. Up to five
    /// attempts: a genuinely chatty implementation dirties every window and
    /// still fails deterministically, while a momentary concurrent error
    /// ruins at most one attempt.
    /// </summary>
    [Fact]
    public void HealthySinkRun_DoesNotMoveProtectionErrorCounter()
    {
        using var dir = TempDir.Create("dbglink-protect-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        for (var attempt = 0; ; attempt++)
        {
            var before = sink!.Health.Errors;
            sink.LogTool("InspectFunction", "ok", 1, 10, 20, 5);
            sink.Flush();
            sink.WriteDigest();
            if (sink.Health.Errors == before)
                return;
            Assert.True(attempt < 4, "healthy sink runs kept moving the protection-error counter");
        }
    }
}
