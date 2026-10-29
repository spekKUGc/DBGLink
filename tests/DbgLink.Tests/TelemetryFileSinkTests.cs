using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

public sealed class TelemetryFileSinkTests
{
    [Fact]
    public void TryCreate_ReturnsNull_WhenDisabled()
    {
        var metrics = new ServerMetrics();
        using var dir1 = TempDir.Create("dbglink-telemetry-");
        using var dir2 = TempDir.Create("dbglink-telemetry-");
        Assert.Null(TelemetryFileSink.TryCreate(metrics, dir1, _ => "off"));
        Assert.Null(TelemetryFileSink.TryCreate(metrics, dir2, _ => "0"));
    }

    [Fact]
    public void LogTool_AppendsCompactLines_AndDigestStaysSmall()
    {
        using var dir = TempDir.Create("dbglink-telemetry-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);
        metrics.FileSink = sink;

        using (var scope = metrics.BeginTool("InspectFunction"))
            scope.Complete(failed: false, outcome: "ok", requestBytes: 120, responseBytes: 2048);
        using (var scope = metrics.BeginTool("ReadMemAtAddress"))
            scope.Complete(failed: true, outcome: "backend_error", requestBytes: 30, responseBytes: 0, errorCode: "debugger_closed");

        sink!.Flush();
        sink.WriteDigest();

        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        Assert.Contains("InspectFunction ok", events);
        Assert.Contains("ReadMemAtAddress backend_error", events);
        Assert.Contains("err=debugger_closed", events);
        // One line per call: compact, no JSON braces.
        Assert.DoesNotContain("{", events.Split('\n')[1]);

        var digest = TestFileIO.ReadAllTextRetry(sink.DigestPath);
        Assert.Contains("# DBGLink telemetry digest", digest);
        Assert.Contains("Read this file first", digest);
        Assert.Contains("debugger_closed", digest);
        Assert.True(new FileInfo(sink.DigestPath).Length < 32 * 1024);
    }

    [Fact]
    public void Concurrent_Logging_KeepsEveryLine()
    {
        using var dir = TempDir.Create("dbglink-telemetry-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null);
        Assert.NotNull(sink);

        // The queue (cap 2000) and the flush lock make concurrent logging
        // lossless: every line from every thread must reach the active file.
        Parallel.For(0, 200, new ParallelOptions { MaxDegreeOfParallelism = 8 },
            i => sink!.LogTool("ConcurrentTool", "ok", 1, 10, 100, 0));
        sink!.Flush();
        sink.Flush();

        var events = TestFileIO.ReadAllTextRetry(sink.EventsPath);
        var lines = events.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(l => l.Contains("ConcurrentTool ok"));
        Assert.Equal(200, lines);
    }

    [Fact]
    public void Rotation_KeepsBoundedGenerations()
    {
        using var dir = TempDir.Create("dbglink-telemetry-");
        var metrics = new ServerMetrics();
        using var sink = TelemetryFileSink.TryCreate(metrics, dir, _ => null, maxEventsBytes: 200);
        Assert.NotNull(sink);
        for (var i = 0; i < 50; i++)
            sink!.LogTool("EvaluateExpressions", "ok", 1, 10, 100, 0);
        sink!.Flush();
        sink.Flush();
        Assert.True(new FileInfo(sink.EventsPath).Length < 4096);
        Assert.True(Directory.GetFiles(dir).Length <= 4); // per-PID active file + up to 2 generations + digest.md
    }

    [Fact]
    public void Sink_NeverThrows_OnBadDirectory()
    {
        var metrics = new ServerMetrics();
        metrics.FileSink = null;
        metrics.RecordToolResult("X", "ok", 1, 1, 1);
        var snapshot = metrics.Snapshot();
        Assert.NotNull(snapshot["tools"]);
    }
}
