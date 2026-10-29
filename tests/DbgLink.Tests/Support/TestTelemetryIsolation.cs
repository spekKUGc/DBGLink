using System.Runtime.CompilerServices;

namespace DbgLink.Tests;

/// <summary>
/// Test isolation for the local telemetry sink.
///
/// The suite creates a LocalMcpServer in ~180 places. Without this, every one
/// of them resolved the sink's default directory to the user's real
/// %LOCALAPPDATA%\DBGLink\telemetry: the suite wrote into production data,
/// raced with itself over the shared digest.md, and ran one machine-wide
/// process-table enumeration per sink (the orphan cleanup). Pointing the
/// sink at a per-run temporary directory keeps the suite out of the user's
/// data and gives every run its own digest.
///
/// A module initializer is used because xUnit 2.x has no assembly fixture:
/// it runs when the test assembly is loaded, before any test can create a
/// sink.
/// </summary>
internal static class TestTelemetryIsolation
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        try
        {
            var directory = Path.Combine(
                Path.GetTempPath(), "dbglink-test-telemetry-" + Environment.ProcessId);
            Directory.CreateDirectory(directory);
            Environment.SetEnvironmentVariable("DBGLINK_TELEMETRY_DIR", directory);
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Cleanup(directory);
        }
        catch
        {
            // Isolation is best-effort: a failure here must not fail the run.
        }
    }

    private static void Cleanup(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
        catch { }
    }
}
