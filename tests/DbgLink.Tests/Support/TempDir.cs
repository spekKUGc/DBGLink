namespace DbgLink.Tests;

/// <summary>
/// Owned temporary directory for tests. Created under %TEMP% with a
/// <c>dbglink-</c> prefix, deleted best-effort (recursive) on Dispose.
/// Deletion tolerates read-only attributes and locked/transient files:
/// it never throws. Use as <c>using var dir = TempDir.Create("dbglink-...")</c>;
/// the implicit <see cref="string"/> conversion keeps existing
/// <c>Path.Combine(dir, ...)</c> / <c>new GhidraClient(dir)</c> call sites
/// compiling unchanged while guaranteeing cleanup (no 19k-dir leak).
/// </summary>
internal sealed class TempDir : IDisposable
{
    public string Path { get; }

    private int _disposed;

    private TempDir(string path) => Path = path;

    public static TempDir Create(string prefix = "dbglink-")
    {
        if (string.IsNullOrWhiteSpace(prefix))
            prefix = "dbglink-";
        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return new TempDir(path);
    }

    public static implicit operator string(TempDir dir) => dir.Path;

    public override string ToString() => Path;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        try
        {
            if (!Directory.Exists(Path))
                return;
            // Locked/read-only files (telemetry sinks, staged binaries) must
            // not wedge the cleanup: normalize attributes first, then delete.
            // Best-effort throughout: a wedged dir is a leak, never a failure.
            try
            {
                foreach (var file in Directory.EnumerateFiles(Path, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Normal); }
                    catch { }
                }
            }
            catch { }
            Directory.Delete(Path, recursive: true);
        }
        catch
        {
            try
            {
                if (Directory.Exists(Path))
                    Directory.Delete(Path, recursive: true);
            }
            catch { }
        }
    }
}
