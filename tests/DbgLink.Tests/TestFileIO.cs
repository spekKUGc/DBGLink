namespace DbgLink.Tests;

/// <summary>
/// Resilient file reads for test assertions on telemetry output: the sink
/// writes with append/rotate/move semantics on timer threads, and external
/// processes (AV/indexer) may briefly lock a fresh file. A short bounded
/// retry turns those races into stable assertions instead of flakes.
/// </summary>
internal static class TestFileIO
{
    internal static string ReadAllTextRetry(string path, int attempts = 10, int delayMs = 50)
    {
        if (attempts < 1)
            throw new ArgumentOutOfRangeException(nameof(attempts));
        while (true)
        {
            try
            {
                return File.ReadAllText(path);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (--attempts <= 0)
                    throw;
                Thread.Sleep(delayMs);
            }
        }
    }
}
