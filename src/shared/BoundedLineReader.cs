using System.Buffers;
using System.Text;

namespace DbgLink.Shared;

/// <summary>
/// Reads exactly one newline-terminated frame from a stream under a byte cap.
/// Returns null on EOF before a newline, a frame over <paramref name="maxBytes"/>,
/// bytes after the newline in the same read, or an empty frame when
/// <paramref name="rejectEmptyLine"/> is set. Decodes with strict UTF-8
/// (invalid sequences throw <see cref="DecoderFallbackException"/>) and trims
/// a trailing CR.
/// </summary>
public static class BoundedLineReader
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<string?> ReadAsync(
        Stream stream,
        int maxBytes,
        bool rejectEmptyLine,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        using var data = new MemoryStream(capacity: 4096);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return null;

                var newline = Array.IndexOf(buffer, (byte)'\n', 0, read);
                var count = newline >= 0 ? newline : read;
                if (data.Length + count > maxBytes)
                    return null;
                data.Write(buffer, 0, count);
                if (newline >= 0)
                {
                    if (newline + 1 != read)
                        return null;
                    var line = StrictUtf8.GetString(data.GetBuffer(), 0, checked((int)data.Length)).TrimEnd('\r');
                    if (rejectEmptyLine && line.Length == 0)
                        return null;
                    return line;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
