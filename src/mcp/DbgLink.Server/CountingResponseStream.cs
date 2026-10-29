namespace DbgLink.Server;

internal sealed class CountingResponseStream(Stream inner, ServerMetrics metrics) : Stream
{
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken token) => inner.FlushAsync(token);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count)
    {
        inner.Write(buffer, offset, count);
        metrics.RecordBytesSent(count);
    }
    // Span path: Stream's default copies through a rented array into
    // Write(byte[],...); writing through directly skips that copy while
    // still counting the bytes exactly once.
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        inner.Write(buffer);
        metrics.RecordBytesSent(buffer.Length);
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
        => WriteAsync(buffer.AsMemory(offset, count), token).AsTask();
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
    {
        await inner.WriteAsync(buffer, token).ConfigureAwait(false);
        metrics.RecordBytesSent(buffer.Length);
    }
}
