extern alias Server;
using System.Text;
using BoundedLineReader = Server::DbgLink.Shared.BoundedLineReader;
using Xunit;

namespace DbgLink.Tests;

public sealed class BoundedLineReaderTests
{
    [Fact]
    public async Task ReadAsync_NoNewline_ReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes("hello without newline");
        using var stream = new MemoryStream(bytes);
        var result = await BoundedLineReader.ReadAsync(stream, 1024, false, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task ReadAsync_GarbageAfterNewlineInSameRead_ReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes("valid\ntrailing_garbage");
        using var stream = new MemoryStream(bytes);
        var result = await BoundedLineReader.ReadAsync(stream, 1024, false, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task ReadAsync_ExactlyMaxBytesPlusNewline_ReturnsLine()
    {
        var expected = new string('x', 64);
        var bytes = Encoding.UTF8.GetBytes(expected + "\n");
        using var stream = new MemoryStream(bytes);
        var result = await BoundedLineReader.ReadAsync(stream, 64, false, CancellationToken.None);
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task ReadAsync_MaxBytesPlusOneBeforeNewline_ReturnsNull()
    {
        var payload = new string('x', 65);
        var bytes = Encoding.UTF8.GetBytes(payload + "\n");
        using var stream = new MemoryStream(bytes);
        var result = await BoundedLineReader.ReadAsync(stream, 64, false, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task ReadAsync_CrLf_EmptyLineRejection()
    {
        var bytes = Encoding.UTF8.GetBytes("\r\n");
        using var streamNotRejected = new MemoryStream(bytes);
        var resultNotRejected = await BoundedLineReader.ReadAsync(streamNotRejected, 1024, false, CancellationToken.None);
        Assert.Equal("", resultNotRejected);

        using var streamRejected = new MemoryStream(bytes);
        var resultRejected = await BoundedLineReader.ReadAsync(streamRejected, 1024, true, CancellationToken.None);
        Assert.Null(resultRejected);
    }

    [Fact]
    public async Task ReadAsync_InvalidUtf8Byte_ThrowsDecoderFallbackException()
    {
        var bytes = new byte[] { (byte)'a', 0xFF, (byte)'b', (byte)'\n' };
        using var stream = new MemoryStream(bytes);
        await Assert.ThrowsAsync<DecoderFallbackException>(async () =>
        {
            await BoundedLineReader.ReadAsync(stream, 1024, false, CancellationToken.None);
        });
    }
}
