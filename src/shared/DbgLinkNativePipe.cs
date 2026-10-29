using System.Buffers;
using System.IO.Pipes;
using System.Runtime.Versioning;

#pragma warning disable CA1416 // RequestAsync guards the Windows-only implementation at its public boundary.

namespace DbgLink.Shared;

/// <summary>
/// Exchanges one bounded message with the native DBGLink pipe.
///
/// The native bridge is a Win32 message-mode pipe. Use synchronous stream
/// operations on the managed client handle for compatibility with x64dbg's
/// native overlapped server; the blocking exchange is isolated on the thread
/// pool and cancellation closes the handle to release a pending read.
/// </summary>
public static class DbgLinkNativePipe
{
    public static async Task<byte[]> RequestAsync(
        string pipeName,
        ReadOnlyMemory<byte> request,
        int connectTimeoutMilliseconds,
        TimeSpan timeout,
        int maxResponseBytes,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The DBGLink native pipe is supported only on Windows.");
        if (string.IsNullOrWhiteSpace(pipeName))
            throw new ArgumentException("A native pipe name is required.", nameof(pipeName));
        if (request.IsEmpty)
            throw new ArgumentException("A native pipe request is required.", nameof(request));
        if (connectTimeoutMilliseconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(connectTimeoutMilliseconds));
        if (timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout));
        if (maxResponseBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));

        // The native server's request size is validated by its parser. Do not
        // allocate a second request buffer merely to revalidate that limit.
        var exchange = Task.Run(
            () => ExchangeSynchronously(
                pipeName,
                request,
                connectTimeoutMilliseconds,
                timeout,
                maxResponseBytes,
                cancellationToken),
            CancellationToken.None);
        return await exchange.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ExchangeSynchronously(
        string pipeName,
        ReadOnlyMemory<byte> request,
        int connectTimeoutMilliseconds,
        TimeSpan timeout,
        int maxResponseBytes,
        CancellationToken cancellationToken)
    {
        using var operationTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operationTimeout.CancelAfter(timeout);

        using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.None);
        using var cancellationRegistration = operationTimeout.Token.Register(
            static state => ((NamedPipeClientStream)state!).Dispose(),
            pipe);

        try
        {
            operationTimeout.Token.ThrowIfCancellationRequested();
            pipe.Connect(connectTimeoutMilliseconds);
            operationTimeout.Token.ThrowIfCancellationRequested();
            pipe.ReadMode = PipeTransmissionMode.Message;
            pipe.Write(request.Span);
            pipe.Flush();
            return ReadMessage(pipe, maxResponseBytes);
        }
        catch (ObjectDisposedException) when (operationTimeout.IsCancellationRequested)
        {
            throw new OperationCanceledException(operationTimeout.Token);
        }
        catch (IOException) when (operationTimeout.IsCancellationRequested)
        {
            throw new OperationCanceledException(operationTimeout.Token);
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ReadMessage(NamedPipeClientStream pipe, int maxResponseBytes)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(8 * 1024, maxResponseBytes));
        using var response = new MemoryStream(Math.Min(4 * 1024, maxResponseBytes));
        try
        {
            while (true)
            {
                var read = pipe.Read(buffer, 0, buffer.Length);
                if (read == 0)
                    throw new InvalidDataException("The native bridge closed the pipe before completing its response.");
                if (response.Length > maxResponseBytes - read)
                    throw new InvalidDataException("The native bridge response exceeded its byte limit.");

                response.Write(buffer, 0, read);
                if (pipe.IsMessageComplete)
                    return response.ToArray();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}

#pragma warning restore CA1416
