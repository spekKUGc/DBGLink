using DbgLink.Shared;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Performs the bounded, loopback-only readiness handshake with the launcher-owned Ghidra bridge.
/// </summary>
public static class GhidraBridgeProbe
{
    private const int ProtocolVersion = 1;
    private const int MaxEndpointBytes = 8 * 1024;
    private const int MaxResponseBytes = 256 * 1024;
    private const int MaxEndpointCandidates = 16;
    private const int MaxEndpointDirectoryEntries = 4_096;
    private const int MaxTokenChars = 256;
    private static readonly TimeSpan MaxWaitTimeout = TimeSpan.FromMinutes(20);
    private static readonly TimeSpan MaxCandidateProbeTimeout = TimeSpan.FromSeconds(2);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] NewLine = [(byte)'\n'];

    public static async Task<GhidraBridgeStatus> WaitForReadyAsync(
        string endpointDirectory,
        bool requireActiveProgram,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(endpointDirectory))
            throw new ArgumentException("A Ghidra endpoint directory is required.", nameof(endpointDirectory));
        if (timeout <= TimeSpan.Zero || timeout > MaxWaitTimeout)
            throw new ArgumentOutOfRangeException(nameof(timeout));
        if (!Path.IsPathFullyQualified(endpointDirectory) || !PathSafety.IsReparseFree(endpointDirectory))
            throw new ArgumentException("The Ghidra endpoint directory must be a safe absolute path.", nameof(endpointDirectory));

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var candidate in EnumerateCandidates(endpointDirectory))
            {
                var endpoint = TryReadEndpoint(candidate);
                if (endpoint is null)
                    continue;

                var remainingForProbe = timeout - stopwatch.Elapsed;
                if (remainingForProbe <= TimeSpan.Zero)
                    break;

                var status = await TryReadStatusAsync(
                    endpoint,
                    cancellationToken,
                    remainingForProbe < MaxCandidateProbeTimeout
                        ? remainingForProbe
                        : MaxCandidateProbeTimeout).ConfigureAwait(false);
                if (status is null || (requireActiveProgram && !status.Value.Available))
                    continue;

                stopwatch.Stop();
                return new(
                    endpoint.Host,
                    endpoint.Port,
                    endpoint.ProcessId,
                    status.Value.Available,
                    status.Value.ResponseBytes,
                    stopwatch.Elapsed.TotalMilliseconds,
                    status.Value.Program);
            }

            var remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
                break;
            await Task.Delay(
                TimeSpan.FromMilliseconds(Math.Min(250, remaining.TotalMilliseconds)),
                cancellationToken).ConfigureAwait(false);
        }

        var requirement = requireActiveProgram ? "an active Ghidra program" : "a Ghidra bridge endpoint";
        throw new TimeoutException($"Ghidra did not expose {requirement} through the loopback bridge before the timeout.");
    }

    private static IEnumerable<string> EnumerateCandidates(string directory)
    {
        try
        {
            if (!Directory.Exists(directory))
                return Array.Empty<string>();

            var newest = new PriorityQueue<string, DateTime>();
            var scanned = 0;
            foreach (var path in Directory.EnumerateFiles(directory, "ghidra-bridge-*.json"))
            {
                if (scanned++ >= MaxEndpointDirectoryEntries)
                    break;

                try
                {
                    newest.Enqueue(path, File.GetLastWriteTimeUtc(path));
                    if (newest.Count > MaxEndpointCandidates)
                        newest.Dequeue();
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (ArgumentException) { }
                catch (NotSupportedException) { }
            }

            return newest.UnorderedItems
                .OrderByDescending(item => item.Priority)
                .Select(item => item.Element)
                .ToArray();
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
        catch (ArgumentException)
        {
            return Array.Empty<string>();
        }
        catch (NotSupportedException)
        {
            return Array.Empty<string>();
        }
    }

    private static GhidraEndpoint? TryReadEndpoint(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!Path.IsPathFullyQualified(path) || !PathSafety.IsReparseFree(path) ||
                !info.Exists || info.Attributes.HasFlag(FileAttributes.Directory) ||
                info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.Length is <= 0 or > MaxEndpointBytes)
                return null;

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.SequentialScan);
            var endpointBytes = new byte[MaxEndpointBytes];
            var endpointLength = 0;
            while (endpointLength < endpointBytes.Length)
            {
                var read = stream.Read(endpointBytes.AsSpan(endpointLength));
                if (read == 0)
                    break;
                endpointLength += read;
            }
            if (endpointLength == 0 ||
                (endpointLength == endpointBytes.Length && stream.ReadByte() != -1))
                return null;

            using var document = JsonDocument.Parse(
                endpointBytes.AsMemory(0, endpointLength),
                new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !TryReadInt32(root, "protocolVersion", out var protocol) || protocol != ProtocolVersion ||
                !TryReadString(root, "host", out var host) || host != "127.0.0.1" ||
                !TryReadInt32(root, "port", out var port) || port is < 1 or > 65_535 ||
                !TryReadInt64(root, "pid", out var processId) || processId <= 0 ||
                !TryReadString(root, "token", out var token) ||
                token.Length is < 16 or > MaxTokenChars || token.Any(char.IsControl))
            {
                return null;
            }

            return new(host, port, processId, token);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private static async Task<GhidraStatus?> TryReadStatusAsync(
        GhidraEndpoint endpoint,
        CancellationToken cancellationToken,
        TimeSpan probeTimeout)
    {
        using var probeCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCancellation.CancelAfter(probeTimeout);

        try
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, endpoint.Port, probeCancellation.Token).ConfigureAwait(false);
            await using var network = client.GetStream();

            var request = JsonSerializer.SerializeToUtf8Bytes(new
            {
                id = 1,
                token = endpoint.Token,
                method = "status",
                @params = new { }
            });
            await network.WriteAsync(request, probeCancellation.Token).ConfigureAwait(false);
            await network.WriteAsync(NewLine, probeCancellation.Token).ConfigureAwait(false);
            await network.FlushAsync(probeCancellation.Token).ConfigureAwait(false);

            var line = await BoundedLineReader.ReadAsync(network, MaxResponseBytes, rejectEmptyLine: false, probeCancellation.Token).ConfigureAwait(false);
            if (line is null)
                return null;

            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !TryReadInt32(root, "id", out var responseId) || responseId != 1 ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object ||
                !TryReadString(result, "endpoint", out var responseEndpoint) || responseEndpoint != "127.0.0.1" ||
                !result.TryGetProperty("available", out var available) ||
                available.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return null;
            }

            return new(
                available.GetBoolean(),
                StrictUtf8.GetByteCount(line),
                TryReadProgramSummary(result));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (SocketException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static bool TryReadString(JsonElement objectElement, string name, out string value)
    {
        if (objectElement.TryGetProperty(name, out var property) &&
            property.ValueKind == JsonValueKind.String &&
            property.GetString() is { } text)
        {
            value = text;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryReadInt32(JsonElement objectElement, string name, out int value)
    {
        value = 0;
        return objectElement.TryGetProperty(name, out var property) &&
            property.ValueKind == JsonValueKind.Number &&
            property.TryGetInt32(out value);
    }

    private static bool TryReadInt64(JsonElement objectElement, string name, out long value)
    {
        value = 0;
        return objectElement.TryGetProperty(name, out var property) &&
            property.ValueKind == JsonValueKind.Number &&
            property.TryGetInt64(out value);
    }

    private static GhidraProgramSummary? TryReadProgramSummary(JsonElement result)
    {
        if (!result.TryGetProperty("program", out var program) ||
            program.ValueKind != JsonValueKind.Object ||
            !TryReadString(program, "fileName", out var fileName) ||
            string.IsNullOrWhiteSpace(fileName))
        {
            return null;
        }

        var format = ReadOptionalString(program, "format", "unknown");
        var architecture = ReadOptionalString(program, "architecture", "unknown");
        var language = ReadOptionalString(program, "language", "unknown");
        var languageId = ReadOptionalString(program, "languageId", "unknown");
        var compiler = ReadOptionalString(program, "compiler", "unknown");
        var compilerSpec = ReadOptionalString(program, "compilerSpec", "unknown");
        var sha256 = ReadOptionalString(program, "sha256", string.Empty);
        var imageBase = ReadOptionalString(program, "imageBase", string.Empty);
        var minAddress = ReadOptionalString(program, "minAddress", string.Empty);
        var maxAddress = ReadOptionalString(program, "maxAddress", string.Empty);
        var functionCount = 0;
        if (program.TryGetProperty("functionCount", out var functionCountElement) &&
            functionCountElement.ValueKind == JsonValueKind.Number)
        {
            functionCountElement.TryGetInt32(out functionCount);
            functionCount = Math.Max(0, functionCount);
        }

        return new(
            fileName,
            format,
            architecture,
            language,
            languageId,
            compiler,
            compilerSpec,
            sha256,
            imageBase,
            minAddress,
            maxAddress,
            functionCount);
    }

    private static string ReadOptionalString(JsonElement objectElement, string name, string fallback)
        => TryReadString(objectElement, name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;

    private sealed record GhidraEndpoint(string Host, int Port, long ProcessId, string Token);

    private readonly record struct GhidraStatus(
        bool Available,
        int ResponseBytes,
        GhidraProgramSummary? Program);
}

public sealed record GhidraBridgeStatus(
    string Host,
    int Port,
    long ProcessId,
    bool Available,
    int ResponseBytes,
    double ReadyMs,
    GhidraProgramSummary? Program = null);

public sealed record GhidraProgramSummary(
    string FileName,
    string Format,
    string Architecture,
    string Language,
    string LanguageId,
    string Compiler,
    string CompilerSpec,
    string Sha256,
    string ImageBase,
    string MinAddress,
    string MaxAddress,
    int FunctionCount);
