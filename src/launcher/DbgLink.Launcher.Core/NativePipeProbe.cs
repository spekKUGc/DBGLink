using DbgLink.Shared;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Verifies that the launcher-connected pipe is the expected DBGLink native bridge.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NativePipeProbe
{
    private const int MaxResponseBytes = 64 * 1024;
    private const int ConnectTimeoutMilliseconds = 500;
    private static readonly TimeSpan MaxWaitTimeout = TimeSpan.FromMinutes(10);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] PingRequest = StrictUtf8.GetBytes("{\"id\":1,\"method\":\"ping\"}\n");

    public static async Task<NativeBridgeHandshake> WaitForReadyAsync(
        string pipeName,
        int expectedProcessId,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Func<bool>? isProcessAlive = null,
        string? pipeToken = null)
    {
        if (string.IsNullOrWhiteSpace(pipeName))
            throw new ArgumentException("A native bridge pipe name is required.", nameof(pipeName));
        if (expectedProcessId <= 0)
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        if (pipeToken is not null && !NativeEndpointResolver.IsValidPipeToken(pipeToken))
            throw new ArgumentException("The native pipe token is invalid.", nameof(pipeToken));
        var barePipeName = NormalizePipeName(pipeName, expectedProcessId);
        if (timeout <= TimeSpan.Zero || timeout > MaxWaitTimeout)
            throw new ArgumentOutOfRangeException(nameof(timeout));

        var pingRequest = BuildPingRequest(pipeToken);
        var stopwatch = Stopwatch.StartNew();
        Exception? lastError = null;
        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (isProcessAlive is not null && !isProcessAlive())
                throw new InvalidOperationException("The debugger exited before the native bridge became ready.");

            try
            {
                var remainingForProbe = timeout - stopwatch.Elapsed;
                if (remainingForProbe <= TimeSpan.Zero)
                    break;

                return await ProbeOnceAsync(
                    barePipeName,
                    expectedProcessId,
                    pingRequest,
                    cancellationToken,
                    remainingForProbe).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = new TimeoutException("The native bridge probe timed out.");
            }
            catch (IOException exception)
            {
                lastError = exception;
            }
            catch (TimeoutException exception)
            {
                lastError = exception;
            }
            catch (UnauthorizedProbeException exception)
            {
                // The token is fixed for the pipe's lifetime, so a rejection is
                // terminal: retrying only burns the budget and can hide the
                // reason behind a later connect failure.
                lastError = exception;
                break;
            }
            catch (InvalidDataException exception)
            {
                lastError = exception;
            }
            catch (JsonException exception)
            {
                lastError = new InvalidDataException("The native bridge returned invalid JSON.", exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                lastError = exception;
            }

            var remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
                break;
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(250, remaining.TotalMilliseconds)), cancellationToken)
                .ConfigureAwait(false);
        }

        var detail = lastError is null
            ? "No readable pipe endpoint was observed."
            : DescribeProbeFailure(lastError);
        throw new TimeoutException(
            $"The DBGLink native bridge did not answer a valid ping before the timeout " +
            $"(debugger PID {expectedProcessId}, pipe {pipeName}). {detail} " +
            "Verify that the matching DbgLink.dp64/DbgLink.dp32 plugin is loaded " +
            "in this debugger and that it runs under the same Windows account.");
    }

    /// <summary>
    /// Accepts the legacy bare pipe name (<c>DbgLink.Control.{pid}</c>) and the
    /// N1 full form (<c>\\.\pipe\DbgLink.Control.{pid}.&lt;suffix&gt;</c>).
    /// Either way the name must be bound to the expected debugger process id;
    /// the caller-facing full form is stripped to the bare name that
    /// <c>NamedPipeClientStream</c> expects.
    /// </summary>
    private static string NormalizePipeName(string pipeName, int expectedProcessId)
    {
        var bare = pipeName.StartsWith(NativeEndpointResolver.PipePrefix, StringComparison.Ordinal)
            ? pipeName[NativeEndpointResolver.PipePrefix.Length..]
            : pipeName;
        var expected = $"DbgLink.Control.{expectedProcessId}";
        if (string.Equals(bare, expected, StringComparison.Ordinal))
            return bare;
        if (bare.StartsWith(expected + ".", StringComparison.Ordinal) &&
            bare.Length > expected.Length + 1 &&
            bare.Length <= NativeEndpointResolver.MaxPipeNameChars &&
            !bare[(expected.Length + 1)..].Any(character => character == '\\' || char.IsControl(character)))
            return bare;
        throw new ArgumentException(
            "The pipe name must be bound to the expected debugger process ID.", nameof(pipeName));
    }

    private static byte[] BuildPingRequest(string? pipeToken)
        => pipeToken is null
            ? PingRequest
            : StrictUtf8.GetBytes("{\"id\":1,\"method\":\"ping\",\"token\":\"" + pipeToken + "\"}\n");

    private static async Task<NativeBridgeHandshake> ProbeOnceAsync(
        string pipeName,
        int expectedProcessId,
        byte[] pingRequest,
        CancellationToken cancellationToken,
        TimeSpan probeTimeout)
    {
        var responseBytes = await DbgLinkNativePipe.RequestAsync(
            pipeName,
            pingRequest,
            ConnectTimeoutMilliseconds,
            probeTimeout,
            MaxResponseBytes,
            cancellationToken).ConfigureAwait(false);
        var line = DecodeResponse(responseBytes);
        if (string.IsNullOrWhiteSpace(line))
            throw new InvalidDataException("The native bridge returned an empty ping response.");

        using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (IsUnauthorizedResponse(root))
            throw new UnauthorizedProbeException();
        if (root.ValueKind != JsonValueKind.Object ||
            JsonProtocolValidation.HasDuplicateProperties(root) ||
            !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.Number ||
            !id.TryGetInt32(out var responseId) || responseId != 1 ||
            !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("plugin", out var plugin) || plugin.ValueKind != JsonValueKind.String || plugin.GetString() != "DBGLink" ||
            !root.TryGetProperty("bridge", out var bridge) || bridge.ValueKind != JsonValueKind.String || bridge.GetString() != "native" ||
            !root.TryGetProperty("pid", out var pid) || pid.ValueKind != JsonValueKind.Number ||
            !pid.TryGetInt32(out var actualPid) || actualPid != expectedProcessId ||
            !root.TryGetProperty("debugging", out var debugging) ||
            debugging.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException("The native bridge ping response did not match the expected DBGLink contract.");
        }

        return new(expectedProcessId, debugging.GetBoolean());
    }

    private static bool IsUnauthorizedResponse(JsonElement root)
    {
        try
        {
            return root.ValueKind == JsonValueKind.Object &&
                !JsonProtocolValidation.HasDuplicateProperties(root) &&
                root.TryGetProperty("ok", out var ok) &&
                ok.ValueKind == JsonValueKind.False &&
                root.TryGetProperty("error", out var error) &&
                error.ValueKind == JsonValueKind.Object &&
                error.TryGetProperty("code", out var code) &&
                code.ValueKind == JsonValueKind.String &&
                string.Equals(code.GetString(), "unauthorized", StringComparison.Ordinal);
        }
        catch (InvalidOperationException) { return false; }
    }

    private static string DecodeResponse(byte[] responseBytes)
    {
        var newline = Array.IndexOf(responseBytes, (byte)'\n');
        if (newline < 0 || newline + 1 != responseBytes.Length)
            throw new InvalidDataException("The native bridge response was not one complete JSON line.");

        try
        {
            return StrictUtf8.GetString(responseBytes, 0, newline).TrimEnd('\r');
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("The native bridge returned invalid UTF-8.", exception);
        }
    }

    private sealed class UnauthorizedProbeException()
        : Exception("The native bridge rejected the pipe token (unauthorized).");

    private static string DescribeProbeFailure(Exception exception)
        => exception switch
        {
            UnauthorizedAccessException =>
                "Access was denied while opening the pipe; its ACL may not allow this launcher account.",
            TimeoutException =>
                "The pipe was present but did not complete the ping in time.",
            UnauthorizedProbeException =>
                "The pipe rejected the token (unauthorized).",
            InvalidDataException =>
                $"The pipe answered, but its response was not the expected DBGLink contract ({exception.Message})",
            IOException =>
                $"The pipe connection failed ({exception.Message})",
            _ =>
                $"The last probe failed with {exception.GetType().Name} ({exception.Message})"
        };
}

public sealed record NativeBridgeHandshake(int ProcessId, bool Debugging);
