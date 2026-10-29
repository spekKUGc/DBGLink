using DbgLink.Shared;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace DbgLink.Server;

internal static class ToolSupport
{
    /// <summary>
    /// The launcher's native pipe token is a credential for direct bridge
    /// writes. The MCP server needs it only to build its own BridgeClient; it
    /// must never reach a model-visible tool result. Keep normal responses
    /// byte-identical and only re-serialize when the key is present.
    /// </summary>
    internal static string RedactSessionSecrets(string? raw)
    {
        if (string.IsNullOrEmpty(raw) ||
            !raw.Contains("\"nativePipeToken\"", StringComparison.Ordinal))
            return raw ?? "";
        try
        {
            var root = JsonNode.Parse(raw);
            if (root is null)
                return raw;
            RedactSessionSecrets(root);
            return root.ToJsonString();
        }
        catch (JsonException)
        {
            return raw;
        }
        catch (InvalidOperationException)
        {
            return raw;
        }
    }

    private static void RedactSessionSecrets(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            obj.Remove("nativePipeToken");
            foreach (var child in obj.Select(pair => pair.Value).ToArray())
                if (child is not null) RedactSessionSecrets(child);
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array)
                if (child is not null) RedactSessionSecrets(child);
        }
    }

    internal static bool IsJsonInteger(JsonElement value)
    {
        var raw = value.GetRawText();
        if (raw.Length == 0)
            return false;
        var index = raw[0] == '-' ? 1 : 0;
        if (index == raw.Length)
            return false;
        if (raw[index] == '0' && index + 1 < raw.Length)
            return false;
        for (; index < raw.Length; index++)
        {
            if (raw[index] is < '0' or > '9')
                return false;
        }
        return true;
    }

    internal static string? ReadAnalysisId(JsonElement? arguments)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } ||
            !arguments.Value.TryGetProperty("analysisId", out var value))
            return null;

        var text = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        if (text is null || !AnalysisSessionRegistry.IsValidAnalysisId(text))
            throw new InvalidOperationException("analysisId must be a bounded identifier returned by OpenGhidraFile.");

        return text;
    }

    internal static JsonElement? RemoveAnalysisId(JsonElement? arguments)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } ||
            !arguments.Value.EnumerateObject().Any(property => property.NameEquals("analysisId")))
            return arguments;

        var buffer = new ArrayBufferWriter<byte>(256);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in arguments.Value.EnumerateObject())
            {
                if (property.NameEquals("analysisId"))
                    continue;
                writer.WritePropertyName(property.Name);
                property.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
        return JsonSerializer.Deserialize<JsonElement>(buffer.WrittenSpan);
    }

    internal static int ReadArgumentInt(JsonElement? arguments, string name, int fallback)
    {
        return arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty(name, out var value) &&
            value.TryGetInt32(out var number)
            ? number
            : fallback;
    }

    /// <summary>
    /// One budget rule for composite tools: maxChars stays the hard character
    /// ceiling, while an explicit maxTokens optionally tightens it with a
    /// conservative 4-chars/token guard. 0 disables the token guard.
    /// </summary>
    internal const int GuardCharsPerToken = 4;
    internal const int MaxGuardTokens = 30_000;
    // The response envelope alone costs roughly 150-200 tokens, so caps below
    // this floor cannot be honored; treat them as the floor instead of
    // returning a misleading maxTokens echo.
    internal const int MinGuardTokens = 500;

    internal static int ReadResponseBudget(
        JsonElement? arguments, int defaultChars, int minChars, int maxChars, out int maxTokens)
    {
        var chars = Math.Clamp(ReadArgumentInt(arguments, "maxChars", defaultChars), minChars, maxChars);
        maxTokens = Math.Clamp(ReadArgumentInt(arguments, "maxTokens", 0), 0, MaxGuardTokens);
        if (maxTokens is > 0 and < MinGuardTokens)
            maxTokens = MinGuardTokens;
        if (maxTokens > 0)
            chars = Math.Min(chars, maxTokens * GuardCharsPerToken);
        return chars;
    }

    internal static int EstimateGuardTokens(int chars)
        => (Math.Max(0, chars) + GuardCharsPerToken - 1) / GuardCharsPerToken;

    internal static string WithTokenBudgetHint(string continuation, int maxTokens)
        => maxTokens > 0
            ? continuation.Replace("maxChars", "maxChars/maxTokens", StringComparison.Ordinal)
            : continuation;

    internal static bool ReadArgumentBool(JsonElement? arguments, string name, bool fallback)
    {
        return arguments is { ValueKind: JsonValueKind.Object } &&
            arguments.Value.TryGetProperty(name, out var value) &&
            value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;
    }

    internal static string? ReadArgumentString(JsonElement? arguments, string name)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } ||
            !arguments.Value.TryGetProperty(name, out var value) ||
            value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    internal static JsonElement ToJsonElement(JsonObject value)
        => JsonSerializer.SerializeToElement(value);

    internal static string LimitSnapshotText(string text, int budget, ref bool truncated)
    {
        if (text.Length <= budget)
            return text;

        truncated = true;
        const string suffix = "\n...[truncated]";
        if (budget <= suffix.Length)
            return suffix[..budget];

        var prefixLength = budget - suffix.Length;
        // Keep the returned .NET string well-formed when bridge text contains
        // a supplementary Unicode code point at the truncation boundary.
        if (prefixLength > 0 && char.IsHighSurrogate(text[prefixLength - 1]))
            prefixLength--;
        if (prefixLength < text.Length && char.IsLowSurrogate(text[prefixLength]))
            prefixLength--;
        return text[..prefixLength] + suffix;
    }

    internal static bool IsSafeText(string text, bool allowLineBreaks)
    {
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (char.IsControl(character) &&
                !(allowLineBreaks && character is '\r' or '\n' or '\t'))
                return false;
            if (char.GetUnicodeCategory(character) == UnicodeCategory.Format)
                return false;
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= text.Length || !char.IsLowSurrogate(text[index + 1]))
                    return false;
                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }
        return true;
    }

    internal readonly record struct BridgeResponseAnalysis(bool IsError, string Text);

    /// <summary>
    /// True only for the native bridge's definitive "no such method" answer.
    /// Used to pin a session to the individual snapshot path without treating
    /// transient transport errors as a permanent capability verdict.
    /// </summary>
    internal static bool IsUnknownBridgeMethod(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("error", out var error) ||
                error.ValueKind != JsonValueKind.Object)
                return false;
            var code = error.TryGetProperty("code", out var codeValue) && codeValue.ValueKind == JsonValueKind.String
                ? codeValue.GetString()
                : null;
            var message = error.TryGetProperty("message", out var messageValue) && messageValue.ValueKind == JsonValueKind.String
                ? messageValue.GetString()
                : null;
            return string.Equals(code, "native_error", StringComparison.Ordinal) &&
                message is not null &&
                message.Contains("Unknown bridge method", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Wire options for re-serialized payloads: emit non-ASCII and HTML-ish
    /// characters literally instead of \\uXXXX. Pure decoding-side change; the
    /// JSON means exactly the same thing, it just stops paying six bytes for
    /// one character.
    /// </summary>
    internal static readonly JsonSerializerOptions WireJsonOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Encoding options for tools that measure their own JSON against a byte
    /// budget. Same relaxed encoder as the wire, so a length probe counts the
    /// bytes the caller actually sees instead of the escaped form.
    /// </summary>
    internal static JsonSerializerOptions BudgetJsonOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Universal wire-shape pass, applied once to every finished tool payload:
    /// <list type="bullet">
    /// <item>structured data travels nested, never as an escaped JSON string
    /// (every quote in such a string used to cost six bytes as \\u0022 and the
    /// client had to parse a string to reach the object);</item>
    /// <item>a negative optional flag is not written at all — a truncation
    /// flag's presence means true, so <c>"truncated": false</c> was pure
    /// enumeration cost on every happy-path response;</item>
    /// <item>an empty object or array property is dropped, because "absent"
    /// and "empty" mean the same thing to a caller.</item>
    /// </list>
    /// Pure strings (hex dumps, decompiled C, messages) are never containers,
    /// so they pass through byte-identical.
    /// </summary>
    internal static string NestJsonText(string text)
    {
        if (text.Length < 2)
            return text;
        var root = text.AsSpan().TrimStart();
        if (root.IsEmpty || (root[0] != '{' && root[0] != '['))
            return text;

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(text);
        }
        catch (JsonException) { return text; }
        catch (ArgumentException) { return text; }
        if (node is not (JsonObject or JsonArray))
            return text;

        NestJsonTextChildren(node);
        DropOptionalNoise(node);
        // Always write with the wire encoder, even when nothing else changed:
        // the default encoder escapes '&', '+', '<' and '>' to \uXXXX (six
        // bytes for one character), which is pure loss in decompiled C, and
        // escapes every non-ASCII character the same way. The JSON is
        // semantically identical; only the byte count changes.
        return node.ToJsonString(WireJsonOptions);
    }

    /// <summary>
    /// Drops the two zero-information shapes from a finished payload: a
    /// negative optional flag (its presence is the signal) and an empty
    /// container (absent == empty). Values inside arrays are kept as-is: an
    /// array slot has no "absent" state, so removing one would change meaning.
    /// </summary>
    private static bool DropOptionalNoise(JsonNode? node)
    {
        var changed = false;
        if (node is not JsonObject obj)
            return false;

        foreach (var key in obj.Select(pair => pair.Key).ToArray())
        {
            var child = obj[key];
            if (child is JsonValue value && value.TryGetValue<bool>(out var flag) &&
                !flag && IsOptionalNegativeFlag(key))
            {
                obj.Remove(key);
                changed = true;
                continue;
            }
            if (child is JsonArray emptyArray && emptyArray.Count == 0)
            {
                obj.Remove(key);
                changed = true;
                continue;
            }
            if (child is JsonObject emptyObject && emptyObject.Count == 0)
            {
                obj.Remove(key);
                changed = true;
                continue;
            }
            changed |= DropOptionalNoise(child);
        }
        return changed;
    }

    private static bool IsOptionalNegativeFlag(string key)
        => key.EndsWith("truncated", StringComparison.OrdinalIgnoreCase) ||
           key.Equals("omitted", StringComparison.OrdinalIgnoreCase) ||
           key.Equals("partial", StringComparison.OrdinalIgnoreCase);

    private static bool NestJsonTextChildren(JsonNode? node)
    {
        var changed = false;
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(pair => pair.Key).ToArray())
                {
                    if (obj[key] is JsonValue value &&
                        value.TryGetValue<string>(out var nestedText) &&
                        TryParseContainer(nestedText) is { } nested)
                    {
                        obj[key] = nested;
                        changed = true;
                        continue;
                    }
                    changed |= NestJsonTextChildren(obj[key]);
                }
                break;
            case JsonArray array:
                for (var index = 0; index < array.Count; index++)
                {
                    if (array[index] is JsonValue value &&
                        value.TryGetValue<string>(out var nestedText) &&
                        TryParseContainer(nestedText) is { } nested)
                    {
                        array[index] = nested;
                        changed = true;
                        continue;
                    }
                    changed |= NestJsonTextChildren(array[index]);
                }
                break;
        }
        return changed;
    }

    private static JsonNode? TryParseContainer(string text)
    {
        if (text.Length < 2)
            return null;
        var first = text.AsSpan().TrimStart();
        if (first.IsEmpty || (first[0] != '{' && first[0] != '['))
            return null;
        try
        {
            var node = JsonNode.Parse(text);
            return node is JsonObject or JsonArray ? node : null;
        }
        catch (JsonException) { return null; }
        catch (ArgumentException) { return null; }
    }

    internal static BridgeResponseAnalysis AnalyzeBridgeResponse(string raw, bool includeText = true)
    {
        try
        {
            // A static batch wraps bounded backend responses in results/response envelopes.
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            var isError = root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("ok", out var ok) ||
                ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                ok.ValueKind == JsonValueKind.False ||
                (includeText && ok.ValueKind == JsonValueKind.True &&
                    (!root.TryGetProperty("text", out var textValue) ||
                     textValue.ValueKind != JsonValueKind.String) &&
                    (!root.TryGetProperty("result", out var resultValue) ||
                     resultValue.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined));
            if (!includeText || root.ValueKind != JsonValueKind.Object)
                return new(isError, raw);

            if (root.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
                return new(isError, text.GetString() ?? "");
            if (root.TryGetProperty("result", out var result))
                // A string result is the payload itself, not a JSON literal:
                // returning GetRawText() here handed callers a quoted, escaped
                // copy of the text they asked for.
                return new(isError, result.ValueKind == JsonValueKind.String
                    ? result.GetString() ?? ""
                    : result.GetRawText());
            if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
            {
                var code = ReadResponseString(error, "code", "bridge_error");
                var message = ReadResponseString(error, "message", "bridge request failed");
                var errorText = $"[{code}] {message}";
                if (errorText.Length > DbgLink.Shared.BridgeEnvelope.MaxErrorMessageChars)
                    errorText = errorText[..DbgLink.Shared.BridgeEnvelope.MaxErrorMessageChars] + "...[truncated]";
                return new(isError, errorText);
            }
            return new(isError, raw);
        }
        catch (JsonException) { }
        catch (InvalidOperationException) { }
        return new(true, raw);
    }

    internal static string ReadResponseString(JsonElement objectElement, string name, string fallback)
    {
        if (!objectElement.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            return fallback;

        var text = value.GetString();
        return string.IsNullOrWhiteSpace(text) ? fallback : text;
    }

    internal sealed record StaticFunction(string Name, string Entry, string Path, string? Sha256, ulong Rva);

    internal sealed record LiveModule(ulong Base, ulong End, string Name, string Path);

    internal sealed record ModuleMatch(LiveModule Module, string IdentityKind, bool HashVerified);

    /// <summary>
    /// Safe, bounded, non-leaking one-liner for client-facing messages:
    /// single line, no control chars, capped at 256 chars, never echoes raw
    /// argument values (so no secret/path leak). The real exception type
    /// travels separately in telemetry/logs. Shared by the dispatcher and the
    /// request policy: two copies of a security-relevant sanitizer would drift.
    /// </summary>
    internal static string SanitizeOneLine(string? message, string fallback)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(message))
                return fallback;
            var oneLine = message.Replace('\r', ' ').Replace('\n', ' ');
            oneLine = new string(oneLine.Where(c => !char.IsControl(c)).ToArray()).Trim();
            if (string.IsNullOrWhiteSpace(oneLine))
                return fallback;
            const int max = 256;
            if (oneLine.Length > max)
                oneLine = oneLine[..max] + "...[truncated]";
            return oneLine;
        }
        catch
        {
            return fallback;
        }
    }

    /// <summary>
    /// Model-facing reason for an unexpected failure. Exception type names are
    /// diagnostics: they belong in logs and telemetry, not in a tool result,
    /// where the caller cannot act on them and they leak server internals.
    /// One mapping keeps the wording stable everywhere.
    /// </summary>
    internal static string FailureReason(Exception exception) => exception switch
    {
        OperationCanceledException => "the operation was canceled",
        TimeoutException => "the backend timed out",
        IOException or System.Net.Sockets.SocketException => "the backend connection failed",
        UnauthorizedAccessException => "access was denied",
        ArgumentException => "the backend rejected the request",
        JsonException => "the backend returned malformed JSON",
        _ => "the backend failed",
    };

    /// <summary>
    /// One canonical autoPause pause-failure text. It used to be copy-pasted in
    /// four places, so the guidance could drift between tools that fail the
    /// same way.
    /// </summary>
    internal static string AutoPausePauseFailure(Exception exception) =>
        $"autoPause=true could not pause the running target ({FailureReason(exception)}); " +
        "the target was left running. Pause it (ControlDebuggerExecution action=pause) and retry without autoPause.";

}
