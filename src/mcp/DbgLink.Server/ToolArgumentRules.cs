using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DbgLink.Shared;
namespace DbgLink.Server;

internal static class ToolArgumentRules
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    public static string? Validate(JsonObject schema, JsonElement? arguments)
    {
        if (arguments is { ValueKind: not (JsonValueKind.Object or JsonValueKind.Null or JsonValueKind.Undefined) })
            return "arguments must be an object.";
        var args = arguments is { ValueKind: JsonValueKind.Object } ? arguments.Value : JsonSerializer.SerializeToElement(new { });
        if (JsonProtocolValidation.HasDuplicateProperties(args)) return "arguments contain duplicate properties.";
        if (schema["required"] is JsonArray required)
            foreach (var field in required)
                if (!args.TryGetProperty(field!.GetValue<string>(), out _)) return field.GetValue<string>() + " is required.";
        var properties = schema["properties"] as JsonObject ?? new JsonObject();
        foreach (var field in args.EnumerateObject())
        {
            if (properties[field.Name] is not JsonObject rule)
            {
                if (schema["additionalProperties"]?.GetValue<bool>() == false)
                {
                    // Name the accepted keys: an agent that guessed "length"
                    // instead of "byteCount" should not need a second round
                    // trip to discover the schema.
                    var accepted = schema["properties"] is JsonObject acceptedProperties
                        ? string.Join(", ", acceptedProperties.Select(property => property.Key).Take(12))
                        : "";
                    return string.IsNullOrEmpty(accepted)
                        ? "Unsupported argument: " + field.Name
                        : $"Unsupported argument: {field.Name} (accepted: {accepted})";
                }
                continue;
            }
            var valid = ValidateValue(rule, field.Value);
            if (!valid) return field.Name + " does not satisfy its argument schema.";
        }
        if (schema["x-exclusiveSelectors"] is JsonArray selectors &&
            selectors.Count(field => args.TryGetProperty(field!.GetValue<string>(), out _)) > 1)
            return "DecompileModule accepts either function or start, not both.";
        if (schema["x-encodingChoice"]?.GetValue<bool>() == true &&
            !ToolSupport.ReadArgumentBool(args, "ascii", true) && !ToolSupport.ReadArgumentBool(args, "unicode", true))
            return "At least one encoding must be enabled.";
        if (schema["x-requiresAnyOf"] is JsonArray anyOf && anyOf.Count > 0)
        {
            var present = false;
            foreach (var option in anyOf)
            {
                if (option is not null && args.TryGetProperty(option.GetValue<string>(), out _))
                {
                    present = true;
                    break;
                }
            }
            if (!present)
                return string.Join(" or ", anyOf.Select(node => node!.GetValue<string>())) + " is required.";
        }
        // ReadStaticBytes: address/length and ranges[] are mutually exclusive.
        // Fail fast at the MCP layer instead of round-tripping the ambiguous
        // shape to the bridge.
        if (schema["x-exclusiveAddressRanges"]?.GetValue<bool>() == true &&
            args.TryGetProperty("ranges", out _) &&
            (args.TryGetProperty("address", out _) || args.TryGetProperty("length", out _)))
            return "ReadStaticBytes accepts either address/length or ranges, not both.";
        return null;
    }

    private static bool ValidateValue(JsonObject rule, JsonElement value)
    {
        if (rule["enum"] is JsonArray allowedValues)
        {
            if (value.ValueKind != JsonValueKind.String)
                return false;
            var text = value.GetString();
            var permitted = false;
            foreach (var entry in allowedValues)
            {
                if (entry is JsonValue candidate && candidate.TryGetValue<string>(out var allowed) &&
                    string.Equals(allowed, text, StringComparison.Ordinal))
                {
                    permitted = true;
                    break;
                }
            }
            if (!permitted)
                return false;
        }
        return rule["type"]?.GetValue<string>() switch
        {
            "string" => value.ValueKind == JsonValueKind.String && ValidText(value.GetString()!, rule),
            "integer" => value.ValueKind == JsonValueKind.Number && ValidInt(value, rule),
            "number" => value.ValueKind == JsonValueKind.Number && ValidNumber(value, rule),
            "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            "object" => value.ValueKind == JsonValueKind.Object && Validate(rule, value) is null,
            "array" => value.ValueKind == JsonValueKind.Array &&
                (rule["minItems"] is null || value.GetArrayLength() >= rule["minItems"]!.GetValue<int>()) &&
                (rule["maxItems"] is null || value.GetArrayLength() <= rule["maxItems"]!.GetValue<int>()) &&
                (rule["items"] is not JsonObject itemRule || value.EnumerateArray().All(item => ValidateValue(itemRule, item))),
            _ => false
        };
    }

    private static bool ValidNumber(JsonElement value, JsonObject rule)
    {
        if (!value.TryGetDouble(out var number) || double.IsNaN(number) || double.IsInfinity(number))
            return false;
        if (rule["minimum"] is not null && (!TryGetDoubleBound(rule["minimum"]!, out var minimum) || number < minimum))
            return false;
        if (rule["maximum"] is not null && (!TryGetDoubleBound(rule["maximum"]!, out var maximum) || number > maximum))
            return false;
        return true;
    }

    private static bool ValidInt(JsonElement value, JsonObject rule)
    {
        if (!ToolSupport.IsJsonInteger(value) || !value.TryGetInt64(out var number))
            return false;
        if (rule["minimum"] is not null && (!TryGetInt64Bound(rule["minimum"]!, out var minimum) || number < minimum))
            return false;
        if (rule["maximum"] is not null && (!TryGetInt64Bound(rule["maximum"]!, out var maximum) || number > maximum))
            return false;
        // Closed value sets (e.g. hardware breakpoint sizes 1/2/4/8) fail fast
        // at the MCP layer instead of round-tripping to the native bridge.
        if (rule["x-allowedInts"] is JsonArray allowed)
        {
            var permitted = false;
            foreach (var entry in allowed)
            {
                if (entry is JsonValue candidate &&
                    (candidate.TryGetValue<long>(out var asLong) && asLong == number ||
                     candidate.TryGetValue<int>(out var asInt) && asInt == number))
                {
                    permitted = true;
                    break;
                }
            }
            if (!permitted)
                return false;
        }
        return true;
    }

    private static bool TryGetDoubleBound(JsonNode node, out double bound)
    {
        bound = 0;
        if (node is JsonValue value)
        {
            if (value.TryGetValue<double>(out bound))
                return true;
            if (value.TryGetValue<long>(out var asLong))
            {
                bound = asLong;
                return true;
            }
            if (value.TryGetValue<int>(out var asInt))
            {
                bound = asInt;
                return true;
            }
        }
        return false;
    }

    private static bool TryGetInt64Bound(JsonNode node, out long bound)
    {
        bound = 0;
        if (node is JsonValue value)
        {
            if (value.TryGetValue<long>(out bound))
                return true;
            if (value.TryGetValue<int>(out var asInt))
            {
                bound = asInt;
                return true;
            }
        }
        return false;
    }

    private static bool ValidText(string text, JsonObject rule)
    {
        if (!ToolSupport.IsSafeText(text, rule["x-multiline"]?.GetValue<bool>() == true)) return false;
        if (rule["minLength"] is not null && text.Length < rule["minLength"]!.GetValue<int>()) return false;
        if (rule["maxLength"] is not null && text.Length > rule["maxLength"]!.GetValue<int>()) return false;
        if (rule["x-nonblank"]?.GetValue<bool>() == true && string.IsNullOrWhiteSpace(text)) return false;
        if (rule["x-maxUtf8Bytes"] is not null && StrictUtf8.GetByteCount(text) > rule["x-maxUtf8Bytes"]!.GetValue<int>()) return false;
        if (rule["pattern"] is not null && !MatchPattern(text, rule["pattern"]!.GetValue<string>())) return false;
        if (rule["x-bytePattern"]?.GetValue<bool>() == true)
        {
            var tokens = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length is < 1 or > 256 || !tokens.Any(token => token is not ("?" or "??"))) return false;
            if (tokens.Any(token => token is not ("?" or "??") && (token.Length != 2 || !token.All(Uri.IsHexDigit)))) return false;
        }
        if (rule["x-hexBytes"]?.GetValue<bool>() == true && !ValidHexBytes(text, rule))
            return false;
        return true;
    }

    private static bool MatchPattern(string text, string pattern)
    {
        // Fail closed: Validate runs outside the dispatcher's try block, so a
        // catastrophic-backtracking timeout (or a malformed schema pattern)
        // must reject the argument, not escape as an unhandled exception.
        try
        {
            return Regex.IsMatch(text, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
        }
        catch (Exception exception) when (exception is RegexMatchTimeoutException or TimeoutException or ArgumentException)
        {
            return false;
        }
    }

    private static bool ValidHexBytes(string text, JsonObject rule)
    {
        // Accepted spellings: "48 8B", "0x48,0x8B", "488B". Decoded size
        // must fit the native per-call write cap so the MCP layer fails fast
        // instead of round-tripping an oversized patch to the bridge.
        var maxBytes = rule["x-maxBytes"]?.GetValue<int>() ?? 4096;
        var digits = new StringBuilder(text.Length);
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (character is ' ' or '\t' or ',' or ';' or '-')
                continue;
            if (character == '0' && index + 1 < text.Length &&
                (text[index + 1] is 'x' or 'X'))
            {
                index++;
                continue;
            }
            digits.Append(character);
        }
        if (digits.Length == 0 || digits.Length % 2 != 0 || digits.Length / 2 > maxBytes)
            return false;
        for (var index = 0; index < digits.Length; index++)
        {
            if (!Uri.IsHexDigit(digits[index]))
                return false;
        }
        return true;
    }
}
