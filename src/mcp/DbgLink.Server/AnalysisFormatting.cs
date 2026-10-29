using DbgLink.Shared;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal static partial class AnalysisFormatting
{
    internal static string? ReadNodeString(JsonNode? node, string propertyName)
    {
        try
        {
            return node is JsonObject objectNode && objectNode[propertyName] is JsonValue value &&
                value.TryGetValue<string>(out var result)
                ? result
                : null;
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    internal static bool? ReadNodeNullableBool(JsonNode? node, string propertyName)
    {
        try
        {
            return node is JsonObject objectNode && objectNode[propertyName] is JsonValue value &&
                value.TryGetValue<bool>(out var result)
                ? result
                : null;
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    internal static void AddBoundedSection(
        JsonObject sections,
        string name,
        JsonNode? value,
        ref int remainingChars,
        ref bool truncated)
    {
        if (value is null)
            return;

        var serializedLength = value.ToJsonString().Length;
        const int sectionOverhead = 64;
        if (serializedLength + sectionOverhead <= remainingChars)
        {
            sections[name] = value;
            remainingChars -= serializedLength + sectionOverhead;
            return;
        }

        sections[name] = new JsonObject
        {
            ["omitted"] = true,
            ["reason"] = "response_budget",
        };
        remainingChars = Math.Max(0, remainingChars - sectionOverhead);
        truncated = true;
    }

    internal static JsonNode? ReadBridgeResultNode(string raw)
    {
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                JsonProtocolValidation.HasDuplicateProperties(root) ||
                !root.TryGetProperty("ok", out var ok) ||
                ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) ||
                result.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                return null;

            return JsonNode.Parse(result.GetRawText());
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static int ReadNodeInt(JsonNode? node, string propertyName)
    {
        try
        {
            return node is JsonObject objectNode && objectNode[propertyName] is JsonValue value &&
                value.TryGetValue<int>(out var result)
                ? result
                : 0;
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return 0;
        }
    }

    internal static int ReadNestedNodeInt(JsonNode? node, string parentName, string propertyName)
    {
        try
        {
            return node is JsonObject objectNode && objectNode[parentName] is JsonObject parent &&
                parent[propertyName] is JsonValue value && value.TryGetValue<int>(out var result)
                ? result
                : 0;
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return 0;
        }
    }

    internal static bool ReadNodeBool(JsonNode? node, string propertyName)
    {
        try
        {
            return node is JsonObject objectNode && objectNode[propertyName] is JsonValue value &&
                value.TryGetValue<bool>(out var result) && result;
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return false;
        }
    }

    internal static void AddChildErrors(JsonArray errors, string section, JsonNode node)
    {
        if (node is not JsonObject objectNode || objectNode["errors"] is not JsonArray childErrors)
            return;

        var ignoredTruncated = false;
        foreach (var childError in childErrors)
        {
            if (childError is JsonObject childObject)
            {
                var error = new JsonObject
                {
                    ["section"] = section,
                    ["code"] = ReadNodeString(childObject, "code") ?? "partial",
                    ["message"] = ToolSupport.LimitSnapshotText(
                        ReadNodeString(childObject, "message") ?? childObject.ToJsonString(),
                        1_024,
                        ref ignoredTruncated),
                };
                var childSection = ReadNodeString(childObject, "section");
                if (!string.IsNullOrWhiteSpace(childSection))
                    error["sourceSection"] = childSection;
                errors.Add(error);
            }
            else
            {
                errors.Add(new JsonObject
                {
                    ["section"] = section,
                    ["code"] = "partial",
                    ["message"] = "The nested route returned an unspecified error.",
                });
            }
        }
    }
}
