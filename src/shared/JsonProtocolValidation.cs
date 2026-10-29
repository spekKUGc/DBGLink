using System.Text.Json;

namespace DbgLink.Shared;

/// <summary>
/// Rejects JSON documents that repeat a property name at any depth. Used by both
/// the MCP server and the launcher before trusting a parsed payload.
/// </summary>
public static class JsonProtocolValidation
{
    public static bool HasDuplicateProperties(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => HasDuplicateObjectProperties(element),
            JsonValueKind.Array => element.EnumerateArray().Any(HasDuplicateProperties),
            _ => false,
        };
    }

    private static bool HasDuplicateObjectProperties(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name) || HasDuplicateProperties(property.Value))
                return true;
        }

        return false;
    }
}
