using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

/// <summary>
/// Single owner of tool presentation: advertised catalog metadata and the
/// compact {columns,rows} wire shape. Every tool calls the same two entry
/// points. Presentation only: the original metadata and executable
/// validation rules are untouched.
/// </summary>
internal static class ToolPresentation
{
    /// <summary>
    /// Builds advertised metadata (single standard catalog): examples policy,
    /// description rewrites, implied-bound dedup. Clones the input; the
    /// original is never mutated. The profile argument is ignored (kept for
    /// call-site compatibility); lean/comprehensive merged into one.
    /// </summary>
    public static JsonObject Advertise(JsonObject metadata, ToolProfile profile)
    {
        var advertised = metadata.DeepClone().AsObject();
        if (advertised["inputSchema"] is JsonObject schema)
        {
            // P0-1: examples are repeated, optional JSON Schema annotations;
            // validation uses the original metadata and executable rules.
            // Drop them in every profile except one non-trivial SetBreakpoint
            // module+rva example (the only one that teaches address conversion).
            if (schema["examples"] is JsonArray examples)
            {
                var name = advertised["name"]?.GetValue<string>();
                if (!string.Equals(name, "SetBreakpoint", StringComparison.Ordinal))
                    schema.Remove("examples");
                else if (examples.Count == 0)
                    schema.Remove("examples");
                else
                {
                    // Keep only the module+rva example; drop address-only echoes.
                    JsonNode? keep = null;
                    foreach (var item in examples)
                    {
                        if (item is JsonObject obj && obj.ContainsKey("module") && obj.ContainsKey("rva"))
                        {
                            keep = item.DeepClone();
                            break;
                        }
                    }
                    keep ??= examples[0]?.DeepClone();
                    schema["examples"] = new JsonArray(keep!);
                }
            }
        }
        if (advertised["inputSchema"] is JsonObject comprehensiveSchema)
        {
            DedupeImpliedBounds(comprehensiveSchema);
            // Round-10 proved defaults safe to omit (server applies them when
            // the argument is absent); the lean-only gate died with the merge.
            RemoveLeanDefaults(comprehensiveSchema);
            // A zero floor carries no information (rejected server-side with a
            // named error); non-zero minimums stay as real guidance.
            RemoveZeroMinimums(comprehensiveSchema);
            RemoveTrivialDescriptions(comprehensiveSchema);
            // x-* vendor keywords are opaque to models; executable validation
            // runs on the original metadata, never on this payload.
            RemoveVendorExtensions(comprehensiveSchema);
            // analysisId discovery lives on the 3 session tools; the
            // dispatcher still accepts it everywhere (active-session fallback).
            if (advertised["name"]?.GetValue<string>() is not
                ("ListAnalysisSessions" or "CloseAnalysisSession" or "ReopenAnalysisSession") &&
                comprehensiveSchema["properties"] is JsonObject advertisedProps)
                advertisedProps.Remove("analysisId");
        }
        return advertised;
    }

    /// <summary>
    /// Drops <c>"minimum": 0</c> floors: zero is the natural bound and the
    /// server rejects negatives with a named error. Non-zero minimums
    /// (threadId ≥ 1, maxItems ≥ 1) stay — they teach real limits.
    /// </summary>
    private static void RemoveZeroMinimums(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            if (obj["minimum"] is JsonValue minimum &&
                minimum.TryGetValue<int>(out var floor) && floor == 0)
                obj.Remove("minimum");
            foreach (var property in obj)
                RemoveZeroMinimums(property.Value);
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
                RemoveZeroMinimums(item);
        }
    }

    /// <summary>
    /// Drops <c>x-*</c> vendor extensions (x-nonblank, x-maxUtf8Bytes,
    /// x-allowedInts, …): hints for our own validator, noise for models.
    /// Three keys stay because they shape validation itself and strict
    /// clients validate against the advertised schema: <c>x-multiline</c>
    /// widens the accepted set (LF in comments), <c>x-requiresAnyOf</c> and
    /// <c>x-exclusiveAddressRanges</c> teach mutually-exclusive argument
    /// shapes. Stripping any of those would contract or obscure what counts
    /// as valid; everything else the server still enforces.
    /// </summary>
    private static void RemoveVendorExtensions(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            foreach (var key in obj.Select(property => property.Key)
                         .Where(key => key.StartsWith("x-", StringComparison.Ordinal) &&
                                       key is not ("x-multiline" or "x-requiresAnyOf" or "x-exclusiveAddressRanges")).ToList())
                obj.Remove(key);
            foreach (var property in obj)
                RemoveVendorExtensions(property.Value);
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
                RemoveVendorExtensions(item);
        }
    }

    /// <summary>
    /// The {columns,rows} transform: an array of objects becomes one table.
    /// Keys are paid once per result instead of once per row. Opt-in; the
    /// default stays byte-compatible.
    /// </summary>
    public static string Compact(string raw, params string[] arrayKeys)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(raw);
        }
        catch (JsonException)
        {
            // Preserve the bridge's bytes when the envelope is not ours to
            // parse; the caller then sees the original error instead of a
            // second, less useful serialization error.
            return raw;
        }
        if (node is not JsonObject envelope || envelope["result"] is not JsonObject result)
            return raw;

        var changed = false;
        foreach (var key in arrayKeys)
            changed |= Compact(result, key);
        return changed ? envelope.ToJsonString() : raw;
    }

    /// <summary>
    /// Compacts one named child array of <paramref name="parent"/>. Returns
    /// false (parent untouched) for missing, empty, non-object-row, or
    /// column-less arrays.
    /// </summary>
    public static bool Compact(JsonObject parent, string key)
    {
        if (parent[key] is not JsonArray rows || rows.Count == 0 ||
            rows.Any(node => node is not JsonObject))
            return false;

        var columns = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows.OfType<JsonObject>())
            foreach (var property in row)
                if (seen.Add(property.Key))
                    columns.Add(property.Key);
        if (columns.Count == 0)
            return false;

        var codedRows = new JsonArray();
        foreach (var row in rows.OfType<JsonObject>())
        {
            var cells = new JsonArray();
            foreach (var column in columns)
                cells.Add(row[column]?.DeepClone());
            codedRows.Add(cells);
        }

        parent[key] = new JsonObject
        {
            ["columns"] = new JsonArray(columns
                .Select(column => (JsonNode?)JsonValue.Create(column)).ToArray()),
            ["rows"] = codedRows
        };
        return true;
    }

    /// <summary>
    /// Trivial property descriptions: self-evident from the property name,
    /// removed everywhere they occur. Data, not code.
    /// </summary>
    private static readonly HashSet<string> TrivialDescriptions = new(StringComparer.Ordinal)
    {
        "Register name, e.g. rax.",
        "New value, hex or decimal.",
        "Resume or pause.",
        "Direction.",
        "Which to list.",
        "Telemetry groups.",
        "Page size.",
        "Page offset.",
        "Zero-based index.",
    };

    private static void RemoveTrivialDescriptions(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            if (obj["description"] is JsonValue description &&
                description.TryGetValue<string>(out var text) &&
                TrivialDescriptions.Contains(text))
                obj.Remove("description");
            foreach (var property in obj)
                RemoveTrivialDescriptions(property.Value);
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
                RemoveTrivialDescriptions(item);
        }
    }

    /// <summary>
    /// Drops JSON-Schema <c>default</c> annotations: the server applies exactly
    /// those defaults when an argument is absent, so they are client-prefill
    /// convenience only.
    /// </summary>
    private static void RemoveLeanDefaults(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            obj.Remove("default");
            foreach (var property in obj)
                RemoveLeanDefaults(property.Value);
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
                RemoveLeanDefaults(item);
        }
    }

    /// <summary>
    /// Universal schema slim-down: drop a <c>minLength: 1</c> floor where the
    /// stricter <c>x-nonblank</c> keyword in the same rule already rejects
    /// empty text. <c>maxLength</c> is deliberately kept even when it equals
    /// <c>x-maxUtf8Bytes</c>: the vendor key is stripped below, and without
    /// maxLength the advertised property would carry no bound at all.
    /// Validation still runs the executable rule, so behavior is unchanged;
    /// only the advertised tools/list text shrinks.
    /// </summary>
    private static void DedupeImpliedBounds(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            if (obj["x-nonblank"]?.GetValue<bool>() == true &&
                obj["minLength"] is JsonValue minimum &&
                minimum.TryGetValue<int>(out var minimumValue) && minimumValue == 1)
                obj.Remove("minLength");
            foreach (var property in obj)
                DedupeImpliedBounds(property.Value);
        }
        else if (node is JsonArray array)
        {
            foreach (var item in array)
                DedupeImpliedBounds(item);
        }
    }
}
