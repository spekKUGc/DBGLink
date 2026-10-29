using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

/// <summary>
/// Pure helpers behind GetAnalysisSnapshot: state consistency assessment,
/// summary projection, batched-capability probing and module budget trimming.
/// </summary>
internal static class AnalysisSnapshotSummary
{
    internal static JsonObject AssessConsistency(JsonNode? before, JsonNode? after)
    {
        // x64dbg keeps reporting running=true after the debuggee exits
        // (debugging=false). Normalize both states up front so status,
        // changedFields and the before/after clones agree with the summary
        // projection below (which forces running=false when debugging=false).
        before = NormalizeNotDebuggingRunning(before);
        after = NormalizeNotDebuggingRunning(after);
        static bool Valid(JsonNode? node) => node is JsonObject state &&
            state["debuggerPid"] is JsonValue pid && pid.TryGetValue<int>(out var processId) && processId > 0 &&
            state["generation"] is JsonValue generation && generation.TryGetValue<string>(out var value) &&
            ulong.TryParse(value, out _) &&
            state["debugging"] is JsonValue debugging && debugging.TryGetValue<bool>(out _) &&
            state["running"] is JsonValue running && running.TryGetValue<bool>(out _) &&
            state["stableRead"] is JsonValue stable && stable.TryGetValue<bool>(out _);
        var status = "unavailable";
        if (Valid(before) && Valid(after))
        {
            if (!AnalysisFormatting.ReadNodeBool(before, "stableRead") || !AnalysisFormatting.ReadNodeBool(after, "stableRead") ||
                !JsonNode.DeepEquals(before!["generation"], after!["generation"]) ||
                !JsonNode.DeepEquals(before["debuggerPid"], after["debuggerPid"]) ||
                !JsonNode.DeepEquals(before["threadId"], after["threadId"]) ||
                !JsonNode.DeepEquals(before["debugging"], after["debugging"]) ||
                !JsonNode.DeepEquals(before["running"], after["running"])) status = "changed";
            else if (!AnalysisFormatting.ReadNodeBool(before, "debugging")) status = "not_debugging";
            else if (AnalysisFormatting.ReadNodeBool(before, "running")) status = "running";
            else if (before!["threadId"] is JsonValue thread && thread.TryGetValue<uint>(out var id) && id > 0) status = "unchanged";
        }
        // Token saver: unchanged snapshots omit before/after/scope clones.
        if (string.Equals(status, "unchanged", StringComparison.Ordinal))
        {
            return new JsonObject
            {
                ["status"] = status,
                ["atomic"] = false,
                ["generation"] = before?["generation"]?.DeepClone(),
                ["threadId"] = before?["threadId"]?.DeepClone(),
            };
        }
        if (string.Equals(status, "changed", StringComparison.Ordinal))
        {
            var changedFields = new JsonArray();
            foreach (var name in new[] { "generation", "debuggerPid", "threadId", "debugging", "running", "stableRead" })
                if (!JsonNode.DeepEquals(before?[name], after?[name]))
                    changedFields.Add(name);
            return new JsonObject
            {
                ["status"] = status,
                ["atomic"] = false,
                ["after"] = after?.DeepClone(),
                ["changedFields"] = changedFields,
            };
        }
        return new JsonObject
        {
            ["status"] = status, ["atomic"] = false,
            ["before"] = before?.DeepClone(), ["after"] = after?.DeepClone(),
        };
    }

    internal static JsonNode? NormalizeNotDebuggingRunning(JsonNode? node)
    {
        if (node is not JsonObject state)
            return node;
        if (state["debugging"] is not JsonValue debuggingValue ||
            !debuggingValue.TryGetValue<bool>(out var debugging) || debugging)
            return node;
        // Clone before mutating so the caller's state object (also used for
        // the summary projection) is never modified in place.
        var clone = (JsonObject)state.DeepClone();
        clone["running"] = false;
        return clone;
    }

    internal static JsonObject BuildSnapshotSummary(
        JsonNode? state,
        JsonNode? modules,
        string consistencyStatus,
        bool includeThreads = false,
        bool includeModules = true,
        JsonObject? sections = null,
        JsonArray? skipped = null,
        int errorCount = 0,
        bool truncated = false,
        string transport = "individual")
    {
        var nextAction = consistencyStatus switch
        {
            "running" => "Pause the debugger and repeat the snapshot.",
            "not_debugging" => "Start or attach a debug session, then repeat the snapshot.",
            "changed" => "Repeat the snapshot after the debugger stops changing state.",
            "unchanged" when errorCount > 0 => "Review errors before correlating static and live evidence.",
            "unchanged" when truncated => "Repeat with a higher maxChars or disable optional sections for complete evidence.",
            "unchanged" => "Use the snapshot for static/live correlation.",
            _ => "Repeat the snapshot after the native debugger bridge is ready.",
        };
        var summary = new JsonObject
        {
            ["consistency"] = consistencyStatus,
            ["nextAction"] = nextAction,
            ["errorCount"] = errorCount,
            ["truncated"] = truncated,
        };
        if (state is JsonObject stateObject)
        {
            foreach (var propertyName in new[] { "debuggerPid", "debugging", "running", "threadId" })
                if (stateObject[propertyName] is JsonNode value)
                    summary[propertyName] = value.DeepClone();
            // x64dbg keeps reporting running=true after the debuggee exits
            // (debugging=false): normalize the summary so the LLM does not try
            // to pause/resume a session that is already over. Consistency
            // before/after are normalized the same way in AssessConsistency.
            if (stateObject["debugging"] is JsonValue debuggingValue &&
                debuggingValue.TryGetValue<bool>(out var debugging) && !debugging)
                summary["running"] = false;
        }
        if (includeModules)
        {
            var moduleOmitted = sections?["modules"] is JsonObject moduleSection &&
                AnalysisFormatting.ReadNodeBool(moduleSection, "omitted");
            summary["moduleStatus"] = modules is not JsonObject
                ? "unavailable"
                : moduleOmitted ? "omitted" : "included";
            summary["moduleCount"] = modules is JsonObject moduleObject
                ? AnalysisFormatting.ReadNodeInt(moduleObject, "returnedCount")
                : 0;
            summary["modulesTruncated"] = modules is not JsonObject || moduleOmitted ||
                AnalysisFormatting.ReadNodeBool(modules, "truncated");
        }
        else
        {
            // Modules not requested: omit module-status keys entirely
            // (absent = not requested) instead of echoing a string.
        }

        if (skipped is { Count: > 0 })
            summary["skippedSections"] = skipped.DeepClone();
        return summary;
    }

    internal static bool HasAnalysisSnapshotCapability(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
            return document.RootElement.TryGetProperty("capabilities", out var capabilities) &&
                capabilities.ValueKind == JsonValueKind.Object &&
                capabilities.TryGetProperty("analysisSnapshot", out var capability) &&
                capability.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    internal static void TrimModuleRecordsToBudget(JsonObject moduleResult, JsonArray records, int remainingChars)
    {
        moduleResult["returnedCount"] = records.Count;
        // Budget-first layout: measure the envelope without records before
        // touching the full payload, so an over-budget module table with
        // thousands of records never pays for a throwaway full serialization.
        // The empty envelope carries the same "modules": [] wrapper (2 chars),
        // so seeding the running length with emptyLength - 2 keeps the keep-all
        // boundary byte-identical to the previous full-serialization check.
        var empty = (JsonObject)moduleResult.DeepClone();
        empty["modules"] = new JsonArray();
        empty["returnedCount"] = 0;
        var emptyLength = empty.ToJsonString().Length;
        var recordLengths = records.Select(record => record?.ToJsonString().Length ?? 4).ToArray();
        var targetLength = Math.Max(0, remainingChars - 64);
        var usedLength = Math.Max(0, emptyLength - 2);
        var keep = 0;
        foreach (var recordLength in recordLengths)
        {
            var candidateLength = usedLength + recordLength + (keep == 0 ? 0 : 1);
            if (candidateLength > targetLength)
                break;
            usedLength = candidateLength;
            keep++;
        }

        if (keep >= records.Count)
            return;

        moduleResult["truncated"] = true;
        while (records.Count > keep)
            records.RemoveAt(records.Count - 1);
        moduleResult["returnedCount"] = keep;
    }
}
