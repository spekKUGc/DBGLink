using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal static partial class AnalysisFormatting
{
    internal static IReadOnlyList<ToolSupport.LiveModule> ParseSnapshotModules(JsonNode? snapshot)
    {
        try
        {
            if (snapshot is not JsonObject snapshotObject ||
                snapshotObject["sections"] is not JsonObject sections)
                return new AddressMapping.LiveModuleCollection { Truncated = true };
            if (sections["modules"] is JsonObject records)
                return AddressMapping.ParseModuleRecords(records);
            if (
                sections["modules"] is not JsonValue moduleValue ||
                !moduleValue.TryGetValue<string>(out var moduleText))
                return new AddressMapping.LiveModuleCollection { Truncated = true };
            return AddressMapping.ParseLiveModules(moduleText);
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return new AddressMapping.LiveModuleCollection { Truncated = true };
        }
    }

    private static readonly string[] SystemLibraries =
    [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
        "rpcrt4.dll", "msvcrt.dll", "ucrtbase.dll", "comctl32.dll", "ole32.dll",
        "shell32.dll", "shlwapi.dll", "ws2_32.dll", "advapi32.dll"
    ];

    internal static bool IsSystemModule(string? name, string? path)
    {
        if (!string.IsNullOrEmpty(path))
        {
            // OrdinalIgnoreCase avoids the ToLowerInvariant allocation per
            // module record on the hot snapshot-fold path.
            if (path.Contains(@"\windows\system32\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\windows\syswow64\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\windows\winsxs\", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (!string.IsNullOrEmpty(name))
        {
            foreach (var sys in SystemLibraries)
            {
                if (name.Equals(sys, StringComparison.OrdinalIgnoreCase) ||
                    name.Contains(sys, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            if (name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("system_library_", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    internal static bool IsSystemModuleOrFrame(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        var lower = text.ToLowerInvariant();
        return SystemLibraries.Any(sys => lower.Contains(sys)) ||
            lower.Contains(@"\windows\system32\") ||
            lower.Contains("system_library_");
    }

    internal static JsonNode? FoldModulesNode(JsonNode? moduleNode)
    {
        if (moduleNode is null) return null;
        if (moduleNode is JsonObject obj && obj["modules"] is JsonArray records && records.Count > 6)
        {
            var userModules = new JsonArray();
            var systemModuleNames = new List<string>();
            ulong minSysBase = ulong.MaxValue;
            ulong maxSysEnd = 0;

            foreach (var record in records)
            {
                if (record is JsonObject entry)
                {
                    var name = ReadNodeString(entry, "name") ?? "";
                    var path = ReadNodeString(entry, "path") ?? "";
                    if (IsSystemModule(name, path))
                    {
                        systemModuleNames.Add(name);
                        var baseStr = ReadNodeString(entry, "base");
                        var endStr = ReadNodeString(entry, "end");
                        if (baseStr != null && AddressMapping.TryParseAddress(baseStr, out var b) &&
                            endStr != null && AddressMapping.TryParseAddress(endStr, out var e))
                        {
                            if (b < minSysBase) minSysBase = b;
                            if (e > maxSysEnd) maxSysEnd = e;
                        }
                    }
                    else
                    {
                        userModules.Add(entry.DeepClone());
                    }
                }
            }

            if (systemModuleNames.Count > 4)
            {
                var summaryExamples = string.Join(", ", systemModuleNames.Take(4));
                var collapsedRecord = new JsonObject
                {
                    ["name"] = $"[{systemModuleNames.Count} system modules collapsed]",
                    ["collapsed"] = true,
                    ["count"] = systemModuleNames.Count,
                    ["summary"] = $"{summaryExamples}... (+{systemModuleNames.Count - Math.Min(4, systemModuleNames.Count)} others in System32)",
                    ["baseRange"] = minSysBase < ulong.MaxValue ? $"0x{minSysBase:X} - 0x{maxSysEnd:X}" : "system_space"
                };
                userModules.Add(collapsedRecord);

                obj["modules"] = userModules;
                obj["collapsedSystemCount"] = systemModuleNames.Count;
                obj["returnedCount"] = userModules.Count;
            }
        }
        return moduleNode;
    }
}
