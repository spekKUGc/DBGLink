using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal static partial class AnalysisFormatting
{
    internal static JsonNode? FoldCallStackNode(JsonNode? callStackNode)
    {
        if (callStackNode is null) return null;

        // Text format callstack (e.g. Frame 0: ... \n Frame 1: ...)
        if (callStackNode is JsonValue val && val.TryGetValue<string>(out var text))
        {
            var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (lines.Length <= 2) return callStackNode;

            var resultLines = new List<string>();
            var consecutiveSystem = 0;
            var systemDllSummary = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                var isSys = i > 0 && IsSystemModuleOrFrame(line); // Always preserve top frame (frame 0)
                if (isSys)
                {
                    consecutiveSystem++;
                    foreach (var sys in SystemLibraries)
                    {
                        if (line.Contains(sys, StringComparison.OrdinalIgnoreCase))
                            systemDllSummary.Add(sys);
                    }
                }
                else
                {
                    if (consecutiveSystem > 0)
                    {
                        var dlls = systemDllSummary.Count > 0 ? string.Join(", ", systemDllSummary) : "system runtime";
                        resultLines.Add($"(+{consecutiveSystem} system frames collapsed: {dlls})");
                        consecutiveSystem = 0;
                        systemDllSummary.Clear();
                    }
                    resultLines.Add(line);
                }
            }

            if (consecutiveSystem > 0)
            {
                var dlls = systemDllSummary.Count > 0 ? string.Join(", ", systemDllSummary) : "system runtime";
                resultLines.Add($"(+{consecutiveSystem} system frames collapsed: {dlls})");
            }

            var finalLines = CollapseRecursiveTextFrames(resultLines);
            return JsonValue.Create(string.Join("\n", finalLines));
        }

        // JsonObject with "frames" array
        if (callStackNode is JsonObject obj && obj["frames"] is JsonArray framesArr && framesArr.Count > 2)
        {
            var newFrames = new JsonArray();
            var consecutiveSystem = 0;
            var systemDllSummary = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < framesArr.Count; i++)
            {
                var frameNode = framesArr[i];
                var frameStr = frameNode?.ToJsonString() ?? "";
                var isSys = i > 0 && IsSystemModuleOrFrame(frameStr);
                if (isSys)
                {
                    consecutiveSystem++;
                    foreach (var sys in SystemLibraries)
                    {
                        if (frameStr.Contains(sys, StringComparison.OrdinalIgnoreCase))
                            systemDllSummary.Add(sys);
                    }
                }
                else
                {
                    if (consecutiveSystem > 0)
                    {
                        var dlls = systemDllSummary.Count > 0 ? string.Join(", ", systemDllSummary) : "system runtime";
                        newFrames.Add(new JsonObject
                        {
                            ["collapsed"] = true,
                            ["count"] = consecutiveSystem,
                            ["libraries"] = dlls
                        });
                        consecutiveSystem = 0;
                        systemDllSummary.Clear();
                    }
                    newFrames.Add(frameNode?.DeepClone());
                }
            }

            if (consecutiveSystem > 0)
            {
                var dlls = systemDllSummary.Count > 0 ? string.Join(", ", systemDllSummary) : "system runtime";
                newFrames.Add(new JsonObject
                {
                    ["collapsed"] = true,
                    ["count"] = consecutiveSystem,
                    ["libraries"] = dlls
                });
            }

            var clonedObj = obj.DeepClone().AsObject();
            clonedObj["frames"] = CollapseRecursiveJsonFrames(newFrames);
            return clonedObj;
        }

        return callStackNode;
    }

    private static string GetFrameSignature(string line)
    {
        var colonIdx = line.IndexOf(':');
        if (colonIdx >= 0 && colonIdx < 16 && line.StartsWith("Frame", StringComparison.OrdinalIgnoreCase))
        {
            return line[(colonIdx + 1)..].Trim();
        }
        return line.Trim();
    }

    private static List<string> CollapseRecursiveTextFrames(List<string> lines)
    {
        if (lines.Count <= 2) return lines;
        // Signatures computed once up front: the run scan below references
        // each line's signature O(1) times without re-slicing the text.
        var sigs = new string[lines.Count];
        for (var s = 0; s < lines.Count; s++)
            sigs[s] = lines[s].StartsWith("(+") ? lines[s] : GetFrameSignature(lines[s]);
        var result = new List<string>(lines.Count);

        int i = 0;
        while (i < lines.Count)
        {
            var line = lines[i];
            if (line.StartsWith("(+"))
            {
                result.Add(line);
                i++;
                continue;
            }

            var sig = sigs[i];
            int j = i + 1;
            while (j < lines.Count && !lines[j].StartsWith("(+") && sigs[j] == sig)
            {
                j++;
            }

            var runLength = j - i;
            if (runLength >= 3)
            {
                result.Add(line);
                result.Add($"(+{runLength - 1} recursive frames collapsed: {sig})");
                i = j;
            }
            else
            {
                result.Add(line);
                i++;
            }
        }

        return result;
    }

    private static JsonArray CollapseRecursiveJsonFrames(JsonArray frames)
    {
        if (frames.Count <= 2) return frames;
        // Memoized serializations: each frame is fingerprinted at most once
        // (previously every run comparison re-serialized both sides).
        var sigs = new string?[frames.Count];
        string Sig(int k) => sigs[k] ??= frames[k]?.ToJsonString() ?? "";
        var result = new JsonArray();

        int i = 0;
        while (i < frames.Count)
        {
            var frame = frames[i];
            if (frame is JsonObject obj && ReadNodeBool(obj, "collapsed"))
            {
                result.Add(frame?.DeepClone());
                i++;
                continue;
            }

            var sig = Sig(i);
            int j = i + 1;
            while (j < frames.Count &&
                   !(frames[j] is JsonObject jObj && ReadNodeBool(jObj, "collapsed")) &&
                   Sig(j) == sig)
            {
                j++;
            }

            var runLength = j - i;
            if (runLength >= 3)
            {
                result.Add(frame?.DeepClone());
                result.Add(new JsonObject
                {
                    ["collapsed"] = true,
                    ["count"] = runLength - 1,
                    ["reason"] = "recursion"
                });
                i = j;
            }
            else
            {
                result.Add(frame?.DeepClone());
                i++;
            }
        }

        return result;
    }
}
