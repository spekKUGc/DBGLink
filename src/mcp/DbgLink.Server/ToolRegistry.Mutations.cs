using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>
    /// BatchAnnotate: 1-16 rename/comment/vartype operations in one Ghidra
    /// transaction. The envelope mirrors the single-tool schemas; per-kind
    /// required fields and limits are enforced by the Java bridge before the
    /// transaction opens, per-operation failures come back by index, and every
    /// success is journaled for replay.
    /// </summary>
    private void RegisterBatchAnnotate(AnalysisContext context)
    {
        Register(new JsonObject
        {
            ["name"] = "BatchAnnotate",
            ["description"] = "Apply 1-16 rename/comment/vartype/define ops in one Ghidra transaction. Failures are indexed per op; bad ops reject the batch. committed=true is authoritative. For durable progress, use SubmitAnnotations.",
            ["inputSchema"] = AnnotationBatchInputSchema()
        }, async call =>
        {
            var raw = await context.Ghidra.RequestAsync(call.Name, call.Arguments, call.CancellationToken).ConfigureAwait(false);
            return SlimBatchAnnotateAck(raw);
        }, ToolCapability.Mutation, requiresControl: false, lean: true, minimumTimeoutMs: 120_000);
    }

    /// <summary>
    /// SubmitAnnotations: apply a 1-16 operation annotation batch (same shape
    /// as BatchAnnotate) and report durable progress. Every applied operation
    /// is journaled; GetAnalysisQueue consults that journal (excludeAnnotated)
    /// to stop re-suggesting already-annotated functions across restarts.
    /// </summary>
    private void RegisterSubmitAnnotations(AnalysisContext context)
    {
        Register(new JsonObject
        {
            ["name"] = "SubmitAnnotations",
            ["description"] = "BatchAnnotate shape (1-16 ops) plus durable progress (doneCount, journaled for GetAnalysisQueue). committed=true is authoritative.",
            ["inputSchema"] = AnnotationBatchInputSchema()
        }, async call =>
        {
            var raw = await context.Ghidra.RequestAsync(call.Name, call.Arguments, call.CancellationToken).ConfigureAwait(false);
            return SlimSubmitAnnotationsAck(raw);
        }, ToolCapability.Mutation, requiresControl: false, lean: true, minimumTimeoutMs: 120_000);
    }

    /// <summary>
    /// The one operations array shared by BatchAnnotate and SubmitAnnotations:
    /// both tools take the same 1-16 rename/comment/vartype batch by contract,
    /// so a second inline copy was pure catalog cost and drift risk.
    /// </summary>
    private static JsonObject AnnotationBatchInputSchema() => new()
    {
        ["type"] = "object",
        ["additionalProperties"] = false,
        ["required"] = new JsonArray("operations"),
        ["properties"] = new JsonObject
        {
            ["operations"] = new JsonObject
            {
                ["type"] = "array",
                ["minItems"] = 1,
                ["maxItems"] = 16,
                ["items"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray("kind", "function"),
                    ["properties"] = new JsonObject
                    {
                        ["kind"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["enum"] = new JsonArray(
                                "rename_function", "set_function_comment", "rename_variable", "set_variable_type", "create_function"),
                            ["description"] = "rename_function (name), set_function_comment (comment), rename_variable (variable+name), set_variable_type (variable+type), create_function (function=entry address, name optional)."
                        },
                        ["function"] = NonBlankText("Ghidra function address, RVA, or name.", 256),
                        ["name"] = SymbolNameRule("New simple symbol name."),
                        ["comment"] = MultilineText("Comment text; empty string clears it.", 8192),
                        ["variable"] = NonBlankText("Exact variable name.", 128),
                        ["type"] = NonBlankText("Ghidra data type name or path.", 256)
                    }
                }
            }
        }
    };

    /// <summary>
    /// Slim ack for BatchAnnotate: keeps the per-operation outcome needed to
    /// retry only failed indexes, caps failure messages and never passes
    /// through fat echoes (module sha256, function identity objects, previous
    /// values). The Java bridge already returns a bounded shape; this
    /// projection is the wire contract and defends against drift.
    /// Top-level error envelopes pass through untouched.
    /// </summary>
    internal static string SlimBatchAnnotateAck(string raw)
    {
        JsonObject? resultNode;
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("ok", out var ok) ||
                ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) ||
                result.ValueKind != JsonValueKind.Object)
                return raw;
            resultNode = JsonNode.Parse(result.GetRawText())!.AsObject();
        }
        catch (JsonException)
        {
            return raw;
        }

        var rows = new JsonArray();
        if (resultNode["results"] is JsonArray sourceRows)
        {
            foreach (var sourceRow in sourceRows)
            {
                if (sourceRow is not JsonObject entry)
                    continue;
                var row = new JsonObject
                {
                    ["index"] = entry["index"]?.DeepClone(),
                    ["kind"] = entry["kind"]?.DeepClone(),
                    ["committed"] = entry["committed"]?.DeepClone() ?? false,
                    ["journaled"] = entry["journaled"]?.DeepClone() ?? false,
                };
                CopySlimValue(entry, row, "function");
                CopySlimValue(entry, row, "name");
                CopySlimValue(entry, row, "commentChars");
                CopySlimValue(entry, row, "variable");
                CopySlimValue(entry, row, "type");
                CopySlimValue(entry, row, "alreadyDefined");
                CopySlimValue(entry, row, "code");
                if (entry["message"] is JsonValue message && message.TryGetValue<string>(out var messageText))
                {
                    var truncated = false;
                    row["message"] = ToolSupport.LimitSnapshotText(messageText, 160, ref truncated);
                }
                rows.Add(row);
            }
        }

        var slim = new JsonObject
        {
            ["operation"] = "BatchAnnotate",
            ["applied"] = resultNode["applied"]?.DeepClone() ?? JsonValue.Create(0),
            ["failed"] = resultNode["failed"]?.DeepClone() ?? JsonValue.Create(0),
            ["results"] = rows,
        };
        return new JsonObject { ["ok"] = true, ["result"] = slim }.ToJsonString();
    }

    /// <summary>Slim ack for SubmitAnnotations: the BatchAnnotate projection plus
    /// the durable progress counter (progress.doneCount).</summary>
    internal static string SlimSubmitAnnotationsAck(string raw)
    {
        var slimmed = SlimBatchAnnotateAck(raw);
        try
        {
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 16 });
            if (!document.RootElement.TryGetProperty("result", out var rawResult) ||
                !rawResult.TryGetProperty("progress", out var progress) ||
                progress.ValueKind != JsonValueKind.Object)
                return slimmed;
            var node = JsonNode.Parse(slimmed)!.AsObject();
            if (node["result"] is JsonObject result)
            {
                result["operation"] = "SubmitAnnotations";
                result["progress"] = JsonNode.Parse(progress.GetRawText());
            }
            return node.ToJsonString();
        }
        catch (JsonException)
        {
            return slimmed;
        }
    }

    private static void CopySlimValue(JsonObject source, JsonObject target, string property)
    {
        if (source[property] is JsonValue value &&
            value.GetValueKind() is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
            target[property] = value.DeepClone();
    }

    private void RegisterGhidraMutations(AnalysisContext context)
    {
        RegisterBatchAnnotate(context);
        RegisterSubmitAnnotations(context);
    }
}
