using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>
    /// GetAnalysisQueue: bottom-up worklist of the next N functions,
    /// leaves-first (callees before callers). Read-only planning queue;
    /// each row carries name, entry, instructionCount, named plus the
    /// calleeCount the order sorts by (rva opt-in via includeRva).
    /// P2-10 withDigests: opt-in per-row AnalyzeFunctions digests (capped,
    /// triage budgets) so queue+N analyze collapses to one call.
    /// </summary>
    private void RegisterAnalysisQueue(AnalysisContext context)
    {
        Register(new JsonObject
        {
            ["name"] = "GetAnalysisQueue",
            ["description"] = "Next N functions leaves-first; rows carry name, entry, instructionCount, named, calleeCount. Skips annotated (excludeAnnotated); raise limit when truncated. withDigests embeds per-row digests (up to 16, digestLimit to 24).",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["limit"] = IntRule(8, 1, 64, "Max rows."),
                    ["excludeAnnotated"] = BoolRule(true, "Skip journaled (already annotated) functions."),
                    ["withDigests"] = BoolRule(false, "Per-row digests for up to digestLimit rows; beyond the cap rows carry no digest."),
                    ["digestLimit"] = IntRule(16, 1, 24, "Max digested rows; capped at 24."),
                    ["includeRva"] = BoolRule(false, "Add rva."),
                    ["module"] = Utf8Text("Active-program path or file name; no external file is opened.", 2048)
                },
                ["examples"] = new JsonArray(new JsonObject { ["limit"] = 8 }),
                ["additionalProperties"] = false
            }
        }, call => ExecuteAnalysisQueueAsync(context, call.Arguments, call.CancellationToken),
            ToolCapability.ReadOnly, requiresControl: false, lean: true, minimumTimeoutMs: 120_000);
    }

    /// <summary>Digest fan-out batch size: the AnalyzeFunctions bridge cap,
    /// so each fan-out call covers at most one batch of rows.</summary>
    internal const int QueueDigestBatchSize = 8;

    /// <summary>Default digest rows per queue call: one queue + two digest
    /// calls cover a full BatchAnnotate transaction (16 ops).</summary>
    internal const int DefaultQueueDigestLimit = 16;

    /// <summary>Hard cap for digestLimit: beyond BatchAnnotate width the rows
    /// are dead weight (the model cannot annotate them in one turn).</summary>
    internal const int MaxQueueDigestLimit = 24;

    /// <summary>Wall-clock budget for the whole digest fan-out: a slow batch
    /// must degrade to digestsTruncated, never stall the queue call.</summary>
    internal const int QueueDigestFanOutTimeoutMs = 60_000;

    /// <summary>Triage budget for the digest fan-out: one digest entry already
    /// holds decompilation plus references/strings/constants, so the batch
    /// AnalyzeFunctions clamp (maxChars 8000) applies here too.</summary>
    internal const int QueueDigestMaxChars = 8_000;
    internal const int QueueDigestMaxItems = 8;

    /// <summary>
    /// P2-10 local queue read: without withDigests this is a pure bridge
    /// passthrough (byte-stable); with withDigests it strips the MCP-only
    /// flags, runs the queue, then fans out AnalyzeFunctions calls in batches
    /// of QueueDigestBatchSize and embeds each digest entry in its own row.
    /// Digest failures never fail the queue: rows keep no digest and the
    /// honest digestsTruncated/digestError flags explain why.
    /// </summary>
    internal static async Task<string> ExecuteAnalysisQueueAsync(
        AnalysisContext context, JsonElement? arguments, CancellationToken cancellationToken)
    {
        var withDigests = ToolSupport.ReadArgumentBool(arguments, "withDigests", false);
        var digestLimit = Math.Clamp(ToolSupport.ReadArgumentInt(arguments, "digestLimit", DefaultQueueDigestLimit),
            1, MaxQueueDigestLimit);
        // Both flags are MCP-only: the bridge rejects unknown fields, so they
        // are stripped in both modes. WithoutKey returns the same reference
        // when the key is absent, keeping the opted-out path byte-stable.
        var forward = WithoutKey(WithoutKey(arguments, "withDigests"), "digestLimit");
        var raw = await context.Ghidra.RequestAsync("GetAnalysisQueue", forward, cancellationToken).ConfigureAwait(false);
        if (!withDigests)
            return raw;
        return await AttachQueueDigestsAsync(context, raw, digestLimit, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> AttachQueueDigestsAsync(
        AnalysisContext context, string raw, int digestLimit, CancellationToken cancellationToken)
    {
        JsonObject? root;
        JsonObject? result;
        JsonArray? queue;
        try
        {
            root = JsonNode.Parse(raw)?.AsObject();
            result = root?["result"]?.AsObject();
            queue = result?["queue"]?.AsArray();
            if (root is null || result is null || queue is null)
                return raw;
        }
        catch (JsonException)
        {
            return raw;
        }
        catch (InvalidOperationException)
        {
            return raw;
        }

        // Rows eligible for a digest, in queue order, capped at digestLimit.
        var eligible = new List<(JsonObject Row, string Selector)>();
        foreach (var row in queue)
        {
            if (eligible.Count >= digestLimit)
                break;
            if (row is not JsonObject rowObject)
                continue;
            var entry = AnalysisFormatting.ReadNodeString(rowObject, "entry");
            if (!string.IsNullOrWhiteSpace(entry))
                eligible.Add((rowObject, entry!));
        }

        result["withDigests"] = true;
        if (eligible.Count == 0)
        {
            result["digestedCount"] = 0;
            result["digestsTruncated"] = queue.Count > 0;
            return root.ToJsonString();
        }

        // Fan out in AnalyzeFunctions-sized batches (at most 8 selectors per
        // bridge call): each batch attaches only to its own slice, verified
        // by length, so a short batch can never shift later rows onto foreign
        // digests. The per-batch budget keeps the 8000-char total: batches
        // share it instead of multiplying the payload.
        var batchCount = (eligible.Count + QueueDigestBatchSize - 1) / QueueDigestBatchSize;
        var perBatchChars = Math.Clamp(QueueDigestMaxChars / batchCount, 1_000, QueueDigestMaxChars);
        using var fanOutTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        fanOutTimeout.CancelAfter(QueueDigestFanOutTimeoutMs);
        var fanOutToken = fanOutTimeout.Token;
        var attached = 0;
        string? firstError = null;
        var timedOut = false;
        for (var batch = 0; batch < batchCount; batch++)
        {
            var slice = eligible.Skip(batch * QueueDigestBatchSize).Take(QueueDigestBatchSize).ToArray();
            JsonArray? entries = null;
            string? sliceError = null;
            try
            {
                var digestRaw = await context.Ghidra.RequestAsync("AnalyzeFunctions",
                    JsonSerializer.SerializeToElement(new
                    {
                        functions = slice.Select(pair => pair.Selector).ToArray(),
                        maxChars = perBatchChars,
                        maxItems = QueueDigestMaxItems,
                        // C-free digests: pin the default so a producer change
                        // cannot silently multiply the payload with decompilation.
                        includeDecomp = false,
                    }), fanOutToken).ConfigureAwait(false);
                entries = JsonNode.Parse(digestRaw)?["result"]?["functions"]?.AsArray();
                sliceError = entries is null
                    ? BridgeClient.TryParseErrorCode(digestRaw) ?? "digest_unavailable"
                    : null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                // Fan-out budget exhausted: keep the queue with whatever is
                // attached so far and report truncation honestly.
                timedOut = true;
                break;
            }
            catch
            {
                sliceError = "digest_unavailable";
            }
            if (sliceError is not null || entries is null)
            {
                firstError ??= sliceError ?? "digest_unavailable";
                continue;
            }
            // Length-verified pairing: the n-th slice row pairs with
            // entries[n]. A short batch fails its slice instead of shifting
            // later rows onto foreign digests.
            if (entries.Count != slice.Length)
            {
                firstError ??= "digest_length_mismatch";
                continue;
            }
            for (var index = 0; index < slice.Length; index++)
            {
                slice[index].Row["digest"] = CompactQueueDigest(entries[index]);
                attached++;
            }
        }

        result["digestedCount"] = attached;
        result["digestsTruncated"] = queue.Count > eligible.Count || attached < eligible.Count || timedOut;
        if (attached == 0)
            result["digestError"] = firstError ?? (timedOut ? "digest_timeout" : "digest_unavailable");
        return root.ToJsonString();
    }

    /// <summary>
    /// The queue row already carries name/entry; the digest function object
    /// repeats them (plus rva, derivable from entry) and always emits empty
    /// arrays. Keep identity once, keep only populated sections.
    /// </summary>
    private static JsonNode? CompactQueueDigest(JsonNode? entry)
    {
        if (entry is not JsonObject digest)
            return entry?.DeepClone();
        var compact = (JsonObject)digest.DeepClone();
        if (compact["function"] is JsonObject function)
        {
            // The parent queue row already carries name, entry and rva; the
            // digest's function object kept repeating all three. Analysis data
            // (naming quality, counts) stays.
            function.Remove("name");
            function.Remove("rva");
            function.Remove("entry");
        }
        if (compact["references"] is JsonObject references)
        {
            RemoveEmptyArray(references, "callers");
            RemoveEmptyArray(references, "callees");
        }
        RemoveEmptyArray(compact, "strings");
        RemoveEmptyArray(compact, "constants");
        return compact;
    }

    private static void RemoveEmptyArray(JsonObject node, string key)
    {
        if (node[key] is JsonArray { Count: 0 })
            node.Remove(key);
    }
}
