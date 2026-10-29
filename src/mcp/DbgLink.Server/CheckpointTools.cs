using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed class CheckpointTools
{
    private readonly CheckpointStore _checkpoints;
    private static readonly JsonSerializerOptions _jsonOptions = ToolSupport.BudgetJsonOptions;

    public CheckpointTools(CheckpointStore checkpoints)
    {
        _checkpoints = checkpoints;
    }

    internal Task<string> CreateCheckpointAsync(JsonElement? arguments, string? analysisId)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object })
        {
            return InvalidCheckpoint("Checkpoint arguments are required.");
        }

        var args = arguments.Value;
        // sha256 is optional when the caller's session already saved a
        // checkpoint: the hash resolves server-side from the store's
        // analysisId binding, saving a ListAnalysisSessions-for-hash lookup.
        // An explicitly supplied hash always wins and is strictly validated.
        string? sha256 = null;
        if (args.TryGetProperty("sha256", out var shaElement))
        {
            if (shaElement.ValueKind != JsonValueKind.String ||
                AddressMapping.NormalizeSha256(shaElement.GetString()) is not string supplied)
            {
                return InvalidCheckpoint("The checkpoint SHA-256 must be exactly 64 hexadecimal characters.");
            }
            sha256 = supplied;
        }
        sha256 ??= ResolveSha256ForSession(analysisId);
        if (sha256 is null)
        {
            return InvalidCheckpoint("The checkpoint SHA-256 is unknown or ambiguous for this session: pass sha256 explicitly (64 hexadecimal characters).");
        }

        if (!TryReadString(args, "findings", required: true, out var findings)
            || !TryReadString(args, "hypotheses", required: true, out var hypotheses)
            || !TryReadString(args, "verified", required: true, out var verified)
            || !TryReadString(args, "nextStep", required: true, out var nextStep))
        {
            return InvalidCheckpoint("The checkpoint must include findings, hypotheses, verified, and nextStep.");
        }

        // An empty save would silently erase a previously stored handoff for
        // the same SHA-256 (last-writer-wins slot, no history). Require real
        // content, mirroring the title/nextStep non-blank rule below.
        if (string.IsNullOrWhiteSpace(findings) || string.IsNullOrWhiteSpace(hypotheses)
            || string.IsNullOrWhiteSpace(verified) || string.IsNullOrWhiteSpace(nextStep))
        {
            return InvalidCheckpoint("Checkpoint findings, hypotheses, verified, and nextStep must be non-empty strings.");
        }

        var title = "DBGLink checkpoint";
        if (args.TryGetProperty("title", out _)
            && (!TryReadString(args, "title", required: true, out title) || string.IsNullOrWhiteSpace(title)))
        {
            return InvalidCheckpoint("The checkpoint title must be a non-empty string.");
        }

        if (!TryReadOptionalString(args, "context", out var context)
            || !TryReadOptionalString(args, "liveValues", out var liveValues))
        {
            return InvalidCheckpoint("Checkpoint context and liveValues must be strings when supplied.");
        }

        var checkpoint = new McpCheckpoint(
            sha256,
            title,
            findings,
            hypotheses,
            verified,
            nextStep,
            context,
            liveValues,
            DateTimeOffset.UtcNow,
            analysisId);

        try
        {
            _checkpoints.Save(checkpoint);
            return Task.FromResult(BridgeEnvelope.Success(new JsonObject
            {
                ["saved"] = true,
                ["sha256"] = checkpoint.Sha256,
                ["createdAtUtc"] = checkpoint.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["message"] = "The DBGLink checkpoint was saved for this binary SHA-256."
            }, options: _jsonOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or TimeoutException)
        {
            return Task.FromResult(BridgeEnvelope.Error(
                "checkpoint_unavailable",
                $"The checkpoint could not be saved ({ToolSupport.FailureReason(exception)})."));
        }
    }

    internal Task<string> GetLastCheckpointAsync(JsonElement? arguments = null)
    {
        if (!TryReadRequiredSha256(arguments, out var requestedSha256))
        {
            return InvalidCheckpoint("The checkpoint SHA-256 must be exactly 64 hexadecimal characters.");
        }

        (McpCheckpoint? Checkpoint, IReadOnlyList<string> AvailableSha256) snapshot;
        try
        {
            snapshot = _checkpoints.LoadSnapshot(requestedSha256);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or TimeoutException)
        {
            return Task.FromResult(BridgeEnvelope.Error(
                "checkpoint_unavailable",
                $"The requested checkpoint could not be loaded ({ToolSupport.FailureReason(exception)})."));
        }

        var argsObj = arguments is { ValueKind: JsonValueKind.Object } ? arguments.Value : (JsonElement?)null;
        var includeAllHashes = argsObj is not null && argsObj.Value.TryGetProperty("includeAllHashes", out var allHashesEl) &&
            allHashesEl.ValueKind == JsonValueKind.True;
        var available = includeAllHashes
            ? snapshot.AvailableSha256
            : snapshot.AvailableSha256.Take(8).ToArray();
        var result = new JsonObject
        {
            ["found"] = snapshot.Checkpoint is not null,
            ["availableSha256"] = new JsonArray(available.Select(value => JsonValue.Create(value)).ToArray())
        };
        if (!includeAllHashes && snapshot.AvailableSha256.Count > available.Count)
            result["availableTruncated"] = true;
        if (snapshot.Checkpoint is null)
        {
            result["message"] = "No DBGLink checkpoint has been saved for this binary SHA-256.";
        }
        else
        {
            var checkpoint = snapshot.Checkpoint!;
            var fields = ReadOptionalString(argsObj, "fields") ?? "full";
            var maxChars = ReadOptionalInt(argsObj, "maxChars", 2000, 256, 8000);
            var include = ReadOptionalStringArray(argsObj, "include");
            var ifNoneMatch = ReadOptionalString(argsObj, "ifNoneMatch");
            var contentHash = ComputeCheckpointHash(checkpoint);
            result["contentHash"] = contentHash;
            if (ifNoneMatch is not null && string.Equals(ifNoneMatch, contentHash, StringComparison.OrdinalIgnoreCase))
            {
                result["unchanged"] = true;
                return Task.FromResult(BridgeEnvelope.Success(result, options: _jsonOptions));
            }
            if (string.Equals(fields, "summary", StringComparison.OrdinalIgnoreCase))
            {
                result["checkpoint"] = BuildCheckpointSummary(checkpoint, contentHash, maxChars, include);
            }
            else
            {
                var age = DateTimeOffset.UtcNow - checkpoint.CreatedAtUtc;
                var ageDays = age.TotalDays < 0 ? 0 : (int)Math.Floor(age.TotalDays);
                result["checkpoint"] = new JsonObject
                {
                    ["title"] = checkpoint.Title,
                    ["sha256"] = checkpoint.Sha256,
                    ["findings"] = checkpoint.Findings,
                    ["hypotheses"] = checkpoint.Hypotheses,
                    ["verified"] = checkpoint.Verified,
                    ["nextStep"] = checkpoint.NextStep,
                    ["context"] = checkpoint.Context,
                    ["liveValues"] = checkpoint.LiveValues,
                    ["liveValuesRequireRevalidation"] = true,
                    ["createdAtUtc"] = checkpoint.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                    ["analysisId"] = checkpoint.AnalysisId,
                    // Lifecycle: age tells the resuming run how stale this
                    // handoff is; >30 days is flagged, never hidden.
                    ["ageDays"] = ageDays,
                    ["stale"] = ageDays > 30,
                };
            }
        }

        return Task.FromResult(BridgeEnvelope.Success(result, options: _jsonOptions));
    }

    /// <summary>
    /// Fail-closed server-side hash resolution for sha256-omitted creates:
    /// resolves only when EXACTLY ONE distinct sha256 has ever been saved
    /// under this analysisId. If the same analysisId was reused for a
    /// different binary (two distinct shas), resolution returns null so the
    /// caller must pass sha256 explicitly instead of filing under the wrong
    /// (newest) binary. Scans the bounded store (file-backed, lock-guarded)
    /// and never hashes anything. Returns null when the session is unknown,
    /// ambiguous, or the store is unreadable; the caller then reports
    /// checkpoint_invalid with a pass-it-explicitly hint instead of guessing.
    /// Residual risk: when the analysisId is reused for a new binary that has
    /// never saved a checkpoint, the store still holds exactly one (old) sha
    /// and resolution files under the old binary. Callers must pass sha256
    /// explicitly after switching targets; a future cross-check against the
    /// live session's known sha (ListAnalysisSessions sha256/manifest) could
    /// reject that mismatch without hashing on the hot path.
    /// </summary>
    private string? ResolveSha256ForSession(string? analysisId)
    {
        if (string.IsNullOrWhiteSpace(analysisId))
            return null;
        try
        {
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (var candidate in _checkpoints.ListSha256())
            {
                McpCheckpoint? checkpoint;
                try
                {
                    checkpoint = _checkpoints.Load(candidate);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or TimeoutException)
                {
                    continue;
                }
                if (checkpoint is null ||
                    !string.Equals(checkpoint.AnalysisId, analysisId, StringComparison.Ordinal))
                    continue;
                distinct.Add(checkpoint.Sha256);
            }
            return distinct.Count == 1 ? distinct.Single() : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or TimeoutException)
        {
            return null;
        }
    }

    internal static JsonObject BuildCheckpointSummary(McpCheckpoint checkpoint, string contentHash, int maxChars, HashSet<string>? include)
    {
        bool Want(string name) => include is null || include.Contains(name);
        var age = DateTimeOffset.UtcNow - checkpoint.CreatedAtUtc;
        var ageDays = age.TotalDays < 0 ? 0 : (int)Math.Floor(age.TotalDays);
        var fieldChars = new JsonObject
        {
            ["findings"] = checkpoint.Findings.Length,
            ["hypotheses"] = checkpoint.Hypotheses.Length,
            ["verified"] = checkpoint.Verified.Length,
            ["nextStep"] = checkpoint.NextStep.Length,
            ["context"] = checkpoint.Context.Length,
            ["liveValues"] = checkpoint.LiveValues.Length,
        };
        var summary = new JsonObject
        {
            ["title"] = checkpoint.Title,
            ["sha256"] = checkpoint.Sha256,
            ["createdAtUtc"] = checkpoint.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture),
            ["analysisId"] = checkpoint.AnalysisId,
            ["contentHash"] = contentHash,
            ["ageDays"] = ageDays,
            ["stale"] = ageDays > 30,
            ["fieldChars"] = fieldChars,
            ["availableNote"] = "Pass fields=full or include=[...] for full text.",
        };
        if (Want("findings")) summary["findingsPreview"] = Truncate(checkpoint.Findings, maxChars);
        if (Want("hypotheses")) summary["hypothesesPreview"] = Truncate(checkpoint.Hypotheses, maxChars);
        if (Want("verified")) summary["verifiedPreview"] = Truncate(checkpoint.Verified, maxChars);
        if (Want("nextStep")) summary["nextStepPreview"] = Truncate(checkpoint.NextStep, maxChars);
        summary["contextPreview"] = Truncate(checkpoint.Context, Math.Min(maxChars, 2000));
        summary["contextFullLength"] = checkpoint.Context.Length;
        summary["liveValuesPreview"] = Truncate(checkpoint.LiveValues, 0);
        summary["liveValuesFullLength"] = checkpoint.LiveValues.Length;
        summary["liveValuesRequireRevalidation"] = true;
        return summary;
    }

    private static string Truncate(string text, int max)
    {
        if (max <= 0) return string.Empty;
        if (text.Length <= max) return text;
        return text[..max] + "...[truncated]";
    }

    private static string? ReadOptionalString(JsonElement? args, string name)
    {
        if (args is not { ValueKind: JsonValueKind.Object }) return null;
        if (!args.Value.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String) return null;
        return el.GetString();
    }

    private static int ReadOptionalInt(JsonElement? args, string name, int def, int min, int max)
    {
        if (args is not { ValueKind: JsonValueKind.Object }) return def;
        if (!args.Value.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Number) return def;
        try
        {
            var v = el.GetInt32();
            return Math.Clamp(v, min, max);
        }
        catch { return def; }
    }

    private static HashSet<string>? ReadOptionalStringArray(JsonElement? args, string name)
    {
        if (args is not { ValueKind: JsonValueKind.Object }) return null;
        if (!args.Value.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Array) return null;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in el.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String && item.GetString() is string s && s.Length > 0)
                set.Add(s);
        return set.Count == 0 ? null : set;
    }

    internal static string ComputeCheckpointHash(McpCheckpoint checkpoint)
    {
        var joined = string.Join("\n", new[] { checkpoint.Findings, checkpoint.Hypotheses, checkpoint.Verified, checkpoint.NextStep });
        var bytes = System.Text.Encoding.UTF8.GetBytes(joined);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16];
    }

    private static Task<string> InvalidCheckpoint(string message)
        => Task.FromResult(BridgeEnvelope.Error("checkpoint_invalid", message));

    private static bool TryReadRequiredSha256(JsonElement? arguments, out string sha256)
    {
        sha256 = string.Empty;
        return arguments is { ValueKind: JsonValueKind.Object }
            && TryReadString(arguments.Value, "sha256", required: true, out sha256)
            && AddressMapping.NormalizeSha256(sha256) is not null;
    }

    private static bool TryReadOptionalString(JsonElement arguments, string name, out string value)
    {
        value = string.Empty;
        if (!arguments.TryGetProperty(name, out var element))
        {
            return true;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString() ?? string.Empty;
        return true;
    }

    private static bool TryReadString(JsonElement arguments, string name, bool required, out string value)
    {
        value = string.Empty;
        if (!arguments.TryGetProperty(name, out var element))
        {
            return !required;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString() ?? string.Empty;
        return true;
    }
}
