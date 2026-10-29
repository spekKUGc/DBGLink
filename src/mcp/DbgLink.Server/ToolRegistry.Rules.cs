using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal sealed partial class ToolRegistry
{
    /// <summary>Canonical autoPause description (P0-1): one short sentence
    /// shared by all tools. The BoolRule default=false already conveys the
    /// default; the text keeps only the load-bearing pause/resume contract.</summary>
    private const string AutoPauseDescription =
        "True pauses a running target, then resumes it; paused stays paused.";

    private const string AutoPauseBatchDescription =
        "True pauses a running target for the batch, then resumes it; debugger batch only.";

    // Bound dedup rule: a bound implied by a stricter keyword is not repeated
    // in the advertised schema (x-nonblank already rejects empty and
    // whitespace-only text; x-maxUtf8Bytes equal to maxLength is at least as
    // strict). The server still validates with the executable rule, so the
    // only effect is a smaller tools/list for every property built here.
    private static JsonObject TextRule(string description, int maximum = 256) => new()
    {
        ["type"] = "string",
        ["maxLength"] = maximum,
        ["x-nonblank"] = true,
        ["description"] = description
    };

    private static JsonObject OptText(string description, int maxLength = 64) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["maxLength"] = maxLength,
    };

    /// <summary>
    /// Breakpoint condition/log text: free-form x64dbg expressions, but the
    /// native quoted-argument policy cannot embed a literal quote and rejects
    /// C0 controls + DEL. Fail fast at the MCP layer with a schema pattern so
    /// hostile text never costs a bridge round-trip (native still fails
    /// closed). Valid expressions like 'eax == 1' pass; only '"' and
    /// &lt;0x20/0x7F are banned.
    /// </summary>
    private const string NoQuoteOrControlPattern = "^[^\"\\x00-\\x1F\\x7F]*$";

    private static JsonObject BreakpointTextRule(string description, int maxLength = 256) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["maxLength"] = maxLength,
        ["pattern"] = NoQuoteOrControlPattern,
    };

    private static JsonObject IntRule(int value, int minimum, int maximum, string? description = null)
    {
        var rule = new JsonObject
        {
            ["type"] = "integer",
            ["default"] = value,
            ["minimum"] = minimum,
            ["maximum"] = maximum,
        };
        if (description is not null)
            rule["description"] = description;
        return rule;
    }

    private static JsonObject AddrRule(string description) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["x-maxUtf8Bytes"] = 256,
        ["x-nonblank"] = true,
    };

    private static JsonObject KindRule(string description, string pattern) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["maxLength"] = 16,
        ["pattern"] = pattern,
    };

    private static JsonObject BoolRule(bool value, string? description = null)
    {
        var rule = new JsonObject
        {
            ["type"] = "boolean",
            ["default"] = value,
        };
        if (description is not null)
            rule["description"] = description;
        return rule;
    }

    /// <summary>Non-blank string with description before the length bounds.</summary>
    private static JsonObject NonBlankText(string description, int maxLength) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["maxLength"] = maxLength,
        ["x-nonblank"] = true,
    };

    /// <summary>Optional UTF-8-bounded string: x-maxUtf8Bytes already implies maxLength.</summary>
    private static JsonObject Utf8Text(string description, int maxLength) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["x-maxUtf8Bytes"] = maxLength,
    };

    private static JsonObject StepKindRule(string? description = null)
    {
        var rule = new JsonObject
        {
            ["type"] = "string",
            ["default"] = "into",
            ["pattern"] = "^(?i)(into|over|out)$",
        };
        if (description is not null)
            rule["description"] = description;
        return rule;
    }

    private static JsonObject Sha256Rule(string description) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["pattern"] = "^[0-9a-fA-F]{64}$",
        ["x-nonblank"] = true,
    };

    private static JsonObject MultilineText(string description, int maxLength, bool nonblank = false)
    {
        var rule = new JsonObject
        {
            ["type"] = "string",
            ["description"] = description,
            ["maxLength"] = maxLength,
        };
        rule["x-multiline"] = true;
        if (nonblank)
        {
            // x-nonblank is stricter than minLength 1; no second bound.
            rule["x-nonblank"] = true;
        }
        return rule;
    }

    /// <summary>
    /// Tool method names are short PascalCase alphanumerics. Rejects
    /// injection-shaped payloads before the allow-list lookup so the error
    /// names the shape problem, not a misleading "unsupported method".
    /// Runtime-only check: the advertised batch schema text is untouched.
    /// </summary>
    internal static bool IsValidToolMethodName(string? method)
    {
        if (string.IsNullOrEmpty(method) || method.Length > 64)
            return false;
        if (!char.IsAsciiLetter(method[0]))
            return false;
        for (var index = 1; index < method.Length; index++)
        {
            if (!char.IsAsciiLetterOrDigit(method[index]))
                return false;
        }
        return true;
    }

    private static JsonObject SymbolNameRule(string description) => new()
    {
        ["type"] = "string",
        ["description"] = description,
        ["maxLength"] = 128,
        ["pattern"] = "^[A-Za-z_$?][A-Za-z0-9_$?]*$",
        ["minLength"] = 1,
    };

    private static JsonObject ArchitectureRule() => new()
    {
        ["type"] = "string",
        ["enum"] = new JsonArray("auto", "x86", "x64"),
        ["default"] = "auto",
        ["description"] = "Target arch; auto needs path."
    };
}
