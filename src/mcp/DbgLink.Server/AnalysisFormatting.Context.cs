using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;

namespace DbgLink.Server;

internal static partial class AnalysisFormatting
{
    internal static bool IsHexZero(ReadOnlySpan<char> span)
    {
        span = span.Trim();
        if (span.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            span = span[2..];
        while (span.Length > 0 && span[0] == '0')
            span = span[1..];
        return span.IsEmpty;
    }

    internal static JsonNode? FormatSparseContext(JsonNode? contextNode)
        => FormatContext(contextNode, sparse: true, state: null);

    internal static JsonNode? FormatDiffContext(JsonNode? contextNode, SessionSnapshotState state)
        => FormatContext(contextNode, sparse: false, state: state);

    private static JsonNode? FormatContext(
        JsonNode? contextNode,
        bool sparse,
        SessionSnapshotState? state)
    {
        if (contextNode is null) return null;
        if (contextNode is not JsonValue value || !value.TryGetValue<string>(out var text))
            return contextNode;

        var parts = new List<string>();
        var remaining = text.AsSpan();
        while (!remaining.IsEmpty)
        {
            var separator = remaining.IndexOf('|');
            var part = (separator >= 0 ? remaining[..separator] : remaining).Trim();
            remaining = separator >= 0 ? remaining[(separator + 1)..] : ReadOnlySpan<char>.Empty;
            if (part.IsEmpty) continue;

            if (part.StartsWith("DISASM", StringComparison.OrdinalIgnoreCase) ||
                part.StartsWith("STACK", StringComparison.OrdinalIgnoreCase))
            {
                parts.Add(part.ToString());
                continue;
            }

            var formattedPart = new StringBuilder();
            while (!part.IsEmpty)
            {
                part = part.TrimStart(' ');
                if (part.IsEmpty) break;

                var tokenSeparator = part.IndexOf(' ');
                var token = tokenSeparator >= 0 ? part[..tokenSeparator] : part;
                part = tokenSeparator >= 0 ? part[(tokenSeparator + 1)..] : ReadOnlySpan<char>.Empty;
                if (!ShouldKeepContextToken(token, sparse, state)) continue;

                if (formattedPart.Length > 0) formattedPart.Append(' ');
                formattedPart.Append(token);
            }

            if (formattedPart.Length > 0)
                parts.Add(formattedPart.ToString());
        }

        return JsonValue.Create(string.Join(" | ", parts));
    }

    private static bool ShouldKeepContextToken(
        ReadOnlySpan<char> token,
        bool sparse,
        SessionSnapshotState? state)
    {
        var equals = token.IndexOf('=');
        if (equals <= 0 || equals == token.Length - 1) return true;

        var name = token[..equals].Trim();
        var value = token[(equals + 1)..].Trim();
        if (sparse)
        {
            // Token saver: sparse keeps CIP + non-zero only. RSP/RBP/EFLAGS
            // ride along only when non-zero or changed (handled by diffOnly).
            if (name.Equals("CIP", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("RIP", StringComparison.OrdinalIgnoreCase))
                return true;

            return !IsHexZero(value);
        }

        var key = CanonicalRegister(name);
        var currentValue = value.ToString();
        if (name.Equals("CIP", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("RIP", StringComparison.OrdinalIgnoreCase))
        {
            // The instruction pointer always rides along, but the baseline is
            // still updated so the next diff can detect a step.
            state!.UpdateRegister(key, currentValue);
            return true;
        }

        // Atomic compare-and-update: the baseline is read and written under
        // one lock, so concurrent diff callers cannot interleave and leave a
        // baseline that mixes registers from different calls.
        return state!.UpdateRegister(key, currentValue);
    }

    internal static string CanonicalRegister(ReadOnlySpan<char> name)
    {
        if (name.Equals("RIP", StringComparison.OrdinalIgnoreCase)) return "CIP";
        if (name.Equals("RFLAGS", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("CFLAGS", StringComparison.OrdinalIgnoreCase)) return "EFLAGS";
        if (name.Equals("CSP", StringComparison.OrdinalIgnoreCase)) return "RSP";
        if (name.Equals("CBP", StringComparison.OrdinalIgnoreCase)) return "RBP";
        return name.ToString().ToUpperInvariant();
    }

    /// <summary>
    /// Brief slim view of the live context text: keeps the header line (live
    /// cip, module, instruction) and the registers block with zero-valued
    /// rows dropped (rip/cip always rides along), and cuts the disassembly
    /// and stack blocks. Old pipe-format contexts keep the register part and
    /// drop DISASM/STACK segments. Unknown shapes pass through untouched.
    /// </summary>
    internal static string SlimBriefContextText(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        if (text.Contains("[Registers]", StringComparison.OrdinalIgnoreCase))
            return SlimBlockContextText(text);
        if (text.Contains('|'))
        {
            var kept = new List<string>();
            foreach (var part in text.Split('|'))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("DISASM", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("STACK", StringComparison.OrdinalIgnoreCase))
                    continue;
                kept.Add(trimmed);
            }
            return string.Join(" | ", kept);
        }
        return text;
    }

    private static string SlimBlockContextText(string text)
    {
        var cut = text.Length;
        foreach (var marker in new[] { "\n[Disassembly]", "\n[DISASSEMBLY]", "\n[Stack]", "\n[STACK]" })
        {
            var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0 && index < cut)
                cut = index;
        }
        var head = cut < text.Length ? text[..cut] : text;
        var lines = head.Split('\n');
        var kept = new List<string>(lines.Length);
        foreach (var line in lines)
        {
            if (!IsZeroRegisterRow(line.Trim()))
                kept.Add(line);
        }
        return string.Join("\n", kept).TrimEnd();
    }

    private static bool IsZeroRegisterRow(string line)
    {
        var colon = line.IndexOf(':');
        if (colon <= 0 || colon > 9)
            return false;
        var name = line[..colon].Trim();
        if (name.Length == 0 || name.Length > 8)
            return false;
        foreach (var c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c))
                return false;
        }
        if (name.Equals("rip", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("cip", StringComparison.OrdinalIgnoreCase))
            return false;
        var value = line[(colon + 1)..].Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            value = value[2..];
        if (value.Length == 0 || value.Length > 16)
            return false;
        foreach (var c in value)
        {
            if (c != '0')
                return false;
        }
        return true;
    }

    internal static void UpdateLastRegisters(JsonNode? contextNode, SessionSnapshotState state)
    {
        if (contextNode is not JsonValue val || !val.TryGetValue<string>(out var text))
            return;

        var collected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var textSpan = text.AsSpan();
        while (!textSpan.IsEmpty)
        {
            var pipeIdx = textSpan.IndexOf('|');
            var partSpan = pipeIdx >= 0 ? textSpan[..pipeIdx] : textSpan;
            textSpan = pipeIdx >= 0 ? textSpan[(pipeIdx + 1)..] : ReadOnlySpan<char>.Empty;

            var trimmed = partSpan.Trim();
            if (trimmed.IsEmpty ||
                trimmed.StartsWith("DISASM", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("STACK", StringComparison.OrdinalIgnoreCase))
                continue;

            var tokenSpan = trimmed;
            while (!tokenSpan.IsEmpty)
            {
                while (!tokenSpan.IsEmpty && tokenSpan[0] == ' ')
                    tokenSpan = tokenSpan[1..];
                if (tokenSpan.IsEmpty) break;

                var spaceIdx = tokenSpan.IndexOf(' ');
                var tok = spaceIdx >= 0 ? tokenSpan[..spaceIdx] : tokenSpan;
                tokenSpan = spaceIdx >= 0 ? tokenSpan[(spaceIdx + 1)..] : ReadOnlySpan<char>.Empty;

                var eqIdx = tok.IndexOf('=');
                if (eqIdx > 0 && eqIdx < tok.Length - 1)
                {
                    var regName = CanonicalRegister(tok[..eqIdx].Trim());
                    var regVal = tok[(eqIdx + 1)..].Trim().ToString();
                    collected[regName] = regVal;
                }
            }
        }

        state.ReplaceRegisters(collected);
    }
}
