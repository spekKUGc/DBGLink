namespace DbgLink.Server;

internal static class NativePipeNamePolicy
{
    private const string ProcessPipePrefix = "DbgLink.Control.";
    private const int MaxPipeNameLength = 200;
    // N1 native pipe authentication appends a random hex suffix to the pipe
    // name (`DbgLink.Control.<pid>.<hex>`). The bound keeps the overall
    // 200-char cap meaningful while accepting the contracted suffix.
    private const int MaxRandomSuffixChars = 32;
    private const string FullPipePrefix = @"\\.\pipe\";

    public static bool IsValid(string? pipeName)
    {
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > MaxPipeNameLength || pipeName.Any(char.IsControl))
            return false;
        if (pipeName.Equals("DbgLink.Control", StringComparison.Ordinal))
            return true;
        if (!pipeName.StartsWith(ProcessPipePrefix, StringComparison.Ordinal))
            return false;

        var suffix = pipeName[ProcessPipePrefix.Length..];
        // Legacy `<pid>` form, or the N1 `<pid>.<hex>` form. The pid rules
        // are unchanged; the random suffix is hex only.
        var dot = suffix.IndexOf('.');
        var processText = dot < 0 ? suffix : suffix[..dot];
        if (!IsValidProcessId(processText))
            return false;
        if (dot < 0)
            return true;

        var random = suffix[(dot + 1)..];
        return random.Length is >= 1 and <= MaxRandomSuffixChars && random.All(IsHexDigit);
    }

    private static bool IsValidProcessId(string processText)
    {
        if (processText.Length == 0 || (processText.Length > 1 && processText[0] == '0'))
            return false;

        var processId = 0;
        foreach (var character in processText)
        {
            if (character is < '0' or > '9')
                return false;
            var digit = character - '0';
            if (processId > (int.MaxValue - digit) / 10)
                return false;
            processId = processId * 10 + digit;
        }

        return processId > 0;
    }

    private static bool IsHexDigit(char character)
        => character is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    /// <summary>
    /// Strips one leading <c>\\.\pipe\</c> prefix so the full Windows pipe
    /// path form (as published by the N1 rendezvous and forwarded by the
    /// launcher) validates and dials the same as the bare name that
    /// <see cref="IsValid"/> requires. Anything else passes through
    /// unchanged; validation still happens in <see cref="IsValid"/>.
    /// </summary>
    public static string? Normalize(string? pipeName)
        => pipeName is not null && pipeName.StartsWith(FullPipePrefix, StringComparison.Ordinal)
            ? pipeName[FullPipePrefix.Length..]
            : pipeName;
}
