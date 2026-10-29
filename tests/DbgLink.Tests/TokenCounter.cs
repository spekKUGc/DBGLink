using Microsoft.ML.Tokenizers;

namespace DbgLink.Tests;

/// <summary>
/// Real BPE token counting for efficiency tests (cl100k_base, Codex/GPT-4 family).
/// Single source: every Tok helper in the efficiency/benchmark tests delegates here,
/// so model-specific counting changes in exactly one place.
/// Production telemetry counts with the same encoding via
/// DbgLink.Server.TokenMeter; this is the test-side mirror of it.
/// </summary>
internal static class TokenCounter
{
    private static readonly TiktokenTokenizer Tokenizer =
        TiktokenTokenizer.CreateForEncoding("cl100k_base");
    private static readonly object Gate = new();

    internal static int Count(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return 0;
        lock (Gate)
            return Tokenizer.CountTokens(text);
    }
}
