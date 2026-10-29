using Microsoft.ML.Tokenizers;

namespace DbgLink.Server;

/// <summary>
/// Real cl100k_base BPE token counting for telemetry (Codex/GPT-4 family).
/// Single production source: every tok number goes through here. There is
/// no heuristic fallback: a side without payload text contributes 0, and
/// text beyond MaxCharsToTokenize is dropped (only the leading prefix is
/// counted), so a huge payload cannot stall the request path.
/// Never throws into a request path: any tokenizer failure degrades to 0
/// for that side.
/// Thread-safe: the tokenizer is immutable after lazy creation and safe for
/// concurrent use, so concurrent tool calls count without a global lock.
/// </summary>
internal static class TokenMeter
{
    /// <summary>At most this many leading chars per call side go through
    /// BPE; the remainder (if any) is dropped, never estimated. Bounds the
    /// request-path cost for huge payloads.
    ///
    /// The number is a latency budget, not an accuracy target: telemetry only
    /// needs an order of magnitude, while the tokenizer is superlinear on long
    /// single-character runs (a 200 KB side cost seconds, and the cap is what
    /// let that reach the request path). 16 K chars keeps a big payload under
    /// a few milliseconds.</summary>
    internal const int MaxCharsToTokenize = 16_000;

    // Both packages are required: Microsoft.ML.Tokenizers alone throws at
    // runtime when creating the encoding without the Data.Cl100kBase data.
    private static readonly Lazy<TiktokenTokenizer> Tokenizer = new(
        static () => TiktokenTokenizer.CreateForEncoding("cl100k_base"),
        System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

    private static int CountText(string text)
    {
        // TiktokenTokenizer is immutable after creation and safe for concurrent
        // use; serializing every call on a global lock turned this cheap lookup
        // into a process-wide bottleneck across all servers in one process.
        return Tokenizer.Value.CountTokens(text);
    }

    /// <summary>One tool call's tokens: real BPE per side where the actual
    /// text is available, 0 per side without text. Null/empty text means
    /// "unavailable" for that side. The byte counts only preserve the
    /// long-standing call-site shape; they never feed the count. Never
    /// throws.</summary>
    internal static long CountCall(string? requestText, string? responseText, long requestBytes, long responseBytes)
    {
        // requestBytes/responseBytes are kept so byte-only call sites need
        // no signature churn; with no text there is nothing real to count.
        _ = requestBytes;
        _ = responseBytes;
        try
        {
            return CountSide(requestText) + CountSide(responseText);
        }
        catch
        {
            return 0;
        }
    }

    private static long CountSide(string? text)
    {
        try
        {
            if (string.IsNullOrEmpty(text))
                return 0;
            // Over cap: BPE the prefix, drop the tail (no estimation).
            var prefix = text.Length <= MaxCharsToTokenize ? text : text.Substring(0, MaxCharsToTokenize);
            return Math.Max(0, CountText(prefix));
        }
        catch
        {
            return 0;
        }
    }
}
