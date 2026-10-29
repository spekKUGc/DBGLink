namespace DbgLink.Server;

/// <summary>
/// Raised when a caller names an analysis session that does not exist (or was
/// closed). The dispatcher maps it to the <c>bad_session</c> outcome.
///
/// It exists as a dedicated type so the classification cannot silently change
/// when the human-readable message is reworded: the old check matched the
/// English message prefix "Analysis session '", which turned any refactor of
/// that string into a generic "exception" outcome.
/// </summary>
internal sealed class AnalysisSessionNotFoundException : InvalidOperationException
{
    internal AnalysisSessionNotFoundException(string analysisId)
        : base($"Analysis session '{analysisId}' was not found.")
    {
        AnalysisId = analysisId;
    }

    /// <summary>The session id that could not be resolved.</summary>
    internal string AnalysisId { get; }
}
