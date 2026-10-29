namespace DbgLink.Tests;

/// <summary>
/// Scoped override of the native pipe token environment variable. The
/// server reads the token from the environment (the launcher passes it that
/// way because a command-line credential is readable by every local process),
/// so the tests that pin the command-line behaviour have to control the
/// ambient value.
///
/// The variable name is spelled out here instead of referencing
/// DbgLinkConfigPath: the shared source is compiled into both the server and
/// the launcher assembly, so the type name is ambiguous in this test project.
/// </summary>
internal static class PipeTokenEnvironment
{
    private const string VariableName = "DBGLINK_NATIVE_PIPE_TOKEN";

    /// <summary>Sets the variable to <paramref name="value"/> (null clears it)
    /// and restores the previous value on dispose.</summary>
    internal static ScopeHandle Scope(string? value)
    {
        var previous = Environment.GetEnvironmentVariable(VariableName);
        Environment.SetEnvironmentVariable(VariableName, value);
        return new ScopeHandle(previous);
    }

    internal sealed class ScopeHandle : IDisposable
    {
        private readonly string? _previous;
        private int _disposed;

        internal ScopeHandle(string? previous) => _previous = previous;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            Environment.SetEnvironmentVariable(VariableName, _previous);
        }
    }
}
