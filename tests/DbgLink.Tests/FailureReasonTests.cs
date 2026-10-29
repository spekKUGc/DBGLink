using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Round 5 error-path rule: model-facing failure text carries a stable reason,
/// never an exception type name, and shared guidance has one source.
/// </summary>
public sealed class FailureReasonTests
{
    [Theory]
    [InlineData(typeof(TimeoutException), "the backend timed out")]
    [InlineData(typeof(IOException), "the backend connection failed")]
    [InlineData(typeof(UnauthorizedAccessException), "access was denied")]
    [InlineData(typeof(InvalidOperationException), "the backend failed")]
    public void Failure_reason_is_stable_and_type_free(Type exceptionType, string expected)
    {
        var exception = (Exception)Activator.CreateInstance(exceptionType)!;
        Assert.Equal(expected, ToolSupport.FailureReason(exception));
        Assert.DoesNotContain("Exception", ToolSupport.FailureReason(exception));
    }

    [Fact]
    public void Auto_pause_failure_never_names_the_exception_type()
    {
        var text = ToolSupport.AutoPausePauseFailure(new IOException("pipe broke"));
        Assert.DoesNotContain("IOException", text);
        Assert.Contains("ControlDebuggerExecution action=pause", text);
        Assert.Contains("left running", text);
    }
}
