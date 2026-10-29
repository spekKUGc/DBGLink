using System.Text.RegularExpressions;

namespace DbgLink.Launcher.Core;

public enum ToolkitComponent
{
    Debugger,
    NativeBridge,
    McpServer,
    GhidraBridge,
    Toolkit
}

public enum ToolkitComponentState
{
    Pending,
    Starting,
    Ready,
    WaitingForTarget,
    Failed,
    Stopped
}

public sealed record ToolkitStatusUpdate(
    ToolkitComponent Component,
    ToolkitComponentState State,
    string Message);

public sealed class ToolkitLaunchException : Exception
{
    public ToolkitLaunchException(
        ToolkitComponent component,
        string phase,
        Exception innerException)
        : base(
            $"{ToolkitComponentNames.Get(component)} failed during {phase}: " +
            ToolkitDiagnostics.Sanitize(innerException.Message),
            innerException)
    {
        Component = component;
        Phase = phase;
    }

    public ToolkitComponent Component { get; }

    public string Phase { get; }
}

public static class ToolkitComponentNames
{
    public static string Get(ToolkitComponent component) => component switch
    {
        ToolkitComponent.Debugger => "Debugger",
        ToolkitComponent.NativeBridge => "Native bridge",
        ToolkitComponent.McpServer => "MCP server",
        ToolkitComponent.GhidraBridge => "Ghidra bridge",
        ToolkitComponent.Toolkit => "Toolkit",
        _ => component.ToString()
    };
}

public static class ToolkitDiagnostics
{
    private const int MaxMessageCharacters = 2_048;
    private static readonly Regex BearerPattern = new(
        @"(?i)(bearer\s+)[^\s,;]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex TokenPattern = new(
        @"(?i)((?:auth(?:token)?|token)\s*[""']?\s*[:=]\s*[""']?)[A-Za-z0-9._~+/=-]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex WindowsPathPattern = new(
        @"(?:(?:[A-Za-z]:[\\/])|(?:\\\\))[^,\s;""']+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string Describe(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        var message = exception is ToolkitLaunchException launch
            ? launch.Message
            : $"{exception.GetType().Name}: {exception.Message}";
        if (exception is ToolkitLaunchException { InnerException: { } inner })
            message += $"\r\nCause: {inner.GetType().Name}: {inner.Message}";
        return Sanitize(message);
    }

    public static string Sanitize(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return "No error details were provided.";

        var sanitized = BearerPattern.Replace(message, "$1<redacted>");
        sanitized = TokenPattern.Replace(sanitized, "$1<redacted>");
        sanitized = WindowsPathPattern.Replace(sanitized, "<redacted-path>");
        sanitized = sanitized.Replace("AuthToken", "<redacted-auth-token>", StringComparison.OrdinalIgnoreCase);
        return sanitized.Length <= MaxMessageCharacters
            ? sanitized
            : TruncatePreservingUnicode(sanitized, MaxMessageCharacters) + "…";
    }

    private static string TruncatePreservingUnicode(string value, int maxCharacters)
    {
        var prefixLength = maxCharacters;
        if (prefixLength > 0 && char.IsHighSurrogate(value[prefixLength - 1]))
            prefixLength--;
        if (prefixLength > 0 && prefixLength < value.Length && char.IsLowSurrogate(value[prefixLength]))
            prefixLength--;
        return value[..prefixLength];
    }
}
