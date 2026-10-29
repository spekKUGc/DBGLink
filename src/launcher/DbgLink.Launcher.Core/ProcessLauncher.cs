using System.Diagnostics;
using System.Text;

namespace DbgLink.Launcher.Core;

internal static class ProcessLauncher
{
    public static Process Start(ProcessLaunchSpec spec)
    {
        if (spec.UseShellExecute)
            return StartCommandFile(spec);

        var startInfo = new ProcessStartInfo
        {
            FileName = spec.FileName,
            WorkingDirectory = spec.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Normal,
            RedirectStandardOutput = spec.CaptureOutput,
            RedirectStandardError = spec.CaptureOutput
        };

        foreach (var argument in spec.Arguments)
            startInfo.ArgumentList.Add(argument);

        if (spec.RemoveEnvironmentVariables is not null)
            foreach (var name in spec.RemoveEnvironmentVariables)
                startInfo.Environment.Remove(name);
        foreach (var pair in spec.EnvironmentVariables)
            startInfo.Environment[pair.Key] = pair.Value;
        return StartCore(startInfo);
    }

    private static Process StartCommandFile(ProcessLaunchSpec spec)
    {
        var extension = Path.GetExtension(spec.FileName);
        if (!extension.Equals(".bat", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Shell execution is restricted to validated Windows command files.");
        }

        var commandInterpreter = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = commandInterpreter,
            WorkingDirectory = spec.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = spec.CaptureOutput,
            RedirectStandardError = spec.CaptureOutput
        };
        if (spec.RemoveEnvironmentVariables is not null)
            foreach (var name in spec.RemoveEnvironmentVariables)
                startInfo.Environment.Remove(name);
        foreach (var pair in spec.EnvironmentVariables)
            startInfo.Environment[pair.Key] = pair.Value;
        startInfo.Arguments = "/d /v:off /c " + BuildCommand(spec.FileName, spec.Arguments);
        return StartCore(startInfo);
    }

    private static string BuildCommand(string fileName, IReadOnlyList<string> arguments)
    {
        var command = new StringBuilder();
        AppendCommandArgument(command, fileName);
        foreach (var argument in arguments)
            AppendCommandArgument(command, argument);
        return '"' + command.ToString() + '"';
    }

    private static void AppendCommandArgument(StringBuilder command, string argument)
    {
        if (argument.Length != 0 && !IsCommandArgumentSafe(argument))
            throw new ArgumentException("Command-file paths and arguments may not contain quotes, percent signs, exclamation marks, or control characters.", nameof(argument));

        if (command.Length != 0)
            command.Append(' ');
        command.Append('"').Append(argument).Append('"');
    }

    internal static bool IsCommandArgumentSafe(string value)
        => !string.IsNullOrWhiteSpace(value) && value.IndexOfAny(['\0', '\r', '\n', '"', '%', '!']) < 0;

    private static Process StartCore(ProcessStartInfo startInfo) =>
        Process.Start(startInfo) ??
        throw new InvalidOperationException($"Could not start {Path.GetFileName(startInfo.FileName)}.");
}
