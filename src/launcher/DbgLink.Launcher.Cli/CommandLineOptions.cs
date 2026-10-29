using System.Globalization;
using DbgLink.Launcher.Core;

namespace DbgLink.Launcher.Cli;

internal sealed record CommandLineOptions(
    string? X64DbgPath,
    string? X32DbgPath,
    string? GhidraHome,
    string? BundleRoot,
    string? InputFile,
    string? ShutdownFile,
    int Port,
    bool Install,
    bool AllowAnnotation,
    bool AllowMutation,
    bool Json,
    bool Relaxed,
    bool ClearCache,
    bool Help)
{
    public static CommandLineOptions Parse(string[] args)
    {
        string? x64 = null, x32 = null, ghidra = null, bundle = null, input = null, shutdownFile = null;
        var port = LauncherDefaults.DefaultPort;
        var install = true;
        var annotation = true;
        var mutation = true;
        var json = true;
        var relaxed = false;
        var clearCache = false;
        var help = false;

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            var separator = argument.IndexOf('=');
            var option = separator > 0 ? argument[..separator] : argument;
            var inlineValue = separator > 0 ? argument[(separator + 1)..] : null;
            switch (option.ToLowerInvariant())
            {
                case "--x64dbg": x64 = Value(args, ref index, option, inlineValue); break;
                case "--x32dbg": x32 = Value(args, ref index, option, inlineValue); break;
                case "--ghidra-home": ghidra = Value(args, ref index, option, inlineValue); break;
                case "--bundle-root": bundle = Value(args, ref index, option, inlineValue); break;
                case "--input": input = Value(args, ref index, option, inlineValue); break;
                case "--shutdown-file": shutdownFile = Value(args, ref index, option, inlineValue); break;
                case "--port":
                    if (!int.TryParse(
                            Value(args, ref index, option, inlineValue),
                            NumberStyles.None,
                            CultureInfo.InvariantCulture,
                            out port) ||
                        port is < 1 or > 65_535)
                        throw new ArgumentException("--port must be between 1 and 65535.");
                    break;
                case "--no-install": install = FlagValue(option, inlineValue, false); break;
                case "--allow-annotation": annotation = FlagValue(option, inlineValue, true); break;
                case "--allow-mutation": mutation = FlagValue(option, inlineValue, true); break;
                case "--text": json = FlagValue(option, inlineValue, false); break;
                case "--json": json = FlagValue(option, inlineValue, true); break;
                case "--relaxed": relaxed = FlagValue(option, inlineValue, true); break;
                case "--clear-cache": clearCache = FlagValue(option, inlineValue, true); break;
                case "--help":
                case "-h":
                case "/?":
                    if (inlineValue is not null)
                        throw new ArgumentException($"{option} does not accept a value.");
                    help = true;
                    break;
                default: throw new ArgumentException($"Unknown argument: {argument}");
            }
        }

        return new(x64, x32, ghidra, bundle, input, shutdownFile, port, install, annotation, mutation, json, relaxed, clearCache, help);
    }

    private static string Value(string[] args, ref int index, string option, string? inlineValue)
    {
        if (inlineValue is not null)
        {
            if (string.IsNullOrWhiteSpace(inlineValue))
                throw new ArgumentException($"{option} requires a value.");
            return inlineValue;
        }

        if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]) ||
            (args[index].StartsWith("-", StringComparison.Ordinal) && !Path.IsPathFullyQualified(args[index])))
            throw new ArgumentException($"{option} requires a value.");
        return args[index];
    }

    private static bool FlagValue(string option, string? inlineValue, bool value)
    {
        if (inlineValue is not null)
            throw new ArgumentException($"{option} does not accept a value.");
        return value;
    }
}
