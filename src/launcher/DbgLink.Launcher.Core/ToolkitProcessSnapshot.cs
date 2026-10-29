using System.Diagnostics;
using System.Runtime.Versioning;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Bounded, path-free process health and private-memory evidence for the launcher soak.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed record ToolkitProcessSnapshot(
    DateTimeOffset TimestampUtc,
    ToolkitProcessMetrics? Debugger,
    ToolkitProcessMetrics? McpServer,
    ToolkitProcessMetrics? Ghidra)
{
    public bool AllStartedProcessesAlive =>
        (Debugger is null || Debugger.IsAlive) &&
        (McpServer is null || McpServer.IsAlive) &&
        (Ghidra is null || Ghidra.IsAlive);

    public long TotalPrivateMemoryBytes =>
        SaturatingAdd(
            SaturatingAdd(
                Math.Max(0, Debugger?.PrivateMemoryBytes ?? 0),
                Math.Max(0, McpServer?.PrivateMemoryBytes ?? 0)),
            Math.Max(0, Ghidra?.PrivateMemoryBytes ?? 0));

    private static long SaturatingAdd(long left, long right)
        => left > long.MaxValue - right ? long.MaxValue : left + right;
}

/// <summary>
/// Process metrics intentionally contain identity and counters only; executable paths are never captured.
/// </summary>
public sealed record ToolkitProcessMetrics(
    ToolkitComponent Component,
    int ProcessId,
    bool IsAlive,
    long PrivateMemoryBytes,
    long WorkingSetBytes);

internal static class ToolkitProcessMetricsReader
{
    public static ToolkitProcessMetrics? Read(ToolkitComponent component, Process? process)
    {
        if (process is null)
            return null;

        try
        {
            process.Refresh();
            var isAlive = !process.HasExited;
            return new(
                component,
                process.Id,
                isAlive,
                isAlive ? Math.Max(0, process.PrivateMemorySize64) : 0,
                isAlive ? Math.Max(0, process.WorkingSet64) : 0);
        }
        catch (InvalidOperationException)
        {
            return new(component, SafeProcessId(process), false, 0, 0);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new(component, SafeProcessId(process), false, 0, 0);
        }
    }

    private static int SafeProcessId(Process process)
    {
        try { return process.Id; }
        catch (InvalidOperationException) { return 0; }
        catch (System.ComponentModel.Win32Exception) { return 0; }
    }
}
