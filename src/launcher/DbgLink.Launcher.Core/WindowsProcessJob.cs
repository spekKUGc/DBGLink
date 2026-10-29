using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Owns launcher-created processes and terminates the remaining tree when the
/// launcher exits. This is intentionally Windows-only because the GUI is
/// Windows-only.
/// </summary>
public sealed class WindowsProcessJob : IDisposable
{
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private IntPtr _handle;

    private WindowsProcessJob(IntPtr handle) => _handle = handle;

    public static WindowsProcessJob Create()
    {
        var handle = CreateJobObjectW(IntPtr.Zero, null);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the launcher process job.");

        try
        {
            var limits = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitKillOnJobClose
                }
            };
            if (!SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformationClass,
                    ref limits,
                    (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not configure launcher process cleanup.");
            }

            return new WindowsProcessJob(handle);
        }
        catch
        {
            CloseHandle(handle);
            throw;
        }
    }

    public void Assign(Process process)
    {
        ObjectDisposedException.ThrowIf(_handle == IntPtr.Zero, this);
        ArgumentNullException.ThrowIfNull(process);

        if (process.HasExited)
            throw new InvalidOperationException($"Process {process.Id} exited before it could be contained.");

        if (!AssignProcessToJobObject(_handle, process.Handle))
        {
            var exception = new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not contain process {process.Id} in the launcher job.");
            // The process was created by the launcher but is not protected by
            // the job when assignment fails. Do not leave that process behind
            // if the caller's normal cleanup only closes the Process wrapper.
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // Preserve the assignment failure; the coordinator will make
                // a second cleanup attempt while handling the launch error.
            }
            throw exception;
        }
    }

    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (handle != IntPtr.Zero)
            CloseHandle(handle);
        GC.SuppressFinalize(this);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        uint informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}
