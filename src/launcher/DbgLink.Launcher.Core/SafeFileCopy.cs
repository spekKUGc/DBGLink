using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Copies a file through handles opened without following the final reparse point.
/// </summary>
public static class SafeFileCopy
{
    public static FileStream OpenNonReparseRead(string path)
        => OpenFile(path, GenericRead, FileShareRead, OpenExisting);

    public static FileStream CreateNonReparseDestination(string path, bool overwrite)
        => OpenFile(
            path,
            GenericWrite,
            0,
            overwrite ? CreateAlways : CreateNew);

    public static void Copy(
        string sourcePath,
        string destinationPath,
        long maxBytes,
        bool overwrite)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
            throw new ArgumentException("A source path is required.", nameof(sourcePath));
        if (string.IsNullOrWhiteSpace(destinationPath))
            throw new ArgumentException("A destination path is required.", nameof(destinationPath));
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));

        using var source = OpenFile(
            sourcePath,
            GenericRead,
            FileShareRead,
            OpenExisting);
        var sourceLength = source.Length;
        if (sourceLength < 0 || sourceLength > maxBytes)
            throw new InvalidDataException("The source file exceeds its bounded copy limit.");

        using var destination = OpenFile(
            destinationPath,
            GenericWrite,
            0,
            overwrite ? CreateAlways : CreateNew);
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            var remaining = sourceLength;
            while (remaining > 0)
            {
                var read = source.Read(
                    buffer.AsSpan(0, (int)Math.Min((long)buffer.Length, remaining)));
                if (read == 0)
                    throw new InvalidDataException("The source file changed during the bounded copy.");

                destination.Write(buffer.AsSpan(0, read));
                remaining -= read;
            }

            if (source.ReadByte() != -1)
                throw new InvalidDataException("The source file grew during the bounded copy.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        destination.Flush(flushToDisk: true);
        if (destination.Length != sourceLength)
            throw new InvalidDataException("The bounded file copy was incomplete.");
    }

    private static FileStream OpenFile(
        string path,
        uint desiredAccess,
        uint shareMode,
        uint creationDisposition)
    {
        if (desiredAccess == GenericWrite && creationDisposition == CreateAlways)
        {
            try
            {
                if (File.Exists(path))
                {
                    var attributes = File.GetAttributes(path);
                    if ((attributes & FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
                    }
                }
            }
            catch
            {
            }
        }

        var handle = CreateFileW(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            creationDisposition,
            FileAttributeNormal | FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            var operation = desiredAccess == GenericRead ? "read" : "write";
            var fileName = Path.GetFileName(path);
            throw new Win32Exception(
                error,
                $"Could not {operation} '{fileName}' without following a reparse point (Win32 error {error}).");
        }

        try
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                var error = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    error,
                    $"Could not verify attributes for '{Path.GetFileName(path)}' (Win32 error {error}).");
            }
            if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new InvalidDataException("The file may not be a reparse point.");

            return new FileStream(
                handle,
                desiredAccess == GenericRead ? FileAccess.Read : FileAccess.Write,
                64 * 1024,
                isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private const uint GenericRead = 0x8000_0000;
    private const uint GenericWrite = 0x4000_0000;
    private const uint FileShareRead = 0x0000_0001;
    private const uint CreateNew = 1;
    private const uint CreateAlways = 2;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x0000_0080;
    private const uint FileAttributeReparsePoint = 0x0000_0400;
    private const uint FileFlagOpenReparsePoint = 0x0020_0000;
    private const uint FileFlagSequentialScan = 0x0800_0000;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
