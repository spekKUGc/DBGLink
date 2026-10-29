using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
namespace DbgLink.Launcher.Core;

public static class DebuggerArchitectureDetector
{
    public static DebuggerArchitecture Detect(string path, DebuggerArchitecture fallback)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
            using var reader = new BinaryReader(stream);
            if (reader.ReadUInt16() != 0x5A4D)
                return fallback;

            stream.Position = 0x3C;
            var peOffset = reader.ReadInt32();
            if (peOffset < 0 || peOffset > stream.Length - 6)
                return fallback;

            stream.Position = peOffset;
            if (reader.ReadUInt32() != 0x00004550)
                return fallback;

            return reader.ReadUInt16() switch
            {
                0x014c => DebuggerArchitecture.X86,
                0x8664 => DebuggerArchitecture.X64,
                _ => fallback
            };
        }
        catch (EndOfStreamException)
        {
            return fallback;
        }
        catch (UnauthorizedAccessException)
        {
            return fallback;
        }
        catch (IOException)
        {
            return fallback;
        }
        catch (ArgumentException)
        {
            return fallback;
        }
        catch (NotSupportedException)
        {
            return fallback;
        }
    }
}
