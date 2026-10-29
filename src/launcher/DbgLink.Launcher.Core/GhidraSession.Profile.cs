using System.Buffers;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;
using DbgLink.Shared;

namespace DbgLink.Launcher.Core;

/// <summary>
/// Creates an isolated, bounded Ghidra profile for one launcher session.
/// </summary>
public sealed partial class GhidraSession : IDisposable, IAsyncDisposable
{
    private static DirectoryInfo FindAcceptedProfile(string ghidraHome)
    {
        var applicationProperties = Path.Combine(ghidraHome, "Ghidra", "application.properties");
        EnsureNoReparseAncestors(applicationProperties);
        var version = ReadProperty(applicationProperties, "application.version");
        var appData = Environment.GetEnvironmentVariable("APPDATA");
        if (string.IsNullOrWhiteSpace(appData))
            throw new InvalidOperationException("APPDATA is required to locate the accepted Ghidra profile.");

        var root = Path.Combine(appData, "ghidra");
        var expectedProfilePrefix = "ghidra_" + version;
        var candidates = new List<string>();
        if (Directory.Exists(root))
        {
            var newest = new PriorityQueue<string, DateTime>();
            var scanned = 0;
            foreach (var path in Directory.EnumerateDirectories(root))
            {
                if (scanned++ >= MaxProfileDirectoryEntries)
                    break;

                var preferences = Path.Combine(path, "preferences");
                var frontend = Path.Combine(path, "FrontEndTool.xml");
                if (!Path.GetFileName(path).StartsWith(expectedProfilePrefix, StringComparison.OrdinalIgnoreCase) ||
                    !IsBoundedRegularFile(preferences) ||
                    !IsBoundedRegularFile(frontend) ||
                    !PathSafety.IsReparseFree(path))
                    continue;

                try
                {
                    newest.Enqueue(path, Directory.GetLastWriteTimeUtc(path));
                    if (newest.Count > MaxProfileCandidates)
                        newest.Dequeue();
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (ArgumentException) { }
                catch (NotSupportedException) { }
            }

            candidates.AddRange(newest.UnorderedItems
                .OrderByDescending(item => item.Priority)
                .Select(item => item.Element));
        }

        foreach (var candidate in candidates)
        {
            var preferences = Path.Combine(candidate, "preferences");
            if (File.ReadLines(preferences).Take(10_000).Any(line =>
                line.Equals("USER_AGREEMENT=ACCEPT", StringComparison.Ordinal)))
                return new DirectoryInfo(candidate);
        }

        throw new InvalidOperationException(
            "Accept the Ghidra user agreement once before launching DBGLink.");
    }

    private static string ReadProperty(string path, string key)
    {
        if (!IsBoundedRegularFile(path))
            throw new InvalidDataException("Ghidra application.properties is missing or exceeds its limit.");

        foreach (var line in File.ReadLines(path).Take(2_000))
        {
            if (line.StartsWith(key + "=", StringComparison.Ordinal))
            {
                var value = line[(key.Length + 1)..].Trim();
                if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(char.IsControl))
                    throw new InvalidDataException($"Ghidra application.properties has an invalid {key}.");
                return value;
            }
        }
        throw new InvalidDataException($"Ghidra application.properties has no {key}.");
    }

    private static bool IsBoundedRegularFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists &&
                !info.Attributes.HasFlag(FileAttributes.Directory) &&
                !info.Attributes.HasFlag(FileAttributes.ReparsePoint) &&
                info.Length <= MaxProfileFileBytes &&
                PathSafety.IsReparseFree(path);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static void CopyBoundedFile(string source, string destination)
    {
        var info = new FileInfo(source);
        if (!PathSafety.IsReparseFree(source) || !info.Exists ||
            info.Attributes.HasFlag(FileAttributes.Directory) || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            info.Length > MaxProfileFileBytes)
            throw new InvalidDataException("Ghidra profile file is missing, linked, or exceeds its limit.");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        EnsureNoReparseParents(destination, Path.GetDirectoryName(destination)!);
        SafeFileCopy.Copy(source, destination, MaxProfileFileBytes, overwrite: false);
        EnsureNoReparseParents(destination, Path.GetDirectoryName(destination)!);
    }

    private static void ConfigureFrontend(string path)
    {
        var document = XDocument.Load(path, LoadOptions.PreserveWhitespace);
        var tool = document.Root?.Element("TOOL_CONFIG")?.Element("TOOL")
            ?? throw new InvalidDataException("Ghidra FrontEndTool.xml has an unexpected structure.");
        var root = tool.Element("ROOT_NODE")
            ?? throw new InvalidDataException("Ghidra FrontEndTool.xml has no root node.");

        foreach (var package in tool.Elements("PACKAGE")
            .Where(element => string.Equals((string?)element.Attribute("NAME"), "DBGLink", StringComparison.Ordinal))
            .ToArray())
        {
            package.Remove();
        }

        root.AddBeforeSelf(
            new XElement(
                "PACKAGE",
                new XAttribute("NAME", "DBGLink"),
                new XElement("INCLUDE", new XAttribute("CLASS", FrontendPluginClass))));
        document.Save(path, SaveOptions.DisableFormatting);
    }

    private static void ConfigureKnownExtension(string path)
    {
        var document = XDocument.Load(path, LoadOptions.PreserveWhitespace);
        var tool = document.Root?.Element("TOOL")
            ?? throw new InvalidDataException("Ghidra CodeBrowser config has an unexpected structure.");
        var root = tool.Element("ROOT_NODE")
            ?? throw new InvalidDataException("Ghidra CodeBrowser config has no root node.");
        var extensions = tool.Element("EXTENSIONS");
        if (extensions is null)
        {
            extensions = new XElement("EXTENSIONS");
            root.AddBeforeSelf(extensions);
        }

        if (!extensions.Elements("EXTENSION")
            .Any(element => string.Equals((string?)element.Attribute("NAME"), ExtensionName, StringComparison.OrdinalIgnoreCase)))
        {
            extensions.Add(new XElement("EXTENSION", new XAttribute("NAME", ExtensionName)));
        }
        document.Save(path, SaveOptions.DisableFormatting);
    }

    private static void InstallExtension(string zipPath, string targetDirectory)
    {
        var archiveInfo = new FileInfo(zipPath);
        if (!PathSafety.IsReparseFree(zipPath) || !archiveInfo.Exists ||
            archiveInfo.Attributes.HasFlag(FileAttributes.Directory) ||
            archiveInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            archiveInfo.Length > MaxExtensionArchiveBytes)
            throw new InvalidDataException("Ghidra extension ZIP is missing or too large.");
        EnsureNoReparseAncestors(targetDirectory);

        using var archiveStream = SafeFileCopy.OpenNonReparseRead(zipPath);
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read);
        if (archive.Entries.Count > MaxZipEntries)
            throw new InvalidDataException("Ghidra extension ZIP contains too many entries.");

        var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "extension.properties",
            "Module.manifest",
            "lib/GhidraBridge.jar"
        };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalBytes = 0L;
        const string prefix = "GhidraBridge/";

        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Ghidra extension ZIP contains an unexpected root path.");
            var relative = name[prefix.Length..];
            if (string.IsNullOrWhiteSpace(relative) || name.EndsWith('/'))
                continue;
            if (relative.Contains("..", StringComparison.Ordinal) || relative.StartsWith('/') ||
                relative.Length > 260 || relative.Contains('\0') || relative.Contains(':'))
                throw new InvalidDataException("Ghidra extension ZIP contains an unsafe path.");
            if (!seen.Add(relative))
                throw new InvalidDataException("Ghidra extension ZIP contains a duplicate entry.");
            if (entry.Length < 0 || entry.Length > MaxZipBytes - totalBytes)
                throw new InvalidDataException("Ghidra extension ZIP exceeds the uncompressed byte budget.");
            totalBytes += entry.Length;
            required.Remove(relative);

            var destination = Path.GetFullPath(Path.Combine(targetDirectory, relative.Replace('/', Path.DirectorySeparatorChar)));
            var targetRoot = Path.GetFullPath(targetDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!destination.StartsWith(targetRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Ghidra extension ZIP escaped its installation directory.");
            var destinationDirectory = Path.GetDirectoryName(destination)!;
            EnsureNoReparseParents(destination, targetDirectory);
            Directory.CreateDirectory(destinationDirectory);
            EnsureNoReparseParents(destination, targetDirectory);
            if (File.Exists(destination) && (File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Ghidra extension ZIP targeted a reparse point.");
            using (var sourceStream = entry.Open())
            using (var destinationStream = SafeFileCopy.CreateNonReparseDestination(destination, overwrite: true))
            {
                CopyZipEntryBounded(sourceStream, destinationStream, entry.Length);
                destinationStream.Flush(flushToDisk: true);
                if (destinationStream.Length != entry.Length)
                    throw new InvalidDataException("Ghidra extension ZIP entry was not copied completely.");
            }
        }

        if (required.Count != 0)
            throw new InvalidDataException("Ghidra extension ZIP is missing: " + string.Join(", ", required));
    }

    private static void CopyZipEntryBounded(Stream source, Stream destination, long expectedLength)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            var remaining = expectedLength;
            while (remaining > 0)
            {
                var read = source.Read(
                    buffer.AsSpan(0, (int)Math.Min((long)buffer.Length, remaining)));
                if (read == 0)
                    throw new InvalidDataException("Ghidra extension ZIP entry was truncated during extraction.");

                destination.Write(buffer.AsSpan(0, read));
                remaining -= read;
            }

            if (source.ReadByte() != -1)
                throw new InvalidDataException("Ghidra extension ZIP entry exceeded its declared size.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

}
