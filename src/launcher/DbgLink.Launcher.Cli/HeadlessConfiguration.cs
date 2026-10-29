using System.Buffers;
using System.Text;
using DbgLink.Launcher.Core;
using System.Security.Cryptography;
using DbgLink.Shared;

namespace DbgLink.Launcher.Cli;

internal sealed record HeadlessConfigurationResult(
    LauncherSettings? Settings,
    IReadOnlyList<string> Messages,
    IReadOnlyList<string> Errors)
{
    public bool IsValid => Settings is not null && Errors.Count == 0;
}

internal static class HeadlessConfiguration
{
    private const long MaxInstallFileBytes = 128L * 1024 * 1024;
    private const long MaxJavaReleaseBytes = 2L * 1024 * 1024;
    private const int MaxSearchDirectoriesPerLevel = 512;

    private static readonly string[] BundleRuntimeFileNames =
    [
        "DbgLink.Server.exe",
        "GhidraBridge.zip"
    ];

    private static readonly string[] InstalledRuntimeFileNames =
    [
        "DbgLink.Server.exe"
    ];

    public static HeadlessConfigurationResult Resolve(CommandLineOptions options)
    {
        var messages = new List<string>();
        var errors = new List<string>();
        var x64 = FindDebugger(options.X64DbgPath, "DBGLINK_X64DBG_PATH", "x64dbg.exe", options.Relaxed, @"release\x64\x64dbg.exe", @"x64\x64dbg.exe");
        var x32 = FindDebugger(options.X32DbgPath, "DBGLINK_X32DBG_PATH", "x32dbg.exe", options.Relaxed, @"release\x32\x32dbg.exe", @"x32\x32dbg.exe");
        var ghidra = FindGhidra(options.GhidraHome, options.Relaxed);

        Require(x64, "x64dbg.exe was not found. Pass --x64dbg or set DBGLINK_X64DBG_PATH.", errors);
        Require(x32, "x32dbg.exe was not found. Pass --x32dbg or set DBGLINK_X32DBG_PATH.", errors);
        Require(ghidra, "Ghidra was not found. Pass --ghidra-home or set DBGLINK_GHIDRA_HOME.", errors);
        if (errors.Count != 0)
            return new(null, messages, errors);

        var x64Plugins = Path.Combine(Path.GetDirectoryName(x64!)!, "plugins");
        var x32Plugins = Path.Combine(Path.GetDirectoryName(x32!)!, "plugins");
        if (options.Install)
        {
            var bundle = FindBundle(options.BundleRoot);
            if (bundle is not null)
            {
                InstallBundle(bundle, x64Plugins, x32Plugins);
                messages.Add($"Installed DBGLink bundle from {bundle}.");
            }
            else if (!HasInstalledRuntime(x64Plugins, "DbgLink.dp64") || !HasInstalledRuntime(x32Plugins, "DbgLink.dp32"))
            {
                errors.Add("DBGLink runtime is not installed and a bundle was not found. Run tools\\build.cmd or pass --bundle-root.");
            }
        }

        ValidateRuntime(x64Plugins, "DbgLink.dp64", errors);
        ValidateRuntime(x32Plugins, "DbgLink.dp32", errors);
        var x64ExtensionZip = Path.Combine(x64Plugins, "GhidraBridge.zip");
        var x86ExtensionZip = Path.Combine(x32Plugins, "GhidraBridge.zip");
        if (!IsBoundedRegularFile(x64ExtensionZip, 64L * 1024 * 1024))
            errors.Add($"GhidraBridge.zip was not found in {x64Plugins}.");
        if (!IsBoundedRegularFile(x86ExtensionZip, 64L * 1024 * 1024))
            errors.Add($"GhidraBridge.zip was not found in {x32Plugins}.");

        var javaHome = FindJavaHome(ghidra!, options.Relaxed);
        if (javaHome is not null)
        {
            Environment.SetEnvironmentVariable("JAVA_HOME", javaHome);
            messages.Add($"Using JDK 21 from {javaHome}.");
        }

        if (errors.Count != 0)
            return new(null, messages, errors);

        messages.Add($"Using x64dbg: {x64}");
        messages.Add($"Using x32dbg: {x32}");
        messages.Add($"Using Ghidra: {ghidra}");
        var settings = new LauncherSettings(
            x64!,
            x32!,
            ghidra!,
            string.IsNullOrWhiteSpace(options.InputFile) ? ReverseMode.LetLlmChoose : ReverseMode.ChooseFile,
            options.InputFile,
            options.Port,
            Permissions: new LauncherPermissionProfile(
                AllowGhidraAnnotation: options.AllowAnnotation,
                AllowGhidraMutation: options.AllowMutation,
                Relaxed: options.Relaxed));
        return new(settings, messages, errors);
    }

    private static string? FindDebugger(string? specified, string environmentName, string fileName, bool relaxed, params string[] relativePaths)
    {
        foreach (var candidate in ExplicitCandidates(specified, environmentName))
        {
            var resolved = ExistingFile(candidate, fileName);
            if (resolved is not null)
                return resolved;
        }

        var onPath = ExistingFileOnPath(fileName);
        if (onPath is not null)
            return onPath;

        foreach (var root in SearchRoots(relaxed))
        {
            foreach (var relativePath in relativePaths.Prepend(fileName))
            {
                var resolved = ExistingFile(Path.Combine(root, relativePath), fileName);
                if (resolved is not null)
                    return resolved;
            }
        }
        return null;
    }

    private static string? FindGhidra(string? specified, bool relaxed = false)
    {
        foreach (var candidate in ExplicitCandidates(specified, "DBGLINK_GHIDRA_HOME").Concat(ExplicitCandidates(null, "GHIDRA_INSTALL_DIR")))
        {
            var resolved = ExistingGhidra(candidate);
            if (resolved is not null)
                return resolved;
        }
        return SearchRoots(relaxed).Select(ExistingGhidra).FirstOrDefault(path => path is not null);
    }

    private static string? FindBundle(string? specified)
    {
        var candidates = ExplicitCandidates(specified, "DBGLINK_BUNDLE_ROOT").ToList();
        // Only binary-adjacent locations are trusted implicitly: an ancestor of
        // the caller's own checkout can be the current development tree, but a
        // planted bundle anywhere up the tree must not be picked up silently.
        foreach (var root in Ancestors(AppContext.BaseDirectory))
        {
            candidates.Add(root);
            var artifacts = Path.Combine(root, "artifacts");
            if (Directory.Exists(artifacts))
                candidates.Add(Path.Combine(artifacts, "current"));
        }
        return candidates.Select(NormalizeDirectory).FirstOrDefault(IsBundle);
    }

    private static void InstallBundle(string bundle, string x64Plugins, string x32Plugins)
    {
        VerifyBundleManifest(bundle);
        var installationId = Guid.NewGuid().ToString("N");
        var files = BundleFiles(Path.Combine(bundle, "x64", "plugins"), x64Plugins, "DbgLink.dp64")
            .Concat(BundleFiles(Path.Combine(bundle, "x86", "plugins"), x32Plugins, "DbgLink.dp32"))
            .ToArray();

        foreach (var directory in files.Select(file => Path.GetDirectoryName(file.Target)!).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var existingParent = Directory.Exists(directory) ? directory : Path.GetDirectoryName(directory)!;
            if (!PathSafety.IsReparseFree(existingParent))
                throw new InvalidOperationException("The debugger plugin directories must not contain reparse points.");
            Directory.CreateDirectory(directory);
            if (!PathSafety.IsReparseFree(directory))
                throw new InvalidOperationException("The debugger plugin directories must not contain reparse points.");
        }

        foreach (var file in files)
        {
            var sourceInfo = new FileInfo(file.Source);
            if (!sourceInfo.Exists ||
                sourceInfo.Attributes.HasFlag(FileAttributes.Directory) ||
                sourceInfo.Length > MaxInstallFileBytes ||
                !PathSafety.IsReparseFree(file.Source))
                throw new InvalidOperationException($"The DBGLink bundle file is missing or unsafe: {Path.GetFileName(file.Source)}");
            if (File.Exists(file.Target) && !PathSafety.IsReparseFree(file.Target))
                throw new InvalidOperationException($"The installed DBGLink file is a reparse point: {Path.GetFileName(file.Target)}");
        }

        var changes = files
            .Where(file => !FilesEqual(file.Source, file.Target))
            .Select(file => new InstallChange(
                file.Source,
                file.Target,
                file.Target + ".dbglink-stage-" + installationId,
                file.Target + ".dbglink-backup-" + installationId))
            .ToArray();
        var committed = new List<InstallChange>();
        var installationSucceeded = false;
        try
        {
            foreach (var change in changes)
                SafeFileCopy.Copy(change.Source, change.Stage, MaxInstallFileBytes, overwrite: false);

            foreach (var change in changes)
            {
                if (File.Exists(change.Target))
                    File.Move(change.Target, change.Backup);
                try
                {
                    File.Move(change.Stage, change.Target);
                    committed.Add(change);
                }
                catch
                {
                    if (File.Exists(change.Backup))
                        File.Move(change.Backup, change.Target);
                    throw;
                }
            }
            installationSucceeded = true;
        }
        catch (Exception installationException)
        {
            Exception? rollbackException = null;
            for (var index = committed.Count - 1; index >= 0; index--)
            {
                var change = committed[index];
                try
                {
                    if (File.Exists(change.Target))
                        File.Delete(change.Target);
                    if (File.Exists(change.Backup))
                        File.Move(change.Backup, change.Target);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    rollbackException ??= exception;
                }
            }
            if (rollbackException is not null)
                throw new AggregateException(
                    "DBGLink installation failed and could not be fully rolled back; backup files were preserved.",
                    installationException,
                    rollbackException);
            throw;
        }
        finally
        {
            foreach (var change in changes)
            {
                TryDeleteInstallationArtifact(change.Stage);
                if (installationSucceeded)
                    TryDeleteInstallationArtifact(change.Backup);
            }
        }
    }

    private static void TryDeleteInstallationArtifact(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // B-2/S-3 integrity gate for --install. tools\package.ps1 writes a
    // SHA256SUMS manifest (GNU sha256sum format, '/' separators) covering every
    // file in the staged bundle. It is verified BEFORE anything is copied: a
    // missing, malformed, or mismatching manifest fails closed. This proves
    // integrity against corruption/tamper-in-place, not provenance — a fully
    // attacker-crafted bundle directory ships its own manifest. Bundle
    // *location* trust still comes from the explicit --bundle-root /
    // DBGLINK_BUNDLE_ROOT or the binary-adjacent staged bundle (see FindBundle).
    private static void VerifyBundleManifest(string bundle)
    {
        const long MaxManifestBytes = 1L * 1024 * 1024;
        const int MaxManifestEntries = 8192;
        const int MaxManifestLineChars = 4096;
        var bundleRoot = Path.GetFullPath(bundle);
        var manifestPath = Path.Combine(bundleRoot, "SHA256SUMS");
        if (!IsBoundedRegularFile(manifestPath, MaxManifestBytes))
            throw new InvalidOperationException(
                "The DBGLink bundle has no SHA256SUMS manifest. Rebuild it with tools\\build.cmd or pass --bundle-root to a current staged bundle.");

        string[] lines;
        try
        {
            using var manifestStream = SafeFileCopy.OpenNonReparseRead(manifestPath);
            if (manifestStream.Length > MaxManifestBytes)
                throw new InvalidOperationException("The DBGLink bundle manifest exceeds its byte limit.");
            using var reader = new StreamReader(manifestStream, new UTF8Encoding(false, true), false, 4096);
            lines = reader.ReadToEnd().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            throw new InvalidOperationException("The DBGLink bundle manifest could not be read.", exception);
        }
        if (lines.Length == 0 || lines.Length > MaxManifestEntries)
            throw new InvalidOperationException("The DBGLink bundle manifest is empty or too large.");

        var expected = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            if (line.Length > MaxManifestLineChars)
                throw new InvalidOperationException("The DBGLink bundle manifest contains an oversized entry.");
            var separator = line.IndexOf(' ');
            var hashText = separator < 0 ? string.Empty : line[..separator];
            var relative = separator < 0 ? string.Empty : line[(separator + 1)..].TrimStart(' ', '*');
            if (hashText.Length != 64 || !IsHexString(hashText) || !IsSafeManifestPath(relative))
                throw new InvalidOperationException("The DBGLink bundle manifest is malformed.");
            if (!expected.TryAdd(NormalizeManifestPath(relative), Convert.FromHexString(hashText)))
                throw new InvalidOperationException("The DBGLink bundle manifest lists a file twice.");
        }

        // Both directions: every file on disk must be listed with a matching
        // hash (closes substitution), and every listed file must exist (closes
        // deletion). Added-but-unlisted files therefore fail closed too.
        var onDisk = new HashSet<string>(EnumerateBundleFiles(bundleRoot, MaxManifestEntries), StringComparer.OrdinalIgnoreCase);
        foreach (var file in onDisk)
        {
            if (!expected.TryGetValue(file, out var hash))
                throw new InvalidOperationException($"The DBGLink bundle file is not covered by SHA256SUMS: {file}");
            VerifyManifestEntry(bundleRoot, file, hash);
        }
        foreach (var file in expected.Keys)
        {
            if (!onDisk.Contains(file))
                throw new InvalidOperationException($"The DBGLink bundle manifest lists a missing file: {file}");
        }
    }

    private static void VerifyManifestEntry(string bundleRoot, string relative, byte[] expectedHash)
    {
        string full;
        try
        {
            full = Path.GetFullPath(Path.Combine(bundleRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new InvalidOperationException($"The DBGLink bundle manifest lists an invalid path: {relative}");
        }
        if (!full.StartsWith(bundleRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"The DBGLink bundle manifest escapes the bundle: {relative}");
        if (!IsBoundedRegularFile(full, MaxInstallFileBytes))
            throw new InvalidOperationException($"The DBGLink bundle file is missing or unsafe: {relative}");
        try
        {
            using var stream = SafeFileCopy.OpenNonReparseRead(full);
            if (stream.Length > MaxInstallFileBytes)
                throw new InvalidOperationException($"The DBGLink bundle file exceeds its byte limit: {relative}");
            var actual = HashBounded(stream, stream.Length);
            if (actual is null || !CryptographicOperations.FixedTimeEquals(actual, expectedHash))
                throw new InvalidOperationException($"The DBGLink bundle file failed SHA256 verification: {relative}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException($"The DBGLink bundle file could not be verified: {relative}", exception);
        }
    }

    private static IEnumerable<string> EnumerateBundleFiles(string bundleRoot, int maxFiles)
    {
        var prefix = bundleRoot + Path.DirectorySeparatorChar;
        IEnumerable<string> candidates;
        try
        {
            candidates = Directory.EnumerateFiles(bundleRoot, "*", SearchOption.AllDirectories).Take(maxFiles + 1).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidOperationException("The DBGLink bundle could not be enumerated.", exception);
        }
        var count = 0;
        foreach (var candidate in candidates)
        {
            if (++count > maxFiles)
                throw new InvalidOperationException("The DBGLink bundle contains too many files.");
            if (string.Equals(Path.GetFileName(candidate), "SHA256SUMS", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(Path.GetDirectoryName(candidate), bundleRoot, StringComparison.OrdinalIgnoreCase))
                continue;
            string full;
            try
            {
                full = Path.GetFullPath(candidate);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
            {
                throw new InvalidOperationException("The DBGLink bundle contains an invalid path.");
            }
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The DBGLink bundle enumeration escaped the bundle.");
            yield return full[prefix.Length..].Replace(Path.DirectorySeparatorChar, '/');
        }
    }

    private static bool IsHexString(string value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character))
                return false;
        }
        return true;
    }

    private static bool IsSafeManifestPath(string? relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || relative.Length > 1024)
            return false;
        if (Path.IsPathRooted(relative) || relative.Contains(':') || relative.Contains('\\'))
            return false;
        foreach (var segment in relative.Split('/'))
        {
            if (segment.Length == 0 || segment is "." or "..")
                return false;
        }
        return relative.All(character => !char.IsControl(character));
    }

    private static string NormalizeManifestPath(string relative)
        => relative.Replace('\\', '/');

    private static IEnumerable<BundleFile> BundleFiles(string source, string destination, string pluginName)
    {
        foreach (var name in BundleRuntimeFileNames.Prepend(pluginName))
            yield return new BundleFile(Path.Combine(source, name), Path.Combine(destination, name));
    }

    private static bool FilesEqual(string left, string right)
    {
        var leftInfo = new FileInfo(left);
        var rightInfo = new FileInfo(right);
        if (!leftInfo.Exists || !rightInfo.Exists ||
            leftInfo.Attributes.HasFlag(FileAttributes.Directory) ||
            rightInfo.Attributes.HasFlag(FileAttributes.Directory) ||
            leftInfo.Length > MaxInstallFileBytes ||
            leftInfo.Length != rightInfo.Length)
            return false;

        using var leftStream = SafeFileCopy.OpenNonReparseRead(left);
        using var rightStream = SafeFileCopy.OpenNonReparseRead(right);
        if (leftStream.Length > MaxInstallFileBytes || leftStream.Length != rightStream.Length)
            return false;

        var leftHash = HashBounded(leftStream, leftStream.Length);
        var rightHash = HashBounded(rightStream, rightStream.Length);
        return leftHash is not null && rightHash is not null &&
            CryptographicOperations.FixedTimeEquals(leftHash, rightHash);
    }

    private static byte[]? HashBounded(Stream stream, long expectedLength)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            var remaining = expectedLength;
            while (remaining > 0)
            {
                var read = stream.Read(
                    buffer.AsSpan(0, (int)Math.Min((long)buffer.Length, remaining)));
                if (read == 0)
                    return null;

                hash.AppendData(buffer, 0, read);
                remaining -= read;
            }

            return stream.ReadByte() == -1 ? hash.GetHashAndReset() : null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void ValidateRuntime(string directory, string plugin, ICollection<string> errors)
    {
        if (!HasInstalledRuntime(directory, plugin))
            errors.Add($"{plugin} and the self-contained DbgLink.Server.exe are required in {directory}.");
    }

    private static bool HasInstalledRuntime(string directory, string plugin) =>
        InstalledRuntimeFileNames
            .Prepend(plugin)
            .All(name => IsBoundedRegularFile(Path.Combine(directory, name), MaxInstallFileBytes));

    private static bool IsBoundedRegularFile(string path, long maxBytes)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists &&
                !info.Attributes.HasFlag(FileAttributes.Directory) &&
                !info.Attributes.HasFlag(FileAttributes.ReparsePoint) &&
                info.Length > 0 && info.Length <= maxBytes &&
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

    private static string? FindJavaHome(string ghidraHome, bool relaxed = false)
    {
        var candidates = ExplicitCandidates(null, "JAVA_HOME")
            .Concat(new[] { Path.Combine(ghidraHome, "jdk"), Path.Combine(ghidraHome, "jre") })
            .Concat(new[] { ExistingFileOnPath("java.exe") is { } java
                ? Path.GetDirectoryName(Path.GetDirectoryName(java))
                : null })
            .Concat(ProgramFilesJavaRoots())
            .Concat(SearchRoots(relaxed).Where(path => Path.GetFileName(path).StartsWith("jdk-", StringComparison.OrdinalIgnoreCase)));
        return candidates.Select(NormalizeDirectory).FirstOrDefault(IsJava21);
    }

    private static IEnumerable<string?> ProgramFilesJavaRoots()
    {
        foreach (var variable in new[] { "ProgramFiles", "ProgramFiles(x86)" })
        {
            var root = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(root))
                continue;

            foreach (var javaRoot in new[]
            {
                Path.Combine(root, "Eclipse Adoptium"),
                Path.Combine(root, "Java"),
                Path.Combine(root, "Microsoft")
            })
            {
                foreach (var directory in SafeDirectories(javaRoot, "jdk-*"))
                    yield return directory;
            }
        }
    }

    private static IEnumerable<string> SafeDirectories(string root, string pattern)
    {
        try
        {
            return Directory.Exists(root)
                ? Directory.EnumerateDirectories(root, pattern, SearchOption.TopDirectoryOnly)
                    .Take(MaxSearchDirectoriesPerLevel)
                    .ToArray()
                : Array.Empty<string>();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return Array.Empty<string>();
        }
    }

    private static bool IsJava21(string? path)
    {
        if (path is null || !PathSafety.IsReparseFree(path))
            return false;

        var java = Path.Combine(path, "bin", "java.exe");
        var release = Path.Combine(path, "release");
        if (!File.Exists(java) || !File.Exists(release) ||
            !PathSafety.IsReparseFree(java) || !PathSafety.IsReparseFree(release))
            return false;

        try
        {
            return new FileInfo(release).Length <= MaxJavaReleaseBytes &&
                File.ReadLines(release).Any(line =>
                {
                    if (!line.StartsWith("JAVA_VERSION=\"", StringComparison.Ordinal))
                        return false;
                    var versionStr = line.Substring("JAVA_VERSION=\"".Length);
                    var dotIndex = versionStr.IndexOf('.');
                    var quoteIndex = versionStr.IndexOf('"');
                    var end = dotIndex >= 0 && (quoteIndex < 0 || dotIndex < quoteIndex) ? dotIndex : quoteIndex;
                    return end > 0 && int.TryParse(versionStr.AsSpan(0, end), out var major) && major >= 21;
                });
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    private static IEnumerable<string> SearchRoots(bool relaxed)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Hardened discovery (S-1): only the staged bundle next to the launcher
        // binary and the machine-wide Program Files trees are searched. CWD,
        // %USERPROFILE%, Downloads, Desktop and %LOCALAPPDATA% are never
        // searched — a planted x64dbg.exe or analyzeHeadless.bat there must not
        // be auto-discovered and executed. Anything else requires an explicit
        // flag or *-specific environment variable (fail closed, see Require).
        var searchBases = new[]
        {
            AppContext.BaseDirectory,
            Environment.GetEnvironmentVariable("ProgramFiles"),
            Environment.GetEnvironmentVariable("ProgramFiles(x86)")
        };
        // Relaxed (opt-in): the user asks to run a toolkit that lives in a
        // user-writable location. The same roots that S-1 excludes by default
        // become searchable, but only that set — reparse integrity, the exact
        // executable names and the bundle manifest gate all still apply.
        if (relaxed)
        {
            var profile = Environment.GetEnvironmentVariable("USERPROFILE") ??
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            searchBases = searchBases
                .Concat(UserOwnedSearchBases(profile))
                .ToArray();
        }
        foreach (var searchBase in searchBases)
            AddTree(searchBase);
        return roots;

        // Only %USERPROFILE% itself plus the well-known per-user folders: no
        // recursive walk of the profile tree, so a relaxed run still scans a
        // bounded number of directories.
        static IEnumerable<string> UserOwnedSearchBases(string? profile)
        {
            if (string.IsNullOrWhiteSpace(profile))
                yield break;
            yield return profile;
            foreach (var wellKnown in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                         Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                         Path.Combine(profile, "Downloads"),
                         Path.Combine(profile, "Desktop"),
                         Environment.GetEnvironmentVariable("LOCALAPPDATA"),
                     })
            {
                if (!string.IsNullOrWhiteSpace(wellKnown))
                    yield return wellKnown;
            }
        }

        void AddTree(string? root)
        {
            Add(root);
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                return;

            try
            {
                foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly)
                    .Take(MaxSearchDirectoriesPerLevel))
                {
                    Add(directory);
                    try
                    {
                        foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly)
                            .Take(MaxSearchDirectoriesPerLevel))
                            Add(child);
                    }
                    catch (Exception exception) when (
                        exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
                }
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }

        void Add(string? path)
        {
            var normalized = NormalizeDirectory(path);
            if (normalized is not null)
                roots.Add(normalized);
        }
    }

    private static string? ExistingFileOnPath(string fileName)
    {
        var path = Environment.GetEnvironmentVariable("Path");
        if (string.IsNullOrWhiteSpace(path))
            path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
            return null;

        foreach (var rawDirectory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var directory = rawDirectory.Trim().Trim('"');
            var resolved = ExistingFile(Path.Combine(directory, fileName), fileName);
            if (resolved is not null)
                return resolved;
        }
        return null;
    }

    private static IEnumerable<string> ExplicitCandidates(string? specified, string environmentName)
    {
        if (!string.IsNullOrWhiteSpace(specified)) yield return specified;
        var environment = Environment.GetEnvironmentVariable(environmentName);
        if (!string.IsNullOrWhiteSpace(environment)) yield return environment;
    }

    private static IEnumerable<string> Ancestors(string path)
    {
        for (var directory = new DirectoryInfo(path); directory is not null; directory = directory.Parent)
            yield return directory.FullName;
    }

    private static string? ExistingFile(string? path, string expectedName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            var full = Path.GetFullPath(path);
            return File.Exists(full) && PathSafety.IsReparseFree(full) &&
                Path.GetFileName(full).Equals(expectedName, StringComparison.OrdinalIgnoreCase) ? full : null;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException) { return null; }
    }

    private static string? ExistingGhidra(string? path)
    {
        var full = NormalizeDirectory(path);
        return full is not null && File.Exists(Path.Combine(full, "ghidraRun.bat")) &&
            File.Exists(Path.Combine(full, "Ghidra", "application.properties")) &&
            PathSafety.IsReparseFree(Path.Combine(full, "ghidraRun.bat")) &&
            PathSafety.IsReparseFree(Path.Combine(full, "Ghidra", "application.properties")) ? full : null;
    }

    private static string? NormalizeDirectory(string? path)
    {
        try { return !string.IsNullOrWhiteSpace(path) && Directory.Exists(path) ? Path.GetFullPath(path) : null; }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException) { return null; }
    }

    private static bool IsBundle(string? path)
    {
        if (path is null || !PathSafety.IsReparseFree(path))
            return false;
        return BundleFiles(Path.Combine(path, "x64", "plugins"), string.Empty, "DbgLink.dp64")
            .Concat(BundleFiles(Path.Combine(path, "x86", "plugins"), string.Empty, "DbgLink.dp32"))
            .All(file => IsBoundedRegularFile(
                file.Source,
                file.Source.EndsWith("GhidraBridge.zip", StringComparison.OrdinalIgnoreCase)
                    ? 64L * 1024 * 1024
                    : MaxInstallFileBytes));
    }

    private static void Require(string? value, string message, ICollection<string> errors)
    {
        if (value is null) errors.Add(message);
    }

    private sealed record BundleFile(string Source, string Target);
    private sealed record InstallChange(string Source, string Target, string Stage, string Backup);
}
