using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DbgLink.Shared;

namespace DbgLink.Server;

internal sealed record McpCheckpoint(
    string Sha256,
    string Title,
    string Findings,
    string Hypotheses,
    string Verified,
    string NextStep,
    string Context,
    string LiveValues,
    DateTimeOffset CreatedAtUtc,
    string? AnalysisId);

internal sealed class CheckpointFile
{
    public int Version { get; set; } = 2;

    public Dictionary<string, McpCheckpoint> Checkpoints { get; set; } = new(StringComparer.Ordinal);
}

internal sealed class CheckpointStore
{
    private const int CurrentVersion = 2;
    private const int MaxCheckpointBytes = 256 * 1024;
    private const int MaxTitleLength = 256;
    private const int MaxSectionLength = 32_000;
    private const int MaxContextLength = 64_000;
    private const int MaxLiveValuesLength = 64_000;
    private const int MaxAnalysisIdLength = 128;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _path;
    private readonly string _lockPath;
    private readonly object _sync = new();

    private static int _protectionReported;

    /// <summary>
    /// Shared protection-failure reporter for the checkpoint directory and
    /// files. One-shot per process — Save runs on the hot path. Never throws
    /// (it runs inside the save lock) and never blocks: stderr only, which
    /// is a manual-console diagnostic (an auto-started server has no visible
    /// stderr).
    /// </summary>
    private static void ReportProtection(string reason)
    {
        if (Interlocked.Exchange(ref _protectionReported, 1) == 0)
            Console.Error.WriteLine(
                $"Could not protect local DBGLink checkpoint store ({reason}); continuing with existing permissions.");
    }

    public CheckpointStore(string path)
    {
        var fullPath = System.IO.Path.GetFullPath(path);
        if (fullPath.Length > 32_760)
        {
            throw new ArgumentException("The checkpoint path is too long.", nameof(path));
        }

        if (!DbgLinkConfigPath.IsSafePath(fullPath) || !LocalPathPolicy.IsSafeLocalPath(fullPath))
        {
            throw new ArgumentException("The checkpoint path may not traverse a reparse point.", nameof(path));
        }

        _path = fullPath;
        _lockPath = fullPath + ".lock";
        if (_lockPath.Length > 32_760 || !DbgLinkConfigPath.IsSafePath(_lockPath) || !LocalPathPolicy.IsSafeLocalPath(_lockPath))
        {
            throw new ArgumentException("The checkpoint lock path may not traverse a reparse point.", nameof(path));
        }
    }

    public string Path => _path;

    public void Save(McpCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        lock (_sync)
        {
            EnsureSafePath();

            var normalized = NormalizeCheckpoint(checkpoint, checkpoint.Sha256);
            if (normalized is null)
            {
                throw new IOException("Checkpoint is invalid or exceeds the storage limits.");
            }

            var directory = System.IO.Path.GetDirectoryName(_path);
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new IOException("Checkpoint path must include a directory.");
            }

            Directory.CreateDirectory(directory);
            FileProtection.ProtectDirectory(directory, ReportProtection);
            EnsureSafePath();

            using var fileLock = AcquireFileLock();
            var document = ReadDocument();
            document.Checkpoints[normalized.Sha256] = normalized;

            WriteDocument(document);
        }
    }

    private void WriteDocument(CheckpointFile document)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
        if (json.Length > MaxCheckpointBytes)
        {
            throw new IOException("Checkpoint index exceeds the storage limit.");
        }

        var tempPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       options: FileOptions.WriteThrough))
            {
                stream.Write(json);
                stream.Flush(flushToDisk: true);
            }

            FileProtection.ProtectFile(tempPath, ReportProtection);

            EnsureSafePath();
            File.Move(tempPath, _path, overwrite: true);
            FileProtection.ProtectFile(_path, ReportProtection);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    public McpCheckpoint? Load(string sha256)
        => LoadSnapshot(sha256).Checkpoint;

    /// <summary>
    /// Lifecycle: drop the checkpoint for one SHA-256 (e.g. superseded or
    /// poisoned handoffs). Returns false when nothing was stored.
    /// </summary>
    public bool Delete(string sha256)
    {
        var normalizedSha256 = AddressMapping.NormalizeSha256(sha256);
        if (normalizedSha256 is null)
        {
            return false;
        }

        lock (_sync)
        {
            EnsureSafePath();
            if (!File.Exists(_path))
            {
                return false;
            }

            using var fileLock = AcquireFileLock();
            var document = ReadDocument();
            if (!document.Checkpoints.Remove(normalizedSha256))
            {
                return false;
            }

            WriteDocument(document);
            return true;
        }
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                EnsureSafePath();
                if (!File.Exists(_path))
                {
                    return 0;
                }

                using var fileLock = AcquireFileLock();
                return ReadDocument().Checkpoints.Count;
            }
        }
    }

    internal (McpCheckpoint? Checkpoint, IReadOnlyList<string> AvailableSha256) LoadSnapshot(string sha256)
    {
        var normalizedSha256 = AddressMapping.NormalizeSha256(sha256);
        if (normalizedSha256 is null)
        {
            throw new JsonException("sha256 must be a 64-character hexadecimal SHA-256 digest.");
        }

        lock (_sync)
        {
            EnsureSafePath();
            var directory = System.IO.Path.GetDirectoryName(_path)
                ?? throw new IOException("Checkpoint path must include a directory.");
            if (!Directory.Exists(directory) && !File.Exists(_path))
            {
                return (null, Array.Empty<string>());
            }

            using var fileLock = AcquireFileLock();
            var document = ReadDocument();
            var checkpoint = document.Checkpoints.TryGetValue(normalizedSha256, out var value)
                ? value
                : null;
            return (checkpoint, document.Checkpoints.Keys.Order(StringComparer.Ordinal).ToArray());
        }
    }

    internal IReadOnlyList<string> ListSha256()
    {
        lock (_sync)
        {
            EnsureSafePath();
            var directory = System.IO.Path.GetDirectoryName(_path)
                ?? throw new IOException("Checkpoint path must include a directory.");
            if (!Directory.Exists(directory) && !File.Exists(_path))
            {
                return Array.Empty<string>();
            }

            using var fileLock = AcquireFileLock();
            return ReadDocument().Checkpoints.Keys.Order(StringComparer.Ordinal).ToArray();
        }
    }

    private CheckpointFile ReadDocument()
    {
        if (!File.Exists(_path))
        {
            return new CheckpointFile();
        }

        var json = ReadBoundedText(_path);
        using var parsed = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });

        if (parsed.RootElement.ValueKind != JsonValueKind.Object
            || !TryGetPropertyIgnoreCase(parsed.RootElement, "version", out var versionElement)
            || versionElement.ValueKind != JsonValueKind.Number
            || !TryGetPropertyIgnoreCase(parsed.RootElement, "checkpoints", out var checkpointsElement)
            || checkpointsElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Checkpoint storage must use the version 2 SHA-256 index format.");
        }

        EnsureNoDuplicateProperties(parsed.RootElement);

        var document = JsonSerializer.Deserialize<CheckpointFile>(json, JsonOptions)
            ?? throw new JsonException("Checkpoint storage is empty.");

        if (document.Version != CurrentVersion)
        {
            throw new JsonException($"Unsupported checkpoint storage version: {document.Version}.");
        }

        var normalized = new CheckpointFile();
        foreach (var pair in document.Checkpoints)
        {
            var sha256 = AddressMapping.NormalizeSha256(pair.Key);
            if (sha256 is null)
            {
                throw new JsonException("Checkpoint index contains an invalid SHA-256 key.");
            }

            var checkpoint = NormalizeCheckpoint(pair.Value, sha256);
            if (checkpoint is null)
            {
                throw new JsonException("Checkpoint storage contains an invalid checkpoint.");
            }

            if (!normalized.Checkpoints.TryAdd(sha256, checkpoint))
            {
                throw new JsonException("Checkpoint storage contains duplicate SHA-256 keys.");
            }
        }

        return normalized;
    }

    private static McpCheckpoint? NormalizeCheckpoint(McpCheckpoint? checkpoint, string? expectedSha256)
    {
        if (checkpoint is null)
        {
            return null;
        }

        var sha256 = AddressMapping.NormalizeSha256(expectedSha256);
        var checkpointSha256 = AddressMapping.NormalizeSha256(checkpoint.Sha256);
        if (sha256 is null || checkpointSha256 is null || !StringComparer.Ordinal.Equals(sha256, checkpointSha256))
        {
            return null;
        }

        var normalized = checkpoint with
        {
            Sha256 = sha256,
            Context = checkpoint.Context ?? string.Empty,
            LiveValues = checkpoint.LiveValues ?? string.Empty,
        };

        return IsValidCheckpoint(normalized) ? normalized : null;
    }

    private static bool IsValidCheckpoint(McpCheckpoint checkpoint)
    {
        return AddressMapping.NormalizeSha256(checkpoint.Sha256) is not null
            && IsValidText(checkpoint.Title, MaxTitleLength, required: true)
            && !string.IsNullOrWhiteSpace(checkpoint.Title)
            && IsValidText(checkpoint.Findings, MaxSectionLength, required: true)
            && IsValidText(checkpoint.Hypotheses, MaxSectionLength, required: true)
            && IsValidText(checkpoint.Verified, MaxSectionLength, required: true)
            && IsValidText(checkpoint.NextStep, MaxSectionLength, required: true)
            && !string.IsNullOrWhiteSpace(checkpoint.NextStep)
            && IsValidText(checkpoint.Context, MaxContextLength, required: false)
            && IsValidText(checkpoint.LiveValues, MaxLiveValuesLength, required: false)
            && IsValidAnalysisId(checkpoint.AnalysisId)
            && checkpoint.CreatedAtUtc != default;
    }

    private static bool IsValidAnalysisId(string? value)
    {
        // Null/empty predates session binding: checkpoints are keyed by
        // SHA-256, so only constrain ids when one is present.
        if (string.IsNullOrEmpty(value))
            return true;
        return value.Length <= MaxAnalysisIdLength &&
            AnalysisSessionRegistry.IsValidAnalysisId(value);
    }

    private static bool IsValidText(string? value, int maxLength, bool required)
    {
        if (value is null)
        {
            return !required;
        }

        if (value.Length == 0)
        {
            return true;
        }

        if (value.Length > maxLength)
        {
            return false;
        }

        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsControl(character) && character is not ('\r' or '\n' or '\t'))
            {
                return false;
            }

            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    return false;
                }

                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(property.Name, name))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static void EnsureNoDuplicateProperties(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in element.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        throw new JsonException($"Duplicate JSON property: {property.Name}.");
                    }

                    EnsureNoDuplicateProperties(property.Value);
                }

                break;
            }
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    EnsureNoDuplicateProperties(item);
                }

                break;
        }
    }

    private static string ReadBoundedText(string path)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.SequentialScan);
            if (stream.Length > MaxCheckpointBytes)
            {
                throw new JsonException("Checkpoint storage exceeds the size limit.");
            }

            using var data = new MemoryStream(capacity: (int)stream.Length);
            var buffer = new byte[4096];
            while (true)
            {
                var read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                if (data.Length + read > MaxCheckpointBytes)
                {
                    throw new JsonException("Checkpoint storage exceeds the size limit.");
                }

                data.Write(buffer, 0, read);
            }

            return StrictUtf8.GetString(data.GetBuffer(), 0, checked((int)data.Length));
        }
        catch (DecoderFallbackException exception)
        {
            throw new JsonException("Checkpoint storage is not valid UTF-8.", exception);
        }
    }

    private void EnsureSafePath()
    {
        if (string.IsNullOrWhiteSpace(_path))
        {
            throw new IOException("Checkpoint path is empty.");
        }

        if (!DbgLinkConfigPath.IsSafePath(_path) || !LocalPathPolicy.IsSafeLocalPath(_path))
        {
            throw new IOException("The checkpoint path traverses a reparse point.");
        }

        if (!DbgLinkConfigPath.IsSafePath(_lockPath) || !LocalPathPolicy.IsSafeLocalPath(_lockPath))
        {
            throw new IOException("The checkpoint lock path traverses a reparse point.");
        }
    }

    private FileStream AcquireFileLock()
    {
        const int timeoutMilliseconds = 1_500;
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        var delay = 2;
        while (true)
        {
            try
            {
                // DeleteOnClose: the .lock file is removed when the handle
                // closes, so crashed or completed operations never leave a
                // stale lock file behind (leak P0).
                return new FileStream(
                    _lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    options: FileOptions.WriteThrough | FileOptions.DeleteOnClose);
            }
            catch (IOException ex)
            {
                if (Environment.TickCount64 >= deadline)
                {
                    throw new TimeoutException($"Failed to acquire file lock for '{_lockPath}' within {timeoutMilliseconds}ms.", ex);
                }
                Thread.Sleep(delay);
                delay = Math.Min(25, delay * 2);
            }
        }
    }
}
