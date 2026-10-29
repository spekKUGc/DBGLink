using System.Text.Json;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Proof for the checkpoint empty-overwrite bug: a CreateCheckpoint call with
/// empty findings/hypotheses/verified passed validation and silently erased a
/// previously saved good handoff for the same SHA-256.
/// </summary>
public sealed class CheckpointOverwriteTests
{
    private static string NewStorePath(TempDir dir)
        => Path.Combine(dir, "checkpoint.json");

    private static JsonElement Args(string sha, string findings, string hypotheses, string verified)
        => JsonSerializer.SerializeToElement(new
        {
            sha256 = sha,
            title = "t",
            findings,
            hypotheses,
            verified,
            nextStep = "do the next thing",
        });

    private static string TextOf(string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True,
            $"expected ok envelope, got: {raw}");
        return root.GetProperty("result").GetRawText();
    }

    [Fact]
    public async Task EmptyFindings_DoNotEraseSavedCheckpoint()
    {
        var sha = new string('c', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        TextOf(await tools.CreateCheckpointAsync(
            Args(sha, "real findings", "real hypotheses", "real verified"), null));

        var rejected = await tools.CreateCheckpointAsync(Args(sha, "", "", ""), null);
        Assert.Contains("checkpoint_invalid", rejected);

        var loaded = TextOf(await tools.GetLastCheckpointAsync(
            JsonSerializer.SerializeToElement(new { sha256 = sha })));
        Assert.Contains("real findings", loaded);
    }

    [Fact]
    public async Task WhitespaceFindings_AreRejected()
    {
        var sha = new string('d', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        var rejected = await tools.CreateCheckpointAsync(Args(sha, "   ", "\t", "\n"), null);
        Assert.Contains("checkpoint_invalid", rejected);
    }

    [Fact]
    public async Task FullOverwrite_WithContent_StillWorks()
    {
        var sha = new string('e', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        TextOf(await tools.CreateCheckpointAsync(Args(sha, "v1 findings", "v1 hyp", "v1 ver"), null));
        TextOf(await tools.CreateCheckpointAsync(Args(sha, "v2 findings", "v2 hyp", "v2 ver"), null));
        var loaded = TextOf(await tools.GetLastCheckpointAsync(
            JsonSerializer.SerializeToElement(new { sha256 = sha })));
        Assert.Contains("v2 findings", loaded);
        Assert.DoesNotContain("v1 findings", loaded);
    }

    [Fact]
    public async Task BlankTitle_IsRejected()
    {
        // Kills the L51 || -> && mutant: a present-but-blank title must be
        // rejected (TryReadString succeeds, IsNullOrWhiteSpace holds; only
        // || rejects, && would let it through).
        var sha = new string('f', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        var args = JsonSerializer.SerializeToElement(new
        {
            sha256 = sha,
            title = "   ",
            findings = "real findings",
            hypotheses = "real hypotheses",
            verified = "real verified",
            nextStep = "do the next thing",
        });
        var rejected = await tools.CreateCheckpointAsync(args, null);
        Assert.Contains("checkpoint_invalid", rejected);
    }

    [Fact]
    public async Task NonHexSha_IsRejected()
    {
        // Kills the TryReadRequiredSha256 && -> || mutant: a 64-char
        // non-hex sha passes the object+string checks but fails Normalize;
        // only && rejects, || would let it through to LoadSnapshot.
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        var rejected = await tools.GetLastCheckpointAsync(
            JsonSerializer.SerializeToElement(new { sha256 = new string('z', 64) }));
        Assert.Contains("checkpoint_invalid", rejected);
    }

    [Fact]
    public async Task CorruptStoreFile_SaveReturnsUnavailable()
    {
        // Covers the Save exception filter (L85): a corrupt checkpoint file
        // makes ReadDocument throw JsonException inside Save.
        using var dir = TempDir.Create("dbglink-chkpt-");
        var path = NewStorePath(dir);
        await File.WriteAllTextAsync(path, "not-json{{{");
        var tools = new CheckpointTools(new CheckpointStore(path));
        var sha = new string('c', 64);
        var result = await tools.CreateCheckpointAsync(
            Args(sha, "findings", "hypotheses", "verified"), null);
        Assert.Contains("checkpoint_unavailable", result);
    }

    [Fact]
    public async Task CorruptStoreFile_LoadReturnsUnavailable()
    {
        // Covers the LoadSnapshot exception filter (L105).
        using var dir = TempDir.Create("dbglink-chkpt-");
        var path = NewStorePath(dir);
        await File.WriteAllTextAsync(path, "not-json{{{");
        var tools = new CheckpointTools(new CheckpointStore(path));
        var result = await tools.GetLastCheckpointAsync(
            JsonSerializer.SerializeToElement(new { sha256 = new string('c', 64) }));
        Assert.Contains("checkpoint_unavailable", result);
    }

    [Fact]
    public async Task NonStringOptional_IsRejected()
    {
        // Covers TryReadOptionalString non-string rejection (L166).
        var sha = new string('b', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        var args = JsonSerializer.SerializeToElement(new
        {
            sha256 = sha,
            title = "t",
            findings = "f",
            hypotheses = "h",
            verified = "v",
            nextStep = "n",
            context = 123,
        });
        var rejected = await tools.CreateCheckpointAsync(args, null);
        Assert.Contains("checkpoint_invalid", rejected);
    }

    [Fact]
    public async Task NonStringRequired_IsRejected()
    {
        // Covers TryReadString non-string rejection (L183).
        var sha = new string('a', 64);
        using var dir = TempDir.Create("dbglink-chkpt-");
        var tools = new CheckpointTools(new CheckpointStore(NewStorePath(dir)));
        var args = JsonSerializer.SerializeToElement(new
        {
            sha256 = sha,
            title = "t",
            findings = 123,
            hypotheses = "h",
            verified = "v",
            nextStep = "n",
        });
        var rejected = await tools.CreateCheckpointAsync(args, null);
        Assert.Contains("checkpoint_invalid", rejected);
    }
}
