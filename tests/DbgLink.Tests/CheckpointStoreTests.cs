using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class CheckpointStoreTests
{
    private const string Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void Load_rejects_checkpoint_text_with_control_characters()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(path, CreateCheckpointJson(Sha256, title: "title\u0001"));

            Assert.Throws<JsonException>(() => new CheckpointStore(path).Load(Sha256));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public void Load_rejects_checkpoint_text_that_exceeds_field_budget()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(path, CreateCheckpointJson(Sha256, title: new string('t', 257)));

            Assert.Throws<JsonException>(() => new CheckpointStore(path).Load(Sha256));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public void Load_rejects_duplicate_properties()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(
                path,
                "{\"Version\":2,\"Checkpoints\":{\"" + Sha256 + "\":{\"Sha256\":\"" + Sha256
                + "\",\"Title\":\"title\",\"Findings\":\"findings\",\"Findings\":\"other\","
                + "\"Hypotheses\":\"hypotheses\",\"Verified\":\"verified\",\"NextStep\":\"next\","
                + "\"Context\":\"context\",\"LiveValues\":\"\",\"CreatedAtUtc\":\"2026-08-31T00:00:00Z\",\"AnalysisId\":null}}}");

            Assert.Throws<JsonException>(() => new CheckpointStore(path).Load(Sha256));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public void Load_rejects_a_checkpoint_larger_than_the_byte_limit()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(path, new string('x', 256 * 1024 + 1), Encoding.UTF8);

            Assert.Throws<JsonException>(() => new CheckpointStore(path).Load(Sha256));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public void Save_rejects_a_checkpoint_larger_than_the_byte_limit_before_replacing_existing_file()
    {
        var path = CreateTemporaryPath();
        try
        {
            var store = new CheckpointStore(path);
            var existing = new McpCheckpoint(
                Sha256,
                "title",
                "existing",
                "hypotheses",
                "verified",
                "next",
                "context",
                string.Empty,
                DateTimeOffset.UtcNow,
                null);
            store.Save(existing);

            var oversized = existing with { Context = new string('\uD83D', 70_000) };

            Assert.Throws<IOException>(() => store.Save(oversized));
            var loaded = store.Load(Sha256);
            Assert.NotNull(loaded);
            Assert.Equal("existing", loaded!.Findings);
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public async Task Separate_store_instances_preserve_checkpoints_for_each_binary()
    {
        var path = CreateTemporaryPath();
        const string firstSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string secondSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        try
        {
            var firstStore = new CheckpointStore(path);
            var secondStore = new CheckpointStore(path);
            await Task.WhenAll(
                Task.Run(() => firstStore.Save(new McpCheckpoint(
                    firstSha256,
                    "first",
                    "finding first",
                    "hypothesis first",
                    "verified first",
                    "step first",
                    "context first",
                    "CIP=0x1000",
                    DateTimeOffset.UtcNow,
                    null))),
                Task.Run(() => secondStore.Save(new McpCheckpoint(
                    secondSha256,
                    "second",
                    "finding second",
                    "hypothesis second",
                    "verified second",
                    "step second",
                    "context second",
                    "CIP=0x2000",
                    DateTimeOffset.UtcNow.AddSeconds(1),
                    null))));

            var store = new CheckpointStore(path);
            var first = store.Load(firstSha256);
            var second = store.Load(secondSha256);

            Assert.NotNull(first);
            Assert.NotNull(second);
            Assert.Equal("finding first", first!.Findings);
            Assert.Equal("hypothesis first", first.Hypotheses);
            Assert.Equal("verified first", first.Verified);
            Assert.Equal("step first", first.NextStep);
            Assert.Equal("CIP=0x1000", first.LiveValues);
            Assert.Equal("finding second", second!.Findings);
            Assert.Equal(new[] { firstSha256, secondSha256 }, store.ListSha256());
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public void Load_rejects_a_flat_checkpoint_document()
    {
        var path = CreateTemporaryPath();
        try
        {
            File.WriteAllText(
                path,
                "{\"title\":\"not an index\",\"findings\":\"not an index\",\"nextStep\":\"not an index\"}");

            Assert.Throws<JsonException>(() => new CheckpointStore(path).Load(Sha256));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public async Task Restore_exposes_structured_handoff_and_marks_live_values_for_revalidation()
    {
        var path = CreateTemporaryPath();
        const string sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        try
        {
            var store = new CheckpointStore(path);
            var tools = new CheckpointTools(store);
            var arguments = JsonSerializer.SerializeToElement(new
            {
                sha256,
                findings = "finding",
                hypotheses = "hypothesis",
                verified = "verified",
                nextStep = "step",
                liveValues = "RAX=0x10",
                context = "module context"
            });

            using var saveResponse = JsonDocument.Parse(await tools.CreateCheckpointAsync(arguments, "session"));
            Assert.True(saveResponse.RootElement.GetProperty("result").GetProperty("saved").GetBoolean());

            var loadArguments = JsonSerializer.SerializeToElement(new { sha256 });
            using var loadResponse = JsonDocument.Parse(await tools.GetLastCheckpointAsync(loadArguments));
            var checkpoint = loadResponse.RootElement.GetProperty("result").GetProperty("checkpoint");

            Assert.Equal(sha256, checkpoint.GetProperty("sha256").GetString());
            Assert.Equal("finding", checkpoint.GetProperty("findings").GetString());
            Assert.Equal("hypothesis", checkpoint.GetProperty("hypotheses").GetString());
            Assert.Equal("verified", checkpoint.GetProperty("verified").GetString());
            Assert.Equal("step", checkpoint.GetProperty("nextStep").GetString());
            Assert.True(checkpoint.GetProperty("liveValuesRequireRevalidation").GetBoolean());
            Assert.False(checkpoint.TryGetProperty("liveValuesStatus", out _));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public async Task CreateCheckpoint_without_sha256_resolves_from_the_session_store()
    {
        var path = CreateTemporaryPath();
        try
        {
            var store = new CheckpointStore(path);
            var tools = new CheckpointTools(store);
            var sha = new string('a', 64);
            var seeded = await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = sha,
                title = "t",
                findings = "f",
                hypotheses = "h",
                verified = "v",
                nextStep = "n",
            }), "session-a");
            Assert.Contains("\"saved\":true", seeded);

            // Omitted sha256 resolves via the session's earlier save.
            var resolved = await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                title = "t2",
                findings = "f2",
                hypotheses = "h2",
                verified = "v2",
                nextStep = "n2",
            }), "session-a");
            Assert.Contains("\"saved\":true", resolved);
            Assert.Contains(sha, resolved);

            // Unknown sessions (and a missing analysisId) still fail closed.
            var unknownArgs = JsonSerializer.SerializeToElement(new
            {
                title = "t3",
                findings = "f3",
                hypotheses = "h3",
                verified = "v3",
                nextStep = "n3",
            });
            Assert.Contains("checkpoint_invalid", await tools.CreateCheckpointAsync(unknownArgs, "session-unknown"));
            Assert.Contains("checkpoint_invalid", await tools.CreateCheckpointAsync(unknownArgs, null));
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public async Task CreateCheckpoint_explicit_sha256_wins_over_session_resolution()
    {
        var path = CreateTemporaryPath();
        try
        {
            var store = new CheckpointStore(path);
            var tools = new CheckpointTools(store);
            var firstSha = new string('b', 64);
            var secondSha = new string('c', 64);
            await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = firstSha,
                title = "t",
                findings = "first findings",
                hypotheses = "h",
                verified = "v",
                nextStep = "n",
            }), "session-a");

            var saved = await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = secondSha,
                title = "t2",
                findings = "second findings",
                hypotheses = "h2",
                verified = "v2",
                nextStep = "n2",
            }), "session-a");
            Assert.Contains("\"saved\":true", saved);
            Assert.Contains(secondSha, saved);

            var loaded = await tools.GetLastCheckpointAsync(
                JsonSerializer.SerializeToElement(new { sha256 = secondSha }));
            Assert.Contains("second findings", loaded);
            var kept = await tools.GetLastCheckpointAsync(
                JsonSerializer.SerializeToElement(new { sha256 = firstSha }));
            Assert.Contains("first findings", kept);
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    [Fact]
    public async Task CreateCheckpoint_present_but_invalid_sha256_is_rejected()
    {
        var path = CreateTemporaryPath();
        try
        {
            var store = new CheckpointStore(path);
            var tools = new CheckpointTools(store);
            var sha = new string('d', 64);
            await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = sha,
                title = "t",
                findings = "f",
                hypotheses = "h",
                verified = "v",
                nextStep = "n",
            }), "session-a");

            // A present-but-malformed hash is never papered over by resolution.
            var rejected = await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = new string('z', 64),
                title = "t2",
                findings = "f2",
                hypotheses = "h2",
                verified = "v2",
                nextStep = "n2",
            }), "session-a");
            Assert.Contains("checkpoint_invalid", rejected);
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

    private static string CreateCheckpointJson(string sha256, string title)
    {
        return JsonSerializer.Serialize(new
        {
            Version = 2,
            Checkpoints = new Dictionary<string, object>
            {
                [sha256] = new
                {
                    Sha256 = sha256,
                    Title = title,
                    Findings = "findings",
                    Hypotheses = "hypotheses",
                    Verified = "verified",
                    NextStep = "next",
                    Context = "context",
                    LiveValues = string.Empty,
                    CreatedAtUtc = "2026-08-31T00:00:00Z",
                    AnalysisId = (string?)null
                }
            }
        });
    }

    private static string CreateTemporaryPath()
    {
        var directory = Path.Combine(Path.GetTempPath(), "dbglink-checkpoint-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, "checkpoint.json");
    }

    private static void DeleteTemporaryFile(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory is not null && Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }

    [Fact]
    public async Task Checkpoint_FullAndSummary_CarryAgeLifecycle()
    {
        var path = CreateTemporaryPath();
        try
        {
            var sha = new string('b', 64);
            var tools = new CheckpointTools(new CheckpointStore(path));
            await tools.CreateCheckpointAsync(JsonSerializer.SerializeToElement(new
            {
                sha256 = sha,
                title = "t",
                findings = "f",
                hypotheses = "h",
                verified = "v",
                nextStep = "n",
            }), null);
            var full = JsonNode.Parse(await tools.GetLastCheckpointAsync(
                JsonSerializer.SerializeToElement(new { sha256 = sha })))!;
            var checkpoint = full["result"]!["checkpoint"]!;
            Assert.Equal(0, checkpoint["ageDays"]!.GetValue<int>());
            Assert.False(checkpoint["stale"]!.GetValue<bool>());
            var summary = JsonNode.Parse(await tools.GetLastCheckpointAsync(
                JsonSerializer.SerializeToElement(new { sha256 = sha, fields = "summary" })))!;
            Assert.Equal(0, summary["result"]!["checkpoint"]!["ageDays"]!.GetValue<int>());
            Assert.False(summary["result"]!["checkpoint"]!["stale"]!.GetValue<bool>());
        }
        finally
        {
            DeleteTemporaryFile(path);
        }
    }

}
