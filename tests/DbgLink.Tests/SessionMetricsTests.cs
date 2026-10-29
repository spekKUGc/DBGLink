using System.Text.Json;
using DbgLink.Launcher.Core;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class SessionMetricsTests
{
    [Fact]
    public void History_keeps_identical_fast_calls_and_failures_across_pages()
    {
        var metrics = new ServerMetrics();
        for (var index = 0; index < 40; index++)
        {
            using var operation = metrics.BeginTool("InspectFunction");
            operation.Complete(failed: index % 2 == 0);
        }
        var events = new List<SessionActivitySnapshot>();
        long cursor = 0;
        while (true)
        {
            using var document = JsonDocument.Parse(metrics.Snapshot(cursor).ToJsonString());
            Assert.True(SessionMetricsClient.TryParse(document.RootElement, out var snapshot));
            if (snapshot!.ActivityHistory.Count == 0) break;
            events.AddRange(snapshot.ActivityHistory);
            cursor = events[^1].Sequence;
        }
        Assert.Equal(80, events.Count);
        Assert.Equal(Enumerable.Range(1, 80).Select(value => (long)value), events.Select(item => item.Sequence));
        Assert.Equal(40, events.Select(item => item.OperationId).Distinct().Count());
        Assert.Equal(20, events.Count(item => item.State == "failed"));
        Assert.Equal(20, events.Count(item => item.State == "completed"));
        Assert.All(events.GroupBy(item => item.OperationId), group => Assert.Equal("running", group.First().State));
    }

    [Fact]
    public void History_records_disposal_failure_once_and_starts_empty_in_a_new_session()
    {
        var metrics = new ServerMetrics();
        var operation = metrics.BeginTool("InspectFunction");
        operation.Dispose();
        operation.Dispose();
        Assert.Equal(2, metrics.Snapshot()["activityHistory"]!.AsArray().Count);
        Assert.Equal("failed", metrics.Snapshot()["activityHistory"]![1]!["state"]!.GetValue<string>());
        Assert.Empty(new ServerMetrics().Snapshot()["activityHistory"]!.AsArray());
    }

    [Fact]
    public void History_rejects_duplicate_sequence_numbers()
    {
        var metrics = new ServerMetrics();
        using var operation = metrics.BeginTool("InspectFunction");
        operation.Complete();
        var json = metrics.Snapshot();
        json["activityHistory"]![1]!["sequence"] = 1;
        using var document = JsonDocument.Parse(json.ToJsonString());
        Assert.False(SessionMetricsClient.TryParse(document.RootElement, out _));
    }

    [Fact]
    public void ReadBoundedBytes_rejects_a_stream_over_the_limit()
    {
        using var stream = new MemoryStream(new byte[10]);

        Assert.Null(SessionMetricsClient.ReadBoundedBytes(stream, 9));
    }

    [Fact]
    public void ReadBoundedBytes_returns_the_complete_stream_when_within_the_limit()
    {
        using var stream = new MemoryStream([1, 2, 3]);

        Assert.Equal(new byte[] { 1, 2, 3 }, SessionMetricsClient.ReadBoundedBytes(stream, 3));
    }

    [Fact]
    public async Task ReadBoundedBytesAsync_rejects_a_stream_over_the_limit_without_buffering_it_all()
    {
        await using var stream = new MemoryStream(new byte[10]);

        Assert.Null(await SessionMetricsClient.ReadBoundedBytesAsync(stream, 9, CancellationToken.None));
    }

    [Fact]
    public async Task ReadBoundedBytesAsync_returns_the_complete_stream_when_within_the_limit()
    {
        await using var stream = new MemoryStream([1, 2, 3]);

        Assert.Equal(
            new byte[] { 1, 2, 3 },
            await SessionMetricsClient.ReadBoundedBytesAsync(stream, 3, CancellationToken.None));
    }

    [Fact]
    public void TryParse_accepts_the_current_metrics_schema_without_sessions()
    {
        using var document = JsonDocument.Parse(
            "{\"schemaVersion\":2,\"httpRequests\":1,\"roundTrips\":2,\"toolCalls\":1,\"bytesReceived\":3,\"bytesSent\":4,\"uptimeSeconds\":5}");

        Assert.True(SessionMetricsClient.TryParse(document.RootElement, out var snapshot));
        Assert.NotNull(snapshot);
        Assert.Equal(2, snapshot!.RoundTrips);
    }

    [Fact]
    public void TryParse_rejects_duplicate_properties()
    {
        using var document = JsonDocument.Parse(
            "{\"schemaVersion\":2,\"httpRequests\":1,\"httpRequests\":2,\"roundTrips\":0,\"toolCalls\":0,\"bytesReceived\":0,\"bytesSent\":0,\"uptimeSeconds\":0}");

        Assert.False(SessionMetricsClient.TryParse(document.RootElement, out var snapshot));
        Assert.Null(snapshot);
    }

    [Fact]
    public void TryReadToken_rejects_duplicate_or_non_object_config_json()
    {
        using var duplicate = JsonDocument.Parse(
            "{\"AuthToken\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"AuthToken\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}");
        using var scalar = JsonDocument.Parse("[]");

        Assert.Null(SessionMetricsClient.TryReadToken(duplicate.RootElement));
        Assert.Null(SessionMetricsClient.TryReadToken(scalar.RootElement));
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=invalid")]
    public void Bearer_token_validation_rejects_invalid_token68_values(string token)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new { AuthToken = token }));

        Assert.Null(SessionMetricsClient.TryReadToken(document.RootElement));
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+/==")]
    public void Bearer_token_validation_accepts_token68_values(string token)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new { AuthToken = token }));

        Assert.Equal(token, SessionMetricsClient.TryReadToken(document.RootElement));
    }
}
