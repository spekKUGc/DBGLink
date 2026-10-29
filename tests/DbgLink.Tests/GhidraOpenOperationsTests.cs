using DbgLink.Server;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Tests;

public sealed class GhidraOpenOperationsTests
{
    private sealed class Control : IGhidraControlClient
    {
        public readonly List<string> Started = new();
        public readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<string> OpenFileAsync(string path, CancellationToken token)
        {
            lock (Started) Started.Add(path);
            await Release.Task.WaitAsync(token);
            return "{\"ok\":true,\"result\":{\"opened\":true}}";
        }
    }
    private static JsonElement Args(string id) => JsonSerializer.SerializeToElement(new { operationId = id });
    private static string Id(string response) => JsonNode.Parse(response)!["result"]!["operationId"]!.GetValue<string>();

    [Fact]
    public async Task Queued_cancellation_does_not_start_or_allow_overtaking()
    {
        var control = new Control();
        var operations = new GhidraOpenOperations(control);
        try
        {
            var first = Id(await operations.BeginGhidraOpenAsync("first.dll"));
            var second = Id(await operations.BeginGhidraOpenAsync("second.dll"));
            var third = Id(await operations.BeginGhidraOpenAsync("third.dll"));
            var queued = JsonNode.Parse(await operations.GetGhidraOpenStatusAsync(Args(third)))!["result"]!;
            Assert.Equal(2, queued["queuePosition"]!.GetValue<int>());
            Assert.Equal("queued", queued["phase"]!.GetValue<string>());
            await operations.CancelAsync(Args(second));
            await Task.Delay(30);
            lock (control.Started) Assert.Equal(new[] { Path.GetFullPath("first.dll") }, control.Started);
            control.Release.SetResult();
            using var timeout = new CancellationTokenSource(3000);
            while ((await operations.GetGhidraOpenStatusAsync(Args(third))).Contains("pending"))
                await Task.Delay(10, timeout.Token);
            lock (control.Started) Assert.Equal(new[] { Path.GetFullPath("first.dll"), Path.GetFullPath("third.dll") }, control.Started);
            Assert.Contains("ghidra_open_cancelled", await operations.GetGhidraOpenStatusAsync(Args(second)));
            var completed = await operations.GetGhidraOpenStatusAsync(Args(first));
            Assert.Equal(completed, await operations.GetGhidraOpenStatusAsync(Args(first)));
        }
        finally { operations.Stop(); }
    }

    [Fact]
    public async Task Active_cancellation_reaches_control()
    {
        var control = new Control();
        var operations = new GhidraOpenOperations(control);
        try
        {
            var id = Id(await operations.BeginGhidraOpenAsync("first.dll"));
            await operations.CancelAsync(Args(id));
            using var timeout = new CancellationTokenSource(3000);
            string result;
            while ((result = await operations.GetGhidraOpenStatusAsync(Args(id))).Contains("pending"))
                await Task.Delay(10, timeout.Token);
            Assert.Contains("ghidra_open_cancelled", result);
            Assert.Empty(operations.Queue());
        }
        finally { operations.Stop(); }
    }

    private sealed class HangingControl : IGhidraControlClient
    {
        public bool ObservedCancellation;
        public async Task<string> OpenFileAsync(string path, CancellationToken token)
        {
            try
            {
                await Task.Delay(Timeout.Infinite, token);
                return "{\"ok\":true,\"result\":{\"opened\":true}}";
            }
            catch (OperationCanceledException)
            {
                ObservedCancellation = true;
                throw;
            }
        }
    }

    private sealed class SlowSuccessControl(int delayMs) : IGhidraControlClient
    {
        public async Task<string> OpenFileAsync(string path, CancellationToken token)
        {
            await Task.Delay(delayMs, token);
            return "{\"ok\":true,\"result\":{\"opened\":true}}";
        }
    }

    [Fact]
    public async Task Import_exceeding_deadline_yields_terminal_timeout_error()
    {
        // RAW/unknown-format regression: an import that never completes must
        // become a terminal ghidra_import_timeout error, never infinite pending.
        var control = new HangingControl();
        var operations = new GhidraOpenOperations(control, TimeSpan.FromMilliseconds(250));
        try
        {
            var begun = JsonNode.Parse(await operations.BeginGhidraOpenAsync("raw.bin"))!["result"]!;
            var id = begun["operationId"]!.GetValue<string>();
            Assert.Equal("pending", begun["status"]!.GetValue<string>());
            using var timeout = new CancellationTokenSource(10_000);
            string status;
            do
            {
                await Task.Delay(50, timeout.Token);
                status = await operations.GetGhidraOpenStatusAsync(Args(id));
            } while (!status.Contains("ghidra_import_timeout"));
            Assert.Contains("ghidra_import_timeout", status);
            Assert.DoesNotContain("pending", status);
            // The abandoned launcher import is signalled to abort; allow a
            // scheduling beat for the cooperative control to observe it.
            using var cancelWatch = new CancellationTokenSource(5000);
            while (!control.ObservedCancellation)
                await Task.Delay(10, cancelWatch.Token);
            Assert.True(control.ObservedCancellation);
            // Terminal result is stable across polls and leaves no queue entry.
            Assert.Contains("ghidra_import_timeout", await operations.GetGhidraOpenStatusAsync(Args(id)));
            Assert.Empty(operations.Queue());
            Assert.Equal(0, operations.PendingCount);
        }
        finally
        {
            operations.Stop();
            operations.Dispose();
        }
    }

    [Fact]
    public async Task Import_completing_before_deadline_still_succeeds()
    {
        var control = new SlowSuccessControl(50);
        var operations = new GhidraOpenOperations(control, TimeSpan.FromSeconds(10));
        try
        {
            var id = Id(await operations.BeginGhidraOpenAsync("fast.dll"));
            using var timeout = new CancellationTokenSource(5000);
            string status;
            while ((status = await operations.GetGhidraOpenStatusAsync(Args(id))).Contains("pending"))
                await Task.Delay(10, timeout.Token);
            Assert.Contains("opened", status);
            Assert.DoesNotContain("ghidra_import_timeout", status);
        }
        finally
        {
            operations.Stop();
            operations.Dispose();
        }
    }

    [Fact]
    public async Task User_cancel_before_deadline_still_reports_cancelled()
    {
        var control = new HangingControl();
        var operations = new GhidraOpenOperations(control, TimeSpan.FromMinutes(5));
        try
        {
            var id = Id(await operations.BeginGhidraOpenAsync("cancel.bin"));
            await operations.CancelAsync(Args(id));
            using var timeout = new CancellationTokenSource(5000);
            string result;
            while ((result = await operations.GetGhidraOpenStatusAsync(Args(id))).Contains("pending"))
                await Task.Delay(10, timeout.Token);
            Assert.Contains("ghidra_open_cancelled", result);
            Assert.DoesNotContain("ghidra_import_timeout", result);
            Assert.True(control.ObservedCancellation);
        }
        finally
        {
            operations.Stop();
            operations.Dispose();
        }
    }

    [Fact]
    public void Import_timeout_defaults_and_env_override_are_sane()
    {
        Assert.Equal(TimeSpan.FromMinutes(12), GhidraOpenOperations.DefaultImportTimeout);
        Assert.Equal(TimeSpan.FromMinutes(12), GhidraOpenOperations.ResolveImportTimeout(_ => null));
        Assert.Equal(TimeSpan.FromMinutes(12), GhidraOpenOperations.ResolveImportTimeout(_ => "bogus"));
        // Env override is honored but clamped so the 35s long-poll floor and
        // honest cold-JVM imports cannot be configured away.
        Assert.Equal(TimeSpan.FromSeconds(120), GhidraOpenOperations.ResolveImportTimeout(_ => "120000"));
        Assert.Equal(TimeSpan.FromSeconds(60), GhidraOpenOperations.ResolveImportTimeout(_ => "1000"));
        Assert.Equal(TimeSpan.FromMinutes(15), GhidraOpenOperations.ResolveImportTimeout(_ => "3600000"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new GhidraOpenOperations(null, TimeSpan.Zero));
    }

    private sealed class CapacityControl : IGhidraControlClient
    {
        public Task<string> OpenFileAsync(string path, CancellationToken token)
            => Task.FromException<string>(new InvalidOperationException(
                "The maximum number of parallel analysis sessions has been reached."));
    }

    [Fact]
    public async Task Capacity_throw_surfaces_session_capacity_reached_not_generic_failure()
    {
        var operations = new GhidraOpenOperations(new CapacityControl(), TimeSpan.FromSeconds(10));
        try
        {
            var begun = JsonNode.Parse(await operations.BeginGhidraOpenAsync("full.dll"))!["result"]!;
            var id = begun["operationId"]!.GetValue<string>();
            using var timeout = new CancellationTokenSource(5000);
            string status;
            do
            {
                await Task.Delay(10, timeout.Token);
                status = await operations.GetGhidraOpenStatusAsync(Args(id));
            } while (status.Contains("pending"));
            Assert.Contains("session_capacity_reached", status);
            Assert.DoesNotContain("ghidra_open_failed", status);
        }
        finally
        {
            operations.Stop();
            operations.Dispose();
        }
    }
}
