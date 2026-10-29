using System.Text.Json;
using DbgLink.Server;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// Dispatcher-level proof of the reader/writer session lease and of the gate
/// lifecycle. The gate itself is covered by AsyncReaderWriterGateTests; what
/// was missing is the wiring: that the dispatcher really hands out a shared
/// read lease to read-only tools, an exclusive lease to mutations, and that
/// disposing the dispatcher or the session registry while a call is in flight
/// neither hangs the call nor replaces its result with an exception.
/// </summary>
public sealed class DispatcherLeaseTests
{
    private static McpToolDispatcher Build(IBridgeClient bridge, out AnalysisSessionRegistry sessions)
    {
        var config = new ServerConfig { Port = 50398, MaxConcurrentRequests = 8, MaxQueuedOperations = 16 };
        var ghidra = new NullGhidra();
        sessions = new AnalysisSessionRegistry(bridge, ghidra);
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(null, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(
            Path.Combine(Path.GetTempPath(), "dbglink-lease-" + Guid.NewGuid().ToString("N"))));
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), new GhidraOpenOperations(null), sessionControl);
        return new McpToolDispatcher(config, registry, context, sessions, new ServerMetrics(),
            hasControl: false, NullLogger.Instance);
    }

    private static CallToolRequestParams SnapshotRequest() => new()
    {
        Name = "GetAnalysisSnapshot",
        Arguments = new Dictionary<string, JsonElement>
        {
            ["maxChars"] = JsonSerializer.SerializeToElement(4000)
        }
    };

    private static CallToolRequestParams SetRegisterRequest() => new()
    {
        Name = "SetRegister",
        Arguments = new Dictionary<string, JsonElement>
        {
            ["register"] = JsonSerializer.SerializeToElement("rax"),
            ["value"] = JsonSerializer.SerializeToElement("0x1")
        }
    };

    /// <summary>
    /// Two read-only calls on one session must overlap: the session lease is
    /// shared, so a second reader does not queue behind the first.
    /// </summary>
    [Fact]
    public async Task Read_only_calls_on_one_session_overlap()
    {
        var bridge = new GatedBridge();
        var dispatcher = Build(bridge, out var sessions);
        using var scope = sessions;

        var first = dispatcher.CallAsync(SnapshotRequest(), CancellationToken.None);
        await bridge.FirstEntered.WaitAsync(TimeSpan.FromSeconds(10));

        var second = dispatcher.CallAsync(SnapshotRequest(), CancellationToken.None);

        // The second reader must reach the backend while the first one is
        // still inside it. If the lease were exclusive this would time out.
        await bridge.Overlapped.WaitAsync(TimeSpan.FromSeconds(10));

        bridge.Release();
        await Task.WhenAll(first, second);
    }

    /// <summary>
    /// A mutation excludes concurrent readers: while the mutation holds the
    /// session, a read-only call must not reach the backend.
    /// </summary>
    [Fact]
    public async Task A_mutation_excludes_a_concurrent_reader()
    {
        var bridge = new GatedBridge();
        var dispatcher = Build(bridge, out var sessions);
        using var scope = sessions;

        var mutation = dispatcher.CallAsync(SetRegisterRequest(), CancellationToken.None);
        await bridge.FirstEntered.WaitAsync(TimeSpan.FromSeconds(10));

        var reader = dispatcher.CallAsync(SnapshotRequest(), CancellationToken.None);
        await Task.Delay(300);

        // The reader is still waiting for the lease: only the mutation has
        // reached the backend.
        Assert.Equal(1, bridge.TotalEntries);

        bridge.Release();
        await mutation;
        await reader;

        // After the mutation released the session the reader ran.
        Assert.True(bridge.TotalEntries >= 2, "The reader must run once the mutation released the session.");
    }

    /// <summary>
    /// Disposing the session registry while a call is in flight must neither
    /// hang the call nor let a disposal exception escape from the dispatcher's
    /// finally block and replace the real tool result.
    /// </summary>
    [Fact]
    public async Task Disposing_the_registry_mid_call_does_not_hang_or_replace_the_result()
    {
        var bridge = new GatedBridge();
        var dispatcher = Build(bridge, out var sessions);

        var call = dispatcher.CallAsync(SnapshotRequest(), CancellationToken.None);
        await bridge.FirstEntered.WaitAsync(TimeSpan.FromSeconds(10));

        // Tear the registry down while the tool body is still running.
        sessions.Dispose();

        bridge.Release();
        var result = await call.WaitAsync(TimeSpan.FromSeconds(10));

        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.DoesNotContain("ObjectDisposedException", text);
        Assert.DoesNotContain("could not be completed", text);
    }

    /// <summary>
    /// The same for the dispatcher itself: disposing it mid-call must not
    /// strand the call.
    /// </summary>
    [Fact]
    public async Task Disposing_the_dispatcher_mid_call_does_not_strand_the_call()
    {
        var bridge = new GatedBridge();
        var dispatcher = Build(bridge, out var sessions);
        using var scope = sessions;

        var call = dispatcher.CallAsync(SnapshotRequest(), CancellationToken.None);
        await bridge.FirstEntered.WaitAsync(TimeSpan.FromSeconds(10));

        dispatcher.Dispose();

        bridge.Release();
        var result = await call.WaitAsync(TimeSpan.FromSeconds(10));

        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.DoesNotContain("ObjectDisposedException", text);
    }

    /// <summary>
    /// A bridge that blocks every call until it is released and records the
    /// peak number of calls that were inside it at the same time.
    /// </summary>
    private sealed class GatedBridge : IBridgeClient
    {
        private readonly TaskCompletionSource _firstEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _overlapped =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _entered;
        private int _total;
        private int _peak;

        public Task FirstEntered => _firstEntered.Task;

        /// <summary>Total number of calls that entered the backend.</summary>
        public int TotalEntries => Volatile.Read(ref _total);

        /// <summary>Completes once two calls were inside the backend at the
        /// same time.</summary>
        public Task Overlapped => _overlapped.Task;

        public void Release() => _release.TrySetResult();

        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public async Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _total);
            var now = Interlocked.Increment(ref _entered);
            int observed;
            while (true)
            {
                observed = Volatile.Read(ref _peak);
                if (now <= observed) break;
                if (Interlocked.CompareExchange(ref _peak, now, observed) == observed) break;
            }
            if (Volatile.Read(ref _peak) >= 2)
                _overlapped.TrySetResult();
            if (Volatile.Read(ref _total) == 1)
                _firstEntered.TrySetResult();
            try
            {
                await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                return method switch
                {
                    "GetSnapshotState" => "{\"id\":1,\"ok\":true,\"result\":{\"debugging\":true,\"running\":false,\"stableRead\":true}}",
                    "GetCurrentContext" => "{\"id\":1,\"ok\":true,\"result\":{\"text\":\"CIP=0x140001000 | RAX=0x1 | DISASM: nop | STACK: [00]=0x0\"}}",
                    "GetCallStack" => "{\"id\":1,\"ok\":true,\"result\":{\"text\":\"Frame 0: 0x140001000 target.exe!main\"}}",
                    _ => "{\"id\":1,\"ok\":true,\"result\":{}}"
                };
            }
            finally
            {
                Interlocked.Decrement(ref _entered);
            }
        }
    }
}
