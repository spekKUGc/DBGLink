using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DbgLink.Launcher.Core;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// N1 launcher lane: per-PID native-endpoint-&lt;pid&gt;.json rendezvous,
/// pipe-token server arguments, and the single owned temporary root. Every
/// test cleans up its own directories; a passing run leaves nothing behind
/// in %TEMP%.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class LauncherNativeEndpointTests : IDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly string _testRoot =
        Path.Combine(Path.GetTempPath(), "dbglink-n1lau-" + Guid.NewGuid().ToString("N"));
    private readonly string _fakeLocalAppData;
    private bool _disposed;

    public LauncherNativeEndpointTests()
    {
        _fakeLocalAppData = Path.Combine(_testRoot, "localappdata");
        Directory.CreateDirectory(Path.Combine(_fakeLocalAppData, "DBGLink"));
        NativeEndpointResolver.LocalAppDataOverride = _fakeLocalAppData;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        NativeEndpointResolver.LocalAppDataOverride = null;
        NativeEndpointResolver.ProcessStartUtcOverride = null;
        if (Directory.Exists(_testRoot))
            Directory.Delete(_testRoot, recursive: true);
    }

    private string EndpointFileFor(int pid) =>
        Path.Combine(_fakeLocalAppData, "DBGLink", $"native-endpoint-{pid}.json");

    private static string ValidJson(int pid, string pipeName, string token) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            pid,
            pipeName,
            token,
            debugger = "x64dbg",
            imagePath = "C:\\dbg\\x64dbg.exe"
        });

    private void WriteEndpoint(string content, int pid)
        => File.WriteAllText(EndpointFileFor(pid), content, new UTF8Encoding(false));

    private static string PipeFor(int pid) => @"\\.\pipe\DbgLink.Control." + pid + ".ab12cd34";

    private const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // ========================================================================================
    // Rendezvous validation
    // ========================================================================================

    [Fact]
    public void Valid_endpoint_reads_pipe_name_and_token()
    {
        WriteEndpoint(ValidJson(1234, PipeFor(1234), Token), 1234);
        Assert.True(NativeEndpointResolver.TryReadValidEndpoint(
            EndpointFileFor(1234), 1234, out var endpoint, out _));
        Assert.Equal(PipeFor(1234), endpoint!.PipeName);
        Assert.Equal(Token, endpoint.Token);
        Assert.Equal("DbgLink.Control.1234.ab12cd34", endpoint.BarePipeName);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":2,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":\"1\",\"pid\":1234,\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"pid\":1234,\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":4321,\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":\"1234\",\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"DbgLink.Control.1234\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"" + "\\\\.\\pipe\\x\0y" + "\",\"token\":\"" + Token + "\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"0123456789abcdef\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0\"}")]
    [InlineData("{\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef\"}")]
    [InlineData("[1,2,3]")]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("{\"schemaVersion\":1,\"schemaVersion\":1,\"pid\":1234,\"pipeName\":\"x\",\"token\":\"" + Token + "\"}")]
    public void Malformed_endpoints_fail_closed(string content)
    {
        // Pipe names here intentionally omit the \\.\pipe\ prefix (or the
        // token is malformed); every case must fail without throwing.
        if (content == "")
            File.WriteAllBytes(EndpointFileFor(1234), Array.Empty<byte>());
        else
            WriteEndpoint(content, 1234);
        Assert.False(NativeEndpointResolver.TryReadValidEndpoint(
            EndpointFileFor(1234), 1234, out var endpoint, out var detail));
        Assert.Null(endpoint);
        Assert.False(string.IsNullOrWhiteSpace(detail));
        Assert.DoesNotContain(Token, detail);
    }

    [Fact]
    public void Missing_endpoint_file_fails_closed()
    {
        Assert.False(NativeEndpointResolver.TryReadValidEndpoint(
            EndpointFileFor(1234), 1234, out _, out _));
    }

    [Fact]
    public void Directory_at_endpoint_path_fails_closed()
    {
        Directory.CreateDirectory(EndpointFileFor(1234));
        try
        {
            Assert.False(NativeEndpointResolver.TryReadValidEndpoint(
                EndpointFileFor(1234), 1234, out _, out _));
        }
        finally
        {
            Directory.Delete(EndpointFileFor(1234));
        }
    }

    [Fact]
    public void Oversized_endpoint_file_fails_closed()
    {
        using (var stream = new FileStream(EndpointFileFor(1234), FileMode.Create, FileAccess.Write))
            stream.SetLength(65 * 1024);
        Assert.False(NativeEndpointResolver.TryReadValidEndpoint(
            EndpointFileFor(1234), 1234, out _, out _));
    }

    // ========================================================================================
    // Rendezvous polling
    // ========================================================================================

    [Fact]
    public async Task Waiter_resolves_a_late_endpoint_and_deletes_the_file()
    {
        var pid = Environment.ProcessId;
        var writer = Task.Run(async () =>
        {
            await Task.Delay(300);
            WriteEndpoint(ValidJson(pid, PipeFor(pid), Token), pid);
        });
        var endpoint = await NativeEndpointResolver.WaitForEndpointAsync(
            pid, TimeSpan.FromSeconds(10), CancellationToken.None, () => true);
        await writer;
        Assert.Equal(PipeFor(pid), endpoint.PipeName);
        Assert.Equal(Token, endpoint.Token);
        Assert.False(File.Exists(EndpointFileFor(pid)));
    }

    [Fact]
    public async Task Waiter_times_out_fail_closed_when_missing()
    {
        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            NativeEndpointResolver.WaitForEndpointAsync(
                Environment.ProcessId, TimeSpan.FromSeconds(1), CancellationToken.None, () => true));
        Assert.Contains("did not publish a valid endpoint", exception.Message);
    }

    [Fact]
    public async Task Waiter_times_out_fail_closed_on_invalid_content()
    {
        WriteEndpoint(ValidJson(9999, PipeFor(9999), Token), 1234);
        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            NativeEndpointResolver.WaitForEndpointAsync(
                1234, TimeSpan.FromSeconds(1), CancellationToken.None, () => true));
        Assert.Contains("pid did not match", exception.Message);
    }

    [Fact]
    public async Task Waiter_fails_fast_when_the_debugger_is_gone()
    {
        WriteEndpoint(ValidJson(1234, PipeFor(1234), Token), 1234);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NativeEndpointResolver.WaitForEndpointAsync(
                1234, TimeSpan.FromSeconds(10), CancellationToken.None, () => false));
        Assert.True(File.Exists(EndpointFileFor(1234)));
    }

    [Fact]
    public async Task Verified_but_undeletable_file_reports_and_still_resolves()
    {
        var pid = Environment.ProcessId;
        WriteEndpoint(ValidJson(pid, PipeFor(pid), Token), pid);
        File.SetAttributes(EndpointFileFor(pid), FileAttributes.ReadOnly);
        try
        {
            string? report = null;
            var endpoint = await NativeEndpointResolver.WaitForEndpointAsync(
                pid, TimeSpan.FromSeconds(10), CancellationToken.None, () => true, message => report = message);
            Assert.Equal(Token, endpoint.Token);
            Assert.Contains("could not be removed", report);
        }
        finally
        {
            File.SetAttributes(EndpointFileFor(pid), FileAttributes.Normal);
            File.Delete(EndpointFileFor(pid));
        }
    }

    [Fact]
    public async Task Timeout_message_never_echoes_the_token()
    {
        var badToken = new string('B', 64);
        WriteEndpoint(ValidJson(1234, PipeFor(1234), badToken), 1234);
        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            NativeEndpointResolver.WaitForEndpointAsync(
                1234, TimeSpan.FromSeconds(1), CancellationToken.None, () => true));
        Assert.DoesNotContain(badToken, exception.Message);
    }

    // ========================================================================================
    // Per-PID rendezvous + recycled-PID stale guard
    // ========================================================================================

    [Fact]
    public void Endpoint_path_is_per_pid()
    {
        var path1234 = NativeEndpointResolver.EndpointPathFor(1234);
        var path4321 = NativeEndpointResolver.EndpointPathFor(4321);
        Assert.NotNull(path1234);
        Assert.NotNull(path4321);
        Assert.NotEqual(path1234, path4321);
        Assert.Equal("native-endpoint-1234.json", Path.GetFileName(path1234));
        Assert.Equal("native-endpoint-4321.json", Path.GetFileName(path4321));
        Assert.Null(NativeEndpointResolver.EndpointPathFor(0));
        Assert.Null(NativeEndpointResolver.EndpointPathFor(-1));
    }

    [Fact]
    public async Task Waiter_ignores_another_pid_file_and_keeps_it()
    {
        // Two concurrent debugger instances must not clobber each other: a
        // valid file for PID B is invisible to a waiter for PID A.
        const int pidA = 11111;
        const int pidB = 22222;
        WriteEndpoint(ValidJson(pidB, PipeFor(pidB), Token), pidB);
        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            NativeEndpointResolver.WaitForEndpointAsync(
                pidA, TimeSpan.FromSeconds(1), CancellationToken.None, () => true));
        Assert.Contains("was missing", exception.Message);
        Assert.True(File.Exists(EndpointFileFor(pidB)));
        Assert.False(File.Exists(EndpointFileFor(pidA)));
    }

    [Fact]
    public void Stale_file_older_than_process_start_is_rejected()
    {
        var pid = Environment.ProcessId;
        WriteEndpoint(ValidJson(pid, PipeFor(pid), Token), pid);
        var path = EndpointFileFor(pid);
        // Fresh file is newer than the real process start: otherwise valid.
        Assert.True(NativeEndpointResolver.TryReadValidEndpoint(
            path, pid, out var fresh, out _));
        Assert.NotNull(fresh);
        var start = NativeEndpointResolver.TryGetDebuggerStartUtc(pid);
        Assert.NotNull(start);
        var stale = start!.Value - TimeSpan.FromMinutes(5);
        File.SetCreationTimeUtc(path, stale);
        File.SetLastWriteTimeUtc(path, stale);
        // Pin the real process start so the recycled-PID guard fires
        // deterministically (no reliance on live clock skew).
        NativeEndpointResolver.ProcessStartUtcOverride = _ => start!.Value;
        try
        {
            Assert.True(NativeEndpointResolver.IsStaleEndpointFile(path, pid));
            Assert.False(NativeEndpointResolver.TryReadValidEndpoint(
                path, pid, out var endpoint, out var detail));
            Assert.Null(endpoint);
            Assert.Contains("stale", detail);
            Assert.DoesNotContain(Token, detail);
        }
        finally
        {
            NativeEndpointResolver.ProcessStartUtcOverride = null;
        }
    }

    [Fact]
    public async Task Waiter_times_out_on_stale_file_and_keeps_it_for_diagnosis()
    {
        var pid = Environment.ProcessId;
        WriteEndpoint(ValidJson(pid, PipeFor(pid), Token), pid);
        var path = EndpointFileFor(pid);
        var start = NativeEndpointResolver.TryGetDebuggerStartUtc(pid);
        Assert.NotNull(start);
        var stale = start!.Value - TimeSpan.FromMinutes(5);
        File.SetCreationTimeUtc(path, stale);
        File.SetLastWriteTimeUtc(path, stale);
        // Pin the process start newer than the file so the recycled-PID guard fires.
        NativeEndpointResolver.ProcessStartUtcOverride = _ => start!.Value;
        try
        {
            var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
                NativeEndpointResolver.WaitForEndpointAsync(
                    pid, TimeSpan.FromSeconds(1), CancellationToken.None, () => true));
            Assert.Contains("stale", exception.Message);
            Assert.True(File.Exists(path));
        }
        finally
        {
            NativeEndpointResolver.ProcessStartUtcOverride = null;
        }
    }

    [Fact]
    public void Unknown_process_start_skips_only_the_stale_check()
    {
        WriteEndpoint(ValidJson(1234, PipeFor(1234), Token), 1234);
        var path = EndpointFileFor(1234);
        File.SetCreationTimeUtc(path, DateTime.UtcNow - TimeSpan.FromDays(30));
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow - TimeSpan.FromDays(30));
        NativeEndpointResolver.ProcessStartUtcOverride = _ => null;
        try
        {
            Assert.False(NativeEndpointResolver.IsStaleEndpointFile(path, 1234));
            Assert.True(NativeEndpointResolver.TryReadValidEndpoint(
                path, 1234, out var endpoint, out _));
            Assert.NotNull(endpoint);
        }
        finally
        {
            NativeEndpointResolver.ProcessStartUtcOverride = null;
        }
    }

    // ========================================================================================
    // Server arguments
    // ========================================================================================

    [Fact]
    public void Server_spec_passes_pipe_name_and_token()
    {
        var spec = LauncherPlanner.CreateServerSpec(
            CreatePlan(), 42, null, null, null, PipeFor(42), Token);
        var arguments = spec.Arguments.ToArray();
        var nameIndex = Array.IndexOf(arguments, "--pipe-name");
        Assert.True(nameIndex >= 0);
        Assert.Equal("DbgLink.Control.42.ab12cd34", arguments[nameIndex + 1]);
        Assert.Contains("--port", arguments);
        // The token is a per-session credential: it travels in the child's
        // environment, never on the command line, because argv is readable by
        // every local process through Win32_Process.CommandLine.
        Assert.DoesNotContain("--pipe-token", arguments);
        Assert.DoesNotContain(Token, arguments);
        Assert.Equal(Token,
            spec.EnvironmentVariables["DBGLINK_NATIVE_PIPE_TOKEN"]);
    }

    [Fact]
    public void Server_spec_without_token_keeps_legacy_shape()
    {
        var spec = LauncherPlanner.CreateServerSpec(CreatePlan(), 42);
        var arguments = spec.Arguments.ToArray();
        Assert.DoesNotContain("--pipe-token", arguments);
        var nameIndex = Array.IndexOf(arguments, "--pipe-name");
        Assert.Equal("DbgLink.Control.42", arguments[nameIndex + 1]);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Server_spec_requires_name_and_token_together(bool withName, bool withToken)
    {
        Assert.Throws<ArgumentException>(() => LauncherPlanner.CreateServerSpec(
            CreatePlan(), 42, null, null, null,
            withName ? PipeFor(42) : null,
            withToken ? Token : null));
    }

    [Theory]
    [InlineData("DbgLink.Control.42")]
    [InlineData("")]
    public void Server_spec_rejects_a_bad_pipe_name(string pipeName)
    {
        Assert.Throws<ArgumentException>(() => LauncherPlanner.CreateServerSpec(
            CreatePlan(), 42, null, null, null, pipeName, Token));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    public void Server_spec_rejects_a_bad_pipe_token(string token)
    {
        Assert.Throws<ArgumentException>(() => LauncherPlanner.CreateServerSpec(
            CreatePlan(), 42, null, null, null, PipeFor(42), token));
    }

    // ========================================================================================
    // Probe with token over a real loopback pipe
    // ========================================================================================

    [Fact]
    public async Task Probe_sends_the_token_and_accepts_the_full_pipe_name()
    {
        var pid = Random.Shared.Next(1, 2000000000);
        var bare = "DbgLink.Control." + pid + ".ab12cd34";
        await using var server = new NamedPipeServerStream(
            bare, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var probeTask = NativePipeProbe.WaitForReadyAsync(
            @"\\.\pipe\" + bare, pid, TimeSpan.FromSeconds(15), CancellationToken.None, null, Token);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var request = await ReadRequestLineAsync(server);
        Assert.Contains("\"token\":\"" + Token + "\"", request);
        await WriteLineAsync(server,
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":" + pid + ",\"debugging\":true}");
        var handshake = await probeTask;
        Assert.Equal(pid, handshake.ProcessId);
        Assert.True(handshake.Debugging);
    }

    [Fact]
    public async Task Probe_without_token_omits_the_token_member()
    {
        var pid = Random.Shared.Next(1, 2000000000);
        var bare = "DbgLink.Control." + pid + ".ab12cd34";
        await using var server = new NamedPipeServerStream(
            bare, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var probeTask = NativePipeProbe.WaitForReadyAsync(
            @"\\.\pipe\" + bare, pid, TimeSpan.FromSeconds(15), CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var request = await ReadRequestLineAsync(server);
        Assert.DoesNotContain("token", request);
        await WriteLineAsync(server,
            "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":" + pid + ",\"debugging\":false}");
        var handshake = await probeTask;
        Assert.Equal(pid, handshake.ProcessId);
    }

    [Fact]
    public async Task Probe_reports_unauthorized_when_the_token_is_rejected()
    {
        var pid = Random.Shared.Next(1, 2000000000);
        var bare = "DbgLink.Control." + pid + ".ab12cd34";
        using var stop = new CancellationTokenSource();
        // Answer every probe attempt: the retry loop must keep seeing the
        // unauthorized response so the final failure names it.
        var serveTask = Task.Run(() => ServeUnauthorizedAsync(bare, stop.Token));
        try
        {
            var watch = Stopwatch.StartNew();
            var exception = await Assert.ThrowsAsync<TimeoutException>(() => NativePipeProbe.WaitForReadyAsync(
                bare, pid, TimeSpan.FromSeconds(15), CancellationToken.None, null, Token));
            watch.Stop();
            Assert.Contains("unauthorized", exception.Message);
            // A definitive rejection cannot be fixed by retrying (the token is
            // fixed for the pipe's lifetime), so the probe must fail fast
            // instead of burning the whole budget and letting a later connect
            // failure overwrite the reason.
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3),
                $"a rejected token was retried for {watch.ElapsedMilliseconds}ms");
        }
        finally
        {
            stop.Cancel();
            await serveTask.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private static async Task ServeUnauthorizedAsync(string pipeName, CancellationToken cancellationToken)
    {
        // Overlapped instances: each connection is handed to the background
        // while the loop immediately listens again, so a probe Connect never
        // lands in a recreate gap.
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? listener = null;
            try
            {
                listener = new NamedPipeServerStream(
                    pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message, PipeOptions.Asynchronous);
                await listener.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var active = listener;
                listener = null;
                _ = ServeOneUnauthorizedAsync(active);
            }
            catch (OperationCanceledException) { listener?.Dispose(); break; }
            catch (IOException) { listener?.Dispose(); }
        }
    }

    private static async Task ServeOneUnauthorizedAsync(NamedPipeServerStream pipe)
    {
        try
        {
            await using (pipe.ConfigureAwait(false))
            {
                await ReadRequestLineAsync(pipe).ConfigureAwait(false);
                await WriteLineAsync(pipe,
                    "{\"id\":1,\"ok\":false,\"error\":{\"code\":\"unauthorized\",\"message\":\"bad token\"}}")
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }

    [Theory]
    [InlineData(@"\\.\pipe\DbgLink.Control.7.ab12cd34", 8)]
    [InlineData("DbgLink.Control.8", 7)]
    [InlineData(@"\\.\pipe\Other.7", 7)]
    public async Task Probe_rejects_a_pipe_name_not_bound_to_the_pid(string pipeName, int pid)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => NativePipeProbe.WaitForReadyAsync(
            pipeName, pid, TimeSpan.FromSeconds(2), CancellationToken.None));
    }

    [Fact]
    public async Task Probe_rejects_a_malformed_token_argument()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => NativePipeProbe.WaitForReadyAsync(
            "DbgLink.Control.9", 9, TimeSpan.FromSeconds(2), CancellationToken.None, null, "short"));
    }

    // ========================================================================================
    // Single owned temporary root
    // ========================================================================================

    [Fact]
    public void Run_root_is_created_owned_and_removed()
    {
        var root = LauncherTempRoot.CreateRunRoot();
        try
        {
            Assert.True(Directory.Exists(root));
            Assert.True(LauncherTempRoot.IsOwnedRunRoot(root));
            Assert.StartsWith(
                Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase);
            File.WriteAllText(Path.Combine(root, "probe.txt"), "x");
            Assert.True(LauncherTempRoot.TryDeleteTree(root));
            Assert.False(Directory.Exists(root));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Owned_tree_delete_clears_read_only_files_and_nested_dirs()
    {
        var root = LauncherTempRoot.CreateRunRoot();
        try
        {
            var nested = Path.Combine(root, "a", "b");
            Directory.CreateDirectory(nested);
            var locked = Path.Combine(nested, "locked.txt");
            File.WriteAllText(locked, "x");
            File.SetAttributes(locked, FileAttributes.ReadOnly);
            Assert.True(LauncherTempRoot.TryDeleteTree(root));
            Assert.False(Directory.Exists(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    File.SetAttributes(file, FileAttributes.Normal);
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Owned_tree_delete_repairs_owner_only_dacl_without_delete()
    {
        // Regression: the Ghidra bridge hardens its endpoint file with an
        // owner-only protected DACL that omits DELETE, so a plain
        // File.Delete throws UnauthorizedAccessException even for the owner.
        // The owned-tree sweep must re-grant itself and still remove the tree.
        var root = LauncherTempRoot.CreateRunRoot();
        try
        {
            var endpoint = Path.Combine(root, "endpoint");
            Directory.CreateDirectory(endpoint);
            var hardened = Path.Combine(endpoint, "ghidra-bridge-1-22222222-2222-2222-2222-222222222222.json");
            File.WriteAllText(hardened, "{}");
            if (OperatingSystem.IsWindows())
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
                var security = new System.Security.AccessControl.FileSecurity();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    identity,
                    System.Security.AccessControl.FileSystemRights.Read |
                        System.Security.AccessControl.FileSystemRights.Write,
                    System.Security.AccessControl.AccessControlType.Allow));
                new FileInfo(hardened).SetAccessControl(security);
                Assert.Throws<UnauthorizedAccessException>(() => File.Delete(hardened));
            }
            Assert.True(LauncherTempRoot.TryDeleteTree(root));
            Assert.False(Directory.Exists(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var identity = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
                        var security = new FileInfo(file).GetAccessControl();
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            identity,
                            System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.AccessControlType.Allow));
                        new FileInfo(file).SetAccessControl(security);
                        File.SetAttributes(file, FileAttributes.Normal);
                    }
                    catch (Exception) { }
                }
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Owned_tree_delete_refuses_foreign_paths()
    {
        // Existing, but never launcher-owned: must be refused untouched.
        Assert.False(LauncherTempRoot.TryDeleteTree(Environment.GetFolderPath(Environment.SpecialFolder.Windows)));
        Assert.True(Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.Windows)));
        Assert.False(LauncherTempRoot.TryDeleteTree(Path.Combine(Path.GetTempPath(), "dbglink-not-ours")));
        Assert.False(LauncherTempRoot.TryDeleteTree(null));
        Assert.False(LauncherTempRoot.IsOwnedRunRoot(Path.GetTempPath()));
        Assert.False(LauncherTempRoot.IsOwnedSessionRoot(
            Path.Combine(Path.GetTempPath(), "dbglink-" + Guid.NewGuid().ToString("N"))));
    }

    [Fact]
    public async Task Session_parent_validation_rejects_foreign_roots()
    {
        var plan = CreatePlan();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            GhidraSession.PrepareAsync(plan, _ => { }, CancellationToken.None, Path.GetTempPath()));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            GhidraSession.PrepareAsync(
                plan, _ => { }, CancellationToken.None,
                Path.Combine(Path.GetTempPath(), "missing-" + Guid.NewGuid().ToString("N"))));
    }

    // ========================================================================================
    // Helpers
    // ========================================================================================

    private static LauncherPlan CreatePlan()
    {
        var settings = new LauncherSettings("x64dbg.exe", "x32dbg.exe", "ghidra", ReverseMode.LetLlmChoose, null);
        var paths = new ToolkitPaths(
            "x64dbg.exe", "x32dbg.exe", "x64dbg.exe", "ghidra", "ghidraRun.bat", "analyzeHeadless.bat",
            "plugins", "DbgLink.Server.exe", "DbgLink.dp64", "GhidraBridge.zip", "jdk");
        return new LauncherPlan(settings, paths);
    }

    private static async Task<string> ReadRequestLineAsync(NamedPipeServerStream server)
    {
        var buffer = new byte[64 * 1024];
        using var collected = new MemoryStream();
        do
        {
            var read = await server.ReadAsync(buffer.AsMemory(), CancellationToken.None);
            if (read == 0)
                break;
            collected.Write(buffer, 0, read);
        } while (!server.IsMessageComplete);
        var bytes = collected.ToArray();
        var newline = Array.IndexOf(bytes, (byte)'\n');
        return StrictUtf8.GetString(bytes, 0, newline < 0 ? bytes.Length : newline);
    }

    private static async Task WriteLineAsync(Stream stream, string text)
    {
        var bytes = StrictUtf8.GetBytes(text + "\n");
        await stream.WriteAsync(bytes, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
    }
}
