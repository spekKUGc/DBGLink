extern alias Server;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DbgLink.Server;
using DbgLink.Launcher.Core;
using SharedPipe = Server::DbgLink.Shared.DbgLinkNativePipe;
using SharedSafety = Server::DbgLink.Shared.PathSafety;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Integration tests over REAL transports and REAL files/processes:
/// loopback named pipes, loopback TCP, real OS binaries, real process jobs.
/// No x64dbg/Ghidra installation required; no mocks for the transports.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class ComponentLoopbackTests
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    // ========================================================================================
    // BridgeClient over a real message-mode named pipe
    // ========================================================================================

    [Fact]
    public async Task BridgeLoopback_Ping_Succeeds()
    {
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, 2000000000);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var client = new BridgeClient(pipeName);
        var pingTask = client.PingAsync(CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var id = await ReadRequestIdAsync(server);
        await WriteLineAsync(server, "{\"id\":" + id + ",\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":" + Environment.ProcessId + ",\"debugging\":true}");
        Assert.True(await pingTask);
        Assert.Null(client.LastFailure);
    }

    [Fact]
    public async Task BridgeLoopback_ReadMemory_ReturnsBytes()
    {
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, 2000000000);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var client = new BridgeClient(pipeName);
        var requestTask = client.RequestAsync("ReadMemAtAddress",
            JsonSerializer.SerializeToElement(new { address = "0x140001000", byteCount = 4 }), CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var id = await ReadRequestIdAsync(server);
        await WriteLineAsync(server, "{\"id\":" + id + ",\"ok\":true,\"result\":{\"address\":\"0x140001000\",\"bytes\":\"48895C24\",\"bytesRead\":4}}");
        var response = await requestTask;
        Assert.Contains("48895C24", response);
    }

    [Fact]
    public async Task BridgeLoopback_UnknownMethod_ReturnsErrorEnvelope()
    {
        var pipeName = "DbgLink.Control." + Random.Shared.Next(1, 2000000000);
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var client = new BridgeClient(pipeName);
        var requestTask = client.RequestAsync("NoSuchMethod", CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var id = await ReadRequestIdAsync(server);
        await WriteLineAsync(server, "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"unknown_method\",\"message\":\"nope\"}}");
        var response = await requestTask;
        Assert.Contains("unknown_method", response);
    }

    [Fact]
    public async Task BridgeLoopback_NoServer_ThrowsTransportError()
    {
        var missingPid = 400000000 + Random.Shared.Next(1, 400000000);
        var client = new BridgeClient("DbgLink.Control." + missingPid);
        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => client.RequestAsync("ping", CancellationToken.None));
        Assert.True(exception is IOException or TimeoutException or InvalidDataException,
            "Unexpected transport failure: " + exception.GetType().FullName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BridgeClient_RejectsInvalidPipeName(string pipeName)
    {
        Assert.Throws<ArgumentException>(() => new BridgeClient(pipeName!));
    }

    [Fact]
    public async Task BridgeClient_RejectsInvalidMethodAndArguments()
    {
        var client = new BridgeClient("DbgLink.Control.42");
        await Assert.ThrowsAsync<ArgumentException>(() => client.RequestAsync("", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => client.RequestAsync("ping",
            JsonSerializer.SerializeToElement(new[] { 1 }), CancellationToken.None));
    }

    // ========================================================================================
    // GhidraClient over a real TCP loopback + real endpoint directory
    // ========================================================================================

    [Fact]
    public async Task GhidraLoopback_Status_Succeeds()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-test.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('a', 32) + "\"}");
        var client = new GhidraClient(dir);
        var requestTask = client.RequestAsync("status", null, CancellationToken.None);
        using var peer = await listener.AcceptTcpClientAsync(CancellationToken.None);
        await using var stream = peer.GetStream();
        var id = await ReadGhidraRequestIdAsync(stream);
        await WriteLineAsync(stream, "{\"id\":" + id + ",\"ok\":true,\"result\":{\"connected\":true}}");
        var response = await requestTask;
        Assert.Contains("connected", response);
    }

    [Fact]
    public async Task GhidraLoopback_MethodNotAllowed_ReturnsEnvelope()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var client = new GhidraClient(dir);
        var response = await client.RequestAsync("BogusMethod", null, CancellationToken.None);
        Assert.Contains("method_not_allowed", response);
    }

    [Fact]
    public async Task GhidraLoopback_InvalidArguments_ReturnsEnvelope()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var client = new GhidraClient(dir);
        var response = await client.RequestAsync("status",
            JsonSerializer.SerializeToElement(new[] { 1 }), CancellationToken.None);
        Assert.Contains("invalid_arguments", response);
    }

    [Fact]
    public async Task GhidraLoopback_UnauthorizedEnvelope_PassesThrough()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-test.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('a', 32) + "\"}");
        var client = new GhidraClient(dir);
        var requestTask = client.RequestAsync("status", null, CancellationToken.None);
        using var peer = await listener.AcceptTcpClientAsync(CancellationToken.None);
        await using var stream = peer.GetStream();
        var id = await ReadGhidraRequestIdAsync(stream);
        await WriteLineAsync(stream, "{\"id\":" + id + ",\"ok\":false,\"error\":{\"code\":\"unauthorized\",\"message\":\"bad token\"}}");
        Assert.Contains("unauthorized", await requestTask);
    }

    [Fact]
    public async Task GhidraLoopback_NoEndpoint_ReturnsUnavailable()
    {
        using var noEndpointDir = TempDir.Create("dbglink-loopback-");
        var client = new GhidraClient(noEndpointDir);
        var response = await client.RequestAsync("status", null, CancellationToken.None);
        Assert.Contains("ghidra_unavailable", response);
    }

    // ========================================================================================
    // NativePipeProbe over a real loopback pipe
    // ========================================================================================

    [Fact]
    public async Task NativeProbe_Handshake_Succeeds()
    {
        var pid = Random.Shared.Next(1, 2000000000);
        var pipeName = "DbgLink.Control." + pid;
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var probeTask = NativePipeProbe.WaitForReadyAsync(pipeName, pid, TimeSpan.FromSeconds(15), CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        await DrainRequestAsync(server);
        await WriteLineAsync(server, "{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":" + pid + ",\"debugging\":false}");
        var handshake = await probeTask;
        Assert.Equal(pid, handshake.ProcessId);
        Assert.False(handshake.Debugging);
    }

    [Fact]
    public async Task NativeProbe_NoServer_TimesOut()
    {
        var pid = 400000000 + Random.Shared.Next(1, 400000000);
        await Assert.ThrowsAsync<TimeoutException>(() => NativePipeProbe.WaitForReadyAsync(
            "DbgLink.Control." + pid, pid, TimeSpan.FromSeconds(2), CancellationToken.None));
    }

    [Theory]
    [InlineData("", 1)]
    [InlineData("DbgLink.Control.1", 0)]
    [InlineData("DbgLink.Control.2", 1)]
    public async Task NativeProbe_RejectsBadNames(string pipeName, int pid)
    {
        await Assert.ThrowsAnyAsync<Exception>(() => NativePipeProbe.WaitForReadyAsync(
            pipeName, pid, TimeSpan.FromSeconds(2), CancellationToken.None));
    }

    [Fact]
    public async Task NativeProbe_DeadProcess_FailsFast()
    {
        var pid = Environment.ProcessId;
        await Assert.ThrowsAsync<InvalidOperationException>(() => NativePipeProbe.WaitForReadyAsync(
            "DbgLink.Control." + pid, pid, TimeSpan.FromSeconds(10), CancellationToken.None, () => false));
    }

    // ========================================================================================
    // GhidraBridgeProbe over real endpoint files + loopback TCP
    // ========================================================================================

    [Fact]
    public async Task GhidraProbe_Handshake_Succeeds()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-1.json"),
            "{\"protocolVersion\":1,\"host\":\"127.0.0.1\",\"port\":" + port + ",\"pid\":" + Environment.ProcessId + ",\"token\":\"" + new string('a', 32) + "\"}");
        var probeTask = GhidraBridgeProbe.WaitForReadyAsync(dir, requireActiveProgram: false, TimeSpan.FromSeconds(15), CancellationToken.None);
        using var peer = await listener.AcceptTcpClientAsync(CancellationToken.None);
        await using var stream = peer.GetStream();
        await ReadGhidraRequestIdAsync(stream);
        await WriteLineAsync(stream, "{\"id\":1,\"ok\":true,\"result\":{\"endpoint\":\"127.0.0.1\",\"available\":true}}");
        var status = await probeTask;
        Assert.True(status.Available);
        Assert.Equal("127.0.0.1", status.Host);
        Assert.Equal(port, status.Port);
    }

    [Fact]
    public async Task GhidraProbe_EmptyDirectory_TimesOut()
    {
        using var emptyDir1 = TempDir.Create("dbglink-loopback-");
        await Assert.ThrowsAsync<TimeoutException>(() => GhidraBridgeProbe.WaitForReadyAsync(
            emptyDir1, requireActiveProgram: false, TimeSpan.FromSeconds(1), CancellationToken.None));
    }

    [Fact]
    public async Task GhidraProbe_RejectsBadDirectory()
    {
        using var badDir = TempDir.Create("dbglink-loopback-");
        await Assert.ThrowsAsync<ArgumentException>(() => GhidraBridgeProbe.WaitForReadyAsync(
            "", requireActiveProgram: false, TimeSpan.FromSeconds(2), CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => GhidraBridgeProbe.WaitForReadyAsync(
            badDir, requireActiveProgram: false, TimeSpan.Zero, CancellationToken.None));
    }

    // ========================================================================================
    // SafeFileCopy over real files
    // ========================================================================================

    [Fact]
    public void SafeCopy_RoundTrip_PreservesBytes()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var src = Path.Combine(dir, "src.bin");
        var dst = Path.Combine(dir, "dst.bin");
        var payload = new byte[100000];
        Random.Shared.NextBytes(payload);
        File.WriteAllBytes(src, payload);
        SafeFileCopy.Copy(src, dst, 1024 * 1024, overwrite: false);
        Assert.Equal(payload, File.ReadAllBytes(dst));
    }

    [Fact]
    public void SafeCopy_EnforcesLimits()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var src = Path.Combine(dir, "src.bin");
        File.WriteAllBytes(src, new byte[4096]);
        Assert.Throws<InvalidDataException>(() => SafeFileCopy.Copy(src, Path.Combine(dir, "a.bin"), 1024, overwrite: false));
        Assert.Throws<ArgumentOutOfRangeException>(() => SafeFileCopy.Copy(src, Path.Combine(dir, "b.bin"), 0, overwrite: false));
        Assert.Throws<ArgumentException>(() => SafeFileCopy.Copy("", Path.Combine(dir, "c.bin"), 1024, overwrite: false));
        SafeFileCopy.Copy(src, Path.Combine(dir, "d.bin"), 8192, overwrite: false);
        Assert.Throws<System.ComponentModel.Win32Exception>(() => SafeFileCopy.Copy(src, Path.Combine(dir, "d.bin"), 8192, overwrite: false));
    }

    [Fact]
    public void SafeCopy_ReadOnlyDestination_IsOverwritten()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var src = Path.Combine(dir, "src.bin");
        var dst = Path.Combine(dir, "dst.bin");
        File.WriteAllBytes(src, new byte[] { 1, 2, 3 });
        File.WriteAllBytes(dst, new byte[] { 9 });
        File.SetAttributes(dst, FileAttributes.ReadOnly);
        SafeFileCopy.Copy(src, dst, 1024, overwrite: true);
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(dst));
    }

    [Fact]
    public void SafeCopy_SymlinkSource_IsRejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = TempDir.Create("dbglink-loopback-");
        var src = Path.Combine(dir, "src.bin");
        File.WriteAllBytes(src, new byte[] { 1 });
        var link = Path.Combine(dir, "link.bin");
        try { File.CreateSymbolicLink(link, src); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        Assert.Throws<InvalidDataException>(() => SafeFileCopy.Copy(link, Path.Combine(dir, "dst.bin"), 1024, overwrite: false));
        using var stream = SafeFileCopy.OpenNonReparseRead(src);
        Assert.Equal(1, stream.Length);
    }

    // ========================================================================================
    // WindowsProcessJob + ProcessLauncher over real processes
    // ========================================================================================

    [Fact]
    public void ProcessJob_AssignActiveProcess_Succeeds()
    {
        using var job = WindowsProcessJob.Create();
        using var sleeper = Process.Start("cmd.exe", "/c ping -n 6 127.0.0.1 > nul");
        Assert.NotNull(sleeper);
        job.Assign(sleeper);
        Assert.False(sleeper.HasExited);
        sleeper.Kill();
        job.Dispose();
        job.Dispose();
    }

    [Fact]
    public void ProcessJob_ExitedProcess_Throws()
    {
        using var job = WindowsProcessJob.Create();
        using var quick = Process.Start("cmd.exe", "/c exit 0");
        Assert.NotNull(quick);
        quick.WaitForExit();
        Assert.Throws<InvalidOperationException>(() => job.Assign(quick));
    }

    [Fact]
    public void ProcessJob_NullAndDisposed_Throw()
    {
        using var job = WindowsProcessJob.Create();
        Assert.Throws<ArgumentNullException>(() => job.Assign(null!));
        using var sleeper = Process.Start("cmd.exe", "/c ping -n 6 127.0.0.1 > nul");
        Assert.NotNull(sleeper);
        try
        {
            job.Dispose();
            Assert.Throws<ObjectDisposedException>(() => job.Assign(sleeper));
        }
        finally { if (!sleeper.HasExited) sleeper.Kill(); }
    }

    [Fact]
    public void Launcher_StartEcho_CapturesOutput()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(cmd)) return;
        using var process = ProcessLauncher.Start(new ProcessLaunchSpec(
            cmd, new[] { "/c", "echo", "hi-loopback" }, Path.GetTempPath(),
            new Dictionary<string, string>(), UseShellExecute: false, CaptureOutput: true));
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(10000);
        Assert.Contains("hi-loopback", output);
    }

    [Fact]
    public void Launcher_RemovesSensitiveEnvironmentEntries()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(cmd)) return;
        var name = "DBGLINK_TEST_SECRET_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, "sentinel-secret");
        try
        {
            using var process = ProcessLauncher.Start(new ProcessLaunchSpec(
                cmd, new[] { "/c", "set", name }, Path.GetTempPath(),
                new Dictionary<string, string>(), UseShellExecute: false,
                CaptureOutput: true, RemoveEnvironmentVariables: new[] { name }));
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            Assert.DoesNotContain("sentinel-secret", output, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void Launcher_ShellExecuteRestrictedToCommandFiles()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        Assert.Throws<InvalidOperationException>(() => ProcessLauncher.Start(new ProcessLaunchSpec(
            cmd, Array.Empty<string>(), Path.GetTempPath(),
            new Dictionary<string, string>(), UseShellExecute: true)));
    }

    [Theory]
    [InlineData("C:\\a\\b.exe", true)]
    [InlineData("plain", true)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("a%b", false)]
    [InlineData("a!b", false)]
    [InlineData("a\"b", false)]
    [InlineData("a\nb", false)]
    public void Launcher_ArgumentSafety(string value, bool expected)
    {
        Assert.Equal(expected, ProcessLauncher.IsCommandArgumentSafe(value));
    }

    // ========================================================================================
    // Real OS binaries: architecture detection, hashing, target policy
    // ========================================================================================

    [Fact]
    public void ArchDetector_SystemBinaries()
    {
        var system32 = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(system32)) return;
        Assert.Equal(DebuggerArchitecture.X64,
            DebuggerArchitectureDetector.Detect(system32, DebuggerArchitecture.Auto));
        var syswow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "notepad.exe");
        if (File.Exists(syswow))
            Assert.Equal(DebuggerArchitecture.X86,
                DebuggerArchitectureDetector.Detect(syswow, DebuggerArchitecture.X64));
    }

    [Theory]
    [InlineData("missing.exe")]
    public void ArchDetector_Fallbacks(string name)
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        File.WriteAllText(Path.Combine(dir, "plain.txt"), "hello");
        Assert.Equal(DebuggerArchitecture.Auto,
            DebuggerArchitectureDetector.Detect(Path.Combine(dir, "plain.txt"), DebuggerArchitecture.Auto));
        Assert.Equal(DebuggerArchitecture.X86,
            DebuggerArchitectureDetector.Detect(Path.Combine(dir, name), DebuggerArchitecture.X86));
        var empty = Path.Combine(dir, "empty.exe");
        File.WriteAllBytes(empty, Array.Empty<byte>());
        Assert.Equal(DebuggerArchitecture.Auto,
            DebuggerArchitectureDetector.Detect(empty, DebuggerArchitecture.Auto));
    }

    [Fact]
    public void GhidraTarget_ValidateAndStage_DiskFile()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        var sample = Path.Combine(dir, "sample.exe");
        var payload = new byte[4096];
        Random.Shared.NextBytes(payload);
        File.WriteAllBytes(sample, payload);
        var info = GhidraTargetPolicy.Validate(sample);
        Assert.Equal("sample.exe", info.FileName);
        Assert.Equal(4096, info.Length);
        var staged = GhidraTargetPolicy.Stage(sample, Path.Combine(dir, "session"));
        Assert.NotNull(staged.StagedPath);
        Assert.True(File.Exists(staged.StagedPath));
        Assert.Equal(payload, File.ReadAllBytes(staged.StagedPath));
    }

    [Theory]
    [InlineData("sample.txt")]
    [InlineData("relative.exe")]
    [InlineData("")]
    public void GhidraTarget_RejectsBadPaths(string name)
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        if (name == "sample.txt") File.WriteAllText(Path.Combine(dir, name), "x");
        Assert.ThrowsAny<Exception>(() => GhidraTargetPolicy.Validate(
            name == "relative.exe" || name == "" ? name : Path.Combine(dir, name)));
    }

    [Fact]
    public async Task AddressMapping_OsBinaryHash_MatchesSha256()
    {
        var candidate = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(candidate)) return;
        var hash = await AddressMapping.ComputeBoundedModuleHashAsync(candidate, CancellationToken.None);
        Assert.NotNull(hash);
        Assert.Equal(64, hash.Length);
        using var stream = File.OpenRead(candidate);
        var expected = Convert.ToHexString(await System.Security.Cryptography.SHA256.HashDataAsync(stream, CancellationToken.None)).ToLowerInvariant();
        Assert.Equal(expected, hash);
        var cache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Assert.Equal(hash, await AddressMapping.HashModuleAsync(candidate, cache, CancellationToken.None));
        Assert.Equal(hash, await AddressMapping.HashModuleAsync(candidate, cache, CancellationToken.None));
    }

    // ========================================================================================
    // Pure launcher APIs: metrics, status, planning, coordinator
    // ========================================================================================

    [Fact]
    public void Metrics_TryParse_AcceptsMinimalDocument()
    {
        var doc = JsonSerializer.Deserialize<JsonElement>(
            "{\"schemaVersion\":3,\"httpRequests\":1,\"roundTrips\":2,\"toolCalls\":3,\"bytesReceived\":10,\"bytesSent\":20,\"uptimeSeconds\":1.5}");
        Assert.True(SessionMetricsClient.TryParse(doc, out var snapshot));
        Assert.NotNull(snapshot);
        Assert.Equal(1L, snapshot.HttpRequests);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":99,\"httpRequests\":1,\"roundTrips\":1,\"toolCalls\":0,\"bytesReceived\":10,\"bytesSent\":20,\"uptimeSeconds\":1.0}")]
    [InlineData("{\"schemaVersion\":3,\"httpRequests\":-1,\"roundTrips\":1,\"toolCalls\":0,\"bytesReceived\":10,\"bytesSent\":20,\"uptimeSeconds\":1.0}")]
    [InlineData("{\"schemaVersion\":3}")]
    [InlineData("[]")]
    public void Metrics_TryParse_RejectsBadDocuments(string json)
    {
        Assert.False(SessionMetricsClient.TryParse(JsonSerializer.Deserialize<JsonElement>(json), out _));
    }

    [Fact]
    public void MetricsClient_ValidatesArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SessionMetricsClient(0, Path.GetTempPath()));
        Assert.Throws<ArgumentException>(() => new SessionMetricsClient(LauncherDefaults.DefaultPort, ""));
        using var client = new SessionMetricsClient(LauncherDefaults.DefaultPort, Path.Combine(Path.GetTempPath(), "missing.json"));
        Assert.NotNull(client);
    }

    [Fact]
    public async Task MetricsClient_MissingConfig_ReturnsNull()
    {
        var previous = Environment.GetEnvironmentVariable("DBGLINK_BEARER_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("DBGLINK_BEARER_TOKEN", "not-a-token");
            using var metricsDir = TempDir.Create("dbglink-loopback-");
            using var client = new SessionMetricsClient(LauncherDefaults.DefaultPort, Path.Combine(metricsDir, "missing.json"));
            Assert.Null(await client.ReadAsync(CancellationToken.None));
        }
        finally { Environment.SetEnvironmentVariable("DBGLINK_BEARER_TOKEN", previous); }
    }

    [Fact]
    public void ToolkitDiagnostics_RedactsSecrets()
    {
        var redacted = ToolkitDiagnostics.Sanitize("Bearer abc123 failed at C:\\Secrets\\a.exe token=xyz");
        Assert.Contains("<redacted>", redacted);
        Assert.Contains("<redacted-path>", redacted);
        Assert.DoesNotContain("abc123", redacted);
        Assert.Equal("No error details were provided.", ToolkitDiagnostics.Sanitize("  "));
        var described = ToolkitDiagnostics.Describe(new ToolkitLaunchException(
            ToolkitComponent.Debugger, "starting", new IOException("boom")));
        Assert.Contains("Debugger", described);
        Assert.Contains("Cause: IOException", described);
        Assert.Equal("Native bridge", ToolkitComponentNames.Get(ToolkitComponent.NativeBridge));
    }

    [Fact]
    public void LauncherPlan_PipeNameAndDebuggerSpec()
    {
        var settings = new LauncherSettings("C:\\dbg\\x64dbg.exe", "C:\\dbg\\x32dbg.exe",
            "C:\\ghidra", ReverseMode.LetLlmChoose, null, Port: LauncherDefaults.DefaultPort);
        var paths = new ToolkitPaths("C:\\dbg\\x64dbg.exe", "C:\\dbg\\x32dbg.exe", "C:\\dbg\\x64dbg.exe",
            "C:\\ghidra", "C:\\ghidra\\launch.bat", "C:\\ghidra\\headless.bat", "C:\\dbg\\plugins",
            "C:\\dbg\\server.exe", "DbgLink.dp64", "C:\\dbg\\ext.zip", "C:\\java");
        var plan = new LauncherPlan(settings, paths);
        Assert.Equal("DbgLink.Control.1234", plan.PipeNameFor(1234));
        Assert.Throws<ArgumentOutOfRangeException>(() => plan.PipeNameFor(0));
        var spec = LauncherPlanner.CreateDebuggerSpec(plan, DebuggerArchitecture.X64, null);
        Assert.Equal("C:\\dbg\\x64dbg.exe", spec.FileName);
        Assert.Equal("1", spec.EnvironmentVariables["DBGLINK_SKIP_SERVER_AUTOSTART"]);
        Assert.Contains("CONTROL_PLANE_API_KEY", spec.RemoveEnvironmentVariables!);
        Assert.Contains("DBGLINK_BEARER_TOKEN", spec.RemoveEnvironmentVariables!);
        Assert.Throws<ArgumentOutOfRangeException>(() => LauncherPlanner.CreateDebuggerSpec(plan, DebuggerArchitecture.Auto, null));
    }

    [Fact]
    public async Task Coordinator_FreshState_IsIdle()
    {
        await using var coordinator = new ToolkitCoordinator();
        Assert.False(coordinator.IsRunning);
        Assert.Null(coordinator.GhidraEndpointDirectory);
        Assert.Null(coordinator.McpServerExitCode);
        Assert.Null(await coordinator.ReadMetricsAsync(CancellationToken.None));
        Assert.Equal(5, coordinator.StatusSnapshot.Count);
        Assert.All(coordinator.StatusSnapshot, update => Assert.Equal(ToolkitComponentState.Pending, update.State));
        coordinator.ReportRuntimeFailure(ToolkitComponent.Debugger, "boom");
        Assert.Contains(coordinator.StatusSnapshot,
            update => update.Component == ToolkitComponent.Debugger && update.State == ToolkitComponentState.Failed);
        await coordinator.DisposeAsync();
        await coordinator.DisposeAsync();
    }

    [Theory]
    [InlineData("{\"architecture\":\"x64\"}", DebuggerArchitecture.X64, false)]
    [InlineData("{\"architecture\":\"x86\"}", DebuggerArchitecture.X86, false)]
    [InlineData("{\"architecture\":\"bogus\"}", DebuggerArchitecture.Auto, true)]
    [InlineData("{}", DebuggerArchitecture.Auto, true)]
    public void Coordinator_SelectArchitecture_Validates(string json, DebuggerArchitecture expected, bool expectError)
    {
        var result = ToolkitCoordinator.SelectDebuggerArchitecture(JsonSerializer.Deserialize<JsonElement>(json));
        Assert.Equal(expectError, result.Error is not null);
        if (!expectError) Assert.Equal(expected, result.Architecture);
    }

    [Fact]
    public void Coordinator_SelectArchitecture_OnDiskFiles()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        File.WriteAllText(Path.Combine(dir, "plain.txt"), "hello");
        var missingArch = ToolkitCoordinator.SelectDebuggerArchitecture(JsonSerializer.SerializeToElement(new
        {
            architecture = "auto",
            path = Path.Combine(dir, "plain.txt")
        }));
        Assert.NotNull(missingArch.Error);
        var system32 = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(system32)) return;
        var matched = ToolkitCoordinator.SelectDebuggerArchitecture(JsonSerializer.SerializeToElement(new
        {
            architecture = "x64",
            path = system32
        }));
        Assert.Null(matched.Error);
        Assert.Equal(DebuggerArchitecture.X64, matched.Architecture);
    }

    // ========================================================================================
    // GhidraControlClient + shared pipe over real resources
    // ========================================================================================

    [Fact]
    public void GhidraControl_ValidatesConstruction()
    {
        var valid = new GhidraControlClient("DbgLink.GhidraControl.test", new string('a', 32));
        Assert.NotNull(valid);
        Assert.Throws<ArgumentException>(() => new GhidraControlClient("bad-pipe", new string('a', 32)));
        Assert.Throws<ArgumentException>(() => new GhidraControlClient("DbgLink.GhidraControl.test", "short"));
    }

    [Fact]
    public void GhidraControl_ValidateResponse_PassesSessionResult()
    {
        var ok = GhidraControlClient.ValidateResponse("{\"id\":1,\"ok\":true,\"result\":{}}", importing: false);
        Assert.Contains("\"ok\":true", ok);
        var bad = GhidraControlClient.ValidateResponse("{\"ok\":true}", importing: false);
        Assert.Contains("ghidra_control_protocol", bad);
    }

    [Fact]
    public async Task SharedPipe_Echo_RoundTrips()
    {
        var pipeName = "DbgLink.Loopback." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        var payload = StrictUtf8.GetBytes("{\"id\":7,\"method\":\"ping\"}\n");
        var requestTask = SharedPipe.RequestAsync(pipeName, payload, 1500, TimeSpan.FromSeconds(10), 64 * 1024, CancellationToken.None);
        await server.WaitForConnectionAsync(CancellationToken.None);
        var buffer = new byte[65536];
        int total = 0, read;
        do { read = await server.ReadAsync(buffer.AsMemory(total), CancellationToken.None); total += read; }
        while (!server.IsMessageComplete);
        await server.WriteAsync(buffer.AsMemory(0, total), CancellationToken.None);
        await server.FlushAsync(CancellationToken.None);
        Assert.Equal(payload, await requestTask);
    }

    [Fact]
    public async Task SharedPipe_RejectsBadArguments()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => SharedPipe.RequestAsync(
            "", new byte[] { 1 }, 1500, TimeSpan.FromSeconds(5), 1024, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => SharedPipe.RequestAsync(
            "DbgLink.Loopback.x", ReadOnlyMemory<byte>.Empty, 1500, TimeSpan.FromSeconds(5), 1024, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SharedPipe.RequestAsync(
            "DbgLink.Loopback.x", new byte[] { 1 }, 0, TimeSpan.FromSeconds(5), 1024, CancellationToken.None));
    }

    // ========================================================================================
    // Helpers
    // ========================================================================================

    // Test temp dirs are owned via TempDir (auto-deleted on Dispose).

    private static async Task<int> ReadRequestIdAsync(NamedPipeServerStream server)
    {
        var buffer = new byte[65536];
        using var ms = new MemoryStream();
        int read;
        do
        {
            read = await server.ReadAsync(buffer, CancellationToken.None);
            if (read == 0) break;
            ms.Write(buffer, 0, read);
        }
        while (!server.IsMessageComplete);
        using var doc = JsonDocument.Parse(StrictUtf8.GetString(ms.ToArray()));
        return doc.RootElement.GetProperty("id").GetInt32();
    }

    private static async Task DrainRequestAsync(NamedPipeServerStream server)
    {
        var buffer = new byte[65536];
        int read;
        do { read = await server.ReadAsync(buffer, CancellationToken.None); }
        while (read > 0 && !server.IsMessageComplete);
    }

    /// <summary>
    /// The bridge runs four connection workers with per-thread decompilers and
    /// a program read lock, but the client used to serialise every request
    /// behind one semaphore, so only one worker was ever busy. Two reads must
    /// reach the bridge while the first one is still open.
    /// </summary>
    [Fact]
    public async Task GhidraLoopback_ConcurrentReads_ReachTheBridgeAtTheSameTime()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-test.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('a', 32) + "\"}");
        using var client = new GhidraClient(dir);
        using var arrived = new CountdownEvent(2);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        async Task ServeAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var peer = await listener.AcceptTcpClientAsync(stop.Token);
                    _ = Task.Run(async () =>
                    {
                        using (peer)
                        {
                            await using var stream = peer.GetStream();
                            var id = await ReadGhidraRequestIdAsync(stream);
                            arrived.Signal();
                            // Hold the connection until both requests are in
                            // flight: a single-slot client lock can never get
                            // the second one here.
                            await release.Task.WaitAsync(stop.Token);
                            await WriteLineAsync(stream, "{\"id\":" + id + ",\"ok\":true,\"result\":{\"ok\":true}}");
                        }
                    });
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (System.Net.Sockets.SocketException) { }
        }

        var server = ServeAsync();
        var first = client.RequestAsync("InspectFunction",
            JsonSerializer.SerializeToElement(new { function = "alpha" }), CancellationToken.None);
        var second = client.RequestAsync("InspectFunction",
            JsonSerializer.SerializeToElement(new { function = "beta" }), CancellationToken.None);

        var overlapped = arrived.Wait(TimeSpan.FromSeconds(10));
        release.TrySetResult();
        var responses = await Task.WhenAll(first, second);

        Assert.True(overlapped,
            "the second Ghidra request never reached the bridge while the first was in flight: reads are serialised");
        Assert.All(responses, response => Assert.Contains("\"ok\":true", response));

        listener.Stop();
        await server;
    }

    /// <summary>
    /// Disposing the client must refuse new requests instead of throwing from a
    /// disposed semaphore, and must not fault a request that is already in
    /// flight (its finally block releases the semaphore).
    /// </summary>
    [Fact]
    public async Task GhidraLoopback_DisposeRefusesNewRequestsAndDoesNotFaultAnInFlightOne()
    {
        using var dir = TempDir.Create("dbglink-loopback-");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        File.WriteAllText(Path.Combine(dir, "ghidra-bridge-test.json"),
            "{\"host\":\"127.0.0.1\",\"port\":" + port + ",\"protocolVersion\":1,\"token\":\"" + new string('a', 32) + "\"}");
        var client = new GhidraClient(dir);

        var inFlight = client.RequestAsync("status", null, CancellationToken.None);
        using var peer = await listener.AcceptTcpClientAsync(CancellationToken.None);
        await using var stream = peer.GetStream();
        var id = await ReadGhidraRequestIdAsync(stream);

        client.Dispose();

        await WriteLineAsync(stream, "{\"id\":" + id + ",\"ok\":true,\"result\":{\"connected\":true}}");
        Assert.Contains("connected", await inFlight);

        var refused = await client.RequestAsync("status", null, CancellationToken.None);
        Assert.Contains("ghidra_unavailable", refused);
    }

    private static async Task WriteLineAsync(Stream stream, string text)
    {
        var bytes = StrictUtf8.GetBytes(text + "\n");
        await stream.WriteAsync(bytes, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
    }

    private static async Task<int> ReadGhidraRequestIdAsync(Stream stream)
    {
        var buffer = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(one, CancellationToken.None);
            if (read == 0) throw new IOException("EOF waiting for Ghidra request line.");
            if (one[0] == (byte)'\n') break;
            buffer.Add(one[0]);
        }
        using var doc = JsonDocument.Parse(StrictUtf8.GetString(buffer.ToArray()));
        return doc.RootElement.GetProperty("id").GetInt32();
    }
}
