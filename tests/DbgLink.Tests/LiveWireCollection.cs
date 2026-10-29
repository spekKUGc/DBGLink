namespace DbgLink.Tests;

/// <summary>
/// Serializes every test class that binds real OS resources: a real Kestrel
/// HTTP host (via <c>RealServerHarness</c>, <c>LocalMcpServer.RunAsync</c>, or
/// <c>Program.RunAsync</c>), a real Win32 message-mode named pipe (via
/// <c>NamedPipeServerStream</c> / <c>RealNativePipeServer</c>), the real Ghidra
/// TCP/control pipes, or an extra OS process. Under parallel load these
/// contend (ephemeral ports, pipe instances, startup timing) and flake with a
/// different victim per run; each passes in isolation. Keeping them in one
/// collection with <c>DisableParallelization = true</c> runs them
/// sequentially against each other while the rest of the suite still runs in
/// parallel. Do NOT add pure in-process <c>LocalMcpServer</c> tests here.
/// </summary>
[CollectionDefinition("LiveWire", DisableParallelization = true)]
public sealed class LiveWireCollection;
