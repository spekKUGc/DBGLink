using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;

namespace DbgLink.Tests;

public sealed class AnalysisSessionRegistryTests
{
    [Fact]
    public void Omitted_id_selects_latest_opened_session_and_explicit_default_still_works()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.Equal("default", registry.Resolve(null).AnalysisId);
        Assert.True(registry.TryRegister(new("first", "DbgLink.Control.42", Path.GetTempPath())));
        Assert.Equal("first", registry.Resolve(null).AnalysisId);
        Assert.True(registry.TryRegister(new("second", "DbgLink.Control.43", Path.GetTempPath())));
        Assert.Equal("second", registry.Resolve(null).AnalysisId);
        Assert.Equal("first", registry.Resolve("first").AnalysisId);
        Assert.Equal("default", registry.Resolve("default").AnalysisId);
        Assert.False(registry.TryRegister(new("invalid", "bad", Path.GetTempPath())));
        Assert.Equal("second", registry.Resolve(null).AnalysisId);
    }

    [Theory]
    [InlineData("DbgLink.Control.0")]
    [InlineData("DbgLink.Control.2147483648")]
    [InlineData("DbgLink.Control.00042")]
    public void Register_rejects_a_pipe_name_that_cannot_be_a_live_process_pipe(string pipeName)
    {
        var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var descriptor = new AnalysisSessionDescriptor("secondary", pipeName, Path.GetTempPath());

        Assert.False(registry.TryRegister(descriptor));
    }

    [Fact]
    public void Register_rejects_a_pipe_name_without_a_numeric_suffix()
    {
        var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var descriptor = new AnalysisSessionDescriptor(
            "secondary",
            "DbgLink.Control.",
            Path.GetTempPath());

        Assert.False(registry.TryRegister(descriptor));
    }

    [Fact]
    public void Register_rejects_a_missing_endpoint_directory()
    {
        var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var descriptor = new AnalysisSessionDescriptor(
            "secondary",
            "DbgLink.Control.42",
            Path.Combine(Path.GetTempPath(), "dbglink-missing-endpoint-" + Guid.NewGuid().ToString("N")));

        Assert.False(registry.TryRegister(descriptor));
    }

    [Fact]
    public void Register_is_idempotent_for_the_same_session_descriptor()
    {
        var endpoint = Path.Combine(
            Path.GetTempPath(),
            "dbglink-registry-endpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(endpoint);
        try
        {
            var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
            var descriptor = new AnalysisSessionDescriptor(
                "secondary",
                "DbgLink.Control.42",
                endpoint);

            Assert.True(registry.TryRegister(descriptor));
            Assert.True(registry.TryRegister(descriptor));
        }
        finally
        {
            if (Directory.Exists(endpoint))
                Directory.Delete(endpoint, recursive: true);
        }
    }

    [Fact]
    public void Register_rejects_a_different_descriptor_with_an_existing_analysis_id()
    {
        var endpoint = Path.Combine(
            Path.GetTempPath(),
            "dbglink-registry-conflict-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(endpoint);
        try
        {
            var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
            var first = new AnalysisSessionDescriptor(
                "secondary",
                "DbgLink.Control.42",
                endpoint);
            var conflicting = first with { NativePipeName = "DbgLink.Control.43" };

            Assert.True(registry.TryRegister(first));
            Assert.False(registry.TryRegister(conflicting));
        }
        finally
        {
            if (Directory.Exists(endpoint))
                Directory.Delete(endpoint, recursive: true);
        }
    }

    [Fact]
    public void Dispose_removes_registered_sessions_and_rejects_new_registrations()
    {
        var endpoint = Path.Combine(
            Path.GetTempPath(),
            "dbglink-registry-dispose-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(endpoint);
        try
        {
            var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
            var descriptor = new AnalysisSessionDescriptor(
                "secondary",
                "DbgLink.Control.42",
                endpoint);

            Assert.True(registry.TryRegister(descriptor));
            Assert.NotNull(registry.Resolve("secondary"));

            registry.Dispose();

            Assert.Throws<AnalysisSessionNotFoundException>(() => registry.Resolve("secondary"));
            Assert.False(registry.TryRegister(descriptor));
            registry.Dispose();
        }
        finally
        {
            if (Directory.Exists(endpoint))
                Directory.Delete(endpoint, recursive: true);
        }
    }

    [Fact]
    public void Unknown_close_ids_do_not_grow_gate_or_closed_state()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        for (var index = 0; index < 1000; index++)
            registry.Close("ghost-" + index);

        Assert.Equal(0, registry.GateCount);
        Assert.InRange(registry.ClosedCount, 1, 256);
    }

    [Fact]
    public void Mcp_responses_never_expose_the_native_pipe_token()
    {
        const string raw = "{\"ok\":true,\"result\":{\"opened\":true,\"analysisId\":\"analysis-1\"," +
            "\"nativePipeName\":\"DbgLink.Control.42\",\"nativePipeToken\":\"super-secret-token\",\"program\":{\"functionCount\":4}}}";

        var redacted = ToolSupport.RedactSessionSecrets(raw);

        Assert.DoesNotContain("nativePipeToken", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-token", redacted, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(redacted);
        Assert.Equal("DbgLink.Control.42", document.RootElement.GetProperty("result").GetProperty("nativePipeName").GetString());
        Assert.Equal(4, document.RootElement.GetProperty("result").GetProperty("program").GetProperty("functionCount").GetInt32());
    }

    [Fact]
    public void Read_rejects_duplicate_properties_in_session_response()
    {
        const string response = "{\"ok\":true,\"result\":{\"analysisId\":\"first\",\"analysisId\":\"second\",\"nativePipeName\":\"DbgLink.Control.42\",\"ghidraEndpointDirectory\":\"C:\\\\Temp\"}}";

        Assert.False(AnalysisSessionResponse.TryRead(response, out var descriptor));
        Assert.Null(descriptor);
    }

    [Fact]
    public void Dead_id_resolves_only_when_exactly_one_other_session_is_live()
    {
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());

        Assert.False(registry.TryResolveWithFallback("replaced", out var withoutSessions, out var noSessionsNote));
        Assert.Null(withoutSessions);
        Assert.Null(noSessionsNote);

        Assert.True(registry.TryRegister(new("only", "DbgLink.Control.44", Path.GetTempPath())));
        Assert.True(registry.TryResolveWithFallback("replaced", out var fallback, out var note));
        Assert.Equal("only", fallback!.AnalysisId);
        Assert.Contains("replaced", note);
        Assert.Contains("only", note);

        Assert.True(registry.TryResolveWithFallback("only", out var exact, out var exactNote));
        Assert.Equal("only", exact!.AnalysisId);
        Assert.Null(exactNote);

        Assert.True(registry.TryRegister(new("second", "DbgLink.Control.45", Path.GetTempPath())));
        Assert.False(registry.TryResolveWithFallback("replaced", out var ambiguous, out var ambiguousNote));
        Assert.Null(ambiguous);
        Assert.Null(ambiguousNote);
    }

    // Live-bug regression: the launcher forwards the N1 rendezvous pipe name
    // verbatim in full `\\.\pipe\...` form plus the per-session native token.
    // Registration must accept that exact descriptor, store the bare name the
    // pipe client dials, and authenticate the session bridge with the token.
    [Fact]
    public void Register_accepts_the_launcher_full_pipe_path_with_its_native_token()
    {
        const string token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        var descriptor = new AnalysisSessionDescriptor(
            "analysis-repro1",
            @"\\.\pipe\DbgLink.Control.1234.abcdef12",
            Path.GetTempPath(),
            token);

        Assert.True(registry.TryRegister(descriptor));

        var runtime = registry.Resolve("analysis-repro1");
        Assert.Equal("DbgLink.Control.1234.abcdef12", runtime.NativePipeName);
        Assert.Equal(token, runtime.NativePipeToken);
        var bridge = Assert.IsType<BridgeClient>(runtime.Bridge);
        Assert.Equal(token, bridge.PipeToken);
        Assert.True(bridge.RequiresPipeToken);
        Assert.Contains("analysis-repro1", registry.ActiveIds);
        Assert.Equal("default", registry.Resolve("default").AnalysisId);
        // The same launcher descriptor re-registers idempotently.
        Assert.True(registry.TryRegister(descriptor));
    }

    [Fact]
    public void Session_response_round_trips_the_launcher_wire_with_token()
    {
        const string token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var payload = new JsonObject
        {
            ["ok"] = true,
            ["result"] = new JsonObject
            {
                ["analysisId"] = "analysis-rt",
                ["nativePipeName"] = @"\\.\pipe\DbgLink.Control.4321.abcdef01",
                ["nativePipeToken"] = token,
                ["ghidraEndpointDirectory"] = Path.GetTempPath()
            }
        }.ToJsonString();

        Assert.True(AnalysisSessionResponse.TryRead(payload, out var descriptor));
        Assert.NotNull(descriptor);
        Assert.Equal(token, descriptor!.NativePipeToken);

        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());
        Assert.True(registry.TryRegister(descriptor));
        Assert.Equal("analysis-rt", registry.Resolve("analysis-rt").AnalysisId);
        Assert.Contains("analysis-rt", registry.ActiveIds);
    }

    [Fact]
    public void Session_response_rejects_a_non_string_native_token()
    {
        var payload = new JsonObject
        {
            ["ok"] = true,
            ["result"] = new JsonObject
            {
                ["analysisId"] = "analysis-rt",
                ["nativePipeName"] = "DbgLink.Control.4321",
                ["nativePipeToken"] = 42,
                ["ghidraEndpointDirectory"] = Path.GetTempPath()
            }
        }.ToJsonString();

        Assert.False(AnalysisSessionResponse.TryRead(payload, out var descriptor));
        Assert.Null(descriptor);
    }

    [Fact]
    public void ReplaceBridge_accepts_the_launcher_full_pipe_path_with_its_native_token()
    {
        const string token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        using var registry = new AnalysisSessionRegistry(new RecordingBridge(), new NullGhidra());

        registry.ReplaceBridge("default", @"\\.\pipe\DbgLink.Control.42.abcdef12", token);

        var runtime = registry.Resolve("default");
        Assert.Equal("DbgLink.Control.42.abcdef12", runtime.NativePipeName);
        var bridge = Assert.IsType<BridgeClient>(runtime.Bridge);
        Assert.Equal(token, bridge.PipeToken);
        Assert.True(bridge.RequiresPipeToken);
    }
}
