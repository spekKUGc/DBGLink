using System.Text.Json;
using DbgLink.Server;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// A session id that died (replaced or closed by an earlier call) must not brick
/// every later tool call: when exactly one other session is live the dispatcher
/// uses it and says so in the response; zero or several live sessions stay a hard
/// error so an ambiguous request is never answered against the wrong target.
/// </summary>
public sealed class SessionFallbackTests
{
    private static McpToolDispatcher Build(out AnalysisSessionRegistry sessions)
    {
        var config = new ServerConfig { Port = 50399 };
        var bridge = new RecordingBridge();
        var ghidra = new NullGhidra();
        sessions = new AnalysisSessionRegistry(bridge, ghidra);
        var context = new AnalysisContext(bridge, ghidra);
        var sessionControl = new SessionControlTools(null, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(
            Path.Combine(Path.GetTempPath(), "dbglink-fallback-" + Guid.NewGuid().ToString("N"))));
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), new GhidraOpenOperations(null), sessionControl);
        return new McpToolDispatcher(config, registry, context, sessions, new ServerMetrics(),
            hasControl: false, NullLogger.Instance);
    }

    private static CallToolRequestParams Request(string analysisId) => new()
    {
        Name = "ListFunctions",
        Arguments = new Dictionary<string, JsonElement>
        {
            ["analysisId"] = JsonSerializer.SerializeToElement(analysisId)
        }
    };

    [Fact]
    public async Task Dead_id_falls_back_to_the_single_live_session_with_a_visible_note()
    {
        var dispatcher = Build(out var sessions);
        using var scope = sessions;
        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));

        var result = await dispatcher.CallAsync(Request("replaced-session"), CancellationToken.None);

        var text = Assert.IsType<TextContentBlock>(result.Content[0]).Text;
        Assert.Contains("replaced-session", text);
        Assert.Contains("live-one", text);
        Assert.Contains("ListAnalysisSessions", text);
    }

    [Fact]
    public async Task Dead_id_stays_an_error_when_no_other_session_is_live()
    {
        var dispatcher = Build(out var sessions);
        using var scope = sessions;

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => dispatcher.CallAsync(Request("replaced-session"), CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
        Assert.Contains("Active sessions:", error.Message);
    }

    [Fact]
    public async Task Dead_id_stays_an_error_when_several_sessions_are_live()
    {
        var dispatcher = Build(out var sessions);
        using var scope = sessions;
        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));
        Assert.True(sessions.TryRegister(new("live-two", "DbgLink.Control.43", Path.GetTempPath())));

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => dispatcher.CallAsync(Request("replaced-session"), CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
    }

    /// <summary>
    /// Mutating tools must never silently retarget: with exactly one live
    /// non-default session, a bogus id on SetRegister (Mutation) fails closed
    /// instead of driving the live session. Guards the SwitchDebugger
    /// debuggee-reset hazard (same dispatcher gate).
    /// </summary>
    [Fact]
    public async Task Mutating_tool_with_unknown_id_fails_closed_without_retarget()
    {
        var dispatcher = Build(out var sessions);
        using var scope = sessions;
        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));

        var request = new CallToolRequestParams
        {
            Name = "SetRegister",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["register"] = JsonSerializer.SerializeToElement("rax"),
                ["value"] = JsonSerializer.SerializeToElement("0x0"),
                ["analysisId"] = JsonSerializer.SerializeToElement("bogus-session")
            }
        };

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => dispatcher.CallAsync(request, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
        Assert.Contains("bogus-session", error.Message);
        Assert.DoesNotContain("using 'live-one'", error.Message);
    }

    /// <summary>
    /// Annotation tools are mutations too: a bogus id on BatchAnnotate
    /// fails closed with one live session, never retargeting it.
    /// (P3: single-op SetFunctionComment purged; the batch is the cover.)
    /// </summary>
    [Fact]
    public async Task Annotation_tool_with_unknown_id_fails_closed_without_retarget()
    {
        var dispatcher = Build(out var sessions);
        using var scope = sessions;
        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));

        var request = new CallToolRequestParams
        {
            Name = "BatchAnnotate",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["operations"] = JsonSerializer.SerializeToElement(new[]
                {
                    new { kind = "set_function_comment", function = "main", comment = "test" },
                }),
                ["analysisId"] = JsonSerializer.SerializeToElement("bogus-session")
            }
        };

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => dispatcher.CallAsync(request, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
    }

    /// <summary>
    /// Read-only fallback on a JSON-object payload must stay strict-JSON
    /// parseable: the note rides as additive sessionNote/resolvedAnalysisId
    /// fields, never as a text prefix.
    /// </summary>
    [Fact]
    public void Read_fallback_on_json_object_keeps_strict_json_with_note_field()
    {
        const string note = "Unknown session 'bogus-session'; using 'live-one'.";
        var result = McpToolDispatcher.FallbackNotedResult("{\"ok\":true,\"result\":{\"functions\":[]}}", note, "live-one", false);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("sessionNote", out var noteProp));
        Assert.Contains("bogus-session", noteProp.GetString());
        Assert.Contains("live-one", noteProp.GetString());
        Assert.True(root.TryGetProperty("resolvedAnalysisId", out var resolved));
        Assert.Equal("live-one", resolved.GetString());
        // The payload itself is preserved alongside the note.
        Assert.True(root.TryGetProperty("result", out _));
    }

    [Fact]
    public void Active_session_annotation_is_additive_and_names_the_flip()
    {
        const string raw = "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true,\"analysisId\":\"analysis-new\",\"nativePipeName\":\"DbgLink.Control.42\",\"ghidraEndpointDirectory\":\"C:\\\\tmp\"}}";
        var annotated = McpToolDispatcher.AnnotateActiveSession(raw, "analysis-new", "analysis-new");
        using var document = JsonDocument.Parse(annotated);
        var result = document.RootElement.GetProperty("result");
        Assert.Equal("analysis-new", result.GetProperty("activeAnalysisId").GetString());
        Assert.Contains("analysis-new", result.GetProperty("sessionNote").GetString());
        // Original keys survive.
        Assert.Equal("analysis-new", result.GetProperty("analysisId").GetString());
    }

    /// <summary>
    /// SwitchDebugger must never silently retarget: with one live session, a
    /// bogus id fails closed and the control pipe is never hit, so the live
    /// debuggee is not reset/killed.
    /// </summary>
    [Fact]
    public async Task OpenDebugTarget_with_unknown_id_fails_closed_without_touching_live_session()
    {
        var config = new ServerConfig { Port = 50399 };
        var bridge = new RecordingBridge();
        var ghidra = new NullGhidra();
        var sessions = new AnalysisSessionRegistry(bridge, ghidra);
        using var scope = sessions;
        var context = new AnalysisContext(bridge, ghidra);
        var control = new RecordingSessionControl();
        var sessionControl = new SessionControlTools(control, sessions, context);
        var live = new LiveAnalysisTools(context, sessionControl);
        var investigation = new InvestigationTools(context, live);
        var checkpoints = new CheckpointTools(new CheckpointStore(
            Path.Combine(Path.GetTempPath(), "dbglink-fallback-" + Guid.NewGuid().ToString("N"))));
        var registry = new ToolRegistry(context, checkpoints, live, investigation,
            new AddressMapping(context), new GhidraOpenOperations(null), sessionControl);
        var dispatcher = new McpToolDispatcher(config, registry, context, sessions, new ServerMetrics(),
            hasControl: true, NullLogger.Instance);

        Assert.True(sessions.TryRegister(new("live-one", "DbgLink.Control.42", Path.GetTempPath())));

        var request = new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\fake\\target.exe"),
                ["architecture"] = JsonSerializer.SerializeToElement("x64"),
                ["analysisId"] = JsonSerializer.SerializeToElement("bogus-session")
            }
        };

        var error = await Assert.ThrowsAsync<McpProtocolException>(
            () => dispatcher.CallAsync(request, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("was not found", error.Message);
        Assert.Equal(0, control.CallCount);
        // Live session untouched and still resolvable.
        Assert.Equal("live-one", sessions.Resolve("live-one").AnalysisId);
    }

    private sealed class RecordingSessionControl : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public int CallCount;
        public Task<string> OpenFileAsync(string path, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true}");
        public Task<string> SessionControlAsync(string method, JsonElement arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            return Task.FromResult("{\"ok\":true,\"result\":{}}");
        }
    }
}
