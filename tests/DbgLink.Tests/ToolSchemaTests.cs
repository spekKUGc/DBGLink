using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace DbgLink.Tests;

public sealed class ToolSchemaTests
{
    private readonly ITestOutputHelper _output;

    public ToolSchemaTests(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData("ReadMemAtAddress", "{\"address\":\"0x1000\",\"byteCount\":65537}")]
    [InlineData("ReadMemAtAddress", "{\"address\":\"0x1000\",\"byteCount\":4097}")]
    [InlineData("ReadStaticBytes", "{\"address\":\"0x140001000\",\"length\":32769}")]
    [InlineData("ReadMemAtAddress", "{\"address\":\"0x1000\",\"byteCount\":1.0}")]
    [InlineData("ReadMemAtAddress", "{\"address\":\" \"}")]
    [InlineData("FindBytePatternInModule", "{\"pattern\":\"?? ??\"}")]
    [InlineData("TraceUntil", "{\"count\":0,\"kind\":\"into\"}")]
    [InlineData("TraceUntil", "{\"count\":0}")]
    [InlineData("TraceUntil", "{\"maxSteps\":0}")]
    [InlineData("CreateCheckpoint", "{\"unexpected\":true}")]
    public async Task Invalid_arguments_never_reach_a_backend(string name, string json)
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);
        var arguments = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name, Arguments = arguments }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, bridge.RequestCount);
    }

    [Fact]
    public void Advertised_numeric_limits_are_the_limits_used_by_validation()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>().Single(x => x["name"]!.GetValue<string>() == "ReadMemAtAddress");
        var schema = (JsonObject)tool["inputSchema"]!;
        var maximum = schema["properties"]!["byteCount"]!["maximum"]!.GetValue<int>();
        Assert.Null(ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { address = "0x1000", byteCount = maximum })));
        Assert.NotNull(ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { address = "0x1000", byteCount = maximum + 1 })));
    }

    [Theory]
    [InlineData("BatchAnnotate")]
    [InlineData("SubmitAnnotations")]
    public async Task Disabled_capabilities_are_hidden_and_cannot_be_called(string name)
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowAnnotation = false, AllowMutation = false }, new RecordingBridge());
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), x => x["name"]!.GetValue<string>() == name);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Contains("capability", error.Message);
    }

    [Theory]
    [InlineData("RenameFunction")]
    [InlineData("SetFunctionComment")]
    [InlineData("UpdateVariable")]
    [InlineData("CreateFunction")]
    [InlineData("SaveProgram")]
    [InlineData("TriageImports")]
    [InlineData("TriageStrings")]
    [InlineData("SwitchDebugger")]
    [InlineData("CallFunction")]
    [InlineData("SwitchThread")]
    [InlineData("FindBytePatternInModule")]
    [InlineData("ListBreakpoints")]
    [InlineData("CreateCheckpoint")]
    [InlineData("GetLastCheckpoint")]
    [InlineData("InspectFunctionContext")]
    [InlineData("DumpStrings")]
    public async Task Purged_tools_are_unknown(string name)
    {
        // Physically removed tools are undiscoverable AND uncallable:
        // the dispatcher reports unknown_tool (not a capability gate).
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        Assert.DoesNotContain(server.ListTools().OfType<JsonObject>(), x => x["name"]!.GetValue<string>() == name);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = name }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.StartsWith("Unknown tool", error.Message);
    }

    [Fact]
    public void Single_standard_catalog_advertises_curated_suite()
    {
        using var serverComp = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Comprehensive }, new RecordingBridge());
        using var serverLean = new LocalMcpServer(new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());

        var compTools = serverComp.ListTools().OfType<JsonObject>().Select(x => x["name"]!.GetValue<string>()).ToHashSet();
        var leanTools = serverLean.ListTools().OfType<JsonObject>().Select(x => x["name"]!.GetValue<string>()).ToHashSet();

        // Single standard: profile flag is ignored, both lists are identical.
        Assert.Equal(compTools, leanTools);
        Assert.True(compTools.Count >= 30, $"Expected >= 30 tools in standard catalog, got {compTools.Count}");

        // Essential reversing tools must be present
        Assert.Contains("GetAnalysisSnapshot", compTools);
        Assert.Contains("GetModuleMap", compTools);
        Assert.DoesNotContain("StepAndInspect", compTools);
        Assert.Contains("TraceUntil", compTools);
        Assert.Contains("InspectFunction", compTools);
        Assert.Contains("GetInvestigationBrief", compTools);
        Assert.Contains("Triage", compTools);
        // Pre-merge names are hidden aliases: undiscoverable, still callable.
        Assert.DoesNotContain("TriageImports", compTools);
        Assert.DoesNotContain("TriageStrings", compTools);
        Assert.Contains("ReadMemAtAddress", compTools);
        Assert.Contains("InspectAddressStructure", compTools);
        Assert.Contains("EvaluateExpressions", compTools);
        Assert.DoesNotContain("EvaluateExpression", compTools);
        Assert.Contains("SetBreakpoint", compTools);
        Assert.Contains("ClearBreakpoint", compTools);
        Assert.Contains("ControlDebuggerExecution", compTools);
        Assert.DoesNotContain("RunDebugger", compTools);
        Assert.DoesNotContain("PauseDebugger", compTools);
        Assert.DoesNotContain("CancelGhidraOpen", compTools);

        // Obsolete/redundant tools are purged physically from all profiles
        var purgedTools = new[]
        {
            "ContinueDebugger", "StepInto", "StepOver", "StepOut",
            "SetBookmark", "SetComment", "SetLabel",
            "ReadMemoryChunk", "ReadDisassemblyChunk",
            "FindInterestingStrings", "TraceStringReferences", "GetFunctionContext"
        };
        foreach (var purged in purgedTools)
        {
            Assert.DoesNotContain(purged, compTools);
            Assert.DoesNotContain(purged, leanTools);
        }

        // Single standard: one catalog, no lean/comprehensive split.
        var compChars = serverComp.ListTools().ToJsonString().Length;
        var leanChars = serverLean.ListTools().ToJsonString().Length;
        _output.WriteLine($"Schema chars: standard={compChars}, alias={leanChars}");
        Assert.Equal(compChars, leanChars);

        var fullBreakpoint = serverComp.ListTools().OfType<JsonObject>()
            .Single(tool => tool["name"]!.GetValue<string>() == "SetBreakpoint");
        Assert.NotNull(fullBreakpoint["inputSchema"]!["examples"]);
        Assert.NotNull(fullBreakpoint["inputSchema"]!["properties"]!["kind"]!["description"]);
    }

    [Fact]
    public async Task Non_advertised_tools_remain_callable()
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Lean }, bridge);

        // SampleCallStacks is not advertised in tools/list, but must still execute when requested!
        var result = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "SampleCallStacks",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["maxSamples"] = JsonSerializer.SerializeToElement(2)
            }
        }, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(1, bridge.RequestCount);
    }

    [Fact]
    public async Task Lean_schema_projection_does_not_change_tool_argument_validation()
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, Profile = ToolProfile.Lean }, bridge);

        await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "SetBreakpoint",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x140001000"),
                ["kind"] = JsonSerializer.SerializeToElement("hw"),
                ["hwType"] = JsonSerializer.SerializeToElement("x"),
                ["hwSize"] = JsonSerializer.SerializeToElement(1)
            }
        }, CancellationToken.None);

        Assert.Equal(1, bridge.RequestCount);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Single_catalog_is_identical_across_capability_filters(bool hasControl, bool allowMutation)
    {
        var control = hasControl ? new SchemaControl() : null;
        using var comprehensive = new LocalMcpServer(new ServerConfig
        {
            Port = ServerConfig.DefaultPort,
            Profile = ToolProfile.Comprehensive,
            AllowAnnotation = false,
            AllowMutation = allowMutation
        }, new RecordingBridge(), ghidraControl: control);
        using var lean = new LocalMcpServer(new ServerConfig
        {
            Port = 50302,
            Profile = ToolProfile.Lean,
            AllowAnnotation = false,
            AllowMutation = allowMutation
        }, new RecordingBridge(), ghidraControl: control);

        var comprehensiveChars = comprehensive.ListTools().ToJsonString().Length;
        var leanChars = lean.ListTools().ToJsonString().Length;

        // Single standard catalog: profile flag must not change the payload.
        Assert.Equal(comprehensiveChars, leanChars);
    }

    private sealed class SchemaControl : IGhidraControlClient
    {
        public bool SupportsSessionControl => true;
        public Task<string> OpenFileAsync(string path, CancellationToken token) => Task.FromResult("{\"ok\":true}");
    }

    [Fact]
    public async Task Physically_purged_tools_cannot_be_called()
    {
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "StepInto",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["count"] = JsonSerializer.SerializeToElement(1)
                }
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
    }

    [Fact]
    public void Annotation_only_filter_hides_singles_but_keeps_batch_annotate()
    {
        // Verified in ToolRegistry.Definitions: RenameFunction and
        // UpdateVariable are ToolCapability.Mutation; SetFunctionComment is
        // ToolCapability.Annotation. All four single-op tools are hidden from
        // discovery (BatchAnnotate/SubmitAnnotations are the strict superset);
        // the batch stays advertised.
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowAnnotation = false, AllowMutation = true }, new RecordingBridge());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        // Annotation-gated tool hidden…
        Assert.DoesNotContain("SetFunctionComment", names);
        // …and the single-op mutation tools stay hidden too (use the batch)…
        Assert.DoesNotContain("RenameFunction", names);
        Assert.DoesNotContain("UpdateVariable", names);
        Assert.DoesNotContain("CreateFunction", names);
        // …while the batch superset stays advertised.
        Assert.Contains("BatchAnnotate", names);
        Assert.Contains("SubmitAnnotations", names);
    }

    [Fact]
    public void Mutation_only_filter_hides_mutations_and_singles()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowAnnotation = true, AllowMutation = false }, new RecordingBridge());
        var names = server.ListTools().OfType<JsonObject>()
            .Select(x => x["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("RenameFunction", names);
        Assert.DoesNotContain("UpdateVariable", names);
        Assert.DoesNotContain("CreateFunction", names);
        Assert.DoesNotContain("BatchAnnotate", names);
        Assert.DoesNotContain("SubmitAnnotations", names);
        // The hidden single-op annotation tool stays hidden (use the batch).
        Assert.DoesNotContain("SetFunctionComment", names);
    }

    [Fact]
    public void Advertised_static_length_limit_is_the_limit_used_by_validation()
    {
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, new RecordingBridge());
        var tool = server.ListTools().OfType<JsonObject>().Single(x => x["name"]!.GetValue<string>() == "ReadStaticBytes");
        var schema = (JsonObject)tool["inputSchema"]!;
        var maximum = schema["properties"]!["length"]!["maximum"]!.GetValue<int>();
        Assert.Null(ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { address = "0x140001000", length = maximum })));
        Assert.NotNull(ToolArgumentRules.Validate(schema, JsonSerializer.SerializeToElement(new { address = "0x140001000", length = maximum + 1 })));
    }

    [Fact]
    public async Task Advertised_byteCount_maximum_passes_end_to_end_while_max_plus_one_is_rejected()
    {
        // The schema advertises maximum 4096 (ToolRegistry.Definitions):
        // 4096 must reach the backend, 4097 must be rejected before any
        // backend call. Catches schema/execution skew in either direction.
        var bridge = new FixedResponseBridge("{\"ok\":true,\"text\":\"deadbeef\"}");
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

        var ok = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "ReadMemAtAddress",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("0x1000"),
                ["byteCount"] = JsonSerializer.SerializeToElement(4096)
            }
        }, CancellationToken.None);
        Assert.False(ok.IsError);

        var counting = new RecordingBridge();
        using var rejecting = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, counting);
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => rejecting.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "ReadMemAtAddress",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["address"] = JsonSerializer.SerializeToElement("0x1000"),
                    ["byteCount"] = JsonSerializer.SerializeToElement(4097)
                }
            }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.Equal(0, counting.RequestCount);
    }

    [Fact]
    public async Task Unknown_tool_error_does_not_echo_the_name_or_touch_a_backend()
    {
        // Verified in McpToolDispatcher: the message is a fixed "Unknown tool."
        // (plus an optional Did-you-mean hint); the requested name is never
        // echoed, so hostile names cannot be reflected into error text.
        var bridge = new RecordingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = ServerConfig.DefaultPort }, bridge);

        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams { Name = "NoSuchTool_Xyz; DROP TABLE" }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        Assert.StartsWith("Unknown tool", error.Message);
        Assert.DoesNotContain("DROP TABLE", error.Message);
        Assert.Equal(0, bridge.RequestCount);
    }

    // Single standard catalog: every advertised tool keeps its tool-level
    // description (it explains the contract).
    [Fact]
    public void Standard_catalog_keeps_tool_level_descriptions()
    {
        using var server = new LocalMcpServer(
            new ServerConfig { Port = 50302, Profile = ToolProfile.Lean }, new RecordingBridge());
        foreach (var tool in server.ListTools().OfType<JsonObject>())
        {
            var name = tool["name"]!.GetValue<string>();
            Assert.False(string.IsNullOrWhiteSpace(tool["description"]?.GetValue<string>()),
                $"{name}: standard tool text must stay (it explains the contract).");
        }
    }

    // Bound dedup: minLength 1 under x-nonblank is not repeated, and no
    // vendor key except the validation-shaping three may reach the wire.
    // Validation behavior is unchanged (ToolArgumentRules still enforces it),
    // so this guards bytes, not semantics.
    [Theory]
    [InlineData("comprehensive")]
    [InlineData("lean")]
    public void Advertised_schemas_do_not_repeat_implied_bounds(string profileName)
    {
        var profile = profileName == "lean" ? ToolProfile.Lean : ToolProfile.Comprehensive;
        using var server = new LocalMcpServer(
            new ServerConfig { Port = profile == ToolProfile.Lean ? 50302 : ServerConfig.DefaultPort, Profile = profile },
            new RecordingBridge());
        foreach (var tool in server.ListTools().OfType<JsonObject>())
            AssertNoStrayVendorKeys(tool["name"]!.GetValue<string>(), tool["inputSchema"]!, "inputSchema");
    }

    private static void AssertNoStrayVendorKeys(string tool, JsonNode? node, string path)
    {
        if (node is JsonObject obj)
        {
            foreach (var property in obj)
            {
                if (property.Key.StartsWith("x-", StringComparison.Ordinal) &&
                    property.Key is not ("x-multiline" or "x-requiresAnyOf" or "x-exclusiveAddressRanges"))
                    Assert.Fail($"{tool} at {path}: stray vendor key {property.Key} reached the wire.");
                AssertNoStrayVendorKeys(tool, property.Value, $"{path}.{property.Key}");
            }
        }
        else if (node is JsonArray array)
        {
            for (var index = 0; index < array.Count; index++)
                AssertNoStrayVendorKeys(tool, array[index], $"{path}[{index}]");
        }
    }

    private static IEnumerable<string> SchemaDescriptions(JsonNode? node, string path)
    {
        if (node is JsonObject obj)
        {
            if (obj["description"] is not null)
                yield return path;
            foreach (var property in obj)
                foreach (var found in SchemaDescriptions(property.Value, $"{path}.{property.Key}"))
                    yield return found;
        }
        else if (node is JsonArray array)
        {
            for (var index = 0; index < array.Count; index++)
                foreach (var found in SchemaDescriptions(array[index], $"{path}[{index}]"))
                    yield return found;
        }
    }
}
