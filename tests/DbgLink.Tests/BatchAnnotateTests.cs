using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

/// <summary>
/// I-02 BatchAnnotate: schema/gate pins plus the wire contract of the slim
/// batch ack (indexed results, counts, message cap, no fat echoes) and
/// top-level error passthrough.
/// </summary>
[SupportedOSPlatform("windows")]
[Collection("LiveWire")]
public sealed class BatchAnnotateTests
{
    private static readonly string FatSha = new('a', 64);

    private static JsonElement Ops(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static LocalMcpServer CreateServer(bool allowMutation = true)
        => new(
            new ServerConfig { Port = ServerConfig.DefaultPort, AllowMutation = allowMutation },
            new RecordingBridge(),
            new NullGhidra());

    private static string BuildOperations(int count)
    {
        var operations = Enumerable.Range(0, count)
            .Select(index => $"{{\"kind\":\"rename_function\",\"function\":\"f{index}\",\"name\":\"n{index}\"}}");
        return $"{{\"operations\":[{string.Join(',', operations)}]}}";
    }

    [Fact]
    public void Schema_rejects_unknown_kind_oversized_batch_and_closed_envelope()
    {
        using var server = CreateServer();

        // Single-op envelopes of each kind pass; empty comment is a valid clear.
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"rename_function","function":"FixtureCaller","name":"fixture_caller"}]}""")));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"create_function","function":"0x140001000","name":"my_func"}]}""")));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"create_function","function":"0x140001000"}]}""")));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"set_function_comment","function":"f","comment":""}]}""")));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"rename_variable","function":"f","variable":"local_1","name":"counter"}]}""")));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"set_variable_type","function":"f","variable":"local_1","type":"int"}]}""")));

        // Unknown kind fails the enum rule before any backend call.
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"delete_function","function":"f"}]}""")));
        // kind and function are required per operation.
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"function":"f","name":"n"}]}""")));
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"rename_function"}]}""")));
        // The per-operation envelope is closed.
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops(
            """{"operations":[{"kind":"rename_function","function":"f","name":"n","extra":1}]}""")));
        // 1..16 operations, and the outer envelope is closed too.
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops("""{"operations":[]}""")));
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops("""{"operations":[{"kind":"rename_function","function":"f","name":"n"}],"extra":1}""")));
        Assert.NotNull(server.ValidateArguments("BatchAnnotate", Ops(BuildOperations(17))));
        Assert.Null(server.ValidateArguments("BatchAnnotate", Ops(BuildOperations(16))));
    }

    [Fact]
    public async Task Mutation_gate_hides_and_disables_batch_annotate()
    {
        using var server = CreateServer(allowMutation: false);

        Assert.DoesNotContain("BatchAnnotate", server.ListTools().OfType<JsonObject>()
            .Select(tool => tool["name"]!.GetValue<string>()));

        var ex = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "BatchAnnotate",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["operations"] = Ops("""[{"kind":"rename_function","function":"f","name":"n"}]""")
                }
            }, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidParams, ex.ErrorCode);
        Assert.Contains("Mutation", ex.Message);
        Assert.Contains("AllowMutation", ex.Message);
    }

    [Fact]
    public async Task Wire_ack_keeps_indexed_results_and_strips_fat_fields()
    {
        await using var harness = await RealServerHarness.StartAsync();
        var capturedRequest = "";
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, args) =>
        {
            capturedRequest = args?.GetRawText() ?? "";
            return JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    success = true,
                    applied = 3,
                    failed = 1,
                    results = new object[]
                    {
                        new
                        {
                            index = 0, kind = "rename_function", function = "0x140001000", ok = true,
                            committed = true, journaled = true, name = "fixture_caller",
                            previousName = "FixtureCaller", module = new { sha256 = FatSha },
                        },
                        new
                        {
                            index = 1, kind = "set_function_comment", function = "0x140001040", ok = true,
                            committed = true, journaled = true, commentChars = 42,
                            comment = new string('c', 200), previousComment = "old",
                        },
                        new
                        {
                            index = 2, kind = "rename_variable", function = "0x140001040", ok = true,
                            committed = true, journaled = true, variable = "local_1", name = "counter",
                            previousName = "local_1",
                        },
                        new
                        {
                            index = 3, kind = "set_variable_type", function = "0x140001080", ok = false,
                            code = "mutation_conflict", message = new string('m', 400),
                        },
                    }
                }
            });
        });

        var operations = new object[]
        {
            new { kind = "rename_function", function = "FixtureCaller", name = "fixture_caller" },
            new { kind = "set_function_comment", function = "FixtureCallee", comment = "Returns value * 3 + 7." },
            new { kind = "rename_variable", function = "FixtureCallee", variable = "local_1", name = "counter" },
            new { kind = "set_variable_type", function = "FixtureImportedPid", variable = "local_1", type = "int" },
        };
        var result = await harness.CallToolOverWireAsync("BatchAnnotate", new { operations });
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

        using var ack = JsonDocument.Parse(text);
        var root = ack.RootElement;
        Assert.Equal("BatchAnnotate", root.GetProperty("operation").GetString());
        Assert.Equal(3, root.GetProperty("applied").GetInt32());
        Assert.Equal(1, root.GetProperty("failed").GetInt32());
        var rows = root.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(4, rows.Length);
        Assert.Equal(new[] { 0, 1, 2, 3 }, rows.Select(row => row.GetProperty("index").GetInt32()).ToArray());
        Assert.Equal(
            new[] { "rename_function", "set_function_comment", "rename_variable", "set_variable_type" },
            rows.Select(row => row.GetProperty("kind").GetString()).ToArray());

        Assert.True(rows[0].GetProperty("committed").GetBoolean());
        Assert.True(rows[0].GetProperty("journaled").GetBoolean());
        Assert.Equal("0x140001000", rows[0].GetProperty("function").GetString());
        Assert.Equal("fixture_caller", rows[0].GetProperty("name").GetString());
        Assert.Equal(42, rows[1].GetProperty("commentChars").GetInt32());
        Assert.Equal("local_1", rows[2].GetProperty("variable").GetString());
        Assert.Equal("counter", rows[2].GetProperty("name").GetString());
        Assert.False(rows[3].GetProperty("committed").GetBoolean());
        Assert.False(rows[3].GetProperty("journaled").GetBoolean());
        Assert.Equal("mutation_conflict", rows[3].GetProperty("code").GetString());
        Assert.True(rows[3].GetProperty("message").GetString()!.Length <= 160);

        // Fat echoes and oversized values must never reach the model.
        Assert.DoesNotContain("previousName", text);
        Assert.DoesNotContain("previousComment", text);
        Assert.DoesNotContain(FatSha, text);
        Assert.DoesNotContain(new string('c', 200), text);
        Assert.DoesNotContain(new string('m', 400), text);

        // The managed handler sent the operations to the bridge unchanged
        // (the raw text escapes '+' as \u002B, so assert on the parsed shape).
        using var captured = JsonDocument.Parse(capturedRequest);
        var capturedOperations = captured.RootElement.GetProperty("operations").EnumerateArray().ToArray();
        Assert.Equal(4, capturedOperations.Length);
        Assert.Equal("fixture_caller", capturedOperations[0].GetProperty("name").GetString());
        Assert.Equal("Returns value * 3 + 7.", capturedOperations[1].GetProperty("comment").GetString());
    }

    [Fact]
    public async Task Wire_top_level_error_passes_through()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("BatchAnnotate", (id, _) =>
            $"{{\"id\":{id},\"ok\":false,\"error\":{{\"code\":\"program_unavailable\",\"message\":\"no active Ghidra program\"}}}}");

        var result = await harness.CallToolOverWireAsync("BatchAnnotate", new
        {
            operations = new object[] { new { kind = "rename_function", function = "f", name = "n" } }
        });

        Assert.True(result.IsError == true);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.Contains("program_unavailable", text);
        Assert.Contains("no active Ghidra program", text);
    }

    [Fact]
    public async Task SubmitAnnotations_wire_ack_keeps_progress_and_slim_rows()
    {
        await using var harness = await RealServerHarness.StartAsync();
        harness.Ghidra.RegisterTcpHandler("SubmitAnnotations", (id, _) =>
            JsonSerializer.Serialize(new
            {
                id,
                ok = true,
                result = new
                {
                    success = true,
                    applied = 1,
                    failed = 0,
                    results = new object[]
                    {
                        new
                        {
                            index = 0, kind = "rename_function", function = "0x140001000", ok = true,
                            committed = true, journaled = true, name = "fixture_caller",
                            previousName = "FixtureCaller", module = new { sha256 = FatSha },
                        },
                    },
                    progress = new { doneCount = 1 },
                }
            }));

        var result = await harness.CallToolOverWireAsync("SubmitAnnotations", new
        {
            operations = new object[] { new { kind = "rename_function", function = "FixtureCaller", name = "fixture_caller" } }
        });
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

        using var ack = JsonDocument.Parse(text);
        var root = ack.RootElement;
        Assert.Equal("SubmitAnnotations", root.GetProperty("operation").GetString());
        Assert.Equal(1, root.GetProperty("applied").GetInt32());
        Assert.Equal(1, root.GetProperty("progress").GetProperty("doneCount").GetInt32());
        Assert.Equal("fixture_caller",
            root.GetProperty("results").EnumerateArray().Single().GetProperty("name").GetString());
        Assert.DoesNotContain("previousName", text);
        Assert.DoesNotContain(FatSha, text);
    }

    [Fact]
    public async Task SubmitAnnotations_mutation_gate_and_queue_progress_schema()
    {
        using var gated = CreateServer(allowMutation: false);
        Assert.DoesNotContain("SubmitAnnotations", gated.ListTools().OfType<JsonObject>()
            .Select(tool => tool["name"]!.GetValue<string>()));
        var ex = await Assert.ThrowsAsync<McpProtocolException>(() => gated.CallToolAsync(
            new CallToolRequestParams
            {
                Name = "SubmitAnnotations",
                Arguments = new Dictionary<string, JsonElement>
                {
                    ["operations"] = Ops("""[{"kind":"rename_function","function":"f","name":"n"}]""")
                }
            }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, ex.ErrorCode);

        using var open = CreateServer();
        var queue = open.ListTools().OfType<JsonObject>()
            .Single(tool => tool["name"]!.GetValue<string>() == "GetAnalysisQueue");
        var queueProps = (JsonObject)queue["inputSchema"]!["properties"]!;
        Assert.True(queueProps.ContainsKey("excludeAnnotated"));
    }
}
