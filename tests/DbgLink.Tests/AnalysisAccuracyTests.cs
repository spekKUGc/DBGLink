extern alias Server;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using BridgeEnvelope = Server::DbgLink.Shared.BridgeEnvelope;

namespace DbgLink.Tests;

public sealed class AnalysisAccuracyTests
{
    [Fact]
    public async Task Mapping_finds_a_module_in_a_large_module_map_and_applies_aslr()
    {
        var text = string.Join('\n', Enumerable.Range(0, 300).Select(i =>
            $"base=0x{0x100000UL + (ulong)i * 0x10000:X} end=0x{0x101000UL + (ulong)i * 0x10000:X} name=m{i}.dll path=C:\\m{i}.dll"));
        var modules = AddressMapping.ParseLiveModules(text);
        var function = new ToolSupport.StaticFunction("KnownFunction", "0x140000120", @"C:\m299.dll", null, 0x120);
        var result = await AddressMapping.BuildMappingResultAsync(function, modules, false, CancellationToken.None);
        Assert.Equal(300, modules.Count);
        Assert.True(result["match"]!.GetValue<bool>());
        Assert.Equal(AddressMapping.FormatAddress(0x100000UL + 299 * 0x10000UL + 0x120), result["liveAddress"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(true, "module_search_incomplete")]
    [InlineData(false, "module_identity_not_found")]
    public async Task Missing_module_distinguishes_incomplete_and_complete_search(bool truncated, string reason)
    {
        var modules = AddressMapping.ParseModuleRecords(JsonSerializer.SerializeToNode(new { modules = Array.Empty<object>(), truncated }));
        var result = await AddressMapping.BuildMappingResultAsync(
            new ToolSupport.StaticFunction("fn", "0x1000", @"C:\missing.dll", null, 0x10), modules, false, CancellationToken.None);
        Assert.False(result["match"]!.GetValue<bool>());
        Assert.Equal(reason, result["reason"]!.GetValue<string>());
    }

    [Fact]
    public void Structured_modules_preserve_delimiters_and_unicode_in_paths()
    {
        const string path = "C:\\dir name=one path=two\\модуль.dll";
        var records = JsonSerializer.SerializeToNode(new
        {
            modules = new[] { new { @base = "0x100000", end = "0x102000", name = "модуль.dll", path } }, truncated = false
        });
        var modules = AddressMapping.ParseModuleRecords(records);
        Assert.Equal(path, Assert.Single(modules).Path);
        Assert.False(modules.Truncated);
    }

    [Fact]
    public void Malformed_records_cannot_produce_a_complete_negative_result()
    {
        var records = JsonNode.Parse("""{"modules":[{"base":"bad","end":"bad"}],"truncated":false}""");
        Assert.True(AddressMapping.ParseModuleRecords(records).Truncated);
        Assert.True(AddressMapping.ParseModuleRecords(null).Truncated);
    }

    [Theory]
    [InlineData("generation", "2", "changed")]
    [InlineData("threadId", "43", "changed")]
    [InlineData("running", "true", "changed")]
    [InlineData("stableRead", "false", "changed")]
    public void Snapshot_detects_changes_even_when_target_is_paused_again(string field, string value, string expected)
    {
        var before = State();
        var after = before.DeepClone();
        after[field] = field == "generation" ? JsonValue.Create(value) : JsonNode.Parse(value);
        Assert.Equal(expected, AnalysisSnapshotSummary.AssessConsistency(before, after)["status"]!.GetValue<string>());
    }

    [Fact]
    public void Snapshot_does_not_claim_atomicity_or_consistency_without_evidence()
    {
        var stable = AnalysisSnapshotSummary.AssessConsistency(State(), State());
        Assert.Equal("unchanged", stable["status"]!.GetValue<string>());
        Assert.False(stable["atomic"]!.GetValue<bool>());
        Assert.Equal("unavailable", AnalysisSnapshotSummary.AssessConsistency(null, State())["status"]!.GetValue<string>());
        var running = State(); running["running"] = true;
        Assert.Equal("running", AnalysisSnapshotSummary.AssessConsistency(running, running)["status"]!.GetValue<string>());
    }

    [Fact]
    public async Task Snapshot_keeps_whole_module_records_and_checks_state_after_sections()
    {
        var bridge = new AccuracyBridge();
        var tools = new LiveAnalysisTools(new AnalysisContext(bridge, new NullGhidra()));
        var raw = await tools.GetAnalysisSnapshotAsync(JsonSerializer.SerializeToElement(
            new { maxChars = 2000, includeModules = true, includeStatus = true }), CancellationToken.None);
        var snapshot = AnalysisFormatting.ReadBridgeResultNode(raw)!;
        Assert.Equal(2, bridge.Calls.Count(call => call == "GetSnapshotState"));
        Assert.Equal("unchanged", snapshot["consistency"]!["status"]!.GetValue<string>());
        Assert.True(snapshot["truncated"]!.GetValue<bool>());
        Assert.True(snapshot["sections"]!["status"]!["ok"]!.GetValue<bool>());
        Assert.True(snapshot["sections"]!["status"]!["debugging"]!.GetValue<bool>());
        Assert.True(snapshot["errors"] is null || snapshot["errors"]!.AsArray().Count == 0);
        Assert.Equal("unchanged", snapshot["summary"]!["consistency"]!.GetValue<string>());
        Assert.Equal("unchanged", snapshot["consistency"]!["status"]!.GetValue<string>());
        Assert.True(snapshot["summary"]!["moduleCount"]!.GetValue<int>() > 0);
        Assert.True(snapshot["summary"]!["modulesTruncated"]!.GetValue<bool>());
        // Path-stripped records are smaller, so the trimmed table now fits:
        // it ships (truncated) instead of omitting, without per-module paths.
        Assert.Equal("included", snapshot["summary"]!["moduleStatus"]!.GetValue<string>());
        var shipped = snapshot["sections"]!["modules"]!["modules"]!.AsArray();
        Assert.NotEmpty(shipped);
        Assert.All(shipped, record => Assert.False(record!.AsObject().ContainsKey("path")));
        Assert.NotNull(snapshot["sections"]!["context"]);
        Assert.Equal(0, snapshot["summary"]!["errorCount"]!.GetValue<int>());
        var modules = AnalysisFormatting.ParseSnapshotModules(snapshot);
        Assert.IsType<AddressMapping.LiveModuleCollection>(modules);
        Assert.True(((AddressMapping.LiveModuleCollection)modules).Truncated);
        Assert.DoesNotContain("GetAllModulesFromMemMap", bridge.Calls);
    }

    [Fact]
    public async Task Brief_reuses_complete_snapshot_modules_without_a_second_map_request()
    {
        var bridge = new BatchedBriefBridge();
        var context = new AnalysisContext(bridge, new BriefGhidra());
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));

        var raw = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(new { function = "fn", verifyHash = false, includeModules = true }),
            CancellationToken.None);
        var brief = AnalysisFormatting.ReadBridgeResultNode(raw)!;

        Assert.Equal("snapshot_modules", brief["mappingSource"]!.GetValue<string>());
        Assert.Equal(1, brief["bridgeCalls"]!["native"]!.GetValue<int>());
        Assert.Equal(1, bridge.Calls.Count(call => call is "GetServerStatus" or "GetAnalysisSnapshot"));
        Assert.DoesNotContain("GetServerStatus", bridge.Calls);
        Assert.DoesNotContain("GetModuleRecords", bridge.Calls);
        Assert.True(brief["sections"]!["mapping"]!["match"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Snapshot_strips_module_paths_unless_opted_in()
    {
        var tools = new LiveAnalysisTools(new AnalysisContext(new AccuracyBridge(), new NullGhidra()));
        var raw = await tools.GetAnalysisSnapshotAsync(JsonSerializer.SerializeToElement(
            new { maxChars = 16000, includeModules = true }), CancellationToken.None);
        var snapshot = AnalysisFormatting.ReadBridgeResultNode(raw)!;
        var records = snapshot["sections"]!["modules"]!["modules"]!.AsArray();
        Assert.NotEmpty(records);
        Assert.All(records, record =>
        {
            var entry = record!.AsObject();
            if (!entry.ContainsKey("collapsed"))
                Assert.False(entry.ContainsKey("path"));
        });

        var tools2 = new LiveAnalysisTools(new AnalysisContext(new AccuracyBridge(), new NullGhidra()));
        var raw2 = await tools2.GetAnalysisSnapshotAsync(JsonSerializer.SerializeToElement(
            new { maxChars = 16000, includeModules = true, includeModulePaths = true }), CancellationToken.None);
        var snapshot2 = AnalysisFormatting.ReadBridgeResultNode(raw2)!;
        var records2 = snapshot2["sections"]!["modules"]!["modules"]!.AsArray();
        Assert.NotEmpty(records2);
        Assert.Contains(records2, record => record!.AsObject().ContainsKey("path"));
    }

    [Fact]
    public async Task Mapping_uses_a_targeted_structured_request_independent_of_snapshot_budget()
    {
        var bridge = new AccuracyBridge();
        var result = await AddressMapping.BuildLiveMappingAsync(bridge,
            new ToolSupport.StaticFunction("fn", "0x140000100", @"C:\target.dll", null, 0x100), false, CancellationToken.None);
        Assert.True(result["match"]!.GetValue<bool>());
        Assert.Equal("0x70000100", result["liveAddress"]!.GetValue<string>());
        Assert.Equal(@"C:\target.dll", bridge.Filter);
        Assert.Equal(new[] { "GetModuleRecords" }, bridge.Calls);
    }

    [Fact]
    public async Task Brief_preserves_snapshot_consistency_warnings_outside_the_bounded_live_section()
    {
        var bridge = new AccuracyBridge { ChangeState = true };
        var context = new AnalysisContext(bridge, new NullGhidra());
        var tools = new InvestigationTools(context, new LiveAnalysisTools(context));
        var raw = await tools.GetInvestigationBriefAsync(
            JsonSerializer.SerializeToElement(new { function = "fn", maxChars = 2000 }), CancellationToken.None);
        var brief = AnalysisFormatting.ReadBridgeResultNode(raw)!;
        Assert.Contains((JsonArray)brief["errors"]!, error =>
            error?["section"]?.GetValue<string>() == "live" && error.ToJsonString().Contains("snapshot_not_verified"));
    }

    private static JsonNode State() => JsonNode.Parse("""
        {"debuggerPid":123,"generation":"1","debugging":true,"running":false,"threadId":42,"stableRead":true}
        """)!;

    private sealed class BatchedBriefBridge : IBridgeClient
    {
        public List<string> Calls { get; } = [];
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (method == "GetServerStatus")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":123,\"debugging\":true,\"capabilities\":{\"analysisSnapshot\":true}}");
            if (method == "GetAnalysisSnapshot")
            {
                var modules = JsonSerializer.SerializeToNode(new
                {
                    modules = new[]
                    {
                        new { @base = "0x70000000", end = "0x70001000", name = "target.dll", path = @"C:\target.dll" }
                    },
                    truncated = false,
                });
                var result = new JsonObject
                {
                    ["stateBefore"] = State(),
                    ["stateAfter"] = State(),
                    ["sections"] = new JsonObject
                    {
                        ["context"] = "context",
                        ["callStack"] = "stack",
                        ["modules"] = modules,
                    },
                };
                return Task.FromResult(BridgeEnvelope.Success(result));
            }
            return Task.FromResult(BridgeEnvelope.Error("unexpected", method));
        }
    }

    private sealed class BriefGhidra : IGhidraClient
    {
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"id\":1,\"ok\":true,\"result\":{\"function\":{\"name\":\"fn\",\"entry\":\"0x70000010\",\"rva\":\"0x10\",\"module\":{\"path\":\"C:\\\\target.dll\",\"sha256\":\"\"}}}}");
    }

    private sealed class AccuracyBridge : IBridgeClient
    {
        public List<string> Calls { get; } = [];
        public string? Filter { get; private set; }
        public bool ChangeState { get; init; }
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Calls.Add(method);
            if (method == "GetSnapshotState")
            {
                var state = (JsonObject)State();
                if (ChangeState && Calls.Count(call => call == "GetSnapshotState") > 1)
                    state["generation"] = "2";
                return Task.FromResult(BridgeEnvelope.Success(state));
            }
            if (method == "GetModuleRecords")
            {
                Filter = arguments?.GetProperty("modulePath").GetString();
                var records = Enumerable.Range(0, Filter is null ? 300 : 1).Select(i => new
                {
                    @base = "0x70000000", end = "0x70001000", name = "target.dll", path = Filter ?? $"C:\\m{i}.dll"
                });
                return Task.FromResult(JsonSerializer.Serialize(new { id = 1, ok = true, result = new { modules = records, truncated = false } }));
            }
            if (method == "GetServerStatus")
                return Task.FromResult("{\"id\":1,\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":123,\"debugging\":true}");
            return Task.FromResult("""{"id":1,"ok":true,"text":"sample"}""");
        }
    }
}
