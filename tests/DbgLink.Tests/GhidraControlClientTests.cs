using DbgLink.Server;
using System.Text.Json;

namespace DbgLink.Tests;

public sealed class GhidraControlClientTests
{
    [Theory]
    [InlineData("DbgLink.GhidraControl.")]
    [InlineData("DbgLink.GhidraControl.\0session")]
    public void Constructor_rejects_an_invalid_control_pipe_name(string pipeName)
    {
        Assert.Throws<ArgumentException>(() =>
            new GhidraControlClient(
                pipeName,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    [Fact]
    public void ValidateResponse_rejects_duplicate_root_properties()
    {
        var response = GhidraControlClient.ValidateResponse(
            "{\"id\":1,\"ok\":true,\"result\":{},\"result\":{}} ");

        Assert.Contains("ghidra_control_protocol", response);
    }

    [Fact]
    public void ValidateResponse_rejects_duplicate_nested_properties()
    {
        var response = GhidraControlClient.ValidateResponse(
            "{\"id\":1,\"ok\":true,\"result\":{\"value\":1,\"value\":2}} ");

        Assert.Contains("ghidra_control_protocol", response);
    }

    [Fact]
    public void ValidateResponse_rejects_a_non_numeric_id()
    {
        var response = GhidraControlClient.ValidateResponse(
            "{\"id\":\"1\",\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true,\"fileName\":\"target.dll\"}}");

        Assert.Contains("ghidra_control_protocol", response);
    }

    [Fact]
    public void ValidateResponse_accepts_a_well_formed_success()
    {
        var endpointDirectory = Path.Combine(Path.GetTempPath(), "dbglink-control-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(endpointDirectory);
        try
        {
            var response = JsonSerializer.Serialize(new
            {
                id = 1,
                ok = true,
                result = new
                {
                    opened = true,
                    staticReady = true,
                    fileName = "target.dll",
                    analysisId = "analysis-test",
                    nativePipeName = "DbgLink.Control.42",
                    ghidraEndpointDirectory = endpointDirectory
                }
            });

            Assert.Equal(response, GhidraControlClient.ValidateResponse(response));
        }
        finally
        {
            if (Directory.Exists(endpointDirectory))
                Directory.Delete(endpointDirectory, recursive: true);
        }
    }

    [Fact]
    public void ValidateResponse_rejects_success_without_session_metadata()
    {
        var response = GhidraControlClient.ValidateResponse(
            "{\"id\":1,\"ok\":true,\"result\":{\"opened\":true,\"staticReady\":true,\"fileName\":\"target.dll\"}}");

        Assert.Contains("ghidra_control_protocol", response);
    }
}
