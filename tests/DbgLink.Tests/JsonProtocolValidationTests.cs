extern alias Server;
using System.Text.Json;
using JsonProtocolValidation = Server::DbgLink.Shared.JsonProtocolValidation;

namespace DbgLink.Tests;

public sealed class JsonProtocolValidationTests
{
    [Fact]
    public void Duplicate_properties_are_detected_at_the_root()
    {
        using var document = JsonDocument.Parse("{\"id\":1,\"id\":2}");

        Assert.True(JsonProtocolValidation.HasDuplicateProperties(document.RootElement));
    }

    [Fact]
    public void Duplicate_properties_are_detected_in_nested_values()
    {
        using var document = JsonDocument.Parse("{\"result\":{\"value\":1,\"value\":2}}");

        Assert.True(JsonProtocolValidation.HasDuplicateProperties(document.RootElement));
    }

    [Fact]
    public void Unique_properties_are_accepted()
    {
        using var document = JsonDocument.Parse("{\"id\":1,\"result\":{\"value\":2}}");

        Assert.False(JsonProtocolValidation.HasDuplicateProperties(document.RootElement));
    }
}
