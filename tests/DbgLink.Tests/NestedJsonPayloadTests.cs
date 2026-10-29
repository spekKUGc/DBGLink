using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Round 2 universal payload rule: structured data is nested on the wire, not
/// carried as an escaped JSON string. Pure strings stay byte-identical.
/// </summary>
public sealed class NestedJsonPayloadTests
{
    [Fact]
    public void Escaped_json_section_becomes_a_nested_object()
    {
        const string payload = "{\"sections\":{\"context\":\"{\\\"registers\\\":{\\\"rip\\\":\\\"0x1000\\\"}}\"}}";
        var nested = ToolSupport.NestJsonText(payload);
        Assert.Equal("{\"sections\":{\"context\":{\"registers\":{\"rip\":\"0x1000\"}}}}", nested);
        Assert.DoesNotContain("\\u0022", nested);
        Assert.True(nested.Length < payload.Length);
    }

    [Fact]
    public void Arrays_inside_rows_are_nested_too()
    {
        var payload = "{\"rows\":[{\"data\":\"[1,2,3]\"}]}";
        Assert.Equal("{\"rows\":[{\"data\":[1,2,3]}]}", ToolSupport.NestJsonText(payload));
    }

    [Theory]
    [InlineData("{\"bytes\":\"DEADBEEF\"}")]
    [InlineData("{\"text\":\"int main() { return 0; }\"}")]
    [InlineData("{\"note\":\"{\"}")]
    [InlineData("not json at all")]
    [InlineData("[1,2,3]")]
    public void Pure_strings_and_non_containers_pass_through_unchanged(string payload)
        => Assert.Equal(payload, ToolSupport.NestJsonText(payload));

    [Fact]
    public void Non_ascii_is_written_literally_on_the_nested_path()
    {
        var payload = "{\"sections\":{\"note\":\"{\\\"msg\\\":\\\"привет\\\"}\"}}";
        var nested = ToolSupport.NestJsonText(payload);
        Assert.Contains("привет", nested);
        Assert.DoesNotContain("\\u", nested);
    }
}
