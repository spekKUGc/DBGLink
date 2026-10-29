using System.Text.Json;
using DbgLink.Server;

namespace DbgLink.Tests;

/// <summary>
/// p7: one budget rule for composites. maxChars remains the hard ceiling;
/// maxTokens optionally tightens it at a conservative 4 chars/token.
/// </summary>
public sealed class ResponseBudgetTests
{
    private static JsonElement Args(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    [Fact]
    public void Default_budget_keeps_maxChars_and_disables_tokens()
    {
        var chars = ToolSupport.ReadResponseBudget(
            Args("""{"maxChars":16000}"""), 16000, 4000, 60000, out var tokens);

        Assert.Equal(16000, chars);
        Assert.Equal(0, tokens);
    }

    [Fact]
    public void Token_ceiling_tightens_the_character_budget()
    {
        var chars = ToolSupport.ReadResponseBudget(
            Args("""{"maxChars":10000,"maxTokens":500}"""), 16000, 4000, 60000, out var tokens);

        Assert.Equal(2000, chars);
        Assert.Equal(500, tokens);
    }

    [Fact]
    public void Tighter_maxChars_wins_over_the_token_ceiling()
    {
        var chars = ToolSupport.ReadResponseBudget(
            Args("""{"maxChars":1200,"maxTokens":500}"""), 16000, 1000, 60000, out var tokens);

        Assert.Equal(1200, chars);
        Assert.Equal(500, tokens);
    }

    [Fact]
    public void Zero_or_negative_tokens_disables_the_guard()
    {
        Assert.Equal(24000, ToolSupport.ReadResponseBudget(
            Args("""{"maxTokens":0}"""), 24000, 1000, 120000, out var zero));
        Assert.Equal(0, zero);

        Assert.Equal(24000, ToolSupport.ReadResponseBudget(
            Args("""{"maxTokens":-5}"""), 24000, 1000, 120000, out var negative));
        Assert.Equal(0, negative);
    }

    [Fact]
    public void Tiny_token_ceiling_is_raised_to_the_envelope_floor()
    {
        var chars = ToolSupport.ReadResponseBudget(
            Args("""{"maxTokens":100}"""), 16000, 4000, 60000, out var tokens);

        Assert.Equal(500, tokens);
        Assert.Equal(2000, chars);
    }

    [Fact]
    public void Token_ceiling_is_bounded()
    {
        var chars = ToolSupport.ReadResponseBudget(
            Args("""{"maxTokens":999999}"""), 16000, 4000, 60000, out var tokens);

        Assert.Equal(30000, tokens);
        Assert.Equal(16000, chars);
    }

    [Fact]
    public void Token_estimate_rounds_up_and_hint_mentions_maxTokens()
    {
        Assert.Equal(1001, ToolSupport.EstimateGuardTokens(4001));
        Assert.Equal(0, ToolSupport.EstimateGuardTokens(-1));
        Assert.Contains("maxChars/maxTokens",
            ToolSupport.WithTokenBudgetHint("Raise maxChars, or narrow the range.", 100));
        Assert.Equal("Raise maxChars, or narrow the range.",
            ToolSupport.WithTokenBudgetHint("Raise maxChars, or narrow the range.", 0));
    }
}
