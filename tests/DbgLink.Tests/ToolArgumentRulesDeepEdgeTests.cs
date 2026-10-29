using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

public sealed class ToolArgumentRulesDeepEdgeTests
{
    // ========================================================================================
    // GROUP 1: INTEGER VALIDATION & BOUNDARY RULES (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("{\"val\": 0}", true)]
    [InlineData("{\"val\": 1}", true)]
    [InlineData("{\"val\": -1}", true)]
    [InlineData("{\"val\": 100}", true)]
    [InlineData("{\"val\": -100}", true)]
    [InlineData("{\"val\": 2147483647}", true)]
    [InlineData("{\"val\": -2147483648}", true)]
    [InlineData("{\"val\": 1.0}", false)]
    [InlineData("{\"val\": 1.5}", false)]
    [InlineData("{\"val\": 0.001}", false)]
    [InlineData("{\"val\": \"100\"}", false)]
    [InlineData("{\"val\": true}", false)]
    [InlineData("{\"val\": false}", false)]
    [InlineData("{\"val\": null}", false)]
    [InlineData("{\"val\": []}", false)]
    [InlineData("{\"val\": {}}", false)]
    [InlineData("{\"val\": 1e5}", false)]
    [InlineData("{\"val\": 42}", true)]
    [InlineData("{\"val\": 9223372036854775807}", true)]
    [InlineData("{\"val\": -9223372036854775808}", true)]
    public void Integer_format_and_type_discrimination(string json, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["val"] = new JsonObject { ["type"] = "integer" }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(json);
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 2: INTEGER RANGE & ALLOWED SETS (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(10, true)]
    [InlineData(50, true)]
    [InlineData(100, true)]
    [InlineData(9, false)]
    [InlineData(101, false)]
    [InlineData(-10, false)]
    [InlineData(0, false)]
    [InlineData(200, false)]
    [InlineData(12, true)]
    [InlineData(99, true)]
    public void Integer_minimum_and_maximum_bounds(int value, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["count"] = new JsonObject
                {
                    ["type"] = "integer",
                    ["minimum"] = 10,
                    ["maximum"] = 100
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>($"{{\"count\": {value}}}");
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(4, true)]
    [InlineData(8, true)]
    [InlineData(0, false)]
    [InlineData(3, false)]
    [InlineData(5, false)]
    [InlineData(16, false)]
    [InlineData(-1, false)]
    [InlineData(88, false)]
    public void Integer_closed_allowed_set_validation(int value, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["size"] = new JsonObject
                {
                    ["type"] = "integer",
                    ["x-allowedInts"] = new JsonArray(1, 2, 4, 8)
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>($"{{\"size\": {value}}}");
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 3: NUMBER (FLOATING POINT) RULES (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("{\"val\": 0.0}", true)]
    [InlineData("{\"val\": 1.5}", true)]
    [InlineData("{\"val\": -25.75}", false)]
    [InlineData("{\"val\": 100.0}", true)]
    [InlineData("{\"val\": -100.0}", false)]
    [InlineData("{\"val\": 101.0}", false)]
    [InlineData("{\"val\": -0.001}", false)]
    [InlineData("{\"val\": 50.5}", true)]
    [InlineData("{\"val\": 0}", true)]
    [InlineData("{\"val\": 100}", true)]
    [InlineData("{\"val\": \"1.5\"}", false)]
    [InlineData("{\"val\": true}", false)]
    [InlineData("{\"val\": null}", false)]
    [InlineData("{\"val\": []}", false)]
    [InlineData("{\"val\": {}}", false)]
    public void Number_bounds_and_validations(string json, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["val"] = new JsonObject
                {
                    ["type"] = "number",
                    ["minimum"] = 0.0,
                    ["maximum"] = 100.0
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(json);
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 4: STRING LENGTH & NONBLANK VALIDATION (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("abc", true)]
    [InlineData("12345", true)]
    [InlineData("1234567890", true)]
    [InlineData("ab", false)]
    [InlineData("a", false)]
    [InlineData("", false)]
    [InlineData("12345678901", false)]
    [InlineData("   ", true)]
    [InlineData("hello world", false)]
    [InlineData("test!", true)]
    public void String_min_max_length_bounds(string text, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["token"] = new JsonObject
                {
                    ["type"] = "string",
                    ["minLength"] = 3,
                    ["maxLength"] = 10
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { token = text }));
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    [Theory]
    [InlineData("valid", true)]
    [InlineData("a", true)]
    [InlineData("   ", false)]
    [InlineData("", false)]
    [InlineData("\t", false)]
    [InlineData("\r\n", false)]
    [InlineData(" a ", true)]
    [InlineData("  x  ", true)]
    [InlineData("\tvalue\t", true)]
    [InlineData("\nword\n", true)]
    public void String_nonblank_validation(string text, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["input"] = new JsonObject
                {
                    ["type"] = "string",
                    ["x-nonblank"] = true,
                    ["x-multiline"] = true
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { input = text }));
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 5: STRING UTF-8 BYTE LIMIT & MULTIBYTE ENCODINGS (10 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("1234567890", true)] // 10 ASCII bytes
    [InlineData("1234567890123456", true)] // 16 ASCII bytes
    [InlineData("12345678901234567", false)] // 17 ASCII bytes -> exceeds 16
    [InlineData("Привет", true)] // 6 Cyrillic chars = 12 bytes <= 16
    [InlineData("Привет!", true)] // 12 + 1 = 13 bytes <= 16
    [InlineData("Приветствую", false)] // 11 Cyrillic chars = 22 bytes > 16
    [InlineData("🚀🚀", true)] // 2 emojis * 4 bytes = 8 bytes <= 16
    [InlineData("🚀🚀🚀🚀", true)] // 4 emojis * 4 bytes = 16 bytes <= 16
    [InlineData("🚀🚀🚀🚀🚀", false)] // 5 emojis * 4 bytes = 20 bytes > 16
    [InlineData("日本語", true)] // 3 Kanji * 3 bytes = 9 bytes <= 16
    public void String_max_utf8_bytes_enforcement(string text, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["data"] = new JsonObject
                {
                    ["type"] = "string",
                    ["x-maxUtf8Bytes"] = 16
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { data = text }));
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 6: BYTE PATTERN VALIDATION (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("90 90 90", true)]
    [InlineData("CC", true)]
    [InlineData("48 8B ?? 48 89 ??", true)]
    [InlineData("e8 ? ? ? ?", true)]
    [InlineData("AA bb CC dd EE ff", true)]
    [InlineData("00 11 22 33 44 55 66 77 88 99", true)]
    [InlineData("90 ? 90 ?? 90", true)]
    [InlineData("12 34 56 78 9A BC DE F0", true)]
    [InlineData("FF ?? ?? 00", true)]
    [InlineData("?? ?? ??", false)] // all wildcards -> invalid per ToolArgumentRules
    [InlineData("? ?", false)] // all wildcards -> invalid
    [InlineData("??", false)] // only wildcard -> invalid
    [InlineData("?", false)] // only wildcard -> invalid
    [InlineData("G0 90", false)] // 'G0' invalid hex
    [InlineData("0x90", false)] // '0x90' length != 2
    [InlineData("9090", false)] // single 4-char token without space
    [InlineData("9", false)] // 1-char non-wildcard token
    [InlineData("900", false)] // 3-char token
    [InlineData("", false)] // empty pattern
    [InlineData("   ", false)] // whitespace only
    public void Byte_pattern_syntax_and_wildcard_rules(string pattern, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["pattern"] = new JsonObject
                {
                    ["type"] = "string",
                    ["x-bytePattern"] = true
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { pattern }));
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 7: REGEX PATTERN VALIDATION (10 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("rax", true)]
    [InlineData("rcx", true)]
    [InlineData("rdx", true)]
    [InlineData("rbx", true)]
    [InlineData("rsp", true)]
    [InlineData("rbp", true)]
    [InlineData("rsi", true)]
    [InlineData("rdi", true)]
    [InlineData("eax", false)]
    [InlineData("123", false)]
    public void Regex_pattern_matching(string reg, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["register"] = new JsonObject
                {
                    ["type"] = "string",
                    ["pattern"] = "^r(ax|cx|dx|bx|sp|bp|si|di)$"
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { register = reg }));
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 8: EXCLUSIVE SELECTORS & ENCODING CHOICE (5 Tests)
    // ========================================================================================

    [Fact]
    public void ExclusiveSelectors_BothPresent_ReturnsError()
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["x-exclusiveSelectors"] = new JsonArray("function", "start"),
            ["properties"] = new JsonObject
            {
                ["function"] = new JsonObject { ["type"] = "string" },
                ["start"] = new JsonObject { ["type"] = "string" }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>("{\"function\":\"main\",\"start\":\"0x1000\"}");
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal("DecompileModule accepts either function or start, not both.", error);
    }

    [Theory]
    [InlineData("{\"function\":\"main\"}", true)]
    [InlineData("{\"start\":\"0x1000\"}", true)]
    [InlineData("{}", true)]
    public void ExclusiveSelectors_SingleOrNeither_Passes(string json, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["x-exclusiveSelectors"] = new JsonArray("function", "start"),
            ["properties"] = new JsonObject
            {
                ["function"] = new JsonObject { ["type"] = "string" },
                ["start"] = new JsonObject { ["type"] = "string" }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(json);
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    [Theory]
    [InlineData("{\"ascii\":false,\"unicode\":false}", false)]
    [InlineData("{\"ascii\":true,\"unicode\":false}", true)]
    [InlineData("{\"ascii\":false,\"unicode\":true}", true)]
    [InlineData("{\"ascii\":true,\"unicode\":true}", true)]
    [InlineData("{}", true)]
    public void EncodingChoice_AtLeastOneRequired(string json, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["x-encodingChoice"] = true,
            ["properties"] = new JsonObject
            {
                ["ascii"] = new JsonObject { ["type"] = "boolean" },
                ["unicode"] = new JsonObject { ["type"] = "boolean" }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>(json);
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 9: ARRAY maxItems BOUNDARY (Stryker L69 <= -> < survivor)
    // ========================================================================================

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)] // exactly at maxItems: only <= accepts
    [InlineData(3, false)]
    public void Array_maxItems_boundary_is_inclusive(int count, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["items"] = new JsonObject
                {
                    ["type"] = "array",
                    ["maxItems"] = 2,
                    ["items"] = new JsonObject { ["type"] = "integer" }
                }
            }
        };
        var array = "[" + string.Join(",", Enumerable.Repeat("1", count)) + "]";
        var args = JsonSerializer.Deserialize<JsonElement>("{\"items\":" + array + "}");
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }

    // ========================================================================================
    // GROUP 10: LONG-ONLY allowedInts (Stryker L102 asLong branch)
    // ========================================================================================

    [Theory]
    [InlineData(4294967296L, true)] // beyond int range: only the long branch can permit
    [InlineData(4294967297L, false)]
    public void AllowedInts_long_branch_permits_beyond_int_range(long value, bool expectedValid)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["size"] = new JsonObject
                {
                    ["type"] = "integer",
                    ["x-allowedInts"] = new JsonArray(4294967296L)
                }
            }
        };
        var args = JsonSerializer.Deserialize<JsonElement>("{\"size\": " + value + "}");
        var error = ToolArgumentRules.Validate(schema, args);
        Assert.Equal(expectedValid, error is null);
    }
}
