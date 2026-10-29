using System.Text.Json;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

public sealed class SecurityFixRegressionTests
{
    private sealed class StubBridge : IBridgeClient
    {
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
            => Task.FromResult("{\"ok\":true,\"result\":{}}");
    }

    private static LocalMcpServer CreateServer()
        => new(new ServerConfig { Port = 50499 }, new StubBridge(), new NullGhidra(), new CompletedGhidraControl("{}"));

    private static string ResponseText(CallToolResult result)
        => string.Join("", result.Content.Select(c => (c as TextContentBlock)?.Text ?? ""));

    [Theory]
    [InlineData("auto")]
    [InlineData("x86")]
    [InlineData("x64")]
    public async Task OpenDebugTarget_Architecture_Allowlist_Values_Pass_Validation(string architecture)
    {
        using var server = CreateServer();
        var resp = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\target.exe"),
                ["architecture"] = JsonSerializer.SerializeToElement(architecture),
            }
        }, CancellationToken.None);
        Assert.Contains("debug_target_invalid", ResponseText(resp));
    }

    [Theory]
    [InlineData("foobar")]
    [InlineData("X64")]
    [InlineData("")]
    public async Task OpenDebugTarget_Architecture_Outside_Enum_Is_Rejected(string architecture)
    {
        using var server = CreateServer();
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\target.exe"),
                ["architecture"] = JsonSerializer.SerializeToElement(architecture),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
    }

    [Fact]
    public async Task BatchDebuggerOperations_Nested_AnalysisId_Is_Rejected()
    {
        using var server = CreateServer();
        var resp = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[]
                {
                    new { method = "GetMemoryMap", arguments = new { analysisId = "default" } },
                })
            }
        }, CancellationToken.None);
        Assert.True(resp.IsError);
        Assert.Contains("invalid_batch", ResponseText(resp));
    }

    [Theory]
    [InlineData("90 90", false)]
    [InlineData("488B05", false)]
    [InlineData("0x48,0x8B", false)]
    [InlineData("ABC", true)]
    [InlineData("ZZ", true)]
    [InlineData("90 9", true)]
    public async Task WriteMemory_HexBytes_Content_Is_Validated(string hexBytes, bool expectRejection)
    {
        using var server = CreateServer();
        var task = server.CallToolAsync(new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["hexBytes"] = JsonSerializer.SerializeToElement(hexBytes),
            }
        }, CancellationToken.None);
        if (expectRejection)
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() => task);
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }
        else
        {
            var resp = await task;
            Assert.False(resp.IsError);
        }
    }

    [Fact]
    public async Task WriteMemory_HexBytes_Over_Native_Cap_Is_Rejected_Before_Bridge()
    {
        var bridge = new CountingBridge();
        using var server = new LocalMcpServer(new ServerConfig { Port = 50498 }, bridge);
        var oversized = new string('A', 9000);
        await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["hexBytes"] = JsonSerializer.SerializeToElement(oversized),
            }
        }, CancellationToken.None));
        Assert.Equal(0, bridge.RequestCount);
    }

    private sealed class CountingBridge : IBridgeClient
    {
        public int RequestCount;
        public Task<bool> PingAsync(CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<string> RequestAsync(string method, JsonElement? arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref RequestCount);
            return Task.FromResult("{\"ok\":true,\"result\":{}}");
        }
    }

    [Fact]
    public async Task GhidraOpenStatus_Missing_Arguments_Returns_NotFound()
    {
        var operations = new GhidraOpenOperations(null);
        try
        {
            Assert.Contains("ghidra_operation_not_found", await operations.GetGhidraOpenStatusAsync(null));
            Assert.Contains("ghidra_operation_not_found", await operations.CancelAsync(null));
            Assert.Contains("ghidra_operation_not_found",
                await operations.GetGhidraOpenStatusAsync(JsonSerializer.SerializeToElement(new { })));
        }
        finally { operations.Stop(); }
    }

    [Theory]
    [InlineData("C:\\x\\..\\..\\evil.exe")] // Traversal that resolves to a missing file
    [InlineData("relative\\target.exe")] // Not fully qualified
    [InlineData("C:\\nonexistent\\target.txt")] // Wrong extension
    [InlineData("C:\\nonexistent\\ta\"rget.exe")] // Quote breaks x64dbg init quoting
    public async Task OpenDebugTarget_Hostile_Paths_Return_Invalid_Envelope(string path)
    {
        using var server = CreateServer();
        var resp = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement(path),
            }
        }, CancellationToken.None);
        Assert.Contains("debug_target_invalid", ResponseText(resp));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("C:\\nonexistent\\target.exe\0")] // Embedded NUL: control char fails IsSafeText at schema
    [InlineData("C:\\nonexistent\\tar\nget.exe")] // Newline without x-multiline fails IsSafeText at schema
    public async Task OpenDebugTarget_Blank_Paths_Rejected_At_Schema(string path)
    {
        using var server = CreateServer();
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement(path),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
    }

    [Fact]
    public async Task OpenDebugTarget_CommandLine_Overflow_And_Missing_WorkDir_Are_Rejected()
    {
        using var server = CreateServer();

        // 4,097-char command line exceeds the OptText maxLength 4096: schema rejection.
        var longArgsError = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\target.exe"),
                ["arguments"] = JsonSerializer.SerializeToElement(new string('a', 4097)),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, longArgsError.ErrorCode);

        // Missing working directory fails validation instead of throwing.
        var badDir = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\target.exe"),
                ["workDir"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\workdir"),
            }
        }, CancellationToken.None);
        Assert.Contains("debug_target_invalid", ResponseText(badDir));
    }

    [Theory]
    [InlineData("0x", true)] // Bare prefix, zero digits
    [InlineData("0x,", true)] // Prefix plus separator, zero digits
    [InlineData("9", true)] // Odd nibble
    [InlineData("0x9", true)] // Odd nibble behind a prefix
    [InlineData("90\n90", true)] // Newline is not a separator
    [InlineData("90\r90", true)] // Carriage return is not a separator
    [InlineData("90|90", true)] // Pipe is not a separator
    [InlineData("0xx90", true)] // Doubled prefix leaves a non-hex 'x'
    [InlineData("", true)] // Below minLength
    [InlineData("   ", true)] // Blank rejected by x-nonblank
    [InlineData("90", false)] // Single byte
    [InlineData("0x90", false)] // Single byte with prefix
    [InlineData("90-91", false)] // Dash is a documented separator
    [InlineData("90;91", false)] // Semicolon is a documented separator
    [InlineData("90\t91", true)] // Tab is dead on arrival: IsSafeText rejects controls before hex parsing
    [InlineData("aa BB", false)] // Lowercase hex accepted
    public async Task WriteMemory_HexBytes_Separator_And_Prefix_Edges(string hexBytes, bool expectRejection)
    {
        using var server = CreateServer();
        var task = server.CallToolAsync(new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["hexBytes"] = JsonSerializer.SerializeToElement(hexBytes),
            }
        }, CancellationToken.None);
        if (expectRejection)
        {
            var error = await Assert.ThrowsAsync<McpProtocolException>(() => task);
            Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
        }
        else
        {
            var resp = await task;
            Assert.False(resp.IsError);
        }
    }

    [Fact]
    public async Task WriteMemory_HexBytes_Just_Over_Native_Cap_Is_Rejected()
    {
        // 4097 bytes (8194 hex chars) exceeds x-maxBytes=4096; 4096 bytes is the cap.
        using var server = CreateServer();
        var over = new string('A', 8194);
        await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["hexBytes"] = JsonSerializer.SerializeToElement(over),
            }
        }, CancellationToken.None));

        var atCap = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "WriteMemory",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["address"] = JsonSerializer.SerializeToElement("cip"),
                ["hexBytes"] = JsonSerializer.SerializeToElement(new string('A', 8192)),
            }
        }, CancellationToken.None);
        Assert.False(atCap.IsError);
    }

    [Fact]
    public async Task BatchDebuggerOperations_Empty_And_Oversized_Batches_Rejected_At_Schema()
    {
        using var server = CreateServer();

        // minItems = 1: an empty batch never reaches the bridge.
        var emptyError = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(Array.Empty<object>()),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, emptyError.ErrorCode);

        // maxItems = 16: 17 requests are rejected up front.
        var oversized = Enumerable.Range(0, 17)
            .Select(_ => new { method = "ListBreakpoints", arguments = new { } })
            .ToArray();
        var oversizedError = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(oversized),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, oversizedError.ErrorCode);
    }

    [Fact]
    public async Task BatchDebuggerOperations_Malformed_Items_Rejected_At_Schema()
    {
        using var server = CreateServer();

        // Item without "arguments" violates the required properties.
        var missingArgs = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[]
                {
                    new { method = "ListBreakpoints" },
                }),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, missingArgs.ErrorCode);

        // Extra properties are forbidden by additionalProperties=false.
        var extraProp = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[]
                {
                    new { method = "ListBreakpoints", arguments = new { }, analysisId = "default" },
                }),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, extraProp.ErrorCode);

        // Non-object items are rejected before dispatch.
        var nonObject = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchDebuggerOperations",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[] { "ListBreakpoints" }),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, nonObject.ErrorCode);
    }

    [Fact]
    public async Task GhidraOpenStatus_Unknown_OperationId_Returns_NotFound()
    {
        var operations = new GhidraOpenOperations(null);
        try
        {
            var unknown = JsonSerializer.SerializeToElement(new { operationId = "00000000-0000-0000-0000-000000000000" });
            Assert.Contains("ghidra_operation_not_found", await operations.GetGhidraOpenStatusAsync(unknown));
            Assert.Contains("ghidra_operation_not_found", await operations.CancelAsync(unknown));

            // Non-string operation ids are rejected the same way, never thrown.
            var numeric = JsonSerializer.SerializeToElement(new { operationId = 42 });
            Assert.Contains("ghidra_operation_not_found", await operations.GetGhidraOpenStatusAsync(numeric));
        }
        finally { operations.Stop(); }
    }

    [Theory]
    [InlineData("path")]
    [InlineData("workDir")]
    public async Task OpenDebugTarget_Overlong_Strings_Rejected_At_Schema(string field)
    {
        using var server = CreateServer();
        var args = new Dictionary<string, JsonElement>
        {
            ["path"] = JsonSerializer.SerializeToElement("C:\\nonexistent\\target.exe"),
        };
        args[field] = JsonSerializer.SerializeToElement(new string('a', 32761));
        var error = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "OpenDebugTarget",
            Arguments = args,
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, error.ErrorCode);
    }

    [Fact]
    public async Task BatchStaticQueries_Empty_And_Oversized_Batches_Rejected_At_Schema()
    {
        using var server = CreateServer();

        var emptyError = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(Array.Empty<object>()),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, emptyError.ErrorCode);

        var oversized = Enumerable.Range(0, 17)
            .Select(_ => new { method = "ListSymbols", arguments = new { kind = "imports" } })
            .ToArray();
        var oversizedError = await Assert.ThrowsAsync<McpProtocolException>(() => server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(oversized),
            }
        }, CancellationToken.None));
        Assert.Equal(McpErrorCode.InvalidParams, oversizedError.ErrorCode);
    }

    [Fact]
    public async Task BatchStaticQueries_Debugger_Method_Cross_Rejected_As_Invalid_Batch()
    {
        using var server = CreateServer();
        var resp = await server.CallToolAsync(new CallToolRequestParams
        {
            Name = "BatchStaticQueries",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["requests"] = JsonSerializer.SerializeToElement(new object[]
                {
                    new { method = "ListSymbols", arguments = new { kind = "imports" } },
                    new { method = "SetBreakpoint", arguments = new { address = "cip" } },
                }),
            }
        }, CancellationToken.None);
        Assert.True(resp.IsError);
        var text = ResponseText(resp);
        Assert.Contains("invalid_batch", text);
        Assert.Contains("not a static read query", text);
    }
}
