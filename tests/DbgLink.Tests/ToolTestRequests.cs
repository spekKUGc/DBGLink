using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace DbgLink.Tests;

// Adapts existing domain fixtures to typed SDK calls. Wire protocol is tested over HTTP separately.
internal static class ToolTestRequests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static async Task<string?> ExecuteTestRequestAsync(this LocalMcpServer server, string body, CancellationToken token, string? unusedProtocol = null)
    {
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var response = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = JsonNode.Parse(root.GetProperty("id").GetRawText()) };
        try
        {
            response["result"] = root.GetProperty("method").GetString() switch
            {
                "tools/list" => new JsonObject { ["tools"] = server.ListTools() },
                "tools/call" => JsonSerializer.SerializeToNode(await server.CallToolAsync(
                    root.GetProperty("params").Deserialize<CallToolRequestParams>(Json)!, token), Json),
                _ => throw new InvalidOperationException("Use SDK HTTP tests for protocol fixtures.")
            };
        }
        catch (McpProtocolException exception)
        {
            response["error"] = new JsonObject { ["code"] = (int)exception.ErrorCode, ["message"] = exception.Message };
        }
        return response.ToJsonString();
    }

    public static string? ValidateArguments(this LocalMcpServer server, string name, JsonElement arguments)
    {
        var metadata = server.ListTools().OfType<JsonObject>().Single(tool => tool["name"]!.GetValue<string>() == name);
        return ToolArgumentRules.Validate((JsonObject)metadata["inputSchema"]!, arguments);
    }
}
