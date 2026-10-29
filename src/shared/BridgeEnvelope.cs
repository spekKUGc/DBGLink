using System.Text.Json;
using System.Text.Json.Nodes;

namespace DbgLink.Shared;

/// <summary>
/// Single source of the bridge response envelope
/// <c>{"id":…,"ok":true,"result":…}</c> / <c>{"id":…,"ok":false,"error":{…}}</c>.
/// Used by the MCP server and the launcher control pipe; keep key order stable —
/// wire snapshots in tests assert exact serialization.
/// </summary>
public static class BridgeEnvelope
{
    public const int MaxErrorMessageChars = 512;

    /// <summary>
    /// Default wire options: the native bridge (like the Ghidra side) already
    /// writes literal non-ASCII; re-serializing with the stock encoder would
    /// turn one character into a six-byte \\uXXXX escape and inflate every
    /// success/error envelope that carries text.
    /// </summary>
    private static readonly JsonSerializerOptions WireOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Success(JsonObject result, int id = 0, JsonSerializerOptions? options = null)
        => new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = result }.ToJsonString(options ?? WireOptions);

    public static string Error(string code, string message, string? suggest = null, int id = 0, JsonSerializerOptions? options = null)
    {
        var clipped = ClipErrorMessage(message);
        var error = new JsonObject { ["code"] = code, ["message"] = clipped };
        if (!string.IsNullOrEmpty(suggest))
            error["suggest"] = suggest;
        return new JsonObject
        {
            ["id"] = id,
            ["ok"] = false,
            ["error"] = error,
        }.ToJsonString(options ?? WireOptions);
    }

    /// <summary>Error envelope that clips the message to <see cref="MaxErrorMessageChars"/>,
    /// for paths that relay exception text from external processes.</summary>
    public static string BoundedError(int id, string code, string message)
        => Error(code, message, id: id);

    internal static string ClipErrorMessage(string message)
        => message.Length <= MaxErrorMessageChars ? message
            : message[..MaxErrorMessageChars] + $"...[truncated +{message.Length - MaxErrorMessageChars}chars]";
}
