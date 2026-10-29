using System.Text.Json.Nodes;

namespace DbgLink.Server;

/// <summary>
/// Compatibility shim: the compact {columns,rows} wire shape is owned by
/// <see cref="ToolPresentation"/>. Kept so existing call sites
/// (e.g. the triage/map tools) keep compiling and producing identical bytes
/// while they migrate to <see cref="ToolPresentation"/>.
/// </summary>
internal static class CompactJson
{
    public static string RowsInEnvelope(string raw, params string[] arrayKeys)
        => ToolPresentation.Compact(raw, arrayKeys);

    public static bool CompactChild(JsonObject parent, string key)
        => ToolPresentation.Compact(parent, key);
}
