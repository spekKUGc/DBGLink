// ReverseBench: one DbgLink MCP tool call over the real wire, logged for scoring.
// Pattern mirrors tests/DbgLink.Tests/SdkHttpTransportTests.cs (stateless JSON-RPC POST).
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.ML.Tokenizers;

internal static class Program
{
    private static readonly TiktokenTokenizer Tok = TiktokenTokenizer.CreateForEncoding("cl100k_base");
    private static readonly object Gate = new();

    internal static async Task<int> Main(string[] args)
    {
        var cmd = args.ElementAtOrDefault(0);
        if (cmd is "stats") return Stats();
        if (cmd is "reset") return Reset();
        if (cmd is "list") return await ListAsync();
        if (cmd is not "call" && cmd is not "call-file" || args.Length < 3)
        {
            Console.Error.WriteLine("usage: ReverseBench call <Tool> <jsonArgs> | call-file <Tool> <path> | list | stats | reset");
            return 2;
        }
        if (cmd is "call-file") return await CallFileAsync(args[1], args[2]);
        return await CallAsync(args[1], args[2]);
    }

    private static string Endpoint() =>
        Environment.GetEnvironmentVariable("DBGLINK_URL") is { Length: > 0 } u ? u : "http://127.0.0.1:50301/mcp";

    private static string? Token()
    {
        var env = Environment.GetEnvironmentVariable("DBGLINK_BEARER_TOKEN");
        if (!string.IsNullOrWhiteSpace(env)) return env.Trim();
        var configured = Environment.GetEnvironmentVariable("DBGLINK_CONFIG_PATH");
        foreach (var path in new[] { configured, ConfigPath("mcp_config.json"), ConfigPath("config.json") })
        {
            if (string.IsNullOrEmpty(path)) continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("AuthToken", out var t) && t.ValueKind == JsonValueKind.String
                    && !string.IsNullOrWhiteSpace(t.GetString())) return t.GetString()!.Trim();
            }
            catch { }
        }
        return null;
    }

    private static string ConfigPath(string name)
    {
        var lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrEmpty(lad) ? "" : Path.Combine(lad, "DBGLink", name);
    }

    private static int Tokens(string? s)
    {
        lock (Gate) return string.IsNullOrEmpty(s) ? 0 : Tok.CountTokens(s);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, "DbgLink.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Directory.GetCurrentDirectory();
    }

    private static string LogPath() => Path.Combine(RepoRoot(), "artifacts", "reverse-bench", "calls.jsonl");

    private static string ToolsPath() => Path.Combine(RepoRoot(), "artifacts", "reverse-bench", "tools.json");

    private static async Task<int> ListAsync()
    {
        var envelope = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}";
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(110) };
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
        if (Token() is { } tok) http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tok);
        var sw = Stopwatch.StartNew();
        string text; bool isError = false; int status = 0;
        try
        {
            using var resp = await http.PostAsync(Endpoint(), new StringContent(envelope, Encoding.UTF8, "application/json"));
            status = (int)resp.StatusCode;
            var body = await resp.Content.ReadAsStringAsync();
            if (resp.Content.Headers.ContentType?.MediaType == "text/event-stream")
                body = body.Split('\n').FirstOrDefault(l => l.StartsWith("data: ", StringComparison.Ordinal))?[6..] ?? body;
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) { text = err.GetRawText(); isError = true; }
            else if (root.TryGetProperty("result", out var res) && res.TryGetProperty("tools", out var tools))
            {
                text = tools.GetRawText();
            }
            else { text = body; isError = true; }
            if (!resp.IsSuccessStatusCode && !isError && !root.TryGetProperty("error", out _)) isError = true;
        }
        catch (Exception ex)
        {
            sw.Stop();
            Console.Error.WriteLine($"ReverseBench: no server at {Endpoint()} ({ex.GetType().Name}). Start DbgLink first.");
            return 2;
        }
        sw.Stop();
        var row = JsonSerializer.Serialize(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            tool = "tools/list", argChars = 0, respChars = text.Length,
            respTokens = Tokens(text), elapsedMs = sw.ElapsedMilliseconds, isError, httpStatus = status,
        });
        var path = LogPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.AppendAllText(path, row + "\n");
        if (isError) { Console.WriteLine(text); return 1; }
        var tpath = ToolsPath();
        Directory.CreateDirectory(Path.GetDirectoryName(tpath)!);
        File.WriteAllText(tpath, text);
        using var list = JsonDocument.Parse(text);
        var rows = new List<(string Name, string First)>();
        foreach (var el in list.RootElement.EnumerateArray())
        {
            var name = el.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : "";
            var desc = el.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() ?? "" : "";
            var first = desc.Split('\n')[0].TrimEnd('\r').Trim();
            rows.Add((name, first));
        }
        rows.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        foreach (var r in rows) Console.WriteLine($"{r.Name}\t{r.First}");
        return 0;
    }

    private static async Task<int> CallAsync(string tool, string argsJson)
    {
        string argsText;
        try { argsText = ParseArgsObject(argsJson); }
        catch (Exception ex) { Console.Error.WriteLine($"args JSON invalid: {OneLine(ex.Message)}. Tip: put the JSON in a file and use -ArgsFile <path>."); return 2; }
        return await SendAndLogAsync(tool, argsText);
    }

    private static async Task<int> CallFileAsync(string tool, string path)
    {
        var full = Path.GetFullPath(path);
        string content;
        try { content = await File.ReadAllTextAsync(full, Encoding.UTF8); }
        catch (Exception ex) { Console.Error.WriteLine($"args file not found: {full} ({OneLine(ex.Message)})"); return 2; }
        string argsText;
        try { argsText = ParseArgsObject(content); }
        catch (Exception ex) { Console.Error.WriteLine($"args JSON invalid: {OneLine(ex.Message)}. Tip: put the JSON in a file and use -ArgsFile <path>."); return 2; }
        return await SendAndLogAsync(tool, argsText);
    }

    private static string ParseArgsObject(string json)
    {
        using var d = JsonDocument.Parse(json);
        if (d.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("root must be a JSON object");
        return d.RootElement.GetRawText();
    }

    private static string OneLine(string s) =>
        (s ?? "").Split('\n')[0].TrimEnd('\r').Trim();

    private static async Task<int> SendAndLogAsync(string tool, string argsText)
    {
        var envelope = $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":{JsonSerializer.Serialize(tool)},\"arguments\":{argsText}}}}}";
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(110) };
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/event-stream");
        if (Token() is { } tok) http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tok);
        var sw = Stopwatch.StartNew();
        string text; bool isError = false; int status = 0;
        try
        {
            using var resp = await http.PostAsync(Endpoint(), new StringContent(envelope, Encoding.UTF8, "application/json"));
            status = (int)resp.StatusCode;
            var body = await resp.Content.ReadAsStringAsync();
            if (resp.Content.Headers.ContentType?.MediaType == "text/event-stream")
                body = body.Split('\n').FirstOrDefault(l => l.StartsWith("data: ", StringComparison.Ordinal))?[6..] ?? body;
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) { text = err.GetRawText(); isError = true; }
            else if (root.TryGetProperty("result", out var res))
            {
                isError = res.TryGetProperty("isError", out var e) && e.ValueKind == JsonValueKind.True;
                text = res.TryGetProperty("content", out var c) && c.GetArrayLength() > 0 &&
                    c[0].TryGetProperty("text", out var t) ? t.GetString() ?? "" : res.GetRawText();
            }
            else { text = body; isError = true; }
            if (!resp.IsSuccessStatusCode && !isError && !root.TryGetProperty("error", out _)) isError = true;
        }
        catch (Exception ex)
        {
            sw.Stop();
            Console.Error.WriteLine($"ReverseBench: no server at {Endpoint()} ({ex.GetType().Name}). Start DbgLink first.");
            return 2;
        }
        sw.Stop();
        var row = JsonSerializer.Serialize(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            tool, argChars = argsText.Length, respChars = text.Length,
            respTokens = Tokens(text), elapsedMs = sw.ElapsedMilliseconds, isError, httpStatus = status,
        });
        var path = LogPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.AppendAllText(path, row + "\n");
        Console.WriteLine(text);
        return isError ? 1 : 0;
    }

    private static int Stats()
    {
        var path = LogPath();
        if (!File.Exists(path)) { Console.WriteLine("calls=0 errors=0 chars=0 tokens=0 ms=0"); return 0; }
        long n = 0, err = 0, ch = 0, tk = 0, ms = 0;
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var d = JsonDocument.Parse(line);
                var r = d.RootElement;
                n++; ch += r.GetProperty("respChars").GetInt64();
                tk += r.GetProperty("respTokens").GetInt64(); ms += r.GetProperty("elapsedMs").GetInt64();
                if (r.GetProperty("isError").GetBoolean()) err++;
            }
            catch { }
        }
        Console.WriteLine($"calls={n} errors={err} chars={ch} tokens={tk} ms={ms} avgMs={(n == 0 ? 0 : ms / n)}");
        return 0;
    }

    private static int Reset()
    {
        var path = LogPath();
        if (File.Exists(path)) File.Delete(path);
        Console.WriteLine($"log reset: {path}");
        return 0;
    }
}
