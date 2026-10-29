using DbgLink.Server;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Proof for the auth-path case bug: McpRequestPolicy compared the request path
/// ordinal/case-sensitive while endpoint routing matches case-insensitively, so
/// GET /MCP without a token reached the next handler (no 401).
/// </summary>
public sealed class McpAuthPathCaseTests
{
    private const string Token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static (DefaultHttpContext Context, bool Invoked) Invoke(
        string path, string? authHeader, bool requireAuth = true)
    {
        var invoked = false;
        var config = new ServerConfig { Port = ServerConfig.DefaultPort, AuthToken = Token, RequireAuthToken = requireAuth };
        var policy = new McpRequestPolicy(
            next: _ => { invoked = true; return Task.CompletedTask; },
            config,
            new ServerMetrics());
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Host = new HostString("127.0.0.1", ServerConfig.DefaultPort);
        context.Request.Path = new PathString(path);
        if (authHeader is not null)
            context.Request.Headers.Authorization = authHeader;
        policy.InvokeAsync(context).GetAwaiter().GetResult();
        return (context, invoked);
    }

    [Theory]
    [InlineData("/mcp")]
    [InlineData("/MCP")]
    [InlineData("/Mcp")]
    [InlineData("/mcp/")]
    public void McpPathVariants_WithoutToken_AreRejected(string path)
    {
        var (context, invoked) = Invoke(path, authHeader: null);
        Assert.False(invoked);
        Assert.Equal(401, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("/mcp")]
    [InlineData("/MCP")]
    public void McpPathVariants_WithToken_ReachHandler(string path)
    {
        var (context, invoked) = Invoke(path, "Bearer " + Token);
        Assert.True(invoked);
        Assert.NotEqual(401, context.Response.StatusCode);
    }

    [Fact]
    public void Metrics_WithoutToken_IsRejected()
    {
        var (context, invoked) = Invoke("/metrics", authHeader: null);
        Assert.False(invoked);
        Assert.Equal(401, context.Response.StatusCode);
    }

    /// <summary>
    /// ASP.NET endpoint routing normalizes the trailing slash, so "/metrics/"
    /// reaches the same endpoint as "/metrics". The token gate must use the
    /// same normalization: an exact PathString comparison left "/metrics/"
    /// outside the gate and served the metrics snapshot unauthenticated.
    /// </summary>
    [Theory]
    [InlineData("/metrics")]
    [InlineData("/metrics/")]
    [InlineData("/METRICS")]
    [InlineData("/Metrics/")]
    public void MetricsPathVariants_WithoutToken_AreRejected(string path)
    {
        var (context, invoked) = Invoke(path, authHeader: null);
        Assert.False(invoked);
        Assert.Equal(401, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("/metrics")]
    [InlineData("/metrics/")]
    public void MetricsPathVariants_WithToken_ReachHandler(string path)
    {
        var (context, invoked) = Invoke(path, "Bearer " + Token);
        Assert.True(invoked);
        Assert.NotEqual(401, context.Response.StatusCode);
    }

    /// <summary>
    /// A path that merely starts with the same characters must not be gated
    /// as the metrics endpoint (segment-boundary match, not a raw prefix).
    /// </summary>
    [Fact]
    public void NonMetricsPath_IsNotGatedByTheMetricsRule()
    {
        var (context, invoked) = Invoke("/metricsomething", authHeader: null);
        Assert.True(invoked);
        Assert.NotEqual(401, context.Response.StatusCode);
    }

    /// <summary>
    /// DBGLINK_REQUIRE_AUTH=0 opens /mcp but must never open /metrics: the
    /// metrics snapshot exposes session ids, function names and addresses.
    /// </summary>
    [Fact]
    public void Metrics_RequiresToken_EvenWhenMcpAuthIsDisabled()
    {
        var (context, invoked) = Invoke("/metrics", authHeader: null, requireAuth: false);
        Assert.False(invoked);
        Assert.Equal(401, context.Response.StatusCode);
    }

    [Fact]
    public void Mcp_IsOpen_WhenAuthIsDisabled()
    {
        var (context, invoked) = Invoke("/mcp", authHeader: null, requireAuth: false);
        Assert.True(invoked);
        Assert.NotEqual(401, context.Response.StatusCode);
    }
}
