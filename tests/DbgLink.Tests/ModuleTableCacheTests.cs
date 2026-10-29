using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

/// <summary>
/// Round 3 round-trip rule: the native module table is fetched once per
/// session window and shared by breakpoint module+rva resolution, mapping and
/// error enrichment — not once per caller.
/// </summary>
public sealed class ModuleTableCacheTests
{
    private const string ModuleResponse =
        "{\"id\":1,\"ok\":true,\"result\":{\"modules\":[{\"name\":\"test.exe\",\"base\":\"0x140000000\",\"end\":\"0x140050000\",\"path\":\"C:\\\\test.exe\"}],\"truncated\":false}}";

    [Fact]
    public async Task Second_module_lookup_inside_the_window_is_free()
    {
        AddressMapping.InvalidateModuleCache();
        var bridge = new RecordingBridge();
        var fetches = 0;
        Task<string> Fetch(CancellationToken token)
        {
            fetches++;
            return Task.FromResult(ModuleResponse);
        }

        var first = await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None);
        var second = await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None);

        Assert.Single(first!);
        Assert.Single(second!);
        Assert.Equal(1, fetches);
    }

    [Fact]
    public async Task Invalidation_forces_a_refetch()
    {
        AddressMapping.InvalidateModuleCache();
        var bridge = new RecordingBridge();
        var fetches = 0;
        Task<string> Fetch(CancellationToken token)
        {
            fetches++;
            return Task.FromResult(ModuleResponse);
        }

        await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None);
        AddressMapping.InvalidateModuleCache();
        await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None);

        Assert.Equal(2, fetches);
    }

    [Fact]
    public async Task Failed_lookup_is_not_cached()
    {
        AddressMapping.InvalidateModuleCache();
        var bridge = new RecordingBridge();
        var fetches = 0;
        Task<string> Fetch(CancellationToken token)
        {
            fetches++;
            return Task.FromResult("{\"id\":1,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"down\"}}");
        }

        Assert.Null(await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None));
        Assert.Null(await AddressMapping.ReadCachedModuleTableAsync(bridge, Fetch, CancellationToken.None));
        Assert.Equal(2, fetches);
    }
}
