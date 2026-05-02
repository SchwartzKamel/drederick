using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class HttpRobotsToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpRobotsTool(NativeTestHelpers.SmallScope(), audit);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("172.16.0.1"));
    }

    [Fact]
    public async Task Parses_Disallow_Allow_Sitemap()
    {
        const string body =
            "User-agent: *\n" +
            "Disallow: /admin\n" +
            "Disallow: /private  # secret\n" +
            "Allow: /public\n" +
            "Sitemap: https://example.com/sitemap.xml\n";
        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/plain"),
        });
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpRobotsTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Equal(200, r.Status);
        Assert.Equal(new[] { "/admin", "/private" }, r.Disallowed);
        Assert.Equal(new[] { "/public" }, r.Allowed);
        Assert.Equal(new[] { "https://example.com/sitemap.xml" }, r.Sitemaps);
    }

    [Fact]
    public async Task NotFound_Yields_Empty_Result_Without_Error()
    {
        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpRobotsTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Equal(404, r.Status);
        Assert.Empty(r.Disallowed);
        Assert.Null(r.Error);
    }
}
