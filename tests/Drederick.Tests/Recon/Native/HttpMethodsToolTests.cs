using System.Net;
using System.Net.Http;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class HttpMethodsToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpMethodsTool(NativeTestHelpers.SmallScope(), audit);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("172.16.0.1"));
    }

    [Fact]
    public async Task Parses_Allow_Header_And_Flags_Risky_Methods()
    {
        var handler = new StubHttpHandler(req =>
        {
            Assert.Equal(HttpMethod.Options, req.Method);
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(string.Empty),
            };
            resp.Content.Headers.TryAddWithoutValidation("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS");
            return resp;
        });
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpMethodsTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Contains("PUT", r.Allow);
        Assert.Contains("PUT", r.RiskyMethods);
        Assert.Contains("DELETE", r.RiskyMethods);
        Assert.DoesNotContain("GET", r.RiskyMethods);
    }

    [Fact]
    public void SplitMethods_Trims_And_Uppercases()
    {
        var got = HttpMethodsTool.SplitMethods(" get , post , Trace ").ToList();
        Assert.Equal(new[] { "GET", "POST", "TRACE" }, got);
    }
}
