using System.Net;
using System.Net.Http;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class HttpHeadersToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpHeadersTool(NativeTestHelpers.SmallScope(), audit);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8"));
    }

    [Fact]
    public async Task Captures_Response_Headers_Via_HEAD()
    {
        var handler = new StubHttpHandler(req =>
        {
            Assert.Equal(HttpMethod.Head, req.Method);
            var resp = new HttpResponseMessage(HttpStatusCode.OK);
            resp.Headers.Add("X-Powered-By", "Lab/1.0");
            resp.Headers.Add("Set-Cookie", new[] { "a=1", "b=2" });
            return resp;
        });
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpHeadersTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Equal(200, r.Status);
        Assert.Equal("HEAD", r.Method);
        Assert.Contains("X-Powered-By", r.Headers.Keys);
        Assert.Equal(2, r.Headers["Set-Cookie"].Count);
    }

    [Fact]
    public async Task Falls_Back_To_GET_On_405()
    {
        int call = 0;
        var handler = new StubHttpHandler(req =>
        {
            call++;
            if (req.Method == HttpMethod.Head)
                return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed);
            var resp = new HttpResponseMessage(HttpStatusCode.OK);
            resp.Headers.Add("Server", "lab");
            return resp;
        });
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpHeadersTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Equal("GET", r.Method);
        Assert.Equal(2, call);
        Assert.Contains("Server", r.Headers.Keys);
    }
}
