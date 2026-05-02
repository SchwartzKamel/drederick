using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class HttpTitleToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpTitleTool(NativeTestHelpers.SmallScope(), audit);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.168.1.1"));
    }

    [Fact]
    public async Task Extracts_Title_From_Body()
    {
        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "<html><head><title>Drederick Lab</title></head></html>",
                Encoding.UTF8, "text/html"),
        });
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new HttpTitleTool(NativeTestHelpers.SmallScope(), audit, handler);
        var r = await tool.ProbeAsync("10.10.10.5", 80);
        Assert.Equal(200, r.Status);
        Assert.Equal("Drederick Lab", r.Title);
    }

    [Fact]
    public void ExtractTitle_Handles_Whitespace_And_Decodes_Entities()
    {
        var t = HttpTitleTool.ExtractTitle("<TITLE>\n  AT&amp;T\n</TITLE>");
        Assert.Equal("AT&T", t);
    }
}
