using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class HttpHeaderSignalTests
{
    [Fact]
    public void ServerHeader_EmitsHit()
    {
        var sig = new HttpHeaderSignal();
        var hits = sig.Extract(new FingerprintInput { HttpServer = "nginx/1.18.0" });
        Assert.Contains(hits, h => h.Product == "nginx" && h.Version == "1.18.0");
    }

    [Fact]
    public void XAspNetVersion_MapsToMicrosoftAspNet()
    {
        var sig = new HttpHeaderSignal();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-AspNet-Version"] = "4.0.30319",
        };
        var hits = sig.Extract(new FingerprintInput { HttpHeaders = headers });
        Assert.Contains(hits, h => h.Vendor == "microsoft" && h.Product == "asp.net" && h.Version == "4.0.30319");
    }

    [Fact]
    public void XPoweredBy_PHP_EmitsTokenizedHit()
    {
        var sig = new HttpHeaderSignal();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Powered-By"] = "PHP/7.4.3",
        };
        var hits = sig.Extract(new FingerprintInput { HttpHeaders = headers });
        Assert.Contains(hits, h => h.Product == "php" && h.Version == "7.4.3");
    }

    [Fact]
    public void XConfluenceVersion_MapsToAtlassian()
    {
        var sig = new HttpHeaderSignal();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Confluence-Version"] = "7.13.0",
        };
        var hits = sig.Extract(new FingerprintInput { HttpHeaders = headers });
        Assert.Contains(hits, h => h.Vendor == "atlassian" && h.Product == "confluence" && h.Version == "7.13.0");
    }
}
