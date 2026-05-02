using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class BannerSignalTests
{
    [Theory]
    [InlineData("Apache/2.4.41 (Ubuntu)", "apache", "http_server", "2.4.41")]
    [InlineData("nginx/1.18.0", "nginx", "nginx", "1.18.0")]
    [InlineData("Microsoft-IIS/10.0", "microsoft", "iis", "10.0")]
    [InlineData("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "openbsd", "openssh", "8.2p1")]
    [InlineData("vsftpd 3.0.3", "vsftpd", "vsftpd", "3.0.3")]
    [InlineData("MySQL 8.0.32", "oracle", "mysql", "8.0.32")]
    [InlineData("Apache Tomcat/9.0.65", "apache", "tomcat", "9.0.65")]
    [InlineData("Jenkins/2.387.3", "jenkins", "jenkins", "2.387.3")]
    public void ExactPattern_MatchesAtHighWeight(string banner, string vendor, string product, string version)
    {
        var sig = new BannerSignal();
        var hits = sig.Extract(new FingerprintInput { Banner = banner });
        Assert.Contains(hits, h =>
            h.Vendor == vendor && h.Product == product && h.Version == version && h.Weight >= 0.85);
    }

    [Fact]
    public void EmptyInput_NoHits()
    {
        var sig = new BannerSignal();
        Assert.Empty(sig.Extract(new FingerprintInput()));
    }

    [Fact]
    public void NmapProductVersion_AlsoExtracted()
    {
        var sig = new BannerSignal();
        var hits = sig.Extract(new FingerprintInput
        {
            NmapProduct = "OpenSSH",
            NmapVersion = "8.2p1",
        });
        Assert.Contains(hits, h => h.Product == "openssh" && h.Version == "8.2p1");
    }

    [Fact]
    public void GenericFallback_FiresOnlyWhenNoExactMatch()
    {
        var sig = new BannerSignal();
        var hits = sig.Extract(new FingerprintInput { Banner = "WeirdoServer/1.2.3" });
        Assert.Contains(hits, h => h.Signal == "banner" && h.Weight < 0.7);
    }
}
