using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class TlsCertSignalTests
{
    [Fact]
    public void SubjectKeyword_ScoresHigherThanIssuerOnly()
    {
        var sig = new TlsCertSignal();
        var hits = sig.Extract(new FingerprintInput
        {
            TlsSubject = "CN=plesk.example.com, O=Plesk Inc.",
            TlsIssuer = "CN=Let's Encrypt R3",
        });
        var hit = Assert.Single(hits);
        Assert.Equal("plesk", hit.Vendor);
        Assert.Equal("plesk", hit.Product);
        Assert.True(hit.Weight >= 0.55);
    }

    [Fact]
    public void IssuerOnlyMatch_ScoresLower()
    {
        var sig = new TlsCertSignal();
        var hits = sig.Extract(new FingerprintInput
        {
            TlsSubject = "CN=example.com",
            TlsIssuer = "CN=VMware Engineering, O=VMware",
        });
        Assert.Contains(hits, h => h.Vendor == "vmware" && h.Weight < 0.5);
    }

    [Fact]
    public void SubjectAltNames_AreSearched()
    {
        var sig = new TlsCertSignal();
        var hits = sig.Extract(new FingerprintInput
        {
            TlsSubject = "CN=example.com",
            TlsSubjectAltNames = new[] { "vsphere.corp.local", "vcenter.corp.local" },
        });
        Assert.Contains(hits, h => h.Product == "vsphere");
        Assert.Contains(hits, h => h.Product == "vcenter");
    }
}
