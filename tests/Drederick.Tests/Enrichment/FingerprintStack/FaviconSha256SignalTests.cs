using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class FaviconSha256SignalTests
{
    [Fact]
    public void KnownHash_ProducesHit()
    {
        var corpus = new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>
        {
            ["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"]
                = new("jenkins", "jenkins", null),
        });
        var sig = new FaviconSha256Signal(corpus);
        var hits = sig.Extract(new FingerprintInput
        {
            FaviconSha256 = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        });
        var hit = Assert.Single(hits);
        Assert.Equal("jenkins", hit.Product);
        Assert.True(hit.Weight >= 0.6);
    }

    [Fact]
    public void UnknownHash_NoHits()
    {
        var corpus = new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>());
        var sig = new FaviconSha256Signal(corpus);
        Assert.Empty(sig.Extract(new FingerprintInput { FaviconSha256 = "deadbeef" }));
    }

    [Fact]
    public void EmbeddedCorpus_LoadsEntries()
    {
        var corpus = FaviconCorpus.LoadEmbedded();
        Assert.True(corpus.Count >= 30, $"expected ≥30 embedded entries, got {corpus.Count}");
    }
}
