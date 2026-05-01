using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class FingerprintAggregatorTests
{
    [Fact]
    public void NoisyOrCombines_TwoIndependentSignals()
    {
        var agg = new FingerprintAggregator();
        var hits = new[]
        {
            new FingerprintSignalHit("banner",      "nginx", "nginx", "1.18.0", 0.9),
            new FingerprintSignalHit("http-header", "nginx", "nginx", "1.18.0", 0.7),
        };
        var cands = agg.Aggregate(hits);
        var c = Assert.Single(cands);
        // 1 - (0.1 * 0.3) = 0.97
        Assert.InRange(c.Confidence, 0.96, 0.98);
        Assert.Equal(2, c.Signals.Count);
    }

    [Fact]
    public void BelowThreshold_Pruned()
    {
        var agg = new FingerprintAggregator();
        var hits = new[]
        {
            new FingerprintSignalHit("ja3-ja4", "x", "y", null, 0.2),
        };
        Assert.Empty(agg.Aggregate(hits));
    }

    [Fact]
    public void DistinctVersions_DoNotMerge()
    {
        var agg = new FingerprintAggregator();
        var hits = new[]
        {
            new FingerprintSignalHit("banner", "nginx", "nginx", "1.18.0", 0.9),
            new FingerprintSignalHit("banner", "nginx", "nginx", "1.20.0", 0.9),
        };
        var cands = agg.Aggregate(hits);
        Assert.Equal(2, cands.Count);
    }

    [Fact]
    public void BuildCpe_FormatsCorrectly()
    {
        Assert.Equal(
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            FingerprintAggregator.BuildCpe("nginx", "nginx", "1.18.0"));
        Assert.Equal(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            FingerprintAggregator.BuildCpe("Apache", "http_server", null));
    }

    [Fact]
    public void Sorted_ByDescendingConfidence()
    {
        var agg = new FingerprintAggregator();
        var hits = new[]
        {
            new FingerprintSignalHit("banner", "nginx",  "nginx",  "1.18.0", 0.6),
            new FingerprintSignalHit("banner", "apache", "apache", "2.4.0",  0.9),
        };
        var cands = agg.Aggregate(hits);
        Assert.Equal("apache", cands[0].Product);
        Assert.Equal("nginx",  cands[1].Product);
    }
}
