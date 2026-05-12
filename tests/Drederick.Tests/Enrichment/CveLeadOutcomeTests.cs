using Drederick.Enrichment;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-033 — record-shape tests for <see cref="CveLeadOutcome"/>.
/// </summary>
public class CveLeadOutcomeTests
{
    [Fact]
    public void Defaults_Status_To_Pursued_And_No_Error()
    {
        var o = new CveLeadOutcome("CVE-2024-0001", new[] { "metasploit-git" }, 1, true);
        Assert.Equal("CVE-2024-0001", o.CveId);
        Assert.Single(o.SourcesTried);
        Assert.Equal(1, o.PocsCached);
        Assert.True(o.Succeeded);
        Assert.Equal("pursued", o.Status);
        Assert.Null(o.Error);
    }

    [Fact]
    public void Status_And_Error_Surface_When_Set()
    {
        var o = new CveLeadOutcome(
            "CVE-2024-9999", Array.Empty<string>(), 0, false,
            Status: "rate_limited", Error: "429");
        Assert.Equal("rate_limited", o.Status);
        Assert.Equal("429", o.Error);
        Assert.False(o.Succeeded);
    }

    [Fact]
    public void Record_Equality_By_Value()
    {
        var sources = new[] { "nuclei-templates-git" };
        var a = new CveLeadOutcome("CVE-2024-0002", sources, 2, true);
        var b = new CveLeadOutcome("CVE-2024-0002", sources, 2, true);
        Assert.Equal(a, b);
    }
}
