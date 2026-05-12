using Drederick.Recon.Cms;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class CmsCveCorpusTests
{
    [Fact]
    public void AppliesTo_RecognisesAllFiveProducts()
    {
        Assert.True(CmsCveCorpus.AppliesTo("wordpress", "wordpress"));
        Assert.True(CmsCveCorpus.AppliesTo("joomla", "joomla!"));
        Assert.True(CmsCveCorpus.AppliesTo("drupal", "drupal"));
        Assert.True(CmsCveCorpus.AppliesTo("magento", "magento"));
        Assert.True(CmsCveCorpus.AppliesTo("salesagility", "suitecrm"));
        Assert.True(CmsCveCorpus.AppliesTo("adobe", "commerce"));
        Assert.False(CmsCveCorpus.AppliesTo("pterodactyl", "panel"));
        Assert.False(CmsCveCorpus.AppliesTo(null, null));
    }

    [Fact]
    public void Match_UnknownVersion_EmitsAllEntriesForProduct()
    {
        var wp = CmsCveCorpus.Match("wordpress", "wordpress", null);
        Assert.True(wp.Count >= 6);

        var d = CmsCveCorpus.Match("drupal", "drupal", null);
        Assert.True(d.Count >= 4);
    }

    [Fact]
    public void Match_VersionInRange_FiresHeadliners()
    {
        var d8 = CmsCveCorpus.Match("drupal", "drupal", "8.5.0");
        Assert.Contains(d8, m => m.CveId == "CVE-2018-7600");
        Assert.Contains(d8, m => m.CveId == "CVE-2018-7602");

        var j427 = CmsCveCorpus.Match("joomla", "joomla!", "4.2.7");
        Assert.Contains(j427, m => m.CveId == "CVE-2023-23752");

        var mage246 = CmsCveCorpus.Match("magento", "magento", "2.4.6");
        Assert.Contains(mage246, m => m.CveId == "CVE-2024-34102");

        var suite7142 = CmsCveCorpus.Match("salesagility", "suitecrm", "7.14.2");
        Assert.Contains(suite7142, m => m.CveId == "CVE-2023-6886");
    }

    [Fact]
    public void Match_VersionOutOfRange_DropsFixedBuilds()
    {
        // WordPress 6.5 is past every entry's upper bound.
        var wpNew = CmsCveCorpus.Match("wordpress", "wordpress", "6.5.0");
        Assert.DoesNotContain(wpNew, m => m.CveId == "CVE-2017-1001000");
        Assert.DoesNotContain(wpNew, m => m.CveId == "CVE-2023-2745");

        // Drupal 10 is past every Drupalgeddon entry.
        var d10 = CmsCveCorpus.Match("drupal", "drupal", "10.0.0");
        Assert.DoesNotContain(d10, m => m.CveId == "CVE-2018-7600");
    }

    [Fact]
    public void AllEntries_NonEmptyAndHasRefUrls()
    {
        var all = CmsCveCorpus.AllEntries();
        Assert.NotEmpty(all);
        foreach (var e in all)
        {
            Assert.False(string.IsNullOrWhiteSpace(e.CveId));
            Assert.NotNull(e.RefUrls);
            Assert.NotEmpty(e.RefUrls);
            Assert.False(string.IsNullOrWhiteSpace(e.Summary));
        }
    }

    [Fact]
    public void Match_WrongProduct_ReturnsEmpty()
    {
        var matches = CmsCveCorpus.Match("nginx", "nginx", "1.18.0");
        Assert.Empty(matches);
    }
}
