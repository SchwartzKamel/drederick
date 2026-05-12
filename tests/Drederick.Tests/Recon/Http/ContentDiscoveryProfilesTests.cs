using Drederick.Recon.Http;
using Xunit;

namespace Drederick.Tests.Recon.Http;

/// <summary>
/// GAP-057 / htb-content-discovery-vhost-aware: unit tests for the
/// <see cref="ContentDiscoveryProfile"/> enum, profile name parsing,
/// and the default extension-fanout list.
/// </summary>
public class ContentDiscoveryProfilesTests
{
    [Fact]
    public void DefaultExtensionFanout_Has_Expected_Members_In_Stable_Order()
    {
        var expected = new[]
        {
            "php", "html", "txt", "bak", "zip",
            "log", "old", "inc", "asp", "aspx", "jsp",
        };
        Assert.Equal(expected, ContentDiscoveryProfiles.DefaultExtensionFanout.ToArray());
    }

    [Fact]
    public void DefaultExtensionFanout_Has_No_Duplicates_And_No_Leading_Dots()
    {
        var list = ContentDiscoveryProfiles.DefaultExtensionFanout;
        Assert.Equal(list.Count, list.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(list, ext =>
        {
            Assert.False(string.IsNullOrWhiteSpace(ext));
            Assert.False(ext.StartsWith('.'));
            Assert.Equal(ext, ext.ToLowerInvariant());
        });
    }

    [Theory]
    [InlineData(ContentDiscoveryProfile.Default, "default")]
    [InlineData(ContentDiscoveryProfile.RaftSmall, "raft-small")]
    [InlineData(ContentDiscoveryProfile.RaftMedium, "raft-medium")]
    [InlineData(ContentDiscoveryProfile.RaftLarge, "raft-large")]
    public void ToWireName_Returns_Canonical_Kebab(ContentDiscoveryProfile p, string expected)
    {
        Assert.Equal(expected, ContentDiscoveryProfiles.ToWireName(p));
    }

    [Theory]
    [InlineData("default", ContentDiscoveryProfile.Default)]
    [InlineData("DEFAULT", ContentDiscoveryProfile.Default)]
    [InlineData("raft-small", ContentDiscoveryProfile.RaftSmall)]
    [InlineData("raft_medium", ContentDiscoveryProfile.RaftMedium)]
    [InlineData("Raft-Large", ContentDiscoveryProfile.RaftLarge)]
    public void TryParse_Accepts_Known_Names_Case_And_Sep_Insensitive(
        string input, ContentDiscoveryProfile expected)
    {
        Assert.True(ContentDiscoveryProfiles.TryParse(input, out var p));
        Assert.Equal(expected, p);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("raft-huge")]
    [InlineData("nonsense")]
    public void TryParse_Rejects_Unknown_Names(string? input)
    {
        Assert.False(ContentDiscoveryProfiles.TryParse(input, out var p));
        Assert.Equal(ContentDiscoveryProfile.Default, p);
    }

    [Theory]
    [InlineData(ContentDiscoveryProfile.RaftSmall, "raft-small-directories.txt")]
    [InlineData(ContentDiscoveryProfile.RaftMedium, "raft-medium-directories.txt")]
    [InlineData(ContentDiscoveryProfile.RaftLarge, "raft-large-directories.txt")]
    public void WordlistFileName_Maps_Raft_Profiles(ContentDiscoveryProfile p, string expected)
    {
        Assert.Equal(expected, ContentDiscoveryProfiles.WordlistFileName(p));
    }

    [Fact]
    public void WordlistFileName_Default_Returns_Null()
    {
        Assert.Null(ContentDiscoveryProfiles.WordlistFileName(ContentDiscoveryProfile.Default));
    }

    [Fact]
    public void ResolveWordlistPath_Default_Returns_Null()
    {
        Assert.Null(ContentDiscoveryProfiles.ResolveWordlistPath(
            ContentDiscoveryProfile.Default));
    }

    [Fact]
    public void ResolveWordlistPath_Returns_First_Match_From_Provided_Roots()
    {
        var tempDir = Path.Combine(AppContext.BaseDirectory,
            $"drederick-cdp-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var hit = Path.Combine(tempDir, "raft-medium-directories.txt");
            File.WriteAllText(hit, "admin\nlogin\n");

            var resolved = ContentDiscoveryProfiles.ResolveWordlistPath(
                ContentDiscoveryProfile.RaftMedium,
                new[] { tempDir });

            Assert.Equal(hit, resolved);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void ResolveWordlistPath_Returns_Null_When_No_Root_Contains_File()
    {
        var emptyDir = Path.Combine(AppContext.BaseDirectory,
            $"drederick-cdp-empty-{Guid.NewGuid():N}");
        Directory.CreateDirectory(emptyDir);
        try
        {
            var resolved = ContentDiscoveryProfiles.ResolveWordlistPath(
                ContentDiscoveryProfile.RaftLarge,
                new[] { emptyDir });
            Assert.Null(resolved);
        }
        finally
        {
            try { Directory.Delete(emptyDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void ResolveWordlistPath_Skips_Missing_Roots_Without_Throwing()
    {
        var resolved = ContentDiscoveryProfiles.ResolveWordlistPath(
            ContentDiscoveryProfile.RaftSmall,
            new[]
            {
                "/this/path/definitely/does/not/exist/" + Guid.NewGuid().ToString("N"),
                "",
                "   ",
            });
        Assert.Null(resolved);
    }
}
