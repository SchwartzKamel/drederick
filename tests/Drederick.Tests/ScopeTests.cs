using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class ScopeTests
{
    [Fact]
    public void SingleIPv4_Contains_Only_Itself()
    {
        var s = ScopeLoader.Parse("10.10.10.5");
        Assert.True(s.Contains("10.10.10.5"));
        Assert.False(s.Contains("10.10.10.6"));
        Assert.False(s.Contains("192.168.0.1"));
    }

    [Fact]
    public void Cidr24_Contains_All_In_Range()
    {
        var s = ScopeLoader.Parse("192.168.56.0/24");
        Assert.True(s.Contains("192.168.56.1"));
        Assert.True(s.Contains("192.168.56.254"));
        Assert.False(s.Contains("192.168.57.1"));
    }

    [Fact]
    public void Ipv6_Cidr_Contains_In_Range()
    {
        var s = ScopeLoader.Parse("fd00:dead:beef::/64");
        Assert.True(s.Contains("fd00:dead:beef::1"));
        Assert.True(s.Contains("fd00:dead:beef::ffff"));
        Assert.False(s.Contains("fd00:dead:beef:1::1"));
    }

    [Fact]
    public void Comments_And_Blank_Lines_Are_Ignored()
    {
        var text = """
                   # Authorized lab
                   10.10.10.5   # primary box
                   
                   # secondary
                   10.10.10.6
                   """;
        var s = ScopeLoader.Parse(text);
        Assert.True(s.Contains("10.10.10.5"));
        Assert.True(s.Contains("10.10.10.6"));
        Assert.False(s.Contains("10.10.10.7"));
    }

    [Fact]
    public void Empty_Scope_Is_Refused()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse(""));
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("# only comments\n\n"));
    }

    [Fact]
    public void Wildcard_Is_Refused()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("0.0.0.0/0"));
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("::/0"));
    }

    [Fact]
    public void Overbroad_V4_Is_Refused_Without_AllowBroad()
    {
        // /8 is over the strict cap of /16. Lab mode is the default everywhere
        // else, so test strict behavior explicitly.
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("10.0.0.0/8", labMode: false));
    }

    [Fact]
    public void Overbroad_V4_Is_Allowed_With_AllowBroad()
    {
        var s = ScopeLoader.Parse("10.0.0.0/8", allowBroad: true, labMode: false);
        Assert.True(s.Contains("10.1.2.3"));
    }

    [Fact]
    public void Overbroad_V6_Is_Refused_Without_AllowBroad()
    {
        // /16 is under the lab cap of /32 as well, so strict-vs-lab doesn't matter here.
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("fd00::/16"));
    }

    [Fact]
    public void Lab_Mode_Allows_V4_Slash_8_By_Default()
    {
        // Default LabMode=true lifts the v4 cap to /8.
        var s = ScopeLoader.Parse("10.0.0.0/8");
        Assert.True(s.Contains("10.1.2.3"));
    }

    [Fact]
    public void Lab_Mode_Still_Refuses_Wildcard_V4()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("0.0.0.0/0"));
    }

    [Fact]
    public void Lab_Mode_Still_Refuses_Wider_Than_Slash_8_V4()
    {
        // /4 is broader than the /8 lab cap and is not an explicit wildcard,
        // but must still be refused without --allow-broad.
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("10.0.0.0/4"));
    }

    [Fact]
    public void Lab_Mode_Allows_V6_Slash_32_By_Default()
    {
        var s = ScopeLoader.Parse("fd00::/32");
        Assert.True(s.Contains("fd00::1"));
    }

    [Fact]
    public void Strict_Mode_Refuses_Slash_8_That_Lab_Would_Allow()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("10.0.0.0/8", labMode: false));
    }

    [Fact]
    public void Invalid_Prefix_Is_Refused()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("10.0.0.0/zz"));
    }

    [Fact]
    public void Invalid_Address_Is_Refused()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("not-an-ip"));
    }

    [Fact]
    public void Expand_Small_Range_Yields_Host_Addresses()
    {
        var s = ScopeLoader.Parse("192.168.56.0/30");
        var hosts = s.Expand();
        // For /30 with skipEnds, that leaves .1 and .2
        Assert.Equal(new[] { "192.168.56.1", "192.168.56.2" }, hosts);
    }

    [Fact]
    public void Expand_Refuses_Large_Range()
    {
        // /16 is inside the allow-broad threshold boundary for prefix length,
        // but explicitly allow it here to test the expansion-size guard.
        var s = ScopeLoader.Parse("10.0.0.0/16", allowBroad: true);
        Assert.Throws<ScopeException>(() => s.Expand());
    }

    [Fact]
    public void Require_Throws_For_Out_Of_Scope()
    {
        var s = ScopeLoader.Parse("10.10.10.5");
        s.Require("10.10.10.5"); // ok
        Assert.Throws<ScopeException>(() => s.Require("10.10.10.6"));
    }

    [Fact]
    public void LoadFile_Missing_Is_Refused()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.LoadFile("/nonexistent/path.txt"));
    }

    // ---- deny-overlay (exclude:) tests ----

    [Fact]
    public void Scope_Empty_Exclude_Behaves_As_Before()
    {
        // YAML form with no exclude key — must behave identically to legacy.
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   """;
        var s = ScopeLoader.Parse(yaml);
        Assert.True(s.Contains("10.10.10.5"));
        Assert.True(s.Contains("10.10.255.1"));
        Assert.False(s.Contains("10.11.0.1"));
        s.Require("10.10.10.5");
        Assert.Throws<ScopeException>(() => s.Require("10.11.0.1"));
        Assert.Empty(s.Excludes);
    }

    [Fact]
    public void Scope_Excludes_Single_Ip_Even_If_Cidr_Includes_It()
    {
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 10.10.10.5
                   """;
        var s = ScopeLoader.Parse(yaml);
        Assert.True(s.Contains("10.10.10.4"));
        Assert.False(s.Contains("10.10.10.5"));
        Assert.Throws<ScopeException>(() => s.Require("10.10.10.5"));
        s.Require("10.10.10.4"); // sibling still ok
    }

    [Fact]
    public void Scope_Excludes_Cidr_Subset()
    {
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 10.10.10.0/28
                   """;
        var s = ScopeLoader.Parse(yaml);
        // /28 covers .0–.15
        Assert.False(s.Contains("10.10.10.0"));
        Assert.False(s.Contains("10.10.10.7"));
        Assert.False(s.Contains("10.10.10.15"));
        Assert.True(s.Contains("10.10.10.16"));
        Assert.True(s.Contains("10.10.20.5"));
        Assert.Throws<ScopeException>(() => s.Require("10.10.10.7"));
    }

    [Fact]
    public void Scope_Excludes_Hostname_After_Resolution()
    {
        // 'localhost' resolves to 127.0.0.1 (and ::1) on every supported
        // platform; use it as a hostname that can be tested without network.
        var yaml = """
                   include:
                     - 127.0.0.0/8
                   exclude:
                     - localhost
                   """;
        var s = ScopeLoader.Parse(yaml, allowBroad: true);
        Assert.False(s.Contains("127.0.0.1"));
        Assert.True(s.Contains("127.0.0.2"));
        var ex = Assert.Throws<ScopeException>(() => s.Require("127.0.0.1"));
        // Hostname origin label must surface in the deny message.
        Assert.Contains("localhost", ex.Message);
    }

    [Fact]
    public void ScopeLoader_Refuses_Wildcard_In_Exclude()
    {
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 0.0.0.0/0
                   """;
        var ex = Assert.Throws<ScopeException>(() => ScopeLoader.Parse(yaml));
        Assert.Contains("wildcard", ex.Message, StringComparison.OrdinalIgnoreCase);

        var yamlV6 = """
                     include:
                       - fd00::/32
                     exclude:
                       - ::/0
                     """;
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse(yamlV6));
    }

    [Fact]
    public void Scope_Exclude_Wins_Over_Include_Match()
    {
        // The "JobTwo-corp-CTF" case: whole /16 is in scope EXCEPT one box
        // which is the customer's prod. Even though both rules match, the
        // exclude takes precedence (deny wins).
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 10.10.10.5
                   """;
        var s = ScopeLoader.Parse(yaml);
        // Belt-and-braces: include rule does cover .5 ...
        Assert.Contains(s.Entries, e => e.Contains(System.Net.IPAddress.Parse("10.10.10.5")));
        // ... but Require still denies.
        Assert.Throws<ScopeException>(() => s.Require("10.10.10.5"));
    }

    [Fact]
    public void ScopeException_Message_Names_The_Exclude_Rule_That_Fired()
    {
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 10.10.10.5
                     - 10.10.20.0/28
                   """;
        var s = ScopeLoader.Parse(yaml);
        var ex1 = Assert.Throws<ScopeException>(() => s.Require("10.10.10.5"));
        Assert.Contains("10.10.10.5", ex1.Message);
        Assert.Contains("excluded by scope.exclude rule", ex1.Message);

        var ex2 = Assert.Throws<ScopeException>(() => s.Require("10.10.20.7"));
        Assert.Contains("10.10.20.0/28", ex2.Message);
        Assert.Contains("excluded by scope.exclude rule", ex2.Message);
    }

    [Fact]
    public void Yaml_Without_Include_Key_Is_Refused()
    {
        // YAML-shaped but no include list — default-deny posture preserved.
        var yaml = """
                   exclude:
                     - 10.10.10.5
                   """;
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse(yaml));
    }

    [Fact]
    public void Yaml_Mixed_Cidr_And_Single_Ip_In_Exclude()
    {
        var yaml = """
                   include:
                     - 10.10.0.0/16
                   exclude:
                     - 10.10.1.1
                     - 10.10.2.0/30
                   """;
        var s = ScopeLoader.Parse(yaml);
        Assert.Equal(2, s.Excludes.Count);
        Assert.False(s.Contains("10.10.1.1"));
        Assert.True(s.Contains("10.10.1.2"));
        Assert.False(s.Contains("10.10.2.1"));
        Assert.True(s.Contains("10.10.2.5"));
    }
}
