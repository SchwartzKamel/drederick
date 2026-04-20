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
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("10.0.0.0/8"));
    }

    [Fact]
    public void Overbroad_V4_Is_Allowed_With_AllowBroad()
    {
        var s = ScopeLoader.Parse("10.0.0.0/8", allowBroad: true);
        Assert.True(s.Contains("10.1.2.3"));
    }

    [Fact]
    public void Overbroad_V6_Is_Refused_Without_AllowBroad()
    {
        Assert.Throws<ScopeException>(() => ScopeLoader.Parse("fd00::/16"));
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
}
