using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class IpRangeParserTests
{
    [Fact]
    public void Parse_BareIp_ReturnsSingleAddress()
    {
        var r = IpRangeParser.Parse("10.0.0.5");
        Assert.Equal(IpRangeParser.ParseStatus.Ok, r.Status);
        Assert.Single(r.Addresses);
        Assert.Equal("10.0.0.5", r.Addresses[0].ToString());
    }

    [Fact]
    public void Parse_LastOctetRange_Expands()
    {
        var r = IpRangeParser.Parse("10.0.0.1-3");
        Assert.Equal(IpRangeParser.ParseStatus.Ok, r.Status);
        Assert.Equal(3, r.Addresses.Count);
        Assert.Equal("10.0.0.1", r.Addresses[0].ToString());
        Assert.Equal("10.0.0.3", r.Addresses[2].ToString());
    }

    [Fact]
    public void Parse_LastOctetRange_50_ExpandsCorrectCount()
    {
        var r = IpRangeParser.Parse("10.0.0.1-50");
        Assert.Equal(IpRangeParser.ParseStatus.Ok, r.Status);
        Assert.Equal(50, r.Addresses.Count);
    }

    [Fact]
    public void Parse_BackwardsRange_Refused()
    {
        var r = IpRangeParser.Parse("10.0.0.50-10");
        Assert.Equal(IpRangeParser.ParseStatus.Backwards, r.Status);
        Assert.Empty(r.Addresses);
    }

    [Fact]
    public void Parse_Cidr_ReturnsNotARange()
    {
        var r = IpRangeParser.Parse("10.0.0.0/24");
        Assert.Equal(IpRangeParser.ParseStatus.NotARange, r.Status);
    }

    [Fact]
    public void Parse_FullIpDashForm_Deferred()
    {
        var r = IpRangeParser.Parse("10.0.0.1-10.0.0.50");
        Assert.Equal(IpRangeParser.ParseStatus.Invalid, r.Status);
    }

    [Fact]
    public void Parse_Junk_ReturnsInvalid()
    {
        var r = IpRangeParser.Parse("not-an-ip-at-all");
        Assert.Equal(IpRangeParser.ParseStatus.Invalid, r.Status);
    }

    [Fact]
    public void Parse_Empty_ReturnsInvalid()
    {
        var r = IpRangeParser.Parse("");
        Assert.Equal(IpRangeParser.ParseStatus.Invalid, r.Status);
    }
}
