using System.Net;
using Drederick.Ops;
using Xunit;

namespace Drederick.Tests;

public class HtbRangesTests
{
    [Theory]
    [InlineData("10.10.10.5")]
    [InlineData("10.10.10.1")]
    [InlineData("10.10.11.254")]
    [InlineData("10.10.14.7")]
    [InlineData("10.10.15.200")] // /23 covers .14 and .15
    [InlineData("10.129.42.1")]
    [InlineData("10.129.0.1")]
    public void IsHtbTarget_KnownCidrs(string ip)
    {
        Assert.True(HtbRanges.IsHtbTarget(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.10.12.1")]   // between .11 and .14 — not covered
    [InlineData("10.10.16.1")]
    [InlineData("10.128.255.255")]
    [InlineData("8.8.8.8")]
    [InlineData("127.0.0.1")]
    public void IsHtbTarget_OutsideCidrs(string ip)
    {
        Assert.False(HtbRanges.IsHtbTarget(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("driver.htb")]
    [InlineData("FOO.BAR.HTB")]
    [InlineData("a.b.c.htb")]
    [InlineData("x.htb.")]
    public void IsHtbHostname_True(string host)
    {
        Assert.True(HtbRanges.IsHtbHostname(host));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("htb")]          // no dot
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("10.10.10.5")]   // IP literal
    [InlineData("htbcorp.com")]
    public void IsHtbHostname_False(string host)
    {
        Assert.False(HtbRanges.IsHtbHostname(host));
    }

    [Fact]
    public void LookupHostsFile_FindsMatch()
    {
        var tmp = Path.Combine(AppContext.BaseDirectory, "hosts-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(tmp,
            "# comment\n" +
            "127.0.0.1   localhost\n" +
            "10.10.11.42  driver.htb  driver\n" +
            "not-an-ip    foo\n");
        try
        {
            var ip = HtbRanges.TryResolve("driver.htb", tmp);
            Assert.NotNull(ip);
            Assert.Equal("10.10.11.42", ip!.ToString());

            var alias = HtbRanges.TryResolve("driver", tmp);
            Assert.NotNull(alias);
            Assert.Equal("10.10.11.42", alias!.ToString());
        }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public void TryResolve_IpLiteralReturnedAsIs()
    {
        var ip = HtbRanges.TryResolve("10.10.10.5");
        Assert.NotNull(ip);
        Assert.Equal("10.10.10.5", ip!.ToString());
    }

    [Fact]
    public void TryResolve_HtbHostname_UsesHostsFile()
    {
        var tmp = Path.Combine(AppContext.BaseDirectory, "hosts-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(tmp, "10.10.11.99 active.htb\n");
        try
        {
            var ip = HtbRanges.TryResolve("active.htb", tmp);
            Assert.NotNull(ip);
            Assert.Equal("10.10.11.99", ip!.ToString());
        }
        finally { File.Delete(tmp); }
    }
}
