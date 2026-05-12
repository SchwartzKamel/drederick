using Drederick.Ops;
using Xunit;

namespace Drederick.Tests.Ops;

public class SocksProxyConfigTests
{
    [Theory]
    [InlineData("socks5://127.0.0.1:1080", SocksProxyScheme.Socks5, "127.0.0.1", 1080)]
    [InlineData("socks5h://10.10.14.1:9050", SocksProxyScheme.Socks5h, "10.10.14.1", 9050)]
    [InlineData("http://proxy.lab.local:3128", SocksProxyScheme.Http, "proxy.lab.local", 3128)]
    [InlineData("https://corp-egress.example.com:8443", SocksProxyScheme.Https, "corp-egress.example.com", 8443)]
    public void Parse_AcceptsSupportedSchemes(string raw, SocksProxyScheme scheme, string host, int port)
    {
        var cfg = SocksProxyConfig.Parse(raw);
        Assert.Equal(scheme, cfg.Scheme);
        Assert.Equal(host, cfg.Host);
        Assert.Equal(port, cfg.Port);
        Assert.Null(cfg.Username);
        Assert.Null(cfg.Password);
    }

    [Fact]
    public void Parse_ParsesInlineUserinfo()
    {
        var cfg = SocksProxyConfig.Parse("socks5h://op:s3cr3t@127.0.0.1:1080");
        Assert.Equal("op", cfg.Username);
        Assert.Equal("s3cr3t", cfg.Password);
    }

    [Fact]
    public void ToRedactedUri_OmitsCredentials()
    {
        var cfg = SocksProxyConfig.Parse("socks5h://op:s3cr3t@127.0.0.1:1080");
        Assert.Equal("socks5h://127.0.0.1:1080", cfg.ToRedactedUri());
    }

    [Theory]
    [InlineData("ftp://127.0.0.1:21")]
    [InlineData("gopher://127.0.0.1:70")]
    [InlineData("socks4://127.0.0.1:1080")]
    public void Parse_RejectsUnsupportedSchemes(string raw)
        => Assert.Throws<ArgumentException>(() => SocksProxyConfig.Parse(raw));

    [Theory]
    [InlineData("socks5://127.0.0.1")]
    [InlineData("socks5://:1080")]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_RejectsMalformed(string raw)
        => Assert.Throws<ArgumentException>(() => SocksProxyConfig.Parse(raw));

    [Theory]
    [InlineData("socks5://127.0.0.1:1080;rm -rf /:1080")]
    [InlineData("socks5://`whoami`:1080")]
    [InlineData("socks5://$(id):1080")]
    [InlineData("socks5://a b:1080")]
    public void Parse_RejectsShellMetacharacters(string raw)
        => Assert.Throws<ArgumentException>(() => SocksProxyConfig.Parse(raw));

    [Theory]
    [InlineData("socks5://0.0.0.0:1080")]
    [InlineData("socks5h://[::]:1080")]
    public void Parse_RejectsWildcardHost(string raw)
        => Assert.Throws<ArgumentException>(() => SocksProxyConfig.Parse(raw));

    [Fact]
    public void Parse_RejectsSchemeAsHost()
        => Assert.Throws<ArgumentException>(() => SocksProxyConfig.Parse("socks5://http:1080"));

    [Theory]
    [InlineData("socks5://127.0.0.1:1080", true)]
    [InlineData("socks5://localhost:1080", true)]
    [InlineData("socks5://[::1]:1080", true)]
    [InlineData("socks5://10.10.14.5:1080", false)]
    public void IsLoopback_DetectsLoopback(string raw, bool expected)
    {
        var cfg = SocksProxyConfig.Parse(raw);
        Assert.Equal(expected, cfg.IsLoopback);
    }

    [Fact]
    public void TryValidate_ReturnsNullForEmpty()
    {
        Assert.Null(SocksProxyConfig.TryValidate(null));
        Assert.Null(SocksProxyConfig.TryValidate(""));
        Assert.Null(SocksProxyConfig.TryValidate("   "));
    }
}
