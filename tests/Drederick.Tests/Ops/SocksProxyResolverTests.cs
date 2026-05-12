using System.IO;
using System.Linq;
using System.Net;
using Drederick.Audit;
using Drederick.Ops;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Ops;

public class SocksProxyResolverTests
{
    private static (SocksProxyResolver resolver, AuditLog audit, string path) NewResolver(string scopeText = "127.0.0.1/32\n")
    {
        var auditPath = Path.Combine(Path.GetTempPath(), $"socks-resolver-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(auditPath);
        var scope = ScopeLoader.Parse(scopeText, "<memory>", allowBroad: false, labMode: true);
        return (new SocksProxyResolver(scope, audit), audit, auditPath);
    }

    [Fact]
    public void Resolve_NullInput_ReturnsNull()
    {
        var (r, a, p) = NewResolver();
        try
        {
            Assert.Null(r.Resolve(null, labMode: true, allowExternalProxy: false));
            Assert.Null(r.Resolve("   ", labMode: true, allowExternalProxy: false));
        }
        finally { a.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void Resolve_StrictModeNonLoopback_RequiresAllowExternalProxy()
    {
        var (r, a, p) = NewResolver();
        try
        {
            Assert.Throws<ArgumentException>(() =>
                r.Resolve("socks5://10.10.14.5:1080", labMode: false, allowExternalProxy: false));
            // OK with opt-in
            var cfg = r.Resolve("socks5://10.10.14.5:1080", labMode: false, allowExternalProxy: true);
            Assert.NotNull(cfg);
        }
        finally { a.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void Resolve_RefusesProxyHostInScope()
    {
        var (r, a, p) = NewResolver("10.10.10.5/32\n");
        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                r.Resolve("socks5://10.10.10.5:1080", labMode: true, allowExternalProxy: true));
            Assert.Contains("scope", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally { a.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void Resolve_LogsRedactedPasswordSha256_NotPlaintext()
    {
        var (r, a, p) = NewResolver("10.10.10.5/32\n");
        try
        {
            var cfg = r.Resolve("socks5h://op:hunter2@127.0.0.1:1080", labMode: true, allowExternalProxy: false);
            Assert.NotNull(cfg);
            a.Dispose();
            var contents = File.ReadAllText(p);
            Assert.DoesNotContain("hunter2", contents);
            Assert.Contains("password_sha256", contents);
            Assert.Contains("proxy.config.loaded", contents);
        }
        finally { File.Delete(p); }
    }

    [Theory]
    [InlineData(SocksProxyScheme.Socks5, "socks5")]
    [InlineData(SocksProxyScheme.Socks5h, "socks5")] // proxy-side DNS not representable in nmap argv
    [InlineData(SocksProxyScheme.Http, "http")]
    [InlineData(SocksProxyScheme.Https, "http")] // nmap --proxies has no https chain
    public void BuildNmapProxiesArg_MapsScheme(SocksProxyScheme scheme, string expectedPrefix)
    {
        var cfg = new SocksProxyConfig(scheme, "127.0.0.1", 1080, null, null);
        Assert.StartsWith(expectedPrefix + "://", SocksProxyResolver.BuildNmapProxiesArg(cfg));
    }

    [Fact]
    public void BuildProcessEnv_EmitsBothCases()
    {
        var cfg = SocksProxyConfig.Parse("socks5h://127.0.0.1:1080");
        var env = SocksProxyResolver.BuildProcessEnv(cfg);
        Assert.Equal(6, env.Count);
        foreach (var k in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" })
        {
            Assert.True(env.ContainsKey(k), $"missing {k}");
        }
    }

    [Fact]
    public void BuildHttpClientHandler_AssignsProxyAndCredentials()
    {
        var (r, a, p) = NewResolver();
        try
        {
            var cfg = SocksProxyConfig.Parse("socks5h://op:s3cr3t@127.0.0.1:1080");
            using var handler = r.BuildHttpClientHandler(cfg);
            Assert.True(handler.UseProxy);
            Assert.NotNull(handler.Proxy);
            var webProxy = Assert.IsType<WebProxy>(handler.Proxy);
            var cred = webProxy.Credentials as NetworkCredential;
            Assert.NotNull(cred);
            Assert.Equal("op", cred!.UserName);
            Assert.Equal("s3cr3t", cred.Password);
        }
        finally { a.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void ApplyToCurrentProcessEnv_SetsAndAudits()
    {
        var (r, a, p) = NewResolver();
        try
        {
            var prev = Environment.GetEnvironmentVariable("ALL_PROXY");
            var cfg = SocksProxyConfig.Parse("socks5h://127.0.0.1:11080");
            r.ApplyToCurrentProcessEnv(cfg);
            Assert.Equal("socks5h://127.0.0.1:11080", Environment.GetEnvironmentVariable("ALL_PROXY"));
            a.Dispose();
            var contents = File.ReadAllText(p);
            Assert.Contains("proxy.env.applied", contents);
            // restore
            Environment.SetEnvironmentVariable("ALL_PROXY", prev);
            Environment.SetEnvironmentVariable("HTTP_PROXY", null);
            Environment.SetEnvironmentVariable("HTTPS_PROXY", null);
            Environment.SetEnvironmentVariable("all_proxy", null);
            Environment.SetEnvironmentVariable("http_proxy", null);
            Environment.SetEnvironmentVariable("https_proxy", null);
        }
        finally { File.Delete(p); }
    }
}
