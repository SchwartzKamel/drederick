using System.IO;
using System.Linq;
using Drederick.Audit;
using Drederick.Ops;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Ops;

public class SocksProxyIntegrationTests
{
    private static (Scope.Scope scope, AuditLog audit, string path) NewScope(string scopeText)
    {
        var p = Path.Combine(Path.GetTempPath(), $"socks-int-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(p);
        var scope = ScopeLoader.Parse(scopeText, "<memory>", allowBroad: false, labMode: true);
        return (scope, audit, p);
    }

    [Fact]
    public void NmapBuildArgs_WithSocksConfig_EmitsConnectScanAndProxiesArg()
    {
        var (scope, audit, p) = NewScope("10.10.10.5/32\n");
        try
        {
            var resolver = new SocksProxyResolver(scope, audit);
            var cfg = resolver.Resolve("socks5h://127.0.0.1:1080", labMode: true, allowExternalProxy: false);
            Assert.NotNull(cfg);

            var nmap = new NmapTool(scope, audit, labMode: true, socksConfig: cfg, socksResolver: resolver);
            var argv = nmap.BuildArgs("10.10.10.5", portSpec: null);

            Assert.Contains("-sT", argv);
            var pi = argv.IndexOf("--proxies");
            Assert.True(pi >= 0, "missing --proxies in argv");
            Assert.StartsWith("socks5://", argv[pi + 1]); // socks5h maps down to socks5 for nmap
            Assert.Contains("127.0.0.1:1080", argv[pi + 1]);
        }
        finally { audit.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void Resolver_RefusesWhenProxyHostInScope()
    {
        var (scope, audit, p) = NewScope("10.10.10.5/32\n");
        try
        {
            var resolver = new SocksProxyResolver(scope, audit);
            Assert.Throws<InvalidOperationException>(() =>
                resolver.Resolve("socks5://10.10.10.5:1080", labMode: true, allowExternalProxy: true));
        }
        finally { audit.Dispose(); File.Delete(p); }
    }

    [Fact]
    public void Resolver_StrictNonLoopback_RequiresAllowExternalProxy()
    {
        var (scope, audit, p) = NewScope("10.10.10.5/32\n");
        try
        {
            var resolver = new SocksProxyResolver(scope, audit);
            Assert.Throws<ArgumentException>(() =>
                resolver.Resolve("socks5://10.10.14.5:1080", labMode: false, allowExternalProxy: false));
            var cfg = resolver.Resolve("socks5://10.10.14.5:1080", labMode: false, allowExternalProxy: true);
            Assert.NotNull(cfg);
        }
        finally { audit.Dispose(); File.Delete(p); }
    }
}
