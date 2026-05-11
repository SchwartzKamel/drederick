using System;
using System.IO;
using System.Linq;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Scanning;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// GAP-049 (htb-pivot-blind, Part 1): proxy-context plumbing. Validates
/// <see cref="ProxyContext.Parse"/> rules, that <see cref="NmapTool.BuildArgs"/>
/// inserts <c>-sT --proxies socks4://...</c> when a proxy is set, and that
/// <see cref="SynScanner.ScanAsync"/> refuses cleanly under <c>--proxy</c>
/// (raw sockets cannot be tunnelled).
/// </summary>
public class ProxyAwareScannerTests
{
    private static Drederick.Scope.Scope MakeScope(params string[] cidrs)
    {
        var f = Path.Combine(Path.GetTempPath(), $"scope-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(f, cidrs);
        return ScopeLoader.LoadFile(f, allowBroad: false, labMode: true);
    }

    private static AuditLog MakeAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void ProxyContext_Parse_AcceptsLoopbackSocks5()
    {
        var p = ProxyContext.Parse("socks5://127.0.0.1:1080", labMode: false, allowExternal: false);
        Assert.Equal(ProxyType.Socks5, p.Type);
        Assert.Equal("127.0.0.1", p.Host);
        Assert.Equal(1080, p.Port);
        Assert.True(p.IsLoopback);
    }

    [Fact]
    public void ProxyContext_Parse_RefusesWildcardHost()
    {
        Assert.Throws<ArgumentException>(() =>
            ProxyContext.Parse("socks5://0.0.0.0:1080", labMode: true, allowExternal: true));
    }

    [Fact]
    public void ProxyContext_Parse_RequiresExternalFlag_InStrictMode()
    {
        Assert.Throws<ArgumentException>(() =>
            ProxyContext.Parse("socks5://10.10.14.5:1080", labMode: false, allowExternal: false));
        // Lab mode: external proxy permitted.
        var p = ProxyContext.Parse("socks5://10.10.14.5:1080", labMode: true, allowExternal: false);
        Assert.False(p.IsLoopback);
    }

    [Fact]
    public void ProxyContext_ToNmapProxiesArg_TranslatesSocks5ToSocks4()
    {
        var p = ProxyContext.Parse("socks5://127.0.0.1:1080", labMode: true, allowExternal: false);
        Assert.Equal("socks4://127.0.0.1:1080", p.ToNmapProxiesArg());
    }

    [Fact]
    public void NmapTool_BuildArgs_WithProxy_EmitsScanTypeForcedAndProxiesArg()
    {
        var scope = MakeScope("10.129.31.77/32");
        using var audit = MakeAudit(out var path);
        var proxy = ProxyContext.Parse("socks5://127.0.0.1:1080", labMode: true, allowExternal: false);
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: true, permissions: null, proxy: proxy);

        var argv = nmap.BuildArgs("10.129.31.77", portSpec: "80,443");

        Assert.Contains("-sT", argv);
        Assert.Contains("--proxies", argv);
        var proxiesIdx = argv.IndexOf("--proxies");
        Assert.Equal("socks4://127.0.0.1:1080", argv[proxiesIdx + 1]);
        audit.Dispose();
        var lines = File.ReadAllLines(path);
        Assert.Contains(lines, l => l.Contains("nmap.proxy.unsupported_scan_type"));
        File.Delete(path);
    }

    [Fact]
    public void NmapTool_BuildArgs_WithoutProxy_DoesNotEmitProxyArgs()
    {
        var scope = MakeScope("10.129.31.77/32");
        using var audit = MakeAudit(out var path);
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: true);
        var argv = nmap.BuildArgs("10.129.31.77", portSpec: null);
        Assert.DoesNotContain("--proxies", argv);
        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async System.Threading.Tasks.Task SynScanner_WithProxy_ReturnsEmpty_AndAudits()
    {
        var scope = MakeScope("10.129.31.77/32");
        using var audit = MakeAudit(out var path);
        var proxy = ProxyContext.Parse("socks5://127.0.0.1:1080", labMode: true, allowExternal: false);
        var syn = new SynScanner(scope, audit, proxy);
        Assert.True(syn.ProxyForcesFallback);
        var open = await syn.ScanAsync("10.129.31.77", new[] { 80, 443 });
        Assert.Empty(open);
        audit.Dispose();
        var lines = File.ReadAllLines(path);
        Assert.Contains(lines, l => l.Contains("scanner.syn.proxy.fallback"));
        File.Delete(path);
    }

    [Fact]
    public async System.Threading.Tasks.Task NativeScannerTool_WithProxy_RefusesOutOfScope()
    {
        var scope = MakeScope("10.129.31.77/32");
        using var audit = MakeAudit(out var path);
        var proxy = ProxyContext.Parse("socks5://127.0.0.1:1080", labMode: true, allowExternal: false);
        var native = new NativeScannerTool(scope, audit, proxy);
        await Assert.ThrowsAsync<ScopeException>(async () =>
            await native.ScanAsync("8.8.8.8", ports: new[] { 80 }, concurrency: 4, timeoutMs: 200));
        audit.Dispose();
        File.Delete(path);
    }
}
