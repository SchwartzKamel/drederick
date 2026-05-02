using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// GAP-032: native http_probe must accept hostname targets (resolved IP
/// must pass scope), set Host:/SNI from the hostname, and auto-detect
/// vhost-required redirects.
/// </summary>
public class HttpProbeToolTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-http-probe-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static AuditLog NewAudit() => NewAudit(out _);

    private static Func<string, CancellationToken, Task<IPAddress[]>> StaticResolver(
        params (string host, IPAddress[] addrs)[] map)
    {
        var dict = map.ToDictionary(x => x.host, x => x.addrs, StringComparer.OrdinalIgnoreCase);
        return (host, _) =>
        {
            if (dict.TryGetValue(host, out var addrs)) return Task.FromResult(addrs);
            throw new System.Net.Sockets.SocketException(11001); // host not found
        };
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpResponseMessage Response { get; set; } = new(HttpStatusCode.OK);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(Response);
        }
    }

    // 1. IP target → backward-compatible: scope check, no hostname.
    [Fact]
    public async Task ResolveAsync_IpTarget_InScope_Returns_Ip_NoHostname()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var tool = new HttpProbeTool(scope, audit);

        var resolved = await tool.ResolveAsync("10.0.0.5", CancellationToken.None);

        Assert.Equal(IPAddress.Parse("10.0.0.5"), resolved.ResolvedIp);
        Assert.Null(resolved.Hostname);
    }

    // 2. IP target out-of-scope → ScopeException (regression).
    [Fact]
    public async Task ResolveAsync_IpTarget_OutOfScope_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var tool = new HttpProbeTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.ResolveAsync("8.8.8.8", CancellationToken.None));
    }

    // 3. Hostname target with single A in scope → resolves to that IP,
    //    hostname carried for Host:/SNI.
    [Fact]
    public async Task ResolveAsync_Hostname_SingleAInScope_Resolves()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var resolver = StaticResolver(("facts.htb", new[] { IPAddress.Parse("10.0.0.7") }));
        var tool = new HttpProbeTool(scope, audit, resolver, null);

        var resolved = await tool.ResolveAsync("facts.htb", CancellationToken.None);

        Assert.Equal(IPAddress.Parse("10.0.0.7"), resolved.ResolvedIp);
        Assert.Equal("facts.htb", resolved.Hostname);
    }

    // 4. Hostname resolves to multiple IPs, mixed in/out of scope →
    //    first in-scope IP wins.
    [Fact]
    public async Task ResolveAsync_Hostname_MultiA_PicksFirstInScope()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var resolver = StaticResolver(("multi.htb", new[]
        {
            IPAddress.Parse("8.8.8.8"),    // out-of-scope, must be skipped
            IPAddress.Parse("10.0.0.42"),  // in-scope, wins
            IPAddress.Parse("10.0.0.99"),  // also in-scope, but second
        }));
        var tool = new HttpProbeTool(scope, audit, resolver, null);

        var resolved = await tool.ResolveAsync("multi.htb", CancellationToken.None);

        Assert.Equal(IPAddress.Parse("10.0.0.42"), resolved.ResolvedIp);
        Assert.Equal(3, resolved.AllResolved.Count);
    }

    // 5. Hostname resolves only to out-of-scope IPs → ScopeException
    //    with the resolved IPs in the message.
    [Fact]
    public async Task ResolveAsync_Hostname_NoneInScope_Throws_WithResolvedList()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var resolver = StaticResolver(("evil.htb", new[]
        {
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("1.1.1.1"),
        }));
        var tool = new HttpProbeTool(scope, audit, resolver, null);

        var ex = await Assert.ThrowsAsync<ScopeException>(
            () => tool.ResolveAsync("evil.htb", CancellationToken.None));
        Assert.Contains("evil.htb", ex.Message);
        Assert.Contains("8.8.8.8", ex.Message);
        Assert.Contains("1.1.1.1", ex.Message);
        Assert.Contains("none in scope", ex.Message);
    }

    // 6. Hostname fails to resolve → ScopeException (no silent IP-only
    //    fallback that would skip the vhost path).
    [Fact]
    public async Task ResolveAsync_Hostname_DnsFailure_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        // Resolver that always fails.
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, _) => throw new System.Net.Sockets.SocketException(11001);
        var tool = new HttpProbeTool(scope, audit, resolver, null);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.ResolveAsync("does-not-exist.invalid", CancellationToken.None));
    }

    // 7. ProbeAsync end-to-end: hostname target → URI uses hostname
    //    (so Host: + SNI match), captured request shows the hostname
    //    authority, scope-validated against the resolved IP.
    [Fact]
    public async Task ProbeAsync_Hostname_BuildsRequest_WithHostnameAuthority()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var resolver = StaticResolver(("facts.htb", new[] { IPAddress.Parse("10.0.0.7") }));
        var capturing = new CapturingHandler { Response = new HttpResponseMessage(HttpStatusCode.OK) };
        var tool = new HttpProbeTool(scope, audit, resolver, _ => capturing);

        var result = await tool.ProbeAsync("facts.htb", 80, useTls: false);

        Assert.NotNull(capturing.LastRequest);
        Assert.Equal("facts.htb", capturing.LastRequest!.RequestUri!.Host);
        Assert.Equal(80, capturing.LastRequest.RequestUri.Port);
        // Host header is implied by the URI authority — verify it (or
        // the runtime-supplied default) carries the hostname.
        var hostHeader = capturing.LastRequest.Headers.Host
            ?? capturing.LastRequest.RequestUri.Authority;
        Assert.Contains("facts.htb", hostHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("facts.htb", result.Hostname);
        Assert.Equal("10.0.0.7", result.ResolvedIp);
    }

    // 8. ProbeAsync IP target backward-compat: URI uses the IP, no
    //    hostname annotation, no DNS resolution required.
    [Fact]
    public async Task ProbeAsync_IpTarget_BackwardCompatible()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var capturing = new CapturingHandler { Response = new HttpResponseMessage(HttpStatusCode.OK) };
        // DNS resolver that throws so we prove the IP path doesn't touch DNS.
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, _) => throw new InvalidOperationException("dns must not be called for an IP target");
        var tool = new HttpProbeTool(scope, audit, resolver, _ => capturing);

        var result = await tool.ProbeAsync("10.0.0.5", 80, useTls: false);

        Assert.Null(result.Hostname);
        Assert.Equal("10.0.0.5", result.ResolvedIp);
        Assert.Equal("10.0.0.5", capturing.LastRequest!.RequestUri!.Host);
        Assert.False(result.VhostRequired);
    }

    // 9. Vhost auto-detect: 302 → Location with hostname different from
    //    the IP we probed → VhostRequired=true, VhostHostname set,
    //    audit event "http.vhost.detected" emitted.
    [Fact]
    public async Task ProbeAsync_302_To_Hostname_FlagsVhostRequired_AndAudits()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var auditPath);
        var redirect = new HttpResponseMessage(HttpStatusCode.Found);
        redirect.Headers.Location = new Uri("http://facts.htb/login");
        var capturing = new CapturingHandler { Response = redirect };
        var tool = new HttpProbeTool(scope, audit, null, _ => capturing);

        var result = await tool.ProbeAsync("10.0.0.7", 80, useTls: false);

        Assert.True(result.VhostRequired);
        Assert.Equal("facts.htb", result.VhostHostname);
        Assert.Equal("http://facts.htb/login", result.FinalUrl);

        audit.Dispose();
        var jsonl = File.ReadAllText(auditPath);
        Assert.Contains("http.vhost.detected", jsonl);
        Assert.Contains("facts.htb", jsonl);
    }

    // 10. Vhost detection must NOT fire for in-app redirects to the same
    //     IP/hostname (e.g. `/` → `/index.php`) and must NOT fire when
    //     Location targets another IP (cross-IP, different concern).
    [Theory]
    [InlineData("http://10.0.0.7/index.php")]
    [InlineData("http://10.0.0.7:80/login")]
    [InlineData("/relative/redirect")]
    [InlineData("http://192.0.2.99/cross-ip-redirect")]
    public async Task ProbeAsync_Redirects_NotFlagging_Vhost(string location)
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var redirect = new HttpResponseMessage(HttpStatusCode.Found);
        if (Uri.TryCreate(location, UriKind.RelativeOrAbsolute, out var loc))
            redirect.Headers.Location = loc;
        var capturing = new CapturingHandler { Response = redirect };
        var tool = new HttpProbeTool(scope, audit, null, _ => capturing);

        var result = await tool.ProbeAsync("10.0.0.7", 80, useTls: false);

        Assert.False(result.VhostRequired);
        Assert.Null(result.VhostHostname);
    }

    // 11. Hostname target whose 302 points back to itself → not a vhost
    //     redirect (no flag). The hostname-vs-IP check covers both sides.
    [Fact]
    public async Task ProbeAsync_HostnameTarget_RedirectToSameHostname_NoVhostFlag()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var resolver = StaticResolver(("facts.htb", new[] { IPAddress.Parse("10.0.0.7") }));
        var redirect = new HttpResponseMessage(HttpStatusCode.Found);
        redirect.Headers.Location = new Uri("http://facts.htb/login");
        var capturing = new CapturingHandler { Response = redirect };
        var tool = new HttpProbeTool(scope, audit, resolver, _ => capturing);

        var result = await tool.ProbeAsync("facts.htb", 80, useTls: false);

        Assert.False(result.VhostRequired);
    }

    // 12. Audit trail records resolved IP + all-resolved set on start.
    [Fact]
    public async Task ProbeAsync_Audit_StartEvent_HasResolvedIpAndAllResolved()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var auditPath);
        var resolver = StaticResolver(("multi.htb", new[]
        {
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("10.0.0.7"),
        }));
        var capturing = new CapturingHandler { Response = new HttpResponseMessage(HttpStatusCode.OK) };
        var tool = new HttpProbeTool(scope, audit, resolver, _ => capturing);

        await tool.ProbeAsync("multi.htb", 80, useTls: false);

        audit.Dispose();
        var jsonl = File.ReadAllText(auditPath);
        Assert.Contains("\"resolved_ip\":\"10.0.0.7\"", jsonl);
        Assert.Contains("8.8.8.8", jsonl);
    }
}
