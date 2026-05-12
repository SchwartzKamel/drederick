using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Tests for <see cref="SslCertHostsTool"/> (GAP-006). Spins up an
/// in-process TCP listener that performs a TLS handshake using a
/// self-signed cert generated at fixture time via
/// <see cref="CertificateRequest.CreateSelfSigned"/>. No on-disk
/// certs, no openssl shellout.
/// </summary>
public class SslCertHostsToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-sslcerthosts-{Guid.NewGuid():N}.jsonl"));

    private static X509Certificate2 BuildSelfSignedCert(
        string subjectCn,
        IEnumerable<string>? dnsSans = null,
        IEnumerable<IPAddress>? ipSans = null,
        string? issuerCn = null)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={subjectCn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (dnsSans is not null || ipSans is not null)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            if (dnsSans is not null) foreach (var d in dnsSans) sanBuilder.AddDnsName(d);
            if (ipSans is not null) foreach (var i in ipSans) sanBuilder.AddIpAddress(i);
            req.CertificateExtensions.Add(sanBuilder.Build());
        }

        X509Certificate2 cert;
        if (issuerCn is null || issuerCn == subjectCn)
        {
            cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(30));
        }
        else
        {
            // CA-signed: build an issuer cert and sign the leaf.
            using var caRsa = RSA.Create(2048);
            var caReq = new CertificateRequest($"CN={issuerCn}", caRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var caCert = caReq.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(60));
            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);
            using var leaf = req.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
            cert = leaf.CopyWithPrivateKey(rsa);
        }

        // SslStream server auth requires an X509Certificate2 with private
        // key persisted in a way the SChannel-equivalent provider accepts.
        // Round-trip through PFX achieves that on every platform.
        var pfx = cert.Export(X509ContentType.Pfx, "");
        cert.Dispose();
        return X509CertificateLoader.LoadPkcs12(pfx, "", X509KeyStorageFlags.Exportable);
    }

    private sealed class FakeTlsServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _cert;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _serverTask;

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public FakeTlsServer(X509Certificate2 cert)
        {
            _cert = cert;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _serverTask = Task.Run(RunAsync);
        }

        private async Task RunAsync()
        {
            try
            {
                using var client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                using var stream = client.GetStream();
                using var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                try
                {
                    await ssl.AuthenticateAsServerAsync(_cert, clientCertificateRequired: false,
                        enabledSslProtocols: System.Security.Authentication.SslProtocols.None,
                        checkCertificateRevocation: false).ConfigureAwait(false);
                }
                catch { /* let the client surface the handshake error */ }
            }
            catch { /* listener stopped */ }
        }

        public async ValueTask DisposeAsync()
        {
            try { _cts.Cancel(); } catch { }
            try { _listener.Stop(); } catch { }
            try { await _serverTask.ConfigureAwait(false); } catch { }
            _cert.Dispose();
        }
    }

    private static Func<string, int, CancellationToken, Task<Stream>> LoopbackConnectFactory()
        => async (_, port, ct) =>
        {
            var c = new TcpClient();
            await c.ConnectAsync(IPAddress.Loopback, port, ct).ConfigureAwait(false);
            return c.GetStream();
        };

    private static Func<string, CancellationToken, Task<string[]>> Resolver(
        Func<string, string[]> map) =>
        (host, _) => Task.FromResult(map(host) ?? Array.Empty<string>());

    [Fact]
    public async Task ExtractsCnAndSans()
    {
        using var cert = BuildSelfSignedCert("lab.htb",
            dnsSans: new[] { "admin.lab.htb", "api.lab.htb" });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(_ => Array.Empty<string>()));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.Null(r.Error);
        Assert.Equal("lab.htb", r.CommonName);
        Assert.Contains("DNS:admin.lab.htb", r.Sans);
        Assert.Contains("DNS:api.lab.htb", r.Sans);
    }

    [Fact]
    public async Task DetectsSelfSigned()
    {
        using var cert = BuildSelfSignedCert("lab.htb", dnsSans: new[] { "lab.htb" });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(_ => new[] { "127.0.0.1" }));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.True(r.SelfSigned);
        Assert.Equal("CN=lab.htb", r.Issuer);
    }

    [Fact]
    public async Task EmitsHostsProposals_ForUnresolvedSans()
    {
        using var cert = BuildSelfSignedCert("lab.htb",
            dnsSans: new[] { "admin.lab.htb", "api.lab.htb" });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        // Resolver: every name → NXDOMAIN (empty array).
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(_ => Array.Empty<string>()));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.Null(r.Error);
        // Both DNS SANs + the CN (lab.htb) should be proposed (CN is DNS-shaped).
        Assert.Equal(3, r.HostsProposals.Count);
        Assert.Contains(r.HostsProposals, p => p.Hostname == "admin.lab.htb" && p.Source == "ssl-cert-san");
        Assert.Contains(r.HostsProposals, p => p.Hostname == "api.lab.htb" && p.Source == "ssl-cert-san");
        Assert.Contains(r.HostsProposals, p => p.Hostname == "lab.htb" && p.Source == "ssl-cert-cn");
        Assert.All(r.HostsProposals, p => Assert.Null(p.CurrentResolution));
        Assert.All(r.HostsProposals, p => Assert.Equal("127.0.0.1", p.TargetIp));
    }

    [Fact]
    public async Task OmitsHostsProposal_WhenSanAlreadyResolvesToTarget()
    {
        using var cert = BuildSelfSignedCert("lab.htb",
            dnsSans: new[] { "admin.lab.htb", "stale.lab.htb" });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(name => name switch
            {
                "admin.lab.htb" => new[] { "127.0.0.1" }, // already resolves to target.
                "lab.htb" => new[] { "127.0.0.1" },
                _ => Array.Empty<string>(),
            }));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.DoesNotContain(r.HostsProposals, p => p.Hostname == "admin.lab.htb");
        Assert.DoesNotContain(r.HostsProposals, p => p.Hostname == "lab.htb");
        Assert.Contains(r.HostsProposals, p => p.Hostname == "stale.lab.htb");
    }

    [Fact]
    public async Task ExtractsValidityDates()
    {
        using var cert = BuildSelfSignedCert("lab.htb", dnsSans: new[] { "lab.htb" });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(_ => new[] { "127.0.0.1" }));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.NotNull(r.NotBefore);
        Assert.NotNull(r.NotAfter);
        Assert.True(r.NotBefore < r.NotAfter);
        Assert.NotNull(r.Serial);
        Assert.False(string.IsNullOrEmpty(r.SignatureAlgorithm));
    }

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.EnumerateAsync("10.10.10.5", 443));
    }

    [Fact]
    public async Task ArgvInjection_Rejected()
    {
        // Whether ScopeLoader refuses the shell-metachar entry up front
        // or the tool's argv shape check refuses it after scope passes,
        // an "evil;rm" target must never reach the network stack.
        using var audit = NewAudit();
        Drederick.Scope.Scope scope;
        try
        {
            scope = ScopeLoader.Parse("evil;rm");
        }
        catch
        {
            // Loader-side refusal is also a correct outcome — test
            // passes implicitly: the tool can never be invoked with
            // such a scope, so the argv could never reach it.
            return;
        }

        var tool = new SslCertHostsTool(scope, audit);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            tool.EnumerateAsync("evil;rm", 443));
    }

    [Fact]
    public async Task HandlesConnectionRefused_GracefulError()
    {
        // Bind+stop to grab a port we know is closed.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int closedPort = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit);

        var r = await tool.EnumerateAsync("127.0.0.1", closedPort);

        Assert.NotNull(r.Error);
        Assert.Null(r.CommonName);
        Assert.Empty(r.HostsProposals);
    }

    [Fact]
    public async Task ParsesIpSans()
    {
        using var cert = BuildSelfSignedCert("lab.htb",
            dnsSans: new[] { "lab.htb" },
            ipSans: new[] { IPAddress.Parse("10.10.10.5") });
        await using var server = new FakeTlsServer(cert);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SslCertHostsTool(scope, audit,
            LoopbackConnectFactory(),
            Resolver(_ => new[] { "127.0.0.1" }));

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port);

        Assert.Contains("IP:10.10.10.5", r.Sans);
        // IP SANs must NOT produce /etc/hosts proposals.
        Assert.DoesNotContain(r.HostsProposals, p => p.Hostname == "10.10.10.5");
    }
}
