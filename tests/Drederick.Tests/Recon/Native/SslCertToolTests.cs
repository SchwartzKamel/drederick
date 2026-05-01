using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Drederick.Recon;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class SslCertToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new SslCertTool(NativeTestHelpers.SmallScope(), audit,
            (_, _, _) => Task.FromResult<X509Certificate2?>(null));
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8"));
    }

    [Fact]
    public async Task Populates_Subject_And_Fingerprint_From_SelfSigned_Cert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lab.example.com", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("lab.example.com");
        req.CertificateExtensions.Add(sanBuilder.Build());
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);
        using var cert = req.CreateSelfSigned(notBefore, notAfter);

        using var audit = NativeTestHelpers.NewAudit();
        var tool = new SslCertTool(NativeTestHelpers.SmallScope(), audit,
            (_, _, _) => Task.FromResult<X509Certificate2?>(new X509Certificate2(cert.RawData)));
        var r = await tool.ProbeAsync("10.10.10.5", 443);

        Assert.Equal(443, r.Port);
        Assert.Contains("lab.example.com", r.Subject);
        Assert.Equal("RSA", r.PublicKeyAlgorithm);
        Assert.Equal(2048, r.PublicKeyBits);
        Assert.Contains("lab.example.com", r.SubjectAltNames);
        Assert.NotNull(r.Sha256Fingerprint);
        Assert.Equal(64, r.Sha256Fingerprint!.Length);
        Assert.True(r.DaysUntilExpiry > 0);
    }

    [Fact]
    public void Populate_From_Cert_Sets_Issuer_And_Validity()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=issuer-test", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(10));
        var result = new SslCertResult { Port = 8443 };
        SslCertTool.Populate(result, cert);
        Assert.Contains("issuer-test", result.Issuer);
        Assert.NotNull(result.NotBefore);
        Assert.NotNull(result.NotAfter);
    }
}
