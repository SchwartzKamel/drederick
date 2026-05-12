using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Drederick.Audit;
using Drederick.Autopilot;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class PfxCertScannerTests : IDisposable
{
    private readonly string _root;
    private readonly string _outDir;
    private readonly string _scanRoot;
    private readonly string _auditPath;
    private readonly AuditLog _audit;

    public PfxCertScannerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"pfx-scan-{Guid.NewGuid():N}");
        _outDir = Path.Combine(_root, "out");
        _scanRoot = Path.Combine(_outDir, "10.10.10.5", "loot");
        Directory.CreateDirectory(_scanRoot);
        _auditPath = Path.Combine(_root, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string ReadAudit()
    {
        _audit.Dispose();
        return File.ReadAllText(_auditPath);
    }

    // ------------------------------------------------------------------
    // Test fixture helpers — generate PFX / PEM material on the fly.
    // ------------------------------------------------------------------
    private static byte[] BuildPfx(
        string subject,
        string password,
        IEnumerable<string>? dnsSans = null,
        bool clientAuthEku = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (dnsSans != null)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in dnsSans) sanBuilder.AddDnsName(san);
            req.CertificateExtensions.Add(sanBuilder.Build());
        }
        if (clientAuthEku)
        {
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, critical: false));
        }
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return cert.Export(X509ContentType.Pfx, password);
    }

    private static string MakePemEncryptedKey()
    {
        // RFC 5958 encrypted PrivateKeyInfo (PEM "ENCRYPTED PRIVATE KEY").
        using var rsa = RSA.Create(2048);
        var bytes = rsa.ExportEncryptedPkcs8PrivateKey(
            "test-passphrase".AsSpan(),
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        var b64 = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{b64}\n-----END ENCRYPTED PRIVATE KEY-----\n";
    }

    private static string MakePemUnencryptedKey()
    {
        using var rsa = RSA.Create(2048);
        var bytes = rsa.ExportPkcs8PrivateKey();
        var b64 = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n";
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------
    [Fact]
    public async Task LoadsPfx_With_EmptyPassword()
    {
        var path = Path.Combine(_scanRoot, "empty.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=empty", ""));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.Equal("pfx", mat.Kind);
        Assert.False(mat.Encrypted);
        Assert.NotNull(mat.PasswordRecoveredSha256);
        Assert.Equal("CN=empty", mat.Subject);
    }

    [Fact]
    public async Task BrutesPfx_With_HtbPassword()
    {
        var path = Path.Combine(_scanRoot, "secret.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=brute", "htb"));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.True(mat.Encrypted);
        var expected = PfxCertScanner.Sha256Hex(Encoding.UTF8.GetBytes("htb"));
        Assert.Equal(expected, mat.PasswordRecoveredSha256);
    }

    [Fact]
    public async Task Detects_ClientAuth_Eku()
    {
        var path = Path.Combine(_scanRoot, "client.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=client", "", clientAuthEku: true));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.True(mat.ClientAuthCapable);
        Assert.Contains(mat.ExtendedKeyUsage, e => e.Contains("Client", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Detects_PkinitCapable_DcCert()
    {
        var path = Path.Combine(_scanRoot, "dc.pfx");
        File.WriteAllBytes(path, BuildPfx(
            "CN=dc", "", dnsSans: new[] { "dc.lab.local" }, clientAuthEku: true));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.True(mat.ClientAuthCapable);
        Assert.True(mat.PkinitCapable);
        Assert.Contains("dc.lab.local", mat.Sans);
    }

    [Fact]
    public async Task Detects_Encrypted_PemKey()
    {
        var path = Path.Combine(_scanRoot, "enc.key");
        File.WriteAllText(path, MakePemEncryptedKey());

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.Equal("key", mat.Kind);
        Assert.True(mat.Encrypted);
    }

    [Fact]
    public async Task Detects_Unencrypted_PemKey()
    {
        var path = Path.Combine(_scanRoot, "plain.pem");
        File.WriteAllText(path, MakePemUnencryptedKey());

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.Equal("pem", mat.Kind);
        Assert.False(mat.Encrypted);
        Assert.False(string.IsNullOrEmpty(mat.Fingerprint));
    }

    [Fact]
    public async Task Refuses_ScanRoot_Outside_OutDir()
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), $"elsewhere-{Guid.NewGuid():N}");
        Directory.CreateDirectory(elsewhere);
        try
        {
            var scanner = new PfxCertScanner(_audit);
            await Assert.ThrowsAsync<ArgumentException>(
                async () => await scanner.ScanAsync(elsewhere, "host", _outDir));
        }
        finally
        {
            Directory.Delete(elsewhere, recursive: true);
        }
    }

    [Fact]
    public async Task Audit_NeverLogs_PlaintextPasswords()
    {
        // canary password — must NOT appear in audit log
        const string canary = "htb";
        var path = Path.Combine(_scanRoot, "canary.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=canary", canary));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);
        Assert.Single(res.Certificates);

        var auditText = ReadAudit();
        // The recovered password (htb) is also in the curated wordlist by name,
        // but should NEVER appear as a standalone token in the audit. We assert
        // by checking that no audit field stores it verbatim — its sha256 must
        // be present, the plaintext must not appear quoted.
        var pwSha = PfxCertScanner.Sha256Hex(Encoding.UTF8.GetBytes(canary));
        Assert.Contains(pwSha, auditText);
        Assert.DoesNotContain("\"password\":\"" + canary + "\"", auditText);
        Assert.DoesNotContain("\"plaintext\":\"" + canary + "\"", auditText);
    }

    [Fact]
    public async Task Persists_RecoveredPasswordFile_With_Mode_0600()
    {
        const string pw = "htb";
        var path = Path.Combine(_scanRoot, "p.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=p", pw));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);
        var mat = Assert.Single(res.Certificates);

        var pwFile = Path.Combine(_scanRoot, mat.PasswordRecoveredSha256!, "password.txt");
        Assert.True(File.Exists(pwFile));
        Assert.Equal(pw, File.ReadAllText(pwFile));

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(pwFile);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
    }

    [Fact]
    public async Task EmptyDirectory_ReturnsEmptyResult()
    {
        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);
        Assert.Empty(res.Certificates);
        Assert.Null(res.Error);
    }

    [Fact]
    public async Task Detects_TargetHost_PasswordFromWordlist()
    {
        // password = the short hostname → must be picked up by wordlist seeding.
        var path = Path.Combine(_scanRoot, "hostpw.pfx");
        File.WriteAllBytes(path, BuildPfx("CN=hp", "lab"));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "lab.local", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.NotNull(mat.PasswordRecoveredSha256);
    }

    [Fact]
    public async Task Crt_FileFingerprint_Extracted()
    {
        // emit DER cert as .crt
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=metaonly", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var path = Path.Combine(_scanRoot, "cert.crt");
        File.WriteAllBytes(path, cert.Export(X509ContentType.Cert));

        var scanner = new PfxCertScanner(_audit);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);

        var mat = Assert.Single(res.Certificates);
        Assert.Equal("crt", mat.Kind);
        Assert.Equal("CN=metaonly", mat.Subject);
        Assert.False(string.IsNullOrEmpty(mat.Fingerprint));
    }

    [Fact]
    public async Task Ccache_Native_Parses_PrincipalAndGoldenTicket()
    {
        // Hand-built minimal MIT ccache v4 with a krbtgt service ref to trigger
        // golden_ticket_indicator. Layout:
        //   0x05 0x04                  -- format magic
        //   header_len u16 = 0
        //   default_principal:
        //     name-type u32  = 1
        //     num_components u32 = 1
        //     realm_len u32, realm
        //     comp_len u32, comp
        //   then literal "krbtgt" later in the body to trip the heuristic.
        using var ms = new MemoryStream();
        void W16(ushort v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v); }
        void W32(uint v)
        {
            ms.WriteByte((byte)(v >> 24));
            ms.WriteByte((byte)(v >> 16));
            ms.WriteByte((byte)(v >> 8));
            ms.WriteByte((byte)v);
        }
        ms.WriteByte(0x05); ms.WriteByte(0x04);
        W16(0); // header_len
        W32(1); // name-type
        W32(1); // num_components
        var realm = Encoding.UTF8.GetBytes("LAB.LOCAL");
        W32((uint)realm.Length); ms.Write(realm);
        var comp = Encoding.UTF8.GetBytes("administrator");
        W32((uint)comp.Length); ms.Write(comp);
        // Body — include krbtgt principal text.
        var trailer = Encoding.UTF8.GetBytes("krbtgt/LAB.LOCAL@LAB.LOCAL");
        ms.Write(trailer);

        var path = Path.Combine(_scanRoot, "tgt.ccache");
        File.WriteAllBytes(path, ms.ToArray());

        var scanner = new PfxCertScanner(_audit, klistPath: null);
        var res = await scanner.ScanAsync(_scanRoot, "host", _outDir);
        var mat = Assert.Single(res.Certificates);
        Assert.Equal("ccache", mat.Kind);
        Assert.Equal("LAB.LOCAL", mat.Realm);
        Assert.Equal("administrator@LAB.LOCAL", mat.Principal);
        Assert.True(mat.GoldenTicketIndicator);
    }
}
