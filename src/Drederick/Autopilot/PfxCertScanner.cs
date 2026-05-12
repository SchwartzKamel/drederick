using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Drederick.Audit;

namespace Drederick.Autopilot;

/// <summary>
/// GAP-014 — PFX / cert / key / keytab / ccache awareness scanner.
///
/// After the Autopilot lands loot, walks an operator-owned subdirectory of
/// the configured <c>--out</c> tree for known certificate-material file
/// extensions and extracts assumed-breach intelligence: subject / issuer /
/// SANs / Extended Key Usage from X.509, encryption state of PEM keys,
/// Kerberos principal / realm / TGT presence from ccache+keytab files,
/// and recovered PFX passwords from a curated wordlist.
///
/// This tool reads **local files only**. It does not touch the network
/// and does not need a scope check on a target — but it MUST refuse to
/// scan any path outside the operator-configured <c>out/</c> tree, so it
/// can never wander into the operator's home directory or sibling
/// repos. The containment check is the load-bearing invariant.
///
/// Plaintext discipline (load-bearing):
///   • Passwords NEVER appear in audit; only the SHA-256 of the attempted
///     password and a success flag.
///   • Recovered passwords land in <c>&lt;scanRoot&gt;/&lt;sha&gt;/password.txt</c>
///     with mode 0600 (operator-owned, never re-uploaded).
///   • Full key material never appears in audit; only a SHA-256
///     fingerprint of the DER body / raw file bytes.
/// </summary>
public sealed class PfxCertScanner
{
    private readonly AuditLog _audit;
    private readonly IReadOnlyList<string> _extraPasswords;
    private readonly string? _klistPath;

    /// <summary>EKU OIDs we surface by name (everything else stays as raw OID).</summary>
    private static readonly Dictionary<string, string> EkuOidNames = new(StringComparer.Ordinal)
    {
        ["1.3.6.1.5.5.7.3.1"] = "TLS Server Authentication",
        ["1.3.6.1.5.5.7.3.2"] = "TLS Client Authentication",
        ["1.3.6.1.5.5.7.3.3"] = "Code Signing",
        ["1.3.6.1.5.5.7.3.4"] = "Email Protection",
        ["1.3.6.1.5.5.7.3.8"] = "Time Stamping",
        ["1.3.6.1.5.5.7.3.9"] = "OCSP Signing",
        ["1.3.6.1.4.1.311.10.3.4"] = "Encrypting File System",
        ["1.3.6.1.4.1.311.20.2.2"] = "Smart Card Logon",
        ["1.3.6.1.4.1.311.20.2.1"] = "Domain Controller (Enrollment)",
        ["1.3.6.1.4.1.311.21.6"] = "Key Recovery Agent",
    };

    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    public PfxCertScanner(
        AuditLog audit,
        IEnumerable<string>? extraPasswords = null,
        string? klistPath = "/usr/bin/klist")
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _extraPasswords = (extraPasswords ?? Array.Empty<string>()).ToList();
        _klistPath = klistPath;
    }

    public async Task<PfxCertScanResult> ScanAsync(
        string scanRoot,
        string targetHost,
        string outDir,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(scanRoot)) throw new ArgumentException("scanRoot required", nameof(scanRoot));
        if (string.IsNullOrWhiteSpace(outDir)) throw new ArgumentException("outDir required", nameof(outDir));

        var fullScan = Path.GetFullPath(scanRoot);
        var fullOut = Path.GetFullPath(outDir);
        var sep = Path.DirectorySeparatorChar.ToString();
        var fullOutNorm = fullOut.EndsWith(sep, StringComparison.Ordinal) ? fullOut : fullOut + sep;
        var fullScanNorm = fullScan.EndsWith(sep, StringComparison.Ordinal) ? fullScan : fullScan + sep;
        if (!fullScanNorm.StartsWith(fullOutNorm, StringComparison.Ordinal)
            && !string.Equals(fullScan, fullOut, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"scanRoot '{scanRoot}' is not contained within outDir '{outDir}'", nameof(scanRoot));
        }

        var result = new PfxCertScanResult();
        if (!Directory.Exists(fullScan))
        {
            _audit.Record("pfx-cert-scan.start", new Dictionary<string, object?>
            {
                ["scan_root"] = fullScan,
                ["target"] = targetHost,
                ["exists"] = false,
            });
            _audit.Record("pfx-cert-scan.finish", new Dictionary<string, object?>
            {
                ["scan_root"] = fullScan,
                ["target"] = targetHost,
                ["found_count"] = 0,
            });
            return result;
        }

        _audit.Record("pfx-cert-scan.start", new Dictionary<string, object?>
        {
            ["scan_root"] = fullScan,
            ["target"] = targetHost,
            ["exists"] = true,
        });

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(fullScan, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            _audit.Record("pfx-cert-scan.finish", new Dictionary<string, object?>
            {
                ["scan_root"] = fullScan,
                ["target"] = targetHost,
                ["found_count"] = 0,
                ["error"] = ex.Message,
            });
            return result;
        }

        var passwords = BuildPasswordWordlist(targetHost);

        foreach (var path in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(path).ToLowerInvariant().TrimStart('.');
            CertificateMaterial? mat = null;
            try
            {
                mat = ext switch
                {
                    "pfx" or "p12" => InspectPfx(path, passwords, fullScan),
                    "crt" or "cer" => InspectCert(path),
                    "key" or "pem" => InspectPem(path),
                    "ccache" => await InspectCcacheAsync(path, ct).ConfigureAwait(false),
                    "keytab" => await InspectKeytabAsync(path, ct).ConfigureAwait(false),
                    _ => null,
                };
            }
            catch (Exception ex)
            {
                _audit.Record("pfx-cert-scan.error", new Dictionary<string, object?>
                {
                    ["path"] = path,
                    ["error"] = ex.Message,
                });
            }
            if (mat != null) result.Certificates.Add(mat);
        }

        _audit.Record("pfx-cert-scan.finish", new Dictionary<string, object?>
        {
            ["scan_root"] = fullScan,
            ["target"] = targetHost,
            ["found_count"] = result.Certificates.Count,
        });
        return result;
    }

    // ------------------------------------------------------------------
    // PFX / P12
    // ------------------------------------------------------------------
    private CertificateMaterial InspectPfx(string path, IReadOnlyList<string> passwords, string scanRoot)
    {
        var bytes = File.ReadAllBytes(path);
        var mat = new CertificateMaterial
        {
            Path = path,
            Kind = Path.GetExtension(path).ToLowerInvariant().TrimStart('.'),
            Fingerprint = Sha256Hex(bytes),
            Encrypted = true,
        };

        foreach (var pw in passwords)
        {
            X509Certificate2? cert = null;
            try
            {
                cert = X509CertificateLoader.LoadPkcs12(bytes, pw, X509KeyStorageFlags.EphemeralKeySet);
            }
            catch
            {
                cert = null;
            }
            var pwSha = Sha256Hex(Encoding.UTF8.GetBytes(pw));
            _audit.Record("pfx-cert-scan.pfx.attempt", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["password_sha256"] = pwSha,
                ["success"] = cert != null,
            });
            if (cert == null) continue;

            mat.Encrypted = pw.Length != 0;
            mat.PasswordRecoveredSha256 = pwSha;
            PopulateFromCert(mat, cert);
            PersistRecoveredPassword(scanRoot, pwSha, pw);
            cert.Dispose();
            return mat;
        }

        // Couldn't open — still emit metadata-less record with fingerprint.
        return mat;
    }

    // ------------------------------------------------------------------
    // .crt / .cer
    // ------------------------------------------------------------------
    private static CertificateMaterial InspectCert(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var mat = new CertificateMaterial
        {
            Path = path,
            Kind = Path.GetExtension(path).ToLowerInvariant().TrimStart('.'),
            Fingerprint = Sha256Hex(bytes),
        };
        try
        {
            X509Certificate2 cert;
            // Try PEM first, then DER.
            var text = TryReadUtf8(bytes);
            if (text != null && text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                cert = X509Certificate2.CreateFromPem(text);
            }
            else
            {
                cert = X509CertificateLoader.LoadCertificate(bytes);
            }
            using (cert)
            {
                PopulateFromCert(mat, cert);
                mat.Fingerprint = Sha256Hex(cert.RawData);
            }
        }
        catch
        {
            // Unparseable — keep fingerprint of raw bytes.
        }
        return mat;
    }

    // ------------------------------------------------------------------
    // .key / .pem
    // ------------------------------------------------------------------
    private static CertificateMaterial InspectPem(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var text = TryReadUtf8(bytes) ?? string.Empty;
        var kind = Path.GetExtension(path).ToLowerInvariant().TrimStart('.');
        var mat = new CertificateMaterial
        {
            Path = path,
            Kind = kind,
            Fingerprint = Sha256Hex(bytes),
            Encrypted =
                text.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal)
                || text.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal),
        };
        // If a certificate is embedded in the same PEM, extract metadata.
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            try
            {
                using var cert = X509Certificate2.CreateFromPem(text);
                PopulateFromCert(mat, cert);
            }
            catch { /* keep base metadata */ }
        }
        return mat;
    }

    // ------------------------------------------------------------------
    // ccache (MIT Kerberos credential cache)
    // ------------------------------------------------------------------
    private async Task<CertificateMaterial> InspectCcacheAsync(string path, CancellationToken ct)
    {
        var bytes = File.ReadAllBytes(path);
        var mat = new CertificateMaterial
        {
            Path = path,
            Kind = "ccache",
            Fingerprint = Sha256Hex(bytes),
        };
        // Parse natively for principal / realm / krbtgt heuristic.
        try
        {
            ParseCcache(bytes, mat);
        }
        catch
        {
            // best-effort
        }

        // Augment with klist output when available.
        if (!string.IsNullOrEmpty(_klistPath) && File.Exists(_klistPath))
        {
            var stdout = await RunAsync(_klistPath!, new[] { "-c", path }, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(stdout))
            {
                ApplyKlistOutput(stdout!, mat);
            }
        }
        return mat;
    }

    private static void ParseCcache(byte[] bytes, CertificateMaterial mat)
    {
        // FILE: ccache format v4: header bytes 0x05 0x04, then header length (BE u16),
        // header tags, then default principal (component count BE u32, realm len BE u32,
        // realm bytes, then for each component: u32 length + bytes).
        if (bytes.Length < 8 || bytes[0] != 0x05 || bytes[1] != 0x04) return;
        int idx = 2;
        ushort headerLen = ReadU16Be(bytes, idx); idx += 2 + headerLen;
        if (idx + 8 > bytes.Length) return;
        // Skip name-type (u32), read component count (u32).
        idx += 4;
        int compCount = (int)ReadU32Be(bytes, idx); idx += 4;
        if (compCount < 0 || compCount > 16) return;
        int realmLen = (int)ReadU32Be(bytes, idx); idx += 4;
        if (realmLen < 0 || idx + realmLen > bytes.Length) return;
        var realm = Encoding.UTF8.GetString(bytes, idx, realmLen); idx += realmLen;
        var comps = new List<string>(compCount);
        for (int i = 0; i < compCount; i++)
        {
            if (idx + 4 > bytes.Length) return;
            int cl = (int)ReadU32Be(bytes, idx); idx += 4;
            if (cl < 0 || idx + cl > bytes.Length) return;
            comps.Add(Encoding.UTF8.GetString(bytes, idx, cl));
            idx += cl;
        }
        mat.Principal = string.Join('/', comps) + "@" + realm;
        mat.Realm = realm;

        // Scan remaining bytes for the literal "krbtgt" service principal name
        // → strong signal that this ccache holds a TGT.
        if (IndexOfAscii(bytes, "krbtgt") >= 0)
        {
            mat.GoldenTicketIndicator = true;
        }
    }

    private static void ApplyKlistOutput(string stdout, CertificateMaterial mat)
    {
        foreach (var raw in stdout.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("Default principal:", StringComparison.Ordinal)
                || line.StartsWith("Principal:", StringComparison.Ordinal))
            {
                var idx = line.IndexOf(':');
                if (idx > 0 && idx + 1 < line.Length)
                {
                    var principal = line[(idx + 1)..].Trim();
                    if (string.IsNullOrEmpty(mat.Principal)) mat.Principal = principal;
                    var at = principal.LastIndexOf('@');
                    if (at >= 0 && string.IsNullOrEmpty(mat.Realm))
                    {
                        mat.Realm = principal[(at + 1)..];
                    }
                }
            }
            if (line.Contains("krbtgt/", StringComparison.OrdinalIgnoreCase))
            {
                mat.GoldenTicketIndicator = true;
            }
        }
    }

    // ------------------------------------------------------------------
    // keytab
    // ------------------------------------------------------------------
    private async Task<CertificateMaterial> InspectKeytabAsync(string path, CancellationToken ct)
    {
        var bytes = File.ReadAllBytes(path);
        var mat = new CertificateMaterial
        {
            Path = path,
            Kind = "keytab",
            Fingerprint = Sha256Hex(bytes),
        };
        try
        {
            ParseKeytab(bytes, mat);
        }
        catch { /* best-effort */ }

        if (!string.IsNullOrEmpty(_klistPath) && File.Exists(_klistPath))
        {
            var stdout = await RunAsync(_klistPath!, new[] { "-k", path }, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(stdout))
            {
                ApplyKlistOutput(stdout!, mat);
            }
        }
        return mat;
    }

    private static void ParseKeytab(byte[] bytes, CertificateMaterial mat)
    {
        // keytab v0x0502: byte 0 = 0x05, byte 1 = 0x02. Followed by entries.
        // Each entry: s32 size, u16 num_components, u16 realm_len, realm bytes,
        // then num_components × (u16 len + bytes), ... We only need the first
        // entry for principal/realm.
        if (bytes.Length < 4 || bytes[0] != 0x05) return;
        int idx = 2;
        if (idx + 4 > bytes.Length) return;
        idx += 4; // entry size
        if (idx + 2 > bytes.Length) return;
        int numComponents = ReadU16Be(bytes, idx); idx += 2;
        if (numComponents <= 0 || numComponents > 16) return;
        // keytab v0x0501 includes the realm in num_components count; v0x0502 does not.
        // Read realm separately:
        if (idx + 2 > bytes.Length) return;
        int realmLen = ReadU16Be(bytes, idx); idx += 2;
        if (realmLen < 0 || idx + realmLen > bytes.Length) return;
        var realm = Encoding.UTF8.GetString(bytes, idx, realmLen); idx += realmLen;
        var comps = new List<string>(numComponents);
        for (int i = 0; i < numComponents; i++)
        {
            if (idx + 2 > bytes.Length) return;
            int cl = ReadU16Be(bytes, idx); idx += 2;
            if (cl < 0 || idx + cl > bytes.Length) return;
            comps.Add(Encoding.UTF8.GetString(bytes, idx, cl));
            idx += cl;
        }
        mat.Principal = string.Join('/', comps) + "@" + realm;
        mat.Realm = realm;
    }

    // ------------------------------------------------------------------
    // shared helpers
    // ------------------------------------------------------------------
    private static void PopulateFromCert(CertificateMaterial mat, X509Certificate2 cert)
    {
        mat.Subject = cert.Subject;
        mat.Issuer = cert.Issuer;
        mat.NotBefore = cert.NotBefore.ToUniversalTime();
        mat.NotAfter = cert.NotAfter.ToUniversalTime();
        if (string.IsNullOrEmpty(mat.Fingerprint))
        {
            mat.Fingerprint = Sha256Hex(cert.RawData);
        }

        foreach (var ext in cert.Extensions)
        {
            switch (ext.Oid?.Value)
            {
                case "2.5.29.17": // Subject Alternative Name
                    if (ext is X509SubjectAlternativeNameExtension sanExt)
                    {
                        foreach (var dns in sanExt.EnumerateDnsNames()) mat.Sans.Add(dns);
                        foreach (var ip in sanExt.EnumerateIPAddresses()) mat.Sans.Add(ip.ToString());
                    }
                    else
                    {
                        foreach (var san in ParseSans(ext)) mat.Sans.Add(san);
                    }
                    break;
                case "2.5.29.37": // Extended Key Usage
                    if (ext is X509EnhancedKeyUsageExtension eku)
                    {
                        foreach (var oid in eku.EnhancedKeyUsages)
                        {
                            if (oid.Value is null) continue;
                            var name = EkuOidNames.TryGetValue(oid.Value, out var n)
                                ? n : (oid.FriendlyName ?? oid.Value);
                            mat.ExtendedKeyUsage.Add(name);
                            if (string.Equals(oid.Value, ClientAuthOid, StringComparison.Ordinal))
                            {
                                mat.ClientAuthCapable = true;
                            }
                        }
                    }
                    break;
            }
        }

        // PKINIT heuristic: ClientAuth + SAN that smells like a DC.
        if (mat.ClientAuthCapable)
        {
            foreach (var san in mat.Sans)
            {
                if (san.StartsWith("dc.", StringComparison.OrdinalIgnoreCase)
                    || san.Contains(".dc.", StringComparison.OrdinalIgnoreCase)
                    || san.StartsWith("dc-", StringComparison.OrdinalIgnoreCase)
                    || san.Equals("dc", StringComparison.OrdinalIgnoreCase))
                {
                    mat.PkinitCapable = true;
                    break;
                }
            }
        }
    }

    private static IEnumerable<string> ParseSans(System.Security.Cryptography.X509Certificates.X509Extension ext)
    {
        // X509SubjectAlternativeNameExtension is .NET 7+; fall back to Format() parsing.
        try
        {
            var fmt = ext.Format(true) ?? "";
            foreach (var raw in fmt.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var line = raw.Trim();
                // typical outputs: "DNS Name=dc.lab.local", "DNS-Name=foo",
                // "IP Address=10.0.0.1", "Other Name:..." etc.
                int eq = line.IndexOf('=');
                if (eq > 0 && eq + 1 < line.Length)
                {
                    var value = line[(eq + 1)..].Trim();
                    if (!string.IsNullOrEmpty(value)) yield return value;
                }
            }
        }
        finally { }
    }

    internal static IReadOnlyList<string> BuildPasswordWordlist(string targetHost)
    {
        var host = targetHost ?? string.Empty;
        var shortName = host.Split('.', 2)[0];
        var reversed = new string(shortName.Reverse().ToArray());
        var list = new List<string>
        {
            "",
            "password",
            "Password1",
            "Password123",
            "password1",
            "changeit",
            "mimikatz",
            "htb",
            "HTB",
            "letmein",
            "secret",
            "default",
            "admin",
            "admin123",
            "pkpass",
            "p@ssw0rd",
            "P@ssw0rd",
            "Welcome1",
            "123456",
            "qwerty",
            "root",
            "toor",
            "test",
            "test123",
            host,
            shortName,
            reversed,
            shortName + "2024",
            shortName + "2025",
            shortName + "123",
            shortName + "!",
        };
        return list.Distinct(StringComparer.Ordinal).ToList();
    }

    private void PersistRecoveredPassword(string scanRoot, string pwSha, string password)
    {
        try
        {
            var dir = Path.Combine(scanRoot, pwSha);
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "password.txt");
            File.WriteAllText(file, password);
            if (!OperatingSystem.IsWindows())
            {
                try { File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                catch { /* best-effort */ }
            }
            _audit.Record("pfx-cert-scan.password.persisted", new Dictionary<string, object?>
            {
                ["path"] = file,
                ["password_sha256"] = pwSha,
            });
        }
        catch (Exception ex)
        {
            _audit.Record("pfx-cert-scan.password.persist.error", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
            });
        }
    }

    private static async Task<string?> RunAsync(string exe, string[] args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p == null) return null;
            var stdout = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            return stdout;
        }
        catch
        {
            return null;
        }
    }

    internal static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static string? TryReadUtf8(byte[] bytes)
    {
        try
        {
            // Only treat as text if it parses cleanly and contains a PEM marker
            // or is mostly printable.
            return Encoding.UTF8.GetString(bytes);
        }
        catch { return null; }
    }

    private static ushort ReadU16Be(byte[] b, int off)
        => (ushort)((b[off] << 8) | b[off + 1]);

    private static uint ReadU32Be(byte[] b, int off)
        => ((uint)b[off] << 24) | ((uint)b[off + 1] << 16) | ((uint)b[off + 2] << 8) | b[off + 3];

    private static int IndexOfAscii(byte[] hay, string needle)
    {
        var n = Encoding.ASCII.GetBytes(needle);
        for (int i = 0; i <= hay.Length - n.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < n.Length; j++)
            {
                if (hay[i + j] != n[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}
