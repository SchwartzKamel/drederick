// Original NSE script: ssl-cert.nse
// Source: https://nmap.org/nsedoc/scripts/ssl-cert.html
// Author: David Fifield
// License: NPSL
//
// Native C# port: complete a TLS handshake on the given port and dump
// the peer certificate (subject, issuer, SANs, validity window, key
// algo + bits, sha-256 fingerprint). The certificate fetcher is
// abstracted as a delegate so unit tests can supply a known
// X509Certificate2 without hitting the network.
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed class SslCertTool : IReconTool
{
    public string Name => "ssl-cert";
    public string Description =>
        "Native port of nmap's ssl-cert.nse: complete a TLS handshake and dump " +
        "the peer certificate (subject/issuer/SANs/validity/key/fingerprint). " +
        "Target must be in scope.";

    public delegate Task<X509Certificate2?> CertificateFetcher(
        string target, int port, CancellationToken ct);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly CertificateFetcher _fetch;

    public SslCertTool(Scope.Scope scope, AuditLog audit, CertificateFetcher? fetcher = null)
    {
        _scope = scope;
        _audit = audit;
        _fetch = fetcher ?? DefaultFetchAsync;
    }

    public async Task<SslCertResult> ProbeAsync(string target, int port = 443, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("ssl-cert.start", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
        });

        var result = new SslCertResult { Port = port };
        try
        {
            var cert = await _fetch(target, port, ct).ConfigureAwait(false);
            if (cert is null)
            {
                result.Error = "no certificate returned";
            }
            else
            {
                Populate(result, cert);
                cert.Dispose();
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("ssl-cert.finish", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
            ["subject"] = result.Subject, ["error"] = result.Error,
        });
        return result;
    }

    public static void Populate(SslCertResult result, X509Certificate2 cert)
    {
        result.Subject = cert.Subject;
        result.Issuer = cert.Issuer;
        result.NotBefore = cert.NotBefore.ToUniversalTime().ToString("o");
        result.NotAfter = cert.NotAfter.ToUniversalTime().ToString("o");
        result.DaysUntilExpiry = (int)Math.Round((cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
        result.SerialNumber = cert.SerialNumber;
        result.SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName;
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            using var ecdsa = cert.GetECDsaPublicKey();
            if (rsa is not null)
            {
                result.PublicKeyAlgorithm = "RSA";
                result.PublicKeyBits = rsa.KeySize;
            }
            else if (ecdsa is not null)
            {
                result.PublicKeyAlgorithm = "ECDSA";
                result.PublicKeyBits = ecdsa.KeySize;
            }
        }
        catch { /* key extraction is best-effort */ }

        var bytes = cert.GetRawCertData();
        result.Sha256Fingerprint = Convert.ToHexStringLower(SHA256.HashData(bytes));

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17" && ext is X509SubjectAlternativeNameExtension san)
            {
                foreach (var n in san.EnumerateDnsNames())
                    if (!string.IsNullOrEmpty(n)) result.SubjectAltNames.Add(n);
                foreach (var ip in san.EnumerateIPAddresses())
                    result.SubjectAltNames.Add(ip.ToString());
            }
        }
    }

    private static async Task<X509Certificate2?> DefaultFetchAsync(string target, int port, CancellationToken ct)
    {
        using var tcp = new TcpClient();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(TimeSpan.FromSeconds(8));
        await tcp.ConnectAsync(target, port, linked.Token).ConfigureAwait(false);
        await using var net = tcp.GetStream();
        await using var ssl = new SslStream(net, leaveInnerStreamOpen: false,
            (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = target,
            EnabledSslProtocols = SslProtocols.None,
        }, linked.Token).ConfigureAwait(false);
        var remote = ssl.RemoteCertificate;
        return remote is null ? null : new X509Certificate2(remote);
    }
}
