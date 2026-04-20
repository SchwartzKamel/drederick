using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// TLS fingerprinting probe. Completes a TLS handshake and reports the peer
/// certificate's subject, SAN list, issuer, validity window, and negotiated
/// protocol version. Does not attempt client authentication.
/// </summary>
public sealed class TlsProbeTool : IReconTool
{
    public string Name => "tls";

    public string Description =>
        "Complete a TLS handshake and return the peer certificate subject, SAN, issuer, and expiry.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public TlsProbeTool(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public async Task<TlsResult> ProbeAsync(string target, int port, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("tls.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
        });

        var result = new TlsResult { Port = port };
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(target, port, ct).ConfigureAwait(false);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }, ct).ConfigureAwait(false);

            result.TlsVersion = ssl.SslProtocol.ToString();
            if (ssl.RemoteCertificate is X509Certificate raw)
            {
                using var cert = new X509Certificate2(raw);
                result.Subject = cert.Subject;
                result.Issuer = cert.Issuer;
                result.NotBefore = cert.NotBefore.ToUniversalTime().ToString("o");
                result.NotAfter = cert.NotAfter.ToUniversalTime().ToString("o");
                result.DaysUntilExpiry = (int)Math.Floor((cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);

                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17") // SubjectAltName
                    {
                        var formatted = ext.Format(multiLine: true);
                        foreach (var line in formatted.Split('\n'))
                        {
                            var trimmed = line.Trim();
                            if (trimmed.Length == 0) continue;
                            result.SubjectAltNames.Add(trimmed);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _audit.Record("tls.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["error"] = ex.Message,
            });
            result.Error = ex.Message;
        }
        _audit.Record("tls.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["tls_version"] = result.TlsVersion,
            ["error"] = result.Error,
        });
        return result;
    }
}
