using System.ComponentModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// SSL cert → /etc/hosts proposal tool (GAP-006). Opens a TCP+TLS
/// connection to <c>target:port</c>, captures the server's X.509
/// certificate (validation callback always returns true — invalid certs
/// are the point of the scan), extracts CN + Subject Alternative Names,
/// resolves each DNS-shaped name through the operator resolver, and
/// emits a structured <see cref="EtcHostsProposal"/> for any hostname
/// that does not already resolve to <c>target</c>.
///
/// Drederick NEVER writes to <c>/etc/hosts</c>. Host-file mutation is
/// the operator's prerogative; this tool only proposes additions and
/// records them on the briefing-delta audit channel.
/// </summary>
public sealed partial class SslCertHostsTool : IReconTool
{
    public string Name => "ssl-cert-hosts";

    public string Description =>
        "TLS handshake → X.509 cert: extract CN + Subject Alternative Names, " +
        "resolve each DNS-shaped name, and emit a proposed /etc/hosts entry " +
        "for any hostname that doesn't already resolve to the target IP. " +
        "Read-only; never mutates /etc/hosts.";

    private const int MaxConnectTimeoutMs = 5_000;
    private const int MaxHandshakeTimeoutMs = 8_000;

    [GeneratedRegex(@"^[\w.\-:]+$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetShapeRegex();

    [GeneratedRegex(@"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z][A-Za-z0-9-]{0,62}$",
        RegexOptions.CultureInvariant)]
    private static partial Regex DnsHostnameRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;
    private readonly Func<string, CancellationToken, Task<string[]>> _resolver;

    public SslCertHostsTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, int, CancellationToken, Task<Stream>>? connectFactory = null,
        Func<string, CancellationToken, Task<string[]>>? resolver = null)
    {
        _scope = scope;
        _audit = audit;
        _connect = connectFactory ?? DefaultConnectAsync;
        _resolver = resolver ?? DefaultResolveAsync;
    }

    private static async Task<Stream> DefaultConnectAsync(string host, int port, CancellationToken ct)
    {
        var client = new TcpClient();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(MaxConnectTimeoutMs);
        await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
        return client.GetStream();
    }

    private static async Task<string[]> DefaultResolveAsync(string host, CancellationToken ct)
    {
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return addrs.Select(a => a.ToString()).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    [Description("Pull X.509 cert from target:port, extract CN+SAN, propose /etc/hosts entries for unresolved hostnames.")]
    public async Task<SslCertHostsResult> EnumerateAsync(
        string target,
        int port = 443,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        if (string.IsNullOrEmpty(target)
            || Scope.ArgvValidator.ContainsShellMetachars(target)
            || !TargetShapeRegex().IsMatch(target))
        {
            throw new ArgumentException(
                $"Invalid ssl-cert-hosts target '{target}': expected host or host:port.", nameof(target));
        }
        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "port must be in [1, 65535].");

        // Strip any inline :port so we connect using the caller's port arg.
        var bareHost = target.Contains(':') ? target[..target.IndexOf(':')] : target;

        _audit.Record("ssl-cert-hosts.start", new Dictionary<string, object?>
        {
            ["target"] = bareHost,
            ["port"] = port,
        });

        var result = new SslCertHostsResult { Port = port };
        Stream? raw = null;
        SslStream? ssl = null;

        try
        {
            try
            {
                raw = await _connect(bareHost, port, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.Error = $"connect: {ex.Message}";
                RecordFinish(bareHost, port, result);
                return result;
            }

            ssl = new SslStream(raw, leaveInnerStreamOpen: false, (_, _, _, _) => true);
            using (var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                hsCts.CancelAfter(MaxHandshakeTimeoutMs);
                try
                {
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = bareHost,
                    }, hsCts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    result.Error = $"handshake: {ex.Message}";
                    RecordFinish(bareHost, port, result);
                    return result;
                }
            }

            var rawCert = ssl.RemoteCertificate;
            if (rawCert is null)
            {
                result.Error = "server did not present a certificate";
                RecordFinish(bareHost, port, result);
                return result;
            }

            using var cert = new X509Certificate2(rawCert);
            PopulateCertFields(cert, result);

            // Build the list of hostnames to consider for /etc/hosts proposals:
            // every DNS SAN, plus the CN if it's DNS-shaped. IP SANs are
            // captured into result.Sans but never proposed (IPs aren't valid
            // /etc/hosts hostnames).
            var candidates = new List<(string Name, string Source)>();
            foreach (var entry in result.Sans)
            {
                if (entry.StartsWith("DNS:", StringComparison.Ordinal))
                {
                    var name = entry[4..];
                    if (DnsHostnameRegex().IsMatch(name))
                        candidates.Add((name, "ssl-cert-san"));
                }
            }
            if (!string.IsNullOrEmpty(result.CommonName)
                && DnsHostnameRegex().IsMatch(result.CommonName)
                && !candidates.Any(c => c.Name.Equals(result.CommonName, StringComparison.OrdinalIgnoreCase)))
            {
                candidates.Add((result.CommonName, "ssl-cert-cn"));
            }

            foreach (var (name, source) in candidates)
            {
                string[] ips;
                try { ips = await _resolver(name, ct).ConfigureAwait(false); }
                catch { ips = Array.Empty<string>(); }

                if (ips.Contains(bareHost, StringComparer.OrdinalIgnoreCase))
                    continue; // already resolves to target — no proposal needed.

                var proposal = new EtcHostsProposal
                {
                    Hostname = name,
                    TargetIp = bareHost,
                    Source = source,
                    CurrentResolution = ips.Length > 0 ? ips[0] : null,
                };
                result.HostsProposals.Add(proposal);

                _audit.Record("briefing.delta.proposed", new Dictionary<string, object?>
                {
                    ["section"] = "etc_hosts",
                    ["hostname"] = name,
                    ["target_ip"] = bareHost,
                    ["source"] = source,
                    ["current_resolution"] = proposal.CurrentResolution,
                });
            }
        }
        catch (Exception ex)
        {
            result.Error ??= ex.Message;
        }
        finally
        {
            if (ssl is not null)
            {
                try { await ssl.DisposeAsync().ConfigureAwait(false); } catch { }
            }
            else if (raw is not null)
            {
                try { await raw.DisposeAsync().ConfigureAwait(false); } catch { }
            }
        }

        RecordFinish(bareHost, port, result);
        return result;
    }

    private static void PopulateCertFields(X509Certificate2 cert, SslCertHostsResult result)
    {
        result.CommonName = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        result.Issuer = cert.Issuer;
        result.NotBefore = cert.NotBefore.ToUniversalTime();
        result.NotAfter = cert.NotAfter.ToUniversalTime();
        result.Serial = cert.SerialNumber;
        result.SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value;
        result.SelfSigned = string.Equals(
            cert.SubjectName.Name, cert.IssuerName.Name, StringComparison.Ordinal);

        // SAN extension: enumerate DNS, IP, URI entries. .NET 7+ provides
        // X509SubjectAlternativeNameExtension with strongly-typed
        // enumerators for DNS and IP; URIs we extract from the formatted
        // string fallback because there is no enumerator.
        var sanExt = cert.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();
        if (sanExt is not null)
        {
            foreach (var dns in sanExt.EnumerateDnsNames())
            {
                result.Sans.Add($"DNS:{dns}");
            }
            foreach (var ip in sanExt.EnumerateIPAddresses())
            {
                result.Sans.Add($"IP:{ip}");
            }
            // URI: fall back to formatted string parsing — the extension
            // doesn't expose a typed enumerator.
            var formatted = sanExt.Format(multiLine: true);
            foreach (var line in formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("URI=", StringComparison.OrdinalIgnoreCase)
                    || trimmed.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                {
                    result.Sans.Add("URI:" + trimmed[4..]);
                }
            }
        }
    }

    private void RecordFinish(string target, int port, SslCertHostsResult result)
    {
        _audit.Record("ssl-cert-hosts.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["cn_sha256"] = result.CommonName is null
                ? null
                : Sha256Hex(result.CommonName),
            ["sans_count"] = result.Sans.Count,
            ["proposals_count"] = result.HostsProposals.Count,
            ["self_signed"] = result.SelfSigned,
            ["error"] = result.Error,
        });
    }

    private static string Sha256Hex(string s)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(s);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
