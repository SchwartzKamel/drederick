using System.Net;
using Drederick.Audit;
using Drederick.Scope;
using DnsClient;
using DnsClient.Protocol;

namespace Drederick.Recon;

/// <summary>
/// Native DNS recon tool: resolves A/AAAA/CNAME/MX/NS/TXT/PTR/SOA records and
/// attempts AXFR zone transfers — no external <c>dig</c> or other subprocess
/// dependency. Uses DnsClient.NET directly.
///
/// Scope semantics: <paramref name="target"/> MUST be an IP address inside the
/// authorized scope (consistent with all other recon tools). The tool queries
/// the system resolver for PTR and, on any discovered hostname, for
/// A/AAAA/MX/NS/TXT/SOA. An AXFR is attempted against <paramref name="target"/>
/// itself when <paramref name="queryType"/> is "ALL" or "AXFR" — the scope
/// check on the nameserver IP covers this second network hop.
/// </summary>
public sealed class NativeDnsTool : IReconTool
{
    public string Name => "dns-native";

    public string Description =>
        "Native DNS recon: resolves A/AAAA/MX/NS/TXT/SOA records and attempts AXFR zone " +
        "transfers without external dig dependency. Target must be an in-scope IP address.";

    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan AxfrTimeout = TimeSpan.FromSeconds(10);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly INativeDnsResolver _resolver;
    private readonly IAxfrProvider _axfrProvider;

    public NativeDnsTool(
        Scope.Scope scope,
        AuditLog audit,
        INativeDnsResolver? resolver = null,
        IAxfrProvider? axfrProvider = null)
    {
        _scope = scope;
        _audit = audit;
        _resolver = resolver ?? new LookupClientResolver();
        _axfrProvider = axfrProvider ?? new DnsClientAxfrProvider();
    }

    /// <summary>
    /// Run DNS recon against <paramref name="target"/> (an in-scope IP).
    /// </summary>
    /// <param name="target">Target IP address — must be inside the authorized scope.</param>
    /// <param name="queryType">
    /// Record type to query: "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
    /// "PTR", or "ALL" (default). "ALL" runs PTR + A/AAAA/MX/NS/TXT/SOA on any
    /// discovered hostname and attempts an AXFR against the target IP.
    /// </param>
    public async Task<NativeDnsResult> QueryAsync(
        string target,
        string queryType = "ALL",
        CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("dns-native.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["query_type"] = queryType,
        });

        var result = new NativeDnsResult
        {
            Target = target,
            QueryType = queryType,
        };

        var qt = queryType.Trim().ToUpperInvariant();

        try
        {
            // Always do a PTR lookup first; the hostname feeds forward lookups.
            var ptrRecords = await _resolver
                .QueryRecordsAsync(ArpaName(target), QueryType.PTR, ct)
                .ConfigureAwait(false);
            if (ptrRecords.Records.Count > 0)
                result.Records["PTR"] = ptrRecords.Records.ToList();

            // Discover the hostname from the PTR answer so we can do forward lookups.
            var hostname = ExtractHostname(ptrRecords.Records) ?? target;

            if (qt is "ALL" or "A")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.A, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["A"] = r.Records.ToList();
            }
            if (qt is "ALL" or "AAAA")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.AAAA, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["AAAA"] = r.Records.ToList();
            }
            if (qt is "ALL" or "CNAME")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.CNAME, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["CNAME"] = r.Records.ToList();
            }
            if (qt is "ALL" or "MX")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.MX, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["MX"] = r.Records.ToList();
            }
            if (qt is "ALL" or "NS")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.NS, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["NS"] = r.Records.ToList();
            }
            if (qt is "ALL" or "TXT")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.TXT, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["TXT"] = r.Records.ToList();
            }
            if (qt is "ALL" or "SOA")
            {
                var r = await _resolver.QueryRecordsAsync(hostname, QueryType.SOA, ct).ConfigureAwait(false);
                if (r.Records.Count > 0) result.Records["SOA"] = r.Records.ToList();
            }

            // AXFR: attempt zone transfer against the target IP as nameserver.
            if (qt is "ALL" or "AXFR")
            {
                if (IPAddress.TryParse(target, out var nsAddr))
                {
                    var zone = DomainToZone(hostname);
                    var axfrOutcome = await _axfrProvider
                        .QueryAsync(zone, nsAddr, AxfrTimeout, ct)
                        .ConfigureAwait(false);

                    result.AxfrAttempted = true;
                    result.AxfrSuccess = axfrOutcome.Success;
                    if (axfrOutcome.Success)
                        result.AxfrRecords.AddRange(axfrOutcome.Records);
                    else
                        result.AxfrError = axfrOutcome.Error;
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        _audit.Record("dns-native.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["query_type"] = queryType,
            ["record_types"] = string.Join(",", result.Records.Keys),
            ["axfr_attempted"] = result.AxfrAttempted,
            ["axfr_success"] = result.AxfrSuccess,
            ["error"] = result.Error,
        });

        return result;
    }

    // Convert an IPv4 or IPv6 address to its arpa PTR name.
    private static string ArpaName(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return ip;
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var parts = ip.Split('.');
            return string.Join(".", parts.Reverse()) + ".in-addr.arpa";
        }
        // IPv6: expand, reverse nibbles, append ip6.arpa
        var expanded = addr.GetAddressBytes()
            .SelectMany(b => new[] { (b >> 4) & 0xf, b & 0xf })
            .Reverse()
            .Select(n => n.ToString("x"));
        return string.Join(".", expanded) + ".ip6.arpa";
    }

    // Pull the first hostname from a list of PTR record strings like
    // "1.10.10.10.in-addr.arpa\t300\tIN\tPTR\thostname.domain."
    private static string? ExtractHostname(IReadOnlyList<string> ptrRecords)
    {
        foreach (var rec in ptrRecords)
        {
            var parts = rec.Split('\t', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 5)
            {
                var hostname = parts[^1].TrimEnd('.');
                if (!string.IsNullOrWhiteSpace(hostname)) return hostname;
            }
        }
        return null;
    }

    // For AXFR, use the parent domain (strip first label from an FQDN).
    private static string DomainToZone(string hostname)
    {
        var parts = hostname.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 2 ? string.Join(".", parts.Skip(1)) : hostname;
    }
}

/// <summary>
/// Outcome of a single multi-record DNS query via <see cref="INativeDnsResolver"/>.
/// </summary>
public sealed class NativeDnsOutcome
{
    public IReadOnlyList<string> Records { get; init; } = Array.Empty<string>();
    public string? Error { get; init; }
    public bool Refused { get; init; }
}

/// <summary>
/// Abstraction over DNS record queries. Injectable for unit testing.
/// Production implementation: <see cref="LookupClientResolver"/>.
/// </summary>
public interface INativeDnsResolver
{
    Task<NativeDnsOutcome> QueryRecordsAsync(
        string name,
        QueryType queryType,
        CancellationToken ct = default);
}

/// <summary>
/// Default resolver using DnsClient.NET's <see cref="LookupClient"/> against
/// the system nameservers. No external binary required.
/// </summary>
internal sealed class LookupClientResolver : INativeDnsResolver
{
    private readonly LookupClient _client = new(new LookupClientOptions
    {
        UseCache = false,
        Timeout = TimeSpan.FromSeconds(8),
    });

    public async Task<NativeDnsOutcome> QueryRecordsAsync(
        string name,
        QueryType queryType,
        CancellationToken ct = default)
    {
        try
        {
            var response = await _client.QueryAsync(name, queryType, QueryClass.IN, ct).ConfigureAwait(false);
            var records = response.Answers
                .Select(DnsRecordFormatter.Format)
                .Where(s => s is not null)
                .Cast<string>()
                .ToList();
            return new NativeDnsOutcome { Records = records };
        }
        catch (DnsResponseException ex) when (ex.Code == DnsResponseCode.Refused)
        {
            return new NativeDnsOutcome { Refused = true, Error = $"query refused ({ex.Code})" };
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new NativeDnsOutcome { Error = ex.Message };
        }
    }
}
