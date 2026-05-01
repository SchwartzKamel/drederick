using System.Net;
using Drederick.Audit;
using Drederick.Scope;
using DnsClient;
using DnsClient.Protocol;

namespace Drederick.Recon;

/// <summary>
/// Attempts a DNS zone transfer (AXFR) for a domain against a named nameserver
/// using DnsClient.NET — no external <c>dig</c> binary required.
///
/// Scope semantics: AXFR has two targets — the domain being asked about, and the
/// nameserver being asked. We resolve the ambiguity as follows:
///   * The caller MUST pass an explicit nameserver IP literal. The tool calls
///     <see cref="Scope.Scope.Require"/> on that IP. The scope enforcer only
///     understands IP addresses, so an IP literal is the only thing it can
///     meaningfully validate.
///   * If the caller does NOT pass a nameserver, we refuse with a
///     <see cref="ScopeException"/>. Letting the resolver pick the NS would send
///     the AXFR to an address we cannot scope-check in advance.
/// The <c>domain</c> argument is not itself scope-checked because domains are
/// not IPs; the gate is the nameserver IP that will actually receive traffic.
/// </summary>
public sealed class DnsZoneTransferTool : IReconTool
{
    public string Name => "dns-axfr";

    public string Description =>
        "Attempt a DNS zone transfer (AXFR) for a domain against an in-scope nameserver IP. " +
        "Returns the parsed record list on success, or the refusal reason on failure. " +
        "The nameserver MUST be an IP literal inside the authorized scope. " +
        "Uses native DnsClient.NET — no external dig binary required.";

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IAxfrProvider _provider;

    public DnsZoneTransferTool(
        Scope.Scope scope,
        AuditLog audit,
        IAxfrProvider? provider = null)
    {
        _scope = scope;
        _audit = audit;
        _provider = provider ?? new DnsClientAxfrProvider();
    }

    public async Task<DnsZoneTransferResult> ProbeAsync(
        string domain,
        string? nameserver = null,
        CancellationToken ct = default)
    {
        // See class-level comment for the scope semantics rationale.
        if (string.IsNullOrWhiteSpace(nameserver))
        {
            throw new ScopeException(
                "dns-axfr requires an explicit nameserver IP so the scope gate can validate " +
                "the AXFR destination. Pass a nameserver from inside the authorized scope.");
        }
        _scope.Require(nameserver);

        _audit.Record("dns-axfr.start", new Dictionary<string, object?>
        {
            ["domain"] = domain,
            ["nameserver"] = nameserver,
        });

        var result = new DnsZoneTransferResult
        {
            Domain = domain,
            NameServer = nameserver,
        };

        if (!IPAddress.TryParse(nameserver, out var nsAddr))
        {
            result.Success = false;
            result.Error = $"nameserver '{nameserver}' is not a valid IP address";
            _audit.Record("dns-axfr.finish", new Dictionary<string, object?>
            {
                ["domain"] = domain,
                ["nameserver"] = nameserver,
                ["success"] = false,
                ["error"] = result.Error,
            });
            return result;
        }

        var outcome = await _provider.QueryAsync(domain, nsAddr, DefaultTimeout, ct)
            .ConfigureAwait(false);

        if (outcome.Success)
        {
            result.Success = true;
            result.Records.AddRange(outcome.Records);
        }
        else
        {
            result.Success = false;
            result.Error = outcome.Error ?? "zone transfer failed";
        }

        _audit.Record("dns-axfr.finish", new Dictionary<string, object?>
        {
            ["domain"] = domain,
            ["nameserver"] = nameserver,
            ["success"] = result.Success,
            ["record_count"] = result.Records.Count,
            ["error"] = result.Error,
        });
        return result;
    }
}

/// <summary>
/// Result of an AXFR query attempt (returned by <see cref="IAxfrProvider"/>).
/// </summary>
public sealed class AxfrOutcome
{
    public bool Success { get; init; }
    public bool Refused { get; init; }
    public IReadOnlyList<string> Records { get; init; } = Array.Empty<string>();
    public string? Error { get; init; }
}

/// <summary>
/// Abstraction over DNS zone-transfer (AXFR) execution. Injectable for testing;
/// production uses <see cref="DnsClientAxfrProvider"/>.
/// </summary>
public interface IAxfrProvider
{
    Task<AxfrOutcome> QueryAsync(
        string zone,
        IPAddress nameserver,
        TimeSpan timeout,
        CancellationToken ct);
}

/// <summary>
/// Default AXFR provider: uses DnsClient.NET directly, no external binaries.
/// AXFR requires TCP — <c>UseTcpOnly</c> is set on the lookup client.
/// </summary>
internal sealed class DnsClientAxfrProvider : IAxfrProvider
{
    public async Task<AxfrOutcome> QueryAsync(
        string zone,
        IPAddress nameserver,
        TimeSpan timeout,
        CancellationToken ct)
    {
        var opts = new LookupClientOptions(new IPEndPoint(nameserver, 53))
        {
            UseCache = false,
            Recursion = false,
            Timeout = timeout,
            UseTcpOnly = true,
        };
        var client = new LookupClient(opts);

        try
        {
            var response = await client.QueryAsync(zone, QueryType.AXFR, QueryClass.IN, ct)
                .ConfigureAwait(false);

            var records = response.Answers
                .Select(DnsRecordFormatter.Format)
                .Where(s => s is not null)
                .Cast<string>()
                .ToList();

            if (records.Count == 0)
                return new AxfrOutcome { Success = false, Error = "no records returned" };

            return new AxfrOutcome { Success = true, Records = records };
        }
        catch (DnsResponseException ex)
            when (ex.Code == DnsResponseCode.Refused || ex.Code == DnsResponseCode.NotAuthorized)
        {
            return new AxfrOutcome
            {
                Refused = true,
                Error = $"zone transfer refused ({ex.Code})",
            };
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new AxfrOutcome { Error = ex.Message };
        }
    }
}

/// <summary>Formats DnsClient resource records as zone-file-style strings.</summary>
internal static class DnsRecordFormatter
{
    public static string? Format(DnsResourceRecord record)
    {
        var owner = record.DomainName.ToString();
        var ttl = record.TimeToLive;
        var cls = "IN";
        var type = record.RecordType.ToString().ToUpperInvariant();

        var rdata = record switch
        {
            ARecord a => a.Address.ToString(),
            AaaaRecord aaaa => aaaa.Address.ToString(),
            MxRecord mx => $"{mx.Preference} {mx.Exchange}",
            NsRecord ns => ns.NSDName.ToString(),
            SoaRecord soa =>
                $"{soa.MName} {soa.RName} {soa.Serial} {soa.Refresh} {soa.Retry} {soa.Expire} {soa.Minimum}",
            TxtRecord txt => string.Join(" ", txt.Text.Select(t => $"\"{t}\"")),
            CNameRecord cn => cn.CanonicalName.ToString(),
            PtrRecord ptr => ptr.PtrDomainName.ToString(),
            _ => null,
        };

        if (rdata is null) return null;
        return $"{owner}\t{ttl}\t{cls}\t{type}\t{rdata}";
    }
}
