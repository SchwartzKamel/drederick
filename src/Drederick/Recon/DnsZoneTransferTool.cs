using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Attempts a DNS zone transfer (AXFR) for a domain against a named nameserver.
/// Shells out to the <c>dig</c> binary; no record-type bruteforcing, no
/// subdomain enumeration, no recursive NS chasing — this is a single AXFR
/// attempt per call.
///
/// Scope semantics (there is genuine ambiguity here — AXFR has *two* targets:
/// the domain being asked about, and the nameserver being asked). We resolve
/// the ambiguity as follows:
///   * The caller MUST pass an explicit nameserver (an IP literal). The tool
///     calls <see cref="Scope.Scope.Require"/> on that IP. The scope enforcer
///     only understands IP addresses, so an IP literal is the only thing it
///     can meaningfully validate.
///   * If the caller does NOT pass a nameserver, we refuse with a
///     <see cref="ScopeException"/>. Letting <c>dig</c> "pick" the NS would
///     send the AXFR to whichever authoritative server the recursive resolver
///     returns, which we cannot scope-check in advance — that's precisely the
///     kind of "route around the scope" that <see cref="IReconTool"/>
///     forbids. The caller is expected to run <c>dns</c> or <c>nmap</c> on
///     candidate NS hosts inside scope first, then pass one explicitly here.
/// The <c>domain</c> argument is not itself scope-checked because domains are
/// not IPs; the gate is the nameserver IP that will actually receive traffic.
/// </summary>
public sealed class DnsZoneTransferTool : IReconTool
{
    public string Name => "dns-axfr";

    public string Description =>
        "Attempt a DNS zone transfer (AXFR) for a domain against an in-scope nameserver IP. " +
        "Returns the parsed record list on success, or the refusal reason on failure. " +
        "The nameserver MUST be an IP literal inside the authorized scope.";

    private const int TimeoutSeconds = 10;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _digPath;
    private readonly IProcessRunner _runner;

    public DnsZoneTransferTool(
        Scope.Scope scope,
        AuditLog audit,
        string? digPath = null,
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _digPath = digPath ?? "dig";
        _runner = runner ?? new DefaultProcessRunner();
    }

    public Task<DnsZoneTransferResult> ProbeAsync(
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

        var arguments = $"AXFR {domain} @{nameserver} +time=5 +tries=1";

        int exit;
        string stdout;
        string stderr;
        try
        {
            (exit, stdout, stderr) = _runner.Run(_digPath, arguments, TimeoutSeconds);
        }
        catch (TimeoutException ex)
        {
            result.Success = false;
            result.Error = "timeout: " + ex.Message;
            _audit.Record("dns-axfr.finish", new Dictionary<string, object?>
            {
                ["domain"] = domain,
                ["nameserver"] = nameserver,
                ["success"] = false,
                ["error"] = result.Error,
            });
            return Task.FromResult(result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"dig failed to start: {ex.Message}";
            _audit.Record("dns-axfr.finish", new Dictionary<string, object?>
            {
                ["domain"] = domain,
                ["nameserver"] = nameserver,
                ["success"] = false,
                ["error"] = result.Error,
            });
            return Task.FromResult(result);
        }

        if (exit == -1)
        {
            result.Success = false;
            result.Error = string.IsNullOrWhiteSpace(stderr)
                ? "dig binary not available (exit -1)"
                : Tail(stderr, 500);
        }
        else if (LooksRefused(stdout, stderr))
        {
            result.Success = false;
            result.Error = ExtractRefusal(stdout, stderr);
        }
        else
        {
            var records = ParseRecords(stdout).ToList();
            if (records.Count == 0)
            {
                result.Success = false;
                result.Error = exit != 0
                    ? $"dig exit {exit}: {Tail(stderr, 300)}"
                    : "no records returned";
            }
            else
            {
                result.Success = true;
                result.Records.AddRange(records);
            }
        }

        _audit.Record("dns-axfr.finish", new Dictionary<string, object?>
        {
            ["domain"] = domain,
            ["nameserver"] = nameserver,
            ["success"] = result.Success,
            ["record_count"] = result.Records.Count,
            ["error"] = result.Error,
        });
        return Task.FromResult(result);
    }

    private static bool LooksRefused(string stdout, string stderr)
    {
        var haystack = stdout + "\n" + stderr;
        return haystack.Contains("Transfer failed", StringComparison.OrdinalIgnoreCase)
            || haystack.Contains("REFUSED", StringComparison.Ordinal)
            || haystack.Contains("communications error", StringComparison.OrdinalIgnoreCase)
            || haystack.Contains("connection refused", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractRefusal(string stdout, string stderr)
    {
        foreach (var raw in (stdout + "\n" + stderr).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.Contains("Transfer failed", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("REFUSED", StringComparison.Ordinal) ||
                line.Contains("communications error", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("connection refused", StringComparison.OrdinalIgnoreCase))
            {
                return line;
            }
        }
        return "zone transfer refused";
    }

    private static IEnumerable<string> ParseRecords(string stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) yield break;
        foreach (var raw in stdout.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            // dig prefixes comments with ';' (including ';;' diagnostic lines).
            if (line.TrimStart().StartsWith(';')) continue;
            // A valid RR line has at least: owner TTL CLASS TYPE RDATA (>=5 whitespace-
            // separated fields). Reject anything shorter to skip stray output.
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) continue;
            yield return line.Trim();
        }
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
