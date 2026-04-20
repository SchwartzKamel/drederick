using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Read-only SNMPv2c probe that shells out to <c>snmpwalk</c> and reads only the
/// <c>1.3.6.1.2.1.1</c> (system) subtree. Tries the two well-known default
/// communities (<c>public</c>, then <c>private</c>) and stops on the first one
/// that returns data. Never performs writes (no <c>snmpset</c>), never walks
/// other subtrees, and never attempts community brute-forcing.
/// </summary>
public sealed class SnmpTool : IReconTool
{
    public string Name => "snmp";

    public string Description =>
        "Probe SNMPv2c on a single target and read the system OID subtree " +
        "(1.3.6.1.2.1.1) using the default community strings public/private. " +
        "Read-only; never brute-forces communities or walks other subtrees.";

    // Fixed list of communities. Intentionally small: this is discovery, not a
    // brute force. If neither works the tool reports Reachable=false.
    private static readonly string[] DefaultCommunities = ["public", "private"];

    private const string SystemOid = "1.3.6.1.2.1.1";

    // Output hygiene caps. snmpwalk on a misbehaving agent can otherwise stream
    // unbounded data; the system subtree should fit comfortably in both.
    internal const int MaxOids = 200;
    internal const int MaxBytes = 64 * 1024;

    // Per-community wall-clock budget. snmpwalk's own -t 2 -r 0 keeps the
    // network side short; this caps any runaway subprocess.
    private const int TimeoutSeconds = 15;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly string _snmpwalkPath;

    public SnmpTool(
        Scope.Scope scope,
        AuditLog audit,
        IProcessRunner? runner = null,
        string? snmpwalkPath = null)
    {
        _scope = scope;
        _audit = audit;
        _runner = runner ?? new DefaultProcessRunner();
        _snmpwalkPath = snmpwalkPath ?? "snmpwalk";
    }

    public Task<SnmpResult> ProbeAsync(string target, int port = 161, CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("snmp.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["communities"] = DefaultCommunities,
        });

        var result = new SnmpResult { Port = port };
        string? lastError = null;

        foreach (var community in DefaultCommunities)
        {
            ct.ThrowIfCancellationRequested();

            var arguments = BuildArguments(community, target, port);

            int exit;
            string stdout, stderr;
            try
            {
                (exit, stdout, stderr) = _runner.Run(_snmpwalkPath, arguments, TimeoutSeconds);
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                continue;
            }

            // Runner-level failure (binary missing, spawn error): no point
            // retrying with another community, the result will be the same.
            if (exit == -1)
            {
                lastError = FirstNonEmpty(stderr, stdout, $"snmpwalk exited -1");
                break;
            }

            if (exit != 0 || LooksLikeFailure(stdout, stderr))
            {
                lastError = FirstNonEmpty(stderr, stdout, $"snmpwalk exit={exit}");
                continue;
            }

            var parsed = Parse(stdout);
            if (parsed.Count == 0)
            {
                lastError = "snmpwalk returned no OIDs";
                continue;
            }

            result.Community = community;
            result.Reachable = true;
            foreach (var kv in parsed) result.SystemOids[kv.Key] = kv.Value;
            lastError = null;
            break;
        }

        if (!result.Reachable)
        {
            result.Error = Tail(lastError ?? "snmp probe failed", 500);
        }

        _audit.Record("snmp.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["reachable"] = result.Reachable,
            ["community"] = result.Community,
            ["oid_count"] = result.SystemOids.Count,
        });

        return Task.FromResult(result);
    }

    private static string BuildArguments(string community, string target, int port)
    {
        // -v2c              : SNMPv2c (v1 is weaker; v3 needs creds we don't have)
        // -c <community>    : read community string
        // -t 2 -r 0         : 2s timeout, no retries — fail fast
        // -O n -On          : numeric OIDs, no MIB name translation
        // <target>:<port>   : target endpoint (snmpwalk does UDP)
        // SystemOid         : restrict walk to the system subtree
        return string.Join(' ',
            "-v2c", "-c", community, "-t", "2", "-r", "0", "-O", "n", "-On",
            $"{target}:{port}", SystemOid);
    }

    private static bool LooksLikeFailure(string stdout, string stderr)
    {
        var combined = (stdout ?? string.Empty) + "\n" + (stderr ?? string.Empty);
        return combined.Contains("Timeout", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("No Response", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("Authentication failure", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("unknown community", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("No more variables left", StringComparison.OrdinalIgnoreCase);
    }

    internal static Dictionary<string, string> Parse(string stdout)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(stdout)) return dict;

        var capped = stdout.Length > MaxBytes ? stdout[..MaxBytes] : stdout;
        foreach (var rawLine in capped.Split('\n'))
        {
            if (dict.Count >= MaxOids) break;
            var line = rawLine.Trim();
            if (line.Length == 0) continue;

            // Expected line shape: "<OID> = <TYPE>: <VALUE>" where TYPE is a
            // short SMI type name (STRING, OID, Timeticks, INTEGER, ...). We
            // key the dictionary on the raw OID and store the value verbatim
            // (quotes stripped) — consumers can re-parse types if they care.
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var oid = line[..eq].Trim();
            if (oid.Length == 0) continue;

            var rhs = line[(eq + 1)..].Trim();
            var colon = rhs.IndexOf(':');
            string value = (colon > 0 && colon < 30 && !rhs.StartsWith('"'))
                ? rhs[(colon + 1)..].Trim()
                : rhs;

            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
                value = value[1..^1];

            dict[oid] = value;
        }
        return dict;
    }

    private static string FirstNonEmpty(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (!string.IsNullOrWhiteSpace(c)) return c!.Trim();
        }
        return string.Empty;
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
