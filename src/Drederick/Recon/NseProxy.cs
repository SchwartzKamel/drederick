using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Ops;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Pattern 1 — Graceful enrichment via the external <c>nmap</c> binary, as
/// described in <c>docs/PLUGIN_STRATEGY.md</c>. Native scanners (notably
/// <see cref="NativeScannerTool"/>) are always the floor: this tool runs
/// <c>nmap -sV --script &lt;categories&gt; -p &lt;ports&gt; &lt;target&gt;</c> against
/// already-discovered open ports and merges the per-script output into
/// <see cref="HostFinding.NseFindings"/>. When <c>nmap</c> is absent it
/// records an <c>nseproxy.skip</c> audit event and returns cleanly — the
/// run NEVER fails because nmap is missing.
///
/// NSE category policy (mirrors <see cref="NmapTool"/> with the
/// auth/exploit/intrusive/vuln set unconditionally enabled in lab mode, per
/// the docs/PLUGIN_STRATEGY.md spec):
///   • Strict mode default: <c>safe,default,discovery,version</c>.
///   • Lab mode default: <c>safe,default,discovery,version,auth,exploit,intrusive,vuln</c>.
///   • <see cref="RunPermissions.AllowDos"/> OR
///     <see cref="RunPermissions.AllowDestructive"/> adds <c>dos,malware</c>.
///
/// Scope is re-checked on entry. Every host that ends up in subprocess argv
/// is re-validated through <see cref="Scope.Scope.Require"/> immediately
/// before the spawn, per the AGENTS.md
/// <c>@invariant-id:subprocess-args-validated</c> rule.
/// </summary>
public sealed class NseProxy : IReconTool
{
    public string Name => "nse-proxy";

    public string Description =>
        "Pattern 1 graceful enrichment: when nmap is on PATH, run NSE scripts " +
        "(category-gated by lab mode + run permissions) against already-discovered " +
        "open ports and merge per-script output into HostFinding.NseFindings. " +
        "When nmap is absent, log + skip cleanly. Target MUST be in scope.";

    /// <summary>Minimal subprocess result; runner is injected for tests.</summary>
    public sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);

    /// <summary>Process runner: run (path, args) and return exit+streams.</summary>
    public delegate Task<ProcessResult> ProcessRunner(
        string path,
        IReadOnlyList<string> args,
        CancellationToken ct);

    /// <summary>Probe for nmap availability; injected for tests.</summary>
    public delegate bool AvailabilityProbe();

    private const string CategoriesStrict = "safe,default,discovery,version";
    private const string CategoriesLab = "safe,default,discovery,version,auth,exploit,intrusive,vuln";

    private static readonly string[] BaseArgs = ["-Pn", "-sV"];

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _nmapPath;
    private readonly bool _labMode;
    private readonly RunPermissions _permissions;
    private readonly ProcessRunner _runner;
    private readonly AvailabilityProbe _isAvailable;

    public NseProxy(
        Scope.Scope scope,
        AuditLog audit,
        string? nmapPath = null,
        bool labMode = true,
        RunPermissions? permissions = null,
        ProcessRunner? runner = null,
        AvailabilityProbe? isAvailable = null)
    {
        _scope = scope;
        _audit = audit;
        _nmapPath = nmapPath ?? "nmap";
        _labMode = labMode;
        _permissions = permissions ?? RunPermissions.None;
        _runner = runner ?? DefaultRunner;
        _isAvailable = isAvailable ?? (() => PathResolver.IsAvailable("nmap"));
    }

    /// <summary>Effective NSE category list given lab mode + run permissions.</summary>
    public string Categories => BuildCategories(_labMode, _permissions);

    internal static string BuildCategories(bool labMode, RunPermissions permissions)
    {
        var cats = new List<string>(
            (labMode ? CategoriesLab : CategoriesStrict).Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        if (permissions.AllowDos || permissions.AllowDestructive)
        {
            if (!cats.Contains("dos", StringComparer.OrdinalIgnoreCase)) cats.Add("dos");
            if (!cats.Contains("malware", StringComparer.OrdinalIgnoreCase)) cats.Add("malware");
        }
        return string.Join(",", cats);
    }

    /// <summary>
    /// Build a deterministic, sorted, deduped, range-collapsed nmap port spec
    /// from a heterogeneous port list. Throws on any non-positive or
    /// out-of-range entry. Exposed <c>internal</c> for unit testing.
    /// </summary>
    internal static string BuildPortSpec(IEnumerable<int> ports)
    {
        var sorted = new SortedSet<int>();
        foreach (var p in ports)
        {
            if (p < 1 || p > 65535)
                throw new ArgumentOutOfRangeException(nameof(ports), p, "port must be in [1, 65535].");
            sorted.Add(p);
        }
        if (sorted.Count == 0) throw new ArgumentException("Empty port list.", nameof(ports));

        var sb = new StringBuilder();
        int? runStart = null;
        int prev = -2;
        foreach (var p in sorted)
        {
            if (runStart is null)
            {
                runStart = p;
                prev = p;
                continue;
            }
            if (p == prev + 1)
            {
                prev = p;
                continue;
            }
            AppendRange(sb, runStart.Value, prev);
            runStart = p;
            prev = p;
        }
        AppendRange(sb, runStart!.Value, prev);
        return sb.ToString();

        static void AppendRange(StringBuilder sb, int start, int end)
        {
            if (sb.Length > 0) sb.Append(',');
            if (start == end) sb.Append(start);
            else sb.Append(start).Append('-').Append(end);
        }
    }

    /// <summary>
    /// Run the NSE enrichment phase against <paramref name="target"/> with the
    /// given <paramref name="ports"/>. Returns a (possibly empty) list of
    /// <see cref="NseFinding"/> records. NEVER throws on missing nmap or on
    /// nmap exit failure: it logs and returns. Out-of-scope targets and
    /// argv-host mismatches DO throw <see cref="ScopeException"/>.
    /// </summary>
    public async Task<IReadOnlyList<NseFinding>> EnrichAsync(
        string target,
        IReadOnlyList<int> ports,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        if (ports is null || ports.Count == 0)
        {
            _audit.Record("nseproxy.skip", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["reason"] = "no open ports",
                ["port_count"] = 0,
            });
            return Array.Empty<NseFinding>();
        }

        if (!_isAvailable())
        {
            Console.Error.WriteLine("[i] nmap not present, NSE enrichment skipped");
            _audit.Record("nseproxy.skip", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["reason"] = "nmap not on PATH",
                ["port_count"] = ports.Count,
            });
            return Array.Empty<NseFinding>();
        }

        string portSpec;
        try { portSpec = BuildPortSpec(ports); }
        catch (Exception ex)
        {
            _audit.Record("nseproxy.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = "port-spec: " + ex.Message,
            });
            return Array.Empty<NseFinding>();
        }

        var args = new List<string>(BaseArgs);
        args.Add("--script");
        args.Add(Categories);
        args.Add("-p");
        args.Add(portSpec);
        args.Add("-oX");
        args.Add("-");
        args.Add(target);

        // Re-validate every argv element that could be a host before spawn.
        // The only host in argv is `target`, but the loop is the canonical
        // shape for this invariant — it future-proofs us against extra-host
        // argv (pivots, redirect targets) being added without the check.
        AssertArgvHostsInScope(args);

        var argvDigest = ArgvDigest(args);

        _audit.Record("nseproxy.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port_count"] = ports.Count,
            ["categories"] = Categories,
            ["argv_sha256"] = argvDigest,
        });

        ProcessResult pr;
        try
        {
            pr = await _runner(_nmapPath, args, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _audit.Record("nseproxy.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port_count"] = ports.Count,
                ["argv_sha256"] = argvDigest,
                ["error"] = ex.Message,
            });
            return Array.Empty<NseFinding>();
        }

        List<NseFinding> findings;
        try
        {
            findings = ParseXml(pr.Stdout);
        }
        catch (Exception ex)
        {
            _audit.Record("nseproxy.parse_error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["argv_sha256"] = argvDigest,
                ["error"] = ex.Message,
            });
            findings = new List<NseFinding>();
        }

        _audit.Record("nseproxy.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port_count"] = ports.Count,
            ["argv_sha256"] = argvDigest,
            ["returncode"] = pr.ExitCode,
            ["script_count"] = findings.Count,
        });

        return findings;
    }

    /// <summary>
    /// Validate every argv element that parses as an IP literal through the
    /// scope. Subprocess argv injection of an out-of-scope host is rejected.
    /// </summary>
    private void AssertArgvHostsInScope(IEnumerable<string> args)
    {
        foreach (var a in args)
        {
            // Only treat dotted/colon literals as host candidates; bare
            // integers like "80" parse as IPv4 0.0.0.80 under IPAddress.TryParse,
            // and a numeric port spec is not a host.
            if ((a.Contains('.') || a.Contains(':'))
                && System.Net.IPAddress.TryParse(a, out _))
            {
                _scope.Require(a);
            }
        }
    }

    private static List<NseFinding> ParseXml(string xml)
    {
        var findings = new List<NseFinding>();
        if (string.IsNullOrWhiteSpace(xml)) return findings;
        var doc = XDocument.Parse(xml);
        var host = doc.Root?.Element("host");
        if (host is null) return findings;

        foreach (var p in host.Elements("ports").Elements("port"))
        {
            // Closed/filtered ports are dropped — only merge scripts that
            // executed against a confirmed open port.
            var state = p.Element("state")?.Attribute("state")?.Value;
            if (state != "open") continue;

            if (!int.TryParse(p.Attribute("portid")?.Value, out var portNum)) continue;

            foreach (var s in p.Elements("script"))
            {
                findings.Add(new NseFinding
                {
                    Port = portNum,
                    Script = s.Attribute("id")?.Value ?? "",
                    Output = s.Attribute("output")?.Value ?? "",
                });
            }
        }
        return findings;
    }

    private static string ArgvDigest(IEnumerable<string> args)
    {
        var joined = string.Join("\x1f", args);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static async Task<ProcessResult> DefaultRunner(
        string path,
        IReadOnlyList<string> args,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo(path)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return new ProcessResult(proc.ExitCode, stdout, stderr);
    }
}
