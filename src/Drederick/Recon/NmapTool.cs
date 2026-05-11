using System.Diagnostics;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Wrapper around the <c>nmap</c> binary. Service/version detection plus NSE
/// categories chosen according to the active <see cref="RunPermissions"/>:
///
///   • Strict mode (no lab) without any opt-ins: <c>safe,default</c>.
///   • Lab mode without opt-ins: adds <c>discovery,version</c>.
///   • Lab mode OR <see cref="ExploitCategory.CredAttacks"/> opted in:
///     adds <c>auth</c>.
///   • <see cref="ExploitCategory.ExecPocs"/> opted in: adds
///     <c>intrusive,vuln</c> (exploit category excluded — too slow, GAP-022).
///   • <see cref="ExploitCategory.Dos"/> opted in: adds <c>dos,malware</c>.
///
/// Scope is re-checked on entry; the target argument is validated through
/// <see cref="Scope.Scope.Require"/>. Port-spec argv is rejected unless it
/// matches a strict digit/dash/comma regex — see
/// <see cref="RejectUnsafePortSpec"/>.
/// </summary>
public sealed class NmapTool : IReconTool
{
    public string Name => "nmap";

    public string Description =>
        "Run nmap service/version scan with safe NSE scripts against a single target IP. " +
        "Returns open TCP ports and detected services. The target MUST be inside the authorized scope.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _nmapPath;
    private readonly bool _labMode;
    private readonly RunPermissions _permissions;
    private readonly ProxyContext? _proxy;

    // Strict (non-lab) NSE categories. Safe + default only.
    // safe    : scripts that do not attempt anything unsafe against the target
    // default : the curated default set
    private const string NseCategoriesStrict = "safe,default";

    // Lab/CTF NSE categories. Adds discovery + version for richer enumeration.
    // discovery : active discovery of networks/services
    // version   : version-detection helper scripts
    private const string NseCategoriesLab = "safe,default,discovery,version";

    // -Pn           : targets often drop ICMP in HTB/CTF environments
    // -sV -sC       : service/version + default NSE scripts
    // --script      : restrict to enumeration categories only (lab vs strict)
    // --top-ports   : sensible default when the agent hasn't asked for -p-
    // --host-timeout: cap per-host runtime to prevent NSE script stalls (GAP-022)
    private static readonly string[] BaseArgsCommon =
    [
        "-Pn", "-sV", "-sC",
        "-T4", "--min-rate", "1000",
        "--host-timeout", "300",
    ];

    public NmapTool(
        Scope.Scope scope,
        AuditLog audit,
        string? nmapPath = null,
        bool labMode = true,
        RunPermissions? permissions = null,
        ProxyContext? proxy = null)
    {
        _scope = scope;
        _audit = audit;
        _nmapPath = nmapPath ?? "nmap";
        _labMode = labMode;
        _permissions = permissions ?? RunPermissions.None;
        _proxy = proxy;
    }

    public string NseCategories => BuildNseCategories(_labMode, _permissions);

    /// <summary>
    /// GAP-049: build the nmap argv for a single target. When a
    /// <see cref="ProxyContext"/> is configured, prepends <c>-sT --proxies
    /// socks4://host:port</c> (nmap's <c>--proxies</c> only supports SOCKS4
    /// and HTTP, and only for TCP connect scans — UDP/SYN probes silently
    /// bypass the proxy and would leak the operator IP, so they're refused
    /// upstream by <see cref="Scanning.SynScanner"/>). Emits the warning
    /// audit event <c>nmap.proxy.unsupported_scan_type</c> when any
    /// non-CONNECT category was requested. Exposed <c>internal</c> so tests
    /// can assert argv shape without spawning nmap.
    /// </summary>
    internal List<string> BuildArgs(string target, string? portSpec)
    {
        var args = new List<string>(BaseArgsCommon);
        if (_proxy is not null)
        {
            args.Insert(0, "-sT");
            args.Add("--proxies");
            args.Add(_proxy.ToNmapProxiesArg());
            _audit.Record("nmap.proxy.unsupported_scan_type", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["proxy_endpoint"] = $"{_proxy.Host}:{_proxy.Port}",
                ["proxy_type"] = _proxy.Type.ToString(),
                ["note"] = "nmap --proxies supports SOCKS4/HTTP for TCP connect scans only; UDP/SYN probes bypass the proxy.",
            });
        }
        args.Add("--script");
        args.Add(NseCategories);
        args.Add("-oX");
        args.Add("-");
        if (!string.IsNullOrWhiteSpace(portSpec))
        {
            RejectUnsafePortSpec(portSpec);
            args.Add("-p");
            args.Add(portSpec);
        }
        else
        {
            args.Add("--top-ports");
            args.Add("1000");
        }
        args.Add(target);
        return args;
    }

    internal static string BuildNseCategories(bool labMode, RunPermissions permissions)
    {
        // Start from the lab/strict baseline.
        var cats = new List<string>(
            (labMode ? NseCategoriesLab : NseCategoriesStrict).Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        // Lab mode or credential attacks → enable `auth` scripts (SMB null
        // sessions, FTP anon, SNMP community checks, HTTP default logins).
        if (labMode || permissions.AllowCredAttacks)
        {
            AddIfMissing(cats, "auth");
        }

        // ExecPocs → unlock the aggressive enumeration NSE set.
        // intrusive : scripts that may be detected/logged by the target
        // vuln      : vulnerability detection scripts
        // NOTE: 'exploit' category deliberately excluded — exploit NSE scripts
        // run 30-60+ min on Windows hosts with many ports (GAP-022). Actual
        // exploitation is handled by nuclei/msf-rc/manual tools, not nmap NSE.
        if (permissions.AllowExecPocs)
        {
            AddIfMissing(cats, "intrusive");
            AddIfMissing(cats, "vuln");
        }

        // Dos → unlock denial-of-service and malware-hunting scripts.
        if (permissions.AllowDos)
        {
            AddIfMissing(cats, "dos");
            AddIfMissing(cats, "malware");
        }

        return string.Join(",", cats);
    }

    private static void AddIfMissing(List<string> cats, string cat)
    {
        if (!cats.Contains(cat, StringComparer.OrdinalIgnoreCase)) cats.Add(cat);
    }

    public async Task<NmapResult> ScanAsync(
        string target,
        string? portSpec = null,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        var args = BuildArgs(target, portSpec);

        _audit.Record("nmap.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["argv"] = args,
        });

        var psi = new ProcessStartInfo(_nmapPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        Process proc;
        try
        {
            proc = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
        }
        catch (Exception ex)
        {
            _audit.Record("nmap.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
            return new NmapResult { ReturnCode = -1, Stderr = ex.Message };
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        _audit.Record("nmap.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["returncode"] = proc.ExitCode,
        });

        if (proc.ExitCode != 0)
        {
            return new NmapResult
            {
                ReturnCode = proc.ExitCode,
                Stderr = Tail(stderr, 2000),
            };
        }

        var result = new NmapResult { ReturnCode = 0 };
        try { result.OpenPorts.AddRange(ParseXml(stdout)); }
        catch (Exception ex) { result.Stderr = "xml-parse: " + ex.Message; }
        return result;
    }

    private static void RejectUnsafePortSpec(string portSpec)
    {
        // Accept only: "-" (all ports), digit runs, and digit-dash-digit / digit-comma-digit
        // separators. No leading/trailing separators, no double separators. This is stricter
        // than nmap itself, which is deliberate: the spec comes from a tool call that the LLM
        // chose, so we reject anything that could be mis-parsed or used for argument injection.
        if (portSpec == "-") return;
        if (portSpec.Length == 0)
            throw new ArgumentException("Empty port spec.");
        if (portSpec[0] is ',' or '-' || portSpec[^1] is ',' or '-')
            throw new ArgumentException($"Unsafe port spec '{portSpec}': leading/trailing separator.");
        char prev = '\0';
        foreach (var ch in portSpec)
        {
            if (ch is >= '0' and <= '9') { prev = ch; continue; }
            if (ch is ',' or '-')
            {
                if (prev is ',' or '-' or '\0')
                    throw new ArgumentException($"Unsafe port spec '{portSpec}': adjacent separators.");
                prev = ch;
                continue;
            }
            throw new ArgumentException(
                $"Unsafe port spec '{portSpec}'. Only digits, commas, and dashes are allowed.");
        }
    }

    private static IEnumerable<NmapPort> ParseXml(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) yield break;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { yield break; }
        var host = doc.Root?.Element("host");
        if (host is null) yield break;
        foreach (var p in host.Elements("ports").Elements("port"))
        {
            var state = p.Element("state")?.Attribute("state")?.Value;
            if (state != "open") continue;
            var svc = p.Element("service");
            var port = new NmapPort
            {
                Port = int.TryParse(p.Attribute("portid")?.Value, out var n) ? n : 0,
                Protocol = p.Attribute("protocol")?.Value ?? "tcp",
                Service = svc?.Attribute("name")?.Value,
                Product = svc?.Attribute("product")?.Value,
                Version = svc?.Attribute("version")?.Value,
                Extra = svc?.Attribute("extrainfo")?.Value,
            };
            foreach (var s in p.Elements("script"))
            {
                port.Scripts.Add(new NmapScript
                {
                    Id = s.Attribute("id")?.Value ?? "",
                    Output = s.Attribute("output")?.Value ?? "",
                });
            }
            yield return port;
        }
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
