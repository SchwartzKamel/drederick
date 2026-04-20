using System.Text.RegularExpressions;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Read-only SMB probe. Runs <c>nmap</c> with the safe/default NSE scripts
/// <c>smb-os-discovery</c>, <c>smb-protocols</c>, and <c>smb2-security-mode</c>
/// to collect OS/host identity, advertised dialects, and signing posture.
///
/// If <c>enum4linux-ng</c> is installed, it is invoked additionally with
/// read-only flags (<c>-A -R</c>) to enumerate shares and users. The tool
/// NEVER uses credential-probing scripts (<c>smb-brute</c>, <c>smb-vuln-*</c>,
/// <c>smb-enum-users</c> with auth, <c>smb-enum-shares</c> with auth), never
/// passes credentials, and never mounts or writes to any share.
/// </summary>
public sealed class SmbTool : IReconTool
{
    public string Name => "smb";

    public string Description =>
        "Probe SMB on 139/445 using nmap's safe/default discovery scripts " +
        "(smb-os-discovery, smb-protocols, smb2-security-mode) and, when " +
        "available, enum4linux-ng with read-only flags. Never authenticates, " +
        "brute-forces, or writes.";

    // Exactly the three NSE scripts allowed: all live in safe/default and do
    // not perform credentialed enumeration, brute forcing, or vuln probing.
    internal const string NmapScripts = "smb-os-discovery,smb-protocols,smb2-security-mode";

    // Hard-denylisted script name fragments. Used both as a self-check on the
    // command line we build and as a test-visible contract.
    internal static readonly string[] ForbiddenScriptFragments =
    [
        "brute",
        "vuln",
        "enum-users",
        "enum-shares",
    ];

    // Cap on enum4linux-ng stdout we will parse/retain, to keep memory bounded
    // if it goes chatty. 128 KiB is plenty for a shares+users listing.
    internal const int MaxEnum4LinuxBytes = 128 * 1024;

    private const int NmapTimeoutSeconds = 120;
    private const int Enum4LinuxTimeoutSeconds = 120;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly string _nmapPath;
    private readonly string _enum4linuxPath;

    public SmbTool(
        Scope.Scope scope,
        AuditLog audit,
        IProcessRunner? runner = null,
        string? nmapPath = null,
        string? enum4linuxPath = null)
    {
        _scope = scope;
        _audit = audit;
        _runner = runner ?? new DefaultProcessRunner();
        _nmapPath = nmapPath ?? "nmap";
        _enum4linuxPath = enum4linuxPath ?? "enum4linux-ng";
    }

    public Task<SmbResult> ProbeAsync(string target, CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("smb.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["nmap_scripts"] = NmapScripts,
        });

        var result = new SmbResult { Port = 445 };

        // ---- 1. nmap scripted scan ----
        var nmapArgs = BuildNmapArguments(target);
        AssertNoForbiddenScripts(nmapArgs);

        try
        {
            var (exit, stdout, stderr) = _runner.Run(_nmapPath, nmapArgs, NmapTimeoutSeconds);
            if (exit == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                try { ParseNmapXml(stdout, result); }
                catch (Exception ex) { AppendError(result, $"xml-parse: {ex.Message}"); }
            }
            else
            {
                var msg = !string.IsNullOrWhiteSpace(stderr) ? Tail(stderr, 500) : $"nmap exit {exit}";
                AppendError(result, $"nmap: {msg}");
            }
        }
        catch (Exception ex)
        {
            AppendError(result, $"nmap: {ex.Message}");
        }

        // ---- 2. enum4linux-ng (optional, silently skipped if absent) ----
        try
        {
            var e4lArgs = BuildEnum4LinuxArguments(target);
            AssertNoForbiddenScripts(e4lArgs); // belt and suspenders
            var (exit, stdout, _) = _runner.Run(_enum4linuxPath, e4lArgs, Enum4LinuxTimeoutSeconds);
            if (exit == -1)
            {
                // Runner reports -1 when the binary could not be spawned
                // (e.g., not on PATH). enum4linux-ng is optional, so we skip
                // silently and do not taint result.Error.
            }
            else
            {
                var capped = stdout.Length > MaxEnum4LinuxBytes ? stdout[..MaxEnum4LinuxBytes] : stdout;
                var (shares, users) = ParseEnum4Linux(capped);
                result.Shares = shares;
                result.Users = users;
            }
        }
        catch
        {
            // enum4linux-ng is best-effort; any spawn/parse failure is ignored.
        }

        _audit.Record("smb.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["os"] = result.Os,
            ["computer_name"] = result.ComputerName,
            ["domain"] = result.Domain,
            ["protocol_count"] = result.Protocols.Count,
            ["signing_required"] = result.SigningRequired,
            ["share_count"] = result.Shares.Count,
            ["user_count"] = result.Users.Count,
            ["error"] = result.Error,
        });

        return Task.FromResult(result);
    }

    // Exposed for tests that want to verify the exact argv shape we build.
    internal static string BuildNmapArguments(string target) =>
        string.Join(' ',
            "-Pn",
            "-p", "139,445",
            "--script", NmapScripts,
            "-oX", "-",
            target);

    internal static string BuildEnum4LinuxArguments(string target) =>
        // -A : all simple enumeration (read-only).
        // -R : RID cycling.
        // No credentials, ever.
        string.Join(' ', "-A", "-R", target);

    internal static void AssertNoForbiddenScripts(string args)
    {
        foreach (var bad in ForbiddenScriptFragments)
        {
            if (args.Contains(bad, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"SmbTool refuses to run: forbidden script fragment '{bad}' in argv: {args}");
            }
        }
    }

    internal static void ParseNmapXml(string xml, SmbResult result)
    {
        if (string.IsNullOrWhiteSpace(xml)) return;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { return; }

        foreach (var script in doc.Descendants("script"))
        {
            var id = (string?)script.Attribute("id");
            switch (id)
            {
                case "smb-os-discovery":
                    ParseOsDiscovery(script, result);
                    break;
                case "smb-protocols":
                    ParseProtocols(script, result);
                    break;
                case "smb2-security-mode":
                    ParseSigning(script, result);
                    break;
            }
        }
    }

    private static void ParseOsDiscovery(XElement script, SmbResult result)
    {
        string? os = null, fqdn = null, netbiosCn = null, server = null;
        string? domainDns = null, netbiosDomain = null, domain = null, workgroup = null;
        foreach (var elem in script.Elements("elem"))
        {
            var key = (string?)elem.Attribute("key");
            var val = elem.Value;
            switch (key)
            {
                case "os": os = val; break;
                case "fqdn": fqdn = val; break;
                case "netbios_computer_name": netbiosCn = val; break;
                case "server": server = val; break;
                case "domain_dns": domainDns = val; break;
                case "netbios_domain_name": netbiosDomain = val; break;
                case "domain": domain = val; break;
                case "workgroup": workgroup = val; break;
            }
        }
        if (os is not null) result.Os = os;
        // Prefer richer identifiers: fqdn > netbios_computer_name > server.
        result.ComputerName = FirstNonNull(fqdn, netbiosCn, server);
        // Prefer DNS-style domain over NetBIOS/workgroup short names.
        result.Domain = FirstNonNull(domainDns, domain, netbiosDomain, workgroup);
    }

    private static string? FirstNonNull(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (!string.IsNullOrEmpty(c)) return c;
        }
        return null;
    }

    private static void ParseProtocols(XElement script, SmbResult result)
    {
        var table = script.Elements("table").FirstOrDefault(t => (string?)t.Attribute("key") == "dialects");
        if (table is null) return;
        foreach (var elem in table.Elements("elem"))
        {
            var v = elem.Value?.Trim();
            if (!string.IsNullOrEmpty(v)) result.Protocols.Add(v);
        }
    }

    private static void ParseSigning(XElement script, SmbResult result)
    {
        // smb2-security-mode reports one or more tables keyed by dialect; the
        // elem text contains "required" or "not required". If *any* table says
        // required, signing is required.
        bool sawRequired = false;
        bool sawNotRequired = false;
        foreach (var elem in script.Descendants("elem"))
        {
            var v = elem.Value ?? "";
            if (Regex.IsMatch(v, @"not\s+required", RegexOptions.IgnoreCase))
            {
                sawNotRequired = true;
            }
            else if (v.Contains("required", StringComparison.OrdinalIgnoreCase))
            {
                sawRequired = true;
            }
        }
        if (sawRequired) result.SigningRequired = true;
        else if (sawNotRequired) result.SigningRequired = false;
    }

    internal static (List<string> Shares, List<string> Users) ParseEnum4Linux(string output)
    {
        var shares = new List<string>();
        var users = new List<string>();
        if (string.IsNullOrEmpty(output)) return (shares, users);

        // enum4linux-ng emits banner lines like
        //     "=======( Shares on 10.10.10.5 )======="
        // and
        //     "=======( Users on 10.10.10.5 )======="
        // separating sections. Within each section, names appear either in
        // single quotes ('IPC$') or as JSON-ish keys ("IPC$":). We accept both.
        string section = "";
        var quoted = new Regex(@"'([^']+)'");
        var jsonKey = new Regex("\"([^\"]+)\"\\s*:");
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;

            if (Regex.IsMatch(line, @"\bShares\s+on\b", RegexOptions.IgnoreCase)
                || Regex.IsMatch(line, @"^\s*\""shares\""\s*:", RegexOptions.IgnoreCase))
            {
                section = "shares";
                continue;
            }
            if (Regex.IsMatch(line, @"\bUsers\s+on\b", RegexOptions.IgnoreCase)
                || Regex.IsMatch(line, @"^\s*\""users\""\s*:", RegexOptions.IgnoreCase))
            {
                section = "users";
                continue;
            }
            if (Regex.IsMatch(line, @"\b(Groups|Policy|OS Information|Sessions|Password Policy)\b",
                              RegexOptions.IgnoreCase))
            {
                section = "";
                continue;
            }

            if (section == "")
                continue;

            foreach (Match m in quoted.Matches(line))
            {
                Add(section == "shares" ? shares : users, m.Groups[1].Value);
            }
            foreach (Match m in jsonKey.Matches(line))
            {
                var name = m.Groups[1].Value;
                // Skip structural JSON keys.
                if (name.Equals("shares", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("users", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("comment", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("type", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("rid", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("username", StringComparison.OrdinalIgnoreCase))
                    continue;
                Add(section == "shares" ? shares : users, name);
            }
        }
        return (shares, users);

        static void Add(List<string> list, string name)
        {
            var n = name.Trim();
            if (n.Length == 0) return;
            if (!list.Contains(n, StringComparer.Ordinal)) list.Add(n);
        }
    }

    private static void AppendError(SmbResult result, string msg)
    {
        result.Error = string.IsNullOrEmpty(result.Error) ? msg : result.Error + "; " + msg;
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
