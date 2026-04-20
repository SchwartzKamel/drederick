using System.Text;
using Drederick.Recon;

namespace Drederick.Reporting;

/// <summary>
/// Emits a per-host <c>manual_commands.txt</c> cheatsheet listing commands the
/// operator <em>may</em> choose to run themselves, outside drederick. Drederick
/// does not execute these. The cheatsheet is an AutoRecon-style convenience;
/// it is only generated when lab/CTF mode is active.
/// <para>
/// The commands emitted are enumeration-oriented only. We deliberately do not
/// suggest exploit, brute-force, password-spray, or payload-delivery commands.
/// If you want those, pick them yourself; drederick won't recommend them.
/// </para>
/// </summary>
public static class ManualCommandsCheatsheet
{
    /// <summary>
    /// Writes per-host working directories under <paramref name="outputRoot"/>:
    /// <c>out/&lt;host&gt;/scans/</c>, <c>out/&lt;host&gt;/loot/</c>,
    /// <c>out/&lt;host&gt;/notes.md</c>, and (if enabled) <c>manual_commands.txt</c>.
    /// </summary>
    /// <param name="outputRoot">Top-level output directory (e.g. <c>out/</c>).</param>
    /// <param name="hosts">Findings to emit cheatsheets for.</param>
    /// <param name="emitCheatsheet">False in strict mode: only the directory skeleton is created.</param>
    public static void Write(string outputRoot, IEnumerable<HostFinding> hosts, bool emitCheatsheet)
    {
        foreach (var h in hosts)
        {
            var hostDir = Path.Combine(outputRoot, SanitizeHostForPath(h.Target));
            Directory.CreateDirectory(Path.Combine(hostDir, "scans"));
            Directory.CreateDirectory(Path.Combine(hostDir, "loot"));

            // notes.md is always present so the operator can start taking notes
            // immediately regardless of mode.
            var notesPath = Path.Combine(hostDir, "notes.md");
            if (!File.Exists(notesPath))
            {
                File.WriteAllText(notesPath, $"# {h.Target}\n\n_Operator notes. Safe to hand-edit; drederick never overwrites this file after creation._\n");
            }

            if (!emitCheatsheet) continue;

            var cheatsheetPath = Path.Combine(hostDir, "manual_commands.txt");
            File.WriteAllText(cheatsheetPath, BuildCheatsheet(h));
        }
    }

    public static string BuildCheatsheet(HostFinding h)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# drederick manual-commands cheatsheet for {h.Target}");
        sb.AppendLine("# Enumeration commands you MAY choose to run yourself, outside drederick.");
        sb.AppendLine("# Drederick does NOT execute these. Lab/CTF authorized targets only.");
        sb.AppendLine("# Offensive categories (exploitation, credential-guessing, payload-");
        sb.AppendLine("# delivery) are intentionally absent. Pick those yourself if appropriate.");
        sb.AppendLine();

        var ports = h.Nmap?.OpenPorts ?? new List<NmapPort>();
        if (ports.Count == 0)
        {
            sb.AppendLine("# No open TCP services were observed. Suggested next steps:");
            sb.AppendLine($"nmap -Pn -p- -T4 --min-rate 1000 {h.Target}");
            sb.AppendLine($"nmap -Pn -sU --top-ports 100 -T4 {h.Target}");
            return sb.ToString();
        }

        foreach (var p in ports)
        {
            var svc = (p.Service ?? "").ToLowerInvariant();
            sb.AppendLine($"## {p.Port}/{p.Protocol} {p.Service} {p.Product} {p.Version}".TrimEnd());

            switch (svc)
            {
                case "http":
                case "http-proxy":
                    EmitHttp(sb, h.Target, p.Port, useTls: false);
                    break;
                case "https":
                case "ssl/http":
                case "http-alt":
                    EmitHttp(sb, h.Target, p.Port, useTls: true);
                    break;
                case "ftp":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script ftp-anon,ftp-syst {h.Target}");
                    sb.AppendLine($"# anonymous read-only listing:");
                    sb.AppendLine($"curl -s --ftp-method nocwd ftp://anonymous:anon@{h.Target}:{p.Port}/");
                    break;
                case "ssh":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script ssh2-enum-algos,ssh-hostkey {h.Target}");
                    sb.AppendLine($"ssh-keyscan -p {p.Port} {h.Target}");
                    break;
                case "smtp":
                case "submission":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script smtp-commands,smtp-ntlm-info {h.Target}");
                    break;
                case "dns":
                case "domain":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script dns-nsid,dns-recursion {h.Target}");
                    sb.AppendLine($"dig @{h.Target} version.bind chaos txt");
                    break;
                case "microsoft-ds":
                case "netbios-ssn":
                case "smb":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script smb-os-discovery,smb-protocols,smb2-security-mode {h.Target}");
                    sb.AppendLine($"# read-only share enumeration:");
                    sb.AppendLine($"smbclient -L //{h.Target}/ -N");
                    break;
                case "ldap":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script ldap-rootdse,ldap-search {h.Target}");
                    sb.AppendLine($"ldapsearch -x -H ldap://{h.Target}:{p.Port} -s base -b \"\"");
                    break;
                case "snmp":
                    sb.AppendLine($"# read-only walk with 'public' community (common CTF default):");
                    sb.AppendLine($"snmpwalk -v2c -c public {h.Target}");
                    break;
                case "rpcbind":
                case "sunrpc":
                    sb.AppendLine($"rpcinfo -p {h.Target}");
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script rpc-grind {h.Target}");
                    break;
                case "kerberos-sec":
                case "kerberos":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script krb5-enum-users --script-args krb5-enum-users.realm=EXAMPLE.LOCAL {h.Target}");
                    sb.AppendLine($"# SPN listing only; drederick will not suggest roasting or user-enum brute-force attacks.");
                    break;
                case "mysql":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script mysql-info {h.Target}");
                    break;
                case "postgresql":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script pgsql-info {h.Target}");
                    break;
                case "redis":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script redis-info {h.Target}");
                    break;
                case "mongodb":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script mongodb-info {h.Target}");
                    break;
                default:
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script safe,default,discovery,version {h.Target}");
                    break;
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static void EmitHttp(StringBuilder sb, string target, int port, bool useTls)
    {
        var scheme = useTls ? "https" : "http";
        sb.AppendLine($"curl -sk -D - {scheme}://{target}:{port}/ -o /dev/null");
        sb.AppendLine($"curl -sk {scheme}://{target}:{port}/robots.txt");
        sb.AppendLine($"curl -sk {scheme}://{target}:{port}/sitemap.xml");
        sb.AppendLine($"nmap -Pn -p {port} --script http-title,http-headers,http-methods,http-enum {target}");
        if (useTls)
        {
            sb.AppendLine($"nmap -Pn -p {port} --script ssl-cert,ssl-enum-ciphers {target}");
            sb.AppendLine($"openssl s_client -connect {target}:{port} -servername {target} </dev/null 2>/dev/null | openssl x509 -noout -text");
        }
    }

    private static string SanitizeHostForPath(string target)
    {
        // IPv6 addresses contain ':' which is a path separator on some filesystems
        // (and a drive-letter delimiter on Windows). Replace with '_' for safety.
        var bad = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(target.Length);
        foreach (var ch in target)
        {
            sb.Append(ch == ':' || Array.IndexOf(bad, ch) >= 0 ? '_' : ch);
        }
        return sb.ToString();
    }
}
