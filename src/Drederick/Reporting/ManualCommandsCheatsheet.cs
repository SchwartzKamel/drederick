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
/// suggest exploit, password-spray, or payload-delivery commands (no
/// <c>msfconsole -x exploit/*</c>, no pre-seeded payloads, no
/// <c>evil-winrm</c> with a hardcoded password, no <c>msfvenom</c>, no
/// <c>hashcat -a 0</c>). If you want those, pick them yourself; drederick
/// will not recommend them.
/// </para>
/// </summary>
public static class ManualCommandsCheatsheet
{
    private const string OperatorBanner =
        "# NOTE: The following commands are suggestions for you to run manually " +
        "after reviewing scope. drederick will not execute them.";

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
        var target = h.Target;
        var sb = new StringBuilder();

        sb.AppendLine($"# drederick manual-commands cheatsheet for {target}");
        sb.AppendLine(OperatorBanner);
        sb.AppendLine("# Enumeration commands you MAY choose to run yourself. drederick does not execute them.");
        sb.AppendLine("# Lab/CTF authorized targets only. Exploitation, credential-spraying, and payload");
        sb.AppendLine("# delivery are intentionally absent.");
        sb.AppendLine();

        sb.AppendLine("## Credentials reuse");
        sb.AppendLine(OperatorBanner);
        sb.AppendLine("# Any credential you recover (from SMB, HTTP, SNMP, loot, etc.) should be");
        sb.AppendLine("# retested across every auth-accepting service on the host AND on peers in");
        sb.AppendLine("# scope. Common reuse surfaces: SMB, WinRM, SSH, RDP, MSSQL, MySQL, Postgres,");
        sb.AppendLine("# FTP, LDAP simple bind, web logins. Keep a single creds.txt and loop it back.");
        sb.AppendLine($"# Example (replace <user>/<pass>): nxc smb {target} -u <user> -p <pass>");
        sb.AppendLine($"#                                  nxc winrm {target} -u <user> -p <pass>");
        sb.AppendLine($"#                                  nxc ldap {target} -u <user> -p <pass>");
        sb.AppendLine($"#                                  nxc ssh {target} -u <user> -p <pass>");
        sb.AppendLine();

        var ports = h.Nmap?.OpenPorts ?? new List<NmapPort>();
        if (ports.Count == 0)
        {
            sb.AppendLine("## No open TCP services observed");
            sb.AppendLine(OperatorBanner);
            sb.AppendLine("# Full-range + UDP top-100 are worth a second pass before giving up:");
            sb.AppendLine($"nmap -Pn -p- -T4 --min-rate 1000 {target}");
            sb.AppendLine($"nmap -Pn -sU --top-ports 100 -T4 {target}");
            sb.AppendLine();
            AppendChecklist(sb);
            return sb.ToString();
        }

        var emitted = new HashSet<string>();
        foreach (var p in ports)
        {
            var svc = (p.Service ?? "").ToLowerInvariant();
            var kind = ClassifyService(p.Port, svc);

            sb.AppendLine($"## {p.Port}/{p.Protocol} {p.Service} {p.Product} {p.Version}".TrimEnd());
            sb.AppendLine(OperatorBanner);

            switch (kind)
            {
                case "smb":
                    if (emitted.Add("smb")) EmitSmb(sb, target);
                    else sb.AppendLine("# see the SMB block above (139/445 share the same commands).");
                    break;
                case "ldap":
                    EmitLdap(sb, target, p.Port, h);
                    break;
                case "kerberos":
                    EmitKerberos(sb, target);
                    break;
                case "http":
                    EmitHttp(sb, target, p.Port, useTls: false);
                    break;
                case "https":
                    EmitHttp(sb, target, p.Port, useTls: true);
                    EmitTlsReference(sb, h, p.Port);
                    break;
                case "ftp":
                    EmitFtp(sb, target);
                    break;
                case "ssh":
                    EmitSsh(sb, target, h);
                    break;
                case "mssql":
                    EmitMssql(sb, target);
                    break;
                case "winrm":
                    EmitWinrm(sb, target);
                    break;
                case "snmp":
                    EmitSnmp(sb, target);
                    break;
                case "rdp":
                    EmitRdp(sb, target);
                    break;
                case "nfs":
                    EmitNfs(sb, target);
                    break;
                case "mysql":
                    EmitMysql(sb, target);
                    break;
                case "postgresql":
                    EmitPostgres(sb, target);
                    break;
                case "redis":
                    EmitRedis(sb, target);
                    break;
                case "mongodb":
                    EmitMongo(sb, target);
                    break;
                case "vnc":
                    EmitVnc(sb, target);
                    break;
                case "smtp":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script smtp-commands,smtp-ntlm-info {target}");
                    break;
                case "dns":
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script dns-nsid,dns-recursion {target}");
                    sb.AppendLine($"dig @{target} version.bind chaos txt");
                    break;
                case "rpcbind":
                    sb.AppendLine($"rpcinfo -p {target}");
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script rpc-grind {target}");
                    break;
                default:
                    sb.AppendLine($"nmap -Pn -p {p.Port} --script safe,default,discovery,version {target}");
                    break;
            }
            sb.AppendLine();
        }

        AppendChecklist(sb);
        return sb.ToString();
    }

    private static string ClassifyService(int port, string svc)
    {
        switch (svc)
        {
            case "smb":
            case "microsoft-ds":
            case "netbios-ssn":
                return "smb";
            case "ldap":
            case "ldaps":
                return "ldap";
            case "kerberos":
            case "kerberos-sec":
                return "kerberos";
            case "http":
            case "http-proxy":
            case "http-alt":
                return "http";
            case "https":
            case "ssl/http":
            case "ssl/https":
                return "https";
            case "ftp":
                return "ftp";
            case "ssh":
                return "ssh";
            case "ms-sql-s":
            case "mssql":
                return "mssql";
            case "ms-wbt-server":
            case "rdp":
                return "rdp";
            case "snmp":
                return "snmp";
            case "nfs":
                return "nfs";
            case "mysql":
                return "mysql";
            case "postgresql":
                return "postgresql";
            case "redis":
                return "redis";
            case "mongodb":
                return "mongodb";
            case "vnc":
                return "vnc";
            case "smtp":
            case "submission":
                return "smtp";
            case "dns":
            case "domain":
                return "dns";
            case "rpcbind":
            case "sunrpc":
                return "rpcbind";
            case "wsman":
            case "winrm":
                return "winrm";
        }

        return port switch
        {
            139 or 445 => "smb",
            389 or 636 => "ldap",
            88 => "kerberos",
            80 or 8080 => "http",
            443 or 8443 => "https",
            21 => "ftp",
            22 => "ssh",
            1433 => "mssql",
            5985 or 5986 => "winrm",
            161 => "snmp",
            3389 => "rdp",
            2049 => "nfs",
            3306 => "mysql",
            5432 => "postgresql",
            6379 => "redis",
            27017 => "mongodb",
            5900 => "vnc",
            25 or 587 => "smtp",
            53 => "dns",
            111 => "rpcbind",
            _ => "other"
        };
    }

    private static void EmitSmb(StringBuilder sb, string target)
    {
        sb.AppendLine("# Null / guest / share enumeration. Credential-less checks only.");
        sb.AppendLine($"nxc smb {target} -u '' -p ''");
        sb.AppendLine($"nxc smb {target} -u 'guest' -p ''");
        sb.AppendLine($"nxc smb {target} --shares -u '' -p ''");
        sb.AppendLine($"smbclient -L //{target}/ -N");
        sb.AppendLine($"rpcclient -U \"\" -N {target}");
        sb.AppendLine($"enum4linux-ng -A {target}");
        sb.AppendLine("# SMB signing / relay-target discovery (operator reviews before using):");
        sb.AppendLine($"nxc smb {target} --gen-relay-list relay-targets.txt");
        sb.AppendLine("# Nmap safe SMB info scripts:");
        sb.AppendLine($"nmap -Pn -p 139,445 --script smb-os-discovery,smb-protocols,smb2-security-mode {target}");
    }

    private static void EmitLdap(StringBuilder sb, string target, int port, HostFinding h)
    {
        sb.AppendLine("# Anonymous LDAP enumeration. Start with RootDSE, then walk the base DN.");
        sb.AppendLine($"ldapsearch -x -H ldap://{target} -s base namingcontexts");
        sb.AppendLine($"ldapsearch -x -H ldap://{target} -b \"<BASE_DN>\" '(objectClass=*)'");
        sb.AppendLine($"nxc ldap {target} -u '' -p '' --asreproastable");
        sb.AppendLine("# Username enumeration via Kerberos pre-auth (replace <domain> and wordlist):");
        sb.AppendLine($"kerbrute userenum --dc {target} -d <domain> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt");

        var ldap = h.Ldap.FirstOrDefault(x => x.Port == port);
        if (ldap != null && ldap.NamingContexts.Count > 0)
        {
            sb.AppendLine("# drederick already enumerated naming contexts — see ldap.naming_contexts in report.json");
            sb.AppendLine("# for the full list before substituting <BASE_DN> above.");
        }
    }

    private static void EmitKerberos(StringBuilder sb, string target)
    {
        sb.AppendLine("# AS-REP candidate listing (requires usernames from LDAP/SMB/kerbrute step):");
        sb.AppendLine($"GetNPUsers.py <domain>/ -dc-ip {target} -usersfile users.txt -no-pass");
        sb.AppendLine("# SPN listing — REQUIRES creds obtained from another enum step first:");
        sb.AppendLine($"GetUserSPNs.py -dc-ip {target} <domain>/<user>:<pass> -request");
    }

    private static void EmitHttp(StringBuilder sb, string target, int port, bool useTls)
    {
        var scheme = useTls ? "https" : "http";
        var url = $"{scheme}://{target}:{port}";
        sb.AppendLine("# Fingerprint + headers:");
        sb.AppendLine($"whatweb {url}");
        sb.AppendLine($"curl -sI {url}");
        sb.AppendLine($"curl -sk -D - {url}/ -o /dev/null");
        sb.AppendLine($"curl -sk {url}/robots.txt");
        sb.AppendLine($"curl -sk {url}/sitemap.xml");
        sb.AppendLine("# Nmap HTTP info scripts (still enumeration-only):");
        sb.AppendLine($"nmap -Pn -p {port} --script http-title,http-headers,http-methods,http-enum {target}");
        sb.AppendLine("# Content discovery:");
        sb.AppendLine($"ffuf -u {url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,307,401,403");
        sb.AppendLine($"gobuster dir -u {url}/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt");
        sb.AppendLine("# Template-based misconfig / disclosure checks (not exploit-class):");
        sb.AppendLine($"nuclei -u {url} -t ~/nuclei-templates/http/ -severity medium,high,critical");
        sb.AppendLine("# Vhost discovery — replace <target_domain> and <size> once you have a baseline:");
        sb.AppendLine($"ffuf -H \"Host: FUZZ.<target_domain>\" -u {url} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <size>");

        if (useTls)
        {
            sb.AppendLine("# Cert + TLS detail:");
            sb.AppendLine($"openssl s_client -connect {target}:{port} -servername {target} </dev/null 2>/dev/null | openssl x509 -noout -text");
            sb.AppendLine($"nmap -Pn -p {port} --script ssl-cert,ssl-enum-ciphers {target}");
        }
    }

    private static void EmitTlsReference(StringBuilder sb, HostFinding h, int port)
    {
        if (h.TlsCipherEnum.Any(x => x.Port == port))
        {
            sb.AppendLine("# drederick already enumerated ciphers — see tls_cipher_enum in report.json");
            sb.AppendLine("# for the full per-version list before re-running ssl-enum-ciphers.");
        }
    }

    private static void EmitFtp(StringBuilder sb, string target)
    {
        sb.AppendLine("# Anonymous / banner checks:");
        sb.AppendLine($"nmap -sV -p 21 --script=ftp-anon {target}");
        sb.AppendLine($"curl -v ftp://{target}/ --user anonymous:anonymous@");
        sb.AppendLine("# Interactive anonymous session:");
        sb.AppendLine($"ftp -n {target}");
        sb.AppendLine("#   ftp> USER anonymous");
        sb.AppendLine("#   ftp> PASS anonymous@");
    }

    private static void EmitSsh(StringBuilder sb, string target, HostFinding h)
    {
        sb.AppendLine("# Banner + offered auth methods:");
        sb.AppendLine($"ssh -v -o StrictHostKeyChecking=no {target}");
        if (h.Ssh.Count > 0)
        {
            sb.AppendLine("# Algorithm enumeration already captured by drederick — see ssh.algorithms in");
            sb.AppendLine("# report.json (kex_algorithms, host_key_algorithms, encryption_algorithms,");
            sb.AppendLine("# mac_algorithms) for the full list instead of re-running ssh2-enum-algos.");
        }
        else
        {
            sb.AppendLine($"nmap -Pn -p 22 --script ssh2-enum-algos,ssh-hostkey {target}");
        }
    }

    private static void EmitMssql(StringBuilder sb, string target)
    {
        sb.AppendLine("# Credential checks — requires a <user>/<pass> from another enum step:");
        sb.AppendLine($"mssqlclient.py <user>:<pass>@{target} -windows-auth");
        sb.AppendLine("# Null auth probe (enumeration only):");
        sb.AppendLine($"nxc mssql {target} -u '' -p ''");
    }

    private static void EmitWinrm(StringBuilder sb, string target)
    {
        sb.AppendLine("# Credential check — replace <user>/<pass> once obtained via other enum:");
        sb.AppendLine($"nxc winrm {target} -u <user> -p <pass>");
        sb.AppendLine("# Interactive shell AFTER you already have working creds from another step:");
        sb.AppendLine($"# evil-winrm -i {target} -u <user> -p <pass>");
    }

    private static void EmitSnmp(StringBuilder sb, string target)
    {
        sb.AppendLine("# Community-string discovery + walk (public is a common default):");
        sb.AppendLine($"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt {target}");
        sb.AppendLine($"snmpwalk -v2c -c public {target}");
    }

    private static void EmitRdp(StringBuilder sb, string target)
    {
        sb.AppendLine("# Manual connect — no creds:");
        sb.AppendLine($"rdesktop {target}");
        sb.AppendLine("# With creds obtained from another enum step:");
        sb.AppendLine($"xfreerdp /v:{target} /u:<user> /p:<pass> /cert-ignore");
    }

    private static void EmitNfs(StringBuilder sb, string target)
    {
        sb.AppendLine($"showmount -e {target}");
        sb.AppendLine($"mount -t nfs {target}:/share /mnt/nfs -o nolock");
    }

    private static void EmitMysql(StringBuilder sb, string target)
    {
        sb.AppendLine("# Requires creds from another enum step:");
        sb.AppendLine($"mysql -h {target} -u root -p");
        sb.AppendLine("# NOTE: drederick intentionally excludes the 'brute' NSE category. The");
        sb.AppendLine("#       line below includes mysql-brute - the OPERATOR runs it only if");
        sb.AppendLine("#       in scope. drederick will not run it.");
        sb.AppendLine($"nmap -sV -p 3306 --script=mysql-empty-password,mysql-brute {target}");
    }

    private static void EmitPostgres(StringBuilder sb, string target)
    {
        sb.AppendLine($"psql -h {target} -U postgres -W");
    }

    private static void EmitRedis(StringBuilder sb, string target)
    {
        sb.AppendLine($"redis-cli -h {target}");
        sb.AppendLine("#   127.0.0.1:6379> INFO");
        sb.AppendLine("#   127.0.0.1:6379> KEYS *");
    }

    private static void EmitMongo(StringBuilder sb, string target)
    {
        sb.AppendLine($"mongo {target}:27017");
        sb.AppendLine("#   > show dbs");
    }

    private static void EmitVnc(StringBuilder sb, string target)
    {
        sb.AppendLine("# Manual connect:");
        sb.AppendLine($"vncviewer {target}");
    }

    private static void AppendChecklist(StringBuilder sb)
    {
        sb.AppendLine("## Next phase checklist");
        sb.AppendLine(OperatorBanner);
        sb.AppendLine("# [ ] Review report.json for service fingerprints");
        sb.AppendLine("# [ ] Run drederick serve -> open Datasette -> review CVEs + PoCs");
        sb.AppendLine("# [ ] Attempt null/guest/anonymous access on all services above");
        sb.AppendLine("# [ ] Enumerate web content if http ports open");
        sb.AppendLine("# [ ] Collect credentials and loop back to start of checklist");
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
