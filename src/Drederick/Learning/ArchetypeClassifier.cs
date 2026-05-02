using Drederick.Autopilot;
using Drederick.Recon;

namespace Drederick.Learning;

/// <summary>
/// Result of <see cref="ArchetypeClassifier.Classify"/>. <see cref="Primary"/>
/// is the highest-scoring archetype for the host. <see cref="Secondary"/> is
/// the runner-up (may be <c>null</c>). <see cref="Confidence"/> is
/// <c>matched / total</c> for the primary archetype's positive checks,
/// capped at <c>0.95</c>. <see cref="Signals"/> lists the human-readable
/// evidence strings for the primary (and secondary, if present).
/// </summary>
public sealed record ArchetypeClassification(
    TargetArchetype Primary,
    TargetArchetype? Secondary,
    double Confidence,
    IReadOnlyList<string> Signals);

/// <summary>
/// Pure, stateless classifier that maps an already-collected
/// <see cref="HostFinding"/> to a <see cref="TargetArchetype"/>. No scope
/// calls — operates on previously gathered evidence only. Intended for
/// downstream planner / LLM-prompt routing and corpus replay.
/// </summary>
public sealed class ArchetypeClassifier
{
    private const double ConfidenceCap = 0.95;

    public ArchetypeClassification Classify(HostFinding host)
    {
        ArgumentNullException.ThrowIfNull(host);

        var ports = ExploitationPlanner.HarvestPortsFromAllSignals(host)
            .Select(p => p.Port)
            .ToHashSet();

        var httpServers = host.Http
            .Select(h => h.Server ?? string.Empty)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToList();
        var sshBanners = host.Ssh
            .Select(s => s.Banner ?? string.Empty)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToList();
        var smbOs = host.Smb
            .Select(s => s.Os ?? string.Empty)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToList();

        bool smbVisible = host.Smb.Count > 0
            || ports.Contains(445)
            || ports.Contains(139);

        bool hasMsHttpApi = httpServers.Any(s => s.Contains("Microsoft-HTTPAPI", StringComparison.OrdinalIgnoreCase));
        bool hasWinRm = ports.Contains(5985) || ports.Contains(5986);
        bool hasOpenSsh = sshBanners.Any(b => b.Contains("OpenSSH", StringComparison.OrdinalIgnoreCase));

        bool hasAdAuthPort = ports.Contains(88) || ports.Contains(389)
            || ports.Contains(636) || ports.Contains(3268) || ports.Contains(3269);
        bool kerbRealm = host.Kerberos.Any(k => !string.IsNullOrEmpty(k.Realm));

        var scores = new Dictionary<TargetArchetype, (int matched, int total, List<string> signals)>();

        // --- WindowsAdEdge (JobTwo r4 shape) -------------------------
        Score(scores, TargetArchetype.WindowsAdEdge,
            gate: !smbVisible && (hasMsHttpApi || hasWinRm),
            (hasMsHttpApi, "Microsoft-HTTPAPI in HTTP Server header"),
            (hasWinRm, "WinRM port (5985/5986) open"),
            (ports.Contains(80) && ports.Contains(443), "HTTP+HTTPS dual stack"),
            (host.Tls.Count >= 2, "multiple TLS-bearing ports"));

        // --- WindowsDcCandidate --------------------------------------
        Score(scores, TargetArchetype.WindowsDcCandidate,
            gate: kerbRealm || (hasAdAuthPort && ports.Contains(445)),
            (ports.Contains(88), "Kerberos port 88"),
            (ports.Contains(389) || ports.Contains(636), "LDAP / LDAPS port"),
            (ports.Contains(445), "SMB port 445"),
            (ports.Contains(3268) || ports.Contains(3269), "Global Catalog port"),
            (kerbRealm, "Kerberos realm advertised"),
            (host.Ldap.Any(l => l.NamingContexts.Count > 0), "LDAP naming contexts present"));

        // --- LinuxClassic (Lame shape: Samba + OpenSSH + FTP) --------
        bool sambaUnixOs = smbOs.Any(s =>
            s.Contains("Unix", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Samba", StringComparison.OrdinalIgnoreCase));
        Score(scores, TargetArchetype.LinuxClassic,
            gate: sambaUnixOs || (smbVisible && hasOpenSsh),
            (sambaUnixOs, "Samba/Unix SMB OS string"),
            (hasOpenSsh, "OpenSSH banner"),
            (host.Ftp.Count > 0 || ports.Contains(21), "FTP service visible"),
            (ports.Contains(139) && ports.Contains(445), "SMB ports 139+445"),
            (ports.Contains(22), "SSH port 22"));

        // --- LinuxModern ---------------------------------------------
        bool modernHttpServer = httpServers.Any(s =>
            s.Contains("nginx", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Apache", StringComparison.OrdinalIgnoreCase)
            || s.Contains("gunicorn", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Caddy", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Werkzeug", StringComparison.OrdinalIgnoreCase));
        Score(scores, TargetArchetype.LinuxModern,
            gate: !smbVisible && (hasOpenSsh || modernHttpServer),
            (hasOpenSsh, "OpenSSH banner"),
            (modernHttpServer, "modern HTTP server (nginx/Apache/gunicorn/…)"),
            (ports.Contains(22), "SSH port 22"),
            (host.Ftp.Count == 0, "no FTP visible"));

        // --- WindowsWorkstation --------------------------------------
        bool windowsSmbOs = smbOs.Any(s => s.Contains("Windows", StringComparison.OrdinalIgnoreCase));
        Score(scores, TargetArchetype.WindowsWorkstation,
            gate: windowsSmbOs && !hasAdAuthPort,
            (windowsSmbOs, "Windows SMB OS string"),
            (ports.Contains(445), "SMB port 445"),
            (ports.Contains(135), "RPC endpoint mapper"),
            (!hasAdAuthPort, "no AD auth ports (not DC)"));

        // --- NetworkAppliance ----------------------------------------
        bool applianceBanner = httpServers.Any(s =>
            s.Contains("RouterOS", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Cisco", StringComparison.OrdinalIgnoreCase)
            || s.Contains("MikroTik", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Juniper", StringComparison.OrdinalIgnoreCase));
        bool snmpReachable = host.Snmp.Any(s => s.Reachable);
        Score(scores, TargetArchetype.NetworkAppliance,
            gate: snmpReachable || applianceBanner || (ports.Contains(23) && ports.Contains(161)),
            (snmpReachable, "SNMP reachable"),
            (ports.Contains(23), "telnet (23) open"),
            (ports.Contains(161), "SNMP port 161"),
            (applianceBanner, "appliance HTTP banner"));

        // --- WebStack ------------------------------------------------
        bool onlyHttpish = host.Smb.Count == 0
            && host.Ssh.Count == 0
            && host.Ftp.Count == 0
            && host.Snmp.Count == 0
            && host.Ldap.Count == 0
            && host.Kerberos.Count == 0
            && host.Rpc.Count == 0
            && (host.Http.Count > 0 || host.Tls.Count > 0);
        var webPorts = new[] { 80, 443, 8080, 8443, 8000, 8888, 3000, 5000 };
        bool webPortsOnly = ports.Count > 0 && ports.All(p => webPorts.Contains(p));
        Score(scores, TargetArchetype.WebStack,
            gate: onlyHttpish && !hasMsHttpApi && !hasWinRm,
            (host.Http.Count > 0, "HTTP probes succeeded"),
            (host.Tls.Count > 0, "TLS probes succeeded"),
            (webPortsOnly, "ports limited to web range"));

        // --- MailServer ----------------------------------------------
        var mailPorts = new[] { 25, 110, 143, 465, 587, 993, 995 };
        int mailHits = mailPorts.Count(p => ports.Contains(p));
        Score(scores, TargetArchetype.MailServer,
            gate: mailHits >= 1,
            (ports.Contains(25), "SMTP port 25"),
            (ports.Contains(110) || ports.Contains(995), "POP3 / POP3S"),
            (ports.Contains(143) || ports.Contains(993), "IMAP / IMAPS"),
            (ports.Contains(587) || ports.Contains(465), "submission / SMTPS"),
            (mailHits >= 2, "multiple mail ports"));

        // --- DbServer ------------------------------------------------
        var dbPorts = new[] { 1433, 1521, 3306, 5432, 6379, 27017, 5984, 9200 };
        bool anyDbPort = dbPorts.Any(p => ports.Contains(p));
        Score(scores, TargetArchetype.DbServer,
            gate: anyDbPort,
            (ports.Contains(3306), "MySQL"),
            (ports.Contains(5432), "PostgreSQL"),
            (ports.Contains(1433), "MSSQL"),
            (ports.Contains(1521), "Oracle"),
            (ports.Contains(27017), "MongoDB"),
            (ports.Contains(6379), "Redis"),
            (ports.Contains(9200), "Elasticsearch"));

        // --- IotEmbedded ---------------------------------------------
        bool embeddedSshBanner = sshBanners.Any(b =>
            b.Contains("Dropbear", StringComparison.OrdinalIgnoreCase)
            || b.Contains("BusyBox", StringComparison.OrdinalIgnoreCase));
        bool embeddedHttpBanner = httpServers.Any(s =>
            s.Contains("lighttpd", StringComparison.OrdinalIgnoreCase)
            || s.Contains("GoAhead", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Boa", StringComparison.OrdinalIgnoreCase)
            || s.Contains("mini_httpd", StringComparison.OrdinalIgnoreCase));
        Score(scores, TargetArchetype.IotEmbedded,
            gate: embeddedSshBanner || embeddedHttpBanner || ports.Contains(2323),
            (embeddedSshBanner, "embedded SSH banner (Dropbear/BusyBox)"),
            (embeddedHttpBanner, "embedded HTTP server (lighttpd/GoAhead/…)"),
            (ports.Contains(23) || ports.Contains(2323), "telnet exposed"));

        // --- Honeypot ------------------------------------------------
        bool tooManyPorts = ports.Count > 25;
        bool extremePorts = ports.Count > 50;
        bool contradictoryOs = smbOs.Any(s => s.Contains("Windows", StringComparison.OrdinalIgnoreCase))
            && smbOs.Any(s => s.Contains("Unix", StringComparison.OrdinalIgnoreCase));
        Score(scores, TargetArchetype.Honeypot,
            gate: tooManyPorts || contradictoryOs,
            (tooManyPorts, $"unusually many ports open ({ports.Count})"),
            (extremePorts, ">50 ports open (extreme)"),
            (contradictoryOs, "contradictory OS banners (Windows + Unix on SMB)"));

        var ranked = scores
            .Where(kv => kv.Value.matched > 0 && kv.Value.total > 0)
            .OrderByDescending(kv => (double)kv.Value.matched / kv.Value.total)
            .ThenByDescending(kv => kv.Value.matched)
            .ToList();

        if (ranked.Count == 0)
        {
            return new ArchetypeClassification(
                TargetArchetype.Unknown, null, 0.0, Array.Empty<string>());
        }

        var top = ranked[0];
        var primaryRatio = (double)top.Value.matched / top.Value.total;
        var confidence = Math.Min(ConfidenceCap, primaryRatio);

        TargetArchetype? secondary = ranked.Count > 1 ? ranked[1].Key : null;
        var signals = new List<string>(top.Value.signals);
        if (ranked.Count > 1)
        {
            signals.AddRange(ranked[1].Value.signals);
        }

        return new ArchetypeClassification(top.Key, secondary, confidence, signals);
    }

    private static void Score(
        Dictionary<TargetArchetype, (int matched, int total, List<string> signals)> scores,
        TargetArchetype arch,
        bool gate,
        params (bool matched, string desc)[] checks)
    {
        if (!gate || checks.Length == 0)
        {
            scores[arch] = (0, checks.Length, new List<string>());
            return;
        }

        var sigs = checks
            .Where(c => c.matched)
            .Select(c => $"{arch}: {c.desc}")
            .ToList();
        scores[arch] = (sigs.Count, checks.Length, sigs);
    }
}
