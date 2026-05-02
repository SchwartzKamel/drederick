namespace Drederick.Autopilot.ChainReasoner;

/// <summary>
/// Declarative recipe a <see cref="ChainReasoner"/> instantiates when its
/// <see cref="Requires"/> predicates are satisfied by <see cref="ChainFacts"/>.
/// Templates are pure data — no side-effects, no scope dereference, no
/// subprocess spawn. The reasoner ranks instantiations by
/// <c>geomean(step.confidence) * Impact - totalCost/1000</c>.
/// </summary>
public sealed record ChainTemplate
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public IReadOnlyList<string> Requires { get; init; } = Array.Empty<string>();
    public IReadOnlyList<AttackStep> Steps { get; init; } = Array.Empty<AttackStep>();
    public double Impact { get; init; } = 0.5;
    public string Description { get; init; } = "";
}

/// <summary>
/// Built-in, vendor-neutral chain templates. Each template is reproducible
/// and well-known in the offensive corpus; none of them executes anything by
/// itself — they describe the shape of a multi-stage operation that
/// downstream tools (which re-check scope) will perform.
/// </summary>
public static class BuiltInChainTemplates
{
    public static IReadOnlyList<ChainTemplate> All { get; } = new[]
    {
        // 1. Anonymous SMB → loot share → harvest creds from configs.
        new ChainTemplate
        {
            Id = "anon-smb-loot",
            Name = "Anonymous SMB share looting",
            Description = "Null-session enumerate shares, mirror reachable shares, grep for credentials in config files.",
            Impact = 0.55,
            Requires = new[] { "service.smb", "smb.anon-read=true" },
            Steps = new[]
            {
                new AttackStep { Name = "enumerate-shares", Tool = "smb", Args = "--null-session list", Requires = new[]{"service.smb"}, Produces = new[]{"smb.shares.listed"}, Confidence = 0.8, Cost = 30, Rationale = "Null session SMB listing succeeded in recon." },
                new AttackStep { Name = "mirror-readable", Tool = "smb", Args = "--mirror -R", Requires = new[]{"smb.shares.listed"}, Produces = new[]{"loot.files"}, Confidence = 0.7, Cost = 120, Rationale = "Mirror anonymous-readable shares to loot/." },
                new AttackStep { Name = "grep-secrets", Tool = "loot.scan", Args = "--patterns creds,keys", Requires = new[]{"loot.files"}, Produces = new[]{"cred.any"}, Confidence = 0.45, Cost = 40, Rationale = "Static credential extraction from looted files." },
            },
        },

        // 2. Kerberoast then BloodHound graph for path-to-DA.
        new ChainTemplate
        {
            Id = "kerberoast-bloodhound",
            Name = "Kerberoast → BloodHound path",
            Description = "Roast SPN tickets, crack offline, then map graph to Domain Admin.",
            Impact = 0.85,
            Requires = new[] { "service.kerberos", "kerberos.spns>0", "cred.any" },
            Steps = new[]
            {
                new AttackStep { Name = "kerberoast", Tool = "cred", Args = "kerberoast", Requires = new[]{"service.kerberos","kerberos.spns>0","cred.any"}, Produces = new[]{"hashes.tgs"}, Confidence = 0.7, Cost = 60, Rationale = "SPNs present + low-priv creds make AS-REQ for TGS feasible." },
                new AttackStep { Name = "crack-offline", Tool = "cred", Args = "hashcat -m 13100", Requires = new[]{"hashes.tgs"}, Produces = new[]{"cred.user.spn"}, Confidence = 0.4, Cost = 600, Rationale = "Offline crack of TGS hashes against rockyou+rules." },
                new AttackStep { Name = "bloodhound-collect", Tool = "ldap", Args = "bloodhound-python", Requires = new[]{"cred.any","service.ldap"}, Produces = new[]{"graph.collected"}, Confidence = 0.85, Cost = 90, Rationale = "Authenticated LDAP collection feeds BloodHound." },
                new AttackStep { Name = "find-path", Tool = "bloodhound", Args = "shortest-path-to-DA", Requires = new[]{"graph.collected"}, Produces = new[]{"path.to.da"}, Confidence = 0.55, Cost = 30, Rationale = "Graph search for unconstrained delegation / DA path." },
            },
        },

        // 3. Web RCE → local enum → priv-esc.
        new ChainTemplate
        {
            Id = "web-rce-priv-esc",
            Name = "Web RCE → local enum → privilege escalation",
            Description = "Land a webshell via known vuln, drop into a session, enumerate, escalate.",
            Impact = 0.75,
            Requires = new[] { "http.target" },
            Steps = new[]
            {
                new AttackStep { Name = "web-exploit", Tool = "exploit", Args = "auto-select-by-fingerprint", Requires = new[]{"http.target"}, Produces = new[]{"session.open=true"}, Confidence = 0.35, Cost = 200, Rationale = "Fingerprint match against PoC corpus; success only on known-vuln stack." },
                new AttackStep { Name = "post-enum", Tool = "postex", Args = "linpeas|winpeas", Requires = new[]{"session.open=true"}, Produces = new[]{"privesc.candidates"}, Confidence = 0.85, Cost = 60, Rationale = "Standard host enumeration once session is live." },
                new AttackStep { Name = "priv-esc", Tool = "exploit", Args = "auto-select-local", Requires = new[]{"privesc.candidates"}, Produces = new[]{"session.elevated"}, Confidence = 0.4, Cost = 180, Rationale = "Run the highest-confidence local privesc candidate." },
            },
        },

        // 4. Pass-the-Hash on WinRM → domain pivot.
        new ChainTemplate
        {
            Id = "winrm-pth-domain",
            Name = "WinRM pass-the-hash → domain pivot",
            Description = "Reuse captured NTLM against WinRM endpoints; pivot via the resulting session.",
            Impact = 0.7,
            Requires = new[] { "service.winrm", "cred.any" },
            Steps = new[]
            {
                new AttackStep { Name = "spray-pth", Tool = "cred", Args = "netexec winrm --ntlm", Requires = new[]{"service.winrm","cred.any"}, Produces = new[]{"session.open=true"}, Confidence = 0.5, Cost = 90, Rationale = "PtH against WinRM with captured hashes." },
                new AttackStep { Name = "domain-collect", Tool = "ldap", Args = "bloodhound-python --hashes", Requires = new[]{"session.open=true"}, Produces = new[]{"graph.collected"}, Confidence = 0.8, Cost = 90, Rationale = "Authenticated AD collection from pivot session." },
                new AttackStep { Name = "pivot-laterally", Tool = "postex", Args = "wmiexec / psexec", Requires = new[]{"graph.collected"}, Produces = new[]{"session.lateral"}, Confidence = 0.45, Cost = 120, Rationale = "Lateral movement to next high-value host." },
            },
        },

        // 5. MySQL UDF privilege escalation.
        new ChainTemplate
        {
            Id = "mysql-udf-priv-esc",
            Name = "MySQL UDF privilege escalation",
            Description = "Write user-defined function to plugin dir, hijack mysqld for code exec.",
            Impact = 0.65,
            Requires = new[] { "service.mysql", "cred.any" },
            Steps = new[]
            {
                new AttackStep { Name = "auth-mysql", Tool = "cred", Args = "mysql --login", Requires = new[]{"service.mysql","cred.any"}, Produces = new[]{"db.session"}, Confidence = 0.55, Cost = 40, Rationale = "Authenticate to MySQL with known cred." },
                new AttackStep { Name = "drop-udf", Tool = "exploit", Args = "udf raptor", Requires = new[]{"db.session"}, Produces = new[]{"udf.installed"}, Confidence = 0.4, Cost = 120, Rationale = "Write malicious .so/.dll into plugin directory." },
                new AttackStep { Name = "exec-as-root", Tool = "exploit", Args = "select sys_exec()", Requires = new[]{"udf.installed"}, Produces = new[]{"session.open=true"}, Confidence = 0.6, Cost = 30, Rationale = "Trigger UDF; mysqld typically runs root in CTF lab images." },
            },
        },

        // 6. FTP upload → webshell when FTP root maps to webroot.
        new ChainTemplate
        {
            Id = "ftp-upload-shell",
            Name = "Anonymous FTP → webshell drop",
            Description = "Upload webshell over anon FTP into HTTP-served path.",
            Impact = 0.6,
            Requires = new[] { "ftp.anon=true", "http.target" },
            Steps = new[]
            {
                new AttackStep { Name = "ftp-write-probe", Tool = "ftp", Args = "anonymous put-test", Requires = new[]{"ftp.anon=true"}, Produces = new[]{"ftp.write=true"}, Confidence = 0.45, Cost = 30, Rationale = "Some anon-readable FTPs also allow write." },
                new AttackStep { Name = "drop-webshell", Tool = "exploit", Args = "ftp put webshell", Requires = new[]{"ftp.write=true","http.target"}, Produces = new[]{"webshell.deployed"}, Confidence = 0.5, Cost = 30, Rationale = "FTP root often maps to webroot in misconfigured stacks." },
                new AttackStep { Name = "trigger-shell", Tool = "exploit", Args = "GET /shell.php?cmd=id", Requires = new[]{"webshell.deployed"}, Produces = new[]{"session.open=true"}, Confidence = 0.7, Cost = 20, Rationale = "Touch the webshell to spawn an interactive session." },
            },
        },

        // 7. SNMP community 'public' → Cisco enable secret extraction.
        new ChainTemplate
        {
            Id = "snmp-cisco-secret",
            Name = "SNMP RW → Cisco config dump",
            Description = "Use writable SNMP community to TFTP the running-config and crack the enable secret.",
            Impact = 0.5,
            Requires = new[] { "snmp.community.public" },
            Steps = new[]
            {
                new AttackStep { Name = "snmp-walk", Tool = "snmp", Args = "walk -c public", Requires = new[]{"snmp.community.public"}, Produces = new[]{"snmp.dump"}, Confidence = 0.85, Cost = 30, Rationale = "Confirmed reachability with default community." },
                new AttackStep { Name = "config-pull", Tool = "snmp", Args = "tftp-config-pull", Requires = new[]{"snmp.dump"}, Produces = new[]{"loot.config"}, Confidence = 0.35, Cost = 60, Rationale = "RW community required for TFTP-pull; fail-fast otherwise." },
                new AttackStep { Name = "crack-secret", Tool = "cred", Args = "hashcat -m 500", Requires = new[]{"loot.config"}, Produces = new[]{"cred.any"}, Confidence = 0.45, Cost = 600, Rationale = "Crack Cisco type-5 enable-secret offline." },
            },
        },

        // 8. LDAP anon → AS-REP roast preauth-disabled accounts.
        new ChainTemplate
        {
            Id = "ldap-asrep-roast",
            Name = "LDAP anon → AS-REP roast",
            Description = "Enumerate users via anonymous LDAP, request AS-REPs for accounts with preauth disabled.",
            Impact = 0.7,
            Requires = new[] { "ldap.anon-bind=true", "service.kerberos" },
            Steps = new[]
            {
                new AttackStep { Name = "ldap-userenum", Tool = "ldap", Args = "anon enum users", Requires = new[]{"ldap.anon-bind=true"}, Produces = new[]{"users.list"}, Confidence = 0.85, Cost = 30, Rationale = "Anonymous LDAP returns the user list on permissive AD." },
                new AttackStep { Name = "asrep-roast", Tool = "cred", Args = "GetNPUsers", Requires = new[]{"users.list","service.kerberos"}, Produces = new[]{"hashes.asrep"}, Confidence = 0.35, Cost = 60, Rationale = "Hits accounts with DONT_REQ_PREAUTH; rate is corpus-dependent." },
                new AttackStep { Name = "crack-asrep", Tool = "cred", Args = "hashcat -m 18200", Requires = new[]{"hashes.asrep"}, Produces = new[]{"cred.user.asrep"}, Confidence = 0.4, Cost = 600, Rationale = "Crack AS-REP hashes offline." },
            },
        },
    };
}
