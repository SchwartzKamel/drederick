using System.Collections.Concurrent;
using System.ComponentModel;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Orchestrates the four recon tools behind a small, LLM-friendly surface.
/// Maintains a per-run <see cref="HostFinding"/> table and enforces per-target
/// per-tool budgets so a runaway agent cannot re-scan the same host forever.
/// </summary>
public sealed class ReconToolbox
{
    private readonly NmapTool _nmap;
    private readonly HttpProbeTool _http;
    private readonly TlsProbeTool _tls;
    private readonly DnsProbeTool _dns;
    private readonly SmbTool? _smb;
    private readonly FtpTool? _ftp;
    private readonly SshTool? _ssh;
    private readonly SnmpTool? _snmp;
    private readonly LdapTool? _ldap;
    private readonly RpcTool? _rpc;
    private readonly KerberosTool? _kerberos;
    private readonly DnsZoneTransferTool? _dnsAxfr;
    private readonly HttpContentDiscoveryTool? _httpContentDiscovery;
    private readonly TlsCipherEnumTool? _tlsCipherEnum;
    private readonly NativeScannerTool? _nativeScanner;
    private readonly NativeDnsTool? _nativeDns;
    private readonly Drederick.Enrichment.FingerprintStack.FingerprintStackTool? _fingerprintStack;
    private readonly S3MinioProbeTool? _s3;
    private readonly CmsFingerprintTool? _cmsFingerprint;
    private readonly Drederick.Recon.Ad.SmbNullSessionTool? _smbNullSession;
    // --- htb-smtp-enum ---
    private readonly SmtpEnumTool? _smtpEnum;
    // --- end htb-smtp-enum ---

    // --- htb-nfs-enum --- (GAP-007)
    [Description("Enumerate NFS exports against a target on port 2049 / mountd RPC. " +
                 "Lists exports via 'showmount -e', attempts a read-only mount at NFSv3 " +
                 "(falling back to NFSv4), walks up to two directory levels, captures " +
                 "uid/gid metadata, flags well-known sensitive files (id_rsa, *.kdbx, " +
                 "*.env, wp-config.php, …), detects no_root_squash exports, and in lab " +
                 "mode probes for anonymous write. Always unmounts cleanly.")]
    public async Task<string> EnumerateNfsAsync(
        [Description("Target IP or hostname (must be in scope).")] string target,
        CancellationToken ct = default)
    {
        var tool = _nfsEnum ?? throw new InvalidOperationException("NfsEnumTool is not registered.");
        Charge(target, "nfs-enum");
        var r = await tool.EnumerateAsync(target, ct).ConfigureAwait(false);
        GetOrCreate(target).NfsEnum.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }
    // --- end htb-nfs-enum ---

    // --- htb-nfs-enum ---
    private readonly NfsEnumTool? _nfsEnum;
    // --- end htb-nfs-enum ---
    // --- htb-ssl-cert-hosts ---
    private readonly SslCertHostsTool? _sslCertHosts;
    // --- end htb-ssl-cert-hosts ---
    // --- htb-locale-lfi-probe ---
    private readonly Drederick.Recon.Http.LocaleLfiProbe? _localeLfi;
    // --- end htb-locale-lfi-probe ---
    // --- htb-cloud-storage-enum --- (GAP-018)
    private readonly CloudStorageEnumTool? _cloudStorage;
    // --- end htb-cloud-storage-enum ---
    private readonly IReadOnlyCollection<IReconTool> _tools;
    private readonly AuditLog _audit;
    private readonly ConcurrentDictionary<string, HostFinding> _findings = new();
    private readonly ConcurrentDictionary<(string target, string tool), int> _calls = new();
    private int _toolCallsTotal;

    public ReconToolbox(
        IEnumerable<IReconTool> tools,
        AuditLog audit,
        ToolBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(tools);
        var materialized = tools.ToList();

        _nmap = materialized.OfType<NmapTool>().SingleOrDefault()
            ?? throw new ArgumentException(
                $"{nameof(ReconToolbox)} requires exactly one {nameof(NmapTool)}.", nameof(tools));
        _http = materialized.OfType<HttpProbeTool>().SingleOrDefault()
            ?? throw new ArgumentException(
                $"{nameof(ReconToolbox)} requires exactly one {nameof(HttpProbeTool)}.", nameof(tools));
        _tls = materialized.OfType<TlsProbeTool>().SingleOrDefault()
            ?? throw new ArgumentException(
                $"{nameof(ReconToolbox)} requires exactly one {nameof(TlsProbeTool)}.", nameof(tools));
        _dns = materialized.OfType<DnsProbeTool>().SingleOrDefault()
            ?? throw new ArgumentException(
                $"{nameof(ReconToolbox)} requires exactly one {nameof(DnsProbeTool)}.", nameof(tools));

        // New scanners are optional so the legacy 4-tool positional constructor
        // (and any tests constructed against the original surface) continues to
        // work. Methods that require a missing scanner throw
        // InvalidOperationException at call time.
        _smb = materialized.OfType<SmbTool>().SingleOrDefault();
        _ftp = materialized.OfType<FtpTool>().SingleOrDefault();
        _ssh = materialized.OfType<SshTool>().SingleOrDefault();
        _snmp = materialized.OfType<SnmpTool>().SingleOrDefault();
        _ldap = materialized.OfType<LdapTool>().SingleOrDefault();
        _rpc = materialized.OfType<RpcTool>().SingleOrDefault();
        _kerberos = materialized.OfType<KerberosTool>().SingleOrDefault();
        _dnsAxfr = materialized.OfType<DnsZoneTransferTool>().SingleOrDefault();
        _httpContentDiscovery = materialized.OfType<HttpContentDiscoveryTool>().SingleOrDefault();
        _tlsCipherEnum = materialized.OfType<TlsCipherEnumTool>().SingleOrDefault();
        _nativeScanner = materialized.OfType<NativeScannerTool>().SingleOrDefault();
        _nativeDns = materialized.OfType<NativeDnsTool>().SingleOrDefault();
        _fingerprintStack = materialized.OfType<Drederick.Enrichment.FingerprintStack.FingerprintStackTool>().SingleOrDefault();
        _s3 = materialized.OfType<S3MinioProbeTool>().SingleOrDefault();
        _cmsFingerprint = materialized.OfType<CmsFingerprintTool>().SingleOrDefault();
        _smbNullSession = materialized.OfType<Drederick.Recon.Ad.SmbNullSessionTool>().SingleOrDefault();
        // --- htb-smtp-enum ---
        _smtpEnum = materialized.OfType<SmtpEnumTool>().SingleOrDefault();
        // --- end htb-smtp-enum ---
        // --- htb-nfs-enum ---
        _nfsEnum = materialized.OfType<NfsEnumTool>().SingleOrDefault();
        // --- end htb-nfs-enum ---
        // --- htb-ssl-cert-hosts ---
        _sslCertHosts = materialized.OfType<SslCertHostsTool>().SingleOrDefault();
        // --- end htb-ssl-cert-hosts ---
        // --- htb-locale-lfi-probe ---
        _localeLfi = materialized.OfType<Drederick.Recon.Http.LocaleLfiProbe>().SingleOrDefault();
        // --- end htb-locale-lfi-probe ---
        // --- htb-cloud-storage-enum --- (GAP-018)
        _cloudStorage = materialized.OfType<CloudStorageEnumTool>().SingleOrDefault();
        // --- end htb-cloud-storage-enum ---

        _tools = materialized;
        _audit = audit;
        Budget = budget ?? ToolBudget.Default;
    }

    /// <summary>
    /// Back-compat constructor preserving the original positional 4-scanner
    /// signature so existing callers (Program.cs, tests) do not have to
    /// change. New code should prefer the <see cref="IEnumerable{IReconTool}"/>
    /// overload to support dynamically registered scanners.
    /// </summary>
    public ReconToolbox(
        NmapTool nmap,
        HttpProbeTool http,
        TlsProbeTool tls,
        DnsProbeTool dns,
        AuditLog audit,
        ToolBudget? budget = null)
        : this(new IReconTool[] { nmap, http, tls, dns }, audit, budget)
    {
    }

    /// <summary>All registered recon tools, in registration order. Exposed so
    /// the LLM runner can enumerate tool metadata (<see cref="IReconTool.Name"/>,
    /// <see cref="IReconTool.Description"/>) without hard-coding the set.</summary>
    public IReadOnlyList<IReconTool> Tools => (IReadOnlyList<IReconTool>)_tools;

    public ToolBudget Budget { get; }

    public IReadOnlyDictionary<string, HostFinding> Findings => _findings;

    public int ToolCallsTotal => _toolCallsTotal;

    /// <summary>
    /// Optional progress sink. When set, every tool invocation emits a single
    /// line like <c>[+] nmap 10.10.10.5</c> or <c>[+] http 10.10.10.5:80</c>.
    /// Wire it to <see cref="Console.Error"/> from the CLI (unless --quiet)
    /// so operators see live activity during long scans.
    /// </summary>
    public TextWriter? Progress { get; set; }

    private HostFinding GetOrCreate(string target) =>
        _findings.GetOrAdd(target, t => new HostFinding
        {
            Target = t,
            Started = DateTimeOffset.UtcNow.ToString("o"),
        });

    private void Charge(string target, string tool)
    {
        var count = _calls.AddOrUpdate((target, tool), 1, (_, c) => c + 1);
        Interlocked.Increment(ref _toolCallsTotal);
        var perToolCap = Budget.CapFor(tool);
        if (count > perToolCap)
        {
            _audit.Record("budget.deny", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["tool"] = tool,
                ["count"] = count,
                ["cap"] = perToolCap,
                ["scope"] = "per-tool",
            });
            throw new InvalidOperationException(
                $"Budget exceeded: {tool} called {count} times on {target} (cap {perToolCap}).");
        }
        if (_toolCallsTotal > Budget.MaxTotalCalls)
        {
            _audit.Record("budget.deny", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["tool"] = tool,
                ["count"] = _toolCallsTotal,
                ["cap"] = Budget.MaxTotalCalls,
                ["scope"] = "global",
            });
            throw new InvalidOperationException(
                $"Total tool-call budget exceeded: {_toolCallsTotal} > {Budget.MaxTotalCalls}.");
        }
        EmitProgress(target, tool, port: null);
    }

    private void EmitProgress(string target, string tool, int? port)
    {
        var writer = Progress;
        if (writer is null) return;
        try
        {
            var where = port is > 0 ? $"{target}:{port}" : target;
            writer.WriteLine($"[+] {tool,-22} {where}");
            writer.Flush();
        }
        catch { /* progress is best-effort; never fail a scan on stderr hiccup */ }
    }

    // --- Public tool surface (string in / string out for LLM ergonomics) ---

    [Description("Run nmap service/version scan with safe NSE scripts against a single target IP. " +
                 "Returns a JSON summary of open TCP ports and detected services. " +
                 "The target MUST be inside the authorized scope.")]
    public async Task<string> NmapScanAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("Optional port spec, e.g. '1-65535' or '80,443'. Omit for top-1000.")] string? ports,
        CancellationToken ct = default)
    {
        Charge(target, "nmap");
        var r = await _nmap.ScanAsync(target, ports, ct).ConfigureAwait(false);
        var f = GetOrCreate(target);
        f.Nmap = r;
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Fetch an HTTP(S) response from a single port and return status, title, server, " +
                 "and which common security headers are missing. Accepts hostname OR IP targets — " +
                 "hostname is resolved via DNS and the resolved IP must pass scope; the hostname " +
                 "is sent in the Host header (and SNI for HTTPS) so vhost-routed apps return their " +
                 "real content. On a 3xx → Location with a hostname, sets vhost_required + " +
                 "vhost_hostname so you can retry with the hostname as the target.")]
    public async Task<string> HttpProbeAsync(
        [Description("Target IP or hostname (must resolve to an in-scope IP).")] string target,
        [Description("TCP port number.")] int port,
        [Description("Use TLS (https) if true.")] bool useTls,
        CancellationToken ct = default)
    {
        Charge(target, "http");
        var r = await _http.ProbeAsync(target, port, useTls, ct).ConfigureAwait(false);
        GetOrCreate(target).Http.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe a target for an S3-compatible / MinIO service. Detects via " +
                 "MinIO health endpoint, Server header, anonymous bucket listing, and " +
                 "AccessDenied error fingerprint. When AWS-style credentials with " +
                 "realm='s3' are present in the credential store, also lists buckets and " +
                 "object metadata. Read-only metadata only — never downloads payloads.")]
    public async Task<string> S3ProbeAsync(
        [Description("Target IP or hostname (must resolve to an in-scope IP).")] string target,
        [Description("TCP port (MinIO default 9000; AWS S3 typically 443).")] int port = 9000,
        CancellationToken ct = default)
    {
        if (_s3 is null) throw new InvalidOperationException("S3MinioProbeTool not registered.");
        Charge(target, "s3");
        var r = await _s3.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).S3.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Identify the CMS / web framework running on a target. Embedded fingerprint corpus matches " +
                 "CameleonCMS, WordPress, Drupal, Joomla, Magento, Ghost, TYPO3, SilverStripe, MediaWiki, " +
                 "phpBB, SuiteCRM, ManageEngine via cookies, meta generator tags, response headers, HTML " +
                 "patterns, and path probes. Returns ranked matches with version where extractable. Run " +
                 "before exploitation planning to unlock CMS-specific chains.")]
    public async Task<string> CmsFingerprintAsync(
        [Description("Target IP or hostname (must resolve to an in-scope IP).")] string target,
        [Description("TCP port (default 80).")] int port = 80,
        [Description("Use TLS (https) if true.")] bool tls = false,
        [Description("Optional Host header / vhost (gap-032 pattern).")] string? hostname = null,
        CancellationToken ct = default)
    {
        if (_cmsFingerprint is null) throw new InvalidOperationException("CmsFingerprintTool not registered.");
        Charge(target, "cms-fingerprint");
        var r = await _cmsFingerprint.FingerprintAsync(target, port, tls, hostname, ct).ConfigureAwait(false);
        GetOrCreate(target).CmsFingerprint.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Anonymous SMB + LDAP enumeration against an AD-shaped target. Probes 445 for SMB2 " +
                 "negotiate, attempts a null-session IPC$ tree-connect, enumerates shares (skipping " +
                 "ADMIN$/IPC$/C$ unless includeAdminShares is true), RID-cycles 500-1100 by default, " +
                 "runs SAMR EnumDomainUsers, and pulls naming contexts + a (samAccountName=*) user list " +
                 "via anonymous LDAP bind on 389. Credential-free; run first on any AD-shaped box " +
                 "(445/389/88 open) — output feeds AS-REP roasting, kerberoasting, and password spray.")]
    public async Task<string> SmbNullSessionAsync(
        [Description("Target IP or hostname (must resolve to an in-scope IP).")] string target,
        [Description("RID cycle start (default 500).")] int ridStart = 500,
        [Description("RID cycle end (default 1100, hard-capped at start+1000).")] int ridEnd = 1100,
        [Description("Include ADMIN$/IPC$/C$ in the share list (default false).")] bool includeAdminShares = false,
        CancellationToken ct = default)
    {
        if (_smbNullSession is null) throw new InvalidOperationException("SmbNullSessionTool not registered.");
        Charge(target, "smb-null-session");
        var r = await _smbNullSession.EnumerateAsync(target, ridStart, ridEnd, includeAdminShares, ct).ConfigureAwait(false);
        GetOrCreate(target).SmbNullSession.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Complete a TLS handshake and return the peer certificate subject, SAN, issuer, and expiry.")]
    public async Task<string> TlsProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number.")] int port,
        CancellationToken ct = default)
    {
        Charge(target, "tls");
        var r = await _tls.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Tls.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Forward and reverse DNS lookup for a target. Returns a JSON summary.")]
    public async Task<string> DnsProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        CancellationToken ct = default)
    {
        Charge(target, "dns");
        var r = await _dns.ProbeAsync(target, ct).ConfigureAwait(false);
        GetOrCreate(target).Dns = r;
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe SMB on 139/445 using nmap's safe discovery scripts and, when available, " +
                 "enum4linux-ng with read-only flags. Returns advertised dialects, OS/computer " +
                 "identity, signing posture, and (anonymously-listable) shares. Never authenticates.")]
    public async Task<string> SmbProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        CancellationToken ct = default)
    {
        var tool = _smb ?? throw new InvalidOperationException("SmbTool is not registered.");
        Charge(target, "smb");
        var r = await tool.ProbeAsync(target, ct).ConfigureAwait(false);
        GetOrCreate(target).Smb.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe FTP: grab the banner and attempt an anonymous (USER anonymous / PASS anonymous@) " +
                 "login. When accepted, list the server root. Never brute-forces credentials.")]
    public async Task<string> FtpProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (1-65535).")] int port,
        CancellationToken ct = default)
    {
        var tool = _ftp ?? throw new InvalidOperationException("FtpTool is not registered.");
        ValidatePort(port);
        Charge(target, "ftp");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Ftp.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe SSH: read the banner and parse the KEX/host-key/cipher/MAC algorithm lists " +
                 "from the server's SSH2_MSG_KEXINIT. Unauthenticated, read-only.")]
    public async Task<string> SshProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (1-65535).")] int port,
        CancellationToken ct = default)
    {
        var tool = _ssh ?? throw new InvalidOperationException("SshTool is not registered.");
        ValidatePort(port);
        Charge(target, "ssh");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Ssh.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Native SNMP v1/v2c enumeration: system info, process list, installed software walk " +
                 "without external snmpwalk dependency. Tries common read communities (public, private, " +
                 "community, manager, snmp, secret, cisco) and walks the system MIB, hrSWRun, and " +
                 "hrSWInstalled subtrees. Read-only.")]
    public async Task<string> SnmpProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("UDP port number (1-65535).")] int port,
        CancellationToken ct = default)
    {
        var tool = _snmp ?? throw new InvalidOperationException("SnmpTool is not registered.");
        ValidatePort(port);
        Charge(target, "snmp");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Snmp.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe LDAP: attempt an anonymous bind and, when permitted, read the RootDSE " +
                 "(namingContexts, supportedControl, supportedLDAPVersion, supportedSASLMechanisms). " +
                 "Never performs credentialed enumeration or brute force.")]
    public async Task<string> LdapProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (typically 389 or 636).")] int port,
        CancellationToken ct = default)
    {
        var tool = _ldap ?? throw new InvalidOperationException("LdapTool is not registered.");
        ValidatePort(port);
        Charge(target, "ldap");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Ldap.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe RPC portmapper (111): list registered RPC programs via rpcinfo -p and, when " +
                 "available, nmap's rpcinfo NSE script. Read-only.")]
    public async Task<string> RpcProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (typically 111).")] int port,
        CancellationToken ct = default)
    {
        var tool = _rpc ?? throw new InvalidOperationException("RpcTool is not registered.");
        ValidatePort(port);
        Charge(target, "rpc");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).Rpc.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Probe Kerberos-adjacent surface via LDAP RootDSE: infer the Kerberos realm and, " +
                 "when an anonymous bind is permitted, enumerate servicePrincipalName values in the " +
                 "directory. Never requests TGTs, never AS-REP roasts, never brute-forces.")]
    public async Task<string> KerberosProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("LDAP TCP port number (typically 389 or 636).")] int port,
        CancellationToken ct = default)
    {
        var tool = _kerberos ?? throw new InvalidOperationException("KerberosTool is not registered.");
        ValidatePort(port);
        Charge(target, "kerberos");
        var r = await tool.ProbeAsync(target, port, null, null, ct).ConfigureAwait(false);
        GetOrCreate(target).Kerberos.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Attempt a DNS zone transfer (AXFR) for a domain against an explicit nameserver IP " +
                 "using dig. The nameserver MUST be inside the authorized scope; the domain is a " +
                 "label only. Read-only — AXFR is a pure query.")]
    public async Task<string> DnsZoneTransferAsync(
        [Description("DNS domain to request an AXFR for, e.g. 'example.lab'.")] string domain,
        [Description("Nameserver IP address to query (must be in scope).")] string nameserver,
        CancellationToken ct = default)
    {
        var tool = _dnsAxfr ?? throw new InvalidOperationException("DnsZoneTransferTool is not registered.");
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("domain must not be empty.", nameof(domain));
        if (string.IsNullOrWhiteSpace(nameserver))
            throw new ArgumentException("nameserver must not be empty.", nameof(nameserver));
        Charge(nameserver, "dns-axfr");
        var r = await tool.ProbeAsync(domain, nameserver, ct).ConfigureAwait(false);
        GetOrCreate(nameserver).DnsZoneTransfer.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Path-only HTTP content discovery: GET a bounded list of common paths under a base " +
                 "URL, recording interesting statuses (200/201/204/301/302/307/401/403) and sizes. " +
                 "Rate-limited, no parameter or credential brute-forcing.")]
    public async Task<string> HttpContentDiscoveryAsync(
        [Description("Absolute base URL, e.g. 'http://10.0.0.5:8080'. Host must be in scope.")] string baseUrl,
        CancellationToken ct = default)
    {
        var tool = _httpContentDiscovery
            ?? throw new InvalidOperationException("HttpContentDiscoveryTool is not registered.");
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri) ||
            (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException(
                $"baseUrl '{baseUrl}' must be an absolute http/https URL.", nameof(baseUrl));
        }
        Charge(baseUri.Host, "http-content-discovery");
        var r = await tool.ProbeAsync(baseUrl, ct).ConfigureAwait(false);
        GetOrCreate(baseUri.Host).HttpContentDiscovery.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Enumerate the TLS cipher suites and protocol versions a service supports using " +
                 "nmap's ssl-enum-ciphers NSE script. Returns per-version cipher lists and grades. " +
                 "Read-only.")]
    public async Task<string> TlsCipherEnumAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (typically 443).")] int port,
        CancellationToken ct = default)
    {
        var tool = _tlsCipherEnum
            ?? throw new InvalidOperationException("TlsCipherEnumTool is not registered.");
        ValidatePort(port);
        Charge(target, "tls-cipher-enum");
        var r = await tool.ProbeAsync(target, port, ct).ConfigureAwait(false);
        GetOrCreate(target).TlsCipherEnum.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }

    [Description("Fast native TCP port scanner with banner grabbing. " +
                 "Use when nmap is unavailable or for initial quick sweep. " +
                 "Returns a JSON summary of open TCP ports with detected services. " +
                 "The target MUST be inside the authorized scope.")]
    public async Task<string> ScanNativeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("Optional comma-separated port list, e.g. '80,443,22'. Omit for built-in top-port list.")] string? ports,
        CancellationToken ct = default)
    {
        var tool = _nativeScanner ?? throw new InvalidOperationException("NativeScannerTool is not registered.");
        int[]? portList = null;
        if (!string.IsNullOrWhiteSpace(ports))
        {
            portList = ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(int.Parse)
                .ToArray();
        }
        Charge(target, "nativescan");
        var hf = await tool.ScanAsync(target, portList, ct: ct).ConfigureAwait(false);
        GetOrCreate(target).NativeScan = hf.NativeScan;
        return System.Text.Json.JsonSerializer.Serialize(hf.NativeScan);
    }

    [Description("Native DNS recon: resolves A/AAAA/MX/NS/TXT/SOA records and attempts AXFR zone " +
                 "transfers without external dig dependency. Target must be an in-scope IP address. " +
                 "queryType: 'ALL' (default), 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'AXFR'.")]
    public async Task<string> NativeDnsQueryAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("Record type: ALL, A, AAAA, MX, NS, TXT, SOA, PTR, or AXFR. Defaults to ALL.")] string queryType = "ALL",
        CancellationToken ct = default)
    {
        var tool = _nativeDns ?? throw new InvalidOperationException("NativeDnsTool is not registered.");
        Charge(target, "dns-native");
        var r = await tool.QueryAsync(target, queryType, ct).ConfigureAwait(false);
        GetOrCreate(target).NativeDns.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }


    [Description("Multi-signal host fingerprinter: combines banner / TLS certificate / HTTP headers / " +
                 "favicon SHA-256 into ranked (vendor, product, version) candidates with confidence " +
                 "scores and CPE 2.3 strings. Operates on existing recon signals already collected " +
                 "for the target; optionally fetches /favicon.ico over a scope-checked HTTP probe. " +
                 "Returns a JSON list of FingerprintReports (one per port).")]
    public async Task<string> FingerprintStackAsync(
        [Description("Target IP address (must be in scope).")] string target,
        CancellationToken ct = default)
    {
        var tool = _fingerprintStack
            ?? throw new InvalidOperationException("FingerprintStackTool is not registered.");
        Charge(target, "fingerprint-stack");
        var finding = GetOrCreate(target);
        var reports = await tool.FingerprintHostAsync(target, finding, ct).ConfigureAwait(false);
        finding.Fingerprint.AddRange(reports);
        return System.Text.Json.JsonSerializer.Serialize(reports);
    }

    // --- htb-smtp-enum --- (GAP-011)
    [Description("Enumerate SMTP on a port (25/465/587/2525): banner, EHLO capabilities, " +
                 "STARTTLS upgrade when advertised, and unauthenticated user discovery via " +
                 "VRFY/EXPN/RCPT TO against a small admin wordlist. Read-only, no credential brute-force.")]
    public async Task<string> EnumerateSmtpAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (default 25).")] int port = 25,
        [Description("Optional path to a newline-delimited wordlist of usernames. When omitted a built-in 20-name admin list is used.")] string? wordlistPath = null,
        CancellationToken ct = default)
    {
        var tool = _smtpEnum ?? throw new InvalidOperationException("SmtpEnumTool is not registered.");
        ValidatePort(port);
        Charge(target, "smtp-enum");
        var r = await tool.EnumerateAsync(target, port, wordlistPath, ct: ct).ConfigureAwait(false);
        GetOrCreate(target).SmtpEnum.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }
    // --- end htb-smtp-enum ---

    // --- htb-ssl-cert-hosts --- (GAP-006)
    [Description("Connect to a TLS port (e.g. 443, 8443, 993, 465, 636) and extract the X.509 " +
                 "Common Name and Subject Alternative Names. Emits structured /etc/hosts " +
                 "proposal records for hostnames that do not already resolve to the target IP. " +
                 "Tool never writes /etc/hosts itself.")]
    public async Task<string> EnumerateSslCertAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (default 443).")] int port = 443,
        CancellationToken ct = default)
    {
        var tool = _sslCertHosts ?? throw new InvalidOperationException("SslCertHostsTool is not registered.");
        ValidatePort(port);
        Charge(target, "ssl-cert-hosts");
        var r = await tool.EnumerateAsync(target, port, ct: ct).ConfigureAwait(false);
        GetOrCreate(target).SslCertHosts.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }
    // --- end htb-ssl-cert-hosts ---

    // --- htb-locale-lfi-probe --- (GAP-035 / CVE-2025-49132 shape)
    [Description("Generic locale-parameter LFI probe: discovers query parameters " +
                 "whose names match a locale-shaped allow-list (lang, locale, page, " +
                 "file, template, include, …) from operator-supplied HTML or an " +
                 "explicit candidate list, then replaces each value with a curated " +
                 "set of path-traversal / PHP-wrapper payloads (../etc/passwd, " +
                 "php://filter/convert.base64-encode, null-byte truncation, Unicode " +
                 "bypasses). Detects confirmed file-read via passwd/win.ini markers, " +
                 "PHP source leakage, base64 blobs (filter wrapper), and length " +
                 "anomalies vs a baseline sentinel request. Read-only GET; never " +
                 "follows redirects off scope. Body content is never logged — only a " +
                 "SHA-256 fingerprint of the first 8 KiB.")]
    public async Task<string> ProbeLocaleLfiAsync(
        [Description("Absolute base URL, e.g. 'http://10.0.0.5:8080/'. Host must be an in-scope IP.")] string baseUrl,
        [Description("Optional operator-supplied HTML to discover locale-shaped params from.")] string? discoveryHtml = null,
        [Description("Comma-separated additional parameter names to include in the locale-shaped allow-list.")] string? extraParams = null,
        [Description("Max probe requests per host (default 100).")] int maxProbes = Drederick.Recon.Http.LocaleLfiProbe.DefaultMaxProbes,
        CancellationToken ct = default)
    {
        var tool = _localeLfi ?? throw new InvalidOperationException("LocaleLfiProbe is not registered.");
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
            throw new ArgumentException($"baseUrl '{baseUrl}' must be absolute.", nameof(baseUrl));
        Charge(baseUri.Host, "locale-lfi");
        IEnumerable<string>? extras = null;
        if (!string.IsNullOrWhiteSpace(extraParams))
        {
            extras = extraParams.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        var r = await tool.ProbeAsync(
            baseUrl,
            candidates: null,
            discoveryHtml: discoveryHtml,
            extraParams: extras,
            maxProbes: maxProbes,
            ct: ct).ConfigureAwait(false);
        GetOrCreate(baseUri.Host).LocaleLfi.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }
    // --- end htb-locale-lfi-probe ---

    // --- htb-cloud-storage-enum --- (GAP-018)
    [Description("Probe a target's S3-compatible endpoint for anonymous bucket listing. " +
                 "Accepts a single bucket name or walks a built-in 200-name wordlist. For " +
                 "listable buckets, parses object keys + sizes and (when harvest is enabled) " +
                 "downloads high-signal artifacts (.env, id_rsa, credentials, *.bak, " +
                 "*.sqlite, wp-config.php) into out/loot/<host>/cloud-bucket-<name>/. " +
                 "Local-only loot — never exfiltrated.")]
    public async Task<string> EnumerateCloudStorageAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number (default 443).")] int port = 443,
        [Description("Use TLS (https) instead of plain http. Default true.")] bool useTls = true,
        [Description("Optional single bucket name to probe; when omitted the built-in 200-name wordlist is walked.")] string? bucketName = null,
        [Description("Disable harvesting of matching objects; record listings only.")] bool noHarvest = false,
        CancellationToken ct = default)
    {
        var tool = _cloudStorage ?? throw new InvalidOperationException("CloudStorageEnumTool is not registered.");
        ValidatePort(port);
        Charge(target, "cloud-storage");
        var r = await tool.EnumerateAsync(
            target, port, useTls, bucketName,
            bucketWordlist: null,
            harvestEnabled: !noHarvest,
            ct: ct).ConfigureAwait(false);
        GetOrCreate(target).CloudStorage.Add(r);
        return System.Text.Json.JsonSerializer.Serialize(r);
    }
    // --- end htb-cloud-storage-enum ---


    private static void ValidatePort(int port)
    {
        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "port must be in [1, 65535].");
    }

    public void Finalize(IEnumerable<string> targets)
    {
        foreach (var t in targets)
        {
            if (_findings.TryGetValue(t, out var f))
            {
                f.Finished ??= DateTimeOffset.UtcNow.ToString("o");
            }
        }
    }

    public void SeedFromKnowledgeBase(KnowledgeBase kb, IEnumerable<string> targets)
    {
        // Seeding is informational only; prior findings are carried into the
        // output so the agent/report can reason over deltas.
        foreach (var t in targets)
        {
            if (kb.Hosts.TryGetValue(t, out var prior))
            {
                _audit.Record("kb.seed", new Dictionary<string, object?>
                {
                    ["target"] = t,
                    ["prior_finished"] = prior.Finished,
                });
            }
        }
    }
}

/// <summary>
/// Per-target-per-tool and global call caps for <see cref="ReconToolbox"/>.
/// The budget is a runaway-loop rate-limit, not a security boundary: scope
/// is enforced inside every tool, so weakening these caps does not weaken
/// authorization. <see cref="Default"/> (3/200) is calibrated for short
/// deterministic <c>AdaptiveRunner</c> passes; LLM-driven runs
/// (<c>--agent</c>, <c>--agent=hybrid</c>) need substantially more headroom
/// to iterate through service variants and PoCs without starving — see
/// <see cref="LlmDefault"/> (10/500). Per-tool overrides
/// (<see cref="PerToolOverrides"/>) let the operator raise specific tools
/// (e.g. <c>http</c>) further without lifting the global default.
/// A cap of 0 is "deny-all" (the first call exceeds it). Negative caps
/// are rejected by <see cref="CommandLineOptions"/> parsing.
/// </summary>
public sealed record ToolBudget(int PerTargetPerTool, int MaxTotalCalls)
{
    /// <summary>Optional per-tool overrides keyed by <see cref="IReconTool.Name"/>
    /// (e.g. <c>"http"</c>, <c>"nmap"</c>). When set, the override replaces
    /// <see cref="PerTargetPerTool"/> for that tool. Other tools fall back to
    /// the global cap.</summary>
    public IReadOnlyDictionary<string, int>? PerToolOverrides { get; init; }

    /// <summary>Default budget for deterministic / no-LLM runs. Calibrated for
    /// short adaptive passes — bumping these values without raising
    /// <see cref="LlmDefault"/> will not affect LLM-driven planning.</summary>
    public static ToolBudget Default { get; } = new(PerTargetPerTool: 3, MaxTotalCalls: 200);

    /// <summary>Default budget for LLM-driven runs (<c>--agent</c>,
    /// <c>--agent=hybrid</c>, <c>--agent=llm</c>). The LLM planner needs
    /// many more iterations than the deterministic runner — R5 JobTwo
    /// starved on http=3 / nmap=3 after 17 LLM-issued HTTP probes
    /// (GAP-029). 10 per tool / 500 global is enough for a realistic
    /// hard-box fight while still capping runaway loops.</summary>
    public static ToolBudget LlmDefault { get; } = new(PerTargetPerTool: 10, MaxTotalCalls: 500);

    /// <summary>Resolve the effective per-target cap for <paramref name="tool"/>:
    /// override if present, else global <see cref="PerTargetPerTool"/>.</summary>
    public int CapFor(string tool) =>
        PerToolOverrides is not null && PerToolOverrides.TryGetValue(tool, out var cap)
            ? cap
            : PerTargetPerTool;
}
