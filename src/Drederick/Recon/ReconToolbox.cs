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
        if (count > Budget.PerTargetPerTool)
        {
            throw new InvalidOperationException(
                $"Budget exceeded: {tool} called {count} times on {target} (cap {Budget.PerTargetPerTool}).");
        }
        if (_toolCallsTotal > Budget.MaxTotalCalls)
        {
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
                 "and which common security headers are missing. Non-exploitative.")]
    public async Task<string> HttpProbeAsync(
        [Description("Target IP address (must be in scope).")] string target,
        [Description("TCP port number.")] int port,
        [Description("Use TLS (https) if true.")] bool useTls,
        CancellationToken ct = default)
    {
        Charge(target, "http");
        var r = await _http.ProbeAsync(target, port, useTls, ct).ConfigureAwait(false);
        GetOrCreate(target).Http.Add(r);
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

public sealed record ToolBudget(int PerTargetPerTool, int MaxTotalCalls)
{
    public static ToolBudget Default { get; } = new(PerTargetPerTool: 3, MaxTotalCalls: 200);
}
