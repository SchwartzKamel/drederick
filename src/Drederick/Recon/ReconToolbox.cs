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
