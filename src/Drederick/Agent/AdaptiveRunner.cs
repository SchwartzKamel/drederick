using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;

namespace Drederick.Agent;

/// <summary>
/// Deterministic adaptive runner. Does not require an LLM or any network
/// credentials, so it is the default offline / CI runner. Implements a small
/// plan-act-observe loop that genuinely adapts:
///
///   1. Digest prior findings from the knowledge base to pick a smart first port set.
///   2. Run DNS + nmap in parallel.
///   3. Inspect open ports; dispatch HTTP / TLS probes to the right services.
///   4. If no ports came back and we haven't tried a full sweep, retry with -p-.
///   5. Merge into the in-run findings table (toolbox owns that state).
///
/// This is the "engage" phase for lab use without cloud dependency.
/// </summary>
public sealed class AdaptiveRunner : IReconAgentRunner
{
    private readonly AuditLog _audit;
    private readonly int _hostConcurrency;
    private readonly int _serviceConcurrency;

    public AdaptiveRunner(AuditLog audit, int parallelism = 4)
        : this(audit, hostConcurrency: parallelism, serviceConcurrency: 8)
    {
    }

    public AdaptiveRunner(AuditLog audit, int hostConcurrency, int serviceConcurrency)
    {
        _audit = audit;
        _hostConcurrency = Math.Max(1, hostConcurrency);
        _serviceConcurrency = Math.Max(1, serviceConcurrency);
    }

    public async Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase prior,
        CancellationToken ct)
    {
        _audit.Record("runner.start", new Dictionary<string, object?>
        {
            ["runner"] = nameof(AdaptiveRunner),
            ["targets"] = targets,
            ["host_concurrency"] = _hostConcurrency,
            ["service_concurrency"] = _serviceConcurrency,
        });

        var pool = new HostWorkerPool(_hostConcurrency, _serviceConcurrency);
        await pool.RunAsync(
            targets,
            (target, svcPool, token) => RunOneAsync(target, tools, prior, svcPool, token),
            onHostError: (host, ex) => _audit.Record("runner.host_error", new Dictionary<string, object?>
            {
                ["target"] = host,
                ["error"] = ex.Message,
            }),
            ct).ConfigureAwait(false);

        tools.Finalize(targets);
        _audit.Record("runner.finish", new Dictionary<string, object?>
        {
            ["tool_calls"] = tools.ToolCallsTotal,
        });
    }

    private async Task RunOneAsync(
        string target,
        ReconToolbox tools,
        KnowledgeBase prior,
        ServiceWorkerPool svcPool,
        CancellationToken ct)
    {
        _audit.Record("runner.plan", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["prior"] = prior.Digest(target),
        });

        // Step 1: DNS + initial nmap in parallel. If prior knowledge exists, we
        // bias the first scan toward previously observed ports plus the top list
        // so we reconfirm quickly and still catch drift.
        string? initialPorts = null;
        if (prior.Hosts.TryGetValue(target, out var priorFinding) &&
            priorFinding.Nmap?.OpenPorts is { Count: > 0 } openPorts)
        {
            initialPorts = string.Join(",", openPorts.Select(p => p.Port).Distinct());
        }

        var dnsTask = tools.DnsProbeAsync(target, ct);
        var nmapTask = tools.NmapScanAsync(target, initialPorts, ct);
        await Task.WhenAll(dnsTask, nmapTask).ConfigureAwait(false);

        // Step 2: look at the findings to choose follow-ups.
        if (!tools.Findings.TryGetValue(target, out var f) || f.Nmap is null)
            return;

        // Adaptive: if the targeted scan found nothing and we targeted a prior
        // port set, widen to top-1000. If the top-1000 scan found nothing,
        // escalate to full range once.
        if (f.Nmap.OpenPorts.Count == 0)
        {
            _audit.Record("runner.adapt", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["reason"] = "no ports on first pass; widening",
            });
            await tools.NmapScanAsync(target,
                initialPorts is null ? "1-65535" : null, ct).ConfigureAwait(false);
        }

        if (f.Nmap.OpenPorts.Count == 0) return;

        // Step 3: fan out to HTTP / TLS probes on discovered services through
        // the bounded per-host service channel (true back-pressure).
        foreach (var port in f.Nmap.OpenPorts)
        {
            var svc = (port.Service ?? "").ToLowerInvariant();
            var isTls = svc.Contains("https") || svc.Contains("ssl") || svc == "tls"
                        || port.Port is 443 or 8443 or 9443;
            var isHttp = svc.Contains("http") || port.Port is 80 or 8080 or 8000 or 8008 or 8888 or 3000 or 5000;

            if (isTls)
            {
                var tlsPort = port.Port;
                await svcPool.EnqueueAsync(new ScanJob(
                    tools.Tools.First(t => t.Name == "tls"),
                    target, tlsPort,
                    token => SafeRun(() => tools.TlsProbeAsync(target, tlsPort, token))),
                    ct).ConfigureAwait(false);
                await svcPool.EnqueueAsync(new ScanJob(
                    tools.Tools.First(t => t.Name == "http"),
                    target, tlsPort,
                    token => SafeRun(() => tools.HttpProbeAsync(target, tlsPort, useTls: true, token))),
                    ct).ConfigureAwait(false);
            }
            else if (isHttp)
            {
                var httpPort = port.Port;
                await svcPool.EnqueueAsync(new ScanJob(
                    tools.Tools.First(t => t.Name == "http"),
                    target, httpPort,
                    token => SafeRun(() => tools.HttpProbeAsync(target, httpPort, useTls: false, token))),
                    ct).ConfigureAwait(false);
            }
        }
    }

    private async Task SafeRun(Func<Task<string>> f)
    {
        try { await f().ConfigureAwait(false); }
        catch (Exception ex)
        {
            _audit.Record("runner.followup_error", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
            });
        }
    }
}
