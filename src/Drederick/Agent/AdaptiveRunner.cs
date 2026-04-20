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
    private readonly bool _enableContentDiscovery;

    public AdaptiveRunner(AuditLog audit, int parallelism = 4)
        : this(audit, hostConcurrency: parallelism, serviceConcurrency: 8)
    {
    }

    public AdaptiveRunner(AuditLog audit, int hostConcurrency, int serviceConcurrency)
        : this(audit, hostConcurrency, serviceConcurrency, enableContentDiscovery: false)
    {
    }

    public AdaptiveRunner(AuditLog audit, int hostConcurrency, int serviceConcurrency, bool enableContentDiscovery)
    {
        _audit = audit;
        _hostConcurrency = Math.Max(1, hostConcurrency);
        _serviceConcurrency = Math.Max(1, serviceConcurrency);
        _enableContentDiscovery = enableContentDiscovery;
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

        // Step 3: fan out to follow-up probes on discovered services through
        // the bounded per-host service channel (true back-pressure). Dispatch
        // is driven by a pure plan (see BuildDispatchPlan) so the mapping
        // stays deterministic and unit-testable.
        var plan = BuildDispatchPlan(f.Nmap.OpenPorts, _enableContentDiscovery);
        foreach (var action in plan)
        {
            var p = action.Port;
            var toolName = action.ToolName;
            var tool = tools.Tools.FirstOrDefault(t => t.Name == toolName);
            if (tool is null)
            {
                // Scanner not registered in this toolbox; skip silently. This
                // lets deployments opt in to the extended scanner set without
                // breaking the runner.
                continue;
            }

            Func<CancellationToken, Task> run = toolName switch
            {
                "tls" => token => SafeRun(() => tools.TlsProbeAsync(target, p, token)),
                "http" => token => SafeRun(() => tools.HttpProbeAsync(target, p, action.UseTls, token)),
                "tls-cipher-enum" => token => SafeRun(() => tools.TlsCipherEnumAsync(target, p, token)),
                "http-content-discovery" => token => SafeRun(() => tools.HttpContentDiscoveryAsync(
                    $"{(action.UseTls ? "https" : "http")}://{target}:{p}", token)),
                "smb" => token => SafeRun(() => tools.SmbProbeAsync(target, token)),
                "ftp" => token => SafeRun(() => tools.FtpProbeAsync(target, p, token)),
                "ssh" => token => SafeRun(() => tools.SshProbeAsync(target, p, token)),
                "snmp" => token => SafeRun(() => tools.SnmpProbeAsync(target, p, token)),
                "ldap" => token => SafeRun(() => tools.LdapProbeAsync(target, p, token)),
                "rpc" => token => SafeRun(() => tools.RpcProbeAsync(target, p, token)),
                "kerberos" => token => SafeRun(() => tools.KerberosProbeAsync(target, p, token)),
                _ => _ => Task.CompletedTask,
            };

            await svcPool.EnqueueAsync(new ScanJob(tool, target, p, run), ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A single entry in the deterministic per-port dispatch plan. Port-bearing
    /// scanners get <see cref="Port"/>; <see cref="UseTls"/> distinguishes plain
    /// HTTP from HTTPS for the http/http-content-discovery tools and is unused
    /// for everything else.
    /// </summary>
    public readonly record struct DispatchAction(string ToolName, int Port, bool UseTls = false);

    /// <summary>
    /// Pure, deterministic mapping from nmap-observed open ports to follow-up
    /// scanner invocations. Exposed <c>internal</c> so tests can assert the
    /// service→tool routing without spinning up an actual ReconToolbox.
    /// </summary>
    public static IReadOnlyList<DispatchAction> BuildDispatchPlan(
        IReadOnlyList<NmapPort> openPorts,
        bool enableContentDiscovery)
    {
        var plan = new List<DispatchAction>();
        foreach (var port in openPorts)
        {
            var svc = (port.Service ?? "").ToLowerInvariant();
            var proto = (port.Protocol ?? "tcp").ToLowerInvariant();

            var isTls = svc.Contains("https") || svc.Contains("ssl") || svc == "tls"
                        || port.Port is 443 or 8443 or 9443;
            var isHttp = svc.Contains("http") || port.Port is 80 or 8080 or 8000 or 8008 or 8888 or 3000 or 5000;

            if (isTls)
            {
                plan.Add(new DispatchAction("tls", port.Port));
                plan.Add(new DispatchAction("http", port.Port, UseTls: true));
                plan.Add(new DispatchAction("tls-cipher-enum", port.Port));
                if (enableContentDiscovery)
                {
                    plan.Add(new DispatchAction("http-content-discovery", port.Port, UseTls: true));
                }
            }
            else if (isHttp)
            {
                plan.Add(new DispatchAction("http", port.Port, UseTls: false));
                if (enableContentDiscovery)
                {
                    plan.Add(new DispatchAction("http-content-discovery", port.Port, UseTls: false));
                }
            }

            if (svc == "microsoft-ds" || svc == "netbios-ssn")
            {
                plan.Add(new DispatchAction("smb", port.Port));
            }
            if (svc == "ftp")
            {
                plan.Add(new DispatchAction("ftp", port.Port));
            }
            if (svc == "ssh")
            {
                plan.Add(new DispatchAction("ssh", port.Port));
            }
            // SNMP: only auto-dispatch when the port is explicitly UDP or nmap
            // labelled it 'snmp' (nmap's -sU is rare in default runs so we treat
            // a labelled service as sufficient evidence).
            if (svc == "snmp" || (svc.Contains("snmp") && proto == "udp"))
            {
                plan.Add(new DispatchAction("snmp", port.Port));
            }
            if (svc == "ldap" || svc == "ldaps")
            {
                plan.Add(new DispatchAction("ldap", port.Port));
                plan.Add(new DispatchAction("kerberos", port.Port));
            }
            if (svc == "sunrpc" || svc == "rpcbind")
            {
                plan.Add(new DispatchAction("rpc", port.Port));
            }
            // DNS zone transfer intentionally NOT auto-dispatched: the scanner
            // requires an explicit authorized nameserver IP (see
            // DnsZoneTransferTool class doc). Surfaced only via the LLM tool
            // surface or an explicit CLI invocation.
        }
        return plan;
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
