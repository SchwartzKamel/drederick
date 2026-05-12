using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Recon.Fuzz;
using Drederick.Scaffolding;

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

    /// <summary>
    /// Optional in-fight scaffolding (briefing.md + attack-graph.yaml).
    /// When set, activation events are emitted at <see cref="RunAsync"/>
    /// start. See <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §4.
    /// </summary>
    public ScaffoldingContext? Scaffolding { get; set; }

    // --- htb-cve-lead-actions-resolve ---
    /// <summary>
    /// GAP-033 — optional hook invoked at the tail of <see cref="RunAsync"/>
    /// after the worker pool drains and <c>tools.Finalize</c> has run.
    /// Orchestrators wire this to <see cref="Drederick.Enrichment.CveLeadResolver"/>
    /// so that CVEs annotated post-recon but lacking cached PoC artefacts
    /// are pursued via <c>PocAggregator.FetchOnDemandAsync</c> before the
    /// run reports out. Null by default — leaves AdaptiveRunner pure recon.
    /// </summary>
    public Func<CancellationToken, Task>? PostRunHookAsync { get; set; }
    // --- end htb-cve-lead-actions-resolve ---

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

        Scaffolding?.ActivateKnownNodes();

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

        // --- htb-cve-lead-actions-resolve ---
        // GAP-033 — optional post-recon hook so orchestrators can dispatch
        // Drederick.Enrichment.CveLeadResolver after CveAnnotator runs,
        // pursuing CVEs that were matched during annotation but had no
        // cached PoC artefact. Hook is null/no-op when unset, so wiring
        // remains the responsibility of the call site (Program.cs /
        // DrederickHost) and this runner stays single-purpose.
        if (PostRunHookAsync is { } hook)
        {
            try
            {
                await hook(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _audit.Record("runner.post_hook.error", new Dictionary<string, object?>
                {
                    ["hook"] = "cve_lead_resolver",
                    ["error"] = ex.Message,
                });
            }
        }
        // --- end htb-cve-lead-actions-resolve ---
    }

    private async Task RunOneAsync(
        string target,
        ReconToolbox tools,
        KnowledgeBase prior,
        ServiceWorkerPool svcPool,
        CancellationToken ct)
    {
        // --- htb-structured-plan-prior --- (GAP-054)
        // Emit the structured PlanPrior alongside a human-readable summary.
        // The prose digest moves to the optional `summary` field; the
        // authoritative shape is the typed PlanPrior.
        var planPrior = PlanPriorBuilder.Build(
            kb: prior,
            audit: _audit,
            budget: null,
            targets: new[] { target },
            summary: prior.Digest(target));
        var planFields = new Dictionary<string, object?>(planPrior.ToAuditFields())
        {
            ["target"] = target,
        };
        _audit.Record("runner.plan.prior", planFields);
        // --- end htb-structured-plan-prior ---

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

    /// <summary>
    /// Schedules HTTP-driven fuzz tools (header, web-param, vhost, api,
    /// graphql) against any HTTP services discovered during the recon pass.
    /// Additive helper — does not modify the existing
    /// <see cref="RunAsync(IReadOnlyList{string}, ReconToolbox, KnowledgeBase, CancellationToken)"/>
    /// contract. Callers (typically <c>DrederickHost</c>) invoke it AFTER
    /// the main runner finishes, when they want a fuzz pass.
    ///
    /// <para>Conservative scheduling rules (each tool re-checks scope
    /// internally, so the worst-case from a misroute is a
    /// <see cref="Drederick.Scope.ScopeException"/>):</para>
    /// <list type="bullet">
    ///   <item><description>HTTP service discovered → header-fuzz, web-param-fuzz, vhost-fuzz</description></item>
    ///   <item><description>Path looks API-ish (<c>/api</c>, <c>/v1</c>) → api-endpoint-fuzz</description></item>
    ///   <item><description>GraphQL endpoint detected → graphql-fuzz</description></item>
    /// </list>
    ///
    /// <para>JWT, Subdomain, Protocol, FileFormat, and LlmPayload fuzzers
    /// require operator-supplied input (token, apex domain, capture file,
    /// upload form, anchor URL) and are not auto-scheduled here. They remain
    /// available via direct <see cref="FuzzToolbox.GetByName"/> lookup or
    /// LLM tool calls.</para>
    /// </summary>
    public async Task ScheduleFuzzAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        FuzzToolbox fuzz,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(fuzz);

        _audit.Record("runner.fuzz.start", new Dictionary<string, object?>
        {
            ["targets"] = targets,
            ["registered_tools"] = fuzz.Tools.Select(t => t.Name).ToArray(),
        });

        var header = fuzz.GetByName("header-fuzz") as HeaderFuzzTool;
        var webparam = fuzz.GetByName("web-param-fuzz") as WebParamFuzzTool;
        var api = fuzz.GetByName("api-endpoint-fuzz") as ApiEndpointFuzzTool;
        var graphql = fuzz.GetByName("graphql-fuzz") as GraphqlFuzzTool;
        var vhost = fuzz.GetByName("vhost-fuzz") as VhostFuzzTool;
        var apexQueued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var target in targets)
        {
            if (ct.IsCancellationRequested) break;
            if (!tools.Findings.TryGetValue(target, out var f) || f.Nmap is null) continue;

            foreach (var p in f.Nmap.OpenPorts)
            {
                var svc = (p.Service ?? "").ToLowerInvariant();
                var isTls = svc.Contains("https") || svc.Contains("ssl") || p.Port is 443 or 8443 or 9443;
                var isHttp = isTls || svc.Contains("http") || p.Port is 80 or 8080 or 8000 or 8008 or 8888 or 3000 or 5000;
                if (!isHttp) continue;

                var scheme = isTls ? "https" : "http";
                var url = $"{scheme}://{target}:{p.Port}/";

                async Task Try(string toolName, Func<Task> action)
                {
                    try
                    {
                        fuzz.RecordCall(toolName, target);
                        await action().ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _audit.Record("runner.fuzz.error", new Dictionary<string, object?>
                        {
                            ["tool"] = toolName,
                            ["target"] = target,
                            ["url"] = url,
                            ["error"] = ex.Message,
                        });
                    }
                }

                if (header is not null) await Try("header-fuzz", () => header.ProbeAsync(url, options: null, ct: ct));
                if (webparam is not null) await Try("web-param-fuzz", () => webparam.ProbeAsync(url, options: null, ct: ct));

                // --- htb-llm-vhost-fuzz-surface ---
                // GAP-051: vhost-fuzz auto-schedule. When http_probe detected
                // a Host-header redirect, derive apex and queue one vhost
                // brute per (apex,port) per pass. Tool re-checks scope on apex.
                // The same scheduling policy is exposed as a standalone
                // `Drederick.Recon.Fuzz.VhostAutoScheduler` for callers
                // outside this runner (e.g. LLM tool invocations) — see
                // VhostAutoScheduler.DeriveApex / ScheduleAsync. The
                // inline path below is preserved so existing tests
                // (AdaptiveRunnerVhostAutoScheduleTests) keep asserting
                // on the `vhost-fuzz.start` / `runner.fuzz.error` events.
                if (vhost is not null && f.Http is not null)
                {
                    foreach (var hr in f.Http)
                    {
                        if (!hr.VhostRequired || string.IsNullOrWhiteSpace(hr.VhostHostname)) continue;
                        if (!HttpResultMatchesPort(hr, p.Port)) continue;
                        var apex = DeriveApexDomain(hr.VhostHostname!);
                        if (string.IsNullOrWhiteSpace(apex)) continue;
                        if (System.Net.IPAddress.TryParse(apex, out _)) continue;
                        var dedupKey = $"{apex}:{p.Port}";
                        if (!apexQueued.Add(dedupKey)) continue;
                        var apexUrl = $"{scheme}://{apex}:{p.Port}/";
                        await Try("vhost-fuzz", () => vhost.ProbeAsync(apexUrl, apex, options: null, ct: ct));
                    }
                }

                if (api is not null) await Try("api-endpoint-fuzz", () => api.ProbeAsync(url, options: null, ct: ct));
                if (graphql is not null && (svc.Contains("graphql") || url.Contains("graphql", StringComparison.OrdinalIgnoreCase)))
                {
                    await Try("graphql-fuzz", () => graphql.ProbeAsync(url, options: null, ct: ct));
                }
            }
        }

        _audit.Record("runner.fuzz.finish", new Dictionary<string, object?>
        {
            ["fuzz_calls_total"] = fuzz.ToolCallsTotal,
        });
    }

    /// <summary>
    /// GAP-051: Derive the apex domain from a hostname using a "last two
    /// labels" rule. <c>panel.pterodactyl.htb</c> → <c>pterodactyl.htb</c>.
    /// IP literals and single-label hosts pass through unchanged. We
    /// deliberately skip the Public Suffix List because lab/CTF targets
    /// frequently use synthetic TLDs (.htb, .lab, .box) that PSL would
    /// resolve incorrectly. Operators on real registrar suffixes can
    /// supply the apex explicitly via the LLM vhost_fuzz tool.
    /// </summary>
    public static string DeriveApexDomain(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return string.Empty;
        var h = hostname.Trim().Trim('.');
        if (System.Net.IPAddress.TryParse(h, out _)) return h;
        var parts = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2) return h.ToLowerInvariant();
        return string.Concat(parts[^2], ".", parts[^1]).ToLowerInvariant();
    }

    private static bool HttpResultMatchesPort(HttpResult hr, int port)
    {
        if (string.IsNullOrEmpty(hr.Url)) return false;
        if (!Uri.TryCreate(hr.Url, UriKind.Absolute, out var u)) return false;
        return u.Port == port;
    }
}
