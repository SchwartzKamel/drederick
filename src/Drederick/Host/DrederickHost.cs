using Drederick.Agent;
using Drederick.Audit;
using Drederick.Enrichment;
using Drederick.Memory;
using Drederick.Ops;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;

namespace Drederick.Host;

/// <summary>
/// Shared engine facade used by the <c>Drederick.UI</c> operator console and
/// — in future iterations — by <see cref="Drederick.Cli"/>. Wraps the existing
/// wiring (scope → toolbox → runner → reports → knowledge base) behind a
/// single <see cref="RunAsync(Host.RunOptions, IProgress{ScanEvent}?, CancellationToken)"/>
/// call, plus a couple of side-effect-free helpers (<see cref="LoadScope"/>).
///
/// <para>
/// Invariant posture is preserved end-to-end:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>@invariant-id:scope-in-every-tool</c> — every tool in the
///     <see cref="ReconToolbox"/> re-checks scope internally; the host is a
///     pass-through, not a substitute.
///   </description></item>
///   <item><description>
///     <c>@invariant-id:aggregate-not-execute</c> — enrichment runs
///     (<see cref="CveAnnotator"/>, <see cref="PocAggregator"/>) are
///     opt-in via <see cref="RunOptions.AnnotateCves"/> and
///     <see cref="RunOptions.AggregatePocRefs"/> (default on for parity
///     with the CLI). Both stages only <em>record</em> references and
///     optionally cache PoC source bytes; neither ever <c>chmod +x</c>'s
///     or executes a PoC.
///   </description></item>
///   <item><description>
///     <c>@invariant-id:llm-cannot-escape-scope</c> — when
///     <see cref="RunOptions.UseAgent"/> is true, the agent runner's
///     <c>AIFunction</c>s still route through scope-enforced tools.
///   </description></item>
/// </list>
///
/// <para>
/// The AdaptiveRunner and MicrosoftAgentRunner already record to
/// <see cref="AuditLog"/>. The <c>IProgress&lt;ScanEvent&gt;</c> parameter is
/// additive: it emits a coarser-grained stream for live UI binding. Both
/// sinks receive every significant event.
/// </para>
/// </summary>
public sealed class DrederickHost
{
    /// <summary>
    /// Loads and validates a scope file. Thin wrapper that lets UI code
    /// preview the parsed <see cref="Drederick.Scope.Scope"/> (entry count,
    /// source) without starting a full run. Throws
    /// <see cref="ScopeException"/> on invalid / over-broad / wildcard scopes
    /// so the UI can surface the error text verbatim.
    /// </summary>
    public static Drederick.Scope.Scope LoadScope(string path, bool allowBroad, bool labMode)
        => ScopeLoader.LoadFile(path, allowBroad: allowBroad, labMode: labMode);

    /// <summary>
    /// Runs a recon pass with the given options. Loads the scope from
    /// <see cref="RunOptions.ScopePath"/>. Blocks on the caller's thread;
    /// for UI use, wrap in <c>Task.Run</c> or await directly from a
    /// background-capable context.
    /// </summary>
    /// <param name="options">Immutable run configuration.</param>
    /// <param name="progress">Optional UI-facing progress sink.</param>
    /// <param name="ct">Cancellation token — honoured by the runner.</param>
    /// <returns>
    /// Summary of what was produced: host count, tool call total, output dir.
    /// </returns>
    public Task<RunResult> RunAsync(
        RunOptions options,
        IProgress<ScanEvent>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ScopePath))
        {
            throw new InvalidOperationException(
                "RunOptions.ScopePath is required for this overload. " +
                "For GUI-authored inline scopes, call RunAsync(Scope, RunOptions, ...) instead.");
        }
        var scope = ScopeLoader.LoadFile(
            options.ScopePath,
            allowBroad: options.AllowBroad,
            labMode: options.LabMode);
        return RunAsync(scope, options, progress, ct);
    }

    /// <summary>
    /// Runs a recon pass against an already-parsed scope. Used by the
    /// <c>Drederick.UI</c> operator console so operators can compose a scope
    /// entirely inside the GUI (inline CIDR editor) without first writing a
    /// file to disk.
    /// <para>
    /// Invariant: the supplied <paramref name="scope"/> must have been
    /// produced by <see cref="ScopeLoader"/> (it's the only public
    /// constructor route). That is where default-deny, wildcard refusal, and
    /// prefix-cap validation happen — this method does NOT re-validate, so
    /// callers must not construct <see cref="Drederick.Scope.Scope"/>
    /// instances through any other path.
    /// </para>
    /// </summary>
    public async Task<RunResult> RunAsync(
        Drederick.Scope.Scope scope,
        RunOptions options,
        IProgress<ScanEvent>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(options);

        Emit(progress, ScanEventKind.ScopeLoaded, message: scope.Source);

        // Every explicit target must sit inside the scope.
        foreach (var t in options.Targets)
        {
            if (!scope.Contains(t))
            {
                throw new ScopeException(
                    $"Target '{t}' is not in scope (source: {scope.Source}).");
            }
        }
        if (options.Targets.Count == 0)
        {
            throw new InvalidOperationException(
                "No targets supplied. Pass at least one target or expand the scope before calling RunAsync.");
        }
        var targets = options.Targets.ToList();

        Directory.CreateDirectory(options.OutputDir);
        var auditPath = Path.Combine(options.OutputDir, "audit.jsonl");
        using var audit = new AuditLog(auditPath);

        audit.Record("session.start", new Dictionary<string, object?>
        {
            ["scope_source"] = scope.Source,
            ["target_count"] = targets.Count,
            ["runner"] = options.UseAgent ? "agent" : "adaptive",
            ["lab_mode"] = options.LabMode,
            ["initiator"] = "host",
        });
        Emit(progress, ScanEventKind.SessionStart,
            message: $"{targets.Count} target(s); lab={options.LabMode}; runner={(options.UseAgent ? "agent" : "adaptive")}");

        var kb = KnowledgeBase.Load(options.MemoryPath);

        var toolbox = BuildToolbox(scope, audit, options.LabMode);
        toolbox.SeedFromKnowledgeBase(kb, targets);

        // VPN preflight — optional, matches CLI's Program.cs behaviour. When
        // RequireVpn is set and the tunnel is down for an HTB target, abort
        // before any scanner work runs.
        if (options.VpnPreflight)
        {
            var vpnReport = new SqliteReport(options.OutputDir);
            var outcome = VpnPreflight.Run(
                new VpnPreflight.Options(targets, options.RequireVpn, SkipVpnCheck: false),
                audit,
                vpnReport,
                stderr: TextWriter.Null);
            Emit(progress, ScanEventKind.VpnPreflight, message: outcome.ToString());
            if (outcome == VpnPreflightOutcome.AbortNoVpn)
            {
                audit.Record("session.aborted", new Dictionary<string, object?> { ["reason"] = "vpn-required" });
                throw new InvalidOperationException(
                    "VPN preflight: require-vpn is set and no tun* interface is up for the HTB target(s).");
            }
        }

        IReconAgentRunner runner;
        if (options.UseAgent)
        {
            var agentRunner = MicrosoftAgentRunner.TryCreateFromProvider(options.LlmProvider, null, audit);
            if (agentRunner is null)
            {
                var providerName = options.LlmProvider.ToString().ToLowerInvariant();
                audit.Record("runner.fallback", new Dictionary<string, object?>
                {
                    ["requested_provider"] = providerName,
                    ["reason"] = $"no_{providerName}_config",
                });
                if (options.LlmProvider == Drederick.Jeopardy.Llm.LlmProvider.Auto)
                {
                    Emit(progress, ScanEventKind.Info, message: "No LLM provider configured (probed: copilot, azure, openai); falling back to AdaptiveRunner.");
                }
                else
                {
                    Emit(progress, ScanEventKind.Info, message: $"LLM provider '{providerName}' not configured; falling back to AdaptiveRunner. Hint: --llm-provider=auto probes all providers.");
                }
                runner = new AdaptiveRunner(audit, options.HostConcurrency, options.ServiceConcurrency, options.ContentDiscovery);
            }
            else
            {
                runner = agentRunner;
            }
        }
        else
        {
            runner = new AdaptiveRunner(audit, options.HostConcurrency, options.ServiceConcurrency, options.ContentDiscovery);
        }

        Emit(progress, ScanEventKind.RunnerStart, message: runner.GetType().Name);

        try
        {
            await runner.RunAsync(targets, toolbox, kb, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Emit(progress, ScanEventKind.Info, message: "cancelled");
            audit.Record("session.cancelled");
            throw;
        }
        catch (Exception ex)
        {
            audit.Record("session.error", new Dictionary<string, object?> { ["error"] = ex.Message });
            Emit(progress, ScanEventKind.Error, message: ex.Message);
            throw;
        }

        Emit(progress, ScanEventKind.RunnerFinish, toolCallsTotal: toolbox.ToolCallsTotal);

        // --- fuzz pass (opt-in) ---
        // Schedules HTTP-driven fuzz tools (header, web-param, api, graphql)
        // against any HTTP services the recon pass discovered. The fuzz
        // toolbox is constructed with default-deny destructive permissions
        // so ProtocolFuzzTool will refuse to spawn boofuzz subprocesses
        // unless the operator separately opts into RunPermissions.
        // Off by default — fuzzers depend on external binaries (arjun, ffuf,
        // kr, etc.) that may not be installed; flip via RunOptions.EnableFuzz
        // once `drederick doctor` confirms the toolchain.
        if (options.EnableFuzz && runner is AdaptiveRunner adaptive)
        {
            try
            {
                var fuzzbox = BuildFuzzToolbox(scope, audit, Drederick.Exploit.RunPermissions.None);
                Emit(progress, ScanEventKind.Info, message: "fuzz pass starting");
                await adaptive.ScheduleFuzzAsync(targets, toolbox, fuzzbox, ct).ConfigureAwait(false);
                Emit(progress, ScanEventKind.Info, message: $"fuzz pass complete ({fuzzbox.ToolCallsTotal} call(s))");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                audit.Record("fuzz.error", new Dictionary<string, object?> { ["error"] = ex.Message });
                Emit(progress, ScanEventKind.Error, message: $"fuzz pass error: {ex.Message}");
            }
        }

        var allFindings = targets
            .Select(t => toolbox.Findings.TryGetValue(t, out var f) ? f : null)
            .Where(f => f is not null)
            .Select(f => f!)
            .OrderBy(f => f.Target, StringComparer.Ordinal)
            .ToList();

        foreach (var f in allFindings)
        {
            Emit(progress, ScanEventKind.HostFinished, target: f.Target);
        }

        JsonReport.Write(Path.Combine(options.OutputDir, "report.json"), allFindings, scope.Source);
        Emit(progress, ScanEventKind.ReportWritten, message: "report.json");
        MarkdownReport.Write(Path.Combine(options.OutputDir, "report.md"), allFindings, scope.Source);
        Emit(progress, ScanEventKind.ReportWritten, message: "report.md");
        ManualCommandsCheatsheet.Write(options.OutputDir, allFindings, emitCheatsheet: options.LabMode);
        new SqliteReport(options.OutputDir).WriteReport(allFindings);
        Emit(progress, ScanEventKind.ReportWritten, message: "findings.db");

        // CVE annotation — matches CLI behaviour: default on, tolerates
        // offline (NvdCache returns empty on failure). Errors are audited
        // but never abort the run.
        if (options.AnnotateCves)
        {
            try
            {
                var annotator = new CveAnnotator();
                var annotation = await annotator.AnnotateAsync(allFindings, options.OutputDir, ct).ConfigureAwait(false);
                audit.Record("cve.annotate", new Dictionary<string, object?>
                {
                    ["cves"] = annotation.CveCount,
                    ["findings"] = annotation.FindingCount,
                    ["cache_loaded"] = annotation.CacheLoaded,
                });
                Emit(progress, ScanEventKind.CveAnnotated,
                    message: $"{annotation.CveCount} CVE(s) across {annotation.FindingCount} finding(s)");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                audit.Record("cve.annotate.error", new Dictionary<string, object?> { ["error"] = ex.Message });
                Emit(progress, ScanEventKind.Error, message: $"cve-annotate: {ex.Message}");
            }
        }

        // PoC aggregation — matches CLI behaviour. Invariant: aggregate +
        // present, never execute. We only record references (URL, SHA-256,
        // optional cached-path); nothing is launched from the cache.
        if (options.AggregatePocRefs)
        {
            try
            {
                var pocAggregator = new PocAggregator(audit: audit);
                var pocResult = await pocAggregator
                    .AggregateAsync(allFindings, options.OutputDir, options.FetchPocSource, ct)
                    .ConfigureAwait(false);
                audit.Record("poc.aggregate", new Dictionary<string, object?>
                {
                    ["cves"] = pocResult.CveCount,
                    ["refs"] = pocResult.RefCount,
                    ["cached"] = pocResult.CachedCount,
                    ["fetch_poc"] = options.FetchPocSource,
                });
                Emit(progress, ScanEventKind.PocAggregated,
                    message: $"{pocResult.RefCount} ref(s) across {pocResult.CveCount} CVE(s); cached={pocResult.CachedCount}");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                audit.Record("poc.aggregate.error", new Dictionary<string, object?> { ["error"] = ex.Message });
                Emit(progress, ScanEventKind.Error, message: $"poc-aggregate: {ex.Message}");
            }
        }

        kb.Merge(allFindings);
        kb.Save(options.MemoryPath);

        audit.Record("session.end", new Dictionary<string, object?>
        {
            ["host_count"] = allFindings.Count,
            ["tool_calls"] = toolbox.ToolCallsTotal,
        });
        Emit(progress, ScanEventKind.SessionEnd, toolCallsTotal: toolbox.ToolCallsTotal,
            message: $"{allFindings.Count} host(s)");

        return new RunResult(
            HostCount: allFindings.Count,
            ToolCallsTotal: toolbox.ToolCallsTotal,
            OutputDir: options.OutputDir,
            ScopeSource: scope.Source);
    }

    private static ReconToolbox BuildToolbox(Drederick.Scope.Scope scope, AuditLog audit, bool labMode)
    {
        var nmap = new NmapTool(scope, audit, labMode: labMode);
        var http = new HttpProbeTool(scope, audit);
        var tls = new TlsProbeTool(scope, audit);
        var dns = new DnsProbeTool(scope, audit);
        var smb = new SmbTool(scope, audit);
        var ftp = new FtpTool(scope, audit);
        var ssh = new SshTool(scope, audit);
        var snmp = new SnmpTool(scope, audit);
        var ldap = new LdapTool(scope, audit);
        var rpc = new RpcTool(scope, audit);
        var kerberos = new KerberosTool(scope, audit);
        var dnsAxfr = new DnsZoneTransferTool(scope, audit);
        var httpContentDiscovery = new HttpContentDiscoveryTool(scope, audit);
        var tlsCipherEnum = new TlsCipherEnumTool(scope, audit);
        // --- htb-smtp-enum ---
        var smtpEnum = new SmtpEnumTool(scope, audit);
        // --- end htb-smtp-enum ---

        return new ReconToolbox(
            new IReconTool[]
            {
                nmap, http, tls, dns,
                smb, ftp, ssh, snmp, ldap, rpc, kerberos,
                dnsAxfr, httpContentDiscovery, tlsCipherEnum,
                // --- htb-smtp-enum ---
                smtpEnum,
                // --- end htb-smtp-enum ---
            },
            audit);
    }

    // --- fuzz tools ---
    /// <summary>
    /// Constructs the full <see cref="Drederick.Recon.Fuzz.FuzzToolbox"/>
    /// with all 10 fuzz tools registered. Each tool re-checks scope
    /// internally; <see cref="Drederick.Recon.Fuzz.ProtocolFuzzTool"/>
    /// additionally consults <see cref="Drederick.Exploit.RunPermissions"/>
    /// (destructive opt-in) before any subprocess spawn.
    /// </summary>
    private static Drederick.Recon.Fuzz.FuzzToolbox BuildFuzzToolbox(
        Drederick.Scope.Scope scope,
        AuditLog audit,
        Drederick.Exploit.RunPermissions permissions)
    {
        var tools = new Drederick.Recon.Fuzz.IFuzzTool[]
        {
            new Drederick.Recon.Fuzz.WebParamFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.VhostFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.SubdomainFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.ApiEndpointFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.GraphqlFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.JwtFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.HeaderFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.ProtocolFuzzTool(scope, audit, permissions),
            new Drederick.Recon.Fuzz.FileFormatFuzzTool(scope, audit),
            new Drederick.Recon.Fuzz.LlmPayloadFuzzTool(scope, audit),
        };
        return new Drederick.Recon.Fuzz.FuzzToolbox(tools, audit);
    }

    private static void Emit(
        IProgress<ScanEvent>? progress,
        ScanEventKind kind,
        string? target = null,
        string? tool = null,
        string? message = null,
        int? toolCallsTotal = null)
    {
        progress?.Report(new ScanEvent(
            Kind: kind,
            Timestamp: DateTimeOffset.UtcNow,
            Target: target,
            Tool: tool,
            Message: message,
            ToolCallsTotal: toolCallsTotal));
    }
}

/// <summary>Summary of a completed <see cref="DrederickHost.RunAsync"/>.</summary>
public sealed record RunResult(
    int HostCount,
    int ToolCallsTotal,
    string OutputDir,
    string ScopeSource);
