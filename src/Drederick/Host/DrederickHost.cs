using Drederick.Agent;
using Drederick.Audit;
using Drederick.Memory;
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
///     <c>@invariant-id:aggregate-not-execute</c> — this facade performs
///     enumeration only. It does NOT invoke the CVE annotator, the PoC
///     aggregator, or any enrichment stage that writes to <c>poc_cache</c>;
///     those stay gated behind the CLI for now.
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

        IReconAgentRunner runner;
        if (options.UseAgent)
        {
            var agentRunner = MicrosoftAgentRunner.TryCreateFromEnvironment(audit);
            if (agentRunner is null)
            {
                audit.Record("runner.fallback", new Dictionary<string, object?> { ["reason"] = "no_api_key" });
                Emit(progress, ScanEventKind.Info, message: "OPENAI_API_KEY not set; falling back to AdaptiveRunner.");
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

        return new ReconToolbox(
            new IReconTool[]
            {
                nmap, http, tls, dns,
                smb, ftp, ssh, snmp, ldap, rpc, kerberos,
                dnsAxfr, httpContentDiscovery, tlsCipherEnum,
            },
            audit);
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
