using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Drederick.Scope;
using EmpireModuleResult = Drederick.PostEx.EmpireModuleResult;

namespace Drederick.Autopilot;

// ============================================================================
// Empire phase adapter interfaces
// ----------------------------------------------------------------------------
// The Empire infrastructure shipped in Wave B (EmpireServer,
// EmpireListenerProvisioner, EmpireStagerGenerator, EmpirePostExDispatcher)
// is concrete + sealed: it talks to a real Empire REST server over an
// HttpClient. The autopilot phase below depends only on these tiny
// adapter interfaces so tests can inject stubs without standing up Empire,
// and so the phase logic (scope re-checks, opt-in gates, audit chain,
// loot harvest) is exercised independently of transport plumbing.
// Production wiring wraps the concrete Wave-B classes in trivial adapters.
// ============================================================================

/// <summary>Adapter surface for the Empire C2 server lifecycle.</summary>
public interface IEmpireServer
{
    bool IsRunning { get; }
    Task StartAsync(CancellationToken ct = default);
    Task StopAsync(CancellationToken ct = default);
}

/// <summary>Adapter surface for idempotent listener provisioning.</summary>
public interface IEmpireListenerProvisioner
{
    Task<EmpireListener> EnsureListenerAsync(EmpireListenerSpec spec, CancellationToken ct = default);
}

/// <summary>Adapter surface for stager generation. The target is the
/// victim host the stager will be dropped on — implementations MUST
/// <c>_scope.Require(target)</c> before any network egress.</summary>
public interface IEmpireStagerGenerator
{
    Task<EmpireDeliveryArtifact> GenerateAsync(
        string listenerName,
        EmpireStagerKind kind,
        string target,
        CancellationToken ct = default);
}

/// <summary>Adapter surface for post-ex module dispatch. The dispatcher
/// is responsible for re-checking scope against <c>session.Host</c> and
/// for routing plaintext loot directly to <see cref="CredentialStore"/>.</summary>
public interface IEmpirePostExDispatcher
{
    Task<EmpireModuleResult> RunAsync(
        EmpireSession session,
        EmpirePostExAction action,
        IReadOnlyDictionary<string, string>? parameters = null,
        CancellationToken ct = default);
}

/// <summary>
/// Empire post-exploitation phase of the autopilot loop. Runs after the
/// primary exploit phase has had a chance to compromise hosts, then for
/// each compromised host:
/// <list type="number">
///   <item>Re-validates the host against <see cref="Drederick.Scope.Scope"/>
///   — every host the phase touches re-checks, even though the underlying
///   dispatcher also re-checks. Belt-and-braces.</item>
///   <item>Resolves any active Empire agent against
///   <see cref="SessionAgentMapper"/>.</item>
///   <item>If no agent is registered yet, generates a stager bound to the
///   provisioned listener and audits the artifact for downstream delivery
///   (delivery itself flows through the existing <see cref="ExploitRunner"/>
///   payload-staging path).</item>
///   <item>For every active session, dispatches the configured default
///   module set (<see cref="EmpirePhaseConfig.DefaultModules"/>) via the
///   injected <see cref="IEmpirePostExDispatcher"/>. The dispatcher pushes
///   captured plaintext into <see cref="CredentialStore"/> directly; only
///   SHA-256 digests reach the audit log.</item>
/// </list>
///
/// Hard rules enforced here (in addition to the per-tool checks):
/// <list type="bullet">
///   <item>Phase short-circuits with <c>autopilot.empire.phase.skipped</c>
///   when <see cref="EmpirePhaseConfig.Enabled"/> is false, or when
///   <see cref="RunPermissions.AllowPayloads"/> is false, or when the
///   compromised-host set is empty.</item>
///   <item>Modules categorised as <see cref="ExploitCategory.CredAttacks"/>
///   (mimikatz, lsadump, dcsync, ssh keys) require
///   <see cref="RunPermissions.AllowCredAttacks"/>; the phase pre-filters
///   them out when the gate is closed rather than letting the dispatcher
///   throw and inflate the failure count.</item>
///   <item>Plaintext credentials, stager bodies, and module bodies are
///   NEVER written to the audit log. SHA-256 + length only.</item>
/// </list>
/// </summary>
public sealed class EmpireAutopilotPhase
{
    public const string DefaultListenerName = "drederick-autopilot";
    public const string DefaultListenerHost = "0.0.0.0";
    public const int DefaultListenerPort = 8443;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly RunPermissions _permissions;
    private readonly EmpirePhaseConfig _config;
    private readonly IEmpireServer _server;
    private readonly IEmpireListenerProvisioner _listener;
    private readonly IEmpireStagerGenerator _stager;
    private readonly IEmpirePostExDispatcher _dispatcher;
    private readonly SessionAgentMapper _sessions;
    private readonly CredentialStore? _creds;
    private readonly EmpireListenerSpec _listenerSpec;

    public EmpireAutopilotPhase(
        Scope.Scope scope,
        AuditLog audit,
        RunPermissions permissions,
        EmpirePhaseConfig config,
        IEmpireServer server,
        IEmpireListenerProvisioner listener,
        IEmpireStagerGenerator stager,
        IEmpirePostExDispatcher dispatcher,
        SessionAgentMapper sessions,
        CredentialStore? creds = null,
        EmpireListenerSpec? listenerSpec = null)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _permissions = permissions ?? throw new ArgumentNullException(nameof(permissions));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _server = server ?? throw new ArgumentNullException(nameof(server));
        _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        _stager = stager ?? throw new ArgumentNullException(nameof(stager));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _creds = creds;
        _listenerSpec = listenerSpec
            ?? new EmpireListenerSpec(DefaultListenerName, DefaultListenerHost, DefaultListenerPort);
    }

    /// <summary>
    /// Run the phase. <paramref name="exploitationResults"/> is consumed
    /// only to derive the compromised-host set; the actual post-ex actions
    /// flow through <see cref="SessionAgentMapper"/>.
    /// </summary>
    public async Task<EmpireAutopilotReport> RunAsync(
        IReadOnlyList<ExploitActionResult> exploitationResults,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(exploitationResults);

        // --- gate 1: master flag --------------------------------------------
        if (!_config.Enabled)
        {
            _audit.Record("autopilot.empire.phase.skipped", new Dictionary<string, object?>
            {
                ["reason"] = "disabled",
            });
            return EmpireAutopilotReport.SkippedReport("disabled");
        }

        // --- gate 2: payloads opt-in ----------------------------------------
        if (!_permissions.AllowPayloads)
        {
            _audit.Record("autopilot.empire.phase.skipped", new Dictionary<string, object?>
            {
                ["reason"] = "allow_payloads_required",
            });
            return EmpireAutopilotReport.SkippedReport("allow_payloads_required");
        }

        // --- compromised-host set ------------------------------------------
        var compromisedHosts = ComputeCompromisedHosts(exploitationResults);
        if (compromisedHosts.Count == 0)
        {
            _audit.Record("autopilot.empire.phase.skipped", new Dictionary<string, object?>
            {
                ["reason"] = "no_compromised_hosts",
            });
            return EmpireAutopilotReport.SkippedReport("no_compromised_hosts");
        }

        _audit.Record("autopilot.empire.phase.start", new Dictionary<string, object?>
        {
            ["hosts"] = compromisedHosts.Count,
            ["allow_payloads"] = _permissions.AllowPayloads,
            ["allow_cred_attacks"] = _permissions.AllowCredAttacks,
            ["allow_destructive"] = _permissions.AllowDestructive,
            ["max_wait_seconds"] = (int)_config.MaxWait.TotalSeconds,
            ["checkin_wait_seconds"] = (int)_config.CheckinWait.TotalSeconds,
        });

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(_config.MaxWait);
        var token = linkedCts.Token;

        // --- bring up server + listener -------------------------------------
        try
        {
            if (!_server.IsRunning)
                await _server.StartAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _audit.Record("autopilot.empire.phase.finish", FinishFields(0, 0, 0, error: "cancelled_server_start"));
            return EmpireAutopilotReport.Failed("cancelled_server_start");
        }
        catch (Exception ex)
        {
            _audit.Record("autopilot.empire.phase.finish", FinishFields(0, 0, 0, error: $"server_start: {ex.Message}"));
            return EmpireAutopilotReport.Failed($"server_start: {ex.Message}");
        }

        EmpireListener listener;
        try
        {
            listener = await _listener.EnsureListenerAsync(_listenerSpec, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _audit.Record("autopilot.empire.phase.finish", FinishFields(0, 0, 0, error: "cancelled_listener"));
            return EmpireAutopilotReport.Failed("cancelled_listener");
        }
        catch (Exception ex)
        {
            _audit.Record("autopilot.empire.phase.finish", FinishFields(0, 0, 0, error: $"listener: {ex.Message}"));
            return EmpireAutopilotReport.Failed($"listener: {ex.Message}");
        }

        // --- per-host loop --------------------------------------------------
        var perHost = new List<EmpireHostPhaseResult>(compromisedHosts.Count);
        int modulesRun = 0;
        int loot = 0;
        foreach (var host in compromisedHosts)
        {
            if (token.IsCancellationRequested) break;

            EmpireHostPhaseResult hostResult;
            try
            {
                hostResult = await ProcessHostAsync(host, listener, token).ConfigureAwait(false);
            }
            catch (ScopeException ex)
            {
                _audit.Record("autopilot.empire.host_processed", new Dictionary<string, object?>
                {
                    ["host"] = host,
                    ["status"] = "scope_refused",
                    ["error"] = ex.Message,
                });
                hostResult = EmpireHostPhaseResult.ScopeRefused(host, ex.Message);
            }
            catch (OperationCanceledException)
            {
                _audit.Record("autopilot.empire.host_processed", new Dictionary<string, object?>
                {
                    ["host"] = host,
                    ["status"] = "cancelled",
                });
                hostResult = EmpireHostPhaseResult.Cancelled(host);
            }
            catch (Exception ex)
            {
                _audit.Record("autopilot.empire.host_processed", new Dictionary<string, object?>
                {
                    ["host"] = host,
                    ["status"] = "error",
                    ["error"] = ex.Message,
                });
                hostResult = EmpireHostPhaseResult.Failed(host, ex.Message);
            }
            perHost.Add(hostResult);
            modulesRun += hostResult.ModuleResults.Count;
            loot += hostResult.ModuleResults.Sum(r => r.ParsedFindings.Count);
        }

        _audit.Record("autopilot.empire.phase.finish", FinishFields(perHost.Count, modulesRun, loot));
        return new EmpireAutopilotReport(
            Enabled: true,
            Skipped: false,
            SkipReason: null,
            Error: null,
            ListenerId: listener.Id,
            ListenerName: listener.Name,
            HostResults: perHost);
    }

    private async Task<EmpireHostPhaseResult> ProcessHostAsync(
        string host, EmpireListener listener, CancellationToken ct)
    {
        // ============ SCOPE CHECK (first statement) ============
        // The dispatcher re-checks too, but a planner bug that smuggled in
        // an out-of-scope host would otherwise burn an entire delivery
        // round-trip before being caught.
        _scope.Require(host);

        _audit.Record("autopilot.empire.host_processed.start", new Dictionary<string, object?>
        {
            ["host"] = host,
            ["listener"] = listener.Name,
        });

        var agents = _sessions.GetAgentsByHost(host);
        var sessions = ResolveSessions(host, agents);

        EmpireDeliveryArtifact? stager = null;
        if (sessions.Count == 0)
        {
            // No agent yet — generate a stager for the host's likely
            // platform so the next pass (or a downstream ExploitRunner
            // delivery) has the artifact ready. We default to Windows
            // when we have no platform signal, since that's the modal
            // Empire deployment.
            var platform = InferPlatform(agents);
            var kind = _config.StagerKinds.TryGetValue(platform, out var k)
                ? k
                : EmpireStagerKind.Ps1;
            stager = await _stager.GenerateAsync(listener.Name, kind, host, ct).ConfigureAwait(false);
            _audit.Record("autopilot.empire.host_processed", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["status"] = "stager_generated",
                ["listener"] = listener.Name,
                ["stager_kind"] = kind.ToString().ToLowerInvariant(),
                ["payload_sha256"] = stager.PayloadSha256,
                ["payload_length"] = stager.PayloadLength,
                ["agents"] = 0,
            });
            return EmpireHostPhaseResult.StagedAwaitingCheckin(host, stager);
        }

        var moduleResults = new List<EmpireModuleResult>();
        foreach (var session in sessions)
        {
            if (ct.IsCancellationRequested) break;
            var platform = EmpireModuleCatalog.PlatformFor(session);
            if (!_config.DefaultModules.TryGetValue(platform, out var actions))
                continue;

            foreach (var action in actions)
            {
                if (ct.IsCancellationRequested) break;
                if (!IsActionPermitted(action, out var refusedReason))
                {
                    _audit.Record("autopilot.empire.module.skipped", new Dictionary<string, object?>
                    {
                        ["host"] = host,
                        ["agent_id"] = session.AgentId,
                        ["action"] = action.ToString(),
                        ["reason"] = refusedReason,
                    });
                    continue;
                }

                EmpireModuleResult result;
                try
                {
                    result = await _dispatcher.RunAsync(session, action, parameters: null, ct).ConfigureAwait(false);
                }
                catch (PermissionRefusedException ex)
                {
                    _audit.Record("autopilot.empire.module.skipped", new Dictionary<string, object?>
                    {
                        ["host"] = host,
                        ["agent_id"] = session.AgentId,
                        ["action"] = action.ToString(),
                        ["reason"] = $"permission: {ex.Message}",
                    });
                    continue;
                }
                moduleResults.Add(result);
            }
        }

        _audit.Record("autopilot.empire.host_processed", new Dictionary<string, object?>
        {
            ["host"] = host,
            ["status"] = "dispatched",
            ["listener"] = listener.Name,
            ["agents"] = sessions.Count,
            ["modules_run"] = moduleResults.Count,
            ["parsed_findings"] = moduleResults.Sum(r => r.ParsedFindings.Count),
        });

        return EmpireHostPhaseResult.Dispatched(host, sessions, moduleResults);
    }

    /// <summary>
    /// Compromised = at least one successful (non-skipped) exploit action
    /// for this target *or* an active Empire agent already on the host.
    /// Lateral-chain entry points (a pre-existing session opened in an
    /// earlier autopilot iteration) qualify even without a fresh
    /// exploitation success this round.
    /// </summary>
    internal IReadOnlyList<string> ComputeCompromisedHosts(IReadOnlyList<ExploitActionResult> results)
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var r in results)
        {
            if (r.Succeeded && !r.Skipped && !string.IsNullOrWhiteSpace(r.Action.Target))
                set.Add(r.Action.Target);
        }
        foreach (var (_, host, _) in _sessions.ListActiveAgents())
        {
            if (!string.IsNullOrWhiteSpace(host)) set.Add(host);
        }
        return set.ToList();
    }

    private bool IsActionPermitted(EmpirePostExAction action, out string reason)
    {
        var category = EmpireModuleCatalog.CategoryFor(action);
        switch (category)
        {
            case ExploitCategory.CredAttacks when !_permissions.AllowCredAttacks:
                reason = "allow_cred_attacks_required";
                return false;
            case ExploitCategory.Destructive when !_permissions.AllowDestructive:
                reason = "allow_destructive_required";
                return false;
            default:
                reason = string.Empty;
                return true;
        }
    }

    private static IReadOnlyList<EmpireSession> ResolveSessions(
        string host, IReadOnlyList<(string agentId, string host)> agents)
    {
        if (agents.Count == 0) return Array.Empty<EmpireSession>();
        var now = DateTimeOffset.UtcNow;
        var list = new List<EmpireSession>(agents.Count);
        foreach (var (agentId, agentHost) in agents)
        {
            list.Add(new EmpireSession(
                AgentId: agentId,
                Host: agentHost,
                User: string.Empty,
                Listener: string.Empty,
                OpenedAt: now));
        }
        return list;
    }

    private static EmpirePlatform InferPlatform(IReadOnlyList<(string agentId, string host)> agents)
    {
        // No active agents on this host (this is the stage-only branch);
        // default to Windows for the modal Empire deployment shape.
        return EmpirePlatform.Windows;
    }

    private static Dictionary<string, object?> FinishFields(
        int hosts, int modules, int parsedFindings, string? error = null)
    {
        var d = new Dictionary<string, object?>
        {
            ["hosts_processed"] = hosts,
            ["modules_run"] = modules,
            ["parsed_findings"] = parsedFindings,
        };
        if (error is not null) d["error"] = error;
        return d;
    }
}

/// <summary>
/// Per-host outcome inside <see cref="EmpireAutopilotReport.HostResults"/>.
/// One of: <c>scope_refused</c>, <c>cancelled</c>, <c>error</c>,
/// <c>staged_awaiting_checkin</c>, or <c>dispatched</c>.
/// </summary>
public sealed record EmpireHostPhaseResult(
    string Host,
    string Status,
    IReadOnlyList<EmpireSession> Sessions,
    IReadOnlyList<EmpireModuleResult> ModuleResults,
    EmpireDeliveryArtifact? Stager,
    string? Error)
{
    public static EmpireHostPhaseResult ScopeRefused(string host, string err) =>
        new(host, "scope_refused", Array.Empty<EmpireSession>(),
            Array.Empty<EmpireModuleResult>(), null, err);

    public static EmpireHostPhaseResult Cancelled(string host) =>
        new(host, "cancelled", Array.Empty<EmpireSession>(),
            Array.Empty<EmpireModuleResult>(), null, null);

    public static EmpireHostPhaseResult Failed(string host, string err) =>
        new(host, "error", Array.Empty<EmpireSession>(),
            Array.Empty<EmpireModuleResult>(), null, err);

    public static EmpireHostPhaseResult StagedAwaitingCheckin(string host, EmpireDeliveryArtifact stager) =>
        new(host, "staged_awaiting_checkin", Array.Empty<EmpireSession>(),
            Array.Empty<EmpireModuleResult>(), stager, null);

    public static EmpireHostPhaseResult Dispatched(
        string host,
        IReadOnlyList<EmpireSession> sessions,
        IReadOnlyList<EmpireModuleResult> modules) =>
        new(host, "dispatched", sessions, modules, null, null);
}

/// <summary>End-of-phase summary returned to <see cref="AutopilotRunner"/>.</summary>
public sealed record EmpireAutopilotReport(
    bool Enabled,
    bool Skipped,
    string? SkipReason,
    string? Error,
    int ListenerId,
    string? ListenerName,
    IReadOnlyList<EmpireHostPhaseResult> HostResults)
{
    public static EmpireAutopilotReport SkippedReport(string reason) =>
        new(false, true, reason, null, 0, null, Array.Empty<EmpireHostPhaseResult>());

    public static EmpireAutopilotReport Failed(string error) =>
        new(true, false, null, error, 0, null, Array.Empty<EmpireHostPhaseResult>());
}
