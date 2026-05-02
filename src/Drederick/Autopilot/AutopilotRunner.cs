using System.Collections.Concurrent;
using System.Diagnostics;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Scope;

namespace Drederick.Autopilot;

/// <summary>
/// Post-recon orchestrator — the cornerman in the Tatum corner. Consumes a
/// completed <see cref="HostFinding"/> set, asks
/// <see cref="ExploitationPlanner"/> for a fight card (prioritised action
/// list), works each opponent round-by-round through the appropriate
/// <see cref="IExploitTool"/>, harvests captured stdout for knockouts (CTF
/// flags), and feeds any credentials discovered back into
/// <see cref="CredentialStore"/> so subsequent rounds can chain them.
///
/// Every punch is re-validated through scope + permissions at the executing
/// tool — the runner never bypasses any gate, it just tees up calls. "I must
/// dissent" from any bypass. Failures do not abort the fight; they are
/// recorded and the next action runs.
/// </summary>
public sealed class AutopilotRunner
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly RunPermissions _permissions;
    private readonly NucleiRunner? _nuclei;
    private readonly PasswordSprayTool? _spray;
    private readonly CredentialStore _creds;
    private readonly ExploitationPlanner _planner;
    private readonly FlagExtractor _flagExtractor;
    private readonly string _outputRoot;
    private readonly int _maxIterations;
    private readonly int _maxActionsPerIteration;

    // --- AD-specific tools (optional; wired when in-scope DC detected) ---
    private readonly AsRepRoastTool? _asrep;
    private readonly KerberoastTool? _kerberoast;
    private readonly DelegationEnumTool? _delegationEnum;
    private readonly DcSyncDetectionTool? _dcSyncDetect;
    private readonly CertVulnerabilityEnumTool? _certVulnEnum;

    public AutopilotRunner(
        Scope.Scope scope,
        AuditLog audit,
        RunPermissions permissions,
        ExploitationPlanner planner,
        CredentialStore creds,
        FlagExtractor flagExtractor,
        string outputRoot,
        NucleiRunner? nuclei = null,
        PasswordSprayTool? spray = null,
        int maxIterations = 3,
        int maxActionsPerIteration = 64,
        AsRepRoastTool? asrep = null,
        KerberoastTool? kerberoast = null,
        DelegationEnumTool? delegationEnum = null,
        DcSyncDetectionTool? dcSyncDetect = null,
        CertVulnerabilityEnumTool? certVulnEnum = null)
    {
        _scope = scope;
        _audit = audit;
        _permissions = permissions;
        _planner = planner;
        _creds = creds;
        _flagExtractor = flagExtractor;
        _outputRoot = outputRoot;
        _nuclei = nuclei;
        _spray = spray;
        _maxIterations = Math.Max(1, maxIterations);
        _maxActionsPerIteration = Math.Max(1, maxActionsPerIteration);
        _asrep = asrep;
        _kerberoast = kerberoast;
        _delegationEnum = delegationEnum;
        _dcSyncDetect = dcSyncDetect;
        _certVulnEnum = certVulnEnum;
    }

    /// <summary>Run the autopilot loop. Returns an aggregate summary.</summary>
    public async Task<AutopilotReport> RunAsync(
        IReadOnlyList<HostFinding> findings, CancellationToken ct = default)
    {
        _audit.Record("autopilot.start", new Dictionary<string, object?>
        {
            ["hosts"] = findings.Count,
            ["allow_exec_pocs"] = _permissions.AllowExecPocs,
            ["allow_cred_attacks"] = _permissions.AllowCredAttacks,
            ["ack_lockout_risk"] = _permissions.AcknowledgeLockoutRisk,
            ["max_iterations"] = _maxIterations,
        });

        var allResults = new List<ExploitActionResult>();
        var flagsSeen = new ConcurrentDictionary<string, FlagMatch>();
        var executedIds = new HashSet<string>(StringComparer.Ordinal);
        int iteration = 0;
        int executed = 0;

        for (iteration = 0; iteration < _maxIterations; iteration++)
        {
            ct.ThrowIfCancellationRequested();
            var plan = _planner.Plan(findings, _creds, _permissions);
            var fresh = plan.Where(a => !executedIds.Contains(a.Id)).Take(_maxActionsPerIteration).ToList();

            _audit.Record("autopilot.iter", new Dictionary<string, object?>
            {
                ["iteration"] = iteration,
                ["planned"] = plan.Count,
                ["to_execute"] = fresh.Count,
            });

            if (fresh.Count == 0) break;

            foreach (var action in fresh)
            {
                ct.ThrowIfCancellationRequested();
                executedIds.Add(action.Id);
                var outcome = await ExecuteAsync(action, flagsSeen, ct).ConfigureAwait(false);
                allResults.Add(outcome);
                executed++;
            }
        }

        // Also scan the out/ directory once at the end for any flags that
        // landed on disk without going through captured stdout (nuclei JSON,
        // msf loot, manual writes).
        foreach (var m in _flagExtractor.ScanDirectory(_outputRoot))
        {
            flagsSeen.TryAdd(m.ValueSha256, m);
        }

        var flags = flagsSeen.Values.ToList();
        _audit.Record("autopilot.finish", new Dictionary<string, object?>
        {
            ["iterations"] = iteration,
            ["actions_executed"] = executed,
            ["successes"] = allResults.Count(r => r.Succeeded),
            ["flags"] = flags.Count,
            ["creds_known"] = _creds.Count,
        });

        return new AutopilotReport(
            Iterations: iteration,
            Actions: allResults,
            Flags: flags,
            KnownCredentials: _creds.List());
    }

    private async Task<ExploitActionResult> ExecuteAsync(
        ExploitAction action,
        ConcurrentDictionary<string, FlagMatch> flagsSeen,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        _audit.Record("autopilot.action.start", new Dictionary<string, object?>
        {
            ["id"] = action.Id,
            ["tool"] = action.Tool,
            ["target"] = action.Target,
            ["priority"] = action.Priority,
            ["reason"] = action.Reason,
        });

        // Belt-and-braces: the tool re-checks scope anyway, but we fail fast
        // (and audit) if the planner emitted something off-scope due to a bug.
        try { _scope.Require(action.Target); }
        catch (ScopeException ex)
        {
            return Skip(action, $"scope: {ex.Message}", sw);
        }

        try
        {
            switch (action.Tool)
            {
                case "nuclei":
                    return await RunNucleiAsync(action, flagsSeen, sw, ct).ConfigureAwait(false);
                case "password-spray":
                    return await RunSprayAsync(action, flagsSeen, sw, ct).ConfigureAwait(false);
                case "asrep-roast":
                    return await RunAsRepRoastAsync(action, sw, ct).ConfigureAwait(false);
                case "kerberoast":
                    return await RunKerberoastAsync(action, sw, ct).ConfigureAwait(false);
                case "delegation-enum":
                    return await RunDelegationEnumAsync(action, sw, ct).ConfigureAwait(false);
                case "dcsync-detect":
                    return await RunDcSyncDetectAsync(action, sw, ct).ConfigureAwait(false);
                case "cert-vuln-enum":
                    return await RunCertVulnEnumAsync(action, sw, ct).ConfigureAwait(false);
                default:
                    return Skip(action, $"unknown tool '{action.Tool}'", sw);
            }
        }
        catch (ScopeException ex) { return Fail(action, $"scope: {ex.Message}", sw); }
        catch (PermissionRefusedException ex) { return Skip(action, $"permission: {ex.Message}", sw); }
        catch (Exception ex) { return Fail(action, ex.Message, sw); }
    }

    private async Task<ExploitActionResult> RunNucleiAsync(
        ExploitAction action,
        ConcurrentDictionary<string, FlagMatch> flagsSeen,
        Stopwatch sw, CancellationToken ct)
    {
        if (_nuclei is null) return Skip(action, "nuclei runner not registered", sw);
        if (string.IsNullOrEmpty(action.Artifact)) return Skip(action, "missing template path", sw);
        if (string.IsNullOrEmpty(action.Url)) return Skip(action, "missing base URL", sw);

        var result = await _nuclei.RunAsync(action.Target, action.Artifact!, action.Url!, ct)
            .ConfigureAwait(false);
        sw.Stop();

        _flagExtractor.ScanText(result.Run.StdoutTruncated, $"nuclei:{action.Target}:{action.Port}", flagsSeen);
        var succeeded = result.Findings.Count > 0;
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = succeeded,
            ExitCode = result.Run.ExitCode,
            Error = result.Run.Error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunSprayAsync(
        ExploitAction action,
        ConcurrentDictionary<string, FlagMatch> flagsSeen,
        Stopwatch sw, CancellationToken ct)
    {
        if (_spray is null) return Skip(action, "spray runner not registered", sw);
        if (string.IsNullOrEmpty(action.Protocol)) return Skip(action, "missing protocol", sw);
        if (action.Cred is null) return Skip(action, "missing credential ref", sw);

        var secret = _creds.TryGetSecret(action.Cred);
        if (secret is null) return Skip(action, "credential not in store", sw);

        var result = await _spray.RunAsync(
            action.Target, action.Protocol!, action.Cred.User, secret, action.Cred.Realm, ct)
            .ConfigureAwait(false);
        sw.Stop();

        _creds.RecordAttempt(action.Target, action.Protocol!, action.Cred, result.Succeeded);
        _flagExtractor.ScanText(result.Run.StdoutTruncated, $"spray:{action.Target}:{action.Protocol}", flagsSeen);
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = result.Succeeded,
            ExitCode = result.Run.ExitCode,
            Error = result.Run.Error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunAsRepRoastAsync(
        ExploitAction action, Stopwatch sw, CancellationToken ct)
    {
        if (_asrep is null) return Skip(action, "asrep-roast tool not registered", sw);
        if (string.IsNullOrEmpty(action.Realm)) return Skip(action, "missing realm", sw);
        if (action.Cred is null) return Skip(action, "missing credential ref for authenticated asrep-roast", sw);

        var secret = _creds.TryGetSecret(action.Cred);
        if (secret is null) return Skip(action, "credential not in store", sw);

        var result = await _asrep.RunAsync(
            action.Target,
            action.Realm!,
            authUser: action.Cred.User,
            authPassword: secret,
            ct: ct)
            .ConfigureAwait(false);
        sw.Stop();
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = result.Hashes.Count > 0,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunKerberoastAsync(
        ExploitAction action, Stopwatch sw, CancellationToken ct)
    {
        if (_kerberoast is null) return Skip(action, "kerberoast tool not registered", sw);
        if (string.IsNullOrEmpty(action.Realm)) return Skip(action, "missing realm", sw);
        if (action.Cred is null) return Skip(action, "missing credential ref", sw);

        var secret = _creds.TryGetSecret(action.Cred);
        if (secret is null) return Skip(action, "credential not in store", sw);

        var result = await _kerberoast.RunAsync(
            action.Target, action.Realm!, action.Cred.User, secret, ct: ct)
            .ConfigureAwait(false);
        sw.Stop();
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = result.Tickets.Count > 0,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunDelegationEnumAsync(
        ExploitAction action, Stopwatch sw, CancellationToken ct)
    {
        if (_delegationEnum is null) return Skip(action, "delegation-enum tool not registered", sw);
        var result = await _delegationEnum.ProbeAsync(action.Target, action.Port, ct: ct)
            .ConfigureAwait(false);
        sw.Stop();
        var found = result.Unconstrained.Count + result.Constrained.Count +
                    result.ConstrainedWithProtocolTransition.Count + result.Rbcd.Count;
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = found > 0,
            Error = result.Error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunDcSyncDetectAsync(
        ExploitAction action, Stopwatch sw, CancellationToken ct)
    {
        if (_dcSyncDetect is null) return Skip(action, "dcsync-detect tool not registered", sw);
        var result = await _dcSyncDetect.ProbeAsync(action.Target, action.Port, ct: ct)
            .ConfigureAwait(false);
        sw.Stop();
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = result.SuspiciousPrincipals.Count > 0,
            Error = result.Error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private async Task<ExploitActionResult> RunCertVulnEnumAsync(
        ExploitAction action, Stopwatch sw, CancellationToken ct)
    {
        if (_certVulnEnum is null) return Skip(action, "cert-vuln-enum tool not registered", sw);
        var result = await _certVulnEnum.ProbeAsync(action.Target, action.Port, ct: ct)
            .ConfigureAwait(false);
        sw.Stop();
        var found = result.VulnerableTemplates.Count + result.EnrollmentServices.Count;
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = found > 0,
            Error = result.Error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private ExploitActionResult Skip(ExploitAction a, string reason, Stopwatch sw)
    {
        sw.Stop();
        _audit.Record("autopilot.action.skip", new Dictionary<string, object?>
        {
            ["id"] = a.Id,
            ["tool"] = a.Tool,
            ["target"] = a.Target,
            ["reason"] = reason,
        });
        return new ExploitActionResult
        {
            Action = a,
            Skipped = true,
            SkipReason = reason,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }

    private ExploitActionResult Fail(ExploitAction a, string error, Stopwatch sw)
    {
        sw.Stop();
        _audit.Record("autopilot.action.fail", new Dictionary<string, object?>
        {
            ["id"] = a.Id,
            ["tool"] = a.Tool,
            ["target"] = a.Target,
            ["error"] = error,
        });
        return new ExploitActionResult
        {
            Action = a,
            Succeeded = false,
            Error = error,
            DurationMs = sw.ElapsedMilliseconds,
        };
    }
}

/// <summary>End-of-run summary returned to the CLI for reporting.</summary>
public sealed record AutopilotReport(
    int Iterations,
    IReadOnlyList<ExploitActionResult> Actions,
    IReadOnlyList<FlagMatch> Flags,
    IReadOnlyList<CredentialRef> KnownCredentials);
