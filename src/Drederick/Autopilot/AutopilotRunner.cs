using System.Collections.Concurrent;
using System.Diagnostics;
using Drederick.Audit;
using Drederick.Enrichment;
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
    private readonly MsfRcRunner? _msf;
    private readonly PocAggregator? _pocAggregator;
    private readonly CveLeadLlmAuthor? _cveLeadLlmAuthor;
    private readonly bool _fetchPoc;
    private readonly CredentialStore _creds;
    private readonly ExploitationPlanner _planner;
    private readonly FlagExtractor _flagExtractor;
    private readonly string _outputRoot;
    private readonly int _maxIterations;
    private readonly int _maxActionsPerIteration;

    // GAP-033 — per-RunAsync map of CVE id → fetch outcome. Loop guard for
    // the cve-lead → on-demand-fetch → re-plan loop: one fetch attempt per
    // CVE per autopilot run. Subsequent encounters of the same CVE within
    // the same RunAsync skip cleanly without re-querying sources.
    private enum CveFetchOutcome { Succeeded, Empty }

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
        MsfRcRunner? msf = null,
        PocAggregator? pocAggregator = null,
        CveLeadLlmAuthor? cveLeadLlmAuthor = null,
        bool fetchPoc = true,
        int maxIterations = 3,
        int maxActionsPerIteration = 64)
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
        _msf = msf;
        _pocAggregator = pocAggregator;
        _cveLeadLlmAuthor = cveLeadLlmAuthor;
        _fetchPoc = fetchPoc;
        _maxIterations = Math.Max(1, maxIterations);
        _maxActionsPerIteration = Math.Max(1, maxActionsPerIteration);
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
        // GAP-033 loop guard — one fetch attempt per CVE per RunAsync.
        var cveFetchTried = new Dictionary<string, CveFetchOutcome>(StringComparer.OrdinalIgnoreCase);
        // cve-lead-llm-author-fallback loop guard — one LLM-author attempt
        // per (cve, target) tuple per RunAsync. Keyed via
        // CveLeadLlmAuthor.MakeAttemptKey so the planner re-emitting the
        // same dead lead never costs additional LLM calls. Thread-safe
        // because exec_shell results may flow back from concurrent shell
        // runners in future revisions.
        var cveLlmAttempted = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
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
                var outcome = await ExecuteAsync(action, flagsSeen, cveFetchTried, cveLlmAttempted, ct).ConfigureAwait(false);
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
        Dictionary<string, CveFetchOutcome> cveFetchTried,
        ConcurrentDictionary<string, byte> cveLlmAttempted,
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
                case "msfrc":
                    return await RunMsfRcAsync(action, flagsSeen, sw, ct).ConfigureAwait(false);
                case "password-spray":
                    return await RunSprayAsync(action, flagsSeen, sw, ct).ConfigureAwait(false);
                case "cve-lead":
                    // GAP-033 — route the lead instead of dead-ending it.
                    // GAP-031 made the planner emit a band-250 cve-lead
                    // when a CVE matched but no cached PoC artifact was
                    // present at recon-enrichment time. This arm now asks
                    // PocAggregator to fetch on demand for the single CVE.
                    // On success the cache is populated and the next
                    // autopilot iteration's planner pass naturally emits
                    // the corresponding band-490 msfrc / band-500 nuclei
                    // action (different StableId from the lead, so it
                    // bypasses executedIds dedup). On failure we audit
                    // cve.lead.unfetchable and mark the CVE as a dead end
                    // for the rest of this RunAsync so subsequent leads
                    // for the same id skip without re-querying sources.
                    return await RunCveLeadAsync(action, cveFetchTried, cveLlmAttempted, flagsSeen, sw, ct).ConfigureAwait(false);
                default:
                    return Skip(action, $"unknown tool '{action.Tool}'", sw);
            }
        }
        catch (ScopeException ex) { return Fail(action, $"scope: {ex.Message}", sw); }
        catch (PermissionRefusedException ex) { return Skip(action, $"permission: {ex.Message}", sw); }
        catch (Exception ex) { return Fail(action, ex.Message, sw); }
    }

    private async Task<ExploitActionResult> RunCveLeadAsync(
        ExploitAction action,
        Dictionary<string, CveFetchOutcome> cveFetchTried,
        ConcurrentDictionary<string, byte> cveLlmAttempted,
        ConcurrentDictionary<string, FlagMatch> flagsSeen,
        Stopwatch sw, CancellationToken ct)
    {
        var cveId = action.CveId;
        if (string.IsNullOrWhiteSpace(cveId))
            return Skip(action, "cve-lead: missing cve id", sw);
        var key = cveId.ToUpperInvariant();

        // --no-fetch-poc: keep the lead in the audit trail (band-250 still
        // emitted) but don't reach for sources.
        if (!_fetchPoc)
        {
            return Skip(action,
                $"cve-lead: {key} — fetch disabled (--no-fetch-poc)", sw);
        }

        if (_pocAggregator is null)
        {
            return Skip(action,
                $"cve-lead: {key} — poc aggregator not registered, manual fetch required", sw);
        }

        // Loop guard: only one fetch per CVE per RunAsync. Subsequent
        // encounters short-circuit deterministically.
        if (cveFetchTried.TryGetValue(key, out var prior))
        {
            var reason = prior == CveFetchOutcome.Succeeded
                ? $"cve-lead: {key} — already fetched this run, awaiting next iteration's plan"
                : $"cve-lead: {key} — prior on-demand fetch returned no artifact (dead lead)";
            return Skip(action, reason, sw);
        }

        PocAggregator.FetchOnDemandResult result;
        try
        {
            result = await _pocAggregator.FetchOnDemandAsync(key, _outputRoot, _fetchPoc, ct)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Source-level failures are swallowed inside the aggregator;
            // anything reaching here is a configuration / I/O bug. Mark the
            // CVE so we don't retry within this run, audit, and move on.
            cveFetchTried[key] = CveFetchOutcome.Empty;
            _audit.Record("cve.lead.unfetchable", new Dictionary<string, object?>
            {
                ["id"] = action.Id,
                ["cve"] = key,
                ["target"] = action.Target,
                ["port"] = action.Port,
                ["error"] = ex.Message,
            });
            return Skip(action, $"cve-lead: {key} — fetch error: {ex.Message}", sw);
        }

        if (result.ArtifactCount > 0)
        {
            cveFetchTried[key] = CveFetchOutcome.Succeeded;
            _audit.Record("cve.lead.fetched", new Dictionary<string, object?>
            {
                ["id"] = action.Id,
                ["cve"] = key,
                ["target"] = action.Target,
                ["port"] = action.Port,
                ["refs"] = result.RefCount,
                ["cached"] = result.ArtifactCount,
                ["sources"] = string.Join(",", result.SourcesWithArtifact),
            });
            sw.Stop();
            return new ExploitActionResult
            {
                Action = action,
                Succeeded = true,
                Skipped = true,
                SkipReason =
                    $"cve-lead: {key} — fetched {result.ArtifactCount} artifact(s) from " +
                    $"{string.Join(",", result.SourcesWithArtifact)}; next iteration will re-plan",
                DurationMs = sw.ElapsedMilliseconds,
            };
        }

        cveFetchTried[key] = CveFetchOutcome.Empty;

        // cve-lead-llm-author-fallback — last-chance authoring path. The
        // facts.htb R3+R4 fights showed 640/640 cve-leads dead-ending here
        // because no source had a cached or on-demand artifact. The R5 win
        // came from a Copilot driver authoring shell commands from CVE
        // knowledge. This bridges that gap: prompt the LLM with structured
        // context and the bounded exec_shell handle, then feed any
        // authored-and-run result back into the autopilot loop.
        //
        // Every gate (AllowCveLeadLlmAuthor master, AllowExecShell
        // dependency, no-LLM-key, attempted dedup) is enforced inside
        // CveLeadLlmAuthor.TryAuthorAsync; failures fall through to the
        // pre-existing unfetchable skip without disturbing the audit chain.
        if (_cveLeadLlmAuthor is not null)
        {
            CveLeadLlmAuthorResult llmResult;
            try
            {
                llmResult = await _cveLeadLlmAuthor.TryAuthorAsync(action, cveLlmAttempted, ct)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch (ScopeException ex)
            {
                // Defense-in-depth scope refusal from the bridge — propagate
                // through the standard ExecuteAsync ScopeException handler
                // shape so the audit chain matches every other tool.
                _audit.Record("cve.lead.unfetchable", new Dictionary<string, object?>
                {
                    ["id"] = action.Id,
                    ["cve"] = key,
                    ["target"] = action.Target,
                    ["port"] = action.Port,
                    ["refs"] = result.RefCount,
                    ["reason"] = $"scope_refused: {ex.Message}",
                });
                return Fail(action, $"scope: {ex.Message}", sw);
            }

            if (llmResult.DidAuthorShell && llmResult.ShellResult is { } shell)
            {
                _flagExtractor.ScanText(shell.StdoutTruncated,
                    $"cve-lead-llm:{action.Target}:{action.Port}", flagsSeen);
                _audit.Record("cve.lead.unfetchable", new Dictionary<string, object?>
                {
                    ["id"] = action.Id,
                    ["cve"] = key,
                    ["target"] = action.Target,
                    ["port"] = action.Port,
                    ["refs"] = result.RefCount,
                    ["reason"] = "llm_authored_exec_shell",
                    ["argv_digest"] = shell.ArgvDigest,
                    ["exit_code"] = shell.ExitCode,
                });
                sw.Stop();
                return new ExploitActionResult
                {
                    Action = action,
                    Succeeded = shell.ExitCode == 0 && !shell.KilledOnTimeout,
                    ExitCode = shell.ExitCode,
                    Error = shell.Error,
                    DurationMs = sw.ElapsedMilliseconds,
                };
            }
            // Skip / no-key / disabled / error / already-attempted all
            // fall through to the standard unfetchable skip — the bridge
            // has already audited the detailed reason in its own event
            // chain (cve.lead.llm_author.*).
        }

        _audit.Record("cve.lead.unfetchable", new Dictionary<string, object?>
        {
            ["id"] = action.Id,
            ["cve"] = key,
            ["target"] = action.Target,
            ["port"] = action.Port,
            ["refs"] = result.RefCount,
            ["reason"] = "no source returned an artifact",
        });
        return Skip(action,
            $"cve-lead: {key} — no source had artifact (refs={result.RefCount}, cached=0)", sw);
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

    private async Task<ExploitActionResult> RunMsfRcAsync(
        ExploitAction action,
        ConcurrentDictionary<string, FlagMatch> flagsSeen,
        Stopwatch sw, CancellationToken ct)
    {
        if (_msf is null) return Skip(action, "msf runner not registered", sw);
        if (string.IsNullOrWhiteSpace(action.Module)) return Skip(action, "missing metasploit module", sw);
        if (action.Options.Count == 0) return Skip(action, "missing metasploit options", sw);

        var result = await _msf.RunAsync(action.Target, action.Module!, action.Options, ct)
            .ConfigureAwait(false);
        sw.Stop();

        _flagExtractor.ScanText(result.Run.StdoutTruncated, $"msfrc:{action.Target}:{action.Port}", flagsSeen);
        return new ExploitActionResult
        {
            Action = action,
            Succeeded = result.SessionOpened || result.Run.ExitCode == 0,
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
