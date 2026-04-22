using System.Collections.Concurrent;
using System.Globalization;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Detection;
using Drederick.Jeopardy.Ops;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Jeopardy.Swarm;

namespace Drederick.Jeopardy.Coordinator;

/// <summary>
/// Top-level configuration for one Jeopardy competition run. Scope is
/// enforced against <see cref="CtfdUrl"/>'s host at coordinator boot,
/// before any tool interaction.
/// </summary>
public sealed record CoordinatorConfig(
    Uri CtfdUrl,
    string CtfdToken,
    IReadOnlyList<SwarmModelSlot> Models,
    TimeSpan WallClockPerChallenge,
    decimal? TotalRunBudgetUsd = null,
    decimal? PerChallengeBudgetUsd = null,
    int MaxConcurrentChallenges = 4,
    string? OperatorInboxPath = null,
    string? ReportOutputDir = null,
    TimeSpan? PollInterval = null,
    IReadOnlyList<string>? CategoryFilter = null,
    IReadOnlyList<int>? ChallengeIdFilter = null);

public interface ICtfCoordinator
{
    Task<CompetitionReport> RunAsync(CoordinatorConfig cfg, CancellationToken ct);
}

/// <summary>
/// Orchestrator for Drederick's Jeopardy division. Runs one competition:
/// polls CTFd, races a <see cref="ISolverSwarm"/> per unsolved challenge,
/// routes operator hints / loop-detector signals through the message bus,
/// caps total-run spend, and emits a <see cref="CompetitionReport"/>.
/// </summary>
public sealed class CtfCoordinator : ICtfCoordinator
{
    private readonly ICtfdClient _ctfd;
    private readonly ICtfdPoller _poller;
    private readonly ISolverSwarm _swarm;
    private readonly IFlagSubmitCoordinator _flagSubmit;
    private readonly ISolverMessageBus _bus;
    private readonly ICostTracker _costs;
    private readonly ILoopDetector _loopDetector;
    private readonly IOperatorInbox? _operatorInbox;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly TimeSpan _budgetWatchdogInterval;

    public CtfCoordinator(
        ICtfdClient ctfd,
        ICtfdPoller poller,
        ISolverSwarm swarm,
        IFlagSubmitCoordinator flagSubmit,
        ISolverMessageBus bus,
        ICostTracker costs,
        ILoopDetector loopDetector,
        IOperatorInbox? operatorInbox,
        Scope.Scope scope,
        AuditLog audit)
        : this(ctfd, poller, swarm, flagSubmit, bus, costs, loopDetector, operatorInbox, scope, audit,
              TimeSpan.FromSeconds(10))
    {
    }

    internal CtfCoordinator(
        ICtfdClient ctfd,
        ICtfdPoller poller,
        ISolverSwarm swarm,
        IFlagSubmitCoordinator flagSubmit,
        ISolverMessageBus bus,
        ICostTracker costs,
        ILoopDetector loopDetector,
        IOperatorInbox? operatorInbox,
        Scope.Scope scope,
        AuditLog audit,
        TimeSpan budgetWatchdogInterval)
    {
        _ctfd = ctfd ?? throw new ArgumentNullException(nameof(ctfd));
        _poller = poller ?? throw new ArgumentNullException(nameof(poller));
        _swarm = swarm ?? throw new ArgumentNullException(nameof(swarm));
        _flagSubmit = flagSubmit ?? throw new ArgumentNullException(nameof(flagSubmit));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _costs = costs ?? throw new ArgumentNullException(nameof(costs));
        _loopDetector = loopDetector ?? throw new ArgumentNullException(nameof(loopDetector));
        _operatorInbox = operatorInbox;
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _budgetWatchdogInterval = budgetWatchdogInterval > TimeSpan.Zero
            ? budgetWatchdogInterval
            : TimeSpan.FromSeconds(10);
    }

    public async Task<CompetitionReport> RunAsync(CoordinatorConfig cfg, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(cfg);
        if (cfg.Models is null || cfg.Models.Count == 0)
        {
            throw new ArgumentException("CoordinatorConfig.Models must contain at least one slot.", nameof(cfg));
        }

        // Defense in depth: fail fast at coordinator boot, even though the
        // caller already constructed ICtfdClient (which also checks).
        _scope.Require(cfg.CtfdUrl.Host);

        var startedAt = DateTimeOffset.UtcNow;
        _audit.Record("coordinator.start", new Dictionary<string, object?>
        {
            ["ctfd_host"] = cfg.CtfdUrl.Host,
            ["models"] = cfg.Models.Select(m => m.ModelId).ToArray(),
            ["model_count"] = cfg.Models.Count,
            ["max_concurrent_challenges"] = cfg.MaxConcurrentChallenges,
            ["wall_clock_per_challenge_s"] = (int)cfg.WallClockPerChallenge.TotalSeconds,
            ["total_run_budget_usd"] = cfg.TotalRunBudgetUsd?.ToString("F6", CultureInfo.InvariantCulture),
            ["per_challenge_budget_usd"] = cfg.PerChallengeBudgetUsd?.ToString("F6", CultureInfo.InvariantCulture),
            ["poll_interval_ms"] = cfg.PollInterval is { } p ? (long?)p.TotalMilliseconds : null,
            ["category_filter"] = cfg.CategoryFilter?.ToArray(),
            ["challenge_id_filter"] = cfg.ChallengeIdFilter?.ToArray(),
            ["operator_inbox"] = cfg.OperatorInboxPath is not null,
        });

        using var runCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var active = new ConcurrentDictionary<int, ActiveChallenge>();
        var limiter = new SemaphoreSlim(Math.Max(1, cfg.MaxConcurrentChallenges));
        var perChallengeResults = new ConcurrentDictionary<int, SwarmResult>();
        var skippedIds = new ConcurrentDictionary<int, string>();
        var attemptedCategories = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var discovered = new ConcurrentDictionary<int, CtfdChallenge>();
        int budgetExceededFlag = 0;

        var categorySet = cfg.CategoryFilter is { Count: > 0 }
            ? new HashSet<string>(cfg.CategoryFilter, StringComparer.OrdinalIgnoreCase)
            : null;
        var idSet = cfg.ChallengeIdFilter is { Count: > 0 }
            ? new HashSet<int>(cfg.ChallengeIdFilter)
            : null;

        // --- event wiring ---
        void OnLoopDetected(LoopReport lr)
        {
            try
            {
                var insight = new SolverInsight(
                    ChallengeId: lr.ChallengeId,
                    SolverId: "coordinator",
                    ModelId: "coordinator",
                    Kind: InsightKind.CoordinatorHint,
                    Summary: $"Loop detected: kind={lr.LoopKind}, reps={lr.Repetitions}. Break the pattern; try a different primitive.",
                    DetailsSha256: null,
                    Tags: new[] { "loop", lr.LoopKind, "solver:" + lr.SolverId },
                    At: DateTimeOffset.UtcNow);
                _ = _bus.PublishAsync(insight, runCts.Token).AsTask();
            }
            catch (Exception ex)
            {
                _audit.Record("coordinator.loop.route_error", new Dictionary<string, object?>
                {
                    ["error"] = ex.GetType().Name,
                });
            }
        }
        _loopDetector.LoopDetected += OnLoopDetected;

        void OnChallengeSolved(FlagOutcome outcome)
        {
            // Defense in depth: if somehow a swarm is still running for a
            // challenge that flipped to Solved via bus/submit events, cancel it.
            if (active.TryGetValue(outcome.ChallengeId, out var slot))
            {
                try { slot.Cts.Cancel(); } catch (ObjectDisposedException) { }
            }
        }
        _flagSubmit.ChallengeSolved += OnChallengeSolved;

        Func<OperatorMessage, Task>? inboxHandler = null;
        Func<OperatorMessage, Task>? shutdownHandler = null;
        if (_operatorInbox is not null)
        {
            inboxHandler = msg => HandleOperatorAsync(msg, cfg, active, runCts, skippedIds);
            shutdownHandler = async msg =>
            {
                _audit.Record("coordinator.shutdown", new Dictionary<string, object?>
                {
                    ["kind"] = msg.Kind,
                    ["reason"] = "operator",
                });
                try { runCts.Cancel(); } catch (ObjectDisposedException) { }
                await Task.CompletedTask.ConfigureAwait(false);
            };
            _operatorInbox.MessageReceived += inboxHandler;
            _operatorInbox.ShutdownRequested += shutdownHandler;
            if (!string.IsNullOrEmpty(cfg.OperatorInboxPath))
            {
                try
                {
                    await _operatorInbox.StartAsync(cfg.OperatorInboxPath!, runCts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _audit.Record("coordinator.inbox.error", new Dictionary<string, object?>
                    {
                        ["error"] = ex.GetType().Name + ": " + ex.Message,
                    });
                }
            }
        }

        // --- budget watchdog ---
        var budgetTask = cfg.TotalRunBudgetUsd.HasValue
            ? WatchRunBudgetAsync(cfg.TotalRunBudgetUsd.Value, runCts,
                () => Interlocked.Exchange(ref budgetExceededFlag, 1), runCts.Token)
            : Task.CompletedTask;

        // --- main stream loop ---
        try
        {
            try
            {
                await foreach (var change in _poller.StreamAsync(runCts.Token)
                    .WithCancellation(runCts.Token).ConfigureAwait(false))
                {
                    if (runCts.IsCancellationRequested) break;

                    switch (change.Kind)
                    {
                        case ChallengeChangeKind.Discovered:
                            discovered[change.Challenge.Id] = change.Challenge;
                            TryDispatch(change.Challenge, cfg, categorySet, idSet, active, limiter,
                                perChallengeResults, attemptedCategories, skippedIds, runCts);
                            break;
                        case ChallengeChangeKind.SolvedExternally:
                            if (active.TryGetValue(change.Challenge.Id, out var slot))
                            {
                                skippedIds[change.Challenge.Id] = "external_solve";
                                _audit.Record("coordinator.skipped", new Dictionary<string, object?>
                                {
                                    ["challenge_id"] = change.Challenge.Id,
                                    ["reason"] = "external_solve",
                                });
                                try { slot.Cts.Cancel(); } catch (ObjectDisposedException) { }
                            }
                            break;
                        case ChallengeChangeKind.Updated:
                            discovered[change.Challenge.Id] = change.Challenge;
                            break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on external / operator cancel.
            }
        }
        finally
        {
            _loopDetector.LoopDetected -= OnLoopDetected;
            _flagSubmit.ChallengeSolved -= OnChallengeSolved;
            if (_operatorInbox is not null)
            {
                if (inboxHandler is not null) _operatorInbox.MessageReceived -= inboxHandler;
                if (shutdownHandler is not null) _operatorInbox.ShutdownRequested -= shutdownHandler;
            }

            // Wait for all active swarms to settle.
            Task[] outstanding;
            outstanding = active.Values.Select(a => a.Task).ToArray();
            try { await Task.WhenAll(outstanding).ConfigureAwait(false); }
            catch { /* per-task errors captured inside run wrapper */ }

            try { runCts.Cancel(); } catch (ObjectDisposedException) { }
            try { await budgetTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }

            // Dispose disposables in reverse order of creation; always.
            if (_operatorInbox is not null)
            {
                try { await _operatorInbox.DisposeAsync().ConfigureAwait(false); } catch { }
            }
            try { await _poller.DisposeAsync().ConfigureAwait(false); } catch { }
            if (_bus is IAsyncDisposable busDisp)
            {
                try { await busDisp.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            limiter.Dispose();
        }

        var finishedAt = DateTimeOffset.UtcNow;
        var results = perChallengeResults.Values.ToArray();

        int pointsScored = 0;
        var solvesByModel = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var r in results)
        {
            if (r.CombinedOutcome == SolverOutcome.Solved)
            {
                if (discovered.TryGetValue(r.ChallengeId, out var chal))
                {
                    pointsScored += chal.Value;
                }
                if (!string.IsNullOrEmpty(r.WinningModelId))
                {
                    solvesByModel[r.WinningModelId!] = solvesByModel.GetValueOrDefault(r.WinningModelId!) + 1;
                }
            }
        }

        var report = new CompetitionReport(
            StartedAt: startedAt,
            FinishedAt: finishedAt,
            ChallengesDiscovered: discovered.Count,
            ChallengesSolved: results.Count(r => r.CombinedOutcome == SolverOutcome.Solved),
            ChallengesAttempted: results.Length,
            PointsScored: pointsScored,
            TotalUsdCost: _costs.Snapshot().TotalUsd,
            PerChallenge: results,
            SolvesByModel: solvesByModel,
            AttemptsByCategory: attemptedCategories.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase));

        if (!string.IsNullOrEmpty(cfg.ReportOutputDir))
        {
            try
            {
                Directory.CreateDirectory(cfg.ReportOutputDir);
                await File.WriteAllTextAsync(
                    Path.Combine(cfg.ReportOutputDir, "report.json"),
                    CompetitionReportRenderer.ToJson(report),
                    CancellationToken.None).ConfigureAwait(false);
                await File.WriteAllTextAsync(
                    Path.Combine(cfg.ReportOutputDir, "report.md"),
                    CompetitionReportRenderer.ToMarkdown(report),
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _audit.Record("coordinator.report.error", new Dictionary<string, object?>
                {
                    ["error"] = ex.GetType().Name + ": " + ex.Message,
                });
            }
        }

        _audit.Record("coordinator.finish", new Dictionary<string, object?>
        {
            ["discovered"] = report.ChallengesDiscovered,
            ["attempted"] = report.ChallengesAttempted,
            ["solved"] = report.ChallengesSolved,
            ["points"] = report.PointsScored,
            ["total_usd"] = report.TotalUsdCost.ToString("F6", CultureInfo.InvariantCulture),
            ["budget_exceeded"] = Volatile.Read(ref budgetExceededFlag) == 1,
        });

        return report;
    }

    private void TryDispatch(
        CtfdChallenge chal,
        CoordinatorConfig cfg,
        HashSet<string>? categorySet,
        HashSet<int>? idSet,
        ConcurrentDictionary<int, ActiveChallenge> active,
        SemaphoreSlim limiter,
        ConcurrentDictionary<int, SwarmResult> results,
        ConcurrentDictionary<string, int> attemptedCategories,
        ConcurrentDictionary<int, string> skipped,
        CancellationTokenSource runCts)
    {
        if (chal.Solved)
        {
            if (skipped.TryAdd(chal.Id, "already_solved"))
            {
                _audit.Record("coordinator.skipped", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["reason"] = "already_solved",
                });
            }
            return;
        }
        if (_flagSubmit.IsSolved(chal.Id))
        {
            if (skipped.TryAdd(chal.Id, "already_solved"))
            {
                _audit.Record("coordinator.skipped", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["reason"] = "already_solved",
                });
            }
            return;
        }
        if (idSet is not null && !idSet.Contains(chal.Id))
        {
            if (skipped.TryAdd(chal.Id, "id_filter"))
            {
                _audit.Record("coordinator.skipped", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["reason"] = "id_filter",
                });
            }
            return;
        }
        if (categorySet is not null && !categorySet.Contains(chal.Category))
        {
            if (skipped.TryAdd(chal.Id, "category_filter"))
            {
                _audit.Record("coordinator.skipped", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["reason"] = "category_filter",
                    ["category"] = chal.Category,
                });
            }
            return;
        }
        if (active.ContainsKey(chal.Id)) return;

        var chalCts = CancellationTokenSource.CreateLinkedTokenSource(runCts.Token);
        var slot = new ActiveChallenge(chalCts, null!);
        if (!active.TryAdd(chal.Id, slot))
        {
            chalCts.Dispose();
            return;
        }

        var task = RunChallengeAsync(chal, cfg, chalCts, limiter, results, active, attemptedCategories);
        slot = new ActiveChallenge(chalCts, task);
        active[chal.Id] = slot;
    }

    private async Task RunChallengeAsync(
        CtfdChallenge chal,
        CoordinatorConfig cfg,
        CancellationTokenSource chalCts,
        SemaphoreSlim limiter,
        ConcurrentDictionary<int, SwarmResult> results,
        ConcurrentDictionary<int, ActiveChallenge> active,
        ConcurrentDictionary<string, int> attemptedCategories)
    {
        try
        {
            await limiter.WaitAsync(chalCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _audit.Record("coordinator.challenge.cancelled_before_start", new Dictionary<string, object?>
            {
                ["challenge_id"] = chal.Id,
            });
            active.TryRemove(chal.Id, out _);
            chalCts.Dispose();
            return;
        }

        attemptedCategories.AddOrUpdate(
            string.IsNullOrEmpty(chal.Category) ? "(uncategorized)" : chal.Category,
            1, (_, c) => c + 1);

        _audit.Record("coordinator.challenge.start", new Dictionary<string, object?>
        {
            ["challenge_id"] = chal.Id,
            ["challenge_name"] = chal.Name,
            ["category"] = chal.Category,
            ["points"] = chal.Value,
        });

        try
        {
            // Fetch detail so solver has description + attachments.
            CtfdChallenge full = chal;
            try
            {
                full = await _ctfd.GetChallengeAsync(chal.Id, chalCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _audit.Record("coordinator.challenge.detail_error", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["error"] = ex.GetType().Name + ": " + ex.Message,
                });
            }

            var swarmCfg = new SwarmConfig(
                Models: cfg.Models,
                WallClockPerChallenge: cfg.WallClockPerChallenge,
                TotalBudgetUsdPerChallenge: cfg.PerChallengeBudgetUsd,
                MaxParallelSolvers: Math.Max(1, cfg.Models.Count),
                CancelLosersOnWin: true);

            SwarmResult swarmResult;
            try
            {
                swarmResult = await _swarm.RaceAsync(full, swarmCfg, chalCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                swarmResult = BuildCancelledResult(full);
            }
            catch (Exception ex)
            {
                _audit.Record("coordinator.challenge.error", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["error"] = ex.GetType().Name + ": " + ex.Message,
                });
                swarmResult = BuildErrorResult(full, ex);
            }

            results[chal.Id] = swarmResult;
            _audit.Record("coordinator.challenge.finish", new Dictionary<string, object?>
            {
                ["challenge_id"] = chal.Id,
                ["challenge_name"] = chal.Name,
                ["outcome"] = swarmResult.CombinedOutcome.ToString(),
                ["winning_model_id"] = swarmResult.WinningModelId,
                ["usd_cost"] = swarmResult.TotalUsdCost.ToString("F6", CultureInfo.InvariantCulture),
            });
        }
        finally
        {
            limiter.Release();
            active.TryRemove(chal.Id, out _);
            chalCts.Dispose();
        }
    }

    private static SwarmResult BuildCancelledResult(CtfdChallenge chal) =>
        new(
            ChallengeId: chal.Id,
            ChallengeName: chal.Name,
            CombinedOutcome: SolverOutcome.GaveUp,
            PerSolver: Array.Empty<SolverRunResult>(),
            WinningSolverId: null,
            WinningModelId: null,
            TotalElapsed: TimeSpan.Zero,
            TotalUsdCost: 0m);

    private static SwarmResult BuildErrorResult(CtfdChallenge chal, Exception ex) =>
        new(
            ChallengeId: chal.Id,
            ChallengeName: chal.Name,
            CombinedOutcome: SolverOutcome.Error,
            PerSolver: new[]
            {
                new SolverRunResult(
                    SolverId: "coordinator@chal" + chal.Id.ToString(CultureInfo.InvariantCulture),
                    ModelId: "coordinator",
                    ChallengeId: chal.Id,
                    Outcome: SolverOutcome.Error,
                    FlagSubmitted: null,
                    Turns: 0,
                    Elapsed: TimeSpan.Zero,
                    UsdCost: 0m,
                    LoopKind: null,
                    FailureReason: ex.GetType().Name + ": " + ex.Message),
            },
            WinningSolverId: null,
            WinningModelId: null,
            TotalElapsed: TimeSpan.Zero,
            TotalUsdCost: 0m);

    private async Task HandleOperatorAsync(
        OperatorMessage msg,
        CoordinatorConfig cfg,
        ConcurrentDictionary<int, ActiveChallenge> active,
        CancellationTokenSource runCts,
        ConcurrentDictionary<int, string> skipped)
    {
        var kind = (msg.Kind ?? "").Trim().ToLowerInvariant();
        int? chalId = null;
        if (int.TryParse(msg.ChallengeId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            chalId = parsed;
        }

        _audit.Record("coordinator.operator.routed", new Dictionary<string, object?>
        {
            ["kind"] = kind,
            ["challenge_id"] = chalId,
            ["target"] = chalId.HasValue ? "challenge:" + chalId.Value : "broadcast",
        });

        switch (kind)
        {
            case "hint":
                if (chalId.HasValue)
                {
                    try
                    {
                        await _bus.PublishAsync(BuildOperatorHint(
                            chalId.Value.ToString(CultureInfo.InvariantCulture),
                            msg.Body ?? string.Empty,
                            new[] { "op:hint" }), runCts.Token).ConfigureAwait(false);
                    }
                    catch { }
                }
                else
                {
                    foreach (var id in active.Keys.ToArray())
                    {
                        try
                        {
                            await _bus.PublishAsync(BuildOperatorHint(
                                id.ToString(CultureInfo.InvariantCulture),
                                msg.Body ?? string.Empty,
                                new[] { "op:hint", "broadcast" }), runCts.Token).ConfigureAwait(false);
                        }
                        catch { }
                    }
                }
                break;

            case "focus":
                if (chalId.HasValue)
                {
                    foreach (var kv in active.ToArray())
                    {
                        if (kv.Key != chalId.Value)
                        {
                            try { kv.Value.Cts.Cancel(); } catch (ObjectDisposedException) { }
                        }
                    }
                }
                break;

            case "skip":
                if (chalId.HasValue && active.TryGetValue(chalId.Value, out var slot))
                {
                    skipped[chalId.Value] = "operator_skip";
                    try { slot.Cts.Cancel(); } catch (ObjectDisposedException) { }
                }
                break;

            case "stop":
            case "shutdown":
                _audit.Record("coordinator.shutdown", new Dictionary<string, object?>
                {
                    ["kind"] = kind,
                    ["reason"] = "operator",
                });
                try { runCts.Cancel(); } catch (ObjectDisposedException) { }
                break;
        }
    }

    private async Task WatchRunBudgetAsync(
        decimal cap,
        CancellationTokenSource runCts,
        Action onExceeded,
        CancellationToken ct)
    {
        try
        {
            using var timer = new PeriodicTimer(_budgetWatchdogInterval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                var spent = _costs.Snapshot().TotalUsd;
                if (spent > cap)
                {
                    _audit.Record("coordinator.budget_exceeded", new Dictionary<string, object?>
                    {
                        ["cap_usd"] = cap.ToString("F6", CultureInfo.InvariantCulture),
                        ["spent_usd"] = spent.ToString("F6", CultureInfo.InvariantCulture),
                    });
                    onExceeded();
                    try { runCts.Cancel(); } catch (ObjectDisposedException) { }
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private sealed record ActiveChallenge(CancellationTokenSource Cts, Task Task);

    private static SolverInsight BuildOperatorHint(string challengeId, string body, IReadOnlyList<string> tags) =>
        new(
            ChallengeId: challengeId,
            SolverId: "operator",
            ModelId: "operator",
            Kind: InsightKind.OperatorHint,
            Summary: body,
            DetailsSha256: null,
            Tags: tags,
            At: DateTimeOffset.UtcNow);
}
