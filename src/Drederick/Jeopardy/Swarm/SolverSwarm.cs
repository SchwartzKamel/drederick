using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;

namespace Drederick.Jeopardy.Swarm;

/// <summary>
/// Race coordinator for multi-model Jeopardy solvers. Spawns one
/// <see cref="IChallengeSolver"/> invocation per <see cref="SwarmModelSlot"/>
/// concurrently (bounded by <see cref="SwarmConfig.MaxParallelSolvers"/>),
/// cancels losers on first correct flag, enforces a per-challenge USD cap,
/// and aggregates per-solver outcomes.
/// </summary>
public interface ISolverSwarm
{
    Task<SwarmResult> RaceAsync(CtfdChallenge chal, SwarmConfig cfg, CancellationToken ct);
}

/// <inheritdoc cref="ISolverSwarm" />
public sealed class SolverSwarm : ISolverSwarm
{
    private readonly IChallengeSolver _solverFactory;
    private readonly IFlagSubmitCoordinator _flagSubmit;
    private readonly ISolverMessageBus _bus;
    private readonly ICostTracker _costs;
    private readonly AuditLog _audit;
    private readonly TimeSpan _budgetPollInterval;

    public SolverSwarm(
        IChallengeSolver solverFactory,
        IFlagSubmitCoordinator flagSubmit,
        ISolverMessageBus bus,
        ICostTracker costs,
        AuditLog audit)
        : this(solverFactory, flagSubmit, bus, costs, audit, TimeSpan.FromSeconds(5))
    {
    }

    internal SolverSwarm(
        IChallengeSolver solverFactory,
        IFlagSubmitCoordinator flagSubmit,
        ISolverMessageBus bus,
        ICostTracker costs,
        AuditLog audit,
        TimeSpan budgetPollInterval)
    {
        _solverFactory = solverFactory ?? throw new ArgumentNullException(nameof(solverFactory));
        _flagSubmit = flagSubmit ?? throw new ArgumentNullException(nameof(flagSubmit));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _costs = costs ?? throw new ArgumentNullException(nameof(costs));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _budgetPollInterval = budgetPollInterval > TimeSpan.Zero
            ? budgetPollInterval
            : TimeSpan.FromSeconds(5);
    }

    public async Task<SwarmResult> RaceAsync(CtfdChallenge chal, SwarmConfig cfg, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(chal);
        ArgumentNullException.ThrowIfNull(cfg);
        if (cfg.Models is null || cfg.Models.Count == 0)
        {
            throw new ArgumentException("SwarmConfig.Models must contain at least one slot.", nameof(cfg));
        }

        var n = cfg.Models.Count;
        var chalIdStr = chal.Id.ToString(CultureInfo.InvariantCulture);
        var maxParallel = Math.Max(1, cfg.MaxParallelSolvers);
        var coolOff = cfg.CoolOffBetweenStarts ?? TimeSpan.Zero;

        _audit.Record("swarm.race.start", new Dictionary<string, object?>
        {
            ["challenge_id"] = chal.Id,
            ["challenge"] = chal.Name,
            ["models_count"] = n,
            ["models"] = cfg.Models.Select(m => m.ModelId).ToArray(),
            ["max_parallel"] = maxParallel,
            ["wall_clock_seconds"] = (int)cfg.WallClockPerChallenge.TotalSeconds,
            ["total_budget_usd"] = cfg.TotalBudgetUsdPerChallenge?.ToString("F6", CultureInfo.InvariantCulture),
            ["cool_off_ms"] = (int)coolOff.TotalMilliseconds,
            ["cancel_losers_on_win"] = cfg.CancelLosersOnWin,
        });

        var swStart = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        using var outerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var perSlotCts = new CancellationTokenSource[n];
        var results = new SolverRunResult?[n];
        var slotStarts = new DateTimeOffset?[n];
        using var sem = new SemaphoreSlim(maxParallel, maxParallel);

        int budgetExceededFlag = 0;
        int cancelLosersAuditedOnce = 0;

        for (int i = 0; i < n; i++)
        {
            perSlotCts[i] = CancellationTokenSource.CreateLinkedTokenSource(outerCts.Token);
        }

        // Cancel-losers handler. Matches by winning ModelId; slots with a
        // different ModelId are cancelled. Slots sharing the winner's ModelId
        // are left alone — the winner is among them and will return Solved.
        void OnChallengeSolved(FlagOutcome outcome)
        {
            if (outcome.ChallengeId != chal.Id || !outcome.Correct)
            {
                return;
            }
            if (!cfg.CancelLosersOnWin)
            {
                return;
            }
            if (Interlocked.Exchange(ref cancelLosersAuditedOnce, 1) == 0)
            {
                _audit.Record("swarm.cancel_losers", new Dictionary<string, object?>
                {
                    ["challenge_id"] = chal.Id,
                    ["winner_solver_id"] = outcome.WinnerSolverId,
                    ["winner_model_id"] = outcome.WinnerModelId,
                });
            }
            for (int i = 0; i < n; i++)
            {
                if (!string.Equals(cfg.Models[i].ModelId, outcome.WinnerModelId, StringComparison.Ordinal))
                {
                    try { perSlotCts[i].Cancel(); }
                    catch (ObjectDisposedException) { }
                }
            }
        }

        _flagSubmit.ChallengeSolved += OnChallengeSolved;

        // Initial budget check — if already over, cancel everything before
        // spawning. Per-slot tasks will still produce a result record.
        if (IsOverBudget(cfg, chalIdStr))
        {
            Interlocked.Exchange(ref budgetExceededFlag, 1);
            try { outerCts.Cancel(); } catch (ObjectDisposedException) { }
        }

        var tasks = new Task[n];
        for (int i = 0; i < n; i++)
        {
            int idx = i;
            var slot = cfg.Models[idx];
            tasks[idx] = RunSlotAsync(
                chal,
                cfg,
                slot,
                idx,
                n,
                perSlotCts[idx],
                sem,
                coolOff,
                chalIdStr,
                results,
                slotStarts);
        }

        // Budget watchdog. Uses a dedicated CTS so we can stop it cleanly
        // once every slot task has finished.
        using var budgetWatcherCts = CancellationTokenSource.CreateLinkedTokenSource(outerCts.Token);
        Task budgetWatcher = cfg.TotalBudgetUsdPerChallenge.HasValue
            ? WatchBudgetAsync(cfg, chalIdStr, outerCts, budgetWatcherCts.Token, () => Interlocked.Exchange(ref budgetExceededFlag, 1))
            : Task.CompletedTask;

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            _flagSubmit.ChallengeSolved -= OnChallengeSolved;
            try { budgetWatcherCts.Cancel(); } catch (ObjectDisposedException) { }
            try { await budgetWatcher.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }
            for (int i = 0; i < n; i++)
            {
                perSlotCts[i].Dispose();
            }
        }

        sw.Stop();

        var perSolver = new SolverRunResult[n];
        for (int i = 0; i < n; i++)
        {
            perSolver[i] = results[i] ?? BuildCancelledResult(cfg.Models[i], chal, TimeSpan.Zero, "no-result");
        }

        SolverRunResult? winner = perSolver.FirstOrDefault(r => r.Outcome == SolverOutcome.Solved);
        SolverOutcome combined;
        if (winner is not null)
        {
            combined = SolverOutcome.Solved;
        }
        else if (Volatile.Read(ref budgetExceededFlag) == 1)
        {
            combined = SolverOutcome.BudgetExceeded;
        }
        else
        {
            combined = AggregateOutcome(perSolver);
        }

        decimal totalUsd = perSolver.Sum(r => r.UsdCost);
        var result = new SwarmResult(
            ChallengeId: chal.Id,
            ChallengeName: chal.Name,
            CombinedOutcome: combined,
            PerSolver: perSolver,
            WinningSolverId: winner?.SolverId,
            WinningModelId: winner?.ModelId,
            TotalElapsed: sw.Elapsed,
            TotalUsdCost: totalUsd);

        _audit.Record("swarm.race.finish", new Dictionary<string, object?>
        {
            ["challenge_id"] = chal.Id,
            ["challenge"] = chal.Name,
            ["outcome"] = combined.ToString(),
            ["winning_solver_id"] = result.WinningSolverId,
            ["winning_model_id"] = result.WinningModelId,
            ["total_usd"] = totalUsd.ToString("F6", CultureInfo.InvariantCulture),
            ["total_elapsed_ms"] = (long)sw.Elapsed.TotalMilliseconds,
            ["per_solver"] = perSolver.Select(r => new Dictionary<string, object?>
            {
                ["solver_id"] = r.SolverId,
                ["model"] = r.ModelId,
                ["outcome"] = r.Outcome.ToString(),
                ["turns"] = r.Turns,
                ["elapsed_ms"] = (long)r.Elapsed.TotalMilliseconds,
                ["usd_cost"] = r.UsdCost.ToString("F6", CultureInfo.InvariantCulture),
            }).ToArray(),
        });

        return result;
    }

    private async Task RunSlotAsync(
        CtfdChallenge chal,
        SwarmConfig cfg,
        SwarmModelSlot slot,
        int idx,
        int n,
        CancellationTokenSource slotCts,
        SemaphoreSlim sem,
        TimeSpan coolOff,
        string chalIdStr,
        SolverRunResult?[] results,
        DateTimeOffset?[] slotStarts)
    {
        var slotSw = new Stopwatch();
        try
        {
            if (coolOff > TimeSpan.Zero && idx > 0)
            {
                var delay = TimeSpan.FromMilliseconds(coolOff.TotalMilliseconds * idx);
                await Task.Delay(delay, slotCts.Token).ConfigureAwait(false);
            }

            await sem.WaitAsync(slotCts.Token).ConfigureAwait(false);
            try
            {
                slotCts.Token.ThrowIfCancellationRequested();

                slotStarts[idx] = DateTimeOffset.UtcNow;
                slotSw.Start();

                var perSlotBudget = slot.PerChallengeBudgetUsd;
                if (!perSlotBudget.HasValue && cfg.TotalBudgetUsdPerChallenge.HasValue)
                {
                    perSlotBudget = cfg.TotalBudgetUsdPerChallenge.Value / n;
                }

                var solverCfg = new SolverConfig(
                    ModelId: slot.ModelId,
                    MaxTurns: slot.MaxTurns,
                    WallClock: cfg.WallClockPerChallenge,
                    PerChallengeBudgetUsd: perSlotBudget);

                var runResult = await _solverFactory.SolveAsync(chal, solverCfg, slotCts.Token)
                    .ConfigureAwait(false);
                results[idx] = runResult;
            }
            finally
            {
                sem.Release();
            }
        }
        catch (OperationCanceledException)
        {
            results[idx] = BuildCancelledResult(slot, chal, slotSw.Elapsed, "cancelled");
        }
        catch (Exception ex)
        {
            results[idx] = new SolverRunResult(
                SolverId: SynthesizeSolverId(slot, chal),
                ModelId: slot.ModelId,
                ChallengeId: chal.Id,
                Outcome: SolverOutcome.Error,
                FlagSubmitted: null,
                Turns: 0,
                Elapsed: slotSw.Elapsed,
                UsdCost: 0m,
                LoopKind: null,
                FailureReason: ex.GetType().Name + ": " + ex.Message);
        }
    }

    private async Task WatchBudgetAsync(
        SwarmConfig cfg,
        string chalIdStr,
        CancellationTokenSource outerCts,
        CancellationToken ct,
        Action onExceeded)
    {
        try
        {
            using var timer = new PeriodicTimer(_budgetPollInterval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                if (IsOverBudget(cfg, chalIdStr))
                {
                    onExceeded();
                    _audit.Record("swarm.budget_exceeded", new Dictionary<string, object?>
                    {
                        ["challenge_id"] = chalIdStr,
                        ["cap_usd"] = cfg.TotalBudgetUsdPerChallenge?.ToString("F6", CultureInfo.InvariantCulture),
                        ["spent_usd"] = _costs.UsdForChallenge(chalIdStr).ToString("F6", CultureInfo.InvariantCulture),
                    });
                    try { outerCts.Cancel(); } catch (ObjectDisposedException) { }
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private bool IsOverBudget(SwarmConfig cfg, string chalIdStr)
    {
        if (!cfg.TotalBudgetUsdPerChallenge.HasValue) return false;
        var spent = _costs.UsdForChallenge(chalIdStr);
        return spent > cfg.TotalBudgetUsdPerChallenge.Value;
    }

    private static SolverRunResult BuildCancelledResult(
        SwarmModelSlot slot,
        CtfdChallenge chal,
        TimeSpan elapsed,
        string reason) => new(
            SolverId: SynthesizeSolverId(slot, chal),
            ModelId: slot.ModelId,
            ChallengeId: chal.Id,
            Outcome: SolverOutcome.GaveUp,
            FlagSubmitted: null,
            Turns: 0,
            Elapsed: elapsed,
            UsdCost: 0m,
            LoopKind: null,
            FailureReason: reason);

    private static string SynthesizeSolverId(SwarmModelSlot slot, CtfdChallenge chal)
        => string.Format(CultureInfo.InvariantCulture, "{0}@chal{1}", slot.ModelId, chal.Id);

    // Aggregation priority (spec):
    //   Solved > LoopDetected > Timeout > BudgetExceeded > GaveUp > Incorrect > Error
    // OutOfDepth is not in the spec list; we rank it alongside Error (lowest)
    // so it never masks a more informative peer outcome.
    private static SolverOutcome AggregateOutcome(IReadOnlyList<SolverRunResult> perSolver)
    {
        int best = int.MaxValue;
        SolverOutcome picked = SolverOutcome.Error;
        foreach (var r in perSolver)
        {
            int rank = PriorityRank(r.Outcome);
            if (rank < best)
            {
                best = rank;
                picked = r.Outcome;
            }
        }
        return picked;
    }

    private static int PriorityRank(SolverOutcome o) => o switch
    {
        SolverOutcome.Solved => 0,
        SolverOutcome.LoopDetected => 1,
        SolverOutcome.Timeout => 2,
        SolverOutcome.BudgetExceeded => 3,
        SolverOutcome.GaveUp => 4,
        SolverOutcome.Incorrect => 5,
        SolverOutcome.OutOfDepth => 6,
        SolverOutcome.Error => 7,
        _ => 99,
    };
}
