using System;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Jeopardy.Ctfd;

namespace Drederick.Jeopardy.Solver;

/// <summary>
/// Terminal outcome of a single-model solver run against one Jeopardy
/// challenge. Ordered roughly from best to worst.
/// </summary>
public enum SolverOutcome
{
    Solved,
    Incorrect,
    GaveUp,
    Timeout,
    BudgetExceeded,
    LoopDetected,
    OutOfDepth,
    Error,
}

/// <summary>
/// Per-solver configuration. <see cref="WallClock"/> defaults to 20 minutes
/// when null; <see cref="PerChallengeBudgetUsd"/> is enforced locally in
/// addition to any env-var caps baked into the <c>ICostTracker</c>.
/// </summary>
public sealed record SolverConfig(
    string ModelId,
    int MaxTurns = 50,
    TimeSpan? WallClock = null,
    decimal? PerChallengeBudgetUsd = null,
    int MaxParallelToolCalls = 3,
    bool EnableBusInsights = true);

/// <summary>
/// Result of a <see cref="IChallengeSolver.SolveAsync"/> call. The flag is
/// stored as SHA-256 only — the plaintext never leaves
/// <see cref="Drederick.Jeopardy.Submit.IFlagSubmitCoordinator"/>.
/// </summary>
public sealed record SolverRunResult(
    string SolverId,
    string ModelId,
    int ChallengeId,
    SolverOutcome Outcome,
    string? FlagSubmitted,
    int Turns,
    TimeSpan Elapsed,
    decimal UsdCost,
    string? LoopKind,
    string? FailureReason);

/// <summary>
/// Tool-using LLM agent that races to solve one Jeopardy challenge. Multiple
/// instances (one per model) race per challenge via the
/// <c>FlagSubmitCoordinator</c>; the first correct submission wins and all
/// losers fast-exit with <see cref="SolverOutcome.GaveUp"/>.
/// </summary>
public interface IChallengeSolver
{
    Task<SolverRunResult> SolveAsync(CtfdChallenge chal, SolverConfig cfg, CancellationToken ct);
}
