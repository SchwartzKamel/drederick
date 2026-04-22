using System;
using System.Collections.Generic;
using Drederick.Jeopardy.Solver;

namespace Drederick.Jeopardy.Swarm;

/// <summary>
/// Aggregate result of a single <see cref="ISolverSwarm"/> race. <see cref="PerSolver"/>
/// is ordered to match <see cref="SwarmConfig.Models"/>, not completion order.
/// </summary>
public sealed record SwarmResult(
    int ChallengeId,
    string ChallengeName,
    SolverOutcome CombinedOutcome,
    IReadOnlyList<SolverRunResult> PerSolver,
    string? WinningSolverId,
    string? WinningModelId,
    TimeSpan TotalElapsed,
    decimal TotalUsdCost);
