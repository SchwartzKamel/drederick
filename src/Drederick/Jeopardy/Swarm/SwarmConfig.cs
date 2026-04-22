using System;
using System.Collections.Generic;

namespace Drederick.Jeopardy.Swarm;

/// <summary>
/// One model slot in a <see cref="SwarmConfig"/>. <paramref name="PerChallengeBudgetUsd"/>
/// overrides the swarm-level split when set; otherwise the slot inherits
/// <c>TotalBudgetUsdPerChallenge / Models.Count</c>.
/// </summary>
public sealed record SwarmModelSlot(
    string ModelId,
    decimal? PerChallengeBudgetUsd = null,
    int MaxTurns = 50);

/// <summary>
/// Race configuration for <see cref="ISolverSwarm"/>. Multiple LLMs are
/// spawned per challenge; the first to submit a correct flag wins and
/// losers are cancelled (if <see cref="CancelLosersOnWin"/>).
/// </summary>
public sealed record SwarmConfig(
    IReadOnlyList<SwarmModelSlot> Models,
    TimeSpan WallClockPerChallenge,
    decimal? TotalBudgetUsdPerChallenge = null,
    int MaxParallelSolvers = 5,
    bool CancelLosersOnWin = true,
    TimeSpan? CoolOffBetweenStarts = null);
