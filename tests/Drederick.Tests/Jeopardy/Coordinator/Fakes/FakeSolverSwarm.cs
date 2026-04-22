using System.Collections.Concurrent;
using System.Globalization;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Swarm;

namespace Drederick.Tests.Jeopardy.Coordinator.Fakes;

/// <summary>
/// Scripted <see cref="ISolverSwarm"/> for coordinator tests. Per-challenge
/// outcomes are registered via <see cref="SetScript"/>; the race honors the
/// supplied <see cref="CancellationToken"/> and optionally delays to let the
/// coordinator exercise parallelism / cancellation logic.
/// </summary>
internal sealed class FakeSolverSwarm : ISolverSwarm
{
    public sealed record Script(
        SolverOutcome Outcome,
        TimeSpan Delay,
        decimal UsdCost = 0m,
        string? WinningModelId = null,
        string? FlagPlaintext = null,
        bool Throw = false);

    private readonly ConcurrentDictionary<int, Script> _scripts = new();
    public readonly ConcurrentBag<int> StartedChallenges = new();
    public readonly ConcurrentBag<int> FinishedChallenges = new();
    public readonly ConcurrentBag<int> CancelledChallenges = new();
    public int ActiveCount;
    public int PeakConcurrent;
    public Script? DefaultScript { get; set; } = new Script(SolverOutcome.GaveUp, TimeSpan.FromMilliseconds(10));

    public void SetScript(int challengeId, Script script) => _scripts[challengeId] = script;

    public async Task<SwarmResult> RaceAsync(CtfdChallenge chal, SwarmConfig cfg, CancellationToken ct)
    {
        StartedChallenges.Add(chal.Id);
        var active = Interlocked.Increment(ref ActiveCount);
        UpdatePeak(active);
        try
        {
            var script = _scripts.TryGetValue(chal.Id, out var s)
                ? s
                : DefaultScript ?? new Script(SolverOutcome.GaveUp, TimeSpan.Zero);

            if (script.Throw)
            {
                throw new InvalidOperationException("scripted fault for challenge " + chal.Id);
            }

            try
            {
                if (script.Delay > TimeSpan.Zero)
                {
                    await Task.Delay(script.Delay, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                CancelledChallenges.Add(chal.Id);
                throw;
            }

            var winningModel = script.WinningModelId
                ?? (cfg.Models.Count > 0 ? cfg.Models[0].ModelId : "model-a");

            var perSolver = new List<SolverRunResult>();
            foreach (var slot in cfg.Models)
            {
                var isWinner = script.Outcome == SolverOutcome.Solved
                    && string.Equals(slot.ModelId, winningModel, StringComparison.Ordinal);
                SolverOutcome slotOutcome;
                if (script.Outcome == SolverOutcome.Solved)
                {
                    slotOutcome = isWinner ? SolverOutcome.Solved : SolverOutcome.GaveUp;
                }
                else
                {
                    slotOutcome = script.Outcome;
                }
                perSolver.Add(new SolverRunResult(
                    SolverId: string.Format(CultureInfo.InvariantCulture, "{0}@chal{1}", slot.ModelId, chal.Id),
                    ModelId: slot.ModelId,
                    ChallengeId: chal.Id,
                    Outcome: slotOutcome,
                    FlagSubmitted: isWinner ? script.FlagPlaintext : null,
                    Turns: 1,
                    Elapsed: script.Delay,
                    UsdCost: isWinner ? script.UsdCost : 0m,
                    LoopKind: null,
                    FailureReason: null));
            }

            FinishedChallenges.Add(chal.Id);

            var winnerRun = perSolver.FirstOrDefault(r => r.Outcome == SolverOutcome.Solved);
            return new SwarmResult(
                ChallengeId: chal.Id,
                ChallengeName: chal.Name,
                CombinedOutcome: script.Outcome,
                PerSolver: perSolver,
                WinningSolverId: winnerRun?.SolverId,
                WinningModelId: winnerRun?.ModelId,
                TotalElapsed: script.Delay,
                TotalUsdCost: script.UsdCost);
        }
        finally
        {
            Interlocked.Decrement(ref ActiveCount);
        }
    }

    private void UpdatePeak(int active)
    {
        int snap;
        do
        {
            snap = Volatile.Read(ref PeakConcurrent);
            if (active <= snap) return;
        } while (Interlocked.CompareExchange(ref PeakConcurrent, active, snap) != snap);
    }
}
