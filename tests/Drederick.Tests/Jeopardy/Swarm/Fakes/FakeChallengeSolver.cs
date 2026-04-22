using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;

namespace Drederick.Tests.Jeopardy.Swarm.Fakes;

/// <summary>
/// Scripted <see cref="IChallengeSolver"/> for <c>SolverSwarm</c> tests.
/// Returns a configured <see cref="SolverOutcome"/> per model id, after an
/// optional delay, and respects the supplied <see cref="CancellationToken"/>
/// (throws <see cref="OperationCanceledException"/> when cancelled).
/// </summary>
internal sealed class FakeChallengeSolver : IChallengeSolver
{
    public sealed record Script(
        SolverOutcome Outcome,
        TimeSpan Delay,
        decimal UsdCost = 0m,
        string? FlagSubmitted = null,
        int Turns = 1,
        string? LoopKind = null,
        string? FailureReason = null,
        bool SubmitOnSolved = true);

    private readonly ConcurrentDictionary<string, Script> _scripts = new(StringComparer.Ordinal);
    private readonly IFlagSubmitCoordinator? _flagSubmit;

    public int ActiveCount;
    public int PeakConcurrent;
    public int CancelledCount;
    public int StartedCount;
    public ConcurrentBag<(string ModelId, DateTimeOffset At)> StartTimestamps { get; } = new();

    public FakeChallengeSolver(IFlagSubmitCoordinator? flagSubmit = null)
    {
        _flagSubmit = flagSubmit;
    }

    public void SetScript(string modelId, Script script) => _scripts[modelId] = script;

    public async Task<SolverRunResult> SolveAsync(CtfdChallenge chal, SolverConfig cfg, CancellationToken ct)
    {
        var solverId = string.Format(CultureInfo.InvariantCulture, "{0}@chal{1}", cfg.ModelId, chal.Id);
        var started = DateTimeOffset.UtcNow;
        StartTimestamps.Add((cfg.ModelId, started));
        Interlocked.Increment(ref StartedCount);

        var active = Interlocked.Increment(ref ActiveCount);
        UpdatePeak(active);

        try
        {
            if (!_scripts.TryGetValue(cfg.ModelId, out var script))
            {
                script = new Script(SolverOutcome.GaveUp, TimeSpan.Zero);
            }

            if (script.Delay > TimeSpan.Zero)
            {
                await Task.Delay(script.Delay, ct).ConfigureAwait(false);
            }

            if (script.Outcome == SolverOutcome.Solved && script.SubmitOnSolved && _flagSubmit is not null)
            {
                var flag = script.FlagSubmitted ?? "flag{fake}";
                await _flagSubmit.SubmitCandidateAsync(new FlagCandidate(
                    ChallengeId: chal.Id,
                    ChallengeName: chal.Name,
                    Flag: flag,
                    SolverId: solverId,
                    ModelId: cfg.ModelId,
                    At: DateTimeOffset.UtcNow), ct).ConfigureAwait(false);
            }

            var elapsed = DateTimeOffset.UtcNow - started;
            return new SolverRunResult(
                SolverId: solverId,
                ModelId: cfg.ModelId,
                ChallengeId: chal.Id,
                Outcome: script.Outcome,
                FlagSubmitted: script.FlagSubmitted,
                Turns: script.Turns,
                Elapsed: elapsed,
                UsdCost: script.UsdCost,
                LoopKind: script.LoopKind,
                FailureReason: script.FailureReason);
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref CancelledCount);
            throw;
        }
        finally
        {
            Interlocked.Decrement(ref ActiveCount);
        }
    }

    private void UpdatePeak(int active)
    {
        int snapshot;
        do
        {
            snapshot = Volatile.Read(ref PeakConcurrent);
            if (active <= snapshot) return;
        } while (Interlocked.CompareExchange(ref PeakConcurrent, active, snapshot) != snapshot);
    }
}
