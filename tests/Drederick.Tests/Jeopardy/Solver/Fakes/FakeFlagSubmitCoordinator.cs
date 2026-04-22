using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Submit;

namespace Drederick.Tests.Jeopardy.Solver.Fakes;

/// <summary>
/// Minimal in-memory <see cref="IFlagSubmitCoordinator"/> for solver tests.
/// Matches candidate flags (SHA-256 compared) against a canned correct flag
/// per challenge. Records all submissions. Safe for concurrent use.
/// </summary>
internal sealed class FakeFlagSubmitCoordinator : IFlagSubmitCoordinator
{
    private readonly object _gate = new();
    private readonly Dictionary<int, string> _correctByChallenge = new();
    private readonly Dictionary<int, FlagOutcome> _wins = new();
    private readonly List<FlagOutcome> _outcomes = new();
    public List<FlagCandidate> Submissions { get; } = new();

    public event Action<FlagOutcome>? ChallengeSolved;

    public void SetCorrect(int challengeId, string flag) => _correctByChallenge[challengeId] = flag;

    public void MarkSolvedByPeer(int challengeId, string flag, string peerSolverId = "peer@chal", string peerModelId = "peer-model")
    {
        var outcome = new FlagOutcome(
            ChallengeId: challengeId,
            Flag: flag,
            Correct: true,
            AlreadySolved: false,
            WinnerSolverId: peerSolverId,
            WinnerModelId: peerModelId,
            SubmittedAt: DateTimeOffset.UtcNow,
            Message: "peer win");
        lock (_gate)
        {
            _wins[challengeId] = outcome;
            _outcomes.Add(outcome);
        }
        ChallengeSolved?.Invoke(outcome);
    }

    public IReadOnlyList<FlagOutcome> Wins
    {
        get { lock (_gate) return _outcomes.ToArray(); }
    }

    public bool IsSolved(int challengeId)
    {
        lock (_gate) return _wins.ContainsKey(challengeId);
    }

    public Task<FlagOutcome?> SubmitCandidateAsync(FlagCandidate candidate, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        lock (_gate) Submissions.Add(candidate);

        lock (_gate)
        {
            if (_wins.TryGetValue(candidate.ChallengeId, out var existing))
            {
                return Task.FromResult<FlagOutcome?>(existing with
                {
                    AlreadySolved = true,
                    SubmittedAt = DateTimeOffset.UtcNow,
                });
            }
        }

        var normalized = FlagSubmitCoordinator.NormalizeFlag(candidate.Flag);
        if (_correctByChallenge.TryGetValue(candidate.ChallengeId, out var want)
            && string.Equals(want, normalized, StringComparison.Ordinal))
        {
            var outcome = new FlagOutcome(
                ChallengeId: candidate.ChallengeId,
                Flag: normalized,
                Correct: true,
                AlreadySolved: false,
                WinnerSolverId: candidate.SolverId,
                WinnerModelId: candidate.ModelId,
                SubmittedAt: DateTimeOffset.UtcNow,
                Message: "correct");
            lock (_gate)
            {
                _wins[candidate.ChallengeId] = outcome;
                _outcomes.Add(outcome);
            }
            ChallengeSolved?.Invoke(outcome);
            return Task.FromResult<FlagOutcome?>(outcome);
        }

        var incorrect = new FlagOutcome(
            ChallengeId: candidate.ChallengeId,
            Flag: normalized,
            Correct: false,
            AlreadySolved: false,
            WinnerSolverId: string.Empty,
            WinnerModelId: string.Empty,
            SubmittedAt: DateTimeOffset.UtcNow,
            Message: "incorrect");
        lock (_gate) _outcomes.Add(incorrect);
        return Task.FromResult<FlagOutcome?>(incorrect);
    }
}
