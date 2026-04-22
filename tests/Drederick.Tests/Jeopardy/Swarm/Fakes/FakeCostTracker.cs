using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Drederick.Jeopardy.Budget;

namespace Drederick.Tests.Jeopardy.Swarm.Fakes;

/// <summary>
/// In-memory <see cref="ICostTracker"/> for swarm tests. Exposes a setter
/// so a test can preload a per-challenge USD balance to drive the budget
/// watchdog path.
/// </summary>
internal sealed class FakeCostTracker : ICostTracker
{
    private readonly object _gate = new();
    private decimal _total;
    private readonly ConcurrentDictionary<string, decimal> _byChallenge = new();

    public void Preload(string challengeId, decimal usd)
    {
        lock (_gate)
        {
            _byChallenge[challengeId] = usd;
            _total += usd;
        }
    }

    public TokenCost Record(string modelId, int promptTokens, int completionTokens, string? challengeId, string? solverId)
    {
        var tc = new TokenCost(modelId, promptTokens, completionTokens, 0m, DateTimeOffset.UtcNow, challengeId, solverId);
        return tc;
    }

    public CostSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new CostSnapshot(_total, 0,
                new Dictionary<string, decimal>(),
                new Dictionary<string, decimal>(_byChallenge));
        }
    }

    public decimal TotalUsd { get { lock (_gate) return _total; } }

    public decimal UsdForChallenge(string challengeId)
    {
        _byChallenge.TryGetValue(challengeId, out var v);
        return v;
    }

    public void AssertWithinBudget(string? challengeId) { }
}
