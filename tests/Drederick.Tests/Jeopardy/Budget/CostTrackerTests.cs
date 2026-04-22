using System.Collections.Concurrent;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Budget;

/// <summary>
/// Deterministic price fixture for tests. Known model "m-known" at
/// $1/$2 per million tokens; "m-cheap" at $0.10/$0.20; everything else
/// returns zero (i.e. "unknown model").
/// </summary>
file sealed class FixturePrices : ICostPriceTable
{
    public (decimal inputPerMTok, decimal outputPerMTok) For(string modelId) =>
        modelId switch
        {
            "m-known" => (1.0m, 2.0m),
            "m-cheap" => (0.10m, 0.20m),
            _ => (0m, 0m),
        };
}

public class CostTrackerTests : IDisposable
{
    private readonly string _workDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;

    public CostTrackerTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-cost-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _auditPath = Path.Combine(_workDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        // Clear potentially-leaking env vars so the default-arg ctor path
        // doesn't inherit caps from a surrounding test run.
        Environment.SetEnvironmentVariable("DREDERICK_BUDGET_RUN_USD", null);
        Environment.SetEnvironmentVariable("DREDERICK_BUDGET_CHALLENGE_USD", null);
        Environment.SetEnvironmentVariable("DREDERICK_BUDGET_STRICT", null);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private IReadOnlyList<JsonElement> ReadAuditEvents(string? @event = null)
    {
        _audit.Dispose();
        var lines = File.ReadAllLines(_auditPath);
        var docs = lines
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Select(l => JsonDocument.Parse(l).RootElement)
            .ToList();
        if (@event is null) return docs;
        return docs.Where(d => d.GetProperty("event").GetString() == @event).ToList();
    }

    [Fact]
    public void Record_KnownModel_ComputesCorrectUsd()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        // 1M prompt @ $1 + 500k completion @ $2 = $1 + $1 = $2
        var tc = t.Record("m-known", 1_000_000, 500_000, "chal-a", "solver-1");
        Assert.Equal(2.0m, tc.UsdCost);
        Assert.Equal(2.0m, t.TotalUsd);
    }

    [Fact]
    public void Record_UnknownModel_ReturnsZero_AndAuditsOnce()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        t.Record("nope-1", 1_000_000, 1_000_000, "c", "s");
        t.Record("nope-1", 2_000_000, 2_000_000, "c", "s");
        t.Record("nope-1", 3_000_000, 3_000_000, "c", "s");
        Assert.Equal(0m, t.TotalUsd);

        var warnings = ReadAuditEvents("cost.unknown_model");
        Assert.Single(warnings);
        Assert.Equal("nope-1", warnings[0].GetProperty("model").GetString());
    }

    [Fact]
    public void Snapshot_AggregatesByModelAndChallenge()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        t.Record("m-known", 1_000_000, 0, "c1", "s1"); // $1
        t.Record("m-known", 0, 1_000_000, "c2", "s1"); // $2
        t.Record("m-cheap", 1_000_000, 0, "c1", "s2"); // $0.10
        var snap = t.Snapshot();

        Assert.Equal(3, snap.TotalCalls);
        Assert.Equal(3.10m, snap.TotalUsd);
        Assert.Equal(3.00m, snap.UsdByModel["m-known"]);
        Assert.Equal(0.10m, snap.UsdByModel["m-cheap"]);
        Assert.Equal(1.10m, snap.UsdByChallenge["c1"]);
        Assert.Equal(2.00m, snap.UsdByChallenge["c2"]);
    }

    [Fact]
    public void UsdForChallenge_IsIsolated()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        t.Record("m-known", 1_000_000, 0, "a", null);
        t.Record("m-known", 2_000_000, 0, "b", null);
        Assert.Equal(1.0m, t.UsdForChallenge("a"));
        Assert.Equal(2.0m, t.UsdForChallenge("b"));
        Assert.Equal(0m, t.UsdForChallenge("c-absent"));
    }

    [Fact]
    public void AssertWithinBudget_RunCapExceeded_Throws()
    {
        var t = new CostTracker(_audit, runCapUsd: 1.00m, prices: new FixturePrices());
        // $1.01 total: prompt 1,010,000 tok @ $1/M
        t.Record("m-known", 1_010_000, 0, "c1", null);
        var ex = Assert.Throws<BudgetExceededException>(() => t.AssertWithinBudget(null));
        Assert.Equal("run", ex.Scope);
        Assert.Equal(1.00m, ex.Cap);
        Assert.True(ex.Actual > 1.00m);
    }

    [Fact]
    public void AssertWithinBudget_ChallengeCapExceeded_Throws_WithScope()
    {
        var t = new CostTracker(_audit, challengeCapUsd: 0.10m, prices: new FixturePrices());
        // $0.11 charged to challenge "hard"
        t.Record("m-cheap", 1_100_000, 0, "hard", null);
        var ex = Assert.Throws<BudgetExceededException>(() => t.AssertWithinBudget("hard"));
        Assert.Equal("challenge:hard", ex.Scope);
        Assert.Equal(0.10m, ex.Cap);
    }

    [Fact]
    public async Task Record_Concurrent_SumIsRaceFree()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        const int threads = 10;
        const int perThread = 100;
        var tasks = new List<Task>();
        for (int i = 0; i < threads; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                for (int j = 0; j < perThread; j++)
                {
                    t.Record("m-known", 1_000, 0, "c" + (j % 5), "s");
                }
            }));
        }
        await Task.WhenAll(tasks);

        // 1_000 tokens * $1/M = $0.001 per call * 1000 calls = $1.00
        Assert.Equal(1000, t.Snapshot().TotalCalls);
        Assert.Equal(1.000m, t.TotalUsd);
    }

    [Fact]
    public void StrictMode_AutoAsserts_OnRecord()
    {
        Environment.SetEnvironmentVariable("DREDERICK_BUDGET_STRICT", "1");
        try
        {
            var t = new CostTracker(_audit, runCapUsd: 0.10m, prices: new FixturePrices());
            Assert.Throws<BudgetExceededException>(() =>
                t.Record("m-known", 200_000, 0, "c", null));
        }
        finally
        {
            Environment.SetEnvironmentVariable("DREDERICK_BUDGET_STRICT", null);
        }
    }

    [Fact]
    public void Record_ScrubsNewlinesInIds()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        t.Record("m-known", 1_000, 0, "chal\nwith\nnewlines", "solv\rnaughty");

        var recs = ReadAuditEvents("cost.record");
        Assert.Single(recs);
        var chal = recs[0].GetProperty("challenge_id").GetString()!;
        var solv = recs[0].GetProperty("solver_id").GetString()!;
        Assert.DoesNotContain('\n', chal);
        Assert.DoesNotContain('\r', chal);
        Assert.DoesNotContain('\n', solv);
        Assert.DoesNotContain('\r', solv);
        Assert.Equal("chal with newlines", chal);
        Assert.Equal("solv naughty", solv);
    }

    [Fact]
    public void CopilotPrices_PriceTable_KnownVsUnknown()
    {
        var (i, o) = CopilotPrices.PriceTable.For("gpt-5.4");
        Assert.True(i > 0m);
        Assert.True(o > 0m);

        var (i2, o2) = CopilotPrices.PriceTable.For("does-not-exist");
        Assert.Equal(0m, i2);
        Assert.Equal(0m, o2);
    }

    [Fact]
    public void BudgetBreach_AuditedBeforeThrow()
    {
        var t = new CostTracker(_audit, runCapUsd: 0.01m, prices: new FixturePrices());
        t.Record("m-known", 100_000, 0, "c", null); // $0.10 > $0.01
        try
        {
            t.AssertWithinBudget(null);
            Assert.Fail("expected throw");
        }
        catch (BudgetExceededException)
        {
            // expected
        }

        var breaches = ReadAuditEvents("cost.budget_exceeded");
        Assert.Single(breaches);
        Assert.Equal("run", breaches[0].GetProperty("scope").GetString());
    }

    [Fact]
    public void Record_ZeroTokens_NoDivideByZero()
    {
        var t = new CostTracker(_audit, prices: new FixturePrices());
        var tc = t.Record("m-known", 0, 0, "c", "s");
        Assert.Equal(0m, tc.UsdCost);
        Assert.Equal(0m, t.TotalUsd);
        Assert.Equal(1, t.Snapshot().TotalCalls);
    }
}
