using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Jeopardy.Swarm;
using Drederick.Tests.Jeopardy.Solver.Fakes;
using Drederick.Tests.Jeopardy.Swarm.Fakes;
using Xunit;

namespace Drederick.Tests.Jeopardy.Swarm;

public sealed class SolverSwarmTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string _auditPath;
    private readonly AuditLog _audit;
    private readonly SolverMessageBus _bus;
    private readonly FakeCostTracker _costs;
    private readonly FakeFlagSubmitCoordinator _flagSubmit;

    public SolverSwarmTests()
    {
        _tmpDir = Path.Combine(AppContext.BaseDirectory, $"drederick-swarm-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _auditPath = Path.Combine(_tmpDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        _bus = new SolverMessageBus(_audit);
        _costs = new FakeCostTracker();
        _flagSubmit = new FakeFlagSubmitCoordinator();
    }

    public void Dispose()
    {
        _audit.Dispose();
        _bus.DisposeAsync().AsTask().GetAwaiter().GetResult();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    private static CtfdChallenge MakeChallenge(int id = 101, string name = "easy-pwn") => new(
        Id: id,
        Name: name,
        Category: "pwn",
        Value: 100,
        Description: "x",
        Files: Array.Empty<CtfdAttachment>(),
        Tags: Array.Empty<string>(),
        ConnectionInfo: null,
        Solved: false);

    private SolverSwarm MakeSwarm(FakeChallengeSolver factory, TimeSpan? budgetPoll = null)
        => new SolverSwarm(factory, _flagSubmit, _bus, _costs, _audit, budgetPoll ?? TimeSpan.FromMilliseconds(50));

    private IReadOnlyList<Dictionary<string, JsonElement>> ReadAudit()
    {
        var list = new List<Dictionary<string, JsonElement>>();
        foreach (var line in File.ReadAllLines(_auditPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            list.Add(JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line)!);
        }
        return list;
    }

    [Fact]
    public async Task OneSolver_Wins_OthersCancelled()
    {
        var chal = MakeChallenge();
        _flagSubmit.SetCorrect(chal.Id, "flag{win}");

        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("m-winner", new FakeChallengeSolver.Script(
            Outcome: SolverOutcome.Solved,
            Delay: TimeSpan.FromMilliseconds(80),
            FlagSubmitted: "flag{win}"));
        factory.SetScript("m-loser-1", new FakeChallengeSolver.Script(
            Outcome: SolverOutcome.Incorrect,
            Delay: TimeSpan.FromSeconds(10)));
        factory.SetScript("m-loser-2", new FakeChallengeSolver.Script(
            Outcome: SolverOutcome.Incorrect,
            Delay: TimeSpan.FromSeconds(10)));

        var cfg = new SwarmConfig(
            Models: new[]
            {
                new SwarmModelSlot("m-loser-1"),
                new SwarmModelSlot("m-winner"),
                new SwarmModelSlot("m-loser-2"),
            },
            WallClockPerChallenge: TimeSpan.FromSeconds(30));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.Solved, result.CombinedOutcome);
        Assert.Equal("m-winner", result.WinningModelId);
        Assert.Equal("m-winner@chal101", result.WinningSolverId);
        Assert.Equal(3, result.PerSolver.Count);
        Assert.True(factory.CancelledCount >= 2, $"expected >=2 cancellations, got {factory.CancelledCount}");
    }

    [Fact]
    public async Task AllIncorrect_CombinedIncorrect()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("a", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(20)));
        factory.SetScript("b", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(20)));
        factory.SetScript("c", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(20)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b"), new SwarmModelSlot("c") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.Incorrect, result.CombinedOutcome);
        Assert.Null(result.WinningSolverId);
    }

    [Fact]
    public async Task AllTimeout_CombinedTimeout()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("a", new FakeChallengeSolver.Script(SolverOutcome.Timeout, TimeSpan.FromMilliseconds(10)));
        factory.SetScript("b", new FakeChallengeSolver.Script(SolverOutcome.Timeout, TimeSpan.FromMilliseconds(10)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);
        Assert.Equal(SolverOutcome.Timeout, result.CombinedOutcome);
    }

    [Fact]
    public async Task Mixed_LoopAndTimeout_PicksLoopDetected()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("a", new FakeChallengeSolver.Script(SolverOutcome.LoopDetected, TimeSpan.FromMilliseconds(10), LoopKind: "PromptLoop"));
        factory.SetScript("b", new FakeChallengeSolver.Script(SolverOutcome.Timeout, TimeSpan.FromMilliseconds(10)));
        factory.SetScript("c", new FakeChallengeSolver.Script(SolverOutcome.Error, TimeSpan.FromMilliseconds(10), FailureReason: "boom"));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b"), new SwarmModelSlot("c") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);
        Assert.Equal(SolverOutcome.LoopDetected, result.CombinedOutcome);
    }

    [Fact]
    public async Task MaxParallel_Bounded()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        var delay = TimeSpan.FromMilliseconds(120);
        for (int i = 0; i < 4; i++)
        {
            factory.SetScript($"m{i}", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, delay));
        }

        var cfg = new SwarmConfig(
            Models: Enumerable.Range(0, 4).Select(i => new SwarmModelSlot($"m{i}")).ToArray(),
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            MaxParallelSolvers: 2);

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal(4, result.PerSolver.Count);
        Assert.True(factory.PeakConcurrent <= 2, $"peak concurrent was {factory.PeakConcurrent}, expected <=2");
        Assert.Equal(4, factory.StartedCount);
    }

    [Fact]
    public async Task CancelLosersFalse_AllRunToCompletion()
    {
        var chal = MakeChallenge();
        _flagSubmit.SetCorrect(chal.Id, "flag{win}");

        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("winner", new FakeChallengeSolver.Script(
            SolverOutcome.Solved, TimeSpan.FromMilliseconds(30), FlagSubmitted: "flag{win}"));
        factory.SetScript("loser", new FakeChallengeSolver.Script(
            SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(150)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("winner"), new SwarmModelSlot("loser") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            CancelLosersOnWin: false);

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.Solved, result.CombinedOutcome);
        Assert.Equal(0, factory.CancelledCount);
        Assert.Equal(SolverOutcome.Incorrect, result.PerSolver[1].Outcome);
    }

    [Fact]
    public async Task CoolOffBetweenStarts_StaggersLaunches()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        foreach (var m in new[] { "a", "b", "c" })
        {
            factory.SetScript(m, new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(10)));
        }

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b"), new SwarmModelSlot("c") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            CoolOffBetweenStarts: TimeSpan.FromMilliseconds(80));

        await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        var starts = factory.StartTimestamps.OrderBy(t => t.At).ToList();
        Assert.Equal(3, starts.Count);
        var gap01 = starts[1].At - starts[0].At;
        var gap12 = starts[2].At - starts[1].At;
        Assert.True(gap01 >= TimeSpan.FromMilliseconds(50),
            $"gap a→b was {gap01.TotalMilliseconds}ms, expected >=50ms");
        Assert.True(gap12 >= TimeSpan.FromMilliseconds(50),
            $"gap b→c was {gap12.TotalMilliseconds}ms, expected >=50ms");
    }

    [Fact]
    public async Task BudgetExceededUpFront_CancelsAll()
    {
        var chal = MakeChallenge(id: 42);
        _costs.Preload("42", 0.02m);

        var factory = new FakeChallengeSolver(_flagSubmit);
        foreach (var m in new[] { "x", "y" })
        {
            factory.SetScript(m, new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromSeconds(10)));
        }

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("x"), new SwarmModelSlot("y") },
            WallClockPerChallenge: TimeSpan.FromSeconds(30),
            TotalBudgetUsdPerChallenge: 0.01m);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);
        sw.Stop();

        Assert.Equal(SolverOutcome.BudgetExceeded, result.CombinedOutcome);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
        Assert.Null(result.WinningSolverId);
    }

    [Fact]
    public async Task ExternalCancellation_ReturnsWithPartialResults()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        foreach (var m in new[] { "a", "b", "c" })
        {
            factory.SetScript(m, new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromSeconds(10)));
        }

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b"), new SwarmModelSlot("c") },
            WallClockPerChallenge: TimeSpan.FromSeconds(30));

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(80));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, cts.Token);

        Assert.Equal(3, result.PerSolver.Count);
        Assert.Null(result.WinningSolverId);
        Assert.All(result.PerSolver, r => Assert.NotEqual(SolverOutcome.Solved, r.Outcome));
    }

    [Fact]
    public async Task PerSolver_ReturnedInConfiguredOrder()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("alpha", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(200)));
        factory.SetScript("bravo", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(10)));
        factory.SetScript("charlie", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(100)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("alpha"), new SwarmModelSlot("bravo"), new SwarmModelSlot("charlie") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal("alpha", result.PerSolver[0].ModelId);
        Assert.Equal("bravo", result.PerSolver[1].ModelId);
        Assert.Equal("charlie", result.PerSolver[2].ModelId);
    }

    [Fact]
    public async Task AuditStartAndFinish_EmittedWithFields()
    {
        var chal = MakeChallenge(id: 7, name: "proofs");
        _flagSubmit.SetCorrect(chal.Id, "flag{a}");
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("m1", new FakeChallengeSolver.Script(SolverOutcome.Solved, TimeSpan.FromMilliseconds(20), FlagSubmitted: "flag{a}"));
        factory.SetScript("m2", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(5)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("m1"), new SwarmModelSlot("m2") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            TotalBudgetUsdPerChallenge: 1.00m);

        await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        var events = ReadAudit();
        var start = events.SingleOrDefault(e => e["event"].GetString() == "swarm.race.start");
        Assert.NotNull(start);
        Assert.Equal(7, start!["challenge_id"].GetInt32());
        Assert.Equal(2, start["models_count"].GetInt32());
        Assert.Equal("1.000000", start["total_budget_usd"].GetString());

        var finish = events.SingleOrDefault(e => e["event"].GetString() == "swarm.race.finish");
        Assert.NotNull(finish);
        Assert.Equal("Solved", finish!["outcome"].GetString());
        Assert.Equal("m1", finish["winning_model_id"].GetString());
        Assert.Equal(JsonValueKind.Array, finish["per_solver"].ValueKind);
        Assert.Equal(2, finish["per_solver"].GetArrayLength());
    }

    [Fact]
    public async Task TotalUsdCost_IsSumOfPerSolverCosts()
    {
        var chal = MakeChallenge();
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("a", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(10), UsdCost: 0.0100m));
        factory.SetScript("b", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(10), UsdCost: 0.0025m));
        factory.SetScript("c", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromMilliseconds(10), UsdCost: 0.0075m));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("a"), new SwarmModelSlot("b"), new SwarmModelSlot("c") },
            WallClockPerChallenge: TimeSpan.FromSeconds(5));

        var result = await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        Assert.Equal(0.0200m, result.TotalUsdCost);
        Assert.Equal(result.PerSolver.Sum(r => r.UsdCost), result.TotalUsdCost);
    }

    [Fact]
    public async Task AuditCancelLosers_EmittedOnWin()
    {
        var chal = MakeChallenge();
        _flagSubmit.SetCorrect(chal.Id, "flag{z}");
        var factory = new FakeChallengeSolver(_flagSubmit);
        factory.SetScript("win", new FakeChallengeSolver.Script(SolverOutcome.Solved, TimeSpan.FromMilliseconds(30), FlagSubmitted: "flag{z}"));
        factory.SetScript("lose", new FakeChallengeSolver.Script(SolverOutcome.Incorrect, TimeSpan.FromSeconds(10)));

        var cfg = new SwarmConfig(
            Models: new[] { new SwarmModelSlot("win"), new SwarmModelSlot("lose") },
            WallClockPerChallenge: TimeSpan.FromSeconds(30));

        await MakeSwarm(factory).RaceAsync(chal, cfg, CancellationToken.None);

        var events = ReadAudit();
        var cancel = events.SingleOrDefault(e => e["event"].GetString() == "swarm.cancel_losers");
        Assert.NotNull(cancel);
        Assert.Equal("win", cancel!["winner_model_id"].GetString());
    }
}
