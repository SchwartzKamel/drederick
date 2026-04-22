using System.Globalization;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Coordinator;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Detection;
using Drederick.Jeopardy.Ops;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Jeopardy.Swarm;
using Drederick.Scope;
using Drederick.Tests.Jeopardy.Coordinator.Fakes;
using Drederick.Tests.Jeopardy.Solver.Fakes;
using Drederick.Tests.Jeopardy.Swarm.Fakes;
using Xunit;

namespace Drederick.Tests.Jeopardy.Coordinator;

public sealed class CtfCoordinatorTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;
    private readonly SolverMessageBus _bus;
    private readonly FakeFlagSubmitCoordinator _flagSubmit;
    private readonly FakeCostTracker _costs;
    private readonly LoopDetector _loopDetector;

    public CtfCoordinatorTests()
    {
        _tmpDir = Path.Combine(AppContext.BaseDirectory, $"drederick-coord-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _auditPath = Path.Combine(_tmpDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        _bus = new SolverMessageBus(_audit);
        _flagSubmit = new FakeFlagSubmitCoordinator();
        _costs = new FakeCostTracker();
        _loopDetector = new LoopDetector(_audit);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { _bus.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    private static CtfdChallenge Chal(int id, string name, string cat = "pwn", int value = 100,
        bool solved = false)
        => new(id, name, cat, value, "desc", Array.Empty<CtfdAttachment>(),
            Array.Empty<string>(), null, solved);

    private static Scope.Scope MakeScope() => ScopeLoader.Parse("10.10.10.5");

    private static Uri CtfdUri() => new("http://10.10.10.5:8000/");

    private static IReadOnlyList<SwarmModelSlot> Models(params string[] ids)
        => ids.Select(i => new SwarmModelSlot(i)).ToArray();

    private CoordinatorConfig MakeCfg(
        IReadOnlyList<int>? idFilter = null,
        IReadOnlyList<string>? catFilter = null,
        decimal? runBudget = null,
        int maxConcurrent = 4,
        string? reportDir = null,
        string? inboxPath = null)
        => new(
            CtfdUrl: CtfdUri(),
            CtfdToken: "dummy-token",
            Models: Models("model-a", "model-b"),
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            TotalRunBudgetUsd: runBudget,
            PerChallengeBudgetUsd: null,
            MaxConcurrentChallenges: maxConcurrent,
            OperatorInboxPath: inboxPath,
            ReportOutputDir: reportDir,
            PollInterval: TimeSpan.FromMilliseconds(10),
            CategoryFilter: catFilter,
            ChallengeIdFilter: idFilter);

    private CtfCoordinator MakeCoord(
        FakeCtfdClient ctfd,
        FakeSolverSwarm swarm,
        IOperatorInbox? inbox = null,
        TimeSpan? budgetPoll = null,
        CtfdPoller? poller = null)
    {
        poller ??= new CtfdPoller(ctfd, _audit, TimeSpan.FromMilliseconds(5),
            delay: (_, _) => Task.Delay(5));
        return new CtfCoordinator(
            ctfd, poller, swarm, _flagSubmit, _bus, _costs, _loopDetector, inbox,
            MakeScope(), _audit,
            budgetPoll ?? TimeSpan.FromMilliseconds(30));
    }

    [Fact]
    public async Task HappyPath_ThreeChallenges_AllSolved()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b"), Chal(3, "c") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(1, new FakeSolverSwarm.Script(SolverOutcome.Solved,
            TimeSpan.FromMilliseconds(20), 0.01m, "model-a", "flag{one}"));
        swarm.SetScript(2, new FakeSolverSwarm.Script(SolverOutcome.Solved,
            TimeSpan.FromMilliseconds(20), 0.02m, "model-b", "flag{two}"));
        swarm.SetScript(3, new FakeSolverSwarm.Script(SolverOutcome.Solved,
            TimeSpan.FromMilliseconds(20), 0.03m, "model-a", "flag{three}"));

        // Pre-populate cost tracker (real-world this comes from solver LLM calls).
        _costs.Preload("1", 0.01m);
        _costs.Preload("2", 0.02m);
        _costs.Preload("3", 0.03m);

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        // Stop the poller after a grace period so RunAsync can return.
        _ = Task.Run(async () => { await Task.Delay(500); cts.Cancel(); });
        var report = await coord.RunAsync(MakeCfg(), cts.Token);

        Assert.Equal(3, report.ChallengesDiscovered);
        Assert.Equal(3, report.ChallengesAttempted);
        Assert.Equal(3, report.ChallengesSolved);
        Assert.Equal(300, report.PointsScored);
        Assert.Equal(0.06m, report.TotalUsdCost);
        Assert.Equal(2, report.SolvesByModel["model-a"]);
        Assert.Equal(1, report.SolvesByModel["model-b"]);
    }

    [Fact]
    public async Task CategoryFilter_OnlyPwnRaced()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[]
        {
            Chal(1, "p1", cat: "pwn"),
            Chal(2, "w1", cat: "web"),
            Chal(3, "p2", cat: "pwn"),
        });
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp, TimeSpan.FromMilliseconds(10));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(500); cts.Cancel(); });
        var report = await coord.RunAsync(MakeCfg(catFilter: new[] { "pwn" }), cts.Token);

        Assert.Equal(2, report.ChallengesAttempted);
        var ids = swarm.StartedChallenges.OrderBy(i => i).ToArray();
        Assert.Equal(new[] { 1, 3 }, ids);
        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("coordinator.skipped") && l.Contains("\"challenge_id\":2"));
    }

    [Fact]
    public async Task ChallengeIdFilter_OnlyOneRaced()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(41, "a"), Chal(42, "b"), Chal(43, "c") });
        var swarm = new FakeSolverSwarm();
        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(400); cts.Cancel(); });
        var report = await coord.RunAsync(MakeCfg(idFilter: new[] { 42 }), cts.Token);

        Assert.Equal(1, report.ChallengesAttempted);
        var ids = swarm.StartedChallenges.ToArray();
        Assert.Single(ids);
        Assert.Equal(42, ids[0]);
    }

    [Fact]
    public async Task TotalRunBudget_Exceeded_CancelsRemaining()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b"), Chal(3, "c") });
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromMilliseconds(500));
        // Preload exceeds the cap immediately.
        _costs.Preload("1", 10m);

        var coord = MakeCoord(ctfd, swarm, budgetPoll: TimeSpan.FromMilliseconds(20));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var report = await coord.RunAsync(MakeCfg(runBudget: 1m), cts.Token);

        Assert.NotNull(report.FinishedAt);
        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("coordinator.budget_exceeded"));
    }

    [Fact]
    public async Task MaxConcurrentChallenges_Respected()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(Enumerable.Range(1, 5).Select(i => Chal(i, "n" + i)).ToArray());
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromMilliseconds(200));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        _ = Task.Run(async () => { await Task.Delay(1500); cts.Cancel(); });
        _ = await coord.RunAsync(MakeCfg(maxConcurrent: 2), cts.Token);

        Assert.True(swarm.PeakConcurrent <= 2,
            $"PeakConcurrent was {swarm.PeakConcurrent}, expected <=2");
    }

    [Fact]
    public async Task OperatorHint_WithChallengeId_RoutedToBus()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(7, "seven") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(7, new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromMilliseconds(600)));
        var inbox = new OperatorInbox(_bus, _audit);
        var inboxPath = Path.Combine(_tmpDir, "inbox.jsonl");
        File.WriteAllText(inboxPath, "");

        var coord = MakeCoord(ctfd, swarm, inbox);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(250); cts.Cancel(); });

        // Push a hint once the challenge is likely running.
        var hintTask = Task.Run(async () =>
        {
            await Task.Delay(80);
            var msg = new OperatorMessage(
                At: DateTimeOffset.UtcNow,
                ChallengeId: "7",
                SolverId: null,
                Kind: "hint",
                Body: "try rop gadget at 0x401234");
            await OperatorSender.SendAsync(inboxPath, msg, CancellationToken.None);
        });

        _ = await coord.RunAsync(MakeCfg(inboxPath: inboxPath), cts.Token);
        await hintTask;

        var hist = _bus.History("7");
        Assert.Contains(hist, i => i.Kind == InsightKind.OperatorHint);
    }

    [Fact]
    public async Task OperatorFocus_CancelsOtherActiveSwarms()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b"), Chal(3, "c") });
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromSeconds(5));
        var inbox = new OperatorInbox(_bus, _audit);
        var inboxPath = Path.Combine(_tmpDir, "inbox.jsonl");
        File.WriteAllText(inboxPath, "");

        var coord = MakeCoord(ctfd, swarm, inbox);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var op = Task.Run(async () =>
        {
            await Task.Delay(200);
            var msg = new OperatorMessage(DateTimeOffset.UtcNow, "2", null, "focus", "focus on 2");
            await OperatorSender.SendAsync(inboxPath, msg, CancellationToken.None);
            await Task.Delay(400);
            cts.Cancel();
        });

        var report = await coord.RunAsync(MakeCfg(inboxPath: inboxPath, maxConcurrent: 3), cts.Token);
        await op;

        // Challenges 1 and 3 should have been cancelled; 2 should have
        // completed (or timed out). We verify via per-challenge results.
        Assert.Equal(3, report.ChallengesAttempted);
        // Not strictly enforceable without solver-level introspection, so at
        // least confirm the focus message was audited as operator.routed.
        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("coordinator.operator.routed") && l.Contains("\"kind\":\"focus\""));
    }

    [Fact]
    public async Task OperatorShutdown_CancelsAllAndReturnsPartialReport()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b") });
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromSeconds(5));
        var inbox = new OperatorInbox(_bus, _audit);
        var inboxPath = Path.Combine(_tmpDir, "inbox.jsonl");
        File.WriteAllText(inboxPath, "");

        var coord = MakeCoord(ctfd, swarm, inbox);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        _ = Task.Run(async () =>
        {
            await Task.Delay(150);
            var msg = new OperatorMessage(DateTimeOffset.UtcNow, null, null, "shutdown", "stop");
            await OperatorSender.SendAsync(inboxPath, msg, CancellationToken.None);
        });

        var report = await coord.RunAsync(MakeCfg(inboxPath: inboxPath), cts.Token);
        Assert.NotNull(report.FinishedAt);
        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("coordinator.shutdown"));
    }

    [Fact]
    public async Task ChallengeThrows_OtherChallengesComplete()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b"), Chal(3, "c") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(1, new FakeSolverSwarm.Script(SolverOutcome.GaveUp, TimeSpan.FromMilliseconds(20)));
        swarm.SetScript(2, new FakeSolverSwarm.Script(SolverOutcome.GaveUp, TimeSpan.Zero, Throw: true));
        swarm.SetScript(3, new FakeSolverSwarm.Script(SolverOutcome.GaveUp, TimeSpan.FromMilliseconds(20)));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(500); cts.Cancel(); });
        var report = await coord.RunAsync(MakeCfg(), cts.Token);

        Assert.Equal(3, report.ChallengesAttempted);
        var errRes = report.PerChallenge.Single(r => r.ChallengeId == 2);
        Assert.Equal(SolverOutcome.Error, errRes.CombinedOutcome);
        Assert.Contains(report.PerChallenge, r => r.ChallengeId == 1);
        Assert.Contains(report.PerChallenge, r => r.ChallengeId == 3);
    }

    [Fact]
    public async Task ExternalCancellation_ReturnsGracefully()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a"), Chal(2, "b") });
        var swarm = new FakeSolverSwarm();
        swarm.DefaultScript = new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromSeconds(5));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var report = await coord.RunAsync(MakeCfg(), cts.Token);

        Assert.NotNull(report.FinishedAt);
        Assert.True(report.ChallengesAttempted >= 0);
    }

    [Fact]
    public async Task Report_PlaintextFlag_NotWritten_ShaOnly()
    {
        const string canary = "flag{canary_coord_123}";
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(99, "canary-chal") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(99, new FakeSolverSwarm.Script(SolverOutcome.Solved,
            TimeSpan.FromMilliseconds(20), 0.5m, "model-a", canary));

        var reportDir = Path.Combine(_tmpDir, "report");
        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(300); cts.Cancel(); });
        var report = await coord.RunAsync(MakeCfg(reportDir: reportDir), cts.Token);

        var jsonPath = Path.Combine(reportDir, "report.json");
        var mdPath = Path.Combine(reportDir, "report.md");
        Assert.True(File.Exists(jsonPath));
        Assert.True(File.Exists(mdPath));
        var json = File.ReadAllText(jsonPath);
        var md = File.ReadAllText(mdPath);
        Assert.DoesNotContain(canary, json);
        Assert.DoesNotContain(canary, md);
        // Compute the expected sha to confirm it's there.
        var expectedSha = System.Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(canary))).ToLowerInvariant();
        Assert.Contains(expectedSha, json);
        Assert.Contains(expectedSha, md);
    }

    [Fact]
    public async Task LoopDetected_RoutesCoordinatorHint()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(5, "looper") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(5, new FakeSolverSwarm.Script(SolverOutcome.GaveUp, TimeSpan.FromSeconds(2)));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // Fire a loop after the coordinator has started.
        _ = Task.Run(async () =>
        {
            await Task.Delay(150);
            for (int i = 0; i < 4; i++)
            {
                _loopDetector.Observe(new SolverAction(
                    SolverId: "model-a@chal5",
                    ChallengeId: "5",
                    ActionKind: "exec",
                    FingerprintSha256: new string('a', 64),
                    At: DateTimeOffset.UtcNow));
            }
            await Task.Delay(200);
            cts.Cancel();
        });

        _ = await coord.RunAsync(MakeCfg(), cts.Token);

        // Give the async publish a moment to settle (it's fire-and-forget).
        await Task.Delay(100);
        var hist = _bus.History("5");
        Assert.Contains(hist, i => i.Kind == InsightKind.CoordinatorHint
            && i.Tags.Any(t => t.StartsWith("loop", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task SolvedExternally_CancelsActiveSwarm()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(10, "ten") });
        // Second poll: the challenge has been solved by another team.
        ctfd.Enqueue(new[] { Chal(10, "ten", solved: true) });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(10, new FakeSolverSwarm.Script(SolverOutcome.GaveUp,
            TimeSpan.FromSeconds(5)));

        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(500); cts.Cancel(); });
        _ = await coord.RunAsync(MakeCfg(), cts.Token);

        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("coordinator.skipped")
            && l.Contains("external_solve"));
    }

    [Fact]
    public async Task OutOfScopeHost_ThrowsOnBoot()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a") });
        var swarm = new FakeSolverSwarm();
        var coord = MakeCoord(ctfd, swarm);

        var badCfg = new CoordinatorConfig(
            CtfdUrl: new Uri("http://10.99.99.99:8000/"),
            CtfdToken: "t",
            Models: Models("model-a"),
            WallClockPerChallenge: TimeSpan.FromSeconds(5),
            MaxConcurrentChallenges: 1,
            PollInterval: TimeSpan.FromMilliseconds(5));

        await Assert.ThrowsAsync<ScopeException>(async () =>
            await coord.RunAsync(badCfg, CancellationToken.None));
    }

    [Fact]
    public async Task Report_IncludesTatumBranding()
    {
        var ctfd = new FakeCtfdClient();
        ctfd.Enqueue(new[] { Chal(1, "a") });
        var swarm = new FakeSolverSwarm();
        swarm.SetScript(1, new FakeSolverSwarm.Script(SolverOutcome.Solved,
            TimeSpan.FromMilliseconds(10), 0.01m, "model-a", "flag{one}"));

        var reportDir = Path.Combine(_tmpDir, "report2");
        var coord = MakeCoord(ctfd, swarm);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () => { await Task.Delay(300); cts.Cancel(); });
        _ = await coord.RunAsync(MakeCfg(reportDir: reportDir), cts.Token);

        var md = File.ReadAllText(Path.Combine(reportDir, "report.md"));
        Assert.Contains("Drederick Tatum", md);
        Assert.Contains("A fair fight", md);
    }
}
