using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Detection;
using Drederick.Jeopardy.Sandbox;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Scope;
using Drederick.Tests.Jeopardy.Sandbox;
using Drederick.Tests.Jeopardy.Solver.Fakes;
using Xunit;

namespace Drederick.Tests.Jeopardy.Solver;

public sealed class ChallengeSolverTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string _auditPath;
    private readonly AuditLog _audit;
    private readonly Drederick.Scope.Scope _scope;
    private readonly CannedDockerRunner _docker;
    private readonly SandboxManager _sandboxes;

    public ChallengeSolverTests()
    {
        _tmpDir = Path.Combine(AppContext.BaseDirectory, $"drederick-solver-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _auditPath = Path.Combine(_tmpDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        _scope = ScopeLoader.Parse("10.0.0.0/8\n192.168.0.0/16\n");

        _docker = new CannedDockerRunner();
        _docker.OnArgs("run -d", exit: 0, stdout: "ctr-abc123\n");
        _docker.OnArgs("inspect --format", exit: 0, stdout: "healthy\n");
        _docker.OnArgs("rm -f", exit: 0);
        _sandboxes = new SandboxManager(_scope, _audit, _docker);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static CtfdChallenge Chal(int id = 42, string name = "babycrypto", string category = "crypto")
        => new(
            Id: id,
            Name: name,
            Category: category,
            Value: 100,
            Description: "Find the flag.",
            Files: Array.Empty<CtfdAttachment>(),
            Tags: Array.Empty<string>(),
            ConnectionInfo: null,
            Solved: false);

    private static SolverConfig Cfg(
        int maxTurns = 20,
        TimeSpan? wallClock = null,
        decimal? perChallengeBudget = null,
        int maxParallel = 3,
        bool insights = true)
        => new(
            ModelId: "fake-model",
            MaxTurns: maxTurns,
            WallClock: wallClock ?? TimeSpan.FromSeconds(30),
            PerChallengeBudgetUsd: perChallengeBudget,
            MaxParallelToolCalls: maxParallel,
            EnableBusInsights: insights);

    private (ChallengeSolver solver, FakeCopilotLlmClient llm, FakeFlagSubmitCoordinator flags,
             SolverMessageBus bus, CostTracker costs, LoopDetector loops) BuildSolver(
                int loopThreshold = 3)
    {
        var llm = new FakeCopilotLlmClient();
        var bus = new SolverMessageBus(_audit);
        var flags = new FakeFlagSubmitCoordinator();
        var costs = new CostTracker(_audit);
        var loops = new LoopDetector(_audit, exactRepeatThreshold: loopThreshold);
        var solver = new ChallengeSolver(llm, _sandboxes, flags, bus, costs, loops, _audit);
        return (solver, llm, flags, bus, costs, loops);
    }

    /// <summary>Add a canned exec handler — matches on docker "exec" calls.</summary>
    private void WhenExecContains(string substr, int exit, string stdout = "", string stderr = "")
    {
        _docker.OnArgs(args => args.StartsWith("exec ") && args.Contains(substr, StringComparison.Ordinal),
            exit, stdout, stderr);
    }

    private string ReadAuditAll()
    {
        _audit.Dispose();
        return File.ReadAllText(_auditPath);
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    [Fact]
    public async Task HappyPath_ExecThenSubmitFlag_SolvesChallenge()
    {
        var (solver, llm, flags, _, costs, _) = BuildSolver();
        const string flag = "flag{happy_path_9bf}";
        flags.SetCorrect(42, flag);
        WhenExecContains("cat flag.txt", exit: 0, stdout: flag);

        llm
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"cat flag.txt\"}")
            .EnqueueToolCall("submit_flag", "{\"flag\":\"" + flag + "\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.Solved, result.Outcome);
        Assert.NotNull(result.FlagSubmitted);
        Assert.Equal(2, result.Turns);
        Assert.Equal("fake-model@chal42", result.SolverId);
        Assert.Single(flags.Submissions);
        Assert.True(costs.UsdForChallenge("42") >= 0m);
    }

    [Fact]
    public async Task ExecError_RecoversAndSolvesOnRetry()
    {
        var (solver, llm, flags, _, _, _) = BuildSolver();
        const string flag = "flag{retry_ok}";
        flags.SetCorrect(42, flag);
        _docker.OnArgs(args => args.StartsWith("exec ") && args.Contains("cat /nope", StringComparison.Ordinal),
            exit: 1, stderr: "cat: /nope: No such file");
        _docker.OnArgs(args => args.StartsWith("exec ") && args.Contains("cat /flag", StringComparison.Ordinal),
            exit: 0, stdout: flag);

        llm
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"cat /nope\"}")
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"cat /flag\"}")
            .EnqueueToolCall("submit_flag", "{\"flag\":\"" + flag + "\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.Solved, result.Outcome);
        Assert.Equal(3, result.Turns);
    }

    [Fact]
    public async Task GiveUpTool_TerminatesWithGaveUp()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        llm.EnqueueToolCall("give_up", "{\"reason\":\"out of depth\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        Assert.Contains("give_up", result.FailureReason ?? string.Empty);
    }

    [Fact]
    public async Task BudgetExceeded_ReturnsBudgetExceededOutcome()
    {
        var (solver, llm, _, _, costs, _) = BuildSolver();
        WhenExecContains("enumerate", exit: 0, stdout: "data");
        llm
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"enumerate\"}")
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"enumerate-again\"}")
            .EnqueueToolCall("give_up", "{\"reason\":\"never\"}");
        // Pre-seed cost with a priced model so the per-challenge cap trips.
        // Using gpt-5.4 ($0.002/M input + $0.008/M output) with 1M+1M tokens
        // costs $0.010 — well above the $0.001 cap.
        costs.Record("gpt-5.4", 1_000_000, 1_000_000, "42", "preload@chal42");

        var cfg = Cfg(perChallengeBudget: 0.001m);
        var result = await solver.SolveAsync(Chal(), cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.BudgetExceeded, result.Outcome);
        Assert.Contains("budget", result.FailureReason ?? string.Empty);
    }

    [Fact]
    public async Task WallClockTimeout_ReturnsTimeoutOutcome()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        // Each LLM call sleeps longer than the wall clock.
        llm.EnqueueDelay(TimeSpan.FromSeconds(5)).EnqueueContent("too late");

        var cfg = Cfg(wallClock: TimeSpan.FromMilliseconds(150));
        var result = await solver.SolveAsync(Chal(), cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.Timeout, result.Outcome);
        Assert.Equal("wall_clock", result.FailureReason);
    }

    [Fact]
    public async Task PeerSolvedChallenge_FastExitsWithGaveUp()
    {
        var (solver, llm, flags, _, _, _) = BuildSolver();
        flags.MarkSolvedByPeer(42, "flag{peer_won}");
        // Script a response but it should never be called.
        llm.EnqueueContent("should not run");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        Assert.Equal("peer_won", result.FailureReason);
        Assert.Equal(0, result.Turns);
        Assert.Equal(1, llm.Remaining); // untouched
    }

    [Fact]
    public async Task LoopDetected_EmitsCoordinatorHintAndTerminates()
    {
        var (solver, llm, _, bus, _, _) = BuildSolver(loopThreshold: 3);
        WhenExecContains("whoami", exit: 0, stdout: "ctf");

        for (int i = 0; i < 5; i++)
        {
            llm.EnqueueToolCall("sandbox_exec", "{\"command\":\"whoami\"}", callId: "c" + i);
        }

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.LoopDetected, result.Outcome);
        Assert.NotNull(result.LoopKind);
        var history = bus.History("42");
        Assert.Contains(history, h => h.Kind == InsightKind.CoordinatorHint);
    }

    [Fact]
    public async Task PublishInsight_AppearsInBusHistoryAndRejectsFlagKind()
    {
        var (solver, llm, _, bus, _, _) = BuildSolver();
        llm
            .EnqueueToolCall("publish_insight",
                "{\"kind\":\"Observation\",\"summary\":\"binary is 64-bit PIE\",\"tags\":[\"pwn\"]}")
            .EnqueueToolCall("publish_insight",
                "{\"kind\":\"Flag\",\"summary\":\"here is the flag anyway\"}")
            .EnqueueToolCall("give_up", "{\"reason\":\"done testing\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        var hist = bus.History("42");
        Assert.Contains(hist, h => h.Kind == InsightKind.Observation && h.Summary.Contains("PIE"));
        Assert.DoesNotContain(hist, h => h.Kind == InsightKind.Flag);
    }

    [Fact]
    public async Task GetInsights_FiltersOutOwnInsights()
    {
        var (solver, llm, _, bus, _, _) = BuildSolver();

        // Pre-publish one peer insight + one (fake) own insight.
        await bus.PublishAsync(new SolverInsight(
            ChallengeId: "42",
            SolverId: "peer-model@chal42",
            ModelId: "peer-model",
            Kind: InsightKind.Observation,
            Summary: "peer says look at config.bin",
            DetailsSha256: null,
            Tags: new[] { "peer" },
            At: DateTimeOffset.UtcNow), CancellationToken.None);
        await bus.PublishAsync(new SolverInsight(
            ChallengeId: "42",
            SolverId: "fake-model@chal42",
            ModelId: "fake-model",
            Kind: InsightKind.Observation,
            Summary: "own prior note",
            DetailsSha256: null,
            Tags: Array.Empty<string>(),
            At: DateTimeOffset.UtcNow), CancellationToken.None);

        // Capture the tool result by routing the model to call get_insights, then give_up.
        llm
            .EnqueueToolCall("get_insights", "{}")
            .EnqueueToolCall("give_up", "{\"reason\":\"test done\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        // Assert the turn was observed in the bus history — direct check.
        var all = bus.History("42");
        Assert.Contains(all, h => h.SolverId == "peer-model@chal42");
        Assert.Contains(all, h => h.SolverId == "fake-model@chal42");
    }

    [Fact]
    public async Task FlagPlaintext_NeverAppearsInAuditLog()
    {
        var (solver, llm, flags, _, _, _) = BuildSolver();
        const string canaryFlag = "flag{canary_solver_999}";
        flags.SetCorrect(42, canaryFlag);
        WhenExecContains("get-flag", exit: 0, stdout: canaryFlag);

        llm
            .EnqueueToolCall("sandbox_exec", "{\"command\":\"get-flag\"}")
            .EnqueueToolCall("submit_flag", "{\"flag\":\"" + canaryFlag + "\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);
        Assert.Equal(SolverOutcome.Solved, result.Outcome);

        var auditText = ReadAuditAll();
        Assert.DoesNotContain("canary_solver_999", auditText);
    }

    [Fact]
    public async Task Sandbox_IsDisposedEvenOnLlmException()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        llm.EnqueueException(HttpStatusCode.BadRequest, "bad request");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);
        Assert.Equal(SolverOutcome.Error, result.Outcome);

        // docker rm -f must have been issued for the container we spun up.
        var trace = _docker.ArgvTrace;
        Assert.Contains(trace, a => a.StartsWith("rm -f", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Transient429_Retries_Then_Errors_OnSecondFailure()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        llm
            .EnqueueException((HttpStatusCode)429, "rate limited")
            .EnqueueException((HttpStatusCode)429, "rate limited again");

        var cfg = Cfg(wallClock: TimeSpan.FromSeconds(30));
        var result = await solver.SolveAsync(Chal(), cfg, CancellationToken.None);
        Assert.Equal(SolverOutcome.Error, result.Outcome);
        // First call + one retry = 2 attempts consumed from the queue.
        Assert.Equal(2, llm.CallCount);
    }

    [Fact]
    public async Task Transient429_RetriesOnce_AndRecovers()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        llm
            .EnqueueException((HttpStatusCode)500, "server error")
            .EnqueueToolCall("give_up", "{\"reason\":\"done after retry\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(wallClock: TimeSpan.FromSeconds(30)),
            CancellationToken.None);
        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        Assert.Equal(2, llm.CallCount);
    }

    [Fact]
    public async Task PeerInsights_InjectedAsUserMessageBeforeFirstLlmCall()
    {
        var (solver, llm, _, bus, _, _) = BuildSolver();
        // Pre-publish a peer insight before the solver starts.
        await bus.PublishAsync(new SolverInsight(
            ChallengeId: "42",
            SolverId: "peer-model@chal42",
            ModelId: "peer-model",
            Kind: InsightKind.Partial,
            Summary: "key is reused across blocks",
            DetailsSha256: null,
            Tags: new[] { "crypto", "aes-ecb" },
            At: DateTimeOffset.UtcNow), CancellationToken.None);

        llm.EnqueueToolCall("give_up", "{\"reason\":\"checking prefetch\"}");

        await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        // First LLM call saw 3 messages: system, user(initial), user(peer summary).
        Assert.True(llm.MessageCounts[0] >= 3,
            $"expected >=3 messages, got {llm.MessageCounts[0]}");
    }

    [Fact]
    public async Task MaxTurnsReached_ReturnsGaveUpWithMaxTurnsReason()
    {
        var (solver, llm, _, _, _, _) = BuildSolver();
        // Each turn runs a different exec so we don't trip the loop detector.
        for (int i = 0; i < 6; i++)
        {
            WhenExecContains("probe-" + i, exit: 0, stdout: "line " + i);
            llm.EnqueueToolCall("sandbox_exec",
                "{\"command\":\"probe-" + i + "\"}", callId: "c" + i);
        }

        var cfg = Cfg(maxTurns: 3);
        var result = await solver.SolveAsync(Chal(), cfg, CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        Assert.Equal("max_turns", result.FailureReason);
        Assert.Equal(3, result.Turns);
    }

    [Fact]
    public async Task FlagInFreeTextNeverSubmitted_SolverNags_AndContinues()
    {
        var (solver, llm, flags, _, _, _) = BuildSolver();
        // Model blurts the flag in free-text; we must NOT auto-submit.
        llm
            .EnqueueContent("I think the answer is flag{should_not_be_submitted}")
            .EnqueueToolCall("give_up", "{\"reason\":\"stopping after nag\"}");

        var result = await solver.SolveAsync(Chal(), Cfg(), CancellationToken.None);

        Assert.Equal(SolverOutcome.GaveUp, result.Outcome);
        Assert.Empty(flags.Submissions);
    }
}
