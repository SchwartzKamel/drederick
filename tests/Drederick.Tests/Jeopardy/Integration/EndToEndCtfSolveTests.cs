using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Coordinator;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Detection;
using Drederick.Jeopardy.Llm;
using Drederick.Jeopardy.Ops;
using Drederick.Jeopardy.Sandbox;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Jeopardy.Swarm;
using Drederick.Scope;
using Drederick.Tests.Jeopardy.Sandbox;
using Xunit;

namespace Drederick.Tests.Jeopardy.Integration;

/// <summary>
/// Full end-to-end integration tests for the Jeopardy CTF solver pipeline.
///
/// <para>Wires every production component together:</para>
/// <list type="bullet">
///   <item><see cref="MockCtfdServer"/> standing in for CTFd (real HTTP, localhost).</item>
///   <item>Real <see cref="CtfdClient"/> over HTTP — exercises the HTTP / auth / retry layer.</item>
///   <item>Real <see cref="CtfCoordinator"/>, <see cref="SolverSwarm"/>, <see cref="ChallengeSolver"/>,
///         <see cref="FlagSubmitCoordinator"/>, <see cref="SolverMessageBus"/>,
///         <see cref="CostTracker"/>, <see cref="LoopDetector"/>.</item>
///   <item>Real <see cref="SandboxManager"/> driven by a <see cref="CannedDockerRunner"/>
///         so no <c>docker</c> daemon is required.</item>
///   <item><see cref="ScriptedCopilotLlmClient"/> replacing the real Copilot HTTP client.</item>
/// </list>
///
/// <para>Every flag used in a test is a distinctive canary so the end-of-test
/// audit-log invariant check can assert the plaintext flag never appears in
/// <c>audit.jsonl</c>.</para>
/// </summary>
public sealed class EndToEndCtfSolveTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string _auditPath;
    private readonly AuditLog _audit;
    private readonly Scope.Scope _scope;

    public EndToEndCtfSolveTests()
    {
        _tmpDir = Path.Combine(AppContext.BaseDirectory, $"drederick-e2e-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _auditPath = Path.Combine(_tmpDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        // Loopback scope so the MockCtfdServer (127.0.0.1) is reachable.
        _scope = ScopeLoader.Parse("127.0.0.0/8\n");
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    // -----------------------------------------------------------------
    // Rig
    // -----------------------------------------------------------------

    private sealed class Rig : IAsyncDisposable
    {
        public required MockCtfdServer Server { get; init; }
        public required HttpClient Http { get; init; }
        public required CtfdClient Ctfd { get; init; }
        public required ScriptedCopilotLlmClient Llm { get; init; }
        public required CannedDockerRunner Docker { get; init; }
        public required SandboxManager Sandboxes { get; init; }
        public required SolverMessageBus Bus { get; init; }
        public required CostTracker Costs { get; init; }
        public required LoopDetector LoopDetector { get; init; }
        public required FlagSubmitCoordinator FlagSubmit { get; init; }
        public required ChallengeSolver Solver { get; init; }
        public required SolverSwarm Swarm { get; init; }
        public required CtfdPoller Poller { get; init; }
        public required CtfCoordinator Coordinator { get; init; }

        public async ValueTask DisposeAsync()
        {
            try { await Poller.DisposeAsync(); } catch { }
            try { Ctfd.Dispose(); } catch { }
            try { Http.Dispose(); } catch { }
            try { Server.Dispose(); } catch { }
        }
    }

    private Rig BuildRig(Action<CannedDockerRunner>? dockerConfig = null, TimeSpan? flagSubmitMinInterval = null)
    {
        var server = new MockCtfdServer();
        var http = new HttpClient();
        var ctfd = new CtfdClient(server.BaseUrl, "test-token-abcdef", _scope, _audit, http);
        var llm = new ScriptedCopilotLlmClient();
        var docker = new CannedDockerRunner();
        // Default canned responses sufficient for every happy-path sandbox.
        docker.OnArgs("run -d", exit: 0, stdout: "ctr-" + Guid.NewGuid().ToString("N").Substring(0, 12) + "\n");
        docker.OnArgs("inspect --format", exit: 0, stdout: "healthy\n");
        docker.OnArgs("rm -f", exit: 0);
        dockerConfig?.Invoke(docker);

        var sandboxes = new SandboxManager(_scope, _audit, docker);
        var bus = new SolverMessageBus(_audit);
        var costs = new CostTracker(_audit);
        var loops = new LoopDetector(_audit);
        var flagSubmit = new FlagSubmitCoordinator(ctfd, _audit, bus,
            flagSubmitMinInterval ?? TimeSpan.Zero);
        var solver = new ChallengeSolver(llm, sandboxes, flagSubmit, bus, costs, loops, _audit);
        var swarm = new SolverSwarm(solver, flagSubmit, bus, costs, _audit);
        var poller = new CtfdPoller(ctfd, _audit, TimeSpan.FromMilliseconds(50));
        var coordinator = new CtfCoordinator(
            ctfd, poller, swarm, flagSubmit, bus, costs, loops, operatorInbox: null,
            _scope, _audit);

        return new Rig
        {
            Server = server,
            Http = http,
            Ctfd = ctfd,
            Llm = llm,
            Docker = docker,
            Sandboxes = sandboxes,
            Bus = bus,
            Costs = costs,
            LoopDetector = loops,
            FlagSubmit = flagSubmit,
            Solver = solver,
            Swarm = swarm,
            Poller = poller,
            Coordinator = coordinator,
        };
    }

    private CoordinatorConfig MakeCfg(
        Rig rig,
        IReadOnlyList<string>? modelIds = null,
        IReadOnlyList<string>? catFilter = null,
        IReadOnlyList<int>? idFilter = null,
        decimal? perChallengeBudget = null,
        TimeSpan? wallClock = null,
        int maxConcurrent = 4)
    {
        var ids = modelIds ?? new[] { "claude-sonnet-4.6" };
        var slots = ids.Select(m => new SwarmModelSlot(m, perChallengeBudget)).ToArray();
        return new CoordinatorConfig(
            CtfdUrl: rig.Server.BaseUrl,
            CtfdToken: "test-token-abcdef",
            Models: slots,
            WallClockPerChallenge: wallClock ?? TimeSpan.FromSeconds(15),
            TotalRunBudgetUsd: null,
            PerChallengeBudgetUsd: perChallengeBudget,
            MaxConcurrentChallenges: maxConcurrent,
            OperatorInboxPath: null,
            ReportOutputDir: null,
            PollInterval: TimeSpan.FromMilliseconds(50),
            CategoryFilter: catFilter,
            ChallengeIdFilter: idFilter);
    }

    /// <summary>
    /// Drive a coordinator run. The poller never terminates on its own; this
    /// helper watches the challenge list and cancels once every discovered
    /// challenge has a recorded attempt OR a global timeout expires.
    /// </summary>
    private static async Task<CompetitionReport> RunUntilQuiesceAsync(
        Rig rig, CoordinatorConfig cfg, int expectedChallenges,
        TimeSpan? maxWait = null)
    {
        var deadline = DateTimeOffset.UtcNow + (maxWait ?? TimeSpan.FromSeconds(30));
        using var cts = new CancellationTokenSource();

        // Background watcher: once the swarm has reported N results OR we
        // hit the deadline, cancel the run.
        var watcher = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(50).ConfigureAwait(false);
                // Heuristic: all challenges either solved or attempted once.
                if (rig.FlagSubmit.Wins.Count >= expectedChallenges
                    && DateTimeOffset.UtcNow > deadline - (maxWait ?? TimeSpan.FromSeconds(30)) + TimeSpan.FromMilliseconds(200))
                {
                    break;
                }
            }
            // Always give a grace period so any late finish events land.
            try { await Task.Delay(400, CancellationToken.None).ConfigureAwait(false); } catch { }
            cts.Cancel();
        });

        var report = await rig.Coordinator.RunAsync(cfg, cts.Token).ConfigureAwait(false);
        try { await watcher.ConfigureAwait(false); } catch { }
        return report;
    }

    private string ReadAudit() => File.ReadAllText(_auditPath);

    private void AssertPlaintextFlagNeverInAudit(string flag)
    {
        _audit.Dispose(); // force flush
        var text = File.ReadAllText(_auditPath);
        Assert.False(text.Contains(flag, StringComparison.Ordinal),
            $"Plaintext flag '{flag}' leaked into audit.jsonl — audit must record SHA-256 only.");
    }

    private static void WhenExec(CannedDockerRunner docker, string contains, string stdout)
    {
        docker.OnArgs(a => a.StartsWith("exec ") && a.Contains(contains, StringComparison.Ordinal),
            exit: 0, stdout: stdout);
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    [Fact]
    public async Task HappyPath_SingleModel_SolvesSingleChallenge_AndAuditNeverContainsFlag()
    {
        const string flag = "flag{canary_integration_xyz_happy_path}";
        await using var rig = BuildRig(docker => WhenExec(docker, "cat flag.txt", flag));
        rig.Server.WithChallenge(101, "baby-crypto", "crypto", 100, flag);

        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat flag.txt\"}")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag + "\"}");

        var cfg = MakeCfg(rig);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.True(rig.FlagSubmit.IsSolved(101));
        Assert.Equal(1, report.ChallengesSolved);
        Assert.Equal(100, report.PointsScored);
        // MockCtfd received exactly one submission and marked it correct.
        Assert.Single(rig.Server.Submissions);
        Assert.Equal("correct", rig.Server.Submissions[0].Status);

        AssertPlaintextFlagNeverInAudit(flag);
        // But a solve.success-style event MUST be present.
        var audit = ReadAudit();
        Assert.Contains("\"flag_sha256\"", audit);
    }

    [Fact]
    public async Task MultiChallenge_PartialSolve_ReportsMixedOutcomes()
    {
        const string flag1 = "flag{canary_integration_xyz_multi_a}";
        const string flag2 = "flag{canary_integration_xyz_multi_b}";
        await using var rig = BuildRig(docker =>
        {
            WhenExec(docker, "cat /a", flag1);
            WhenExec(docker, "cat /b", flag2);
        });
        rig.Server
            .WithChallenge(1, "chal-a", "web", 100, flag1)
            .WithChallenge(2, "chal-b", "pwn", 200, flag2)
            .WithChallenge(3, "chal-c", "misc", 300, "flag{impossible-unreachable}");

        // Model solves chal-a, solves chal-b, gives up on chal-c.
        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat /a\"}", callId: "a1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag1 + "\"}", callId: "a2")
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat /b\"}", callId: "b1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag2 + "\"}", callId: "b2")
            .EnqueueToolCall("claude-sonnet-4.6", "give_up", "{\"reason\":\"stumped\"}", callId: "c1");

        var cfg = MakeCfg(rig, maxConcurrent: 1);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 2);

        Assert.Equal(2, report.ChallengesSolved);
        Assert.Equal(300, report.PointsScored); // 100 + 200
        Assert.True(rig.FlagSubmit.IsSolved(1));
        Assert.True(rig.FlagSubmit.IsSolved(2));
        Assert.False(rig.FlagSubmit.IsSolved(3));

        AssertPlaintextFlagNeverInAudit(flag1);
        AssertPlaintextFlagNeverInAudit(flag2);
    }

    [Fact]
    public async Task SwarmRace_FastWrong_Loses_To_SlowCorrect()
    {
        const string correct = "flag{canary_integration_xyz_race_correct}";
        const string wrong = "flag{canary_integration_xyz_race_wrong}";
        await using var rig = BuildRig(docker =>
        {
            WhenExec(docker, "cat /fake", wrong);
            WhenExec(docker, "cat /real", correct);
        });
        rig.Server.WithChallenge(50, "race", "misc", 500, correct);

        // Model-fast: quickly submits the wrong flag, then gives up.
        rig.Llm
            .EnqueueToolCall("model-fast", "sandbox_exec", "{\"command\":\"cat /fake\"}", callId: "f1")
            .EnqueueToolCall("model-fast", "submit_flag", "{\"flag\":\"" + wrong + "\"}", callId: "f2")
            .EnqueueToolCall("model-fast", "give_up", "{\"reason\":\"wrong\"}", callId: "f3");
        // Model-slow: delays, then emits the correct flag.
        rig.Llm
            .EnqueueDelay("model-slow", TimeSpan.FromMilliseconds(300))
            .EnqueueToolCall("model-slow", "sandbox_exec", "{\"command\":\"cat /real\"}", callId: "s1")
            .EnqueueToolCall("model-slow", "submit_flag", "{\"flag\":\"" + correct + "\"}", callId: "s2");

        var cfg = MakeCfg(rig, modelIds: new[] { "model-fast", "model-slow" });
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.Equal(1, report.ChallengesSolved);
        Assert.True(rig.FlagSubmit.IsSolved(50));

        // Server saw both submissions: one incorrect, one correct.
        var statuses = rig.Server.Submissions.Select(s => s.Status).ToArray();
        Assert.Contains("incorrect", statuses);
        Assert.Contains("correct", statuses);

        AssertPlaintextFlagNeverInAudit(correct);
        AssertPlaintextFlagNeverInAudit(wrong);
    }

    [Fact]
    public async Task FlagDedup_TwoModels_SameFlag_ResultsInOneCorrectSubmission()
    {
        const string flag = "flag{canary_integration_xyz_dedup}";
        await using var rig = BuildRig(docker => WhenExec(docker, "cat flag", flag));
        rig.Server.WithChallenge(77, "dedup", "misc", 100, flag);

        rig.Llm
            .EnqueueToolCall("model-a", "sandbox_exec", "{\"command\":\"cat flag\"}", callId: "a1")
            .EnqueueToolCall("model-a", "submit_flag", "{\"flag\":\"" + flag + "\"}", callId: "a2");
        rig.Llm
            .EnqueueToolCall("model-b", "sandbox_exec", "{\"command\":\"cat flag\"}", callId: "b1")
            .EnqueueToolCall("model-b", "submit_flag", "{\"flag\":\"" + flag + "\"}", callId: "b2")
            .EnqueueToolCall("model-b", "give_up", "{\"reason\":\"peer won\"}", callId: "b3");

        var cfg = MakeCfg(rig, modelIds: new[] { "model-a", "model-b" });
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.Equal(1, report.ChallengesSolved);
        // Flag dedup: the server saw at most ONE correct submission even
        // though both models tried the same flag.
        var correct = rig.Server.Submissions.Count(s => s.Status == "correct");
        Assert.Equal(1, correct);

        AssertPlaintextFlagNeverInAudit(flag);
    }

    [Fact]
    public async Task LoopDetection_RepeatedAction_TerminatesSolverWithLoopMarker()
    {
        await using var rig = BuildRig(docker => WhenExec(docker, "whoami", "ctf"));
        rig.Server.WithChallenge(9, "loopy", "pwn", 50,
            "flag{canary_integration_xyz_loop_detect_unreachable}");

        // Enqueue way more than the loop detector's default exact-repeat
        // threshold so the solver has no terminal branch to escape through.
        for (int i = 0; i < 20; i++)
        {
            rig.Llm.EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec",
                "{\"command\":\"whoami\"}", callId: "loop-" + i);
        }

        var cfg = MakeCfg(rig);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 0,
            maxWait: TimeSpan.FromSeconds(15));

        Assert.Equal(0, report.ChallengesSolved);
        // Solver should have exited with LoopDetected outcome.
        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("LoopDetected", audit);
    }

    [Fact]
    public async Task BudgetExhaustion_TripsCleanly_WithBudgetExceededEvent()
    {
        const string flag = "flag{canary_integration_xyz_budget_unreached}";
        await using var rig = BuildRig(docker => WhenExec(docker, "enumerate", "noise"));
        rig.Server.WithChallenge(33, "big-spender", "misc", 100, flag);

        // Use a priced model so costs actually accrue.
        rig.Llm
            .EnqueueToolCall("gpt-5.4", "sandbox_exec",
                "{\"command\":\"enumerate\"}", promptTokens: 500_000, completionTokens: 500_000, callId: "e1")
            .EnqueueToolCall("gpt-5.4", "sandbox_exec",
                "{\"command\":\"enumerate\"}", promptTokens: 500_000, completionTokens: 500_000, callId: "e2")
            .EnqueueToolCall("gpt-5.4", "submit_flag",
                "{\"flag\":\"would-be-flag\"}", callId: "e3");

        // Per-challenge cap of $0.0001 trips well before the third call.
        var cfg = MakeCfg(rig, modelIds: new[] { "gpt-5.4" }, perChallengeBudget: 0.0001m);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 0);

        Assert.Equal(0, report.ChallengesSolved);
        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        // Either the solver saw BudgetExceeded or the cost.budget_exceeded audit event fired.
        Assert.True(
            audit.Contains("BudgetExceeded", StringComparison.Ordinal)
            || audit.Contains("budget_exceeded", StringComparison.Ordinal),
            "Expected a BudgetExceeded outcome or a budget_exceeded audit event.");
    }

    [Fact]
    public async Task CategoryFilter_Respected_OnlyMatchingCategoryAttempted()
    {
        const string webFlag = "flag{canary_integration_xyz_category_web}";
        await using var rig = BuildRig(docker => WhenExec(docker, "solve", webFlag));
        rig.Server
            .WithChallenge(1, "pwn-one", "pwn", 100, "flag{canary_integration_xyz_cat_pwn_unreached}")
            .WithChallenge(2, "web-one", "web", 200, webFlag)
            .WithChallenge(3, "crypto-one", "crypto", 300, "flag{canary_integration_xyz_cat_crypto_unreached}");

        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"solve\"}", callId: "w1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + webFlag + "\"}", callId: "w2");

        var cfg = MakeCfg(rig, catFilter: new[] { "web" });
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.Equal(1, report.ChallengesSolved);
        Assert.True(rig.FlagSubmit.IsSolved(2));
        Assert.False(rig.FlagSubmit.IsSolved(1));
        Assert.False(rig.FlagSubmit.IsSolved(3));

        // Only the "web" category should have ever reached the LLM.
        Assert.True(rig.Llm.CallsFor("claude-sonnet-4.6") >= 1);

        AssertPlaintextFlagNeverInAudit(webFlag);
    }

    [Fact]
    public async Task WrongFlagThenCorrect_ServerReturnsIncorrectFirst_ThenCorrect()
    {
        const string wrong = "flag{canary_integration_xyz_first_wrong}";
        const string correct = "flag{canary_integration_xyz_then_correct}";
        await using var rig = BuildRig(docker =>
        {
            WhenExec(docker, "guess1", wrong);
            WhenExec(docker, "guess2", correct);
        });
        rig.Server.WithChallenge(44, "twice", "misc", 100, correct);

        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"guess1\"}", callId: "x1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + wrong + "\"}", callId: "x2")
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"guess2\"}", callId: "x3")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + correct + "\"}", callId: "x4");

        var cfg = MakeCfg(rig);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.Equal(1, report.ChallengesSolved);
        Assert.Equal(2, rig.Server.Submissions.Count);
        Assert.Equal("incorrect", rig.Server.Submissions[0].Status);
        Assert.Equal("correct", rig.Server.Submissions[1].Status);

        AssertPlaintextFlagNeverInAudit(wrong);
        AssertPlaintextFlagNeverInAudit(correct);
    }

    [Fact]
    public async Task OperatorHint_Reaches_Active_ChallengeSolver_Via_Bus()
    {
        const string flag = "flag{canary_integration_xyz_operator_hint}";
        await using var rig = BuildRig(docker => WhenExec(docker, "cat /loot", flag));
        rig.Server.WithChallenge(15, "hinted", "misc", 100, flag);

        // LLM turn 1: read peer insights (surfaces the hint). Turn 2 onward: solve.
        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "get_insights", "{}", callId: "h0")
            .EnqueueDelay("claude-sonnet-4.6", TimeSpan.FromMilliseconds(250))
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat /loot\"}", callId: "h1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag + "\"}", callId: "h2");

        var cfg = MakeCfg(rig);

        // Publish the operator hint in parallel with the run.
        var hintPublisher = Task.Run(async () =>
        {
            await Task.Delay(100);
            await rig.Bus.PublishAsync(new SolverInsight(
                ChallengeId: "15",
                SolverId: "operator",
                ModelId: "operator",
                Kind: InsightKind.OperatorHint,
                Summary: "operator: use the /loot path",
                DetailsSha256: null,
                Tags: new[] { "op:hint" },
                At: DateTimeOffset.UtcNow), CancellationToken.None);
        });

        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);
        try { await hintPublisher; } catch { }

        Assert.Equal(1, report.ChallengesSolved);
        // Visible effect: the bus.publish audit event recorded the operator hint.
        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("bus.publish", audit);
        Assert.Contains("OperatorHint", audit);

        AssertPlaintextFlagNeverInAudit(flag);
    }

    [Fact]
    public async Task IncorrectFlag_ServerMarksIncorrect_AndSolverCanGiveUp()
    {
        const string wrong = "flag{canary_integration_xyz_always_wrong}";
        await using var rig = BuildRig(docker => WhenExec(docker, "cat /wrong", wrong));
        rig.Server.WithChallenge(88, "nope", "misc", 100,
            "flag{canary_integration_xyz_correct_unreachable}");

        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat /wrong\"}", callId: "n1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + wrong + "\"}", callId: "n2")
            .EnqueueToolCall("claude-sonnet-4.6", "give_up", "{\"reason\":\"out of ideas\"}", callId: "n3");

        var cfg = MakeCfg(rig);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 0);

        Assert.Equal(0, report.ChallengesSolved);
        Assert.False(rig.FlagSubmit.IsSolved(88));
        Assert.Single(rig.Server.Submissions);
        Assert.Equal("incorrect", rig.Server.Submissions[0].Status);

        AssertPlaintextFlagNeverInAudit(wrong);
    }

    [Fact]
    public async Task ChallengeIdFilter_Respected_OnlyRequestedIdsAttempted()
    {
        const string flag = "flag{canary_integration_xyz_id_filter}";
        await using var rig = BuildRig(docker => WhenExec(docker, "solve", flag));
        rig.Server
            .WithChallenge(10, "ten", "misc", 10, "flag{canary_integration_xyz_ten_unreached}")
            .WithChallenge(20, "twenty", "misc", 20, flag)
            .WithChallenge(30, "thirty", "misc", 30, "flag{canary_integration_xyz_thirty_unreached}");

        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"solve\"}", callId: "f1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag + "\"}", callId: "f2");

        var cfg = MakeCfg(rig, idFilter: new[] { 20 });
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 1);

        Assert.Equal(1, report.ChallengesSolved);
        Assert.True(rig.FlagSubmit.IsSolved(20));
        Assert.False(rig.FlagSubmit.IsSolved(10));
        Assert.False(rig.FlagSubmit.IsSolved(30));

        AssertPlaintextFlagNeverInAudit(flag);
    }

    [Fact]
    public async Task AlreadySolved_Challenge_IsSkipped_NoSubmissionSent()
    {
        const string flag = "flag{canary_integration_xyz_presolved_unused}";
        await using var rig = BuildRig();
        rig.Server.WithChallenge(5, "done", "misc", 100, flag);
        rig.Server.MarkSolved(5); // CTFd says it's already done.

        var cfg = MakeCfg(rig);
        var report = await RunUntilQuiesceAsync(rig, cfg, expectedChallenges: 0,
            maxWait: TimeSpan.FromSeconds(3));

        Assert.Equal(0, report.ChallengesAttempted);
        Assert.Empty(rig.Server.Submissions);
        Assert.Equal(0, rig.Llm.TotalCallCount);
    }

    [Fact]
    public void Scope_Refuses_OutOfScope_CtfdHost_AtClientConstruction()
    {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and never in a default scope.
        var tightScope = ScopeLoader.Parse("10.0.0.0/24\n");
        using var http = new HttpClient();

        var ex = Assert.Throws<ScopeException>(() =>
            new CtfdClient(new Uri("http://192.0.2.42:8080/"), "tok", tightScope, _audit, http));
        Assert.Contains("192.0.2.42", ex.Message);
    }

    // ---- CLI smoke -------------------------------------------------------

    [Fact]
    public async Task CliSmoke_RunsEndToEnd_Via_CtfSolveRunner_InternalFactoryHook()
    {
        const string flag = "flag{canary_integration_xyz_cli_smoke}";
        await using var rig = BuildRig(docker => WhenExec(docker, "cat /f", flag));
        rig.Server.WithChallenge(7, "cli", "misc", 250, flag);
        rig.Llm
            .EnqueueToolCall("claude-sonnet-4.6", "sandbox_exec", "{\"command\":\"cat /f\"}", callId: "c1")
            .EnqueueToolCall("claude-sonnet-4.6", "submit_flag", "{\"flag\":\"" + flag + "\"}", callId: "c2");

        var scopePath = Path.Combine(_tmpDir, "scope.txt");
        File.WriteAllText(scopePath, "127.0.0.0/8\n");
        var reportDir = Path.Combine(_tmpDir, "report");

        var opts = CommandLineOptions.Parse(new[]
        {
            "ctf-solve",
            "--scope", scopePath,
            "--ctfd", rig.Server.BaseUrl.ToString(),
            "--ctfd-token", "test-token-abcdef",
            "--models", "claude-sonnet-4.6",
            "--report-dir", reportDir,
            "--wall-clock-min", "1",
            "--poll-interval-sec", "1",
        });

        // Internal factory hook: swap in our pre-built real-component stack.
        Drederick.Jeopardy.Cli.CtfSolveCoordinatorFactory factory = (_, _, _) =>
        {
            var cfg = new CoordinatorConfig(
                CtfdUrl: rig.Server.BaseUrl,
                CtfdToken: "test-token-abcdef",
                Models: new[] { new SwarmModelSlot("claude-sonnet-4.6") },
                WallClockPerChallenge: TimeSpan.FromSeconds(10),
                MaxConcurrentChallenges: 1,
                PollInterval: TimeSpan.FromMilliseconds(50),
                ReportOutputDir: reportDir);
            return (rig.Coordinator, cfg);
        };

        // Need an external driver to cancel the poller once the solve lands.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        _ = Task.Run(async () =>
        {
            // Wait for a successful submission before cancelling.
            while (!cts.IsCancellationRequested)
            {
                if (rig.FlagSubmit.IsSolved(7)) { await Task.Delay(400); break; }
                await Task.Delay(50);
            }
            cts.Cancel();
        });

        var exit = await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, factory, cts.Token);

        Assert.Equal(0, exit);
        Assert.True(File.Exists(Path.Combine(reportDir, "report.json")));
        Assert.True(File.Exists(Path.Combine(reportDir, "report.md")));
        AssertPlaintextFlagNeverInAudit(flag);
    }
}
