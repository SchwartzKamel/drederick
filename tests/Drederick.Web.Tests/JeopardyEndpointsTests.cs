using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Coordinator;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Ops;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Submit;
using Drederick.Jeopardy.Swarm;
using Drederick.Web;
using Drederick.Web.Jeopardy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Drederick.Web.Tests;

/// <summary>
/// Tests for the <c>/api/jeopardy/*</c> REST surface. All tests inject a
/// <see cref="StubJeopardyCoordinatorFactory"/> so no real HTTP / Docker /
/// LLM client is spun up — the factory hands back a stub coordinator whose
/// <see cref="ICtfCoordinator.RunAsync"/> returns a canned
/// <see cref="CompetitionReport"/> only after the session is cancelled.
///
/// <para>Every test that could leak a secret uses a distinctive canary
/// string (<see cref="CanaryToken"/> / <see cref="CanaryFlag"/>) and asserts
/// the canary never appears in <c>audit.jsonl</c> or HTTP responses.</para>
/// </summary>
public sealed class JeopardyEndpointsTests
{
    private const string CanaryToken = "CANARY-CTFD-TOKEN-abc123-XYZ789-should-never-appear";
    private const string CanaryFlag = "CANARY_FLAG{never-in-response-or-audit-42}";

    // ---- fixtures ---------------------------------------------------------

    private static string ResolveRepoFile(string relative)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, relative);
            if (File.Exists(candidate)) return candidate;
            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }
        throw new FileNotFoundException($"Could not locate '{relative}' above {AppContext.BaseDirectory}.");
    }

    private static string WriteTempScope(string contents)
    {
        // Path.GetTempPath mirrors the existing DrederickWebFactory pattern.
        var dir = Path.Combine(Path.GetTempPath(), "drederick-jeopardy-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "scope.txt");
        File.WriteAllText(path, contents);
        return path;
    }

    private static string WriteCwdScope(string contents)
    {
        // Write under the server's cwd so the scope_path traversal guard
        // accepts it. We use AppContext.BaseDirectory which sits under the
        // test bin/ output directory — and Directory.GetCurrentDirectory()
        // at test run time is under the repo root.
        var cwd = Directory.GetCurrentDirectory();
        var dir = Path.Combine(cwd, "jeopardy-test-scopes", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "scope.txt");
        File.WriteAllText(path, contents);
        return path;
    }

    private sealed class JeopardyFactoryHarness : DrederickWebFactory
    {
        public StubJeopardyCoordinatorFactory Factory { get; } = new();

        public JeopardyFactoryHarness(WebAppSettings? seed = null) : base(seed) { }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
            {
                var existing = services
                    .Where(d => d.ServiceType == typeof(IJeopardyCoordinatorFactory)).ToList();
                foreach (var d in existing) services.Remove(d);
                services.AddSingleton<IJeopardyCoordinatorFactory>(Factory);
            });
        }
    }

    private static JeopardyStartRequest DefaultStart(string scopePath, string? url = null, params string[] models) => new()
    {
        CtfdUrl = url ?? "http://127.0.0.1:8080/",
        CtfdToken = CanaryToken,
        ScopePath = scopePath,
        Models = models.Length == 0 ? new List<string> { "claude-sonnet-4.6" } : models.ToList(),
        WallClockMinutes = 1,
        MaxConcurrent = 1,
    };

    // ---- tests ------------------------------------------------------------

    [Fact]
    public async Task Start_HappyPath_ReturnsSessionId_202()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var req = DefaultStart(scope);
        var resp = await client.PostAsJsonAsync("/api/jeopardy/sessions", req);

        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.TryGetProperty("session_id", out var idEl));
        var id = Guid.Parse(idEl.GetString()!);
        Assert.NotEqual(Guid.Empty, id);
    }

    [Fact]
    public async Task Start_OutOfScopeCtfdHost_Returns400()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        // 192.0.2.42 is in TEST-NET-1 — not in 127.0.0.0/8.
        var req = DefaultStart(scope, url: "https://192.0.2.42/");
        var resp = await client.PostAsJsonAsync("/api/jeopardy/sessions", req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var err = await resp.Content.ReadFromJsonAsync<JeopardyErrorDto>();
        Assert.Equal("out_of_scope", err!.Error);
    }

    [Fact]
    public async Task ScopePath_Traversal_Rejected()
    {
        // Write a scope file outside cwd.
        var outside = WriteTempScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var req = DefaultStart(outside);
        var resp = await client.PostAsJsonAsync("/api/jeopardy/sessions", req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var err = await resp.Content.ReadFromJsonAsync<JeopardyErrorDto>();
        Assert.Equal("scope_path_rejected", err!.Error);
    }

    [Fact]
    public async Task Auth_NonLoopback_RequiresBearer()
    {
        var settings = new WebAppSettings
        {
            BindHost = "0.0.0.0",
            BindPort = 0,
            RequireBearer = true,
            Token = "CANARY-web-token-for-jeopardy",
            OutputDir = "out",
        };
        using var factory = new JeopardyFactoryHarness(settings);
        using var client = factory.CreateClient();

        // No header — 401 on start.
        var noAuth = await client.PostAsJsonAsync(
            "/api/jeopardy/sessions", DefaultStart(WriteCwdScope("127.0.0.0/8\n")));
        Assert.Equal(HttpStatusCode.Unauthorized, noAuth.StatusCode);

        // With correct bearer — 202.
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/jeopardy/sessions")
        {
            Content = JsonContent.Create(DefaultStart(WriteCwdScope("127.0.0.0/8\n"))),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.Token);
        var ok = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Accepted, ok.StatusCode);
    }

    [Fact]
    public async Task List_ReturnsActiveSessions()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));

        var listResp = await client.GetAsync("/api/jeopardy/sessions");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        var sessions = await listResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(sessions.GetArrayLength() >= 2);
    }

    [Fact]
    public async Task Get_ReturnsChallengeRoster_WithSwarmState()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        factory.Factory.Challenges = new[]
        {
            new CtfdChallenge(1, "babyrop", "pwn", 100, "d", Array.Empty<CtfdAttachment>(), Array.Empty<string>(), null, false),
            new CtfdChallenge(2, "rsa100", "crypto", 100, "d", Array.Empty<CtfdAttachment>(), Array.Empty<string>(), null, false),
        };
        using var client = factory.CreateClient();

        var start = await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        var id = (await start.Content.ReadFromJsonAsync<JeopardyStartResponse>())!.SessionId;

        var swarmResp = await client.GetAsync($"/api/jeopardy/sessions/{id:D}/swarm");
        Assert.Equal(HttpStatusCode.OK, swarmResp.StatusCode);
        var swarm = await swarmResp.Content.ReadFromJsonAsync<List<JeopardyChallengeStateDto>>();
        Assert.Equal(2, swarm!.Count);
        Assert.Equal("racing", swarm[0].State);
        Assert.Single(swarm[0].ActiveSolvers);

        var chalResp = await client.GetAsync($"/api/jeopardy/sessions/{id:D}/challenges/1");
        Assert.Equal(HttpStatusCode.OK, chalResp.StatusCode);
        var chal = await chalResp.Content.ReadFromJsonAsync<JeopardyChallengeStateDto>();
        Assert.Equal(1, chal!.Id);
        Assert.Equal("babyrop", chal.Name);
    }

    [Fact]
    public async Task Cancel_TerminatesRun_ReturnsTriggeredCts()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var start = await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        var id = (await start.Content.ReadFromJsonAsync<JeopardyStartResponse>())!.SessionId;

        var cancel = await client.DeleteAsync($"/api/jeopardy/sessions/{id:D}");
        Assert.Equal(HttpStatusCode.NoContent, cancel.StatusCode);

        // Give the stub coordinator time to observe the cancel.
        for (int i = 0; i < 40; i++)
        {
            var detail = await client.GetAsync($"/api/jeopardy/sessions/{id:D}");
            if (detail.StatusCode == HttpStatusCode.OK)
            {
                var d = await detail.Content.ReadFromJsonAsync<JeopardySessionDetail>();
                if (d!.Status is "cancelled" or "completed") return;
            }
            await Task.Delay(50);
        }
        Assert.Fail("Session never transitioned out of 'running' after cancel.");
    }

    [Fact]
    public async Task HintInjection_DeliveredToOperatorBus()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var start = await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        var id = (await start.Content.ReadFromJsonAsync<JeopardyStartResponse>())!.SessionId;

        var hintReq = new Dictionary<string, object?>
        {
            ["challenge_id"] = 42,
            ["kind"] = "hint",
            ["body"] = "try ret2libc via puts",
        };
        var hintResp = await client.PostAsJsonAsync(
            $"/api/jeopardy/sessions/{id:D}/hints", hintReq);
        Assert.Equal(HttpStatusCode.OK, hintResp.StatusCode);

        // Read back the inbox file the session points at.
        var inboxPath = factory.Factory.LastInboxPath!;
        Assert.True(File.Exists(inboxPath), "inbox file should exist after hint send");

        // Wait until the file has at least one line.
        string line = "";
        for (int i = 0; i < 40; i++)
        {
            var text = await File.ReadAllTextAsync(inboxPath);
            if (!string.IsNullOrWhiteSpace(text))
            {
                line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0];
                break;
            }
            await Task.Delay(50);
        }
        Assert.Contains("\"Kind\":\"hint\"", line, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("try ret2libc", line, StringComparison.Ordinal);

        // And the history endpoint reflects it.
        var histResp = await client.GetAsync($"/api/jeopardy/sessions/{id:D}/hints");
        Assert.Equal(HttpStatusCode.OK, histResp.StatusCode);
        var history = await histResp.Content.ReadFromJsonAsync<List<JeopardyHintHistoryDto>>();
        Assert.Single(history!);
        Assert.Equal("hint", history[0].Kind);
        Assert.Equal("42", history[0].ChallengeId);
    }

    [Fact]
    public async Task PlaintextFlag_NeverInResponse()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        factory.Factory.Challenges = new[]
        {
            new CtfdChallenge(7, "web easy", "web", 50, "d", Array.Empty<CtfdAttachment>(), Array.Empty<string>(), null, false),
        };
        using var client = factory.CreateClient();

        var start = await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        var id = (await start.Content.ReadFromJsonAsync<JeopardyStartResponse>())!.SessionId;

        // Drive the stub to report a correct flag submission.
        factory.Factory.AnnounceSolved(7, CanaryFlag, "claude-sonnet-4.6");

        // Poll detail until flags_submitted shows our entry.
        JeopardySessionDetail? detail = null;
        for (int i = 0; i < 40; i++)
        {
            var r = await client.GetAsync($"/api/jeopardy/sessions/{id:D}");
            detail = await r.Content.ReadFromJsonAsync<JeopardySessionDetail>();
            if (detail!.FlagsSubmitted.Count > 0) break;
            await Task.Delay(50);
        }
        Assert.NotNull(detail);
        Assert.Single(detail!.FlagsSubmitted);
        var flag = detail.FlagsSubmitted[0];
        Assert.True(flag.Correct);
        Assert.Equal("claude-sonnet-4.6", flag.SolvedByModel);
        Assert.NotNull(flag.FlagSha256);
        Assert.NotEmpty(flag.FlagSha256);

        // The HTTP body must never carry the plaintext flag.
        var rawJson = await (await client.GetAsync($"/api/jeopardy/sessions/{id:D}"))
            .Content.ReadAsStringAsync();
        Assert.DoesNotContain(CanaryFlag, rawJson, StringComparison.Ordinal);

        // Swarm shape too.
        var swarmJson = await (await client.GetAsync($"/api/jeopardy/sessions/{id:D}/swarm"))
            .Content.ReadAsStringAsync();
        Assert.DoesNotContain(CanaryFlag, swarmJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CtfdToken_NeverInAudit()
    {
        var scope = WriteCwdScope("127.0.0.0/8\n");
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/jeopardy/sessions", DefaultStart(scope));
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        // Let the AuditLog auto-flush catch up.
        await Task.Delay(100);

        var auditContents = await File.ReadAllTextAsync(factory.AuditLogPath);
        Assert.DoesNotContain(CanaryToken, auditContents, StringComparison.Ordinal);
        // SHA-256 of the token must be present.
        var expected = JeopardySessionManager.Sha256Hex(CanaryToken);
        Assert.Contains(expected, auditContents, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_MissingFields_Returns400()
    {
        using var factory = new JeopardyFactoryHarness();
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/jeopardy/sessions", new JeopardyStartRequest());
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var err = await resp.Content.ReadFromJsonAsync<JeopardyErrorDto>();
        Assert.Equal("invalid_request", err!.Error);
    }

    // ---- stub coordinator ------------------------------------------------

    /// <summary>
    /// Factory that hands back a <see cref="StubCoordinator"/> with the
    /// same bus / flag-submit / inbox wiring the real factory uses but no
    /// CTFd / Docker / LLM clients. Tests drive the stub by setting
    /// <see cref="Challenges"/> and calling <see cref="AnnounceSolved"/>.
    /// </summary>
    private sealed class StubJeopardyCoordinatorFactory : IJeopardyCoordinatorFactory
    {
        public IReadOnlyList<CtfdChallenge> Challenges { get; set; } = Array.Empty<CtfdChallenge>();
        public string? LastInboxPath { get; private set; }
        public StubFlagSubmit? LastFlagSubmit { get; private set; }

        public Task<JeopardyCoordinatorBundle> CreateAsync(JeopardyFactoryContext ctx, CancellationToken ct)
        {
            var audit = new AuditLog(Path.Combine(ctx.SessionDir, "session-audit.jsonl"));
            var bus = new SolverMessageBus(audit);
            var flagSubmit = new StubFlagSubmit();
            LastFlagSubmit = flagSubmit;

            var inboxPath = Path.Combine(ctx.SessionDir, "inbox.jsonl");
            LastInboxPath = inboxPath;

            var coordinator = new StubCoordinator();
            var config = new CoordinatorConfig(
                CtfdUrl: ctx.CtfdUri,
                CtfdToken: ctx.Request.CtfdToken,
                Models: ctx.Request.Models.Select(m => new SwarmModelSlot(m)).ToArray(),
                WallClockPerChallenge: TimeSpan.FromMinutes(ctx.Request.WallClockMinutes ?? 1),
                OperatorInboxPath: inboxPath,
                ReportOutputDir: ctx.SessionDir);

            var bundle = new JeopardyCoordinatorBundle(
                Coordinator: coordinator,
                Config: config,
                Bus: bus,
                FlagSubmit: flagSubmit,
                InboxPath: inboxPath,
                InitialChallenges: Challenges,
                AsyncDisposables: new IAsyncDisposable[] { bus },
                Disposables: new IDisposable[] { audit });
            return Task.FromResult(bundle);
        }

        public void AnnounceSolved(int challengeId, string flag, string model)
        {
            var outcome = new FlagOutcome(
                ChallengeId: challengeId,
                Flag: flag,
                Correct: true,
                AlreadySolved: false,
                WinnerSolverId: $"solver-{challengeId}",
                WinnerModelId: model,
                SubmittedAt: DateTimeOffset.UtcNow,
                Message: "accepted");
            LastFlagSubmit?.Announce(outcome);
        }
    }

    private sealed class StubCoordinator : ICtfCoordinator
    {
        public async Task<CompetitionReport> RunAsync(CoordinatorConfig cfg, CancellationToken ct)
        {
            // Block until cancelled — the session manager cancels on DELETE.
            try
            {
                await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            return new CompetitionReport(
                StartedAt: DateTimeOffset.UtcNow.AddMinutes(-1),
                FinishedAt: DateTimeOffset.UtcNow,
                ChallengesDiscovered: 0,
                ChallengesSolved: 0,
                ChallengesAttempted: 0,
                PointsScored: 0,
                TotalUsdCost: 0m,
                PerChallenge: Array.Empty<SwarmResult>(),
                SolvesByModel: new Dictionary<string, int>(),
                AttemptsByCategory: new Dictionary<string, int>());
        }
    }

    private sealed class StubFlagSubmit : IFlagSubmitCoordinator
    {
        private readonly List<FlagOutcome> _wins = new();
        public event Action<FlagOutcome>? ChallengeSolved;

        public IReadOnlyList<FlagOutcome> Wins => _wins.ToArray();

        public bool IsSolved(int challengeId) => _wins.Any(w => w.ChallengeId == challengeId);

        public Task<FlagOutcome?> SubmitCandidateAsync(FlagCandidate candidate, CancellationToken ct)
            => Task.FromResult<FlagOutcome?>(null);

        internal void Announce(FlagOutcome outcome)
        {
            _wins.Add(outcome);
            ChallengeSolved?.Invoke(outcome);
        }
    }
}
