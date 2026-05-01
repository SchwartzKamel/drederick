using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Doctor;
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

namespace Drederick.Web.Jeopardy;

/// <summary>
/// Wraps <see cref="CtfCoordinator"/> lifecycle for the web API. Each session
/// owns its own audit log, scope, coordinator, message bus, and operator
/// inbox file. The manager is a process-wide singleton holding the currently-
/// running and recently-completed sessions.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description>Session output lives under
///     <c>&lt;web-output-dir&gt;/jeopardy/&lt;session_id&gt;/</c>; never
///     outside the configured web output root.</description></item>
///   <item><description>No session write path ever emits plaintext CTFd
///     token or plaintext flag; only SHA-256 digests.</description></item>
///   <item><description>Hints are delivered by appending to the session's
///     operator-inbox JSONL file via <see cref="OperatorSender"/>, which is
///     the same path the <c>drederick ctf-msg</c> CLI uses. That preserves
///     the existing audit chain inside the coordinator's
///     <see cref="IOperatorInbox"/>.</description></item>
/// </list>
/// </para>
/// </summary>
internal sealed class JeopardySessionManager : IAsyncDisposable
{
    private readonly AuditLog _webAudit;
    private readonly string _webOutputDir;
    private readonly IJeopardyCoordinatorFactory _factory;
    private readonly ConcurrentDictionary<Guid, JeopardySession> _sessions = new();
    private readonly int _retainCount = 64;

    public JeopardySessionManager(
        AuditLog webAudit,
        WebAppSettings settings,
        IJeopardyCoordinatorFactory factory)
    {
        _webAudit = webAudit ?? throw new ArgumentNullException(nameof(webAudit));
        ArgumentNullException.ThrowIfNull(settings);
        _webOutputDir = settings.OutputDir;
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    public IReadOnlyCollection<JeopardySession> List() => _sessions.Values.ToArray();

    public JeopardySession? Get(Guid id) =>
        _sessions.TryGetValue(id, out var s) ? s : null;

    public async Task<(JeopardySession? Session, string? Error, string? Message)> StartAsync(
        JeopardyStartRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.CtfdUrl))
            return (null, "invalid_request", "ctfd_url is required.");
        if (string.IsNullOrWhiteSpace(request.CtfdToken))
            return (null, "invalid_request", "ctfd_token is required.");
        if (string.IsNullOrWhiteSpace(request.ScopePath))
            return (null, "invalid_request", "scope_path is required.");
        if (request.Models is null || request.Models.Count == 0)
            return (null, "invalid_request", "models must be a non-empty array.");

        if (!Uri.TryCreate(request.CtfdUrl, UriKind.Absolute, out var ctfdUri)
            || (ctfdUri.Scheme != "http" && ctfdUri.Scheme != "https"))
        {
            return (null, "invalid_request", "ctfd_url must be an http(s) URL.");
        }

        var resolvedScopePath = ResolveScopePath(request.ScopePath);
        if (resolvedScopePath is null)
        {
            _webAudit.Record("web.jeopardy.session_start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_scope_path",
                ["scope_path_sha256"] = Sha256Hex(request.ScopePath),
            });
            return (null, "scope_path_rejected",
                "scope_path must resolve to an existing file under the server working directory.");
        }

        Scope.Scope scope;
        try
        {
            scope = ScopeLoader.LoadFile(resolvedScopePath);
        }
        catch (Exception ex)
        {
            return (null, "scope_load_failed", ex.Message);
        }

        // Fast-fail: if the CTFd URL is an IP literal, verify it's in scope
        // right here so we give a clean 400 instead of failing deep inside
        // CtfdClient. Hostname-based URLs are deferred (same behavior as the
        // CLI ctf-solve runner).
        if (System.Net.IPAddress.TryParse(ctfdUri.Host, out _) && !scope.Contains(ctfdUri.Host))
        {
            _webAudit.Record("web.jeopardy.session_start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_out_of_scope",
                ["ctfd_url_sha256"] = Sha256Hex(request.CtfdUrl),
                ["scope_path_sha256"] = Sha256Hex(resolvedScopePath),
            });
            return (null, "out_of_scope",
                $"CTFd host '{ctfdUri.Host}' is not in scope {scope.Source}.");
        }

        var sessionId = Guid.NewGuid();
        var sessionDir = Path.Combine(_webOutputDir, "jeopardy", sessionId.ToString("N"));
        Directory.CreateDirectory(sessionDir);

        var startedAt = DateTimeOffset.UtcNow;
        var session = new JeopardySession(
            sessionId,
            startedAt,
            request.Models.ToArray(),
            sessionDir,
            Sha256Hex(request.CtfdUrl));

        _webAudit.Record("web.jeopardy.session_start", new Dictionary<string, object?>
        {
            ["outcome"] = "accepted",
            ["session_id"] = sessionId.ToString(),
            ["ctfd_url_sha256"] = Sha256Hex(request.CtfdUrl),
            ["ctfd_token_sha256"] = Sha256Hex(request.CtfdToken),
            ["scope_path_sha256"] = Sha256Hex(resolvedScopePath),
            ["models_requested"] = request.Models.ToArray(),
            ["llm_provider"] = request.LlmProvider ?? "copilot",
        });

        JeopardyCoordinatorBundle bundle;
        try
        {
            bundle = await _factory.CreateAsync(
                new JeopardyFactoryContext(
                    Request: request,
                    CtfdUri: ctfdUri,
                    Scope: scope,
                    ResolvedScopePath: resolvedScopePath,
                    SessionDir: sessionDir,
                    SessionId: sessionId),
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            session.MarkFailed("factory_error: " + ex.Message);
            TrimRetained();
            _sessions[sessionId] = session;
            return (session, "setup_failed", ex.Message);
        }

        session.Attach(bundle);
        _sessions[sessionId] = session;
        TrimRetained();

        // Wire event taps BEFORE starting so we don't miss an early solve.
        session.SubscribeFlagWins();

        // Kick off the run. The task is owned by the session; the manager's
        // Dispose cancels + awaits all sessions.
        session.RunTask = Task.Run(async () =>
        {
            try
            {
                var report = await bundle.Coordinator.RunAsync(bundle.Config, session.Cts.Token)
                    .ConfigureAwait(false);
                session.MarkCompleted(report);
            }
            catch (OperationCanceledException)
            {
                session.MarkCancelled();
            }
            catch (Exception ex)
            {
                session.MarkFailed(ex.GetType().Name + ": " + ex.Message);
            }
            finally
            {
                await session.DisposeBundleAsync().ConfigureAwait(false);
            }
        }, CancellationToken.None);

        return (session, null, null);
    }

    public async Task<bool> CancelAsync(Guid id)
    {
        if (!_sessions.TryGetValue(id, out var session)) return false;
        _webAudit.Record("web.jeopardy.session_cancel", new Dictionary<string, object?>
        {
            ["session_id"] = id.ToString(),
        });
        session.RequestCancel();
        // Let cancellation propagate; don't block the HTTP handler on full run.
        await Task.Yield();
        return true;
    }

    /// <summary>
    /// Appends the hint to the session's operator-inbox JSONL. That file is
    /// already tailed by the live coordinator, so delivery goes via the same
    /// path as <c>drederick ctf-msg</c>.
    /// </summary>
    public async Task<(JeopardyHintResponse? Resp, string? Error, string? Message)> SendHintAsync(
        Guid id, JeopardyHintRequest req, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(id, out var session))
            return (null, "not_found", "session not found");
        if (req is null || string.IsNullOrWhiteSpace(req.Body))
            return (null, "invalid_request", "body is required");
        if (string.IsNullOrWhiteSpace(req.Kind))
            return (null, "invalid_request", "kind is required");

        var chalId = req.ChallengeId switch
        {
            null => (string?)null,
            string s => string.IsNullOrWhiteSpace(s) ? null : s.Trim(),
            System.Text.Json.JsonElement je => je.ValueKind switch
            {
                System.Text.Json.JsonValueKind.Number => je.GetInt64().ToString(CultureInfo.InvariantCulture),
                System.Text.Json.JsonValueKind.String => je.GetString(),
                _ => null,
            },
            _ => req.ChallengeId.ToString(),
        };

        var msg = new OperatorMessage(
            At: DateTimeOffset.UtcNow,
            ChallengeId: chalId,
            SolverId: req.SolverId,
            Kind: req.Kind.Trim().ToLowerInvariant(),
            Body: req.Body);

        _webAudit.Record("web.jeopardy.hint_send", new Dictionary<string, object?>
        {
            ["session_id"] = id.ToString(),
            ["kind"] = msg.Kind,
            ["challenge_id"] = chalId,
            ["body_sha256"] = Sha256Hex(req.Body),
        });

        try
        {
            await OperatorSender.SendAsync(session.InboxPath, msg, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return (null, "inbox_write_failed", ex.Message);
        }

        var resp = new JeopardyHintResponse(
            DeliveredAt: msg.At,
            BodySha256: Sha256Hex(req.Body),
            Kind: msg.Kind,
            ChallengeId: chalId);
        session.RecordHint(new JeopardyHintHistoryDto(
            At: msg.At,
            Kind: msg.Kind,
            ChallengeId: chalId,
            SolverId: req.SolverId,
            BodySha256: resp.BodySha256));
        return (resp, null, null);
    }

    public static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input ?? string.Empty));
        return Convert.ToHexStringLower(bytes);
    }

    private string? ResolveScopePath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (raw.Contains('\0', StringComparison.Ordinal)) return null;
        string resolved;
        try
        {
            resolved = Path.GetFullPath(raw);
        }
        catch
        {
            return null;
        }
        var cwd = Path.GetFullPath(Directory.GetCurrentDirectory());
        // Require resolved path to sit inside the server's working directory.
        // This is the same path-traversal guard the runs-agent endpoints use.
        var cwdWithSep = cwd.EndsWith(Path.DirectorySeparatorChar) ? cwd : cwd + Path.DirectorySeparatorChar;
        if (!resolved.Equals(cwd, StringComparison.Ordinal)
            && !resolved.StartsWith(cwdWithSep, StringComparison.Ordinal))
        {
            return null;
        }
        if (!File.Exists(resolved)) return null;
        return resolved;
    }

    private void TrimRetained()
    {
        if (_sessions.Count <= _retainCount) return;
        var toRemove = _sessions.Values
            .Where(s => s.Status is "completed" or "failed" or "cancelled")
            .OrderBy(s => s.FinishedAt ?? s.StartedAt)
            .Take(_sessions.Count - _retainCount)
            .Select(s => s.SessionId)
            .ToArray();
        foreach (var id in toRemove) _sessions.TryRemove(id, out _);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var s in _sessions.Values)
        {
            try { s.RequestCancel(); } catch { }
        }
        foreach (var s in _sessions.Values)
        {
            if (s.RunTask is { } t)
            {
                try { await t.ConfigureAwait(false); } catch { }
            }
        }
    }
}

// ------------------------------------------------------------------------

internal sealed record JeopardyFactoryContext(
    JeopardyStartRequest Request,
    Uri CtfdUri,
    Scope.Scope Scope,
    string ResolvedScopePath,
    string SessionDir,
    Guid SessionId);

/// <summary>
/// Everything a running session needs. <see cref="Disposables"/> are disposed
/// in reverse order when the session's coordinator task finishes.
/// </summary>
internal sealed record JeopardyCoordinatorBundle(
    ICtfCoordinator Coordinator,
    CoordinatorConfig Config,
    ISolverMessageBus Bus,
    IFlagSubmitCoordinator FlagSubmit,
    string InboxPath,
    IReadOnlyList<CtfdChallenge> InitialChallenges,
    IReadOnlyList<IAsyncDisposable> AsyncDisposables,
    IReadOnlyList<IDisposable> Disposables);

internal interface IJeopardyCoordinatorFactory
{
    Task<JeopardyCoordinatorBundle> CreateAsync(JeopardyFactoryContext ctx, CancellationToken ct);
}

/// <summary>
/// Default factory: mirrors <c>CtfSolveRunner</c>'s DI wiring. Provider
/// selection defaults to Copilot; Azure / llama.cpp branches are
/// experimental until the <c>llm-factory-cli</c> todo lands.
/// </summary>
internal sealed class DefaultJeopardyCoordinatorFactory : IJeopardyCoordinatorFactory
{
    public async Task<JeopardyCoordinatorBundle> CreateAsync(JeopardyFactoryContext ctx, CancellationToken ct)
    {
        var sessionAudit = new AuditLog(Path.Combine(ctx.SessionDir, "audit.jsonl"));
        var http = new HttpClient();
        var ctfd = new CtfdClient(ctx.CtfdUri, ctx.Request.CtfdToken, ctx.Scope, sessionAudit, http);

        ICopilotLlmClient? llm = (ctx.Request.LlmProvider ?? "copilot").Trim().ToLowerInvariant() switch
        {
            "azure" => AzureOpenAiLlmClient.TryCreateFromEnvironment(sessionAudit),
            "llamacpp" or "llama-cpp" or "llama.cpp" => LlamaCppLlmClient.TryCreateFromEnvironment(sessionAudit),
            _ => CopilotLlmClient.TryCreateFromEnvironment(sessionAudit),
        };
        if (llm is null)
        {
            http.Dispose();
            ctfd.Dispose();
            sessionAudit.Dispose();
            throw new InvalidOperationException(
                "no LLM client could be created from environment (run `gh auth login --web` or set COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN "
                + "for copilot, or the provider-specific env vars for azure / llamacpp).");
        }

        var sandboxes = new SandboxManager(ctx.Scope, sessionAudit, new DefaultProcessRunner(), "docker");
        var bus = new SolverMessageBus(sessionAudit);
        var costs = new CostTracker(sessionAudit,
            runCapUsd: ctx.Request.RunBudgetUsd,
            challengeCapUsd: ctx.Request.ChallengeBudgetUsd);
        var loops = new LoopDetector(sessionAudit);
        var flagSubmit = new FlagSubmitCoordinator(ctfd, sessionAudit, bus);
        var solver = new ChallengeSolver(llm, sandboxes, flagSubmit, bus, costs, loops, sessionAudit);
        var swarm = new SolverSwarm(solver, flagSubmit, bus, costs, sessionAudit);
        var poller = new CtfdPoller(ctfd, sessionAudit, TimeSpan.FromSeconds(5));

        var inboxPath = Path.Combine(ctx.SessionDir, "inbox.jsonl");
        var inbox = new OperatorInbox(bus, sessionAudit);

        var coordinator = new CtfCoordinator(
            ctfd, poller, swarm, flagSubmit, bus, costs, loops, inbox, ctx.Scope, sessionAudit);

        IReadOnlyList<CtfdChallenge> initial = Array.Empty<CtfdChallenge>();
        try
        {
            initial = await ctfd.ListChallengesAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            // Non-fatal: the poller will retry once the run starts. The
            // challenge roster will simply populate lazily.
        }

        var models = ctx.Request.Models.Select(m => new SwarmModelSlot(m, ctx.Request.ChallengeBudgetUsd)).ToArray();
        var config = new CoordinatorConfig(
            CtfdUrl: ctx.CtfdUri,
            CtfdToken: ctx.Request.CtfdToken,
            Models: models,
            WallClockPerChallenge: TimeSpan.FromMinutes(ctx.Request.WallClockMinutes ?? 20),
            TotalRunBudgetUsd: ctx.Request.RunBudgetUsd,
            PerChallengeBudgetUsd: ctx.Request.ChallengeBudgetUsd,
            MaxConcurrentChallenges: ctx.Request.MaxConcurrent ?? 4,
            OperatorInboxPath: inboxPath,
            ReportOutputDir: ctx.SessionDir,
            PollInterval: TimeSpan.FromSeconds(5),
            CategoryFilter: ctx.Request.Categories,
            ChallengeIdFilter: ctx.Request.ChallengeIds);

        return new JeopardyCoordinatorBundle(
            Coordinator: coordinator,
            Config: config,
            Bus: bus,
            FlagSubmit: flagSubmit,
            InboxPath: inboxPath,
            InitialChallenges: initial,
            AsyncDisposables: new IAsyncDisposable[] { inbox, poller, bus },
            Disposables: new IDisposable[] { ctfd, http, (IDisposable)llm, sessionAudit });
    }
}

// ------------------------------------------------------------------------

/// <summary>
/// Per-session state. Lives in the manager's dictionary until the retention
/// cap evicts it. Thread-safe for the read paths exercised by HTTP handlers.
/// </summary>
internal sealed class JeopardySession
{
    private readonly object _gate = new();
    private readonly List<JeopardyHintHistoryDto> _hints = new();
    private readonly ConcurrentDictionary<int, CtfdChallenge> _discovered = new();
    private readonly ConcurrentDictionary<int, JeopardyFlagRecordDto> _flags = new();

    public Guid SessionId { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? FinishedAt { get; private set; }
    public IReadOnlyList<string> Models { get; }
    public string OutDir { get; }
    public string CtfdUrlSha256 { get; }
    public string Status { get; private set; } = "running";
    public string? Error { get; private set; }
    public string InboxPath { get; private set; } = string.Empty;
    public CancellationTokenSource Cts { get; } = new();
    public Task? RunTask { get; set; }
    public CompetitionReport? Report { get; private set; }
    private JeopardyCoordinatorBundle? _bundle;

    public JeopardySession(
        Guid id,
        DateTimeOffset startedAt,
        IReadOnlyList<string> models,
        string outDir,
        string ctfdUrlSha256)
    {
        SessionId = id;
        StartedAt = startedAt;
        Models = models;
        OutDir = outDir;
        CtfdUrlSha256 = ctfdUrlSha256;
    }

    public void Attach(JeopardyCoordinatorBundle bundle)
    {
        _bundle = bundle;
        InboxPath = bundle.InboxPath;
        foreach (var c in bundle.InitialChallenges) _discovered[c.Id] = c;
    }

    public void SubscribeFlagWins()
    {
        if (_bundle is null) return;
        _bundle.FlagSubmit.ChallengeSolved += OnChallengeSolved;
    }

    private void OnChallengeSolved(FlagOutcome outcome)
    {
        var sha = Sha256Hex(outcome.Flag ?? string.Empty);
        _flags[outcome.ChallengeId] = new JeopardyFlagRecordDto(
            ChallengeId: outcome.ChallengeId,
            FlagSha256: sha,
            Correct: outcome.Correct,
            SolvedByModel: outcome.WinnerModelId,
            SolvedAt: outcome.SubmittedAt);
    }

    public void RequestCancel()
    {
        try { Cts.Cancel(); } catch (ObjectDisposedException) { }
    }

    public void MarkCompleted(CompetitionReport report)
    {
        lock (_gate)
        {
            Report = report;
            Status = "completed";
            FinishedAt = DateTimeOffset.UtcNow;
        }
    }

    public void MarkCancelled()
    {
        lock (_gate)
        {
            Status = "cancelled";
            FinishedAt = DateTimeOffset.UtcNow;
        }
    }

    public void MarkFailed(string error)
    {
        lock (_gate)
        {
            Status = "failed";
            Error = error;
            FinishedAt = DateTimeOffset.UtcNow;
        }
    }

    public async Task DisposeBundleAsync()
    {
        var b = _bundle;
        if (b is null) return;
        try { b.FlagSubmit.ChallengeSolved -= OnChallengeSolved; } catch { }
        foreach (var d in b.AsyncDisposables)
        {
            try { await d.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        foreach (var d in b.Disposables)
        {
            try { d.Dispose(); } catch { }
        }
        _bundle = null;
    }

    public void RecordHint(JeopardyHintHistoryDto hint)
    {
        lock (_gate) _hints.Add(hint);
    }

    public IReadOnlyList<JeopardyHintHistoryDto> Hints()
    {
        lock (_gate) return _hints.ToArray();
    }

    public int ChallengesDiscovered => _discovered.Count;
    public int ChallengesSolved => _flags.Values.Count(f => f.Correct);

    public decimal TotalUsdCost
    {
        get
        {
            lock (_gate) return Report?.TotalUsdCost ?? 0m;
        }
    }

    public IReadOnlyList<JeopardyFlagRecordDto> Flags() => _flags.Values.ToArray();

    public IReadOnlyList<JeopardyChallengeStateDto> BuildSwarm()
    {
        var list = new List<JeopardyChallengeStateDto>(_discovered.Count);
        foreach (var c in _discovered.Values.OrderBy(c => c.Id))
        {
            _flags.TryGetValue(c.Id, out var flag);
            string state;
            if (flag is { Correct: true }) state = "solved";
            else if (flag is not null) state = "failed";
            else if (c.Solved) state = "solved";
            else if (Status is "completed" or "cancelled" or "failed") state = "skipped";
            else state = "racing";

            var active = state == "racing"
                ? Models.Select(m => new JeopardyActiveSolverDto(m, StartedAt, TurnsTaken: 0)).ToArray()
                : Array.Empty<JeopardyActiveSolverDto>();

            list.Add(new JeopardyChallengeStateDto(
                Id: c.Id,
                Name: c.Name,
                Category: c.Category,
                Value: c.Value,
                State: state,
                ActiveSolvers: active,
                FlagSha256: flag?.FlagSha256,
                SolvedByModel: flag?.SolvedByModel,
                SolvedAt: flag?.SolvedAt));
        }
        return list;
    }

    public JeopardyChallengeStateDto? BuildChallenge(int id)
    {
        if (!_discovered.TryGetValue(id, out var c)) return null;
        return BuildSwarm().FirstOrDefault(s => s.Id == id);
    }

    internal void RegisterDiscovered(CtfdChallenge chal) => _discovered[chal.Id] = chal;

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexStringLower(bytes);
    }
}
