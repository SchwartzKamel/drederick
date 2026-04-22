using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Cli;
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

namespace Drederick.Jeopardy.Cli;

/// <summary>
/// Test hook: lets a unit test substitute an <see cref="ICtfCoordinator"/>
/// (and optionally a swapped-in <see cref="CoordinatorConfig"/>) without
/// spinning up a real Copilot client, Docker sandbox, or CTFd HTTP stack.
/// </summary>
internal delegate (ICtfCoordinator Coordinator, CoordinatorConfig Config) CtfSolveCoordinatorFactory(
    CommandLineOptions opts,
    Scope.Scope scope,
    AuditLog audit);

/// <summary>
/// Entry point for the <c>drederick ctf-solve</c> subcommand. Wires the
/// Jeopardy building blocks (CTFd client, Copilot LLM, Docker sandboxes,
/// solver swarm, coordinator) and drives one full competition run.
/// </summary>
public static class CtfSolveRunner
{
    public static Task<int> RunAsync(CommandLineOptions opts, CancellationToken ct)
        => RunAsync(opts, factory: null, ct);

    internal static async Task<int> RunAsync(
        CommandLineOptions opts,
        CtfSolveCoordinatorFactory? factory,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(opts);

        if (opts.Help)
        {
            Console.WriteLine(HelpText);
            return 0;
        }

        // --- validate required flags ---
        if (string.IsNullOrEmpty(opts.ScopePath))
        {
            Console.Error.WriteLine("ctf-solve: --scope is required.");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(opts.CtfdUrl))
        {
            Console.Error.WriteLine("ctf-solve: --ctfd is required (or set CTFD_URL).");
            return 1;
        }
        if (!Uri.TryCreate(opts.CtfdUrl, UriKind.Absolute, out var ctfdUri)
            || (ctfdUri.Scheme != "http" && ctfdUri.Scheme != "https"))
        {
            Console.Error.WriteLine($"ctf-solve: --ctfd must be an http(s) URL, got '{opts.CtfdUrl}'.");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(opts.CtfdToken))
        {
            Console.Error.WriteLine("ctf-solve: --ctfd-token is required (or set CTFD_TOKEN).");
            return 1;
        }
        if (opts.CtfModels.Count == 0)
        {
            Console.Error.WriteLine("ctf-solve: at least one model is required via --models.");
            return 1;
        }

        // --- load scope ---
        Scope.Scope scope;
        try
        {
            scope = ScopeLoader.LoadFile(opts.ScopePath, allowBroad: opts.AllowBroad, labMode: opts.LabMode);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ctf-solve: scope load failed: {ex.Message}");
            return 1;
        }

        // CLI-level fast fail: the scope file must cover the CTFd host. The
        // coordinator re-checks this at boot (defense in depth) but a clean
        // CLI message is friendlier than a ScopeException stack trace. We
        // only surface-check when the host parses as an IP literal (scope
        // entries are CIDRs/IPs); hostname-based CTFd URLs defer the check
        // to the CtfdClient ctor / CtfCoordinator boot.
        if (System.Net.IPAddress.TryParse(ctfdUri.Host, out _) && !scope.Contains(ctfdUri.Host))
        {
            Console.Error.WriteLine(
                $"ctf-solve: CTFd host '{ctfdUri.Host}' is not in scope {scope.Source}. Add it to your scope file and retry.");
            return 1;
        }

        // --- audit ---
        var reportDir = string.IsNullOrEmpty(opts.CtfReportDir)
            ? Path.Combine("out", "ctf-report")
            : opts.CtfReportDir;
        Directory.CreateDirectory(reportDir);
        var auditPath = Path.Combine(reportDir, "audit.jsonl");
        using var audit = new AuditLog(auditPath);

        // --- banner (never logs the token) ---
        Console.WriteLine(BuildBanner(ctfdUri, opts.CtfModels, opts.CtfdToken));

        var startDigest = new Dictionary<string, object?>
        {
            ["ctfd_url"] = ctfdUri.ToString(),
            ["ctfd_token_sha256"] = Sha256Hex(opts.CtfdToken!),
            ["models"] = opts.CtfModels.ToArray(),
            ["wall_clock_min"] = opts.CtfWallClockMinutes,
            ["max_concurrent"] = opts.CtfMaxConcurrent,
            ["poll_interval_sec"] = opts.CtfPollIntervalSec,
            ["run_budget_usd"] = opts.CtfRunBudgetUsd?.ToString("F6", CultureInfo.InvariantCulture),
            ["challenge_budget_usd"] = opts.CtfChallengeBudgetUsd?.ToString("F6", CultureInfo.InvariantCulture),
            ["category_filter"] = opts.CtfCategoryFilter?.ToArray(),
            ["challenge_ids"] = opts.CtfChallengeIds?.ToArray(),
            ["inbox_path"] = opts.CtfInboxPath,
            ["report_dir"] = reportDir,
            ["scope_source"] = scope.Source,
        };
        audit.Record("cli.ctf_solve.start", startDigest);

        // --- build deps ---
        ICtfCoordinator coordinator;
        CoordinatorConfig cfg;
        HttpClient? ownedHttp = null;
        CtfdClient? ownedCtfd = null;
        CopilotLlmClient? ownedLlm = null;

        try
        {
            if (factory is not null)
            {
                (coordinator, cfg) = factory(opts, scope, audit);
            }
            else
            {
                ownedHttp = new HttpClient();
                ownedCtfd = new CtfdClient(ctfdUri, opts.CtfdToken!, scope, audit, ownedHttp);

                ownedLlm = CopilotLlmClient.TryCreateFromEnvironment(audit);
                if (ownedLlm is null)
                {
                    Console.Error.WriteLine(
                        "ctf-solve: no Copilot token found (set COPILOT_TOKEN, GH_TOKEN, or GITHUB_TOKEN).");
                    Console.Error.WriteLine(
                        "ctf-solve: run 'drederick doctor --category=jeopardy' to diagnose setup issues.");
                    audit.Record("cli.ctf_solve.finish", new Dictionary<string, object?>
                    {
                        ["exit"] = 1,
                        ["reason"] = "no_copilot_token",
                    });
                    return 1;
                }

                var sandboxes = new SandboxManager(scope, audit, new DefaultProcessRunner(), "docker");
                var bus = new SolverMessageBus(audit);
                var costs = new CostTracker(audit, runCapUsd: opts.CtfRunBudgetUsd, challengeCapUsd: opts.CtfChallengeBudgetUsd);
                var loopDetector = new LoopDetector(audit);
                var flagSubmit = new FlagSubmitCoordinator(ownedCtfd, audit, bus);
                var solver = new ChallengeSolver(ownedLlm, sandboxes, flagSubmit, bus, costs, loopDetector, audit);
                var swarm = new SolverSwarm(solver, flagSubmit, bus, costs, audit);
                var poller = new CtfdPoller(ownedCtfd, audit, TimeSpan.FromSeconds(opts.CtfPollIntervalSec));
                var inbox = string.IsNullOrEmpty(opts.CtfInboxPath) ? null : new OperatorInbox(bus, audit);

                coordinator = new CtfCoordinator(
                    ownedCtfd, poller, swarm, flagSubmit, bus, costs, loopDetector, inbox, scope, audit);

                cfg = BuildConfig(opts, ctfdUri, reportDir);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ctf-solve: setup failed: {ex.Message}");
            audit.Record("cli.ctf_solve.finish", new Dictionary<string, object?>
            {
                ["exit"] = 1,
                ["reason"] = "setup_error",
                ["error"] = ex.GetType().Name + ": " + ex.Message,
            });
            ownedHttp?.Dispose();
            ownedCtfd?.Dispose();
            return 1;
        }

        // --- run ---
        CompetitionReport? report = null;
        int exit;
        try
        {
            report = await coordinator.RunAsync(cfg, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("ctf-solve: cancelled.");
            exit = 2;
            audit.Record("cli.ctf_solve.finish", new Dictionary<string, object?>
            {
                ["exit"] = exit,
                ["reason"] = "cancelled",
            });
            ownedHttp?.Dispose();
            ownedCtfd?.Dispose();
            ownedLlm?.Dispose();
            return exit;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ctf-solve: run failed: {ex.Message}");
            exit = 1;
            audit.Record("cli.ctf_solve.finish", new Dictionary<string, object?>
            {
                ["exit"] = exit,
                ["reason"] = "error",
                ["error"] = ex.GetType().Name + ": " + ex.Message,
            });
            ownedHttp?.Dispose();
            ownedCtfd?.Dispose();
            ownedLlm?.Dispose();
            return exit;
        }

        // --- write report (defensive: coordinator also writes when ReportOutputDir is set) ---
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(reportDir, "report.json"),
                CompetitionReportRenderer.ToJson(report),
                CancellationToken.None).ConfigureAwait(false);
            await File.WriteAllTextAsync(
                Path.Combine(reportDir, "report.md"),
                CompetitionReportRenderer.ToMarkdown(report),
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ctf-solve: report write failed: {ex.Message}");
        }

        // --- console summary ---
        Console.WriteLine(
            string.Format(CultureInfo.InvariantCulture,
                "ctf-solve: discovered={0} attempted={1} solved={2} points={3} cost=${4}",
                report.ChallengesDiscovered,
                report.ChallengesAttempted,
                report.ChallengesSolved,
                report.PointsScored,
                report.TotalUsdCost.ToString("F4", CultureInfo.InvariantCulture)));
        Console.WriteLine($"ctf-solve: report written to {reportDir}");

        exit = report.ChallengesSolved >= 1 ? 0 : 2;
        audit.Record("cli.ctf_solve.finish", new Dictionary<string, object?>
        {
            ["exit"] = exit,
            ["discovered"] = report.ChallengesDiscovered,
            ["attempted"] = report.ChallengesAttempted,
            ["solved"] = report.ChallengesSolved,
            ["points"] = report.PointsScored,
            ["total_usd"] = report.TotalUsdCost.ToString("F6", CultureInfo.InvariantCulture),
        });

        ownedHttp?.Dispose();
        ownedCtfd?.Dispose();
        ownedLlm?.Dispose();

        return exit;
    }

    internal static CoordinatorConfig BuildConfig(
        CommandLineOptions opts, Uri ctfdUri, string reportDir)
    {
        var slots = opts.CtfModels
            .Select(m => new SwarmModelSlot(m, PerChallengeBudgetUsd: opts.CtfChallengeBudgetUsd))
            .ToArray();
        return new CoordinatorConfig(
            CtfdUrl: ctfdUri,
            CtfdToken: opts.CtfdToken ?? string.Empty,
            Models: slots,
            WallClockPerChallenge: TimeSpan.FromMinutes(opts.CtfWallClockMinutes),
            TotalRunBudgetUsd: opts.CtfRunBudgetUsd,
            PerChallengeBudgetUsd: opts.CtfChallengeBudgetUsd,
            MaxConcurrentChallenges: opts.CtfMaxConcurrent,
            OperatorInboxPath: opts.CtfInboxPath,
            ReportOutputDir: reportDir,
            PollInterval: TimeSpan.FromSeconds(opts.CtfPollIntervalSec),
            CategoryFilter: opts.CtfCategoryFilter,
            ChallengeIdFilter: opts.CtfChallengeIds);
    }

    /// <summary>
    /// Tatum-voiced startup banner. NEVER includes the CTFd or Copilot token:
    /// the token is replaced by a redacted marker even if accidentally passed
    /// in. Rendered as a single multi-line string for easy test assertions.
    /// </summary>
    public static string BuildBanner(Uri ctfdUrl, IReadOnlyList<string> models, string? ctfdToken)
    {
        ArgumentNullException.ThrowIfNull(ctfdUrl);
        ArgumentNullException.ThrowIfNull(models);
        var sb = new StringBuilder();
        sb.AppendLine("In this corner, weighing 260 pounds of pure compute — drederick.");
        sb.Append("  Fighters tonight: ");
        sb.AppendLine(models.Count == 0 ? "(none)" : string.Join(", ", models));
        sb.Append("  Target: ");
        sb.Append(ctfdUrl).Append(", CtfdToken=<redacted:");
        sb.Append(ctfdToken is { Length: >= 6 } ? ctfdToken.Substring(0, 6) : "******");
        sb.AppendLine(">");
        sb.AppendLine("  \"A fair fight is one you didn't prepare well enough for.\"");
        return sb.ToString();
    }

    internal static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public const string HelpText =
        """
        drederick ctf-solve — race a Copilot LLM swarm against a CTFd Jeopardy CTF

        USAGE:
          drederick ctf-solve --scope <file> --ctfd <url> [--ctfd-token <tok>]
                              [--models <csv>] [--wall-clock-min 20]
                              [--run-budget-usd 100] [--challenge-budget-usd 5]
                              [--max-concurrent 4] [--poll-interval-sec 5]
                              [--category-filter pwn,crypto]
                              [--challenge-ids 1,5,42]
                              [--inbox <path>] [--report-dir <dir>]

        ENV FALLBACKS:
          CTFD_URL, CTFD_TOKEN — read when --ctfd / --ctfd-token omitted.
          COPILOT_TOKEN > GH_TOKEN > GITHUB_TOKEN — Copilot LLM auth.

        DEFAULTS:
          --models claude-opus-4.7,gpt-5.4,gemini-3.1-pro
          --wall-clock-min 20    --max-concurrent 4    --poll-interval-sec 5
          --inbox ~/.drederick/jeopardy-inbox.jsonl
          --report-dir ./out/ctf-report/

        EXIT CODES:
          0  at least one challenge solved
          1  hard error (missing scope/token, unreachable CTFd, exception)
          2  completed without solves (timeout, all incorrect, budget exhausted)

        Run 'drederick doctor --category=jeopardy' to diagnose setup issues.
        """;
}
