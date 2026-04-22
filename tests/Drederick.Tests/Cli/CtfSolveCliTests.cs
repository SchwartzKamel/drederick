using System.Globalization;
using Drederick.Cli;
using Xunit;

namespace Drederick.Tests.Cli;

public class CtfSolveCliTests
{
    [Fact]
    public void Parses_Core_Flags()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve",
            "--ctfd", "http://foo.example/",
            "--ctfd-token", "T",
            "--models", "a,b,c",
        });
        Assert.True(o.CtfSolveSubcommand);
        Assert.Equal("http://foo.example/", o.CtfdUrl);
        Assert.Equal("T", o.CtfdToken);
        Assert.Equal(3, o.CtfModels.Count);
        Assert.Equal(new[] { "a", "b", "c" }, o.CtfModels);
    }

    [Fact]
    public void Env_Fallback_Populates_Ctfd_And_Token()
    {
        var origUrl = Environment.GetEnvironmentVariable("CTFD_URL");
        var origTok = Environment.GetEnvironmentVariable("CTFD_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("CTFD_URL", "http://env.example/");
            Environment.SetEnvironmentVariable("CTFD_TOKEN", "ENVTOK");
            var o = CommandLineOptions.Parse(new[] { "ctf-solve" });
            Assert.Equal("http://env.example/", o.CtfdUrl);
            Assert.Equal("ENVTOK", o.CtfdToken);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CTFD_URL", origUrl);
            Environment.SetEnvironmentVariable("CTFD_TOKEN", origTok);
        }
    }

    [Fact]
    public void Default_Models_Are_Populated()
    {
        var o = CommandLineOptions.Parse(new[] { "ctf-solve" });
        Assert.Equal(
            new[] { "claude-opus-4.7", "gpt-5.4", "gemini-3.1-pro" },
            o.CtfModels);
    }

    [Fact]
    public void Parses_Category_Filter_Csv()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve", "--category-filter", "pwn,crypto",
        });
        Assert.NotNull(o.CtfCategoryFilter);
        Assert.Equal(new[] { "pwn", "crypto" }, o.CtfCategoryFilter!);
    }

    [Fact]
    public void Parses_Challenge_Ids_Csv()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve", "--challenge-ids", "1,5,42",
        });
        Assert.NotNull(o.CtfChallengeIds);
        Assert.Equal(new[] { 1, 5, 42 }, o.CtfChallengeIds!);
    }

    [Fact]
    public void Parses_Numeric_Flags()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve",
            "--wall-clock-min", "30",
            "--run-budget-usd", "12.5",
            "--challenge-budget-usd", "0.75",
            "--max-concurrent", "8",
            "--poll-interval-sec", "7",
        });
        Assert.Equal(30, o.CtfWallClockMinutes);
        Assert.Equal(12.5m, o.CtfRunBudgetUsd);
        Assert.Equal(0.75m, o.CtfChallengeBudgetUsd);
        Assert.Equal(8, o.CtfMaxConcurrent);
        Assert.Equal(7, o.CtfPollIntervalSec);
    }

    [Fact]
    public void Default_Inbox_Path_Is_Under_Dotdrederick()
    {
        var o = CommandLineOptions.Parse(new[] { "ctf-solve" });
        Assert.NotNull(o.CtfInboxPath);
        Assert.Contains(".drederick", o.CtfInboxPath!);
        Assert.EndsWith("jeopardy-inbox.jsonl", o.CtfInboxPath);
    }

    [Fact]
    public void Rejects_Unknown_Subcommand_Flag()
    {
        // --ctfd is only valid under ctf-solve.
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--ctfd", "http://x/" }));
    }

    [Fact]
    public void Rejects_Bad_Wall_Clock()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "ctf-solve", "--wall-clock-min", "0" }));
    }

    [Fact]
    public void Banner_Redacts_Token_And_Lists_Models()
    {
        var models = new[] { "claude-opus-4.7", "gpt-5.4", "gemini-3.1-pro" };
        var banner = Drederick.Jeopardy.Cli.CtfSolveRunner.BuildBanner(
            new Uri("http://ctfd.example/"),
            models,
            "super-secret-token-do-not-leak");
        Assert.DoesNotContain("super-secret-token-do-not-leak", banner);
        Assert.Contains("redacted:", banner, StringComparison.Ordinal);
        Assert.Contains("drederick", banner);
        Assert.Contains("claude-opus-4.7", banner);
        Assert.Contains("gpt-5.4", banner);
        Assert.Contains("gemini-3.1-pro", banner);
        Assert.Contains("A fair fight", banner);
    }

    [Fact]
    public void Help_Prints_Jeopardy_Section()
    {
        var help = CommandLineOptions.HelpText;
        Assert.Contains("Jeopardy CTF mode:", help);
        Assert.Contains("ctf-solve", help);
        Assert.Contains("ctf-msg", help);
        Assert.Contains("doctor --category=jeopardy", help);
    }

    // --- jeopardy-llm-provider-cli-tests ---

    [Fact]
    public void Default_LlmProvider_Is_Copilot()
    {
        var o = CommandLineOptions.Parse(new[] { "ctf-solve" });
        Assert.Equal(Drederick.Jeopardy.Llm.LlmProvider.Copilot, o.LlmProvider);
    }

    [Theory]
    [InlineData("copilot", Drederick.Jeopardy.Llm.LlmProvider.Copilot)]
    [InlineData("azure", Drederick.Jeopardy.Llm.LlmProvider.Azure)]
    [InlineData("llamacpp", Drederick.Jeopardy.Llm.LlmProvider.LlamaCpp)]
    [InlineData("llama-cpp", Drederick.Jeopardy.Llm.LlmProvider.LlamaCpp)]
    public void Parses_LlmProvider_TwoToken(string raw, Drederick.Jeopardy.Llm.LlmProvider expected)
    {
        var o = CommandLineOptions.Parse(new[] { "ctf-solve", "--llm-provider", raw });
        Assert.Equal(expected, o.LlmProvider);
    }

    [Fact]
    public void Parses_LlmProvider_Equals_Form()
    {
        var o = CommandLineOptions.Parse(new[] { "ctf-solve", "--llm-provider=azure" });
        Assert.Equal(Drederick.Jeopardy.Llm.LlmProvider.Azure, o.LlmProvider);
    }

    [Fact]
    public void Parses_Azure_Flags_Both_Forms()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve",
            "--llm-provider=azure",
            "--azure-endpoint", "https://foo.openai.azure.test",
            "--azure-api-version=2024-10-21",
            "--azure-deployment", "gpt-5.4=gpt5-prod",
            "--azure-deployment=haiku=haiku-prod",
        });
        Assert.Equal("https://foo.openai.azure.test", o.AzureEndpoint);
        Assert.Equal("2024-10-21", o.AzureApiVersion);
        Assert.Equal("gpt5-prod", o.AzureDeploymentMap["gpt-5.4"]);
        Assert.Equal("haiku-prod", o.AzureDeploymentMap["haiku"]);
    }

    [Fact]
    public void Rejects_Malformed_Azure_Deployment()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "ctf-solve", "--azure-deployment", "no-equals-here" }));
    }

    [Fact]
    public void Parses_LlamaCpp_Flags_Both_Forms()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-solve",
            "--llm-provider=llamacpp",
            "--llamacpp-url", "http://127.0.0.1:8080",
            "--llamacpp-model=qwen=qwen2.5-coder",
            "--llamacpp-model", "llama",
        });
        Assert.Equal("http://127.0.0.1:8080", o.LlamaCppUrl);
        Assert.Equal("qwen2.5-coder", o.LlamaCppModels["qwen"]);
        Assert.Equal("llama", o.LlamaCppModels["llama"]);
    }

    [Fact]
    public void Doctor_Subcommand_Accepts_Provider_Flags()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "doctor",
            "--category=jeopardy",
            "--llm-provider=azure",
            "--azure-endpoint=https://foo.openai.azure.test",
        });
        Assert.True(o.DoctorSubcommand);
        Assert.Equal(Drederick.Jeopardy.Llm.LlmProvider.Azure, o.LlmProvider);
        Assert.Equal("https://foo.openai.azure.test", o.AzureEndpoint);
    }

    [Fact]
    public void Rejects_Provider_Flags_Without_CtfSolve_Or_Doctor()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--llm-provider=azure" }));
    }

    // --- end jeopardy-llm-provider-cli-tests ---

    [Fact]
    public async Task RunAsync_Errors_Out_Without_Scope()
    {
        var opts = CommandLineOptions.Parse(new[]
        {
            "ctf-solve", "--ctfd", "http://foo.example/", "--ctfd-token", "T",
        });
        var exit = await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, CancellationToken.None);
        Assert.Equal(1, exit);
    }

    [Fact]
    public async Task RunAsync_With_Fake_Coordinator_Returns_2_On_No_Solves()
    {
        // Make a scope file that allows the ctfd host.
        var tmpRoot = Path.Combine(Path.GetTempPath(), "drederick-ctfsolve-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpRoot);
        try
        {
            var scopePath = Path.Combine(tmpRoot, "scope.txt");
            File.WriteAllText(scopePath, "127.0.0.1\n");
            var reportDir = Path.Combine(tmpRoot, "report");

            var opts = CommandLineOptions.Parse(new[]
            {
                "ctf-solve",
                "--scope", scopePath,
                "--ctfd", "http://127.0.0.1/",
                "--ctfd-token", "tok-abcdef123",
                "--models", "m1,m2",
                "--report-dir", reportDir,
            });

            var fake = new FakeCoordinator(
                new Drederick.Jeopardy.Coordinator.CompetitionReport(
                    StartedAt: DateTimeOffset.UtcNow,
                    FinishedAt: DateTimeOffset.UtcNow,
                    ChallengesDiscovered: 2,
                    ChallengesSolved: 0,
                    ChallengesAttempted: 2,
                    PointsScored: 0,
                    TotalUsdCost: 0m,
                    PerChallenge: Array.Empty<Drederick.Jeopardy.Swarm.SwarmResult>(),
                    SolvesByModel: new Dictionary<string, int>(),
                    AttemptsByCategory: new Dictionary<string, int>()));

            Drederick.Jeopardy.Cli.CtfSolveCoordinatorFactory factory = (o2, scope, audit) =>
            {
                var cfg = Drederick.Jeopardy.Cli.CtfSolveRunner.BuildConfig(
                    o2, new Uri(o2.CtfdUrl!), reportDir);
                return (fake, cfg);
            };

            var exit = await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, factory, CancellationToken.None);
            Assert.Equal(2, exit);
            Assert.True(fake.Called);
            Assert.True(File.Exists(Path.Combine(reportDir, "report.json")));
            Assert.True(File.Exists(Path.Combine(reportDir, "report.md")));
        }
        finally
        {
            try { Directory.Delete(tmpRoot, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task RunAsync_With_Solve_Returns_0()
    {
        var tmpRoot = Path.Combine(Path.GetTempPath(), "drederick-ctfsolve-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpRoot);
        try
        {
            var scopePath = Path.Combine(tmpRoot, "scope.txt");
            File.WriteAllText(scopePath, "127.0.0.1\n");
            var reportDir = Path.Combine(tmpRoot, "report");

            var opts = CommandLineOptions.Parse(new[]
            {
                "ctf-solve",
                "--scope", scopePath,
                "--ctfd", "http://127.0.0.1/",
                "--ctfd-token", "tok-abcdef123",
                "--models", "m1",
                "--report-dir", reportDir,
            });

            var fake = new FakeCoordinator(
                new Drederick.Jeopardy.Coordinator.CompetitionReport(
                    StartedAt: DateTimeOffset.UtcNow,
                    FinishedAt: DateTimeOffset.UtcNow,
                    ChallengesDiscovered: 1,
                    ChallengesSolved: 1,
                    ChallengesAttempted: 1,
                    PointsScored: 500,
                    TotalUsdCost: 0.05m,
                    PerChallenge: Array.Empty<Drederick.Jeopardy.Swarm.SwarmResult>(),
                    SolvesByModel: new Dictionary<string, int> { ["m1"] = 1 },
                    AttemptsByCategory: new Dictionary<string, int> { ["pwn"] = 1 }));

            Drederick.Jeopardy.Cli.CtfSolveCoordinatorFactory factory = (o2, scope, audit) =>
            {
                var cfg = Drederick.Jeopardy.Cli.CtfSolveRunner.BuildConfig(
                    o2, new Uri(o2.CtfdUrl!), reportDir);
                return (fake, cfg);
            };

            var exit = await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, factory, CancellationToken.None);
            Assert.Equal(0, exit);
        }
        finally
        {
            try { Directory.Delete(tmpRoot, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task RunAsync_Errors_When_CtfdHost_Not_In_Scope()
    {
        var tmpRoot = Path.Combine(Path.GetTempPath(), "drederick-ctfsolve-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpRoot);
        try
        {
            var scopePath = Path.Combine(tmpRoot, "scope.txt");
            // Scope permits a different IP.
            File.WriteAllText(scopePath, "10.0.0.1\n");
            var opts = CommandLineOptions.Parse(new[]
            {
                "ctf-solve",
                "--scope", scopePath,
                "--ctfd", "http://192.0.2.42/",
                "--ctfd-token", "tok",
                "--models", "m1",
            });
            var exit = await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, CancellationToken.None);
            Assert.Equal(1, exit);
        }
        finally
        {
            try { Directory.Delete(tmpRoot, recursive: true); } catch { }
        }
    }

    private sealed class FakeCoordinator : Drederick.Jeopardy.Coordinator.ICtfCoordinator
    {
        private readonly Drederick.Jeopardy.Coordinator.CompetitionReport _report;
        public bool Called { get; private set; }

        public FakeCoordinator(Drederick.Jeopardy.Coordinator.CompetitionReport report)
        {
            _report = report;
        }

        public Task<Drederick.Jeopardy.Coordinator.CompetitionReport> RunAsync(
            Drederick.Jeopardy.Coordinator.CoordinatorConfig cfg, CancellationToken ct)
        {
            Called = true;
            return Task.FromResult(_report);
        }
    }
}
