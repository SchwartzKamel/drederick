using System;
using Drederick.Agent.Budgets;
using Drederick.Cli;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-058: difficulty-adaptive <see cref="ToolBudget"/> with fixed
/// per-tool overrides for noisy tools.
/// </summary>
public class ToolBudgetTests
{
    [Fact]
    public void Default_Is_Medium_Profile_BackwardsCompatible()
    {
        var b = ToolBudget.Default;
        Assert.Equal(Difficulty.Medium, b.Profile.Difficulty);
        Assert.Equal(200, b.GlobalBudget);
        Assert.Equal(3, b.PerToolBudget);
        Assert.Equal(30, b.PerTargetBudget);
    }

    [Fact]
    public void Parameterless_Ctor_Equals_Default()
    {
        var b = new ToolBudget();
        Assert.Equal(Difficulty.Medium, b.Profile.Difficulty);
        Assert.Equal(200, b.GlobalBudget);
    }

    [Theory]
    [InlineData(Difficulty.Easy, 100, 3, 20)]
    [InlineData(Difficulty.Medium, 200, 3, 30)]
    [InlineData(Difficulty.Hard, 400, 4, 50)]
    [InlineData(Difficulty.Insane, 800, 5, 80)]
    public void Each_Difficulty_Produces_Correct_Caps(
        Difficulty d, int global, int perTool, int perTarget)
    {
        var b = new ToolBudget(DifficultyProfile.For(d));
        Assert.Equal(global, b.GlobalBudget);
        Assert.Equal(perTool, b.PerToolBudget);
        Assert.Equal(perTarget, b.PerTargetBudget);
    }

    [Fact]
    public void PerTool_Overrides_Apply_Across_All_Difficulties()
    {
        foreach (var d in new[] { Difficulty.Easy, Difficulty.Medium, Difficulty.Hard, Difficulty.Insane })
        {
            var b = new ToolBudget(DifficultyProfile.For(d));
            Assert.Equal(2, b.CapFor("nmap"));
            Assert.Equal(3, b.CapFor("hydra"));
            Assert.Equal(2, b.CapFor("msf"));
            Assert.Equal(2, b.CapFor("gobuster"));
            Assert.Equal(1, b.CapFor("nuclei"));
            // Unknown tool falls back to the profile's per-tool budget.
            Assert.Equal(b.PerToolBudget, b.CapFor("some-other-tool"));
        }
    }

    [Fact]
    public void ApplyProfile_Reshapes_Caps()
    {
        var b = new ToolBudget(DifficultyProfile.Easy);
        Assert.Equal(100, b.GlobalBudget);

        b.ApplyProfile(DifficultyProfile.Insane);
        Assert.Equal(800, b.GlobalBudget);
        Assert.Equal(5, b.PerToolBudget);
        Assert.Equal(80, b.PerTargetBudget);
        Assert.Equal(Difficulty.Insane, b.Profile.Difficulty);
    }

    [Fact]
    public void ApplyProfile_Is_Idempotent()
    {
        var b = new ToolBudget(DifficultyProfile.Hard);
        b.ApplyProfile(DifficultyProfile.Hard);
        b.ApplyProfile(DifficultyProfile.Hard);

        Assert.Equal(400, b.GlobalBudget);
        Assert.Equal(4, b.PerToolBudget);
        Assert.Equal(50, b.PerTargetBudget);
        Assert.Equal(Difficulty.Hard, b.Profile.Difficulty);
    }

    [Fact]
    public void ApplyProfile_Preserves_Existing_Counters()
    {
        var b = new ToolBudget(DifficultyProfile.Medium);
        b.Charge("tls", "10.0.0.1");
        b.Charge("tls", "10.0.0.2");

        b.ApplyProfile(DifficultyProfile.Insane);

        Assert.Equal(2, b.TotalCalls);
        Assert.Equal(2, b.CallsFor("tls"));
    }

    [Fact]
    public void Charge_Throws_BudgetExceededException_When_Global_Cap_Reached()
    {
        // Easy profile has a 100-call global cap, but we'll squeeze it
        // with a tighter custom shape so the test stays cheap.
        var b = new ToolBudget(new DifficultyProfile(Difficulty.Easy,
            GlobalBudget: 2, PerToolBudget: 5, PerTargetBudget: 5));

        b.Charge("http", "10.0.0.1");
        b.Charge("http", "10.0.0.2");

        var ex = Assert.Throws<BudgetExceededException>(
            () => b.Charge("http", "10.0.0.3"));
        Assert.Contains("Global budget exceeded", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Charge_Throws_When_PerTool_Override_Cap_Reached()
    {
        var b = new ToolBudget(DifficultyProfile.Insane);
        // nuclei is hard-capped at 1 regardless of profile.
        b.Charge("nuclei", "10.0.0.1");
        var ex = Assert.Throws<BudgetExceededException>(
            () => b.Charge("nuclei", "10.0.0.2"));
        Assert.Contains("nuclei", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Charge_Throws_When_PerTarget_Cap_Reached()
    {
        var b = new ToolBudget(new DifficultyProfile(Difficulty.Easy,
            GlobalBudget: 100, PerToolBudget: 100, PerTargetBudget: 1));
        // Unknown tool falls back to the profile's per-tool budget (100),
        // so the per-target cap (1) is the binding constraint.
        b.Charge("http", "10.0.0.1");
        var ex = Assert.Throws<BudgetExceededException>(
            () => b.Charge("http", "10.0.0.1"));
        Assert.Contains("Per-target", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--difficulty=easy", Difficulty.Easy)]
    [InlineData("--difficulty=medium", Difficulty.Medium)]
    [InlineData("--difficulty=hard", Difficulty.Hard)]
    [InlineData("--difficulty=insane", Difficulty.Insane)]
    public void Cli_Parses_Difficulty_Flag_Shorthand(string flag, Difficulty expected)
    {
        var opts = CommandLineOptions.Parse(new[] { "--scope", "scope.yaml", flag });
        Assert.Equal(expected, opts.Difficulty);
    }

    [Theory]
    [InlineData("hard", Difficulty.Hard)]
    [InlineData("insane", Difficulty.Insane)]
    public void Cli_Parses_Difficulty_Flag_Two_Token_Form(string value, Difficulty expected)
    {
        var opts = CommandLineOptions.Parse(new[] { "--scope", "scope.yaml", "--difficulty", value });
        Assert.Equal(expected, opts.Difficulty);
    }

    [Fact]
    public void Cli_Rejects_Unknown_Difficulty()
    {
        Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(new[] { "--scope", "scope.yaml", "--difficulty=brutal" }));
    }

    [Fact]
    public void Cli_Difficulty_Null_When_Not_Supplied_Backwards_Compatible()
    {
        var opts = CommandLineOptions.Parse(new[] { "--scope", "scope.yaml" });
        Assert.Null(opts.Difficulty);
    }
}
