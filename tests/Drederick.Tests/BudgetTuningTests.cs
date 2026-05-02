using Drederick.Cli;
using Xunit;
using ToolBudget = Drederick.Recon.ToolBudget;
using ExploitToolBudget = Drederick.Exploit.ToolBudget;

namespace Drederick.Tests;

/// <summary>
/// GAP-029: tunable budget caps + LLM-mode defaults. The R5 JobTwo loss
/// showed http=3 / nmap=3 starves an LLM-driven planner. These tests
/// pin down the new CLI surface and the mode-aware defaults.
/// </summary>
public class BudgetTuningTests
{
    [Fact]
    public void Default_ToolBudget_Matches_Pre_GAP029_Numbers()
    {
        Assert.Equal(3, ToolBudget.Default.PerTargetPerTool);
        Assert.Equal(200, ToolBudget.Default.MaxTotalCalls);
        Assert.Equal(5, ExploitToolBudget.Default.PerTargetPerTool);
    }

    [Fact]
    public void LlmDefault_ToolBudget_Raises_Caps()
    {
        Assert.Equal(10, ToolBudget.LlmDefault.PerTargetPerTool);
        Assert.Equal(500, ToolBudget.LlmDefault.MaxTotalCalls);
        Assert.Equal(10, ExploitToolBudget.LlmDefault.PerTargetPerTool);
        Assert.Equal(500, ExploitToolBudget.LlmDefault.MaxTotalCalls);
    }

    [Fact]
    public void CapFor_Returns_Override_When_Present_Else_Global()
    {
        var b = new ToolBudget(3, 200)
        {
            PerToolOverrides = new Dictionary<string, int>
            {
                ["http"] = 20,
                ["nmap"] = 10,
            },
        };
        Assert.Equal(20, b.CapFor("http"));
        Assert.Equal(10, b.CapFor("nmap"));
        Assert.Equal(3, b.CapFor("tls"));
    }

    [Fact]
    public void CapFor_Without_Overrides_Falls_Back_To_Global()
    {
        var b = new ToolBudget(7, 100);
        Assert.Equal(7, b.CapFor("anything"));
    }

    [Fact]
    public void Parses_BudgetPerTool_Equals_Form()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget-per-tool=15" });
        Assert.Equal(15, o.BudgetPerTool);
    }

    [Fact]
    public void Parses_BudgetPerTool_TwoToken_Form()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget-per-tool", "12" });
        Assert.Equal(12, o.BudgetPerTool);
    }

    [Fact]
    public void Parses_BudgetGlobal_Equals_Form()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget-global=750" });
        Assert.Equal(750, o.BudgetGlobal);
    }

    [Fact]
    public void Parses_PerTool_Spec_Multiple_Entries()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget=http:20,nmap:10" });
        Assert.Equal(2, o.BudgetPerToolOverrides.Count);
        Assert.Equal(20, o.BudgetPerToolOverrides["http"]);
        Assert.Equal(10, o.BudgetPerToolOverrides["nmap"]);
    }

    [Fact]
    public void Parses_PerTool_Spec_Single_Entry_With_Whitespace()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget=  nuclei : 25  " });
        Assert.Equal(1, o.BudgetPerToolOverrides.Count);
        Assert.Equal(25, o.BudgetPerToolOverrides["nuclei"]);
    }

    [Fact]
    public void Parses_PerTool_Spec_TwoToken_Form()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget", "smb:8" });
        Assert.Equal(8, o.BudgetPerToolOverrides["smb"]);
    }

    [Fact]
    public void Allows_Zero_Cap_As_DenyAll()
    {
        var o = CommandLineOptions.Parse(new[] { "--budget-per-tool=0" });
        Assert.Equal(0, o.BudgetPerTool);
    }

    [Fact]
    public void Rejects_Negative_PerTool_Cap()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget-per-tool=-1" }));
    }

    [Fact]
    public void Rejects_Malformed_Budget_Spec_Missing_Colon()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget=http20" }));
    }

    [Fact]
    public void Rejects_Malformed_Budget_Spec_NonInteger()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget=foo:bar" }));
    }

    [Fact]
    public void Rejects_Malformed_Budget_Spec_Empty_Tool()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget=:9" }));
    }

    [Fact]
    public void Rejects_Empty_Budget_Spec()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget=" }));
    }

    [Fact]
    public void Rejects_Negative_Per_Entry_Cap()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--budget=http:-3" }));
    }

    [Fact]
    public void AgentHybrid_Without_Explicit_Budget_Uses_LlmDefault()
    {
        var o = CommandLineOptions.Parse(new[] { "--agent=hybrid" });
        Assert.True(o.UseAgent);
        Assert.True(o.UseHybridAgent);
        Assert.Null(o.BudgetPerTool);
        Assert.Null(o.BudgetGlobal);

        // Mirrors the selection logic in Program.cs.
        var baseBudget = o.UseAgent ? ToolBudget.LlmDefault : ToolBudget.Default;
        var effective = new ToolBudget(
            PerTargetPerTool: o.BudgetPerTool ?? baseBudget.PerTargetPerTool,
            MaxTotalCalls: o.BudgetGlobal ?? baseBudget.MaxTotalCalls);
        Assert.Equal(10, effective.PerTargetPerTool);
        Assert.Equal(500, effective.MaxTotalCalls);
    }

    [Fact]
    public void AgentLlm_Without_Explicit_Budget_Uses_LlmDefault()
    {
        var o = CommandLineOptions.Parse(new[] { "--agent=llm" });
        Assert.True(o.UseAgent);
        Assert.False(o.UseHybridAgent);
        var baseBudget = o.UseAgent ? ToolBudget.LlmDefault : ToolBudget.Default;
        Assert.Equal(10, baseBudget.PerTargetPerTool);
    }

    [Fact]
    public void Adaptive_Mode_Keeps_Default_Budget()
    {
        var o = CommandLineOptions.Parse(new[] { "--agent=adaptive" });
        Assert.False(o.UseAgent);
        var baseBudget = o.UseAgent ? ToolBudget.LlmDefault : ToolBudget.Default;
        Assert.Equal(3, baseBudget.PerTargetPerTool);
        Assert.Equal(200, baseBudget.MaxTotalCalls);
    }

    [Fact]
    public void Explicit_PerTool_Override_Wins_Over_AgentMode_Default()
    {
        var o = CommandLineOptions.Parse(new[] { "--agent=hybrid", "--budget-per-tool=25" });
        Assert.Equal(25, o.BudgetPerTool);
        var baseBudget = o.UseAgent ? ToolBudget.LlmDefault : ToolBudget.Default;
        var effective = new ToolBudget(
            PerTargetPerTool: o.BudgetPerTool ?? baseBudget.PerTargetPerTool,
            MaxTotalCalls: o.BudgetGlobal ?? baseBudget.MaxTotalCalls);
        Assert.Equal(25, effective.PerTargetPerTool);
        Assert.Equal(500, effective.MaxTotalCalls);
    }

    [Fact]
    public void PerTool_Spec_Combines_With_Global_Override()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "--budget-per-tool=15",
            "--budget=http:50,nmap:20",
        });
        Assert.Equal(15, o.BudgetPerTool);
        Assert.Equal(50, o.BudgetPerToolOverrides["http"]);
        Assert.Equal(20, o.BudgetPerToolOverrides["nmap"]);

        var b = new ToolBudget(o.BudgetPerTool!.Value, 200)
        {
            PerToolOverrides = new Dictionary<string, int>(o.BudgetPerToolOverrides),
        };
        Assert.Equal(50, b.CapFor("http"));
        Assert.Equal(20, b.CapFor("nmap"));
        Assert.Equal(15, b.CapFor("smb"));
    }
}
