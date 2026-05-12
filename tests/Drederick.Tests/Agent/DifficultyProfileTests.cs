using Drederick.Agent.Budgets;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-058: difficulty-adaptive budget profile shape.
/// </summary>
public class DifficultyProfileTests
{
    [Fact]
    public void Easy_Profile_Has_Tight_Caps()
    {
        var p = DifficultyProfile.Easy;
        Assert.Equal(Difficulty.Easy, p.Difficulty);
        Assert.Equal(100, p.GlobalBudget);
        Assert.Equal(3, p.PerToolBudget);
        Assert.Equal(20, p.PerTargetBudget);
    }

    [Fact]
    public void Medium_Profile_Matches_Pre_GAP058_Default()
    {
        var p = DifficultyProfile.Medium;
        Assert.Equal(Difficulty.Medium, p.Difficulty);
        Assert.Equal(200, p.GlobalBudget);
        Assert.Equal(3, p.PerToolBudget);
        Assert.Equal(30, p.PerTargetBudget);
    }

    [Fact]
    public void Hard_Profile_Raises_Caps()
    {
        var p = DifficultyProfile.Hard;
        Assert.Equal(400, p.GlobalBudget);
        Assert.Equal(4, p.PerToolBudget);
        Assert.Equal(50, p.PerTargetBudget);
    }

    [Fact]
    public void Insane_Profile_Has_Maximum_Headroom()
    {
        var p = DifficultyProfile.Insane;
        Assert.Equal(800, p.GlobalBudget);
        Assert.Equal(5, p.PerToolBudget);
        Assert.Equal(80, p.PerTargetBudget);
    }

    [Theory]
    [InlineData("easy", 100)]
    [InlineData("EASY", 100)]
    [InlineData("medium", 200)]
    [InlineData("med", 200)]
    [InlineData("Hard", 400)]
    [InlineData("insane", 800)]
    public void TryParse_Accepts_Known_Difficulties(string input, int expectedGlobal)
    {
        Assert.True(DifficultyProfile.TryParse(input, out var profile));
        Assert.Equal(expectedGlobal, profile.GlobalBudget);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("brutal")]
    [InlineData("nightmare")]
    public void TryParse_Rejects_Unknown_Values(string? input)
    {
        Assert.False(DifficultyProfile.TryParse(input, out var profile));
        // Falls back to medium so callers without explicit handling stay safe.
        Assert.Equal(Difficulty.Medium, profile.Difficulty);
    }

    [Fact]
    public void For_Returns_Canonical_Profile_For_Each_Difficulty()
    {
        Assert.Same(DifficultyProfile.Easy, DifficultyProfile.For(Difficulty.Easy));
        Assert.Same(DifficultyProfile.Medium, DifficultyProfile.For(Difficulty.Medium));
        Assert.Same(DifficultyProfile.Hard, DifficultyProfile.For(Difficulty.Hard));
        Assert.Same(DifficultyProfile.Insane, DifficultyProfile.For(Difficulty.Insane));
    }
}
