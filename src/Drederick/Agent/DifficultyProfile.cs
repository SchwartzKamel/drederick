using System;

namespace Drederick.Agent.Budgets;

/// <summary>
/// Difficulty rating for an engagement. Picks the global / per-tool /
/// per-target budget shape via <see cref="DifficultyProfile"/>. Higher
/// difficulties unlock more headroom for the LLM and adaptive planners
/// at the cost of longer runs.
/// </summary>
public enum Difficulty
{
    Easy,
    Medium,
    Hard,
    Insane,
}

/// <summary>
/// GAP-058: difficulty-adaptive budget shape. A <see cref="DifficultyProfile"/>
/// supplies a single global call cap, a default per-tool cap and a
/// per-target cap to <see cref="ToolBudget"/>. Per-tool overrides for
/// noisy / high-blast-radius tools (nmap, hydra, msf, gobuster, nuclei)
/// are layered on top by <see cref="ToolBudget"/> itself and are
/// difficulty-independent.
/// </summary>
public sealed record DifficultyProfile(
    Difficulty Difficulty,
    int GlobalBudget,
    int PerToolBudget,
    int PerTargetBudget)
{
    /// <summary>Quick-and-thin boxes: tight caps so a runaway loop fails fast.</summary>
    public static DifficultyProfile Easy { get; } = new(Difficulty.Easy, 100, 3, 20);

    /// <summary>Default shape — backwards compatible with pre-GAP-058 budgets.</summary>
    public static DifficultyProfile Medium { get; } = new(Difficulty.Medium, 200, 3, 30);

    /// <summary>Multi-stage hard boxes: more iterations, slightly higher per-tool cap.</summary>
    public static DifficultyProfile Hard { get; } = new(Difficulty.Hard, 400, 4, 50);

    /// <summary>Insane / multi-host CTF chains: maximum headroom.</summary>
    public static DifficultyProfile Insane { get; } = new(Difficulty.Insane, 800, 5, 80);

    /// <summary>Resolve the canonical profile for <paramref name="difficulty"/>.</summary>
    public static DifficultyProfile For(Difficulty difficulty) => difficulty switch
    {
        Difficulty.Easy => Easy,
        Difficulty.Medium => Medium,
        Difficulty.Hard => Hard,
        Difficulty.Insane => Insane,
        _ => throw new ArgumentOutOfRangeException(nameof(difficulty), difficulty, "Unknown difficulty."),
    };

    /// <summary>Parse a CLI string (case-insensitive) into a profile.</summary>
    public static bool TryParse(string? value, out DifficultyProfile profile)
    {
        profile = Medium;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        switch (value.Trim().ToLowerInvariant())
        {
            case "easy": profile = Easy; return true;
            case "medium": case "med": profile = Medium; return true;
            case "hard": profile = Hard; return true;
            case "insane": profile = Insane; return true;
            default: return false;
        }
    }
}
