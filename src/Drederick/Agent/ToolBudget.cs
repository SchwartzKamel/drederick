using System;
using System.Collections.Generic;

namespace Drederick.Agent.Budgets;

/// <summary>
/// GAP-058: difficulty-adaptive, stateful budget tracker shared by the
/// agent runners. Wraps a <see cref="DifficultyProfile"/> with a fixed
/// set of per-tool overrides for noisy / high-blast-radius tooling
/// (nmap, hydra, msf, gobuster, nuclei) and enforces three caps:
/// <list type="bullet">
///   <item><description>Global: total tool calls in the run.</description></item>
///   <item><description>Per-tool: total calls of any single tool, after overrides.</description></item>
///   <item><description>Per-target: calls of one tool against one target.</description></item>
/// </list>
/// Exceeding any cap throws <see cref="BudgetExceededException"/>. The
/// budget is *not* an authorization signal — scope is enforced inside
/// every tool independently. The budget is a runaway-loop rate-limit.
/// </summary>
public sealed class ToolBudget
{
    private static readonly IReadOnlyDictionary<string, int> DefaultPerToolOverrides =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["nmap"] = 2,
            ["hydra"] = 3,
            ["msf"] = 2,
            ["gobuster"] = 2,
            ["nuclei"] = 1,
        };

    private readonly object _lock = new();
    private int _totalCalls;
    private readonly Dictionary<string, int> _perToolCalls =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Tool, string Target), int> _perTargetCalls = new();

    public ToolBudget()
        : this(DifficultyProfile.Medium)
    {
    }

    public ToolBudget(DifficultyProfile profile)
    {
        if (profile is null) throw new ArgumentNullException(nameof(profile));
        Profile = profile;
        GlobalBudget = profile.GlobalBudget;
        PerToolBudget = profile.PerToolBudget;
        PerTargetBudget = profile.PerTargetBudget;
    }

    /// <summary>Backwards-compatible default — medium difficulty.</summary>
    public static ToolBudget Default => new(DifficultyProfile.Medium);

    /// <summary>Current difficulty profile.</summary>
    public DifficultyProfile Profile { get; private set; }

    /// <summary>Total-calls cap for the whole run.</summary>
    public int GlobalBudget { get; private set; }

    /// <summary>Default per-tool cap when no override is registered.</summary>
    public int PerToolBudget { get; private set; }

    /// <summary>Per-tool-per-target cap.</summary>
    public int PerTargetBudget { get; private set; }

    /// <summary>Fixed per-tool overrides (difficulty-independent). Tool
    /// names match <c>IReconTool.Name</c> / <c>IExploitTool.Name</c>.</summary>
    public IReadOnlyDictionary<string, int> PerToolOverrides => DefaultPerToolOverrides;

    /// <summary>Re-shape the budget to <paramref name="profile"/>. Idempotent:
    /// applying the same profile twice is a no-op. Counters are preserved
    /// across calls so that a mid-run profile bump cannot retroactively
    /// "rescue" a planner that has already exhausted the previous cap.</summary>
    public void ApplyProfile(DifficultyProfile profile)
    {
        if (profile is null) throw new ArgumentNullException(nameof(profile));
        lock (_lock)
        {
            Profile = profile;
            GlobalBudget = profile.GlobalBudget;
            PerToolBudget = profile.PerToolBudget;
            PerTargetBudget = profile.PerTargetBudget;
        }
    }

    /// <summary>Effective per-tool cap: override if present, else <see cref="PerToolBudget"/>.</summary>
    public int CapFor(string tool)
    {
        if (string.IsNullOrEmpty(tool)) throw new ArgumentException("tool required", nameof(tool));
        return DefaultPerToolOverrides.TryGetValue(tool, out var cap) ? cap : PerToolBudget;
    }

    /// <summary>Record a single tool invocation and enforce all three
    /// caps. Throws <see cref="BudgetExceededException"/> when any cap
    /// is exceeded; the counter for the offending dimension is *not*
    /// incremented past the cap, so callers may catch and continue.</summary>
    public void Charge(string tool, string target)
    {
        if (string.IsNullOrEmpty(tool)) throw new ArgumentException("tool required", nameof(tool));
        if (string.IsNullOrEmpty(target)) throw new ArgumentException("target required", nameof(target));

        lock (_lock)
        {
            if (_totalCalls + 1 > GlobalBudget)
                throw new BudgetExceededException(
                    $"Global budget exceeded ({GlobalBudget}) for {Profile.Difficulty} profile.");

            var perToolCap = DefaultPerToolOverrides.TryGetValue(tool, out var c) ? c : PerToolBudget;
            _perToolCalls.TryGetValue(tool, out var perTool);
            if (perTool + 1 > perToolCap)
                throw new BudgetExceededException(
                    $"Per-tool budget exceeded for '{tool}' (cap={perToolCap}).");

            var key = (tool, target);
            _perTargetCalls.TryGetValue(key, out var perTarget);
            if (perTarget + 1 > PerTargetBudget)
                throw new BudgetExceededException(
                    $"Per-target budget exceeded for '{tool}' on '{target}' (cap={PerTargetBudget}).");

            _totalCalls++;
            _perToolCalls[tool] = perTool + 1;
            _perTargetCalls[key] = perTarget + 1;
        }
    }

    /// <summary>Total calls charged so far (across all tools/targets).</summary>
    public int TotalCalls
    {
        get { lock (_lock) return _totalCalls; }
    }

    /// <summary>Calls charged so far for <paramref name="tool"/>.</summary>
    public int CallsFor(string tool)
    {
        lock (_lock)
        {
            return _perToolCalls.TryGetValue(tool, out var v) ? v : 0;
        }
    }
}

/// <summary>Thrown by <see cref="ToolBudget.Charge"/> when any cap is hit.</summary>
public sealed class BudgetExceededException : Exception
{
    public BudgetExceededException(string message) : base(message) { }
}
