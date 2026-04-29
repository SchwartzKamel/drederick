using System.Collections.Concurrent;
using Drederick.Audit;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Orchestrates registered <see cref="IFuzzTool"/> implementations and enforces
/// per-target per-tool call budgets so a runaway agent or LLM planner cannot
/// re-fuzz the same surface forever. Mirrors the <see cref="ReconToolbox"/>
/// pattern but specialized for fuzzing: category-based grouping, stricter
/// default budgets (fuzzing is higher-volume than passive recon), and opt-in
/// gating for destructive categories (<see cref="FuzzCategory.Network"/>,
/// <see cref="FuzzCategory.Mutation"/>).
/// </summary>
public sealed class FuzzToolbox
{
    private readonly IReadOnlyList<IFuzzTool> _tools;
    private readonly AuditLog _audit;
    private readonly ConcurrentDictionary<(string target, string tool), int> _calls = new();
    private int _toolCallsTotal;

    /// <summary>
    /// Default per-target per-tool budget for fuzz tools. Lower than
    /// <see cref="ReconToolbox"/> default (3 per target per tool) because
    /// fuzzers are intentionally high-volume and we want tighter rails to
    /// prevent runaway campaigns. Override via the <c>budget</c> parameter
    /// when lab constraints differ.
    /// </summary>
    public static ToolBudget DefaultBudget { get; } = new(PerTargetPerTool: 2, MaxTotalCalls: 100);

    public FuzzToolbox(
        IEnumerable<IFuzzTool> tools,
        AuditLog audit,
        ToolBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(audit);

        var materialized = tools.ToList();

        // Reject duplicate tool names at construction time so registration bugs
        // surface immediately (before the operator burns time on a partial scan).
        var nameSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (var t in materialized)
        {
            if (!nameSet.Add(t.Name))
            {
                throw new ArgumentException(
                    $"Duplicate fuzz tool name '{t.Name}'. All registered tools must have unique Names.",
                    nameof(tools));
            }
        }

        _tools = materialized;
        _audit = audit;
        Budget = budget ?? DefaultBudget;
    }

    /// <summary>
    /// All registered fuzz tools, in registration order. Exposed so the LLM
    /// runner can enumerate tool metadata (<see cref="IReconTool.Name"/>,
    /// <see cref="IReconTool.Description"/>, <see cref="IFuzzTool.Category"/>)
    /// without hard-coding the set.
    /// </summary>
    public IReadOnlyList<IFuzzTool> Tools => _tools;

    /// <summary>
    /// Per-target per-tool and global call budget caps. When a fuzz tool
    /// exceeds its cap, <see cref="RecordCall"/> throws
    /// <see cref="InvalidOperationException"/> with a clear message. This
    /// prevents infinite loops in the LLM planner and limits blast radius
    /// in lab environments where DNS resolvers, reverse proxies, or WAFs
    /// may flag high-volume probes.
    /// </summary>
    public ToolBudget Budget { get; }

    /// <summary>
    /// Total fuzz tool invocations across all tools and targets since
    /// construction. Monotonically increasing. When it exceeds
    /// <see cref="Budget"/>'s <c>MaxTotalCalls</c>, all future
    /// <see cref="RecordCall"/> attempts fail.
    /// </summary>
    public int ToolCallsTotal => _toolCallsTotal;

    /// <summary>
    /// Lookup a fuzz tool by its <see cref="IReconTool.Name"/> (case-sensitive).
    /// Returns <c>null</c> when no tool with that name is registered.
    /// </summary>
    public IFuzzTool? GetByName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return _tools.FirstOrDefault(t => t.Name.Equals(name, StringComparison.Ordinal));
    }

    /// <summary>
    /// Filter registered tools to those in the specified
    /// <paramref name="category"/>. Returns empty when no tools match.
    /// Useful for <see cref="Agent.AdaptiveRunner"/> to schedule category-
    /// specific fuzz passes (e.g. "only run WebApi fuzzers when GraphQL is
    /// detected").
    /// </summary>
    public IEnumerable<IFuzzTool> ByCategory(FuzzCategory category)
    {
        return _tools.Where(t => t.Category == category);
    }

    /// <summary>
    /// Record a single fuzz tool invocation against <paramref name="target"/>
    /// for budget tracking. Increments the per-target per-tool counter and
    /// the global counter. Throws <see cref="InvalidOperationException"/> if
    /// the per-target per-tool cap (<see cref="Budget"/>'s
    /// <c>PerTargetPerTool</c>) or the global cap (<c>MaxTotalCalls</c>) is
    /// exceeded. This is the load-bearing budget enforcement point; every
    /// fuzz tool method in <see cref="FuzzToolbox"/> (or in custom wrappers
    /// that LLM runners call) MUST call this before dispatching to the
    /// underlying tool.
    /// </summary>
    /// <param name="toolName">The <see cref="IReconTool.Name"/> of the tool being invoked.</param>
    /// <param name="target">The target host/URL being fuzzed.</param>
    public void RecordCall(string toolName, string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);

        var count = _calls.AddOrUpdate((target, toolName), 1, (_, c) => c + 1);
        Interlocked.Increment(ref _toolCallsTotal);

        if (count > Budget.PerTargetPerTool)
        {
            throw new InvalidOperationException(
                $"Fuzz budget exceeded: {toolName} called {count} times on {target} " +
                $"(cap {Budget.PerTargetPerTool}). Reduce fuzz iteration count or increase " +
                $"PerTargetPerTool budget.");
        }

        if (_toolCallsTotal > Budget.MaxTotalCalls)
        {
            throw new InvalidOperationException(
                $"Total fuzz tool-call budget exceeded: {_toolCallsTotal} > {Budget.MaxTotalCalls}. " +
                $"The fuzzing campaign is consuming too many resources; halt and triage findings.");
        }

        _audit.Record("fuzz.call", new Dictionary<string, object?>
        {
            ["tool"] = toolName,
            ["target"] = target,
            ["call_count"] = count,
            ["total_calls"] = _toolCallsTotal,
        });
    }
}
