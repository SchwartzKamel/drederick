using Drederick.Audit;

namespace Drederick.Scaffolding;

/// <summary>
/// Bundle of the loaded scaffolding + planner-facing API surface
/// described in <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §4.
/// All planner integrations go through this type so the spec is one
/// hop away from any call site.
/// </summary>
public sealed class ScaffoldingContext
{
    private readonly AuditLog _audit;
    private bool _activated;

    public ScaffoldingContext(BriefingDocument? briefing, AttackGraph? graph, AuditLog audit)
    {
        Briefing = briefing;
        Graph = graph;
        _audit = audit;
    }

    public BriefingDocument? Briefing { get; }
    public AttackGraph? Graph { get; }

    /// <summary>True iff at least one of briefing or attack-graph was loaded.</summary>
    public bool IsActive => Briefing is not null || Graph is not null;

    /// <summary>
    /// LOADER_SPEC §4.5 — emit <c>attack_graph.node.activated</c> for
    /// every node whose <c>state: known</c> and whose artifact is named
    /// in the briefing's assumed-breach table. Idempotent.
    /// </summary>
    public void ActivateKnownNodes()
    {
        if (_activated) return;
        _activated = true;
        if (Graph is null) return;

        var briefingArtifacts = Briefing?.AssumedBreach
            .Select(a => a.Path)
            .Where(p => !string.IsNullOrEmpty(p))
            .ToList()
            ?? new List<string>();

        foreach (var node in Graph.Nodes)
        {
            if (!string.Equals(node.State, "known", StringComparison.OrdinalIgnoreCase)) continue;
            string source = "inference";
            if (!string.IsNullOrEmpty(node.Artifact) &&
                briefingArtifacts.Any(a => node.Artifact!.EndsWith(a, StringComparison.OrdinalIgnoreCase)
                                           || a.EndsWith(node.Artifact!, StringComparison.OrdinalIgnoreCase)))
            {
                source = "briefing";
            }
            else if (Briefing is not null)
            {
                source = "priors";
            }
            _audit.Record("attack_graph.node.activated", new Dictionary<string, object?>
            {
                ["node_id"] = node.Id,
                ["kind"] = node.Kind,
                ["source"] = source,
            });
        }
    }

    /// <summary>
    /// LOADER_SPEC §4.2 — return <c>true</c> and emit
    /// <c>attack_graph.anti_goal.blocked</c> if <paramref name="actionId"/>
    /// matches any anti_goal pattern.
    /// </summary>
    public bool RejectIfAntiGoal(string actionId)
    {
        if (Graph is null) return false;
        foreach (var ag in Graph.AntiGoals)
        {
            foreach (var pat in ag.Patterns.Concat(new[] { ag.Id }))
            {
                if (string.IsNullOrEmpty(pat)) continue;
                if (actionId.Contains(pat, StringComparison.OrdinalIgnoreCase))
                {
                    _audit.Record("attack_graph.anti_goal.blocked", new Dictionary<string, object?>
                    {
                        ["anti_goal"] = ag.Id,
                        ["would_have_action_id"] = actionId,
                        ["reason"] = ag.Reason,
                    });
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// LOADER_SPEC §4.1 — return a sort priority for <paramref name="actionId"/>.
    /// Lower is earlier. Emits <c>attack_graph.priority_hint.applied</c>
    /// for hints that match.
    /// </summary>
    public int PriorityFor(string actionId)
    {
        if (Graph is null) return 1000;
        for (var i = 0; i < Graph.PriorityHints.Count; i++)
        {
            var h = Graph.PriorityHints[i];
            var needle = h.AppliesToAction ?? h.Prefer;
            if (string.IsNullOrEmpty(needle)) continue;
            if (actionId.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                _audit.Record("attack_graph.priority_hint.applied", new Dictionary<string, object?>
                {
                    ["hint"] = new Dictionary<string, object?>
                    {
                        ["prefer"] = h.Prefer,
                        ["over"] = h.Over,
                        ["reason"] = h.Reason,
                    },
                    ["action_id"] = actionId,
                });
                return i;
            }
        }
        return 1000;
    }

    /// <summary>
    /// Render a compact human-readable summary of the scaffolding for
    /// inclusion in the LLM user message (LOADER_SPEC §4.1, §4.2, §4.5).
    /// </summary>
    public string BuildPriorContext()
    {
        if (!IsActive) return string.Empty;
        var sb = new System.Text.StringBuilder();
        sb.AppendLine();
        sb.AppendLine("### In-fight scaffolding (operator-supplied)");
        if (Briefing is not null)
        {
            sb.AppendLine($"- briefing.md ({Briefing.Path}): {Briefing.SectionsParsed.Count} parsed sections");
            if (Briefing.AssumedBreach.Count > 0)
            {
                sb.AppendLine("- Assumed-breach material (CONSUME these — silently ignoring is a contract violation):");
                foreach (var a in Briefing.AssumedBreach)
                    sb.AppendLine($"  - {a.Path} ({a.Kind})" +
                        (a.Identity is not null ? $" identity={a.Identity}" : "") +
                        (a.UseFor is not null ? $" use_for={a.UseFor}" : ""));
            }
            if (Briefing.CornermanDont.Count > 0)
            {
                sb.AppendLine("- Cornerman DON'T (anti-goals):");
                foreach (var d in Briefing.CornermanDont) sb.AppendLine($"  - {d}");
            }
        }
        if (Graph is not null)
        {
            sb.AppendLine($"- attack-graph.yaml ({Graph.Path}): {Graph.Nodes.Count} nodes, {Graph.Edges.Count} edges");
            if (Graph.PriorityHints.Count > 0)
            {
                sb.AppendLine("- Priority hints (apply in order):");
                foreach (var h in Graph.PriorityHints)
                    sb.AppendLine($"  - prefer {h.Prefer}" +
                        (h.Over is not null ? $" over {h.Over}" : "") +
                        (h.Reason is not null ? $" — {h.Reason}" : ""));
            }
            if (Graph.AntiGoals.Count > 0)
            {
                sb.AppendLine("- Anti-goals (HARD blockers — do not schedule):");
                foreach (var a in Graph.AntiGoals)
                    sb.AppendLine($"  - {a.Id}: {a.Reason}");
            }
        }
        return sb.ToString();
    }
}
