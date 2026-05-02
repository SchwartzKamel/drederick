namespace Drederick.Scaffolding;

/// <summary>
/// In-memory representation of <c>attack-graph.yaml</c> as defined by
/// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2.1. Vocabulary is
/// preserved as literal strings — unknown values do not abort loading.
/// </summary>
public sealed record AttackGraph(
    int SchemaVersion,
    string Box,
    IReadOnlyList<AttackGraphNode> Nodes,
    IReadOnlyList<AttackGraphEdge> Edges,
    IReadOnlyList<PriorityHint> PriorityHints,
    IReadOnlyList<AntiGoal> AntiGoals,
    AttackBudget? Budget,
    string? GeneratedBy,
    string? LastUpdated,
    string Path,
    string Sha256);

public sealed record AttackGraphNode(
    string Id,
    string Kind,
    string State,
    IReadOnlyList<string> Requires,
    IReadOnlyList<string> Yields,
    string? Artifact,
    string? Note,
    string? Method,
    string? Tool);

public sealed record AttackGraphEdge(
    string From,
    string To,
    string? Method,
    string? Note);

public sealed record PriorityHint(
    string Prefer,
    string? Over,
    string? Reason,
    string? AppliesToAction);

public sealed record AntiGoal(
    string Id,
    string Reason,
    IReadOnlyList<string> Patterns);

public sealed record AttackBudget(
    int? MaxMinutes,
    int? MaxActions);
