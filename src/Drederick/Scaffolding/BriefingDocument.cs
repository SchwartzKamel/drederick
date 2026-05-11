namespace Drederick.Scaffolding;

/// <summary>
/// Parsed <c>briefing.md</c> shape as required by
/// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2.1. Only the structured
/// sections the loader extracts are typed; the rest of the markdown is
/// retained verbatim in <see cref="RawMarkdown"/> for the LLM cornerman.
/// </summary>
public sealed record BriefingDocument(
    string Path,
    string Sha256,
    int Lines,
    IReadOnlyDictionary<string, string?> Frontmatter,
    string? Topology,
    IReadOnlyList<AssumedBreachArtifact> AssumedBreach,
    IReadOnlyList<string> KnownAttackPaths,
    IReadOnlyList<string> CornermanDo,
    IReadOnlyList<string> CornermanDont,
    string? OutOfScopeReminders,
    IReadOnlyList<string> SectionsParsed,
    string RawMarkdown,
    IReadOnlyList<TopologyEntry> TopologyEntries);

public sealed record AssumedBreachArtifact(
    string Path,
    string Kind,
    string? Identity,
    string? UseFor);

/// <summary>
/// One row of the briefing's <c>## 1. Topology</c> table:
/// <c>| Hostname | Role | IP | Notes |</c>. Used by
/// <see cref="ScaffoldingContext.ActivateKnownNodes"/> to pre-seed
/// <c>attack_graph.node.activated source: briefing</c> events even
/// when drederick is pivot-blind on direct scans (GAP-049).
/// </summary>
public sealed record TopologyEntry(string Hostname, string? Role, string? Ip, string? Notes);
