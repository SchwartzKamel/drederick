using System.Text.Json.Serialization;

namespace Drederick.Autopilot.ChainReasoner;

/// <summary>
/// One step inside a multi-stage attack chain. Steps are ordered;
/// <see cref="Requires"/> must hold before this step runs and
/// <see cref="Produces"/> are facts added on success. Predicate vocabulary is
/// shared with <see cref="ChainFacts"/> (e.g. <c>smb.anon-read=true</c>,
/// <c>cred.user.password</c>, <c>session.open=true</c>).
/// </summary>
public sealed record AttackStep
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("tool")] public string Tool { get; init; } = "";
    [JsonPropertyName("args")] public string Args { get; init; } = "";
    [JsonPropertyName("requires")] public IReadOnlyList<string> Requires { get; init; } = Array.Empty<string>();
    [JsonPropertyName("produces")] public IReadOnlyList<string> Produces { get; init; } = Array.Empty<string>();
    [JsonPropertyName("confidence")] public double Confidence { get; init; } = 0.5;
    [JsonPropertyName("cost")] public int Cost { get; init; } = 100;
    [JsonPropertyName("rationale")] public string Rationale { get; init; } = "";
}

/// <summary>
/// A ranked, explainable composite plan: ordered steps, scoped targets, and
/// the composite score (likelihood × impact − cost) the reasoner used to sort
/// candidates. <see cref="Reason"/> is operator-readable explanation built
/// from the predicates that matched.
/// </summary>
public sealed record AttackChain
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("steps")] public IReadOnlyList<AttackStep> Steps { get; init; } = Array.Empty<AttackStep>();
    [JsonPropertyName("targets")] public IReadOnlyList<string> Targets { get; init; } = Array.Empty<string>();
    [JsonPropertyName("likelihood")] public double Likelihood { get; init; }
    [JsonPropertyName("impact")] public double Impact { get; init; }
    [JsonPropertyName("cost")] public int Cost { get; init; }
    [JsonPropertyName("score")] public double Score { get; init; }
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
    [JsonPropertyName("source")] public string Source { get; init; } = "rule";
}
