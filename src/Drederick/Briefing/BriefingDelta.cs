using System.Text.Json.Serialization;

namespace Drederick.Briefing;

/// <summary>
/// Severity ladder for <see cref="BriefingDelta"/>. Only deltas at or
/// above <see cref="DeltaEmitter.Threshold"/> are emitted. Ordering
/// is intentional — comparisons rely on it.
/// </summary>
public enum BriefingSeverity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// <summary>
/// Kind of high-signal event represented by a briefing delta. The
/// shape is deliberately small and closed: each value maps to a
/// known operator-facing concept so the briefing pane can render
/// it deterministically.
/// </summary>
public enum BriefingDeltaKind
{
    CveMatch,
    NewCredential,
    NewSession,
    Loot,
    PrivescPath,
}

/// <summary>
/// A single typed event proposed for the operator briefing pane.
/// Carries only metadata — never plaintext credentials, never
/// captured secret material, never raw loot bytes. Sensitive
/// evidence is referenced by <see cref="EvidenceRefs"/> (path /
/// audit-id / SHA-256 fragment) and digested by
/// <see cref="DeltaEmitter"/> into a single <c>evidence_sha256</c>
/// audit field so the operator can correlate without the harness
/// leaking the secret itself.
/// </summary>
public sealed class BriefingDelta
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; init; } = DateTimeOffset.UtcNow.ToString("o");

    [JsonPropertyName("target")]
    public string Target { get; init; } = "";

    [JsonPropertyName("kind")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public BriefingDeltaKind Kind { get; init; }

    [JsonPropertyName("severity")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public BriefingSeverity Severity { get; init; }

    /// <summary>
    /// Operator-facing summary. Must not contain plaintext credentials,
    /// session tokens, or other secret material. For
    /// <see cref="BriefingDeltaKind.NewCredential"/> the recommended
    /// shape is "captured N credential(s) for &lt;principal&gt;" — the
    /// secret itself never appears.
    /// </summary>
    [JsonPropertyName("summary")]
    public string SummaryText { get; init; } = "";

    /// <summary>
    /// References to corroborating evidence (audit event ids, file
    /// paths under <c>out/</c>, SHA-256 digests of captured artifacts).
    /// Never the artifact contents.
    /// </summary>
    [JsonPropertyName("evidence_refs")]
    public List<string> EvidenceRefs { get; init; } = new();

    /// <summary>
    /// Number of credentials captured when <see cref="Kind"/> is
    /// <see cref="BriefingDeltaKind.NewCredential"/>. The plaintext
    /// values are never carried on the delta — only the count.
    /// </summary>
    [JsonPropertyName("credential_count")]
    public int? CredentialCount { get; init; }
}
