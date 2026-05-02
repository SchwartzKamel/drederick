using System.Text.Json.Serialization;

namespace Drederick.Learning;

/// <summary>
/// A single LLM-authored fight note. Append-only record; never edited
/// in place. Persisted as one JSON object per line by
/// <see cref="FightNotebook"/>.
///
/// <para><b>Privacy invariants.</b>
///   • <see cref="Body"/> is redacted by <see cref="FightNotebook"/>
///     before persistence (passwords / hashes / private keys masked).
///   • <see cref="TargetHost"/> mirrors <see cref="Drederick.Telemetry.TelemetryRecorder.RedactHost"/>
///     and is reduced to a /24 or /48 for RFC1918 / loopback / link-local.
///   • <see cref="BodySha256"/> is filled in by the writer for cross-run
///     correlation without re-storing the redacted body.</para>
/// </summary>
public sealed class FightNote
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";

    [JsonPropertyName("fight_id")]
    public string? FightId { get; set; }

    [JsonPropertyName("category")]
    public string Category { get; set; } = "";

    [JsonPropertyName("body")]
    public string Body { get; set; } = "";

    [JsonPropertyName("body_sha256")]
    public string BodySha256 { get; set; } = "";

    [JsonPropertyName("tags")]
    public IReadOnlyList<string> Tags { get; set; } = Array.Empty<string>();

    [JsonPropertyName("target_host")]
    public string? TargetHost { get; set; }

    [JsonPropertyName("target_archetype")]
    public string? TargetArchetype { get; set; }

    [JsonPropertyName("source")]
    public string Source { get; set; } = "llm";
}

/// <summary>
/// Canonical note categories. Free-form strings are accepted; this list
/// is what the LLM tool description encourages and what
/// <c>drederick review</c> groups on.
/// </summary>
public static class FightNoteCategory
{
    public const string Observation = "observation";
    public const string Tactic = "tactic";
    public const string Gap = "gap";
    public const string Mistake = "mistake";
    public const string WinningMove = "winning_move";
    public const string Lesson = "lesson";
    public const string General = "general";

    public static readonly IReadOnlyList<string> All =
        new[] { Observation, Tactic, Gap, Mistake, WinningMove, Lesson, General };

    public static bool IsKnown(string? c) =>
        c is not null && All.Contains(c, StringComparer.OrdinalIgnoreCase);
}
