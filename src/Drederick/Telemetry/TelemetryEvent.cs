namespace Drederick.Telemetry;

/// <summary>
/// Per-attempt structured learning datum. Distinct from
/// <see cref="Drederick.Audit.AuditLog"/> entries: telemetry is the analytics
/// substrate that feeds <c>drederick review</c>, planner self-tuning, and
/// fingerprint growth (see <c>docs/LEARNING_LOOP.md</c>). The audit log is
/// the immutable safety record. Both reference each other via
/// <see cref="AuditCorrelationId"/>.
/// </summary>
public sealed record TelemetryEvent
{
    public long Id { get; init; }
    public string Timestamp { get; init; } = string.Empty;
    public string? FightId { get; init; }
    public string TechniqueId { get; init; } = string.Empty;
    public string? TargetArchetype { get; init; }
    public string? TargetHost { get; init; }
    public string? Service { get; init; }
    public int? Port { get; init; }

    /// <summary>One of <c>success</c>, <c>fail</c>, <c>error</c>, <c>skipped</c>.</summary>
    public string Outcome { get; init; } = string.Empty;

    public long TimeMs { get; init; }
    public long? LlmCostTokens { get; init; }
    public string? AuditCorrelationId { get; init; }

    /// <summary>Free-form analyst-readable note. Plaintext secrets MUST NOT appear here.</summary>
    public string? Notes { get; init; }
}

public static class TelemetryOutcome
{
    public const string Success = "success";
    public const string Fail = "fail";
    public const string Error = "error";
    public const string Skipped = "skipped";

    public static bool IsValid(string outcome) =>
        outcome is Success or Fail or Error or Skipped;
}
