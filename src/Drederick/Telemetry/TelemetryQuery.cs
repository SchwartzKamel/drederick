namespace Drederick.Telemetry;

/// <summary>
/// Filter passed to <see cref="TelemetryRecorder.QueryAsync"/>. All fields are
/// optional; null means "no filter on this column". Combined with AND.
/// </summary>
public sealed record TelemetryQuery
{
    public string? FightId { get; init; }
    public string? TechniqueId { get; init; }
    public string? TargetArchetype { get; init; }
    public string? Service { get; init; }
    public string? Outcome { get; init; }
    public string? SinceTimestamp { get; init; }
    public string? UntilTimestamp { get; init; }
    public int Limit { get; init; } = 10_000;
}
