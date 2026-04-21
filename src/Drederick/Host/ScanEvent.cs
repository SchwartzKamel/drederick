namespace Drederick.Host;

/// <summary>
/// Kind of progress event emitted by <see cref="DrederickHost"/> during a run.
/// The UI binds to this stream; the CLI can format it to stdout. Every event
/// has a mirror in <see cref="Drederick.Audit.AuditLog"/> so behaviour parity
/// with the CLI is maintained — the <c>IProgress&lt;ScanEvent&gt;</c> pipe is
/// additive, not a replacement for the append-only audit log.
/// </summary>
public enum ScanEventKind
{
    SessionStart,
    ScopeLoaded,
    RunnerStart,
    ToolStart,
    ToolFinish,
    HostFinished,
    RunnerFinish,
    ReportWritten,
    VpnPreflight,
    CveAnnotated,
    PocAggregated,
    SessionEnd,
    Error,
    Info,
}

/// <summary>
/// A single progress event surfaced to the UI / CLI during a
/// <see cref="DrederickHost.RunAsync"/> call.
///
/// Fields are all optional except <see cref="Kind"/> and
/// <see cref="Timestamp"/>: not every kind populates every field. The UI layer
/// must treat this as an immutable value.
/// </summary>
public sealed record ScanEvent(
    ScanEventKind Kind,
    DateTimeOffset Timestamp,
    string? Target = null,
    string? Tool = null,
    string? Message = null,
    int? ToolCallsTotal = null);
