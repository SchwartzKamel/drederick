namespace Drederick.Doctor;

/// <summary>
/// Outcome category of a single <see cref="IDoctorCheck"/>. Consumers render
/// these to ✓ / ⚠ / ✗ markers; failure of one check never short-circuits
/// sibling checks.
/// </summary>
public enum DoctorCheckStatus
{
    Pass,
    Warn,
    Fail,
}

/// <summary>
/// Structured result of a doctor check. <see cref="FixCommand"/> is the
/// *exact* shell command the operator should run themselves — doctor never
/// executes it silently with sudo. When the check was able to apply the
/// fix itself (e.g. a consented `docker build`), <see cref="FixApplied"/>
/// is true.
/// </summary>
public sealed record DoctorCheckResult(
    string Id,
    DoctorCheckStatus Status,
    string Detail,
    string? FixCommand = null,
    string? FixRationale = null,
    bool FixApplied = false);

/// <summary>
/// One pluggable doctor check. Implementations MUST:
///   * be independent (no hidden ordering between checks),
///   * never re-exec as root or invoke sudo,
///   * record <c>doctor.&lt;category&gt;.&lt;id&gt;.start/.finish</c> to the audit log,
///   * treat a null scope as "no scope loaded" (warn/fail gracefully).
///
/// This is the extension-point introduced by the jeopardy-doctor todo; existing
/// <see cref="DoctorRunner"/> tool detection is unchanged.
/// </summary>
public interface IDoctorCheck
{
    /// <summary>Stable dotted id, e.g. <c>jeopardy.docker.installed</c>.</summary>
    string Id { get; }

    /// <summary>Category bucket for CLI filtering (e.g. <c>jeopardy</c>).</summary>
    string Category { get; }

    /// <summary>
    /// Run the check. Must not throw for expected failures (missing binary,
    /// scope-out, unreachable host) — surface them as <see cref="DoctorCheckStatus.Fail"/>
    /// / <see cref="DoctorCheckStatus.Warn"/>.
    /// </summary>
    /// <param name="install">Caller asked us to apply fixes on consent.</param>
    /// <param name="assumeYes">Caller passed <c>-y/--yes</c>; skip [y/N] prompt.</param>
    Task<DoctorCheckResult> RunAsync(
        bool install,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct);
}
