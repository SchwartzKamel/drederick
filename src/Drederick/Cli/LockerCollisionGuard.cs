using Drederick.Audit;

namespace Drederick.Cli;

/// <summary>
/// GAP-045 startup guard: refuses to reuse an existing locker (the
/// <c>--out</c> directory) that already contains a non-empty
/// <c>audit.jsonl</c>. Convention is "Fresh locker, every fight"
/// (README → Code of the Ring); the next fight is always
/// <c>r&lt;N+1&gt;</c>. PingPong R6 reused <c>drederick_r6/</c> on top
/// of R6-attempt1 (commit <c>1c46d1f</c>) and overwrote committed
/// history; this gate prevents that recurrence.
/// </summary>
public static class LockerCollisionGuard
{
    /// <summary>Outcome of <see cref="Check"/>.</summary>
    public enum Outcome
    {
        /// <summary>Empty / non-existent locker — proceed normally.</summary>
        Ok,
        /// <summary>Collision allowed by <c>--allow-locker-collision</c>;
        /// caller should record <c>locker.collision.allowed</c> on the audit.</summary>
        Allowed,
        /// <summary>Collision refused — caller should print the message
        /// and exit with code 2.</summary>
        Refused,
    }

    /// <summary>Result of <see cref="Check"/>.</summary>
    public sealed record Result(Outcome Outcome, long ExistingAuditBytes, string? Message);

    /// <summary>
    /// Inspect <paramref name="outDir"/> for a non-empty <c>audit.jsonl</c>
    /// and decide whether startup may proceed. Pure check — does not write
    /// any files.
    /// </summary>
    public static Result Check(string outDir, bool allowLockerCollision)
    {
        if (string.IsNullOrEmpty(outDir)) return new Result(Outcome.Ok, 0, null);
        var auditPath = Path.Combine(outDir, "audit.jsonl");
        if (!Directory.Exists(outDir) || !File.Exists(auditPath))
        {
            return new Result(Outcome.Ok, 0, null);
        }
        long len;
        try { len = new FileInfo(auditPath).Length; }
        catch { len = 0; }
        if (len <= 0)
        {
            return new Result(Outcome.Ok, 0, null);
        }
        if (allowLockerCollision)
        {
            return new Result(Outcome.Allowed, len, null);
        }
        var msg =
            $"GAP-045: locker {outDir} already contains audit.jsonl. " +
            "Convention is 'Fresh locker, every fight' (README → Code of the Ring). " +
            "Pass --allow-locker-collision to override.";
        return new Result(Outcome.Refused, len, msg);
    }

    /// <summary>
    /// Apply the guard for top-level CLI use. Returns <c>null</c> if startup
    /// should proceed; returns an exit code (2) if the caller must abort.
    /// On <see cref="Outcome.Allowed"/>, records a
    /// <c>locker.collision.allowed</c> event to the existing audit log.
    /// </summary>
    public static int? Apply(string outDir, bool allowLockerCollision, TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(stderr);
        var r = Check(outDir, allowLockerCollision);
        switch (r.Outcome)
        {
            case Outcome.Ok:
                return null;
            case Outcome.Allowed:
                Directory.CreateDirectory(outDir);
                using (var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl")))
                {
                    audit.Record("locker.collision.allowed", new Dictionary<string, object?>
                    {
                        ["out_dir"] = outDir,
                        ["existing_audit_bytes"] = r.ExistingAuditBytes,
                        ["gap"] = "GAP-045",
                    });
                }
                return null;
            case Outcome.Refused:
            default:
                stderr.WriteLine(r.Message);
                return 2;
        }
    }
}
