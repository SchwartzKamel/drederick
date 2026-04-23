using Drederick.Audit;

namespace Drederick.Doctor;

/// <summary>
/// Doctor check for the optional <c>magika</c> binary (Google's ML file-type
/// detector). Magika speeds up binary pre-classification and directs CTF
/// solver toolchain selection — but drederick works without it. This check
/// warns (never fails) so a missing magika never blocks the operator.
///
/// Category: <c>recon</c>. Id: <c>recon.magika.available</c>.
/// </summary>
public sealed class MagikaToolCheck : IDoctorCheck
{
    public const string CategoryName = "recon";

    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly string _binary;

    public MagikaToolCheck(AuditLog audit, IProcessRunner runner, string binary = "magika")
    {
        _audit = audit;
        _runner = runner;
        _binary = binary;
    }

    public string Id => "recon.magika.available";
    public string Category => CategoryName;

    public Task<DoctorCheckResult> RunAsync(
        bool install,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct)
    {
        _audit.Record($"doctor.recon.{Id}.start", new Dictionary<string, object?> { ["id"] = Id });
        try
        {
            var (exit, sout, _) = _runner.Run(_binary, "--version", 5);
            if (exit == 0)
            {
                var version = (sout ?? string.Empty).Split('\n', 2)[0].Trim();
                return Finish(DoctorCheckStatus.Pass,
                    string.IsNullOrEmpty(version) ? "magika present" : $"magika: {version}");
            }
            return Finish(DoctorCheckStatus.Warn,
                $"`magika --version` exited {exit} — binary-analysis pre-pass will be skipped",
                fixCommand: "pipx install magika  # (fallback: cargo install magika)",
                fixRationale: "magika is optional; drederick falls back to the `file` command when it is missing.");
        }
        catch (Exception ex)
        {
            return Finish(DoctorCheckStatus.Warn,
                $"could not invoke `{_binary} --version`: {ex.Message} — binary-analysis pre-pass will be skipped",
                fixCommand: "pipx install magika  # (fallback: cargo install magika)",
                fixRationale: "magika is optional; drederick falls back to the `file` command when it is missing.");
        }
    }

    private Task<DoctorCheckResult> Finish(
        DoctorCheckStatus status,
        string detail,
        string? fixCommand = null,
        string? fixRationale = null)
    {
        _audit.Record($"doctor.recon.{Id}.finish", new Dictionary<string, object?>
        {
            ["id"] = Id,
            ["status"] = status.ToString().ToLowerInvariant(),
            ["detail"] = detail,
        });
        return Task.FromResult(new DoctorCheckResult(Id, status, detail, fixCommand, fixRationale));
    }
}

/// <summary>
/// Factory + runner for the <c>recon</c> category doctor checks. Currently
/// just the magika availability check; grows as more optional recon tooling
/// is added.
/// </summary>
public static class ReconDoctorChecks
{
    public const string CategoryName = "recon";

    public static IReadOnlyList<IDoctorCheck> All(AuditLog audit, IProcessRunner runner)
    {
        return new IDoctorCheck[]
        {
            new MagikaToolCheck(audit, runner),
        };
    }

    public static async Task<IReadOnlyList<DoctorCheckResult>> RunAllAsync(
        AuditLog audit,
        IProcessRunner runner,
        bool install,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct)
    {
        var checks = All(audit, runner);
        var results = new List<DoctorCheckResult>(checks.Count);

        stdout.WriteLine("drederick doctor: recon-category checks");
        stdout.WriteLine("---------------------------------------");

        foreach (var c in checks)
        {
            DoctorCheckResult r;
            try
            {
                r = await c.RunAsync(install, assumeYes, stdin, stdout, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                r = new DoctorCheckResult(c.Id, DoctorCheckStatus.Fail,
                    $"check threw {ex.GetType().Name}: {ex.Message}");
            }
            results.Add(r);
            var glyph = r.Status switch
            {
                DoctorCheckStatus.Pass => "✓",
                DoctorCheckStatus.Warn => "⚠",
                _ => "✗",
            };
            stdout.WriteLine($"  {glyph} {r.Id,-34} {r.Detail}");
            if (r.Status != DoctorCheckStatus.Pass && !string.IsNullOrEmpty(r.FixCommand))
            {
                stdout.WriteLine($"       fix: {r.FixCommand}");
                if (!string.IsNullOrEmpty(r.FixRationale))
                    stdout.WriteLine($"       why: {r.FixRationale}");
            }
        }

        stdout.WriteLine("---------------------------------------");
        var pass = results.Count(r => r.Status == DoctorCheckStatus.Pass);
        var warn = results.Count(r => r.Status == DoctorCheckStatus.Warn);
        var fail = results.Count(r => r.Status == DoctorCheckStatus.Fail);
        stdout.WriteLine($"summary: {pass} pass  {warn} warn  {fail} fail");
        return results;
    }
}
