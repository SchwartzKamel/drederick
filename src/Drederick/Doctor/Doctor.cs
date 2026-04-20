using System.Diagnostics;
using Drederick.Audit;

namespace Drederick.Doctor;

/// <summary>
/// Detects and (optionally) installs the operator-workstation tooling drederick
/// needs. This modifies the operator's host only; it never touches a target.
/// </summary>
public sealed class DoctorRunner
{
    // Canonical, ordered list. First entry (nmap) is required for recon.
    public static readonly IReadOnlyList<string> Tools = new[]
    {
        "nmap",
        "searchsploit",
        "python3",
        "python2",
        "go",
        "ruby",
        "git",
        "curl",
        "jq",
        "datasette",
    };

    // Tools that are strictly required for drederick's recon core.
    private static readonly HashSet<string> Required = new() { "nmap" };

    private readonly AuditLog _audit;
    private readonly IToolLocator _locator;
    private readonly IProcessRunner _runner;

    public DoctorRunner(AuditLog audit, IToolLocator? locator = null, IProcessRunner? runner = null)
    {
        _audit = audit;
        _locator = locator ?? new PathToolLocator();
        _runner = runner ?? new DefaultProcessRunner();
    }

    public IReadOnlyList<ToolInfo> Detect()
    {
        var now = DateTimeOffset.UtcNow;
        var results = new List<ToolInfo>(Tools.Count);
        foreach (var t in Tools)
        {
            var path = _locator.Which(t);
            string? version = null;
            if (path is not null)
            {
                version = TryGetVersion(path, t);
            }
            var info = new ToolInfo(t, Found: path is not null, Version: version, Path: path, DetectedAt: now);
            results.Add(info);
            _audit.Record("doctor.detect", new Dictionary<string, object?>
            {
                ["name"] = info.Name,
                ["found"] = info.Found,
                ["version"] = info.Version,
                ["path"] = info.Path,
            });
        }
        return results;
    }

    private string? TryGetVersion(string path, string name)
    {
        // Most tools respond to --version; a handful prefer -v / -V. Try the
        // common forms in order and take the first non-empty first-line output.
        string[] argForms = name switch
        {
            "searchsploit" => new[] { "-h" },
            _ => new[] { "--version" },
        };
        foreach (var arg in argForms)
        {
            try
            {
                var (exit, stdout, stderr) = _runner.Run(path, arg, timeoutSeconds: 5);
                var combined = (!string.IsNullOrWhiteSpace(stdout) ? stdout : stderr) ?? string.Empty;
                var firstLine = combined.Split('\n', 2)[0].Trim();
                if (!string.IsNullOrEmpty(firstLine)) return firstLine;
                if (exit == 0 && !string.IsNullOrWhiteSpace(combined)) return combined.Trim();
            }
            catch
            {
                // swallow — report as version=null
            }
        }
        return null;
    }

    /// <summary>
    /// Print a human-readable summary of detected tooling. Also writes to audit.
    /// </summary>
    public static void PrintReport(IReadOnlyList<ToolInfo> tools, PackageManager pm, TextWriter writer)
    {
        writer.WriteLine("drederick doctor: operator tooling report");
        writer.WriteLine($"  package manager: {PackageManagerDetection.DisplayName(pm)}");
        foreach (var t in tools)
        {
            var required = Required.Contains(t.Name) ? " (required)" : string.Empty;
            if (t.Found)
            {
                writer.WriteLine($"  [ok]     {t.Name,-14} {t.Version ?? "?"}  @ {t.Path}");
            }
            else
            {
                writer.WriteLine($"  [miss]   {t.Name,-14} not found on PATH{required}");
            }
        }
    }

    public sealed record InstallOutcome(string Tool, string Command, int ExitCode, bool Skipped);

    /// <summary>
    /// Install missing tools. Never re-execs as root. Prints every sudo command
    /// verbatim, asks for a single [y/N] confirmation covering all of them, and
    /// only runs them when confirmed (or when <paramref name="assumeYes"/>).
    /// </summary>
    public IReadOnlyList<InstallOutcome> Install(
        IReadOnlyList<ToolInfo> detected,
        PackageManager pm,
        bool assumeYes,
        TextReader input,
        TextWriter output)
    {
        var missing = detected.Where(t => !t.Found).ToList();
        if (missing.Count == 0)
        {
            output.WriteLine("doctor: nothing to install — everything is present.");
            return Array.Empty<InstallOutcome>();
        }

        if (pm == PackageManager.None)
        {
            output.WriteLine("doctor: no supported package manager found (apt-get/dnf/pacman/zypper/brew).");
            output.WriteLine("        run scripts/bootstrap.sh manually, or install the listed tools by hand.");
            foreach (var m in missing) output.WriteLine($"  missing: {m.Name}");
            return Array.Empty<InstallOutcome>();
        }

        var hasPipx = _locator.Which("pipx") is not null;
        var hasUv = _locator.Which("uv") is not null;

        var plan = new List<(ToolInfo Tool, InstallRecipe? Recipe)>();
        foreach (var t in missing)
        {
            plan.Add((t, InstallRecipes.Resolve(t.Name, pm, hasPipx, hasUv)));
        }

        output.WriteLine("doctor: will attempt to install the following:");
        var needsAnySudo = false;
        foreach (var (t, r) in plan)
        {
            if (r is null)
            {
                output.WriteLine($"  - {t.Name}: no recipe for {PackageManagerDetection.DisplayName(pm)} (skip)");
                continue;
            }
            var prefix = r.NeedsSudo ? "sudo " : string.Empty;
            output.WriteLine($"  - {t.Name}: {prefix}{r.Command}");
            if (r.NeedsSudo) needsAnySudo = true;
        }
        if (needsAnySudo)
        {
            output.WriteLine("doctor: some steps require sudo. Drederick will NOT re-exec as root.");
            output.WriteLine("        It will invoke the commands shown above via `sudo`, which may prompt you.");
        }

        if (!assumeYes)
        {
            output.Write("proceed? [y/N] ");
            output.Flush();
            var line = input.ReadLine();
            if (line is null || !line.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                output.WriteLine("doctor: cancelled, no changes made.");
                var skipped = new List<InstallOutcome>();
                foreach (var (t, r) in plan)
                {
                    if (r is null) continue;
                    skipped.Add(new InstallOutcome(t.Name, r.Command, ExitCode: -1, Skipped: true));
                }
                return skipped;
            }
        }

        var outcomes = new List<InstallOutcome>();
        foreach (var (t, r) in plan)
        {
            if (r is null) continue;
            var cmd = r.NeedsSudo ? $"sudo {r.Command}" : r.Command;
            output.WriteLine($"doctor: running: {cmd}");
            int exit;
            try
            {
                (exit, _, _) = _runner.RunShell(cmd, timeoutSeconds: 600);
            }
            catch (Exception ex)
            {
                output.WriteLine($"doctor: {t.Name} install failed to launch: {ex.Message}");
                exit = -1;
            }
            outcomes.Add(new InstallOutcome(t.Name, r.Command, exit, Skipped: false));
            _audit.Record("doctor.install", new Dictionary<string, object?>
            {
                ["name"] = t.Name,
                ["command"] = cmd,
                ["exit_code"] = exit,
            });
        }
        return outcomes;
    }
}
