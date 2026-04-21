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
    // HTB/CTF pentest tooling is appended after the originals so existing
    // reports and snapshots stay stable for the first ten entries.
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
        // HTB/CTF tools:
        "netexec",
        "impacket",
        "hashcat",
        "john",
        "responder",
        "gobuster",
        "ffuf",
        "sqlmap",
        "nuclei",
        "kerbrute",
        "seclists",
        "evil-winrm",
        "enum4linux-ng",
        "wfuzz",
    };

    // Tools that are strictly required for drederick's recon core.
    private static readonly HashSet<string> Required = new() { "nmap" };

    /// <summary>
    /// Per-tool detection metadata: alternate binary names to search under
    /// and version-probe argument(s) to try. Tools whose "installation" is
    /// a directory rather than a binary (e.g. <c>seclists</c>) are handled
    /// directly in <see cref="Detect"/>.
    /// </summary>
    public sealed record ToolSpec(
        string Name,
        string[] Aliases,
        string[] VersionArgs);

    public static readonly IReadOnlyDictionary<string, ToolSpec> Specs =
        new Dictionary<string, ToolSpec>
        {
            ["searchsploit"] = new("searchsploit", Array.Empty<string>(), new[] { "-h" }),
            ["netexec"] = new("netexec", new[] { "nxc", "crackmapexec" }, new[] { "--version" }),
            ["impacket"] = new("impacket", new[] { "impacket-GetNPUsers", "GetNPUsers.py" }, new[] { "--help" }),
            ["hashcat"] = new("hashcat", Array.Empty<string>(), new[] { "--version" }),
            ["john"] = new("john", Array.Empty<string>(), new[] { "--version" }),
            ["responder"] = new("responder", new[] { "Responder", "Responder.py" }, new[] { "-h" }),
            ["gobuster"] = new("gobuster", Array.Empty<string>(), new[] { "version" }),
            ["ffuf"] = new("ffuf", Array.Empty<string>(), new[] { "-V" }),
            ["sqlmap"] = new("sqlmap", Array.Empty<string>(), new[] { "--version" }),
            ["nuclei"] = new("nuclei", Array.Empty<string>(), new[] { "-version" }),
            ["kerbrute"] = new("kerbrute", Array.Empty<string>(), new[] { "version" }),
            ["evil-winrm"] = new("evil-winrm", Array.Empty<string>(), new[] { "--version", "-h" }),
            ["enum4linux-ng"] = new("enum4linux-ng", Array.Empty<string>(), new[] { "--help" }),
            ["wfuzz"] = new("wfuzz", Array.Empty<string>(), new[] { "--version" }),
        };

    /// <summary>
    /// Filesystem paths accepted as "seclists is installed". Evaluated at call
    /// time so tests can override <c>HOME</c>.
    /// </summary>
    public static IReadOnlyList<string> SeclistsCandidateDirs()
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            "/usr/share/seclists",
            "/usr/share/SecLists",
            System.IO.Path.Combine(home, "seclists"),
            System.IO.Path.Combine(home, "SecLists"),
        };
    }

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
            Specs.TryGetValue(t, out var spec);
            string? path = null;
            string? version = null;

            if (t == "seclists")
            {
                foreach (var dir in SeclistsCandidateDirs())
                {
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    {
                        path = dir;
                        break;
                    }
                }
            }
            else
            {
                // Try the canonical name, then any declared aliases (e.g.
                // netexec falls back to `nxc` / `crackmapexec`).
                path = _locator.Which(t);
                if (path is null && spec is not null)
                {
                    foreach (var alias in spec.Aliases)
                    {
                        path = _locator.Which(alias);
                        if (path is not null) break;
                    }
                }
                if (path is not null)
                {
                    version = TryGetVersion(path, t);
                }
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
        // Most tools respond to --version; some prefer -v / -V / -h / a
        // `version` subcommand. Per-tool overrides live in Specs; everything
        // else falls through to `--version`.
        string[] argForms = Specs.TryGetValue(name, out var spec) && spec.VersionArgs.Length > 0
            ? spec.VersionArgs
            : new[] { "--version" };
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

            // ANCHOR: datasette-bootstrap (doctor primes the same cache `serve` reads)
            if (t.Name == "datasette")
            {
                var home = Environment.GetEnvironmentVariable("HOME")
                    ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var cacheDir = System.IO.Path.Combine(home, ".drederick");
                var bootOpts = new Bundling.BootstrapOptions(
                    ExplicitPath: null,
                    AutoInstall: true,
                    AssumeYes: true, // doctor has already taken a single [y/N] above
                    CacheDir: cacheDir);
                int bootExit;
                try
                {
                    _ = Bundling.DatasetteBootstrap.EnsureAsync(
                        bootOpts, _audit, CancellationToken.None,
                        runner: _runner, locator: _locator,
                        stdin: input, stdout: output, stdinIsTty: false).GetAwaiter().GetResult();
                    bootExit = 0;
                    output.WriteLine("doctor: datasette install via bundling bootstrap succeeded.");
                }
                catch (Bundling.DatasetteBootstrapException ex)
                {
                    output.WriteLine($"doctor: datasette install failed: {ex.Message}");
                    bootExit = 1;
                }
                outcomes.Add(new InstallOutcome(t.Name, "drederick.bundling:" + r.Command, bootExit, Skipped: false));
                _audit.Record("doctor.install", new Dictionary<string, object?>
                {
                    ["name"] = t.Name,
                    ["command"] = "drederick.bundling.datasette",
                    ["exit_code"] = bootExit,
                });
                continue;
            }
            // END ANCHOR: datasette-bootstrap

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
