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
        "magika",
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
            ["magika"] = new("magika", Array.Empty<string>(), new[] { "--version" }),
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
        var isRoot = IsRoot();

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
            var prefix = (r.NeedsSudo && !isRoot) ? "sudo " : string.Empty;
            output.WriteLine($"  - {t.Name}: {prefix}{r.Command}");
            if (r.NeedsSudo) needsAnySudo = true;
        }
        if (needsAnySudo && !isRoot)
        {
            output.WriteLine("doctor: some steps require sudo. Drederick will NOT re-exec as root.");
            output.WriteLine("        It will invoke the commands shown above via `sudo`, which may prompt you.");
            output.WriteLine("        If sudo prompts are getting swallowed, rerun as root: `sudo drederick doctor --install`");
        }
        if (isRoot)
        {
            output.WriteLine("doctor: running as root — sudo prefixes will be stripped.");
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

            var (exit, _) = RunInstallStep(r.Command, r.NeedsSudo, isRoot, t.Name, output);

            if (exit != 0 && !string.IsNullOrEmpty(r.FallbackCommand))
            {
                output.WriteLine($"doctor: {t.Name} primary install failed (exit={exit}); trying fallback.");
                if (!string.IsNullOrEmpty(r.FallbackRationale))
                {
                    output.WriteLine($"  rationale: {r.FallbackRationale}");
                }
                var (fbExit, _) = RunInstallStep(r.FallbackCommand!, r.FallbackNeedsSudo, isRoot, t.Name, output);
                if (fbExit == 0)
                {
                    exit = 0;
                }
            }

            outcomes.Add(new InstallOutcome(t.Name, r.Command, exit, Skipped: false));
        }
        return outcomes;
    }

    /// <summary>
    /// Run one install command, log a doctor.install audit event, print stderr on
    /// failure, and return the exit code and the shell-escaped command actually
    /// invoked (after sudo/GOBIN massaging). Never throws — exceptions produce
    /// exit code -1 and are logged.
    /// </summary>
    private (int Exit, string Command) RunInstallStep(string command, bool needsSudo, bool isRoot, string toolName, TextWriter output)
    {
        // Re-point `go install …` at a PATH-visible dir so the freshly built
        // binary is actually runnable, instead of landing in ~/go/bin (not on
        // PATH on most Kali/Parrot boxes).
        var cmd = RewriteGoInstall(command, isRoot);
        // Strip the sudo prefix when we're already root — sudo still works,
        // but stripping avoids spurious prompts and keeps audit entries clean.
        if (needsSudo && !isRoot)
        {
            cmd = $"sudo {cmd}";
        }
        output.WriteLine($"doctor: running: {cmd}");
        int exit;
        string stderr = string.Empty;
        string stdout = string.Empty;
        try
        {
            (exit, stdout, stderr) = _runner.RunShell(cmd, timeoutSeconds: 600);
        }
        catch (Exception ex)
        {
            output.WriteLine($"doctor: {toolName} install failed to launch: {ex.Message}");
            exit = -1;
        }
        if (exit != 0)
        {
            var trimmedErr = (stderr ?? string.Empty).Trim();
            var trimmedOut = (stdout ?? string.Empty).Trim();
            if (trimmedErr.Length > 0)
            {
                output.WriteLine($"  stderr: {Truncate(trimmedErr, 1200)}");
            }
            if (trimmedErr.Length == 0 && trimmedOut.Length > 0)
            {
                output.WriteLine($"  stdout: {Truncate(trimmedOut, 1200)}");
            }
        }
        _audit.Record("doctor.install", new Dictionary<string, object?>
        {
            ["name"] = toolName,
            ["command"] = cmd,
            ["exit_code"] = exit,
            ["stderr_tail"] = Truncate((stderr ?? string.Empty).Trim(), 800),
        });
        return (exit, cmd);
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "…[truncated]";

    /// <summary>
    /// If this is a `go install …` command, prefix it with
    /// <c>GOBIN=&lt;destdir&gt;</c> so the built binary lands on PATH.
    /// Destination is <c>/usr/local/bin</c> when running as root, otherwise
    /// <c>$HOME/.local/bin</c> (created if missing).
    /// </summary>
    private static string RewriteGoInstall(string command, bool isRoot)
    {
        // Match `go install` anywhere a shell token can start — at the start of
        // the command or after `;`, `&&`, `||`, `|`, or whitespace. Fallback
        // commands wrap `go install` inside bootstrap shells, so a simple
        // "starts with" check would miss them.
        if (!System.Text.RegularExpressions.Regex.IsMatch(command, @"(^|[;&|\s])go\s+install\s"))
        {
            return command;
        }
        string gobin;
        if (isRoot)
        {
            gobin = "/usr/local/bin";
        }
        else
        {
            var home = Environment.GetEnvironmentVariable("HOME")
                ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            gobin = System.IO.Path.Combine(home, ".local", "bin");
        }
        try { System.IO.Directory.CreateDirectory(gobin); } catch { /* best-effort */ }
        // Export GOBIN at the front of the shell so every inner `go install`
        // (including ones inside bootstrap scripts) inherits it. GOBIN
        // overrides GOPATH/bin for `go install` — supported go-tool contract.
        return $"export GOBIN={ShellQuote(gobin)}; {command}";
    }

    private static string ShellQuote(string s)
        => s.Contains('\'') ? "\"" + s.Replace("\"", "\\\"") + "\"" : $"'{s}'";

    private static bool IsRoot()
    {
        // On Linux/macOS, $UID=0 (euid 0) means root. .NET 8+ exposes this
        // directly via Environment.IsPrivilegedProcess; fall back to UserName
        // for older runtimes or edge cases where euid != ruid.
        try
        {
            if (Environment.IsPrivilegedProcess) return true;
        }
        catch { /* not available on all runtimes */ }
        return string.Equals(Environment.UserName, "root", StringComparison.Ordinal);
    }
}
