using Drederick.Audit;

namespace Drederick.Doctor;

/// <summary>
/// Recipe describing one Empire installation strategy. The runner picks the
/// best-fit recipe per detected package manager; the operator always sees
/// the verbatim command before it runs and must explicitly consent.
/// </summary>
public sealed record EmpireInstallRecipe(
    string Strategy,
    string Command,
    bool NeedsSudo,
    string Rationale);

/// <summary>
/// Empire-specific installer. Modifies ONLY the operator workstation. Mirrors
/// <see cref="DoctorRunner.Install"/> for unattended-but-consented installs:
///
///   * apt → <c>apt install powershell-empire</c> (Kali / Debian / Ubuntu).
///   * brew/dnf/pacman/zypper → no first-party package; fall back to git clone.
///   * always: <c>git clone https://github.com/BC-SECURITY/Empire ~/Empire</c>
///     + <c>cd ~/Empire &amp;&amp; ./setup/install.sh</c>.
///
/// Hard rules:
///   1. Never re-exec as root, never silently sudo. <see cref="EmpireInstallRecipe.NeedsSudo"/>
///      results in a <c>sudo …</c> prefix being printed before execution,
///      but the operator still types their own sudo password.
///   2. Every install attempt records a <c>doctor.install</c> audit event
///      with command, exit code, and a 800-char stderr tail.
///   3. <see cref="InstallAsync"/> aborts cleanly if the operator answers
///      anything other than <c>y</c>.
/// </summary>
public sealed class EmpireInstaller
{
    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly IToolLocator _locator;
    private readonly IEnvReader _env;

    public EmpireInstaller(
        AuditLog audit,
        IProcessRunner runner,
        IToolLocator locator,
        IEnvReader? env = null)
    {
        _audit = audit;
        _runner = runner;
        _locator = locator;
        _env = env ?? new ProcessEnvReader();
    }

    /// <summary>
    /// Resolve the best install recipe for the given package manager.
    /// Apt gets <c>powershell-empire</c>; everything else falls back to a
    /// git clone + bootstrap script.
    /// </summary>
    public EmpireInstallRecipe Resolve(PackageManager pm, string? homeOverride = null)
    {
        var home = homeOverride
            ?? _env.Get("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cloneDir = Path.Combine(home ?? "/root", "Empire");

        var gitFallback = new EmpireInstallRecipe(
            Strategy: "git",
            Command: $"git clone https://github.com/BC-SECURITY/Empire {cloneDir} && cd {cloneDir} && ./setup/install.sh",
            NeedsSudo: false,
            Rationale: "Upstream BC-SECURITY repo; setup/install.sh handles pip deps + db init.");

        return pm switch
        {
            PackageManager.Apt => new EmpireInstallRecipe(
                Strategy: "apt",
                Command: "apt-get install -y powershell-empire",
                NeedsSudo: true,
                Rationale: "Kali / Debian / Ubuntu ship Empire as powershell-empire."),
            // No first-party package on dnf/pacman/zypper/brew at time of writing;
            // fall back to git clone.
            _ => gitFallback,
        };
    }

    /// <summary>
    /// Install Empire on the operator workstation. Prints the planned command,
    /// asks for [y/N] confirmation (skipped if <paramref name="assumeYes"/>),
    /// then executes via <see cref="IProcessRunner.RunShell"/>. Returns the
    /// exit code (-1 if cancelled or launch failed).
    /// </summary>
    public Task<int> InstallAsync(
        PackageManager pm,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct)
    {
        var recipe = Resolve(pm);
        var isRoot = IsRoot();
        var cmd = (recipe.NeedsSudo && !isRoot) ? $"sudo {recipe.Command}" : recipe.Command;

        stdout.WriteLine($"empire-installer: strategy={recipe.Strategy}");
        stdout.WriteLine($"empire-installer: command: {cmd}");
        stdout.WriteLine($"empire-installer: rationale: {recipe.Rationale}");
        if (recipe.NeedsSudo && !isRoot)
        {
            stdout.WriteLine("empire-installer: requires sudo. drederick will NOT re-exec as root;");
            stdout.WriteLine("                  sudo will prompt you for your password directly.");
        }

        if (!assumeYes)
        {
            stdout.Write("proceed? [y/N] ");
            stdout.Flush();
            var line = stdin.ReadLine();
            if (line is null || !line.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                stdout.WriteLine("empire-installer: cancelled, no changes made.");
                _audit.Record("doctor.install", new Dictionary<string, object?>
                {
                    ["name"] = "empire",
                    ["command"] = cmd,
                    ["exit_code"] = -1,
                    ["cancelled"] = true,
                });
                return Task.FromResult(-1);
            }
        }

        ct.ThrowIfCancellationRequested();
        int exit;
        string stderr = string.Empty;
        try
        {
            // git clone + ./setup/install.sh can be slow; give it 30 minutes.
            (exit, _, stderr) = _runner.RunShell(cmd, timeoutSeconds: 1800);
        }
        catch (Exception ex)
        {
            stdout.WriteLine($"empire-installer: failed to launch: {ex.Message}");
            exit = -1;
        }

        if (exit != 0)
        {
            var snippet = (stderr ?? string.Empty).Trim();
            if (snippet.Length > 800) snippet = snippet.Substring(0, 800) + "…[truncated]";
            if (!string.IsNullOrEmpty(snippet))
                stdout.WriteLine($"  stderr: {snippet}");
        }

        _audit.Record("doctor.install", new Dictionary<string, object?>
        {
            ["name"] = "empire",
            ["command"] = cmd,
            ["strategy"] = recipe.Strategy,
            ["exit_code"] = exit,
            ["stderr_tail"] = Truncate((stderr ?? string.Empty).Trim(), 800),
        });
        return Task.FromResult(exit);
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "…[truncated]";

    private static bool IsRoot()
    {
        try { if (Environment.IsPrivilegedProcess) return true; }
        catch { }
        return string.Equals(Environment.UserName, "root", StringComparison.Ordinal);
    }
}
