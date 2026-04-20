using System.Runtime.InteropServices;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Bundling;

/// <summary>
/// Resolves (and, if necessary, installs) a usable <c>datasette</c> executable
/// for <c>drederick serve</c>. Resolution order:
/// <list type="number">
///   <item>Explicit <c>--datasette-path</c> supplied by the operator.</item>
///   <item>A <c>datasette</c> on <c>PATH</c>.</item>
///   <item>A previously managed install under
///         <c>&lt;cache&gt;/venv/datasette/bin/datasette</c> (or the cached
///         pointer file <c>&lt;cache&gt;/bin/datasette.path</c>).</item>
///   <item>Auto-install via <c>uv tool</c>, <c>pipx</c>, or
///         <c>python3 -m venv</c> — in that preference order — unless the
///         caller has opted out of auto-install.</item>
/// </list>
/// Every subprocess invocation is recorded through <see cref="AuditLog"/>.
/// </summary>
public static class DatasetteBootstrap
{
    public const string AuditEventResolved = "bundling.datasette.resolved";
    public const string AuditEventInstall = "bundling.datasette.install";
    public const string AuditEventError = "bundling.datasette.error";

    /// <summary>
    /// Resolve a usable datasette binary, installing it under the cache dir
    /// if necessary and permitted. Returns the absolute path to the binary.
    /// Throws <see cref="DatasetteBootstrapException"/> on unrecoverable
    /// failure (missing python3, user-declined consent, install failure).
    /// </summary>
    public static async Task<string> EnsureAsync(
        BootstrapOptions opts,
        AuditLog audit,
        CancellationToken ct,
        IProcessRunner? runner = null,
        IToolLocator? locator = null,
        TextReader? stdin = null,
        TextWriter? stdout = null,
        bool? stdinIsTty = null)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(audit);
        runner ??= new DefaultProcessRunner();
        locator ??= new PathToolLocator();
        stdin ??= Console.In;
        stdout ??= Console.Out;
        // If caller didn't tell us, trust the runtime: a redirected stdin
        // means we're headless (CI, systemd, sub-shell) and must auto-yes.
        var tty = stdinIsTty ?? !Console.IsInputRedirected;

        ct.ThrowIfCancellationRequested();

        // (1) explicit path wins, but we validate it's a real file.
        if (!string.IsNullOrWhiteSpace(opts.ExplicitPath))
        {
            if (!File.Exists(opts.ExplicitPath))
            {
                var msg = $"--datasette-path '{opts.ExplicitPath}' does not exist.";
                audit.Record(AuditEventError, new Dictionary<string, object?>
                {
                    ["reason"] = "explicit-path-missing",
                    ["path"] = opts.ExplicitPath,
                });
                throw new DatasetteBootstrapException(msg);
            }
            audit.Record(AuditEventResolved, new Dictionary<string, object?>
            {
                ["source"] = "explicit",
                ["path"] = opts.ExplicitPath,
            });
            return opts.ExplicitPath!;
        }

        // (2) PATH.
        var onPath = locator.Which("datasette");
        if (onPath is not null)
        {
            audit.Record(AuditEventResolved, new Dictionary<string, object?>
            {
                ["source"] = "path",
                ["path"] = onPath,
            });
            return onPath;
        }

        // (3) managed install — check the venv layout, then the cached
        // pointer file (which lets uv/pipx installs persist their path).
        var managed = ResolveManaged(opts.CacheDir);
        if (managed is not null)
        {
            audit.Record(AuditEventResolved, new Dictionary<string, object?>
            {
                ["source"] = "cached",
                ["path"] = managed,
            });
            return managed;
        }

        // (4) auto-install.
        if (!opts.AutoInstall)
        {
            const string msg =
                "datasette is not installed and --no-auto-install was set. " +
                "Install it (e.g. `pipx install datasette`, `uv tool install datasette`, " +
                "or re-run `drederick serve` without --no-auto-install).";
            audit.Record(AuditEventError, new Dictionary<string, object?>
            {
                ["reason"] = "auto-install-disabled",
            });
            throw new DatasetteBootstrapException(msg);
        }

        // Require python3 >= 3.9.
        EnsurePython3(runner, audit);

        // Decide which manager to use.
        var useUv = locator.Which("uv") is not null;
        var usePipx = !useUv && locator.Which("pipx") is not null;
        var method = useUv ? "uv" : usePipx ? "pipx" : "venv";

        stdout.WriteLine("drederick: datasette is not installed.");
        stdout.WriteLine($"drederick: will install it via {method}.");
        switch (method)
        {
            case "uv":
                stdout.WriteLine("  command: uv tool install datasette");
                break;
            case "pipx":
                stdout.WriteLine("  command: pipx install datasette");
                break;
            default:
                var venvDir = ManagedVenvDir(opts.CacheDir);
                stdout.WriteLine($"  command: python3 -m venv {venvDir}");
                stdout.WriteLine($"           {venvDir}/bin/pip install --upgrade pip datasette");
                break;
        }

        if (!opts.AssumeYes && tty)
        {
            stdout.Write("proceed? [y/N] ");
            stdout.Flush();
            var line = stdin.ReadLine();
            if (line is null || !line.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                audit.Record(AuditEventError, new Dictionary<string, object?>
                {
                    ["reason"] = "consent-declined",
                });
                throw new DatasetteBootstrapException("datasette install cancelled by operator.");
            }
        }

        audit.Record(AuditEventInstall, new Dictionary<string, object?>
        {
            ["method"] = method,
        });

        string resolved = method switch
        {
            "uv" => InstallViaUv(opts.CacheDir, runner, locator, audit),
            "pipx" => InstallViaPipx(opts.CacheDir, runner, locator, audit),
            _ => InstallViaVenv(opts.CacheDir, runner, audit),
        };

        CacheResolvedPath(opts.CacheDir, resolved);
        audit.Record(AuditEventResolved, new Dictionary<string, object?>
        {
            ["source"] = "installed",
            ["method"] = method,
            ["path"] = resolved,
        });
        await Task.CompletedTask;
        return resolved;
    }

    // ------------------------------------------------------------------ paths

    public static string ManagedVenvDir(string cacheDir)
        => Path.Combine(cacheDir, "venv", "datasette");

    public static string ManagedVenvBinary(string cacheDir)
    {
        var venv = ManagedVenvDir(cacheDir);
        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(venv, "Scripts", "datasette.exe")
            : Path.Combine(venv, "bin", "datasette");
    }

    public static string CachedPointerPath(string cacheDir)
        => Path.Combine(cacheDir, "bin", "datasette.path");

    private static string? ResolveManaged(string cacheDir)
    {
        var venvBin = ManagedVenvBinary(cacheDir);
        if (File.Exists(venvBin)) return venvBin;

        var pointer = CachedPointerPath(cacheDir);
        if (File.Exists(pointer))
        {
            var cached = File.ReadAllText(pointer).Trim();
            if (!string.IsNullOrEmpty(cached) && File.Exists(cached)) return cached;
        }
        return null;
    }

    private static void CacheResolvedPath(string cacheDir, string resolved)
    {
        var pointer = CachedPointerPath(cacheDir);
        var dir = Path.GetDirectoryName(pointer);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(pointer, resolved + Environment.NewLine);
    }

    // ---------------------------------------------------------------- python3

    private static void EnsurePython3(IProcessRunner runner, AuditLog audit)
    {
        int exit;
        string stdout, stderr;
        try
        {
            (exit, stdout, stderr) = runner.Run("python3", "--version", timeoutSeconds: 10);
        }
        catch (Exception ex)
        {
            audit.Record(AuditEventError, new Dictionary<string, object?>
            {
                ["reason"] = "python3-missing",
                ["detail"] = ex.Message,
            });
            throw new DatasetteBootstrapException(
                "python3 is required to install datasette but could not be launched. " +
                "Install it (e.g. `drederick doctor --install`) and retry.");
        }
        var combined = string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;
        if (exit != 0 || string.IsNullOrWhiteSpace(combined))
        {
            audit.Record(AuditEventError, new Dictionary<string, object?>
            {
                ["reason"] = "python3-probe-failed",
                ["exit"] = exit,
            });
            throw new DatasetteBootstrapException(
                "python3 --version failed. Install python3 >= 3.9 and retry.");
        }

        // "Python 3.11.2" -> 3, 11
        var token = combined.Trim().Split(' ').LastOrDefault() ?? string.Empty;
        var parts = token.Split('.');
        if (parts.Length < 2
            || !int.TryParse(parts[0], System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var major)
            || !int.TryParse(parts[1], System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var minor)
            || major < 3 || (major == 3 && minor < 9))
        {
            audit.Record(AuditEventError, new Dictionary<string, object?>
            {
                ["reason"] = "python3-too-old",
                ["version"] = combined.Trim(),
            });
            throw new DatasetteBootstrapException(
                $"python3 >= 3.9 required to install datasette (found {combined.Trim()}).");
        }
    }

    // ----------------------------------------------------------------- uv

    private static string InstallViaUv(
        string cacheDir, IProcessRunner runner, IToolLocator locator, AuditLog audit)
    {
        var (exit, stdout, stderr) = runner.Run("uv", "tool install datasette", timeoutSeconds: 600);
        audit.Record(AuditEventInstall, new Dictionary<string, object?>
        {
            ["method"] = "uv",
            ["command"] = "uv tool install datasette",
            ["exit"] = exit,
        });
        if (exit != 0)
        {
            throw new DatasetteBootstrapException(
                $"uv tool install datasette failed (exit {exit}): {Trim(stderr, stdout)}");
        }
        // uv prints the bin dir; fall back to locator / known locations.
        var resolved = locator.Which("datasette")
            ?? TryUvToolBin(runner)
            ?? TryHomeLocal("datasette");
        if (resolved is null || !File.Exists(resolved))
        {
            throw new DatasetteBootstrapException(
                "uv tool install datasette succeeded but the datasette binary " +
                "could not be located. Ensure `~/.local/bin` (or `uv tool dir --bin`) is on PATH.");
        }
        return resolved;
    }

    private static string? TryUvToolBin(IProcessRunner runner)
    {
        try
        {
            var (exit, stdout, _) = runner.Run("uv", "tool dir --bin", timeoutSeconds: 10);
            if (exit == 0)
            {
                var dir = stdout.Trim().Split('\n').FirstOrDefault()?.Trim();
                if (!string.IsNullOrEmpty(dir))
                {
                    var exe = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? Path.Combine(dir, "datasette.exe")
                        : Path.Combine(dir, "datasette");
                    if (File.Exists(exe)) return exe;
                }
            }
        }
        catch { /* ignore — best-effort discovery */ }
        return null;
    }

    // ---------------------------------------------------------------- pipx

    private static string InstallViaPipx(
        string cacheDir, IProcessRunner runner, IToolLocator locator, AuditLog audit)
    {
        var (exit, stdout, stderr) = runner.Run("pipx", "install datasette", timeoutSeconds: 600);
        audit.Record(AuditEventInstall, new Dictionary<string, object?>
        {
            ["method"] = "pipx",
            ["command"] = "pipx install datasette",
            ["exit"] = exit,
        });
        if (exit != 0)
        {
            throw new DatasetteBootstrapException(
                $"pipx install datasette failed (exit {exit}): {Trim(stderr, stdout)}");
        }
        var resolved = locator.Which("datasette") ?? TryHomeLocal("datasette");
        if (resolved is null || !File.Exists(resolved))
        {
            throw new DatasetteBootstrapException(
                "pipx install datasette succeeded but the datasette binary could not " +
                "be located. Run `pipx ensurepath` and retry.");
        }
        return resolved;
    }

    // ---------------------------------------------------------------- venv

    private static string InstallViaVenv(string cacheDir, IProcessRunner runner, AuditLog audit)
    {
        var venv = ManagedVenvDir(cacheDir);
        Directory.CreateDirectory(Path.GetDirectoryName(venv)!);

        var (exit, stdout, stderr) = runner.Run("python3", $"-m venv \"{venv}\"", timeoutSeconds: 120);
        audit.Record(AuditEventInstall, new Dictionary<string, object?>
        {
            ["method"] = "venv",
            ["step"] = "create",
            ["command"] = $"python3 -m venv {venv}",
            ["exit"] = exit,
        });
        if (exit != 0)
        {
            throw new DatasetteBootstrapException(
                $"python3 -m venv failed (exit {exit}): {Trim(stderr, stdout)}");
        }

        var pip = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(venv, "Scripts", "pip.exe")
            : Path.Combine(venv, "bin", "pip");

        (exit, stdout, stderr) = runner.Run(pip, "install --upgrade pip datasette", timeoutSeconds: 600);
        audit.Record(AuditEventInstall, new Dictionary<string, object?>
        {
            ["method"] = "venv",
            ["step"] = "pip-install",
            ["command"] = $"{pip} install --upgrade pip datasette",
            ["exit"] = exit,
        });
        if (exit != 0)
        {
            throw new DatasetteBootstrapException(
                $"{pip} install datasette failed (exit {exit}): {Trim(stderr, stdout)}");
        }

        var bin = ManagedVenvBinary(cacheDir);
        if (!File.Exists(bin))
        {
            throw new DatasetteBootstrapException(
                $"expected datasette binary at {bin} after venv install, but it is missing.");
        }
        return bin;
    }

    // --------------------------------------------------------------- helpers

    private static string? TryHomeLocal(string exe)
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home)) return null;
        var candidate = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(home, ".local", "bin", exe + ".exe")
            : Path.Combine(home, ".local", "bin", exe);
        return File.Exists(candidate) ? candidate : null;
    }

    private static string Trim(string primary, string fallback)
    {
        var s = string.IsNullOrWhiteSpace(primary) ? fallback : primary;
        s = (s ?? string.Empty).Trim();
        return s.Length > 400 ? s[..400] + "…" : s;
    }
}

public sealed class DatasetteBootstrapException : Exception
{
    public DatasetteBootstrapException(string message) : base(message) { }
}
