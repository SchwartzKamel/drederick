using System.Net.Sockets;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Doctor;

/// <summary>
/// Abstraction for probing whether a local TCP port is currently bound by
/// some other process. Tests inject a deterministic stub; the default
/// implementation uses a non-blocking <see cref="TcpClient"/> connect with
/// a short timeout. This is workstation-only: it never reaches outside
/// the operator host.
/// </summary>
public interface ITcpProbe
{
    /// <summary>
    /// Returns true if a TCP connection to <paramref name="host"/>:<paramref name="port"/>
    /// can be established within <paramref name="timeoutMs"/>, i.e. the port is occupied.
    /// </summary>
    bool IsOccupied(string host, int port, int timeoutMs);
}

internal sealed class DefaultTcpProbe : ITcpProbe
{
    public bool IsOccupied(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// Filesystem abstraction so doctor can probe candidate Empire install
/// locations (e.g. <c>~/Empire/empire.py</c>) without tests touching the
/// real disk.
/// </summary>
public interface IFileSystem
{
    bool FileExists(string path);
    bool DirectoryExists(string path);
    string ReadAllText(string path);
}

internal sealed class DefaultFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public string ReadAllText(string path) => File.ReadAllText(path);
}

/// <summary>
/// Shared dependencies for every Empire doctor check. All fields are
/// constructor-init; nothing mutates after construction.
/// </summary>
public sealed record EmpireDoctorDeps(
    AuditLog Audit,
    IProcessRunner Runner,
    IToolLocator Locator,
    IFileSystem Fs,
    ITcpProbe Tcp,
    IEnvReader Env,
    Scope.Scope? Scope,
    string Python3Binary = "python3",
    int Port = 1337,
    string? EmpireHost = null,
    string? InstallPath = null,
    string MinPythonVersion = "3.8");

/// <summary>
/// Factory + runner for the <c>empire</c> doctor category. Each check is
/// an independent <see cref="IDoctorCheck"/>; failure of one never short-
/// circuits its siblings. All checks modify only the operator workstation.
/// </summary>
public static class EmpireDoctorChecks
{
    public const string CategoryName = "empire";

    public static IReadOnlyList<IDoctorCheck> All(EmpireDoctorDeps deps)
    {
        return new IDoctorCheck[]
        {
            new EmpirePython3PresentCheck(deps),
            new EmpireInstalledCheck(deps),
            new EmpireDepsPythonCheck(deps),
            new EmpirePortAvailableCheck(deps),
            new EmpireConfigTokenSecretCheck(deps),
            new EmpireNetworkReachableCheck(deps),
        };
    }

    public static async Task<IReadOnlyList<DoctorCheckResult>> RunAllAsync(
        EmpireDoctorDeps deps,
        bool install,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct)
    {
        var checks = All(deps);
        var results = new List<DoctorCheckResult>(checks.Count);

        stdout.WriteLine("drederick doctor: empire-category checks");
        stdout.WriteLine("----------------------------------------");

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
            PrintOne(stdout, r);
        }

        stdout.WriteLine("----------------------------------------");
        var pass = results.Count(r => r.Status == DoctorCheckStatus.Pass);
        var warn = results.Count(r => r.Status == DoctorCheckStatus.Warn);
        var fail = results.Count(r => r.Status == DoctorCheckStatus.Fail);
        stdout.WriteLine($"summary: {pass} pass  {warn} warn  {fail} fail");
        return results;
    }

    private static void PrintOne(TextWriter w, DoctorCheckResult r)
    {
        var glyph = r.Status switch
        {
            DoctorCheckStatus.Pass => "✓",
            DoctorCheckStatus.Warn => "⚠",
            _ => "✗",
        };
        w.WriteLine($"  {glyph} {r.Id,-34} {r.Detail}");
        if (r.Status != DoctorCheckStatus.Pass && !string.IsNullOrEmpty(r.FixCommand))
        {
            w.WriteLine($"       fix: {r.FixCommand}");
            if (!string.IsNullOrEmpty(r.FixRationale))
                w.WriteLine($"       why: {r.FixRationale}");
        }
    }

    // ---------------------------------------------------------------------
    // Common helpers
    // ---------------------------------------------------------------------

    internal static void RecordStart(AuditLog a, string id) =>
        a.Record($"doctor.empire.{id}.start", new Dictionary<string, object?> { ["id"] = id });

    internal static DoctorCheckResult Finish(
        AuditLog a,
        string id,
        DoctorCheckStatus status,
        string detail,
        string? fixCommand = null,
        string? fixRationale = null,
        bool fixApplied = false)
    {
        a.Record($"doctor.empire.{id}.finish", new Dictionary<string, object?>
        {
            ["id"] = id,
            ["status"] = status.ToString().ToLowerInvariant(),
            ["detail"] = detail,
            ["fix_applied"] = fixApplied,
        });
        return new DoctorCheckResult(id, status, detail, fixCommand, fixRationale, fixApplied);
    }

    /// <summary>
    /// Default install-path candidates, evaluated in order. Tests override
    /// <c>HOME</c> via the env reader; production reads from process env.
    /// </summary>
    internal static IEnumerable<string> InstallCandidates(EmpireDoctorDeps d)
    {
        if (!string.IsNullOrEmpty(d.InstallPath))
        {
            yield return d.InstallPath;
        }
        var home = d.Env.Get("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(home))
        {
            yield return Path.Combine(home, "Empire");
        }
        // apt-installed Kali default
        yield return "/usr/share/powershell-empire";
        yield return "/opt/Empire";
    }
}

// ---------------------------------------------------------------------------
// 1. python3 >= 3.8
// ---------------------------------------------------------------------------

internal sealed class EmpirePython3PresentCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpirePython3PresentCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.python3.present";
    public string Category => EmpireDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);
        try
        {
            var (exit, sout, serr) = _d.Runner.Run(_d.Python3Binary, "--version", 5);
            if (exit != 0)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    $"`{_d.Python3Binary} --version` exited {exit}",
                    fixCommand: "apt install python3   # (fallback: dnf install python3 | pacman -S python | brew install python)",
                    fixRationale: "Empire is implemented in Python 3 (>= 3.8). It cannot run without an interpreter."));
            }
            var combined = !string.IsNullOrWhiteSpace(sout) ? sout : serr;
            var firstLine = (combined ?? string.Empty).Split('\n', 2)[0].Trim();
            var m = Regex.Match(firstLine, @"Python\s+(\d+)\.(\d+)(?:\.(\d+))?");
            if (!m.Success)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Warn,
                    $"python3 present but version unparsable: '{firstLine}'"));
            }
            int major = int.Parse(m.Groups[1].Value);
            int minor = int.Parse(m.Groups[2].Value);
            var minParts = _d.MinPythonVersion.Split('.');
            int reqMajor = int.Parse(minParts[0]);
            int reqMinor = minParts.Length > 1 ? int.Parse(minParts[1]) : 0;
            if (major > reqMajor || (major == reqMajor && minor >= reqMinor))
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"python3 {major}.{minor} present (>= {_d.MinPythonVersion})"));
            }
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"python3 {major}.{minor} < required {_d.MinPythonVersion}",
                fixCommand: "apt install python3.10   # or use pyenv/asdf to install a newer interpreter",
                fixRationale: "Empire requires Python 3.8 or newer; older interpreters lack required asyncio features."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"could not invoke `{_d.Python3Binary} --version`: {ex.Message}",
                fixCommand: "apt install python3",
                fixRationale: "Empire requires a working python3 interpreter on PATH."));
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Empire installed
// ---------------------------------------------------------------------------

internal sealed class EmpireInstalledCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpireInstalledCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.installed";
    public string Category => EmpireDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);

        // 1. Filesystem candidates first — explicit InstallPath wins.
        foreach (var dir in EmpireDoctorChecks.InstallCandidates(_d))
        {
            var entry = Path.Combine(dir, "empire.py");
            if (_d.Fs.FileExists(entry))
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"Empire found at {entry}"));
            }
            if (_d.Fs.DirectoryExists(Path.Combine(dir, "empire")))
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"Empire install dir found at {dir}"));
            }
        }

        // 2. PATH-resolved CLI binaries: powershell-empire (Kali apt) or empire.
        foreach (var bin in new[] { "powershell-empire", "empire" })
        {
            var path = _d.Locator.Which(bin);
            if (path is not null)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"{bin} present at {path}"));
            }
        }

        return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            "Empire not found (checked ~/Empire, /usr/share/powershell-empire, /opt/Empire, PATH)",
            fixCommand: "apt install powershell-empire   # or: git clone https://github.com/BC-SECURITY/Empire ~/Empire && cd ~/Empire && ./setup/install.sh",
            fixRationale: "Empire is the BC-SECURITY post-exploitation framework; Kali ships it as powershell-empire."));
    }
}

// ---------------------------------------------------------------------------
// 3. python deps importable (flask, sqlalchemy, cryptography)
// ---------------------------------------------------------------------------

internal sealed class EmpireDepsPythonCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpireDepsPythonCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.deps.python";
    public string Category => EmpireDoctorChecks.CategoryName;

    // Conservative best-effort subset of Empire's pip deps that we can probe
    // with a one-liner `python3 -c "import …"`. The full requirements list
    // is much larger; these three cover the API, ORM, and crypto stacks.
    internal static readonly string[] Modules = { "flask", "sqlalchemy", "cryptography" };

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);
        var importExpr = string.Join(", ", Modules);
        try
        {
            var (exit, _, serr) = _d.Runner.Run(
                _d.Python3Binary,
                $"-c \"import {importExpr}\"",
                10);
            if (exit == 0)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"python deps importable: {importExpr}"));
            }
            var snippet = (serr ?? string.Empty).Replace('\n', ' ').Trim();
            if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "…";
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"python deps missing (exit {exit}): {snippet}",
                fixCommand: $"{_d.Python3Binary} -m pip install --user {string.Join(' ', Modules)}",
                fixRationale: "Empire's API/ORM/crypto stack is built on flask, sqlalchemy, and cryptography. Run Empire's setup/install.sh for the full pin set."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"could not invoke python deps probe: {ex.Message}",
                fixCommand: $"{_d.Python3Binary} -m pip install --user {string.Join(' ', Modules)}"));
        }
    }
}

// ---------------------------------------------------------------------------
// 4. port 1337 availability
// ---------------------------------------------------------------------------

internal sealed class EmpirePortAvailableCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpirePortAvailableCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.port.available";
    public string Category => EmpireDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);
        try
        {
            var occupied = _d.Tcp.IsOccupied("127.0.0.1", _d.Port, timeoutMs: 500);
            if (!occupied)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"port {_d.Port} free on 127.0.0.1"));
            }
            // Occupied: could be a running Empire (fine) or another process (warn).
            // We can't tell from a TCP probe alone — surface as warn with a fix hint.
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                $"port {_d.Port} is occupied on 127.0.0.1 — verify it's Empire and not another service",
                fixCommand: $"ss -ltnp | grep ':{_d.Port}'   # or: lsof -iTCP:{_d.Port} -sTCP:LISTEN",
                fixRationale: "If the listener is your own Empire instance this is harmless; otherwise pick a free port via Empire's server config."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                $"port probe failed: {ex.Message}"));
        }
    }
}

// ---------------------------------------------------------------------------
// 5. config has non-default admin password
// ---------------------------------------------------------------------------

internal sealed class EmpireConfigTokenSecretCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpireConfigTokenSecretCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.config.token_secret";
    public string Category => EmpireDoctorChecks.CategoryName;

    // Stock passwords shipped by upstream Empire releases. If the operator
    // hasn't rotated, the config is effectively unauthenticated against
    // anyone who has read the public repo.
    internal static readonly HashSet<string> DefaultPasswords = new(StringComparer.Ordinal)
    {
        "password123",
        "empireadmin",
        "Password123",
    };

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);
        string? configPath = null;
        foreach (var dir in EmpireDoctorChecks.InstallCandidates(_d))
        {
            var p = Path.Combine(dir, "empire", "server", "config.yaml");
            if (_d.Fs.FileExists(p)) { configPath = p; break; }
        }
        if (configPath is null)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — Empire config.yaml not found (install first, then re-run)"));
        }
        try
        {
            var text = _d.Fs.ReadAllText(configPath);
            // Crude YAML scan — avoids a YamlDotNet dependency. Matches
            // `password: "…"` or `password: …`. The exact key is
            // `empireuser` / `password` under `users:` in upstream Empire.
            var pwMatch = Regex.Match(text, @"^\s*password\s*:\s*[""']?([^""'\r\n#]+)[""']?",
                RegexOptions.Multiline);
            if (!pwMatch.Success)
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Warn,
                    $"config present at {configPath} but no `password:` key parsed"));
            }
            var pw = pwMatch.Groups[1].Value.Trim();
            if (DefaultPasswords.Contains(pw))
            {
                return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    $"config at {configPath} still has the default admin password",
                    fixCommand: $"edit {configPath} and rotate the `password:` value to a long random string",
                    fixRationale: "The stock Empire password is public; anyone who reaches the REST port can take over the server."));
            }
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"config has a non-default password ({configPath})"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                $"could not read {configPath}: {ex.Message}"));
        }
    }
}

// ---------------------------------------------------------------------------
// 6. network reachability of a configured remote Empire host (scope-gated)
// ---------------------------------------------------------------------------

internal sealed class EmpireNetworkReachableCheck : IDoctorCheck
{
    private readonly EmpireDoctorDeps _d;
    public EmpireNetworkReachableCheck(EmpireDoctorDeps d) => _d = d;
    public string Id => "empire.network.reachable";
    public string Category => EmpireDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        EmpireDoctorChecks.RecordStart(_d.Audit, Id);
        if (string.IsNullOrEmpty(_d.EmpireHost))
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                "skipped — no --empire-host configured (local-only deployment)"));
        }
        // Hard rule: any non-local probe must go through scope.Require. Doctor
        // never touches a host that isn't in the authorization allow-list.
        if (_d.Scope is null)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"--empire-host {_d.EmpireHost} configured but no scope file loaded",
                fixCommand: $"add {_d.EmpireHost} to your scope file, or unset --empire-host",
                fixRationale: "Doctor cannot probe a remote host without scope authorization — that's the authorization invariant."));
        }
        try
        {
            _d.Scope.Require(_d.EmpireHost);
        }
        catch (ScopeException sx)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"--empire-host {_d.EmpireHost} not in scope: {sx.Message}",
                fixCommand: $"drederick scope add {_d.EmpireHost}   # if you have authorization",
                fixRationale: "Scope is the authorization gate; doctor refuses to reach a host outside it."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"scope check threw {ex.GetType().Name}: {ex.Message}"));
        }
        var occupied = _d.Tcp.IsOccupied(_d.EmpireHost, _d.Port, timeoutMs: 2000);
        if (occupied)
        {
            return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"{_d.EmpireHost}:{_d.Port} reachable"));
        }
        return Task.FromResult(EmpireDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"{_d.EmpireHost}:{_d.Port} did not accept a TCP connection within 2s",
            fixCommand: $"verify the Empire server is running and listening on {_d.Port}",
            fixRationale: "If the listener uses a non-default port, override via --empire-port."));
    }
}
