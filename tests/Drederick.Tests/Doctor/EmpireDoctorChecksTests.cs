using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Doctor;

public class EmpireDoctorChecksTests
{
    // --- helpers ---------------------------------------------------------

    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "empire-doctor-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static (AuditLog Audit, string Dir) NewAudit()
    {
        var dir = NewScratch();
        return (new AuditLog(Path.Combine(dir, "audit.jsonl")), dir);
    }

    private sealed class StubEnv : IEnvReader
    {
        public Dictionary<string, string?> Map { get; } = new();
        public string? Get(string name) => Map.TryGetValue(name, out var v) ? v : null;
    }

    private sealed class StubFs : IFileSystem
    {
        public HashSet<string> Files { get; } = new();
        public HashSet<string> Dirs { get; } = new();
        public Dictionary<string, string> Contents { get; } = new();
        public bool FileExists(string path) => Files.Contains(path);
        public bool DirectoryExists(string path) => Dirs.Contains(path);
        public string ReadAllText(string path) =>
            Contents.TryGetValue(path, out var v) ? v : throw new FileNotFoundException(path);
    }

    private sealed class StubTcp : ITcpProbe
    {
        public Dictionary<(string Host, int Port), bool> Occupied { get; } = new();
        public List<(string Host, int Port)> Calls { get; } = new();
        public bool IsOccupied(string host, int port, int timeoutMs)
        {
            Calls.Add((host, port));
            return Occupied.TryGetValue((host, port), out var v) && v;
        }
    }

    private sealed class StubLocator : IToolLocator
    {
        public Dictionary<string, string?> Map { get; } = new();
        public string? Which(string name) => Map.TryGetValue(name, out var v) ? v : null;
    }

    private static EmpireDoctorDeps Deps(
        RecordingProcessRunner runner,
        StubFs? fs = null,
        StubTcp? tcp = null,
        StubLocator? locator = null,
        StubEnv? env = null,
        Scope.Scope? scope = null,
        string? empireHost = null,
        string? installPath = null,
        int port = 1337)
    {
        var (audit, _) = NewAudit();
        return new EmpireDoctorDeps(
            Audit: audit,
            Runner: runner,
            Locator: locator ?? new StubLocator(),
            Fs: fs ?? new StubFs(),
            Tcp: tcp ?? new StubTcp(),
            Env: env ?? new StubEnv(),
            Scope: scope,
            Port: port,
            EmpireHost: empireHost,
            InstallPath: installPath);
    }

    private static Task<DoctorCheckResult> Run(IDoctorCheck c, bool install = false, bool yes = true)
        => c.RunAsync(install, yes, new StringReader(""), new StringWriter(), CancellationToken.None);

    // --- 1. python3.present: passes on >= 3.8 -----------------------------

    [Fact]
    public async Task Python3_PassesOn310()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a == "--version", exit: 0, stdout: "Python 3.10.12\n");
        var r = await Run(new EmpirePython3PresentCheck(Deps(runner)));
        Assert.Equal("empire.python3.present", r.Id);
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("3.10", r.Detail);
    }

    [Fact]
    public async Task Python3_FailsOn37()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a == "--version", exit: 0, stdout: "Python 3.7.16\n");
        var r = await Run(new EmpirePython3PresentCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("3.7", r.Detail);
    }

    [Fact]
    public async Task Python3_FailsCleanlyWhenMissing()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3", exit: 127, stderr: "command not found");
        var r = await Run(new EmpirePython3PresentCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("apt install python3", r.FixCommand ?? "");
    }

    // --- 2. empire.installed ---------------------------------------------

    [Fact]
    public async Task Installed_PassesWhenEmpirePyFound()
    {
        var fs = new StubFs();
        fs.Files.Add("/home/op/Empire/empire.py");
        var env = new StubEnv { Map = { ["HOME"] = "/home/op" } };
        var r = await Run(new EmpireInstalledCheck(Deps(new RecordingProcessRunner(), fs: fs, env: env)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("empire.py", r.Detail);
    }

    [Fact]
    public async Task Installed_PassesWhenPathBinaryFound()
    {
        var loc = new StubLocator { Map = { ["powershell-empire"] = "/usr/bin/powershell-empire" } };
        var env = new StubEnv { Map = { ["HOME"] = "/nope" } };
        var r = await Run(new EmpireInstalledCheck(Deps(new RecordingProcessRunner(), locator: loc, env: env)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("powershell-empire", r.Detail);
    }

    [Fact]
    public async Task Installed_FailsWithInstallHintWhenMissing()
    {
        var env = new StubEnv { Map = { ["HOME"] = "/nowhere" } };
        var r = await Run(new EmpireInstalledCheck(Deps(new RecordingProcessRunner(), env: env)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("powershell-empire", r.FixCommand ?? "");
        Assert.Contains("BC-SECURITY/Empire", r.FixCommand ?? "");
    }

    // --- 3. python deps importable ---------------------------------------

    [Fact]
    public async Task Deps_PassesWhenImportSucceeds()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a.Contains("import flask"), exit: 0);
        var r = await Run(new EmpireDepsPythonCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
    }

    [Fact]
    public async Task Deps_FailsWhenImportFails()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a.Contains("import flask"), exit: 1,
                stderr: "ModuleNotFoundError: No module named 'flask'");
        var r = await Run(new EmpireDepsPythonCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("pip install", r.FixCommand ?? "");
    }

    // --- 4. port availability --------------------------------------------

    [Fact]
    public async Task Port_PassesWhenFree()
    {
        var tcp = new StubTcp();
        // default: not occupied
        var r = await Run(new EmpirePortAvailableCheck(Deps(new RecordingProcessRunner(), tcp: tcp)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("1337", r.Detail);
        Assert.Contains(tcp.Calls, c => c.Port == 1337);
    }

    [Fact]
    public async Task Port_WarnsWhenOccupied()
    {
        var tcp = new StubTcp();
        tcp.Occupied[("127.0.0.1", 1337)] = true;
        var r = await Run(new EmpirePortAvailableCheck(Deps(new RecordingProcessRunner(), tcp: tcp)));
        Assert.Equal(DoctorCheckStatus.Warn, r.Status);
        Assert.Contains("1337", r.Detail);
        Assert.NotNull(r.FixCommand);
    }

    // --- 5. config: default password warning -----------------------------

    [Fact]
    public async Task Config_FailsOnDefaultPassword()
    {
        var fs = new StubFs();
        var cfg = "/home/op/Empire/empire/server/config.yaml";
        fs.Files.Add(cfg);
        fs.Contents[cfg] = "users:\n  - username: empireadmin\n    password: password123\n";
        var env = new StubEnv { Map = { ["HOME"] = "/home/op" } };
        var r = await Run(new EmpireConfigTokenSecretCheck(Deps(new RecordingProcessRunner(), fs: fs, env: env)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("default admin password", r.Detail);
    }

    [Fact]
    public async Task Config_PassesOnRotatedPassword()
    {
        var fs = new StubFs();
        var cfg = "/home/op/Empire/empire/server/config.yaml";
        fs.Files.Add(cfg);
        fs.Contents[cfg] = "users:\n  - username: empireadmin\n    password: r0t4t3d-l0ng-r4nd0m\n";
        var env = new StubEnv { Map = { ["HOME"] = "/home/op" } };
        var r = await Run(new EmpireConfigTokenSecretCheck(Deps(new RecordingProcessRunner(), fs: fs, env: env)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
    }

    [Fact]
    public async Task Config_WarnsWhenConfigMissing()
    {
        var env = new StubEnv { Map = { ["HOME"] = "/nowhere" } };
        var r = await Run(new EmpireConfigTokenSecretCheck(Deps(new RecordingProcessRunner(), env: env)));
        Assert.Equal(DoctorCheckStatus.Warn, r.Status);
    }

    // --- 6. network reachability: scope-validated ------------------------

    [Fact]
    public async Task Network_PassesWhenNoHostConfigured()
    {
        var r = await Run(new EmpireNetworkReachableCheck(Deps(new RecordingProcessRunner())));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("skipped", r.Detail);
    }

    [Fact]
    public async Task Network_FailsWhenHostNotInScope()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var tcp = new StubTcp();
        var r = await Run(new EmpireNetworkReachableCheck(
            Deps(new RecordingProcessRunner(), tcp: tcp, scope: scope, empireHost: "192.168.99.50")));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("scope", r.Detail.ToLowerInvariant());
        // TCP probe must NOT fire when scope rejects.
        Assert.Empty(tcp.Calls);
    }

    [Fact]
    public async Task Network_FailsWhenScopeMissing()
    {
        var tcp = new StubTcp();
        var r = await Run(new EmpireNetworkReachableCheck(
            Deps(new RecordingProcessRunner(), tcp: tcp, scope: null, empireHost: "10.10.10.5")));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Empty(tcp.Calls);
    }

    [Fact]
    public async Task Network_PassesWhenInScopeAndReachable()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var tcp = new StubTcp();
        tcp.Occupied[("10.10.10.5", 1337)] = true;
        var r = await Run(new EmpireNetworkReachableCheck(
            Deps(new RecordingProcessRunner(), tcp: tcp, scope: scope, empireHost: "10.10.10.5")));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
    }

    // --- 7. RunAllAsync: 6 checks, no short-circuit ----------------------

    [Fact]
    public async Task RunAllAsync_ReturnsAllSixChecks()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a == "--version", exit: 0, stdout: "Python 3.10.12\n")
            .OnRun((f, a) => f == "python3" && a.Contains("import flask"), exit: 0);
        var deps = Deps(runner);
        var results = await EmpireDoctorChecks.RunAllAsync(
            deps, install: false, assumeYes: true, new StringReader(""), new StringWriter(),
            CancellationToken.None);
        Assert.Equal(6, results.Count);
        Assert.Contains(results, r => r.Id == "empire.python3.present");
        Assert.Contains(results, r => r.Id == "empire.installed");
        Assert.Contains(results, r => r.Id == "empire.deps.python");
        Assert.Contains(results, r => r.Id == "empire.port.available");
        Assert.Contains(results, r => r.Id == "empire.config.token_secret");
        Assert.Contains(results, r => r.Id == "empire.network.reachable");
    }

    // --- 8. RunAllAsync: continues past a failure ------------------------

    [Fact]
    public async Task RunAllAsync_DoesNotShortCircuitOnFailure()
    {
        // python3 missing → first check fails. Subsequent checks must still run.
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3", exit: 127, stderr: "missing");
        var deps = Deps(runner);
        var results = await EmpireDoctorChecks.RunAllAsync(
            deps, install: false, assumeYes: true, new StringReader(""), new StringWriter(),
            CancellationToken.None);
        Assert.Equal(6, results.Count);
        Assert.Equal(DoctorCheckStatus.Fail, results[0].Status); // python3 fail
        // port check still runs and passes (default stub: not occupied)
        var port = results.First(r => r.Id == "empire.port.available");
        Assert.Equal(DoctorCheckStatus.Pass, port.Status);
    }

    // --- 9. Stub-fixture end-to-end happy path ---------------------------

    [Fact]
    public async Task StubFixture_AllPassWhenEnvIsHealthy()
    {
        var fs = new StubFs();
        fs.Files.Add("/opt/Empire/empire.py");
        var cfg = "/opt/Empire/empire/server/config.yaml";
        fs.Files.Add(cfg);
        fs.Contents[cfg] = "password: \"super-long-rotated-secret-2024\"\n";

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "python3" && a == "--version", exit: 0, stdout: "Python 3.10.12\n")
            .OnRun((f, a) => f == "python3" && a.Contains("import flask"), exit: 0);
        var env = new StubEnv();
        var deps = Deps(runner, fs: fs, env: env, installPath: "/opt/Empire");
        var results = await EmpireDoctorChecks.RunAllAsync(
            deps, install: false, assumeYes: true, new StringReader(""), new StringWriter(),
            CancellationToken.None);
        Assert.All(results, r => Assert.NotEqual(DoctorCheckStatus.Fail, r.Status));
    }
}
