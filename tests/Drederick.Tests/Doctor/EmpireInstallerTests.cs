using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Doctor;
using Xunit;

namespace Drederick.Tests.Doctor;

public class EmpireInstallerTests
{
    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "empire-installer-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static (AuditLog, string) NewAudit()
    {
        var dir = NewScratch();
        var path = Path.Combine(dir, "audit.jsonl");
        return (new AuditLog(path), path);
    }

    private sealed class StubEnv : IEnvReader
    {
        public System.Collections.Generic.Dictionary<string, string?> Map { get; } = new();
        public string? Get(string name) => Map.TryGetValue(name, out var v) ? v : null;
    }

    private sealed class EmptyLocator : IToolLocator
    {
        public string? Which(string name) => null;
    }

    [Fact]
    public void Resolve_AptPicksPowershellEmpire()
    {
        var (audit, _) = NewAudit();
        var inst = new EmpireInstaller(audit, new RecordingProcessRunner(), new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/op" } });
        var r = inst.Resolve(PackageManager.Apt);
        Assert.Equal("apt", r.Strategy);
        Assert.Contains("powershell-empire", r.Command);
        Assert.True(r.NeedsSudo);
    }

    [Theory]
    [InlineData(PackageManager.Dnf)]
    [InlineData(PackageManager.Pacman)]
    [InlineData(PackageManager.Zypper)]
    [InlineData(PackageManager.Brew)]
    [InlineData(PackageManager.None)]
    public void Resolve_FallsBackToGitCloneWhenNoApt(PackageManager pm)
    {
        var (audit, _) = NewAudit();
        var inst = new EmpireInstaller(audit, new RecordingProcessRunner(), new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/op" } });
        var r = inst.Resolve(pm);
        Assert.Equal("git", r.Strategy);
        Assert.Contains("git clone", r.Command);
        Assert.Contains("BC-SECURITY/Empire", r.Command);
        Assert.Contains("/home/op/Empire", r.Command);
        Assert.False(r.NeedsSudo);
    }

    [Fact]
    public async Task InstallAsync_AbortsWhenOperatorDeclines()
    {
        var (audit, path) = NewAudit();
        var runner = new RecordingProcessRunner();
        var inst = new EmpireInstaller(audit, runner, new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/op" } });
        var stdin = new StringReader("n\n");
        var stdout = new StringWriter();
        var exit = await inst.InstallAsync(PackageManager.Apt, assumeYes: false, stdin, stdout, CancellationToken.None);
        Assert.Equal(-1, exit);
        Assert.DoesNotContain(runner.Calls, c => c.Kind == "shell");
        Assert.Contains("cancelled", stdout.ToString());
        audit.Dispose();
        var auditText = File.ReadAllText(path);
        Assert.Contains("\"cancelled\":true", auditText);
    }

    [Fact]
    public async Task InstallAsync_RunsShellOnConsent()
    {
        var (audit, path) = NewAudit();
        var runner = new RecordingProcessRunner()
            .OnShell(c => c.Contains("powershell-empire"), exit: 0, stdout: "ok");
        var inst = new EmpireInstaller(audit, runner, new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/op" } });
        var stdout = new StringWriter();
        var exit = await inst.InstallAsync(PackageManager.Apt, assumeYes: true,
            new StringReader(""), stdout, CancellationToken.None);
        Assert.Equal(0, exit);
        Assert.Contains(runner.Calls, c => c.Kind == "shell" && c.Arguments.Contains("powershell-empire"));
        audit.Dispose();
        var auditText = File.ReadAllText(path);
        Assert.Contains("doctor.install", auditText);
        Assert.Contains("\"exit_code\":0", auditText);
    }

    [Fact]
    public async Task InstallAsync_GitFallbackUsesCorrectHomeDir()
    {
        var (audit, _) = NewAudit();
        var runner = new RecordingProcessRunner()
            .OnShell(c => c.Contains("git clone"), exit: 0, stdout: "cloned");
        var inst = new EmpireInstaller(audit, runner, new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/operator" } });
        var stdout = new StringWriter();
        var exit = await inst.InstallAsync(PackageManager.Brew, assumeYes: true,
            new StringReader(""), stdout, CancellationToken.None);
        Assert.Equal(0, exit);
        var shellCall = runner.Calls.First(c => c.Kind == "shell");
        Assert.Contains("/home/operator/Empire", shellCall.Arguments);
        Assert.Contains("setup/install.sh", shellCall.Arguments);
    }

    [Fact]
    public async Task InstallAsync_NonZeroExitPropagated()
    {
        var (audit, path) = NewAudit();
        var runner = new RecordingProcessRunner()
            .OnShell(c => true, exit: 100, stderr: "E: Unable to locate package powershell-empire");
        var inst = new EmpireInstaller(audit, runner, new EmptyLocator(),
            new StubEnv { Map = { ["HOME"] = "/home/op" } });
        var stdout = new StringWriter();
        var exit = await inst.InstallAsync(PackageManager.Apt, assumeYes: true,
            new StringReader(""), stdout, CancellationToken.None);
        Assert.Equal(100, exit);
        Assert.Contains("Unable to locate package", stdout.ToString());
        audit.Dispose();
        var auditText = File.ReadAllText(path);
        Assert.Contains("\"exit_code\":100", auditText);
        Assert.Contains("Unable to locate", auditText);
    }
}
