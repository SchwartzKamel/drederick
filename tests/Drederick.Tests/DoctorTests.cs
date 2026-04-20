using Drederick.Audit;
using Drederick.Doctor;
using Xunit;

namespace Drederick.Tests;

public class DoctorTests
{
    // Scratch dir lives under the repo's test output, never /tmp.
    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "doctor-scratch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class FakeLocator : IToolLocator
    {
        private readonly Dictionary<string, string> _map;
        public FakeLocator(Dictionary<string, string> map) => _map = map;
        public string? Which(string name) => _map.TryGetValue(name, out var p) ? p : null;
    }

    private sealed class FakeRunner : IProcessRunner
    {
        public List<string> ShellCommands { get; } = new();
        private readonly Func<string, (int, string, string)> _versionFn;
        public FakeRunner(Func<string, (int, string, string)>? versionFn = null)
        {
            _versionFn = versionFn ?? (_ => (0, "stub 1.2.3", ""));
        }
        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
            => _versionFn(file);
        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
        {
            ShellCommands.Add(commandLine);
            return (0, "", "");
        }
    }

    [Fact]
    public void Detect_FindsToolsOnMockedPath_RecordsVersion()
    {
        var scratch = NewScratch();
        // Make stub executables for a handful of tools.
        foreach (var t in new[] { "nmap", "python3", "git" })
        {
            var p = Path.Combine(scratch, t);
            File.WriteAllText(p, "#!/bin/sh\necho stub\n");
#pragma warning disable CA1416
            File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
#pragma warning restore CA1416
        }
        var locator = new PathToolLocator(new[] { scratch });
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var runner = new FakeRunner(file => (0, $"{Path.GetFileName(file)} v9.9", ""));

        var doc = new DoctorRunner(audit, locator, runner);
        var tools = doc.Detect();

        var nmap = tools.Single(t => t.Name == "nmap");
        Assert.True(nmap.Found);
        Assert.Equal(Path.Combine(scratch, "nmap"), nmap.Path);
        Assert.Contains("v9.9", nmap.Version);

        var missing = tools.Single(t => t.Name == "datasette");
        Assert.False(missing.Found);
        Assert.Null(missing.Version);
        Assert.Null(missing.Path);
    }

    [Fact]
    public void PackageManager_AptDetectedWhenPresent_NoneWhenEmpty()
    {
        var apt = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        Assert.Equal(PackageManager.Apt, PackageManagerDetection.Detect(apt));

        var empty = new FakeLocator(new Dictionary<string, string>());
        Assert.Equal(PackageManager.None, PackageManagerDetection.Detect(empty));

        var dnf = new FakeLocator(new Dictionary<string, string> { ["dnf"] = "/usr/bin/dnf" });
        Assert.Equal(PackageManager.Dnf, PackageManagerDetection.Detect(dnf));
    }

    [Fact]
    public void Install_WithoutConfirmation_DoesNotExecute()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        // apt-get is present (so a pm is selected) but nothing else is — every
        // other tool is missing and would otherwise be installed.
        var locator = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        var runner = new FakeRunner();
        var doc = new DoctorRunner(audit, locator, runner);

        var tools = doc.Detect();
        var pm = PackageManagerDetection.Detect(locator);
        Assert.Equal(PackageManager.Apt, pm);

        // Simulate the user typing "n" (or pressing Enter — empty counts as no).
        using var input = new StringReader("n\n");
        using var output = new StringWriter();
        var outcomes = doc.Install(tools, pm, assumeYes: false, input, output);

        Assert.Empty(runner.ShellCommands);
        Assert.All(outcomes, o => Assert.True(o.Skipped));
        Assert.Contains("cancelled", output.ToString());
    }

    [Fact]
    public void Install_WithAssumeYes_Executes()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        var runner = new FakeRunner();
        var doc = new DoctorRunner(audit, locator, runner);

        var tools = doc.Detect();
        var pm = PackageManagerDetection.Detect(locator);

        using var input = new StringReader("");
        using var output = new StringWriter();
        var outcomes = doc.Install(tools, pm, assumeYes: true, input, output);

        Assert.NotEmpty(runner.ShellCommands);
        Assert.Contains(runner.ShellCommands, c => c.Contains("apt-get install -y nmap"));
        Assert.Contains(runner.ShellCommands, c => c.Contains("exploitdb"));
        Assert.All(outcomes, o => Assert.False(o.Skipped));
    }

    [Fact]
    public void Install_NoPackageManager_DoesNothing()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = new FakeLocator(new Dictionary<string, string>());
        var runner = new FakeRunner();
        var doc = new DoctorRunner(audit, locator, runner);

        var tools = doc.Detect();
        var pm = PackageManagerDetection.Detect(locator);
        Assert.Equal(PackageManager.None, pm);

        using var input = new StringReader("y\n");
        using var output = new StringWriter();
        var outcomes = doc.Install(tools, pm, assumeYes: true, input, output);

        Assert.Empty(runner.ShellCommands);
        Assert.Empty(outcomes);
    }

    [Fact]
    public void InstallRecipe_Datasette_PrefersUvThenPipx()
    {
        var uv = InstallRecipes.Resolve("datasette", PackageManager.Apt, hasPipx: true, hasUv: true);
        Assert.NotNull(uv);
        Assert.Contains("uv tool install", uv!.Command);
        Assert.False(uv.NeedsSudo);

        var pipx = InstallRecipes.Resolve("datasette", PackageManager.Apt, hasPipx: true, hasUv: false);
        Assert.NotNull(pipx);
        Assert.Contains("pipx install datasette", pipx!.Command);
        Assert.False(pipx.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_Searchsploit_AptUsesExploitdbPackage()
    {
        var r = InstallRecipes.Resolve("searchsploit", PackageManager.Apt, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains("apt-get install -y exploitdb", r!.Command);
        Assert.True(r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_Searchsploit_NonAptClonesExploitDb()
    {
        var r = InstallRecipes.Resolve("searchsploit", PackageManager.Dnf, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains("git clone", r!.Command);
        Assert.Contains("exploitdb", r.Command);
    }
}
