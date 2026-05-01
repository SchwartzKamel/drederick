using Drederick.Audit;
using Drederick.Doctor;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// Coverage for the HTB/CTF tools added to <see cref="DoctorRunner"/> — per-tool
/// detect-arg selection, per-package-manager install recipe resolution, the
/// --no-install (detect-only) path, and the findings/audit row written when a
/// tool is missing.
/// </summary>
public class DoctorHtbToolsTests
{
    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "doctor-htb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class FakeLocator : IToolLocator
    {
        private readonly Dictionary<string, string> _map;
        public FakeLocator(Dictionary<string, string> map) => _map = map;
        public string? Which(string name) => _map.TryGetValue(name, out var p) ? p : null;
    }

    /// <summary>
    /// Build a locator that reports every new HTB tool (under its canonical
    /// Tools-list name) as living at a synthetic path. Used to assert detect
    /// argument selection.
    /// </summary>
    private static FakeLocator LocatorWithAllHtbTools()
    {
        var map = new Dictionary<string, string>
        {
            ["apt-get"] = "/usr/bin/apt-get",
            ["netexec"] = "/usr/bin/netexec",
            ["impacket-GetNPUsers"] = "/usr/bin/impacket-GetNPUsers",
            ["hashcat"] = "/usr/bin/hashcat",
            ["john"] = "/usr/bin/john",
            ["responder"] = "/usr/sbin/responder",
            ["gobuster"] = "/usr/bin/gobuster",
            ["ffuf"] = "/usr/bin/ffuf",
            ["sqlmap"] = "/usr/bin/sqlmap",
            ["nuclei"] = "/usr/bin/nuclei",
            ["kerbrute"] = "/root/go/bin/kerbrute",
            ["evil-winrm"] = "/usr/bin/evil-winrm",
            ["enum4linux-ng"] = "/usr/bin/enum4linux-ng",
            ["wfuzz"] = "/usr/bin/wfuzz",
        };
        return new FakeLocator(map);
    }

    [Fact]
    public void Tools_Includes_All_New_Htb_Entries()
    {
        foreach (var name in new[]
        {
            "netexec", "impacket", "hashcat", "john", "responder",
            "gobuster", "ffuf", "sqlmap", "nuclei", "kerbrute",
            "seclists", "evil-winrm", "enum4linux-ng", "wfuzz",
        })
        {
            Assert.Contains(name, DoctorRunner.Tools);
        }
        // Legacy tools preserved.
        foreach (var name in new[] { "nmap", "searchsploit", "python3", "datasette" })
        {
            Assert.Contains(name, DoctorRunner.Tools);
        }
    }

    [Fact]
    public void Detect_UsesPerToolVersionArg_ViaRecordingRunner()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = LocatorWithAllHtbTools();
        var runner = new RecordingProcessRunner()
            .OnRun((_, _) => true, exit: 0, stdout: "stub-version 1.0");

        var doc = new DoctorRunner(audit, locator, runner);
        _ = doc.Detect();

        // Map of (expected invoked path, expected detect argument).
        var expected = new (string path, string arg)[]
        {
            ("/usr/bin/netexec", "--version"),
            ("/usr/bin/impacket-GetNPUsers", "--help"),
            ("/usr/bin/hashcat", "--version"),
            ("/usr/bin/john", "--version"),
            ("/usr/sbin/responder", "-h"),
            ("/usr/bin/gobuster", "version"),
            ("/usr/bin/ffuf", "-V"),
            ("/usr/bin/sqlmap", "--version"),
            ("/usr/bin/nuclei", "-version"),
            ("/root/go/bin/kerbrute", "version"),
            ("/usr/bin/evil-winrm", "--version"),
            ("/usr/bin/enum4linux-ng", "--help"),
            ("/usr/bin/wfuzz", "--version"),
        };

        foreach (var (path, arg) in expected)
        {
            Assert.Contains(runner.Calls, c =>
                c.Kind == "run" && c.FileOrCmd == path && c.Arguments == arg);
        }
    }

    [Fact]
    public void Detect_Netexec_FallsBackToNxcAndCrackmapexecAliases()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));

        // Only nxc present — should still resolve `netexec`.
        var nxc = new FakeLocator(new Dictionary<string, string> { ["nxc"] = "/usr/bin/nxc" });
        var runner1 = new RecordingProcessRunner().OnRun((_, _) => true, 0, "nxc 1.0");
        var tools1 = new DoctorRunner(audit, nxc, runner1).Detect();
        var t1 = tools1.Single(t => t.Name == "netexec");
        Assert.True(t1.Found);
        Assert.Equal("/usr/bin/nxc", t1.Path);

        // Only legacy crackmapexec present.
        var cme = new FakeLocator(new Dictionary<string, string> { ["crackmapexec"] = "/usr/bin/crackmapexec" });
        var runner2 = new RecordingProcessRunner().OnRun((_, _) => true, 0, "cme 5.0");
        var tools2 = new DoctorRunner(audit, cme, runner2).Detect();
        var t2 = tools2.Single(t => t.Name == "netexec");
        Assert.True(t2.Found);
        Assert.Equal("/usr/bin/crackmapexec", t2.Path);
    }

    [Fact]
    public void Detect_Seclists_FindsDirectoryUnderHome()
    {
        var scratch = NewScratch();
        var origHome = Environment.GetEnvironmentVariable("HOME");
        try
        {
            Environment.SetEnvironmentVariable("HOME", scratch);
            var seclistsDir = Path.Combine(scratch, "seclists");
            Directory.CreateDirectory(seclistsDir);

            using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
            var locator = new FakeLocator(new Dictionary<string, string>());
            var runner = new RecordingProcessRunner();
            var doc = new DoctorRunner(audit, locator, runner);
            var tools = doc.Detect();

            var seclists = tools.Single(t => t.Name == "seclists");
            Assert.True(seclists.Found);
            Assert.Equal(seclistsDir, seclists.Path);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOME", origHome);
        }
    }

    [Fact]
    public void Detect_MissingTool_RecordsAuditRowWithFoundFalse()
    {
        var scratch = NewScratch();
        var auditPath = Path.Combine(scratch, "audit.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var locator = new FakeLocator(new Dictionary<string, string>());
            var runner = new RecordingProcessRunner();
            var doc = new DoctorRunner(audit, locator, runner);
            var tools = doc.Detect();

            // All tools missing; every new tool present in the list.
            var hashcat = tools.Single(t => t.Name == "hashcat");
            Assert.False(hashcat.Found);
            Assert.Null(hashcat.Path);
        }
        // Audit log is the tooling sink fallback — assert the missing-tool row.
        var lines = File.ReadAllLines(auditPath);
        Assert.Contains(lines, l =>
            l.Contains("\"event\":\"doctor.detect\"") &&
            l.Contains("\"name\":\"hashcat\"") &&
            l.Contains("\"found\":false"));
        Assert.Contains(lines, l =>
            l.Contains("\"event\":\"doctor.detect\"") &&
            l.Contains("\"name\":\"kerbrute\"") &&
            l.Contains("\"found\":false"));
    }

    // ---- Install recipe matrix ---------------------------------------------

    [Theory]
    [InlineData("hashcat", PackageManager.Apt, "apt-get install -y hashcat", true)]
    [InlineData("hashcat", PackageManager.Dnf, "dnf install -y hashcat", true)]
    [InlineData("hashcat", PackageManager.Pacman, "pacman -S --noconfirm hashcat", true)]
    [InlineData("hashcat", PackageManager.Zypper, "zypper install -y hashcat", true)]
    [InlineData("hashcat", PackageManager.Brew, "brew install hashcat", false)]
    [InlineData("john", PackageManager.Apt, "apt-get install -y john", true)]
    [InlineData("john", PackageManager.Brew, "brew install john", false)]
    [InlineData("responder", PackageManager.Apt, "apt-get install -y responder", true)]
    [InlineData("gobuster", PackageManager.Apt, "apt-get install -y gobuster", true)]
    [InlineData("gobuster", PackageManager.Brew, "brew install gobuster", false)]
    [InlineData("ffuf", PackageManager.Apt, "apt-get install -y ffuf", true)]
    [InlineData("sqlmap", PackageManager.Apt, "apt-get install -y sqlmap", true)]
    [InlineData("sqlmap", PackageManager.Dnf, "dnf install -y sqlmap", true)]
    [InlineData("nuclei", PackageManager.Apt, "apt-get install -y nuclei", true)]
    [InlineData("seclists", PackageManager.Apt, "apt-get install -y seclists", true)]
    [InlineData("evil-winrm", PackageManager.Apt, "apt-get install -y evil-winrm", true)]
    public void InstallRecipe_PrimaryPerPackageManager(string tool, PackageManager pm, string expectedContains, bool needsSudo)
    {
        var r = InstallRecipes.Resolve(tool, pm, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains(expectedContains, r!.Command);
        Assert.Equal(needsSudo, r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_PythonTools_PreferPipxWhenAvailable()
    {
        var cases = new (string Tool, string PyPkg)[]
        {
            ("netexec", "netexec"),
            ("impacket", "impacket"),
            ("enum4linux-ng", "enum4linux-ng"),
            ("wfuzz", "wfuzz"),
        };
        foreach (var (tool, pyPkg) in cases)
        {
            var r = InstallRecipes.Resolve(tool, PackageManager.Apt, hasPipx: true, hasUv: false);
            Assert.NotNull(r);
            Assert.Contains($"pipx install {pyPkg}", r!.Command);
            Assert.False(r.NeedsSudo);
        }
    }

    [Fact]
    public void InstallRecipe_PythonTools_BootstrapPipxWhenMissing()
    {
        // Without pipx and not on apt, resolver should emit a pipx-bootstrap
        // recipe via the current pm. Use dnf so we avoid the apt-specific
        // shortcuts (e.g. impacket→python3-impacket).
        var r = InstallRecipes.Resolve("netexec", PackageManager.Dnf, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains("dnf install -y pipx", r!.Command);
        Assert.Contains("pipx install netexec", r.Command);
        Assert.True(r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_Impacket_AptFallsBackToPython3Impacket_WithoutPipx()
    {
        var r = InstallRecipes.Resolve("impacket", PackageManager.Apt, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains("python3-impacket", r!.Command);
        Assert.True(r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_GoOnlyTools_UseGoInstall()
    {
        // kerbrute: no system packages anywhere.
        foreach (var pm in new[] { PackageManager.Apt, PackageManager.Dnf, PackageManager.Brew })
        {
            var r = InstallRecipes.Resolve("kerbrute", pm, hasPipx: false, hasUv: false);
            Assert.NotNull(r);
            Assert.Contains("go install github.com/ropnop/kerbrute", r!.Command);
            Assert.False(r.NeedsSudo);
        }
        // ffuf on non-apt/brew: go fallback.
        var ffuf = InstallRecipes.Resolve("ffuf", PackageManager.Dnf, false, false);
        Assert.NotNull(ffuf);
        Assert.Contains("go install github.com/ffuf/ffuf", ffuf!.Command);

        // gobuster on non-apt/brew: go fallback.
        var gb = InstallRecipes.Resolve("gobuster", PackageManager.Dnf, false, false);
        Assert.NotNull(gb);
        Assert.Contains("go install github.com/OJ/gobuster", gb!.Command);
    }

    [Fact]
    public void InstallRecipe_Nuclei_NonAptUsesGoInstall()
    {
        var r = InstallRecipes.Resolve("nuclei", PackageManager.Dnf, false, false);
        Assert.NotNull(r);
        Assert.Contains("go install github.com/projectdiscovery/nuclei", r!.Command);
        Assert.False(r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_EvilWinrm_NonAptUsesGemInstall()
    {
        var r = InstallRecipes.Resolve("evil-winrm", PackageManager.Dnf, false, false);
        Assert.NotNull(r);
        Assert.Contains("gem install evil-winrm", r!.Command);
        Assert.False(r.NeedsSudo);
    }

    [Fact]
    public void InstallRecipe_Seclists_NonAptClonesSecLists()
    {
        var r = InstallRecipes.Resolve("seclists", PackageManager.Dnf, false, false);
        Assert.NotNull(r);
        Assert.Contains("git clone", r!.Command);
        Assert.Contains("danielmiessler/SecLists", r!.Command);
        Assert.False(r.NeedsSudo);
    }

    // ---- No-install (detect-only) path -------------------------------------

    [Fact]
    public void Install_NoInstall_DetectOnlyPath_DoesNotShellOut()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        var runner = new RecordingProcessRunner();
        var doc = new DoctorRunner(audit, locator, runner);

        // Detect only: no Install call. Verify zero shell invocations.
        _ = doc.Detect();

        Assert.DoesNotContain(runner.Calls, c => c.Kind == "shell");
    }

    [Fact]
    public void Install_UserDeclinesPrompt_NoShellInvocationsForNewTools()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        var runner = new RecordingProcessRunner();
        var doc = new DoctorRunner(audit, locator, runner);

        var tools = doc.Detect();
        using var input = new StringReader("n\n");
        using var output = new StringWriter();
        var outcomes = doc.Install(tools, PackageManager.Apt, assumeYes: false, input, output);

        Assert.DoesNotContain(runner.Calls, c => c.Kind == "shell");
        Assert.Contains(outcomes, o => o.Tool == "hashcat" && o.Skipped);
        Assert.Contains(outcomes, o => o.Tool == "kerbrute" && o.Skipped);
    }

    [Fact]
    public void Install_WithAssumeYes_RunsAptPrimariesForNewTools()
    {
        var scratch = NewScratch();
        using var audit = new AuditLog(Path.Combine(scratch, "audit.jsonl"));
        var locator = new FakeLocator(new Dictionary<string, string> { ["apt-get"] = "/usr/bin/apt-get" });
        var runner = new RecordingProcessRunner().OnShell(_ => true, 0);
        var doc = new DoctorRunner(audit, locator, runner);

        var tools = doc.Detect();
        using var input = new StringReader("");
        using var output = new StringWriter();
        _ = doc.Install(tools, PackageManager.Apt, assumeYes: true, input, output);

        foreach (var pkg in new[]
        {
            "apt-get install -y hashcat",
            "apt-get install -y john",
            "apt-get install -y responder",
            "apt-get install -y gobuster",
            "apt-get install -y ffuf",
            "apt-get install -y sqlmap",
            "apt-get install -y nuclei",
            "apt-get install -y seclists",
            "apt-get install -y evil-winrm",
            "go install github.com/ropnop/kerbrute@latest",
        })
        {
            Assert.Contains(runner.Calls, c => c.Kind == "shell" && c.Arguments.Contains(pkg));
        }
    }
}
