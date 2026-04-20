using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class SmbToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-smb-{Guid.NewGuid():N}.jsonl");

    private static string LoadFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        public List<(string File, string Arguments)> Calls { get; } = new();
        private readonly Dictionary<string, Queue<(int, string, string)>> _byBinary = new();

        public RecordingRunner Respond(string file, int exit, string stdout, string stderr = "")
        {
            if (!_byBinary.TryGetValue(file, out var q))
            {
                q = new Queue<(int, string, string)>();
                _byBinary[file] = q;
            }
            q.Enqueue((exit, stdout, stderr));
            return this;
        }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            if (_byBinary.TryGetValue(file, out var q) && q.Count > 0) return q.Dequeue();
            // Default: pretend the binary does not exist.
            return (-1, "", $"{file}: not found");
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => throw new NotSupportedException();
    }

    [Fact]
    public async Task ProbeAsync_Refuses_Out_Of_Scope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingRunner();
        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/bin/true", enum4linuxPath: "/bin/true");

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.0.2.1"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task ProbeAsync_Parses_Nmap_Fixture_Populates_Os_Protocols_Signing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var xml = LoadFixture("smb-scripts.xml");
        var runner = new RecordingRunner()
            .Respond("/bin/nmap", 0, xml);
        // enum4linux-ng not wired: will return exit=-1 from the fake -> skip silently.
        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/bin/nmap", enum4linuxPath: "/no/such/enum4linux-ng");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Null(result.Error);
        Assert.Equal("Windows Server 2019 Standard 17763", result.Os);
        Assert.Equal("dc01.corp.example.local", result.ComputerName);
        Assert.Equal("corp.example.local", result.Domain);
        Assert.Contains("3.1.1", result.Protocols);
        Assert.Contains("2.0.2", result.Protocols);
        Assert.Equal(6, result.Protocols.Count);
        Assert.True(result.SigningRequired);
        Assert.Empty(result.Shares);
        Assert.Empty(result.Users);
    }

    [Fact]
    public async Task ProbeAsync_Enum4Linux_Present_Populates_Shares_And_Users()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var xml = LoadFixture("smb-scripts.xml");
        var e4l =
            "enum4linux-ng v1.3.0\n" +
            " =========================( Target Information )=========================\n" +
            " Target: 10.10.10.5\n" +
            "\n" +
            " ============================( Shares on 10.10.10.5 )============================\n" +
            "[*] Enumerating shares\n" +
            "[+] Found shares:\n" +
            "  'IPC$'\n" +
            "  'ADMIN$'\n" +
            "  'NETLOGON'\n" +
            "  'SYSVOL'\n" +
            "\n" +
            " ============================( Users on 10.10.10.5 )============================\n" +
            "[+] Users via RID cycling:\n" +
            "  'Administrator' (rid: 500)\n" +
            "  'Guest' (rid: 501)\n" +
            "  'krbtgt' (rid: 502)\n" +
            "\n" +
            " ============================( Groups on 10.10.10.5 )============================\n" +
            "  'Domain Admins'\n"; // should NOT end up in users/shares (different section)

        var runner = new RecordingRunner()
            .Respond("/bin/nmap", 0, xml)
            .Respond("/bin/enum4linux-ng", 0, e4l);

        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/bin/nmap", enum4linuxPath: "/bin/enum4linux-ng");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Null(result.Error);
        Assert.Equal(new[] { "IPC$", "ADMIN$", "NETLOGON", "SYSVOL" }, result.Shares);
        Assert.Equal(new[] { "Administrator", "Guest", "krbtgt" }, result.Users);
        // nmap bits still populated:
        Assert.Equal("Windows Server 2019 Standard 17763", result.Os);
        Assert.True(result.SigningRequired);

        // Both binaries were invoked:
        Assert.Equal(2, runner.Calls.Count);
        Assert.Equal("/bin/nmap", runner.Calls[0].File);
        Assert.Equal("/bin/enum4linux-ng", runner.Calls[1].File);
    }

    [Fact]
    public async Task ProbeAsync_Enum4Linux_Absent_Does_Not_Crash_And_Nmap_Still_Populated()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var xml = LoadFixture("smb-scripts.xml");
        var runner = new RecordingRunner()
            .Respond("/bin/nmap", 0, xml)
            .Respond("/no/such/enum4linux-ng", -1, "", "enum4linux-ng: not found");

        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/bin/nmap", enum4linuxPath: "/no/such/enum4linux-ng");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Null(result.Error);
        Assert.Equal("Windows Server 2019 Standard 17763", result.Os);
        Assert.True(result.SigningRequired);
        Assert.NotEmpty(result.Protocols);
        Assert.Empty(result.Shares);
        Assert.Empty(result.Users);
    }

    [Fact]
    public async Task ProbeAsync_Nmap_Missing_Sets_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingRunner()
            .Respond("/no/such/nmap", -1, "", "nmap: not found");

        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/no/such/nmap", enum4linuxPath: "/no/such/enum4linux-ng");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Contains("nmap", result.Error);
        Assert.Null(result.Os);
        Assert.Empty(result.Protocols);
        Assert.Null(result.SigningRequired);
    }

    [Fact]
    public async Task ProbeAsync_Nmap_Command_Line_Never_Contains_Forbidden_Scripts()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingRunner()
            .Respond("/bin/nmap", 0, "<nmaprun/>")
            .Respond("/bin/enum4linux-ng", 0, "");

        var tool = new SmbTool(scope, audit, runner,
            nmapPath: "/bin/nmap", enum4linuxPath: "/bin/enum4linux-ng");

        _ = await tool.ProbeAsync("10.10.10.5");

        Assert.NotEmpty(runner.Calls);
        foreach (var (_, args) in runner.Calls)
        {
            Assert.DoesNotContain("brute", args, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("vuln", args, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("enum-users", args, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("enum-shares", args, StringComparison.OrdinalIgnoreCase);
        }

        // Positive check: the three allowed scripts ARE on the nmap argv.
        var nmapCall = runner.Calls.First(c => c.File == "/bin/nmap");
        Assert.Contains("smb-os-discovery", nmapCall.Arguments);
        Assert.Contains("smb-protocols", nmapCall.Arguments);
        Assert.Contains("smb2-security-mode", nmapCall.Arguments);
        Assert.Contains("-p 139,445", nmapCall.Arguments);

        // Credentials must never be passed to enum4linux-ng.
        var e4lCall = runner.Calls.First(c => c.File == "/bin/enum4linux-ng");
        Assert.DoesNotContain("-u ", e4lCall.Arguments);
        Assert.DoesNotContain("-p ", e4lCall.Arguments);
        Assert.DoesNotContain("--user", e4lCall.Arguments);
        Assert.DoesNotContain("--pass", e4lCall.Arguments);
    }
}
