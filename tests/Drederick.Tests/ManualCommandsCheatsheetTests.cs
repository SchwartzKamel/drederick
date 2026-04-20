using Drederick.Recon;
using Drederick.Reporting;
using Xunit;

namespace Drederick.Tests;

public class ManualCommandsCheatsheetTests
{
    private static HostFinding MakeHost(string target, params (int port, string svc)[] services)
    {
        var h = new HostFinding { Target = target, Started = "2026-04-20T21:00:00Z" };
        h.Nmap = new NmapResult { ReturnCode = 0 };
        foreach (var (port, svc) in services)
        {
            h.Nmap.OpenPorts.Add(new NmapPort { Port = port, Protocol = "tcp", Service = svc });
        }
        return h;
    }

    [Fact]
    public void Cheatsheet_Includes_Header_And_Target()
    {
        var h = MakeHost("10.10.10.5", (80, "http"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("10.10.10.5", text);
        Assert.Contains("drederick does not execute", text.ToLowerInvariant());
    }

    [Fact]
    public void Cheatsheet_Emits_Http_Suggestions()
    {
        var h = MakeHost("10.10.10.5", (80, "http"), (443, "https"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("http://10.10.10.5:80/", text);
        Assert.Contains("https://10.10.10.5:443/", text);
        Assert.Contains("robots.txt", text);
        Assert.Contains("ssl-enum-ciphers", text);
    }

    [Fact]
    public void Cheatsheet_Does_Not_Suggest_Exploit_Or_Brute_Commands()
    {
        var h = MakeHost("10.10.10.5",
            (22, "ssh"),
            (80, "http"),
            (445, "microsoft-ds"),
            (88, "kerberos-sec"),
            (389, "ldap"),
            (161, "snmp"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h).ToLowerInvariant();
        // These are the footguns we explicitly refuse to recommend.
        Assert.DoesNotContain("hydra", text);
        Assert.DoesNotContain("medusa", text);
        Assert.DoesNotContain("crackmapexec", text);
        Assert.DoesNotContain("metasploit", text);
        Assert.DoesNotContain("msfconsole", text);
        Assert.DoesNotContain("searchsploit", text);
        Assert.DoesNotContain("as-rep", text);
        Assert.DoesNotContain("asreproast", text);
        Assert.DoesNotContain("kerbrute", text);
        Assert.DoesNotContain("password-spray", text);
        Assert.DoesNotContain("--script brute", text);
        Assert.DoesNotContain("--script exploit", text);
        Assert.DoesNotContain("--script vuln", text);
    }

    [Fact]
    public void Cheatsheet_Fallback_When_No_Ports()
    {
        var h = new HostFinding { Target = "10.10.10.5", Started = "x" };
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("No open TCP services", text);
        Assert.Contains("-p-", text);
    }

    [Fact]
    public void Write_Creates_Per_Host_Working_Directory()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-cheatsheet-" + Guid.NewGuid().ToString("N"));
        try
        {
            var h = MakeHost("10.10.10.5", (80, "http"));
            ManualCommandsCheatsheet.Write(tmp, new[] { h }, emitCheatsheet: true);

            var hostDir = Path.Combine(tmp, "10.10.10.5");
            Assert.True(Directory.Exists(Path.Combine(hostDir, "scans")));
            Assert.True(Directory.Exists(Path.Combine(hostDir, "loot")));
            Assert.True(File.Exists(Path.Combine(hostDir, "notes.md")));
            Assert.True(File.Exists(Path.Combine(hostDir, "manual_commands.txt")));
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void Write_Skips_Cheatsheet_In_Strict_Mode()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-cheatsheet-" + Guid.NewGuid().ToString("N"));
        try
        {
            var h = MakeHost("10.10.10.5", (80, "http"));
            ManualCommandsCheatsheet.Write(tmp, new[] { h }, emitCheatsheet: false);

            var hostDir = Path.Combine(tmp, "10.10.10.5");
            Assert.True(File.Exists(Path.Combine(hostDir, "notes.md")));
            Assert.False(File.Exists(Path.Combine(hostDir, "manual_commands.txt")));
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void Write_Sanitizes_Ipv6_Target_For_Path()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-cheatsheet-" + Guid.NewGuid().ToString("N"));
        try
        {
            var h = MakeHost("fd00::1", (80, "http"));
            ManualCommandsCheatsheet.Write(tmp, new[] { h }, emitCheatsheet: true);

            var sanitized = Path.Combine(tmp, "fd00__1");
            Assert.True(Directory.Exists(sanitized));
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }
}
