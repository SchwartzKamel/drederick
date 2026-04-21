using Drederick.Recon;
using Drederick.Reporting;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// HTB-grade expansion of the per-service cheatsheet. These tests verify the
/// operator gets the enumeration commands listed in the spec, that the
/// per-section banner is present, that <c>{target}</c> is always substituted,
/// and that no exploitation-class commands slip in.
/// </summary>
public class ManualCommandsCheatsheetHtbTests
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
    public void Banner_Note_Is_Present()
    {
        var h = MakeHost("10.10.11.200", (80, "http"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains(
            "NOTE: The following commands are suggestions for you to run manually after reviewing scope. drederick will not execute them.",
            text);
    }

    [Fact]
    public void Smb_Http_Kerberos_Emit_Expected_Keywords()
    {
        var h = MakeHost(
            "10.10.11.200",
            (445, "microsoft-ds"),
            (139, "netbios-ssn"),
            (88, "kerberos-sec"),
            (389, "ldap"),
            (80, "http"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);

        // SMB
        Assert.Contains("nxc smb 10.10.11.200 -u '' -p ''", text);
        Assert.Contains("nxc smb 10.10.11.200 -u 'guest' -p ''", text);
        Assert.Contains("nxc smb 10.10.11.200 --shares -u '' -p ''", text);
        Assert.Contains("smbclient -L //10.10.11.200/ -N", text);
        Assert.Contains("rpcclient -U \"\" -N 10.10.11.200", text);
        Assert.Contains("enum4linux-ng -A 10.10.11.200", text);
        Assert.Contains("--gen-relay-list relay-targets.txt", text);

        // LDAP
        Assert.Contains("ldapsearch -x -H ldap://10.10.11.200 -s base namingcontexts", text);
        Assert.Contains("ldapsearch -x -H ldap://10.10.11.200 -b \"<BASE_DN>\" '(objectClass=*)'", text);
        Assert.Contains("nxc ldap 10.10.11.200 -u '' -p '' --asreproastable", text);
        Assert.Contains("kerbrute userenum --dc 10.10.11.200", text);

        // Kerberos
        Assert.Contains("GetNPUsers.py <domain>/ -dc-ip 10.10.11.200 -usersfile users.txt -no-pass", text);
        Assert.Contains("GetUserSPNs.py -dc-ip 10.10.11.200", text);

        // HTTP
        Assert.Contains("ffuf -u http://10.10.11.200:80/FUZZ", text);
        Assert.Contains("gobuster dir -u http://10.10.11.200:80/", text);
        Assert.Contains("nuclei -u http://10.10.11.200:80", text);
        Assert.Contains("whatweb http://10.10.11.200:80", text);
        Assert.Contains("curl -sI http://10.10.11.200:80", text);
        Assert.Contains("ffuf -H \"Host: FUZZ.<target_domain>\"", text);
    }

    [Fact]
    public void Credentials_Reuse_Section_Is_At_Top()
    {
        var h = MakeHost("10.10.11.200", (80, "http"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        var idxCreds = text.IndexOf("## Credentials reuse", StringComparison.Ordinal);
        var idxHttp = text.IndexOf("## 80/tcp http", StringComparison.Ordinal);
        Assert.True(idxCreds > 0, "Credentials reuse section missing.");
        Assert.True(idxHttp > idxCreds, "Credentials reuse section must appear before service blocks.");
    }

    [Fact]
    public void Next_Phase_Checklist_Items_Are_Present()
    {
        var h = MakeHost("10.10.11.200", (22, "ssh"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("## Next phase checklist", text);
        Assert.Contains("[ ] Review report.json for service fingerprints", text);
        Assert.Contains("[ ] Run drederick serve", text);
        Assert.Contains("[ ] Attempt null/guest/anonymous access on all services above", text);
        Assert.Contains("[ ] Enumerate web content if http ports open", text);
        Assert.Contains("[ ] Collect credentials and loop back to start of checklist", text);
    }

    [Fact]
    public void Empty_Findings_Emit_Checklist_Only_No_Service_Blocks()
    {
        var h = new HostFinding { Target = "10.10.11.200", Started = "x" };
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);

        Assert.Contains("## Credentials reuse", text);
        Assert.Contains("## Next phase checklist", text);
        // No protocol-specific service blocks should appear.
        Assert.DoesNotContain("## 445/tcp", text);
        Assert.DoesNotContain("## 80/tcp", text);
        Assert.DoesNotContain("## 22/tcp", text);
        Assert.DoesNotContain("ffuf -u", text);
        Assert.DoesNotContain("ldapsearch", text);
        Assert.DoesNotContain("kerbrute", text);
    }

    [Fact]
    public void No_Exploitation_Class_Commands_In_HTB_Output()
    {
        var h = MakeHost(
            "10.10.11.200",
            (21, "ftp"),
            (22, "ssh"),
            (80, "http"),
            (88, "kerberos-sec"),
            (139, "netbios-ssn"),
            (161, "snmp"),
            (389, "ldap"),
            (443, "https"),
            (445, "microsoft-ds"),
            (1433, "ms-sql-s"),
            (2049, "nfs"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (5985, "wsman"),
            (6379, "redis"),
            (27017, "mongodb"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        var lower = text.ToLowerInvariant();

        Assert.DoesNotContain("msfconsole", lower);
        Assert.DoesNotContain("msfvenom", lower);
        Assert.DoesNotContain("exploit/", lower);
        Assert.DoesNotContain("hashcat -a 0", lower);
        Assert.DoesNotContain("hydra ", lower);
        Assert.DoesNotContain("medusa ", lower);
        Assert.DoesNotContain("password-spray", lower);
        Assert.DoesNotContain("--script exploit", lower);
        Assert.DoesNotContain("--script vuln", lower);

        // evil-winrm is only mentioned as a commented follow-up step the
        // operator runs AFTER obtaining creds from another enum step — it
        // must never be pre-seeded with a concrete password. Check that any
        // evil-winrm line is commented out.
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (trimmed.Contains("evil-winrm", StringComparison.OrdinalIgnoreCase))
            {
                Assert.StartsWith("#", trimmed);
            }
        }
    }

    [Fact]
    public void Target_Placeholder_Always_Substituted()
    {
        var h = MakeHost(
            "10.10.11.200",
            (21, "ftp"),
            (22, "ssh"),
            (80, "http"),
            (88, "kerberos-sec"),
            (139, "netbios-ssn"),
            (161, "snmp"),
            (389, "ldap"),
            (443, "https"),
            (445, "microsoft-ds"),
            (1433, "ms-sql-s"),
            (2049, "nfs"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (5985, "wsman"),
            (6379, "redis"),
            (27017, "mongodb"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);

        // The literal {target} placeholder must never leak into the output —
        // it should always have been substituted with h.Target.
        Assert.DoesNotContain("{target}", text);
        Assert.DoesNotContain("{port}", text);
        // And the actual target should appear many times (at least once per
        // service block header plus the reuse/examples section).
        var count = 0;
        var idx = 0;
        while ((idx = text.IndexOf("10.10.11.200", idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += "10.10.11.200".Length;
        }
        Assert.True(count > 20, $"Expected target to appear many times, got {count}.");
    }

    [Fact]
    public void Ssh_Block_References_Already_Collected_Algorithms()
    {
        var h = MakeHost("10.10.11.200", (22, "ssh"));
        h.Ssh.Add(new SshResult
        {
            Port = 22,
            Banner = "SSH-2.0-OpenSSH_9.2p1",
            KexAlgorithms = new List<string> { "curve25519-sha256" }
        });
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("see ssh.algorithms in", text);
        // When algorithms are already collected, we should not suggest
        // re-running the nmap ssh2-enum-algos script. The text still *mentions*
        // the script name in the "instead of re-running ..." comment, so
        // detect the actual nmap command-line form instead of the bare word.
        Assert.DoesNotContain("--script ssh2-enum-algos", text);
    }

    [Fact]
    public void Tls_Cipher_Enum_Reference_When_Already_Collected()
    {
        var h = MakeHost("10.10.11.200", (443, "https"));
        h.TlsCipherEnum.Add(new TlsCipherEnumResult { Port = 443 });
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        Assert.Contains("see tls_cipher_enum in report.json", text);
    }

    [Fact]
    public void Mysql_Brute_Is_Tagged_As_Operator_Only()
    {
        var h = MakeHost("10.10.11.200", (3306, "mysql"));
        var text = ManualCommandsCheatsheet.BuildCheatsheet(h);
        // mysql-brute appears, but with the explicit "OPERATOR runs it" tag
        // on the preceding lines so drederick's posture is clear.
        Assert.Contains("mysql-brute", text);
        Assert.Contains("OPERATOR", text);
        Assert.Contains("drederick will not run it", text);
    }
}
