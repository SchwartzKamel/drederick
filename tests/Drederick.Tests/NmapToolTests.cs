using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class NmapToolTests
{
    [Fact]
    public void NseCategories_Lab_Mode_Adds_Discovery_And_Version()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-lab-{Guid.NewGuid():N}.jsonl"));
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: true);
        Assert.Contains("safe", nmap.NseCategories);
        Assert.Contains("default", nmap.NseCategories);
        Assert.Contains("discovery", nmap.NseCategories);
        Assert.Contains("version", nmap.NseCategories);
    }

    [Fact]
    public void NseCategories_Strict_Mode_Is_Safe_Default_Only()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-strict-{Guid.NewGuid():N}.jsonl"));
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: false);
        Assert.Equal("safe,default", nmap.NseCategories);
    }

    [Fact]
    public void NseCategories_Without_ExecPocs_Or_Dos_Exclude_Aggressive_Categories()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-neg-{Guid.NewGuid():N}.jsonl"));
        foreach (var lab in new[] { true, false })
        {
            var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: lab,
                permissions: Drederick.Exploit.RunPermissions.None);
            var cats = nmap.NseCategories;
            // With no ExecPocs / Dos opt-ins, aggressive categories stay out.
            Assert.DoesNotContain("exploit", cats);
            Assert.DoesNotContain("intrusive", cats);
            Assert.DoesNotContain("vuln", cats);
            Assert.DoesNotContain("dos", cats);
            Assert.DoesNotContain("malware", cats);
        }
    }

    [Fact]
    public void NseCategories_ExecPocs_Adds_Intrusive_Vuln_NotExploit()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-execpocs-{Guid.NewGuid():N}.jsonl"));
        var perms = new Drederick.Exploit.RunPermissions(allowExecPocs: true);
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: false, permissions: perms);
        var cats = nmap.NseCategories;
        Assert.Contains("intrusive", cats);
        Assert.Contains("vuln", cats);
        // GAP-022: 'exploit' category deliberately excluded — too slow on Windows
        // hosts with many ports (30-60+ min). Real exploitation is handled by
        // nuclei/msf/manual tools, not nmap NSE.
        Assert.DoesNotContain("exploit", cats);
        // auth is still off (no CredAttacks, no lab).
        Assert.DoesNotContain("auth", cats);
        // dos/malware still gated.
        Assert.DoesNotContain("dos", cats);
        Assert.DoesNotContain("malware", cats);
    }

    [Fact]
    public void NseCategories_CredAttacks_Or_Lab_Adds_Auth()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-auth-{Guid.NewGuid():N}.jsonl"));
        var perms = new Drederick.Exploit.RunPermissions(allowCredAttacks: true);
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: false, permissions: perms);
        Assert.Contains("auth", nmap.NseCategories);

        var labNmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: true);
        Assert.Contains("auth", labNmap.NseCategories);
    }

    [Fact]
    public void NseCategories_Dos_Adds_Dos_And_Malware()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-dos-{Guid.NewGuid():N}.jsonl"));
        var perms = new Drederick.Exploit.RunPermissions(allowDos: true);
        var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: false, permissions: perms);
        var cats = nmap.NseCategories;
        Assert.Contains("dos", cats);
        Assert.Contains("malware", cats);
    }
}
