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
    public void NseCategories_Never_Include_Exploit_Brute_Or_Vuln()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-neg-{Guid.NewGuid():N}.jsonl"));
        foreach (var lab in new[] { true, false })
        {
            var nmap = new NmapTool(scope, audit, nmapPath: "/bin/true", labMode: lab);
            var cats = nmap.NseCategories;
            Assert.DoesNotContain("exploit", cats);
            Assert.DoesNotContain("brute", cats);
            Assert.DoesNotContain("vuln", cats);
            Assert.DoesNotContain("intrusive", cats);
            Assert.DoesNotContain("dos", cats);
            Assert.DoesNotContain("malware", cats);
        }
    }
}
