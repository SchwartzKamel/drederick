using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Xunit;

namespace Drederick.Tests.PostEx;

public class EmpireModuleCatalogTests
{
    [Fact]
    public void Windows_logonpasswords_resolves_to_mimikatz_module()
    {
        var module = EmpireModuleCatalog.Lookup(EmpirePlatform.Windows, EmpirePostExAction.LogonPasswords);
        Assert.Equal("powershell/credentials/mimikatz/logonpasswords", module);
    }

    [Fact]
    public void Linux_portscan_resolves_to_python_portscan_module()
    {
        var module = EmpireModuleCatalog.Lookup(EmpirePlatform.Linux, EmpirePostExAction.Portscan);
        Assert.Equal("python/situational_awareness/network/portscan", module);
    }

    [Fact]
    public void Windows_only_actions_refused_on_Linux()
    {
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Linux, EmpirePostExAction.LogonPasswords));
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Linux, EmpirePostExAction.DcSync));
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Linux, EmpirePostExAction.PersistenceSchtasks));
    }

    [Fact]
    public void Linux_only_actions_refused_on_Windows()
    {
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Windows, EmpirePostExAction.SshKeys));
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Windows, EmpirePostExAction.SuidFiles));
        Assert.Throws<EmpireModuleNotSupportedException>(
            () => EmpireModuleCatalog.Lookup(EmpirePlatform.Windows, EmpirePostExAction.PersistenceCron));
    }

    [Fact]
    public void Windows_catalog_has_all_required_actions()
    {
        var actions = new[]
        {
            EmpirePostExAction.Portscan, EmpirePostExAction.LogonPasswords,
            EmpirePostExAction.KerberosTickets, EmpirePostExAction.LsaDump,
            EmpirePostExAction.DcSync, EmpirePostExAction.WatsonPrivesc,
            EmpirePostExAction.Sherlock, EmpirePostExAction.GetSystem,
            EmpirePostExAction.PersistenceSchtasks,
        };
        foreach (var a in actions)
        {
            Assert.True(EmpireModuleCatalog.TryLookup(EmpirePlatform.Windows, a, out var name));
            Assert.False(string.IsNullOrEmpty(name));
            Assert.StartsWith("powershell/", name);
        }
    }

    [Fact]
    public void Linux_catalog_has_all_required_actions()
    {
        var actions = new[]
        {
            EmpirePostExAction.Portscan, EmpirePostExAction.SshKeys,
            EmpirePostExAction.SudoConfig, EmpirePostExAction.KernelVersion,
            EmpirePostExAction.Capabilities, EmpirePostExAction.SuidFiles,
            EmpirePostExAction.PersistenceCron,
        };
        foreach (var a in actions)
        {
            Assert.True(EmpireModuleCatalog.TryLookup(EmpirePlatform.Linux, a, out var name));
            Assert.False(string.IsNullOrEmpty(name));
            Assert.StartsWith("python/", name);
        }
    }

    [Theory]
    [InlineData(EmpirePostExAction.LogonPasswords, ExploitCategory.CredAttacks)]
    [InlineData(EmpirePostExAction.LsaDump, ExploitCategory.CredAttacks)]
    [InlineData(EmpirePostExAction.DcSync, ExploitCategory.CredAttacks)]
    [InlineData(EmpirePostExAction.KerberosTickets, ExploitCategory.CredAttacks)]
    [InlineData(EmpirePostExAction.SshKeys, ExploitCategory.CredAttacks)]
    [InlineData(EmpirePostExAction.GetSystem, ExploitCategory.Destructive)]
    [InlineData(EmpirePostExAction.PersistenceSchtasks, ExploitCategory.Destructive)]
    [InlineData(EmpirePostExAction.PersistenceCron, ExploitCategory.Destructive)]
    [InlineData(EmpirePostExAction.Portscan, ExploitCategory.ExecPocs)]
    [InlineData(EmpirePostExAction.WatsonPrivesc, ExploitCategory.ExecPocs)]
    [InlineData(EmpirePostExAction.Sherlock, ExploitCategory.ExecPocs)]
    public void Category_mapping_matches_invariants(EmpirePostExAction action, ExploitCategory expected)
    {
        Assert.Equal(expected, EmpireModuleCatalog.CategoryFor(action));
    }

    [Fact]
    public void PlatformFor_detects_python_agent_as_Linux()
    {
        var s = new EmpireSession("EF56", "10.10.10.51", "root", "lab-python", DateTimeOffset.UtcNow);
        Assert.Equal(EmpirePlatform.Linux, EmpireModuleCatalog.PlatformFor(s));
    }

    [Fact]
    public void PlatformFor_detects_powershell_agent_as_Windows()
    {
        var s = new EmpireSession("AB12", "10.10.10.5", "CORP\\bob", "lab-http-powershell", DateTimeOffset.UtcNow);
        Assert.Equal(EmpirePlatform.Windows, EmpireModuleCatalog.PlatformFor(s));
    }

    [Fact]
    public void ActionsFor_returns_disjoint_sets()
    {
        var win = EmpireModuleCatalog.ActionsFor(EmpirePlatform.Windows);
        var lin = EmpireModuleCatalog.ActionsFor(EmpirePlatform.Linux);
        Assert.Contains(EmpirePostExAction.LogonPasswords, win);
        Assert.DoesNotContain(EmpirePostExAction.LogonPasswords, lin);
        Assert.Contains(EmpirePostExAction.SshKeys, lin);
        Assert.DoesNotContain(EmpirePostExAction.SshKeys, win);
        Assert.Contains(EmpirePostExAction.Portscan, win);
        Assert.Contains(EmpirePostExAction.Portscan, lin);
    }
}
