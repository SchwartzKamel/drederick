using System;
using System.Collections.Generic;
using Drederick.Autopilot;
using Drederick.PostEx;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class EmpirePhaseConfigTests
{
    [Fact]
    public void Disabled_Default_Has_Sensible_Defaults()
    {
        var c = EmpirePhaseConfig.Disabled;
        Assert.False(c.Enabled);
        Assert.True(c.MaxWait > TimeSpan.Zero);
        Assert.True(c.CheckinWait > TimeSpan.Zero);
        Assert.Contains(EmpirePlatform.Windows, c.DefaultModules.Keys);
        Assert.Contains(EmpirePlatform.Linux, c.DefaultModules.Keys);
    }

    [Fact]
    public void Default_Modules_Include_Portscan_Per_Platform()
    {
        var c = new EmpirePhaseConfig(enabled: true);
        Assert.Contains(EmpirePostExAction.Portscan, c.DefaultModules[EmpirePlatform.Windows]);
        Assert.Contains(EmpirePostExAction.Portscan, c.DefaultModules[EmpirePlatform.Linux]);
    }

    [Fact]
    public void Windows_Default_Includes_Cred_Module_That_Requires_Cred_Attacks_Optin()
    {
        var c = new EmpirePhaseConfig(enabled: true);
        Assert.Contains(EmpirePostExAction.LogonPasswords, c.DefaultModules[EmpirePlatform.Windows]);
        // Sanity: this action's category MUST be CredAttacks so the phase
        // gate filters it out when --allow-cred-attacks is absent.
        Assert.Equal(Drederick.Exploit.ExploitCategory.CredAttacks,
            EmpireModuleCatalog.CategoryFor(EmpirePostExAction.LogonPasswords));
    }

    [Fact]
    public void Stager_Kinds_Map_Per_Platform()
    {
        var c = new EmpirePhaseConfig(enabled: true);
        Assert.Equal(Drederick.Exploit.Empire.EmpireStagerKind.Ps1, c.StagerKinds[EmpirePlatform.Windows]);
        Assert.Equal(Drederick.Exploit.Empire.EmpireStagerKind.Py, c.StagerKinds[EmpirePlatform.Linux]);
    }

    [Fact]
    public void Negative_MaxWait_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EmpirePhaseConfig(enabled: true, maxWait: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EmpirePhaseConfig(enabled: true, maxWait: TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void Negative_CheckinWait_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EmpirePhaseConfig(enabled: true, checkinWait: TimeSpan.Zero));
    }

    [Fact]
    public void Caller_Can_Override_Default_Modules()
    {
        var custom = new Dictionary<EmpirePlatform, IReadOnlyList<EmpirePostExAction>>
        {
            [EmpirePlatform.Windows] = new[] { EmpirePostExAction.Portscan },
            [EmpirePlatform.Linux] = new[] { EmpirePostExAction.Portscan },
        };
        var c = new EmpirePhaseConfig(enabled: true, defaultModules: custom);
        Assert.Single(c.DefaultModules[EmpirePlatform.Windows]);
        Assert.DoesNotContain(EmpirePostExAction.LogonPasswords, c.DefaultModules[EmpirePlatform.Windows]);
    }
}
