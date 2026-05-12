using System;
using System.Collections.Generic;
using System.Linq;
using Drederick.Agent;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// Empire Wave C — unit tests for <see cref="EmpireCandidateInjector"/>.
/// The injector is pure; these tests assert all four behavior rules and
/// the no-double-injection guard.
/// </summary>
public class EmpireCandidateInjectorTests
{
    private const string WinHost = "10.10.10.5";
    private const string LinHost = "10.10.10.6";

    private static EmpireSession WinSession(string host) =>
        new("agent-w1", host, "CORP\\admin", "http-windows-powershell", DateTimeOffset.UtcNow);

    private static EmpireSession LinSession(string host) =>
        new("agent-l1", host, "root", "http-linux-python", DateTimeOffset.UtcNow);

    [Fact]
    public void Inject_returns_empty_when_autopilot_disabled_even_with_windows_rce()
    {
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: false,
            HasConfirmedWindowsRce: true,
            HasLinuxSshCredentials: true);

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps);

        Assert.Empty(result);
    }

    [Fact]
    public void Inject_returns_empty_when_autopilot_disabled_even_with_active_session()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: false);

        var result = EmpireCandidateInjector.Inject(
            WinHost, new HostFinding(), new[] { WinSession(WinHost) }, caps);

        Assert.Empty(result);
    }

    [Fact]
    public void Inject_emits_powershell_stager_for_windows_rce()
    {
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasConfirmedWindowsRce: true);

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps);

        var c = Assert.Single(result);
        Assert.Equal(EmpireCandidateKind.Stager, c.Kind);
        Assert.Equal(EmpirePlatform.Windows, c.Platform);
        Assert.Equal(EmpireStagerLauncher.PowerShell, c.Launcher);
        Assert.Equal(WinHost, c.Target);
        Assert.Null(c.ModuleAction);
    }

    [Fact]
    public void Inject_emits_python_stager_for_linux_ssh_credentials()
    {
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasLinuxSshCredentials: true);

        var result = EmpireCandidateInjector.Inject(LinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps);

        var c = Assert.Single(result);
        Assert.Equal(EmpireCandidateKind.Stager, c.Kind);
        Assert.Equal(EmpirePlatform.Linux, c.Platform);
        Assert.Equal(EmpireStagerLauncher.Python, c.Launcher);
    }

    [Fact]
    public void Inject_prefers_windows_stager_when_both_capabilities_present()
    {
        // Bias: Windows RCE is a stronger signal than mere SSH creds.
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasConfirmedWindowsRce: true,
            HasLinuxSshCredentials: true);

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps);

        var c = Assert.Single(result);
        Assert.Equal(EmpirePlatform.Windows, c.Platform);
        Assert.Equal(EmpireStagerLauncher.PowerShell, c.Launcher);
    }

    [Fact]
    public void Inject_returns_empty_when_no_signals_present()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: true);

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps);

        Assert.Empty(result);
    }

    [Fact]
    public void Inject_emits_windows_module_candidates_for_active_powershell_session()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: true);
        var sessions = new[] { WinSession(WinHost) };

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), sessions, caps);

        Assert.NotEmpty(result);
        Assert.All(result, c =>
        {
            Assert.Equal(EmpireCandidateKind.Module, c.Kind);
            Assert.Equal(EmpirePlatform.Windows, c.Platform);
            Assert.Equal(WinHost, c.Target);
            Assert.NotNull(c.ModuleAction);
            Assert.False(string.IsNullOrEmpty(c.ModuleName));
        });

        // Must exactly mirror the catalog for this platform.
        var expected = EmpireModuleCatalog.ActionsFor(EmpirePlatform.Windows).ToHashSet();
        var actual = result.Select(c => c.ModuleAction!.Value).ToHashSet();
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Inject_emits_linux_module_candidates_for_active_python_session()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: true);
        var sessions = new[] { LinSession(LinHost) };

        var result = EmpireCandidateInjector.Inject(LinHost, new HostFinding(), sessions, caps);

        Assert.NotEmpty(result);
        Assert.All(result, c =>
        {
            Assert.Equal(EmpireCandidateKind.Module, c.Kind);
            Assert.Equal(EmpirePlatform.Linux, c.Platform);
        });

        var expected = EmpireModuleCatalog.ActionsFor(EmpirePlatform.Linux).ToHashSet();
        var actual = result.Select(c => c.ModuleAction!.Value).ToHashSet();
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Inject_does_not_double_inject_modules_when_chain_already_has_module_step()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: true);
        var sessions = new[] { WinSession(WinHost) };
        var existing = new List<EmpireCandidate>
        {
            new(WinHost, EmpireCandidateKind.Module, EmpirePlatform.Windows,
                ModuleAction: EmpirePostExAction.Portscan,
                ModuleName: "powershell/situational_awareness/network/portscan"),
        };

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), sessions, caps, existing);

        Assert.Empty(result);
    }

    [Fact]
    public void Inject_does_not_double_inject_stager_when_chain_already_has_stager_step()
    {
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasConfirmedWindowsRce: true);
        var existing = new List<EmpireCandidate>
        {
            new(WinHost, EmpireCandidateKind.Stager, EmpirePlatform.Windows, Launcher: EmpireStagerLauncher.PowerShell),
        };

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps, existing);

        Assert.Empty(result);
    }

    [Fact]
    public void Inject_dedup_is_host_scoped()
    {
        // Existing chain step targets a DIFFERENT host — must not suppress
        // injection for the host we're planning against.
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasConfirmedWindowsRce: true);
        var existing = new List<EmpireCandidate>
        {
            new("10.10.10.99", EmpireCandidateKind.Stager, EmpirePlatform.Windows, Launcher: EmpireStagerLauncher.PowerShell),
        };

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), Array.Empty<EmpireSession>(), caps, existing);

        Assert.Single(result);
    }

    [Fact]
    public void Inject_ignores_sessions_for_other_hosts()
    {
        var caps = new EmpireInjectionCapabilities(
            EmpireAutopilotEnabled: true,
            HasConfirmedWindowsRce: true);
        // Session belongs to a different host — must fall through to stager.
        var sessions = new[] { WinSession("10.10.10.99") };

        var result = EmpireCandidateInjector.Inject(WinHost, new HostFinding(), sessions, caps);

        var c = Assert.Single(result);
        Assert.Equal(EmpireCandidateKind.Stager, c.Kind);
    }

    [Fact]
    public void Inject_throws_on_blank_host()
    {
        var caps = new EmpireInjectionCapabilities(EmpireAutopilotEnabled: true);
        Assert.Throws<ArgumentException>(() =>
            EmpireCandidateInjector.Inject("", new HostFinding(), Array.Empty<EmpireSession>(), caps));
    }
}
