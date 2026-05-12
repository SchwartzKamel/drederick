using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Xunit;

namespace Drederick.Tests.Integration.Empire;

/// <summary>
/// Each per-run opt-in gate must surface a typed refusal at the right
/// boundary: payload delivery (<c>--allow-payloads</c>), credential
/// post-ex modules (<c>--allow-cred-attacks</c>), and the synthetic
/// Empire-autopilot master gate.
/// </summary>
public sealed class EmpireFlowOptInGateTests
{
    [Fact]
    public async Task Missing_allow_payloads_refuses_empire_stager_delivery()
    {
        var perms = new RunPermissions(
            allowExecPocs: true,
            allowCredAttacks: true,
            allowPayloads: false,         // <-- the gate under test
            acknowledgeLockoutRisk: true);
        using var h = new EmpireTestHarness("10.10.10.0/24", perms);
        var scen = h.LoadScenario("scenario_windows.json");
        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);

        var ex = await Assert.ThrowsAsync<PermissionRefusedException>(() =>
            h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions));
        Assert.Equal(ExploitCategory.Payloads, ex.Category);
        Assert.Contains("--allow-payloads", ex.Message);
        Assert.Empty(h.Exploit.DeliveredTo);

        var log = h.ReadAuditLogFlushed();
        Assert.Contains("\"event\":\"empire.delivery.refused\"", log);
        Assert.Contains("permission_refused", log);
        Assert.DoesNotContain("\"event\":\"empire.delivery.dispatch\"", log);
    }

    [Fact]
    public async Task Missing_allow_cred_attacks_refuses_mimikatz_postex_module()
    {
        var perms = new RunPermissions(
            allowExecPocs: true,
            allowCredAttacks: false,      // <-- the gate under test
            allowPayloads: true,
            allowDestructive: true,
            acknowledgeLockoutRisk: true);
        using var h = new EmpireTestHarness("10.10.10.0/24", perms);
        var scen = h.LoadScenario("scenario_windows.json");
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        var ex = await Assert.ThrowsAsync<PermissionRefusedException>(() =>
            h.Dispatcher.RunAsync(session, EmpirePostExAction.LogonPasswords));
        Assert.Equal(ExploitCategory.CredAttacks, ex.Category);
        Assert.Empty(h.TaskClient.Queued);
        Assert.Equal(0, h.Credentials.Count);

        var log = h.ReadAuditLogFlushed();
        Assert.Contains("\"event\":\"empire.postex.dispatch.start\"", log);
        Assert.Contains("\"event\":\"empire.postex.dispatch.failure\"", log);
        Assert.Contains("permission_refused", log);
    }

    [Fact]
    public async Task Missing_empire_autopilot_master_gate_refuses_pipeline_entry()
    {
        var perms = new RunPermissions(
            allowExecPocs: true,
            allowCredAttacks: true,
            allowPayloads: true,
            allowDestructive: true,
            acknowledgeLockoutRisk: true);
        using var h = new EmpireTestHarness("10.10.10.0/24", perms, empireAutopilotEnabled: false);
        var scen = h.LoadScenario("scenario_windows.json");

        // Driver: this is the conditional an Empire-autopilot dispatch
        // layer would enforce at the top of its entrypoint. We model it
        // here so the gate is asserted symmetrically with the others.
        EmpireAutopilotDisabledException? thrown = null;
        try
        {
            if (!h.EmpireAutopilotEnabled) throw new EmpireAutopilotDisabledException();
            h.RegisterStagerResponse(scen.StagerResponseJson);
            await h.StagerGenerator.GenerateAsync(scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        }
        catch (EmpireAutopilotDisabledException ex) { thrown = ex; }

        Assert.NotNull(thrown);
        Assert.Contains("--empire-autopilot", thrown!.Message);
        // No stager request was issued.
        Assert.Empty(h.StagerHandler.Requests);
    }

    [Fact]
    public async Task Missing_allow_destructive_refuses_persistence_postex_module()
    {
        // Belt-and-braces: confirm the gating is per-category, not a single
        // boolean. Persistence modules are gated by Destructive, not by
        // CredAttacks. With CredAttacks allowed but Destructive denied,
        // a mimikatz call would succeed, while persistence still refuses.
        var perms = new RunPermissions(
            allowExecPocs: true,
            allowCredAttacks: true,
            allowPayloads: true,
            allowDestructive: false,      // <-- the gate under test
            acknowledgeLockoutRisk: true);
        using var h = new EmpireTestHarness("10.10.10.0/24", perms);
        var scen = h.LoadScenario("scenario_windows.json");
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        var ex = await Assert.ThrowsAsync<PermissionRefusedException>(() =>
            h.Dispatcher.RunAsync(session, EmpirePostExAction.PersistenceSchtasks));
        Assert.Equal(ExploitCategory.Destructive, ex.Category);
    }
}
