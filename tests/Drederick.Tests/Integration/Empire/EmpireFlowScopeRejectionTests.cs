using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Integration.Empire;

/// <summary>
/// Every boundary that crosses scope must refuse. These tests prove that
/// the scope check is reachable through the integration-test harness on
/// each of the three real entry points: stager generation, post-ex
/// dispatch, and credential push.
/// </summary>
public sealed class EmpireFlowScopeRejectionTests
{
    private static RunPermissions LabPerms() => new(
        allowExecPocs: true,
        allowCredAttacks: true,
        allowPayloads: true,
        allowDestructive: true,
        acknowledgeLockoutRisk: true);

    [Fact]
    public async Task Stager_generation_for_out_of_scope_target_refuses()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json");
        // Queue a canned 200 — the stub must never see the request because
        // scope refuses before any HTTP traffic.
        h.RegisterStagerResponse(scen.StagerResponseJson);

        await Assert.ThrowsAsync<ScopeException>(() =>
            h.StagerGenerator.GenerateAsync(scen.Listener, EmpireStagerKind.Ps1, "8.8.8.8"));

        // Network must not have been touched.
        Assert.Empty(h.StagerHandler.Requests);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain("\"event\":\"empire.stager.generate.start\"", log);
        Assert.DoesNotContain("\"event\":\"empire.stager.generate.success\"", log);
    }

    [Fact]
    public async Task PostEx_dispatch_against_out_of_scope_agent_host_refuses()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        // Out-of-scope agent host — never goes through SessionManager
        // because Sessions.Register itself enforces scope; we construct
        // the session directly to test the dispatcher's gate.
        var oos = new EmpireSession("OOS-AGENT", "8.8.8.8", "u", "lab-http", DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<ScopeException>(() =>
            h.Dispatcher.RunAsync(oos, EmpirePostExAction.LogonPasswords));

        Assert.Empty(h.TaskClient.Queued);
    }

    [Fact]
    public async Task SessionManager_register_refuses_out_of_scope_host()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var oos = new EmpireSession("X", "1.1.1.1", "u", "lab-http", DateTimeOffset.UtcNow);
        Assert.Throws<ScopeException>(() => h.Sessions.Register(oos));
        Assert.Empty(h.Sessions.Live);
    }

    [Fact]
    public async Task Cred_push_from_out_of_scope_source_host_is_refused_and_audited()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        // No HTTP responses queued — the bridge must never reach the wire.
        var cred = new DrederickCredential
        {
            User = "alice",
            Realm = "CORP",
            PasswordSha256 = "deadbeef",
            Plaintext = "should-not-leave",
            SourceHost = "8.8.8.8", // OOS
            Source = "manual",
            CredType = "plaintext",
        };
        var pushed = await h.CredBridge.PushToEmpireAsync(cred);
        Assert.False(pushed);

        // No HTTP request reached the cred handler.
        Assert.Empty(h.CredHandler.Requests);

        var log = h.ReadAuditLogFlushed();
        Assert.Contains("\"event\":\"empire.cred.push.skipped_oos\"", log);
        Assert.Contains("\"reason\":\"scope_refused\"", log);
        Assert.DoesNotContain("\"event\":\"empire.cred.push.success\"", log);
        Assert.DoesNotContain("should-not-leave", log);
    }

    [Fact]
    public async Task Exploit_delivery_to_out_of_scope_target_refuses_even_with_payloads_allowed()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json");
        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        await Assert.ThrowsAsync<ScopeException>(() =>
            h.Exploit.DeliverEmpireArtifactAsync("8.8.8.8", artifact, h.Permissions));
        Assert.DoesNotContain("8.8.8.8", h.Exploit.DeliveredTo);
    }
}
