using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Integration.Empire;

/// <summary>
/// End-to-end happy-path Empire integration smoke tests. Each scenario
/// composes the full pipeline (autopilot → stager generation → delivery →
/// agent checkin → post-ex → cred bridge → KnowledgeBase) through the
/// real types, gated by the real scope + opt-in checks. All boundaries
/// (HTTP, Empire task queue, subprocess delivery) are stubbed.
/// </summary>
public sealed class EmpireFlowSmokeTests
{
    private static RunPermissions LabPerms() => new(
        allowExecPocs: true,
        allowCredAttacks: true,
        allowPayloads: true,
        allowDestructive: true,
        acknowledgeLockoutRisk: true);

    [Fact]
    public async Task Windows_mimikatz_harvest_end_to_end_threads_clean()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json")
                    .ApplyCanary("CANARY_INTEGRATION_windows_mimikatz_harvest");

        // 1. Recon → autopilot iteration (no exploitable findings; the
        //    runner should idle cleanly so we know it's wired correctly).
        var report = await h.Autopilot.RunAsync(new[]
        {
            new HostFinding { Target = scen.Target,
                Nmap = new NmapResult { OpenPorts = new() { new() { Port = 445, Service = "microsoft-ds" } } } },
        });
        Assert.Empty(report.Actions);

        // 2. Stager generation.
        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        Assert.Equal(EmpireStagerKind.Ps1, artifact.Kind);
        Assert.Equal(64, artifact.PayloadSha256.Length);

        // 3. Delivery (Payloads gate enforced).
        var (ok, err) = await h.Exploit.DeliverEmpireArtifactAsync(
            scen.Target, artifact, h.Permissions);
        Assert.True(ok);
        Assert.Null(err);

        // 4. Agent checkin → session registration.
        var checkin = h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener);
        var session = h.Sessions.Register(checkin);

        // 5. Post-ex module dispatch (LogonPasswords gated by CredAttacks).
        h.TaskClient.Register("powershell/credentials/mimikatz/logonpasswords", scen.MimikatzOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.LogonPasswords);

        Assert.Equal("completed", result.ExitStatus);
        Assert.NotEmpty(result.ParsedFindings);

        // 6. Cred bridge: at least one captured plaintext flowed into the
        //    store. (Dispatcher Add() carries no SourceHost; the bridge's
        //    auto-subscription would refuse it as 'no_source_host'. We
        //    verify the store now has the credential and that pushing a
        //    SourceHost-attributed copy succeeds.)
        Assert.True(h.Credentials.Count >= 1);

        h.RegisterCredCreate(id: 9001);
        var pushOk = await h.CredBridge.PushToEmpireAsync(new DrederickCredential
        {
            User = "alice",
            Realm = "CORP",
            PasswordSha256 = "deadbeef",
            Plaintext = "CANARY_INTEGRATION_windows_mimikatz_harvest_PUSH",
            SourceHost = scen.Target,
            Source = "empire-mimikatz",
            CredType = "plaintext",
        });
        Assert.True(pushOk);

        // 7. KnowledgeBase: portscan was not run for this scenario, so no
        //    pivots — but a pull from Empire should leave the KB intact.
        h.RegisterEmptyCredList();
        var pull = await h.CredBridge.PullFromEmpireAsync("127.0.0.1:1337");
        Assert.Equal(0, pull.Added);
        Assert.Empty(h.Kb.FindPivotsBySource($"session:{session.AgentId}"));

        // 8. Audit chain assertions.
        var log = h.ReadAuditLogFlushed();
        Assert.Contains("\"event\":\"empire.stager.generate.success\"", log);
        Assert.Contains("\"event\":\"empire.delivery.prepare\"", log);
        Assert.Contains("\"event\":\"empire.delivery.dispatch\"", log);
        Assert.Contains("\"event\":\"empire.session.registered\"", log);
        Assert.Contains("\"event\":\"empire.postex.dispatch.start\"", log);
        Assert.Contains("\"event\":\"empire.postex.dispatch.success\"", log);
        Assert.Contains("\"event\":\"empire.cred.push.success\"", log);
        Assert.Contains("\"event\":\"empire.cred.pull.result\"", log);
        Assert.DoesNotContain("CANARY_INTEGRATION_windows_mimikatz_harvest", log);
    }

    [Fact]
    public async Task Linux_ssh_key_harvest_end_to_end_threads_clean()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_linux.json")
                    .ApplyCanary("CANARY_INTEGRATION_linux_ssh_key_harvest");

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Py, scen.Target);
        Assert.Equal(EmpireStagerKind.Py, artifact.Kind);

        var (ok, _) = await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);
        Assert.True(ok);

        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        h.TaskClient.Register("python/collection/linux/ssh_keys", scen.SshKeysOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.SshKeys);
        Assert.Equal("completed", result.ExitStatus);
        Assert.False(string.IsNullOrEmpty(result.OutputDigest));

        var log = h.ReadAuditLogFlushed();
        // Linux module dispatched against the Linux-platform-resolved session.
        Assert.Contains("python/collection/linux/ssh_keys", log);
        // Canary must not leak through any audit boundary.
        Assert.DoesNotContain("CANARY_INTEGRATION_linux_ssh_key_harvest", log);
    }

    [Fact]
    public async Task Multi_host_pivoting_records_pivots_per_session()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_pivot.json")
                    .ApplyCanary("CANARY_INTEGRATION_multi_host_pivoting");

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);

        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        h.TaskClient.Register("powershell/situational_awareness/network/portscan", scen.PortscanOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.Portscan);
        Assert.Equal("completed", result.ExitStatus);

        var pivots = h.Kb.FindPivotsBySource($"session:{session.AgentId}");
        Assert.NotEmpty(pivots);
        var byIp = pivots.ToDictionary(p => p.Ip);
        Assert.Contains("10.10.10.31", byIp.Keys);
        Assert.Contains("10.10.10.32", byIp.Keys);
        Assert.Contains(22, byIp["10.10.10.31"].OpenPorts);
        Assert.Contains(445, byIp["10.10.10.31"].OpenPorts);
        Assert.Contains(80, byIp["10.10.10.32"].OpenPorts);
        Assert.Contains(3389, byIp["10.10.10.32"].OpenPorts);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain("CANARY_INTEGRATION_multi_host_pivoting", log);
    }

    [Fact]
    public async Task Listener_reuse_across_multiple_hosts_threads_each_target_independently()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var listener = "lab-http-reused";
        var targets = new[] { "10.10.10.40", "10.10.10.41", "10.10.10.42" };

        // Same stager response (modulo HTTP queue) for each target — the
        // listener name is the constant, the per-target audit event is
        // what we assert about.
        var stagerJson = File.ReadAllText(EmpireTestHarness.ResolveFixture("scenario_windows.json"));
        var scen = Scenario.Parse(stagerJson);
        foreach (var _ in targets) h.RegisterStagerResponse(scen.StagerResponseJson);

        var arts = new List<EmpireDeliveryArtifact>();
        foreach (var t in targets)
        {
            var a = await h.StagerGenerator.GenerateAsync(listener, EmpireStagerKind.Ps1, t);
            arts.Add(a);
            var (ok, _) = await h.Exploit.DeliverEmpireArtifactAsync(t, a, h.Permissions);
            Assert.True(ok);
        }

        Assert.Equal(targets.Length, h.Exploit.DeliveredTo.Count);
        Assert.Equal(targets.OrderBy(x => x), h.Exploit.DeliveredTo.OrderBy(x => x));
        // Every artifact references the same listener; deliveries are
        // independent and recorded per target.
        Assert.All(arts, a => Assert.Equal(listener, a.ListenerName));

        var log = h.ReadAuditLogFlushed();
        foreach (var t in targets)
        {
            Assert.Contains($"\"target\":\"{t}\"", log);
        }
    }

    [Fact]
    public async Task Agent_dies_mid_module_returns_error_result_no_state_corruption()
    {
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json")
                    .ApplyCanary("CANARY_INTEGRATION_agent_dies_mid_module");

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        // Task client is NOT registered for this module → QueueModuleAsync
        // throws InvalidOperationException, which the dispatcher captures
        // and surfaces as an error result.
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.LogonPasswords);
        Assert.Equal("error", result.ExitStatus);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Empty(result.ParsedFindings);
        Assert.Equal(0, h.Credentials.Count); // no creds harvested
        Assert.Empty(h.Kb.FindPivotsBySource($"session:{session.AgentId}"));

        // Session can be closed cleanly after the failure.
        Assert.True(h.Sessions.Close(session.AgentId));

        var log = h.ReadAuditLogFlushed();
        Assert.Contains("\"event\":\"empire.postex.dispatch.failure\"", log);
        Assert.Contains("\"event\":\"empire.session.closed\"", log);
        Assert.DoesNotContain("CANARY_INTEGRATION_agent_dies_mid_module", log);
    }
}
