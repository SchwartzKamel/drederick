using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Xunit;

namespace Drederick.Tests.Integration.Empire;

/// <summary>
/// Canary leak tests. A unique sentinel string is planted at every
/// boundary that handles secret material (mimikatz output, SSH keys
/// output, stager response body, plaintext credential push). After the
/// pipeline runs, the sentinel MUST NOT appear in the audit log. This
/// is the strongest form of the "no plaintext in audit" invariant.
/// </summary>
public sealed class EmpireFlowCanaryLeakTests
{
    private const string CanaryPrefix = "CANARY_INTEGRATION_LEAK_";

    private static RunPermissions LabPerms() => new(
        allowExecPocs: true,
        allowCredAttacks: true,
        allowPayloads: true,
        allowDestructive: true,
        acknowledgeLockoutRisk: true);

    [Fact]
    public async Task Canary_in_mimikatz_password_never_appears_in_audit_log()
    {
        const string canary = CanaryPrefix + "MIMIKATZ_PWD";
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json").ApplyCanary(canary);

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        h.TaskClient.Register("powershell/credentials/mimikatz/logonpasswords", scen.MimikatzOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.LogonPasswords);
        Assert.Equal("completed", result.ExitStatus);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain(canary, log);
        // Parsed findings must also not echo the secret verbatim.
        foreach (var f in result.ParsedFindings)
        {
            foreach (var v in f.Fields.Values)
            {
                Assert.DoesNotContain(canary, v ?? string.Empty);
            }
        }
    }

    [Fact]
    public async Task Canary_in_ssh_key_output_never_appears_in_audit_log()
    {
        const string canary = CanaryPrefix + "SSHKEYS";
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_linux.json").ApplyCanary(canary);

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Py, scen.Target);
        await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        h.TaskClient.Register("python/collection/linux/ssh_keys", scen.SshKeysOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.SshKeys);
        Assert.Equal("completed", result.ExitStatus);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain(canary, log);
    }

    [Fact]
    public async Task Canary_in_stager_response_body_is_redacted_in_audit()
    {
        const string canary = CanaryPrefix + "STAGER_BODY";
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_windows.json").ApplyCanary(canary);

        // Inject the canary into the stager output field; EmpireStagerGenerator
        // is required to redact the body when auditing success.
        var doctored = scen.StagerResponseJson.Replace(
            "\"output\":\"powershell",
            "\"output\":\"" + canary + " powershell");
        h.RegisterStagerResponse(doctored);

        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        Assert.False(string.IsNullOrEmpty(artifact.PayloadSha256));

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain(canary, log);
        Assert.Contains("[stager-body-redacted]", log);
    }

    [Fact]
    public async Task Canary_in_plaintext_credential_push_never_appears_in_audit_log()
    {
        const string canary = CanaryPrefix + "CRED_PUSH";
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        h.RegisterCredCreate(id: 7777);

        var pushed = await h.CredBridge.PushToEmpireAsync(new DrederickCredential
        {
            User = "carol",
            Realm = "CORP",
            PasswordSha256 = "f00dface",
            Plaintext = canary,
            SourceHost = "10.10.10.50",
            Source = "manual",
            CredType = "plaintext",
        });
        Assert.True(pushed);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain(canary, log);
        Assert.Contains("\"event\":\"empire.cred.push.success\"", log);

        // The wire request *did* contain the canary (that's how Empire
        // gets the credential); but the audit log must record only its
        // SHA-256, never the plaintext.
        var wire = string.Join("\n", h.CredHandler.RequestBodies);
        Assert.Contains(canary, wire);
    }

    [Fact]
    public async Task Canary_in_portscan_banner_never_appears_in_audit_log()
    {
        const string canary = CanaryPrefix + "PORTSCAN_BANNER";
        using var h = new EmpireTestHarness("10.10.10.0/24", LabPerms());
        var scen = h.LoadScenario("scenario_pivot.json").ApplyCanary(canary);

        h.RegisterStagerResponse(scen.StagerResponseJson);
        var artifact = await h.StagerGenerator.GenerateAsync(
            scen.Listener, EmpireStagerKind.Ps1, scen.Target);
        await h.Exploit.DeliverEmpireArtifactAsync(scen.Target, artifact, h.Permissions);
        var session = h.Sessions.Register(
            h.EmpireServer.Checkin(scen.AgentId, scen.Target, scen.AgentUser, scen.Listener));

        h.TaskClient.Register("powershell/situational_awareness/network/portscan", scen.PortscanOutput!);
        var result = await h.Dispatcher.RunAsync(session, EmpirePostExAction.Portscan);
        Assert.Equal("completed", result.ExitStatus);

        var log = h.ReadAuditLogFlushed();
        Assert.DoesNotContain(canary, log);
    }
}
