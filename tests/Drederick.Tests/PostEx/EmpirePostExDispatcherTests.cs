using System.Text.Json;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.Memory;
using Drederick.PostEx;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.PostEx;

public class EmpirePostExDispatcherTests
{
    private const string CanaryPlaintext = "CANARY_PLAINTEXT_DO_NOT_LOG";

    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-empire-postex-{Guid.NewGuid():N}.jsonl");

    private static string ResolveFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !Directory.Exists(Path.Combine(dir, "tests", "fixtures", "empire")))
            dir = Path.GetDirectoryName(dir);
        if (dir is null) throw new InvalidOperationException("tests/fixtures/empire not found");
        return Path.Combine(dir, "tests", "fixtures", "empire", name);
    }

    private static string ExtractOutputField(string fixturePath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(fixturePath));
        return doc.RootElement.GetProperty("output").GetString() ?? string.Empty;
    }

    private static EmpireSession WindowsSession() => new(
        "AB12CD34", "10.10.10.5", "CORP\\bob", "lab-http-powershell", DateTimeOffset.UtcNow);

    private static EmpireSession LinuxSession() => new(
        "EF56GH78", "10.10.10.51", "root", "lab-https-python", DateTimeOffset.UtcNow);

    private static (EmpirePostExDispatcher d, FixtureEmpireTaskClient c, AuditLog a, string p, CredentialStore creds, KnowledgeBase kb)
        Build(string scope, RunPermissions? perms = null)
    {
        var s = ScopeLoader.Parse(scope);
        var path = NewAuditPath();
        var audit = new AuditLog(path);
        var creds = new CredentialStore(audit);
        var kb = new KnowledgeBase();
        var client = new FixtureEmpireTaskClient();
        var d = new EmpirePostExDispatcher(
            s, audit,
            perms ?? new RunPermissions(allowExecPocs: true, allowCredAttacks: true, allowDestructive: true),
            client, creds, kb);
        return (d, client, audit, path, creds, kb);
    }

    [Fact]
    public async Task Refuses_out_of_scope_host()
    {
        var (d, _, audit, path, _, _) = Build("10.10.10.0/24");
        try
        {
            var session = new EmpireSession("X", "8.8.8.8", "u", "l", DateTimeOffset.UtcNow);
            await Assert.ThrowsAsync<ScopeException>(() => d.RunAsync(session, EmpirePostExAction.Portscan));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Refuses_cred_action_without_allow_cred_attacks()
    {
        var perms = new RunPermissions(allowExecPocs: true, allowCredAttacks: false);
        var (d, client, audit, path, _, _) = Build("10.10.10.0/24", perms);
        try
        {
            await Assert.ThrowsAsync<PermissionRefusedException>(() =>
                d.RunAsync(WindowsSession(), EmpirePostExAction.LogonPasswords));
            audit.Dispose();
            var log = File.ReadAllText(path);
            Assert.Contains("empire.postex.dispatch.start", log);
            Assert.Contains("empire.postex.dispatch.failure", log);
            Assert.Contains("permission_refused", log);
            Assert.Empty(client.Queued);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Refuses_destructive_action_without_allow_destructive()
    {
        var perms = new RunPermissions(allowExecPocs: true, allowCredAttacks: true, allowDestructive: false);
        var (d, _, audit, path, _, _) = Build("10.10.10.0/24", perms);
        try
        {
            await Assert.ThrowsAsync<PermissionRefusedException>(() =>
                d.RunAsync(WindowsSession(), EmpirePostExAction.PersistenceSchtasks));
            await Assert.ThrowsAsync<PermissionRefusedException>(() =>
                d.RunAsync(LinuxSession(), EmpirePostExAction.PersistenceCron));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Mimikatz_parser_extracts_creds_without_leaking_plaintext()
    {
        var (d, client, audit, path, creds, _) = Build("10.10.10.0/24");
        try
        {
            var fixtureOutput = ExtractOutputField(ResolveFixture("module_mimikatz_response.json"));
            Assert.Contains(CanaryPlaintext, fixtureOutput);

            client.Register("powershell/credentials/mimikatz/logonpasswords", fixtureOutput);

            var result = await d.RunAsync(WindowsSession(), EmpirePostExAction.LogonPasswords);

            Assert.Equal("completed", result.ExitStatus);
            Assert.NotEmpty(result.ParsedFindings);
            Assert.All(result.ParsedFindings, f => Assert.Equal("credential", f.Kind));

            audit.Dispose();
            var log = File.ReadAllText(path);
            Assert.DoesNotContain(CanaryPlaintext, log);

            foreach (var f in result.ParsedFindings)
                foreach (var kv in f.Fields)
                    Assert.DoesNotContain(CanaryPlaintext, kv.Value);

            Assert.False(string.IsNullOrEmpty(result.OutputDigest));
            Assert.True(creds.Count >= 1);

            var withNtlm = result.ParsedFindings.FirstOrDefault(f => f.Fields.ContainsKey("ntlm"));
            Assert.NotNull(withNtlm);

            var withPwd = result.ParsedFindings.FirstOrDefault(f => f.Fields.ContainsKey("password_sha256"));
            Assert.NotNull(withPwd);
            Assert.False(withPwd!.Fields.ContainsKey("password"));
            Assert.False(withPwd.Fields.ContainsKey("plaintext"));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Portscan_parser_feeds_KnowledgeBase_pivot_findings()
    {
        var (d, client, audit, path, _, kb) = Build("10.10.10.0/24");
        try
        {
            var output = ExtractOutputField(ResolveFixture("module_portscan_response.json"));
            client.Register("powershell/situational_awareness/network/portscan", output);

            var session = WindowsSession();
            var result = await d.RunAsync(session, EmpirePostExAction.Portscan);

            Assert.Equal("completed", result.ExitStatus);
            Assert.NotEmpty(result.ParsedFindings);
            Assert.All(result.ParsedFindings, f => Assert.Equal("open_ports", f.Kind));

            var pivots = kb.FindPivotsBySource($"session:{session.AgentId}");
            Assert.NotEmpty(pivots);
            var byIp = pivots.ToDictionary(p => p.Ip);
            Assert.Contains("10.10.10.5", byIp.Keys);
            Assert.Contains(22, byIp["10.10.10.5"].OpenPorts);
            Assert.Contains(80, byIp["10.10.10.5"].OpenPorts);
            Assert.Contains(445, byIp["10.10.10.5"].OpenPorts);
            Assert.Contains("10.10.10.7", byIp.Keys);
            Assert.Contains(3389, byIp["10.10.10.7"].OpenPorts);

            audit.Dispose();
            var log = File.ReadAllText(path);
            Assert.Contains("empire.postex.dispatch.start", log);
            Assert.Contains(".queued", log);
            Assert.Contains(".result", log);
            Assert.Contains("empire.postex.dispatch.success", log);
            Assert.Contains("output_sha256", log);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Unsupported_action_returns_typed_result_and_records_failure()
    {
        var (d, _, audit, path, _, _) = Build("10.10.10.0/24");
        try
        {
            var result = await d.RunAsync(WindowsSession(), EmpirePostExAction.SshKeys);
            Assert.Equal("unsupported", result.ExitStatus);
            Assert.NotNull(result.Error);

            audit.Dispose();
            var log = File.ReadAllText(path);
            Assert.Contains("empire.postex.dispatch.failure", log);
            Assert.Contains("unsupported", log);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Successful_dispatch_records_output_sha256_and_truncates_at_64KB()
    {
        var (d, client, audit, path, _, _) = Build("10.10.10.0/24");
        try
        {
            var huge = new string('A', EmpirePostExDispatcher.OutputTruncateBytes + 10_000);
            client.Register("powershell/privesc/sherlock", huge);

            var result = await d.RunAsync(WindowsSession(), EmpirePostExAction.Sherlock);

            Assert.Equal("completed", result.ExitStatus);
            Assert.Equal(EmpirePostExDispatcher.OutputTruncateBytes, result.OutputTruncated.Length);
            Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(huge), result.OutputBytes);
            Assert.False(string.IsNullOrEmpty(result.OutputDigest));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Transport_failure_recorded_and_returns_error_result()
    {
        var (d, _, audit, path, _, _) = Build("10.10.10.0/24");
        try
        {
            var result = await d.RunAsync(WindowsSession(), EmpirePostExAction.Portscan);
            Assert.Equal("error", result.ExitStatus);
            Assert.NotNull(result.Error);

            audit.Dispose();
            var log = File.ReadAllText(path);
            Assert.Contains("empire.postex.dispatch.failure", log);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public void Constructor_rejects_null_dependencies()
    {
        var path = NewAuditPath();
        using var audit = new AuditLog(path);
        try
        {
            var scope = ScopeLoader.Parse("10.0.0.0/16");
            var perms = new RunPermissions();
            var client = new FixtureEmpireTaskClient();
            Assert.Throws<ArgumentNullException>(() => new EmpirePostExDispatcher(null!, audit, perms, client));
            Assert.Throws<ArgumentNullException>(() => new EmpirePostExDispatcher(scope, null!, perms, client));
            Assert.Throws<ArgumentNullException>(() => new EmpirePostExDispatcher(scope, audit, null!, client));
            Assert.Throws<ArgumentNullException>(() => new EmpirePostExDispatcher(scope, audit, perms, null!));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}
