using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Scope;
using Xunit;
using EmpireModuleResult = Drederick.PostEx.EmpireModuleResult;
using EmpireParsedFinding = Drederick.PostEx.EmpireParsedFinding;

namespace Drederick.Tests.Autopilot;

public class EmpireAutopilotPhaseTests : IDisposable
{
    private readonly string _outDir;
    private readonly AuditLog _audit;
    private readonly Scope _scope;

    public EmpireAutopilotPhaseTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), "drederick-empire-phase-" + Guid.NewGuid());
        Directory.CreateDirectory(_outDir);
        _audit = new AuditLog(Path.Combine(_outDir, "audit.jsonl"));
        _scope = Scope.LoadFromText("10.0.0.0/24\n", allowBroad: false, labMode: true);
    }

    public void Dispose()
    {
        try { _audit.Dispose(); } catch { }
        try { Directory.Delete(_outDir, recursive: true); } catch { }
    }

    private RunPermissions Permissions(bool payloads = true, bool creds = true, bool destructive = false) =>
        new(allowExecPocs: false, allowCredAttacks: creds, allowPayloads: payloads,
            allowDestructive: destructive, allowDos: false, acknowledgeLockoutRisk: false);

    private CredentialStore Creds() => new(_audit);

    private static ExploitActionResult SuccessAt(string host) =>
        new(new ExploitAction(host, 445, "smb", "PsExec", ExploitCategory.ExecPocs, null, null, null, null),
            Succeeded: true, Skipped: false, Stdout: "", Stderr: "", ExitCode: 0,
            DurationMs: 10, Notes: null);

    [Fact]
    public async Task Disabled_returns_skipped()
    {
        var phase = new EmpireAutopilotPhase(_scope, _audit, Permissions(), Creds(),
            EmpirePhaseConfig.Disabled, new StubServer(), new StubListener(),
            new StubStager(), new StubDispatcher(), new SessionAgentMapper(_audit));

        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });

        Assert.True(r.Skipped);
        Assert.Equal("disabled", r.SkipReason);
    }

    [Fact]
    public async Task Missing_allow_payloads_skips()
    {
        var phase = new EmpireAutopilotPhase(_scope, _audit, Permissions(payloads: false), Creds(),
            new EmpirePhaseConfig { Enabled = true }, new StubServer(), new StubListener(),
            new StubStager(), new StubDispatcher(), new SessionAgentMapper(_audit));

        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });

        Assert.True(r.Skipped);
        Assert.Equal("allow_payloads_required", r.SkipReason);
    }

    [Fact]
    public async Task No_compromised_hosts_skips()
    {
        var phase = new EmpireAutopilotPhase(_scope, _audit, Permissions(), Creds(),
            new EmpirePhaseConfig { Enabled = true }, new StubServer(), new StubListener(),
            new StubStager(), new StubDispatcher(), new SessionAgentMapper(_audit));

        var r = await phase.RunAsync(Array.Empty<ExploitActionResult>());

        Assert.True(r.Skipped);
        Assert.Equal("no_compromised_hosts", r.SkipReason);
    }

    [Fact]
    public async Task Out_of_scope_host_records_scope_refused()
    {
        var phase = new EmpireAutopilotPhase(_scope, _audit, Permissions(), Creds(),
            new EmpirePhaseConfig { Enabled = true }, new StubServer(), new StubListener(),
            new StubStager(), new StubDispatcher(), new SessionAgentMapper(_audit));

        var r = await phase.RunAsync(new[] { SuccessAt("192.168.99.7") });

        Assert.True(r.Skipped);
        Assert.Equal("no_compromised_hosts", r.SkipReason);
    }

    [Fact]
    public async Task ListenerProvisioning_failure_reports_error()
    {
        var listener = new StubListener { FailNext = true };
        var phase = new EmpireAutopilotPhase(_scope, _audit, Permissions(), Creds(),
            new EmpirePhaseConfig { Enabled = true }, new StubServer(), listener,
            new StubStager(), new StubDispatcher(), new SessionAgentMapper(_audit));

        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });

        Assert.False(r.Skipped);
        Assert.NotNull(r.Error);
    }

    private sealed class StubServer : IEmpireServer
    {
        public bool FailNext { get; set; }
        public Task EnsureRunningAsync(CancellationToken ct = default) =>
            FailNext ? Task.FromException(new InvalidOperationException("server down")) : Task.CompletedTask;
        public Task StopAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class StubListener : IEmpireListenerProvisioner
    {
        public bool FailNext { get; set; }
        public Task<(int Id, string Name)> ProvisionAsync(CancellationToken ct = default) =>
            FailNext
                ? Task.FromException<(int, string)>(new InvalidOperationException("listener fail"))
                : Task.FromResult((1, "auto-listener"));
    }

    private sealed class StubStager : IEmpireStagerGenerator
    {
        public Task<string> GenerateAsync(string platform, string listenerName, string kind,
            CancellationToken ct = default) => Task.FromResult($"# stub {platform} {kind}");
    }

    private sealed class StubDispatcher : IEmpirePostExDispatcher
    {
        public Task<EmpireModuleResult> RunAsync(string agentId, string action, IReadOnlyDictionary<string, string>? args = null, CancellationToken ct = default) =>
            Task.FromResult(new EmpireModuleResult(agentId, action, true, "", "",
                new List<EmpireParsedFinding>(), 0));
    }
}
