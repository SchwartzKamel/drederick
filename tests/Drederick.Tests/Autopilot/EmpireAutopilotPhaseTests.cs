using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.Scope;
using Xunit;
using EmpireModuleResult = Drederick.PostEx.EmpireModuleResult;
using EmpireParsedFinding = Drederick.PostEx.EmpireParsedFinding;

namespace Drederick.Tests.Autopilot;

public class EmpireAutopilotPhaseTests : IDisposable
{
    private readonly string _outDir;
    private readonly AuditLog _audit;
    private readonly Drederick.Scope.Scope _scope;

    public EmpireAutopilotPhaseTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), "drederick-empire-phase-" + Guid.NewGuid());
        Directory.CreateDirectory(_outDir);
        _audit = new AuditLog(Path.Combine(_outDir, "audit.jsonl"));
        _scope = ScopeLoader.Parse("10.0.0.0/24\n");
    }

    public void Dispose()
    {
        try { _audit.Dispose(); } catch { }
        try { Directory.Delete(_outDir, recursive: true); } catch { }
    }

    private RunPermissions Permissions(bool payloads = true, bool creds = true) =>
        new(allowExecPocs: false, allowCredAttacks: creds, allowPayloads: payloads,
            allowDestructive: false, allowDos: false, acknowledgeLockoutRisk: false);

    private CredentialStore Creds() => new(_audit);

    private static ExploitActionResult SuccessAt(string host) =>
        new()
        {
            Action = new ExploitAction { Target = host, Port = 445, Protocol = "smb", Tool = "msfrc" },
            Succeeded = true,
            Skipped = false,
            ExitCode = 0,
            DurationMs = 10,
        };

    private EmpireAutopilotPhase MakePhase(
        EmpirePhaseConfig config,
        RunPermissions? perms = null,
        IEmpireServer? server = null,
        IEmpireListenerProvisioner? listener = null,
        IEmpireStagerGenerator? stager = null,
        IEmpirePostExDispatcher? dispatcher = null)
        => new(_scope, _audit, perms ?? Permissions(), config,
            server ?? new StubServer(), listener ?? new StubListener(),
            stager ?? new StubStager(), dispatcher ?? new StubDispatcher(),
            new SessionAgentMapper(), Creds(),
            new EmpireListenerSpec("auto", "0.0.0.0", 8443));

    [Fact]
    public async Task Disabled_returns_skipped()
    {
        var phase = MakePhase(EmpirePhaseConfig.Disabled);
        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });
        Assert.True(r.Skipped);
        Assert.Equal("disabled", r.SkipReason);
    }

    [Fact]
    public async Task Missing_allow_payloads_skips()
    {
        var phase = MakePhase(new EmpirePhaseConfig(enabled: true), Permissions(payloads: false));
        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });
        Assert.True(r.Skipped);
        Assert.Equal("allow_payloads_required", r.SkipReason);
    }

    [Fact]
    public async Task No_compromised_hosts_skips()
    {
        var phase = MakePhase(new EmpirePhaseConfig(enabled: true));
        var r = await phase.RunAsync(Array.Empty<ExploitActionResult>());
        Assert.True(r.Skipped);
        Assert.Equal("no_compromised_hosts", r.SkipReason);
    }

    [Fact]
    public async Task Out_of_scope_host_records_scope_refused_per_host()
    {
        var phase = MakePhase(new EmpirePhaseConfig(enabled: true));
        var r = await phase.RunAsync(new[] { SuccessAt("192.168.99.7") });
        Assert.False(r.Skipped);
        Assert.Contains(r.HostResults, h => h.Status == "scope_refused");
    }

    [Fact]
    public async Task Listener_failure_reports_error()
    {
        var listener = new StubListener { FailNext = true };
        var phase = MakePhase(new EmpirePhaseConfig(enabled: true), listener: listener);
        var r = await phase.RunAsync(new[] { SuccessAt("10.0.0.5") });
        Assert.False(r.Skipped);
        Assert.NotNull(r.Error);
    }

    private sealed class StubServer : IEmpireServer
    {
        private bool _running;
        public bool FailNext { get; set; }
        public bool IsRunning => _running;
        public Task StartAsync(CancellationToken ct = default)
        {
            if (FailNext) return Task.FromException(new InvalidOperationException("server down"));
            _running = true;
            return Task.CompletedTask;
        }
        public Task StopAsync(CancellationToken ct = default) { _running = false; return Task.CompletedTask; }
    }

    private sealed class StubListener : IEmpireListenerProvisioner
    {
        public bool FailNext { get; set; }
        public Task<EmpireListener> EnsureListenerAsync(EmpireListenerSpec spec, CancellationToken ct = default) =>
            FailNext
                ? Task.FromException<EmpireListener>(new InvalidOperationException("listener fail"))
                : Task.FromResult(new EmpireListener(1, spec.Name, spec.Type, spec.Host, spec.Port));
    }

    private sealed class StubStager : IEmpireStagerGenerator
    {
        public Task<EmpireDeliveryArtifact> GenerateAsync(string listenerName, EmpireStagerKind kind,
            string target, CancellationToken ct = default) =>
            Task.FromResult(new EmpireDeliveryArtifact(kind, listenerName, target, "", "0", 0));
    }

    private sealed class StubDispatcher : IEmpirePostExDispatcher
    {
        public Task<EmpireModuleResult> RunAsync(EmpireSession session, Drederick.PostEx.EmpirePostExAction action,
            IReadOnlyDictionary<string, string>? parameters = null, CancellationToken ct = default) =>
            Task.FromResult(new EmpireModuleResult(session.AgentId, action.ToString(),
                "ok", "0", 0, "", new List<EmpireParsedFinding>(), null));
    }
}
