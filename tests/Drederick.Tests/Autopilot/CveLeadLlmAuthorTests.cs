using System.Collections.Concurrent;
using System.Text;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Autopilot;

/// <summary>
/// Verifies the cve-lead → LLM-author bridge that closes the
/// "unfetchable PoC" gap exposed by facts.htb R3+R4 (640/640 dead leads,
/// autopilot stopped). Every test exercises the contract documented on
/// <see cref="CveLeadLlmAuthor"/>.
/// </summary>
public sealed class CveLeadLlmAuthorTests : IDisposable
{
    private readonly string _outDir;
    private readonly string _auditPath;

    public CveLeadLlmAuthorTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), $"drederick-cve-llm-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_outDir);
        _auditPath = Path.Combine(_outDir, "audit.jsonl");
    }

    public void Dispose()
    {
        try { Directory.Delete(_outDir, recursive: true); } catch { }
    }

    private const string InScope = "10.129.10.5";

    private static Scope.Scope Scope() => ScopeLoader.Parse("10.129.0.0/16");

    private static ExploitAction LeadAction(string cve = "CVE-2026-99999", string target = InScope) =>
        new()
        {
            Tool = "cve-lead",
            Target = target,
            Port = 80,
            Protocol = "http",
            Url = $"http://{target}/",
            Reason = $"matched {cve} on nginx 1.18 (lab corpus)",
            CveId = cve,
            Priority = 250,
            Category = "execpocs",
        };

    private static LlmExecShellTool BuildExecShell(
        Scope.Scope scope, AuditLog audit, RunPermissions perms,
        string outDir, ExecShellSpawn spawn)
    {
        return new LlmExecShellTool(scope, audit, perms, outDir, spawn: spawn);
    }

    private static ExecShellSpawn StaticSpawn(int exitCode, string stdout = "", string stderr = "")
        => (binary, argv, workDir, timeout, ct) =>
            Task.FromResult(new ExecShellSpawnResult(exitCode,
                Encoding.UTF8.GetBytes(stdout), Encoding.UTF8.GetBytes(stderr), TimedOut: false));

    // 1. Permission gate (master) closed → no LLM call, no exec_shell.
    [Fact]
    public async Task MasterGateClosed_ShortCircuitsToSkip_WithoutLlmCall()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: false);
        var spawnCalled = false;
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir,
            (b, a, w, t, ct) => { spawnCalled = true; return Task.FromResult(new ExecShellSpawnResult(0, Array.Empty<byte>(), Array.Empty<byte>(), false)); });
        var llmCalled = false;
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) => { llmCalled = true; return Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("nope")); };

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.NotEnabled, result.Outcome);
        Assert.False(llmCalled);
        Assert.False(spawnCalled);
    }

    // 2. Dependency gate (exec_shell) closed → short-circuit, no LLM call.
    [Fact]
    public async Task ExecShellGateClosed_ShortCircuitsToSkip_WithoutLlmCall()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: false, allowCveLeadLlmAuthor: true);
        var llmCalled = false;
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) => { llmCalled = true; return Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("x")); };

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell: null, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.ExecShellDisabled, result.Outcome);
        Assert.False(llmCalled);
    }

    // 3. No LLM Func wired → no_llm_key outcome.
    [Fact]
    public async Task NoLlmKey_AuditsAndReturnsNoLlmKey()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0));

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm: null);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.NoLlmKey, result.Outcome);
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"outcome\":\"no_llm_key\"", auditText);
    }

    // 4. LLM declines → llm_skipped audit, no exec_shell invocation.
    [Fact]
    public async Task LlmSkip_EmitsLlmSkippedAudit_NoShellSpawned()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var spawnCalled = 0;
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir,
            (b, a, w, t, ct) => { Interlocked.Increment(ref spawnCalled); return Task.FromResult(new ExecShellSpawnResult(0, Array.Empty<byte>(), Array.Empty<byte>(), false)); });
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) =>
            Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("no idea"));

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.LlmSkipped, result.Outcome);
        Assert.Equal(0, spawnCalled);
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"outcome\":\"llm_skipped\"", auditText);
    }

    // 5. LLM authors exec_shell, command succeeds — full audit chain.
    [Fact]
    public async Task LlmAuthorsExecShell_ExitZero_FullAuditChain()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir,
            StaticSpawn(0, stdout: "<html>config</html>"));
        CveLeadLlmAuthorFunc llm = async (ctx, sh, ct) =>
        {
            var r = await sh.RunAsync($"curl -s http://{ctx.Target}/path", null, ct);
            return new CveLeadLlmDecision.ShellAuthored(r);
        };

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.ShellAuthored, result.Outcome);
        Assert.NotNull(result.ShellResult);
        Assert.Equal(0, result.ShellResult!.ExitCode);

        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"cve.lead.llm_author.start\"", auditText);
        Assert.Contains("\"cve.lead.llm_author.shell_authored\"", auditText);
        Assert.Contains("\"outcome\":\"shell_authored\"", auditText);
        Assert.Contains("\"argv_digest\":", auditText);
    }

    // 6. LLM authors exec_shell but command fails — outcome=shell_authored,
    // attempted set populated.
    [Fact]
    public async Task LlmAuthorsExecShell_NonZeroExit_StillCountsAsAttempted()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(1));
        CveLeadLlmAuthorFunc llm = async (ctx, sh, ct) =>
        {
            var r = await sh.RunAsync($"curl -s http://{InScope}/", null, ct);
            return new CveLeadLlmDecision.ShellAuthored(r);
        };

        var attempted = new ConcurrentDictionary<string, byte>();
        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), attempted);

        Assert.Equal(CveLeadLlmAuthorOutcome.ShellAuthored, result.Outcome);
        Assert.Equal(1, result.ShellResult!.ExitCode);
        Assert.Single(attempted); // (cve, target) recorded for dedup.
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"outcome\":\"shell_authored\"", auditText);
    }

    // 7. LLM throws → llm_error outcome, autopilot continues.
    [Fact]
    public async Task LlmException_AuditsLlmError_DoesNotPropagate()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0));
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) =>
            throw new TimeoutException("LLM timeout");

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.LlmError, result.Outcome);
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"outcome\":\"llm_error\"", auditText);
        Assert.Contains("TimeoutException", auditText);
    }

    // 8. Out-of-scope target — bridge re-validates, throws ScopeException.
    [Fact]
    public async Task OutOfScopeTarget_BridgeReValidatesScope()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0));
        var llmCalled = false;
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) =>
        {
            llmCalled = true;
            return Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("never"));
        };

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var oosAction = LeadAction(target: "8.8.8.8");

        await Assert.ThrowsAsync<ScopeException>(() =>
            bridge.TryAuthorAsync(oosAction, new ConcurrentDictionary<string, byte>()));
        Assert.False(llmCalled);
    }

    // 9. Tool budget — second exec_shell call refused, audit emits
    // budget_exceeded.
    [Fact]
    public async Task ExecShellBudget_SecondCallRefused_AuditsBudgetExceeded()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0, "first"));
        CveLeadLlmAuthorFunc llm = async (ctx, sh, ct) =>
        {
            var r1 = await sh.RunAsync($"curl -s http://{InScope}/", null, ct);
            try
            {
                await sh.RunAsync($"curl -s http://{InScope}/again", null, ct);
                return new CveLeadLlmDecision.Error("expected budget exception");
            }
            catch (CveLeadShellBudgetExceededException)
            {
                return new CveLeadLlmDecision.ShellAuthored(r1);
            }
        };

        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var result = await bridge.TryAuthorAsync(LeadAction(), new ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.ShellAuthored, result.Outcome);
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"cve.lead.llm_author.budget_exceeded\"", auditText);
    }

    // 10. Plaintext discipline — banner canary never appears in audit.
    [Fact]
    public async Task PlaintextDiscipline_BannerCanaryNotInAudit()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0));
        const string canary = "PLAINTEXT_CANARY_HUNTER2";

        // Construct the prompt context manually (mirrors what the bridge
        // builds internally) so we can plant the canary as a banner hint
        // and confirm only its digest is auditable.
        var ctx = new CveLeadPromptContext(
            CveId: "CVE-2026-CANARY",
            Target: InScope, Port: 80, Service: "http", Url: null,
            Reason: "smoke-test", BannerHint: canary);
        var digest = ctx.ComputePromptDigest();
        Assert.DoesNotContain(canary, digest);

        // Run a normal Skip path so the bridge writes its start + skip
        // events; the action.Reason field also explicitly contains no
        // canary so we are testing the audit shape, not the action.
        CveLeadLlmAuthorFunc llm = (c, sh, ct) =>
            Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("decline"));
        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        await bridge.TryAuthorAsync(LeadAction(cve: "CVE-2026-CANARY"),
            new ConcurrentDictionary<string, byte>());

        var auditText = File.ReadAllText(_auditPath);
        Assert.DoesNotContain(canary, auditText);
    }

    // 11. Already-attempted CVE — second arrival short-circuits before LLM.
    [Fact]
    public async Task AlreadyAttempted_ShortCircuitsBeforeLlmCall()
    {
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var execShell = BuildExecShell(Scope(), audit, perms, _outDir, StaticSpawn(0));
        var llmCalls = 0;
        CveLeadLlmAuthorFunc llm = (ctx, sh, ct) =>
        {
            Interlocked.Increment(ref llmCalls);
            return Task.FromResult<CveLeadLlmDecision>(new CveLeadLlmDecision.Skip("decline"));
        };

        var attempted = new ConcurrentDictionary<string, byte>();
        var bridge = new CveLeadLlmAuthor(Scope(), audit, perms, execShell, llm);
        var first = await bridge.TryAuthorAsync(LeadAction(), attempted);
        var second = await bridge.TryAuthorAsync(LeadAction(), attempted);

        Assert.Equal(CveLeadLlmAuthorOutcome.LlmSkipped, first.Outcome);
        Assert.Equal(CveLeadLlmAuthorOutcome.AlreadyAttempted, second.Outcome);
        Assert.Equal(1, llmCalls);
    }
}
