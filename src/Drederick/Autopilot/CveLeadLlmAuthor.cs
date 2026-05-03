using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Scope;

namespace Drederick.Autopilot;

/// <summary>
/// Bridges the cve-lead router (GAP-033) and the
/// <see cref="LlmExecShellTool"/> (1ec7dd7) on the unfetchable-PoC path.
///
/// Why this exists: facts.htb R3+R4 burned 640/640 cve-lead actions to
/// "unfetchable" because no source had a cached/on-demand artifact for the
/// matched CVEs. The fight that won (R5) had a Copilot-driver author shell
/// commands from its own CVE knowledge. Drederick now has both primitives
/// in-tree (router + exec_shell) but no glue. This is the glue: when the
/// PoC aggregator returns nothing, prompt the LLM with structured context
/// and a bounded shell-runner; on a successful authoring step the result
/// flows back into the autopilot loop as a normal exploit attempt.
///
/// Hard rules — every one of these is load-bearing:
/// <list type="bullet">
///   <item>Scope is re-validated on the bridge before any LLM round-trip
///         (defense-in-depth on top of <see cref="LlmExecShellTool"/>'s
///         own scope check).</item>
///   <item>Permission gate: master <see cref="RunPermissions.AllowCveLeadLlmAuthor"/>
///         + dependency <see cref="RunPermissions.AllowExecShell"/>. With
///         either off, the bridge short-circuits to skip without ever
///         calling the LLM.</item>
///   <item>Tool budget: at most ONE LLM Func invocation and ONE
///         <c>exec_shell</c> spawn per cve-lead. Second exec_shell call
///         is refused via <see cref="BudgetedShellRunner"/> with a
///         <c>cve.lead.llm_author.budget_exceeded</c> audit event.</item>
///   <item>Plaintext discipline: prompt content is digested
///         (<c>prompt_sha256</c>) before audit; raw banner / cred /
///         hash bytes never touch <c>audit.jsonl</c>.</item>
///   <item>Loop trap: per-run <c>_attempted_cves</c> set
///         (<see cref="ConcurrentDictionary{TKey, TValue}"/>) keyed by
///         <c>CVE@target</c> prevents the planner re-emitting the same
///         dead lead from costing additional LLM calls.</item>
/// </list>
/// </summary>
public sealed class CveLeadLlmAuthor
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly RunPermissions _permissions;
    private readonly LlmExecShellTool? _execShell;
    private readonly CveLeadLlmAuthorFunc? _llm;

    public CveLeadLlmAuthor(
        Scope.Scope scope,
        AuditLog audit,
        RunPermissions permissions,
        LlmExecShellTool? execShell,
        CveLeadLlmAuthorFunc? llm)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(permissions);
        _scope = scope;
        _audit = audit;
        _permissions = permissions;
        _execShell = execShell;
        _llm = llm;
    }

    /// <summary>Compose <see cref="MakeAttemptKey"/> from a CVE id and target.</summary>
    public static string MakeAttemptKey(string cveId, string target)
        => $"{(cveId ?? "").ToUpperInvariant()}@{target ?? ""}";

    /// <summary>
    /// Attempt to author an <c>exec_shell</c> command for the dead-end
    /// <paramref name="action"/>. The caller (typically
    /// <see cref="AutopilotRunner"/>) supplies the per-run
    /// <paramref name="attemptedCves"/> map so we don't re-author the
    /// same (cve, target) twice in one run.
    ///
    /// Throws <see cref="ScopeException"/> if <c>action.Target</c> is
    /// out-of-scope. Every other failure mode (no key, LLM timeout,
    /// model declined, budget exceeded) is caught and reflected in the
    /// returned <see cref="CveLeadLlmAuthorResult"/> + audit log; the
    /// autopilot loop continues.
    /// </summary>
    public async Task<CveLeadLlmAuthorResult> TryAuthorAsync(
        ExploitAction action,
        ConcurrentDictionary<string, byte> attemptedCves,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(attemptedCves);

        if (string.IsNullOrWhiteSpace(action.CveId))
            return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.NoCveId, "missing cve id");

        var cve = action.CveId!.ToUpperInvariant();
        var target = action.Target;

        // Defense-in-depth: scope is re-validated by exec_shell, but the
        // bridge fails fast and audits before any LLM round-trip.
        _scope.Require(target);

        // Master gate. If off, behavior is exactly the prior cve-lead
        // skip path — no LLM call, no audit noise.
        if (!_permissions.AllowCveLeadLlmAuthor)
            return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.NotEnabled,
                "AllowCveLeadLlmAuthor disabled");

        // Dependency gate. The LLM has nothing to do without exec_shell;
        // model authoring + no spawn capability == burned API quota.
        if (!_permissions.AllowExecShell)
            return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.ExecShellDisabled,
                "AllowExecShell disabled (cve-lead LLM author depends on it)");

        // Wiring gate. No LLM client → emit no_llm_key (operational, not
        // a refusal). No exec_shell tool wired → same shape.
        if (_execShell is null || _llm is null)
        {
            _audit.Record("cve.lead.llm_author.skip", new Dictionary<string, object?>
            {
                ["cve"] = cve,
                ["target"] = target,
                ["reason"] = "no_llm_key",
            });
            _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
            {
                ["cve"] = cve,
                ["target"] = target,
                ["outcome"] = "no_llm_key",
            });
            return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.NoLlmKey,
                "no LLM client configured");
        }

        // Loop guard: same (cve, target) only ever attempted once per run.
        var attemptKey = MakeAttemptKey(cve, target);
        if (!attemptedCves.TryAdd(attemptKey, 0))
        {
            return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.AlreadyAttempted,
                $"already attempted this run: {attemptKey}");
        }

        var ctx = new CveLeadPromptContext(
            CveId: cve,
            Target: target,
            Port: action.Port,
            Service: action.Protocol,
            Url: action.Url,
            Reason: action.Reason,
            BannerHint: null);

        var promptDigest = ctx.ComputePromptDigest();

        _audit.Record("cve.lead.llm_author.start", new Dictionary<string, object?>
        {
            ["cve"] = cve,
            ["target"] = target,
            ["service"] = ctx.Service,
            ["port"] = ctx.Port,
            ["prompt_sha256"] = promptDigest,
        });

        var shell = new BudgetedShellRunner(_execShell, target, _audit, cve);

        CveLeadLlmDecision decision;
        try
        {
            decision = await _llm(ctx, shell, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (ScopeException) { throw; }
        catch (Exception ex)
        {
            _audit.Record("cve.lead.llm_author.skip", new Dictionary<string, object?>
            {
                ["cve"] = cve,
                ["target"] = target,
                ["reason"] = $"llm_error: {ex.GetType().Name}",
            });
            _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
            {
                ["cve"] = cve,
                ["target"] = target,
                ["outcome"] = "llm_error",
            });
            return CveLeadLlmAuthorResult.Errored(ex.Message);
        }

        switch (decision)
        {
            case CveLeadLlmDecision.ShellAuthored sa:
                {
                    _audit.Record("cve.lead.llm_author.shell_authored", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["argv_digest"] = sa.Result.ArgvDigest,
                    });
                    _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["outcome"] = "shell_authored",
                        ["exit_code"] = sa.Result.ExitCode,
                    });
                    return new CveLeadLlmAuthorResult(
                        Outcome: CveLeadLlmAuthorOutcome.ShellAuthored,
                        Reason: $"shell authored (exit={sa.Result.ExitCode})",
                        ShellResult: sa.Result);
                }

            case CveLeadLlmDecision.Skip s:
                {
                    _audit.Record("cve.lead.llm_author.skip", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["reason"] = s.Reason,
                    });
                    _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["outcome"] = "llm_skipped",
                    });
                    return CveLeadLlmAuthorResult.Skipped(CveLeadLlmAuthorOutcome.LlmSkipped, s.Reason);
                }

            case CveLeadLlmDecision.Error e:
                {
                    _audit.Record("cve.lead.llm_author.skip", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["reason"] = $"llm_error: {e.Message}",
                    });
                    _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
                    {
                        ["cve"] = cve,
                        ["target"] = target,
                        ["outcome"] = "llm_error",
                    });
                    return CveLeadLlmAuthorResult.Errored(e.Message);
                }

            default:
                _audit.Record("cve.lead.llm_author.finish", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                    ["target"] = target,
                    ["outcome"] = "llm_error",
                });
                return CveLeadLlmAuthorResult.Errored("unknown decision shape");
        }
    }

    /// <summary>
    /// Bounded wrapper around <see cref="LlmExecShellTool.RunAsync"/>.
    /// Enforces the per-fallback exec_shell budget (1) and emits a
    /// <c>cve.lead.llm_author.budget_exceeded</c> audit event on the
    /// second attempt before throwing
    /// <see cref="CveLeadShellBudgetExceededException"/>.
    /// </summary>
    private sealed class BudgetedShellRunner : ICveLeadShellRunner
    {
        private readonly LlmExecShellTool _tool;
        private readonly string _target;
        private readonly AuditLog _audit;
        private readonly string _cve;
        private int _calls;

        public BudgetedShellRunner(LlmExecShellTool tool, string target, AuditLog audit, string cve)
        {
            _tool = tool;
            _target = target;
            _audit = audit;
            _cve = cve;
        }

        public int CallCount => Volatile.Read(ref _calls);

        public async Task<ExecShellResult> RunAsync(
            string command, string? workingDirHint, CancellationToken ct)
        {
            var n = Interlocked.Increment(ref _calls);
            if (n > 1)
            {
                _audit.Record("cve.lead.llm_author.budget_exceeded", new Dictionary<string, object?>
                {
                    ["cve"] = _cve,
                    ["target"] = _target,
                    ["call_index"] = n,
                });
                throw new CveLeadShellBudgetExceededException(
                    $"cve-lead exec_shell budget exceeded (call {n} > 1)");
            }
            return await _tool.RunAsync(command, _target, workingDirHint, timeoutSeconds: null, ct)
                .ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Structured snapshot of everything the LLM is allowed to see when
/// authoring a fallback command. <see cref="BannerHint"/> is the only
/// field that may carry captured plaintext; if populated the bridge
/// digests the canonical form before audit so banners do not leak.
/// </summary>
public sealed record CveLeadPromptContext(
    string CveId,
    string Target,
    int Port,
    string? Service,
    string? Url,
    string? Reason,
    string? BannerHint)
{
    /// <summary>SHA-256 of the canonical context — safe to audit.</summary>
    public string ComputePromptDigest()
    {
        var sb = new StringBuilder();
        sb.Append("cve=").Append(CveId).Append('|');
        sb.Append("target=").Append(Target).Append('|');
        sb.Append("port=").Append(Port).Append('|');
        sb.Append("service=").Append(Service ?? "").Append('|');
        sb.Append("url=").Append(Url ?? "").Append('|');
        sb.Append("reason=").Append(Reason ?? "").Append('|');
        sb.Append("banner=").Append(BannerHint ?? "");
        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

/// <summary>One-shot decision returned by the LLM author Func.</summary>
public abstract record CveLeadLlmDecision
{
    /// <summary>Model declined to author (no idea, low confidence, etc.).</summary>
    public sealed record Skip(string Reason) : CveLeadLlmDecision;

    /// <summary>Model authored and ran an exec_shell command via the bounded
    /// runner; carries the captured <see cref="ExecShellResult"/>.</summary>
    public sealed record ShellAuthored(ExecShellResult Result) : CveLeadLlmDecision;

    /// <summary>Model layer reported an internal error short of an exception
    /// (e.g. malformed response, parsing failure).</summary>
    public sealed record Error(string Message) : CveLeadLlmDecision;
}

/// <summary>Bounded handle the LLM Func uses to invoke exec_shell.</summary>
public interface ICveLeadShellRunner
{
    Task<ExecShellResult> RunAsync(string command, string? workingDirHint, CancellationToken ct);
}

/// <summary>The Func the bridge invokes for one LLM round-trip. Implementations
/// may call <paramref name="shell"/> at most once.</summary>
public delegate Task<CveLeadLlmDecision> CveLeadLlmAuthorFunc(
    CveLeadPromptContext ctx,
    ICveLeadShellRunner shell,
    CancellationToken ct);

/// <summary>Outcome bucket for <see cref="CveLeadLlmAuthor.TryAuthorAsync"/>.</summary>
public enum CveLeadLlmAuthorOutcome
{
    NotEnabled,
    ExecShellDisabled,
    NoLlmKey,
    NoCveId,
    AlreadyAttempted,
    LlmSkipped,
    LlmError,
    ShellAuthored,
}

/// <summary>Result returned by <see cref="CveLeadLlmAuthor.TryAuthorAsync"/>.</summary>
public sealed record CveLeadLlmAuthorResult(
    CveLeadLlmAuthorOutcome Outcome,
    string Reason,
    ExecShellResult? ShellResult = null)
{
    public bool DidAuthorShell => Outcome == CveLeadLlmAuthorOutcome.ShellAuthored;

    public static CveLeadLlmAuthorResult Skipped(CveLeadLlmAuthorOutcome o, string reason)
        => new(o, reason, null);

    public static CveLeadLlmAuthorResult Errored(string reason)
        => new(CveLeadLlmAuthorOutcome.LlmError, reason, null);
}

/// <summary>Raised by <see cref="ICveLeadShellRunner.RunAsync"/> when the
/// LLM Func attempts to invoke exec_shell more than once per fallback.</summary>
public sealed class CveLeadShellBudgetExceededException : Exception
{
    public CveLeadShellBudgetExceededException(string message) : base(message) { }
}
