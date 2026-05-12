using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Scope;

namespace Drederick.Agent;

/// <summary>
/// Hybrid runner: prefer the LLM-driven planner
/// (<see cref="MicrosoftAgentRunner"/>), and fall back to a deterministic
/// runner (typically <see cref="AdaptiveExploitRunner"/> or
/// <see cref="AdaptiveRunner"/>) whenever the LLM path is unavailable
/// (no API key, missing client) or fails for an operational reason
/// (network, auth, rate limit, timeout, transient SDK exception).
///
/// Invariants:
///   • <see cref="ScopeException"/> is NEVER swallowed — scope rejections
///     are an authorization signal and must propagate so the operator
///     sees them. We do not retry the deterministic runner against a
///     scope-rejected target.
///   • <see cref="OperationCanceledException"/> propagates unchanged so
///     Ctrl-C remains responsive and the deterministic runner is not
///     re-invoked after a user-requested cancel.
///   • <see cref="CopilotModelComplianceException"/> propagates unchanged
///     so a selected non-tool model is not hidden by deterministic fallback.
///   • Every fallback writes a <c>hybrid.llm_fallback</c> audit event
///     with the exception type + a SHA-256 digest of the message.
///     We deliberately do not log the full message or stack trace
///     because LLM/SDK error strings can echo back prompt fragments,
///     URLs, or token IDs.
/// </summary>
public sealed class HybridAgentRunner : IReconAgentRunner
{
    private readonly IReconAgentRunner? _llm;
    private readonly IReconAgentRunner _deterministic;
    private readonly AuditLog _audit;

    public HybridAgentRunner(
        IReconAgentRunner? llmInner,
        IReconAgentRunner deterministicInner,
        AuditLog audit)
    {
        _llm = llmInner;
        _deterministic = deterministicInner ?? throw new ArgumentNullException(nameof(deterministicInner));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public async Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase priorKnowledge,
        CancellationToken ct)
    {
        _audit.Record("hybrid.start", new Dictionary<string, object?>
        {
            ["llm_available"] = _llm is not null,
            ["targets"] = targets,
        });

        if (_llm is null)
        {
            // --- htb-hybrid-fallback-transparency ---
            _audit.Record("hybrid.llm_unavailable", new Dictionary<string, object?>
            {
                ["reason"] = "null_llm_runner",
            });
            EmitFallbackEvent(new HybridFallbackEvent(
                Timestamp: DateTimeOffset.UtcNow,
                Stage: HybridFallbackEvent.Stages.Init,
                Reason: HybridFallbackEvent.Reasons.NoApiKey,
                ExceptionType: null,
                MessageHash: null,
                RetryHintSeconds: null,
                FellBackTo: HybridFallbackEvent.FellBack.DeterministicRunner));
            await _deterministic.RunAsync(targets, tools, priorKnowledge, ct).ConfigureAwait(false);
            _audit.Record("hybrid.finish", new Dictionary<string, object?>
            {
                ["path"] = "deterministic",
            });
            return;
        }

        try
        {
            await _llm.RunAsync(targets, tools, priorKnowledge, ct).ConfigureAwait(false);
            _audit.Record("hybrid.finish", new Dictionary<string, object?>
            {
                ["path"] = "llm",
            });
        }
        catch (ScopeException)
        {
            // Authorization signal — must propagate. Do NOT fall back.
            throw;
        }
        catch (OperationCanceledException)
        {
            // User cancellation — propagate; do not invoke the
            // deterministic runner against a cancelled token.
            throw;
        }
        catch (CopilotModelComplianceException)
        {
            // Explicit model non-compliance is operator-visible
            // configuration, not an operational LLM outage to hide.
            throw;
        }
        catch (Exception ex)
        {
            // --- htb-hybrid-fallback-transparency ---
            _audit.Record("hybrid.llm_fallback", new Dictionary<string, object?>
            {
                ["exception_type"] = ex.GetType().FullName,
                ["message_sha256"] = Sha256(ex.Message),
            });
            var (stage, reason) = HybridFallbackEvent.Classify(ex);
            EmitFallbackEvent(new HybridFallbackEvent(
                Timestamp: DateTimeOffset.UtcNow,
                Stage: stage,
                Reason: reason,
                ExceptionType: ex.GetType().FullName,
                MessageHash: HybridFallbackEvent.Sha256Tail(ex.Message),
                RetryHintSeconds: HybridFallbackEvent.ExtractRetryHintSeconds(ex),
                FellBackTo: HybridFallbackEvent.FellBack.DeterministicRunner));
            await _deterministic.RunAsync(targets, tools, priorKnowledge, ct).ConfigureAwait(false);
            _audit.Record("hybrid.finish", new Dictionary<string, object?>
            {
                ["path"] = "deterministic_after_fallback",
            });
        }
    }

    // --- htb-hybrid-fallback-transparency ---
    private void EmitFallbackEvent(HybridFallbackEvent ev)
    {
        _audit.Record(HybridFallbackEvent.EventName, ev.ToAuditFields());
    }

    private static string Sha256(string? s)
    {
        var bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
