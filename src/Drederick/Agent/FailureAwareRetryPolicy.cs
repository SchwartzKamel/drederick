using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Agent;

/// <summary>
/// Per-attempt context passed to retry-aware tool callbacks. <see cref="AggressivenessFactor"/>
/// is in (0, 1]: 1.0 = full aggressiveness, decreasing on each retry so the tool
/// can scale down rps / concurrency / wordlist size. Tools opt-in via
/// <see cref="IRetryAware"/>.
/// </summary>
public sealed record RetryContext(int Attempt, int MaxAttempts, double AggressivenessFactor);

/// <summary>
/// Outcome of a <see cref="FailureAwareRetryPolicy.ExecuteAsync{T}"/> call.
/// <see cref="Result"/> is non-null only on <see cref="Success"/>=true.
/// </summary>
public sealed record RetryOutcome<T>(T? Result, bool Success, int AttemptsUsed, FailureClass? FinalFailure);

/// <summary>
/// Opt-in interface for tools that want their per-attempt aggressiveness
/// scaled down (lower rps, smaller wordlist, fewer concurrent connections).
/// Not used by the policy directly — provided so tool authors can adopt the
/// pattern incrementally without churn.
/// </summary>
public interface IRetryAware
{
    void ApplyRetryContext(RetryContext context);
}

/// <summary>
/// Persistent marker recording that a target/protocol combination is in a
/// credential lockout state. Other credential tools should consult this and
/// refuse to attempt further authentication until <see cref="CooldownUntil"/>.
/// </summary>
public sealed record LockoutMarker(
    string Target,
    string ServiceProtocol,
    DateTimeOffset DetectedAt,
    DateTimeOffset CooldownUntil);

/// <summary>
/// Failure-aware retry policy with per-tool exponential backoff and
/// reduced-aggressiveness retries. Wraps a single tool invocation:
/// <list type="bullet">
///   <item><description>Validates target against <see cref="Scope"/> before the first attempt.</description></item>
///   <item><description>Classifies exceptions via <see cref="ToolFailureClassifier"/>.</description></item>
///   <item><description>Retries recoverable failures up to <c>maxAttempts</c> with the suggested backoff.</description></item>
///   <item><description>Escalates 3 consecutive <c>transient_network</c> failures against the same target to <c>target_dead</c>.</description></item>
///   <item><description>Persists <see cref="LockoutMarker"/>s under <c>out/&lt;host&gt;/lockouts.json</c>.</description></item>
///   <item><description>Records <c>retry.attempt</c> / <c>retry.success</c> / <c>retry.exhausted</c> / <c>retry.target_dead</c> / <c>retry.lockout_detected</c> audit events. Exception messages are SHA-256 hashed; no plaintext secrets leak into the audit log.</description></item>
/// </list>
/// </summary>
public sealed class FailureAwareRetryPolicy
{
    private readonly int _maxAttempts;
    private readonly ToolFailureClassifier _classifier;
    private readonly AuditLog _audit;
    private readonly Scope.Scope? _scope;
    private readonly string? _outDir;
    private readonly Func<TimeSpan, CancellationToken, Task> _sleep;
    private readonly ConcurrentDictionary<string, int> _consecutiveFailures = new();
    private readonly ConcurrentDictionary<string, LockoutMarker> _activeLockouts = new();

    /// <summary>
    /// Construct a policy.
    /// </summary>
    /// <param name="maxAttempts">Maximum total attempts (>= 1).</param>
    /// <param name="classifier">Failure classifier (required).</param>
    /// <param name="audit">Audit log sink (required).</param>
    /// <param name="scope">Optional scope. When non-null, <c>Require(target)</c> is called before the first attempt; <see cref="ScopeException"/> propagates without retry.</param>
    /// <param name="outDir">Optional output directory for lockout persistence (<c>out/&lt;host&gt;/lockouts.json</c>).</param>
    /// <param name="sleep">Optional sleep delegate for testability (default: <see cref="Task.Delay(TimeSpan, CancellationToken)"/>).</param>
    public FailureAwareRetryPolicy(
        int maxAttempts,
        ToolFailureClassifier classifier,
        AuditLog audit,
        Scope.Scope? scope = null,
        string? outDir = null,
        Func<TimeSpan, CancellationToken, Task>? sleep = null)
    {
        if (maxAttempts < 1) throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        _maxAttempts = maxAttempts;
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _scope = scope;
        _outDir = outDir;
        _sleep = sleep ?? ((delay, ct) => delay > TimeSpan.Zero ? Task.Delay(delay, ct) : Task.CompletedTask);
    }

    /// <summary>
    /// Execute <paramref name="work"/> against <paramref name="target"/> with retry semantics.
    /// </summary>
    public async Task<RetryOutcome<T>> ExecuteAsync<T>(
        string toolName,
        string target,
        Func<RetryContext, Task<T>> work,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(toolName);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(work);

        _scope?.Require(target);

        if (IsCurrentlyLockedOut(target, out var existing))
        {
            var cls = new FailureClass(
                Kind: "account_lockout",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: $"target {target} is in cooldown until {existing!.CooldownUntil:o} for protocol {existing.ServiceProtocol}");
            _audit.Record("retry.lockout_detected", new Dictionary<string, object?>
            {
                ["tool"] = toolName,
                ["target"] = target,
                ["protocol"] = existing.ServiceProtocol,
                ["cooldown_until"] = existing.CooldownUntil.ToString("o"),
                ["pre_existing"] = true,
            });
            return new RetryOutcome<T>(default, false, 0, cls);
        }

        FailureClass? lastFailure = null;
        double factor = 1.0;
        for (int attempt = 1; attempt <= _maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            var context = new RetryContext(attempt, _maxAttempts, factor);
            try
            {
                var result = await work(context).ConfigureAwait(false);
                ResetConsecutiveFailures(target);
                _audit.Record("retry.success", new Dictionary<string, object?>
                {
                    ["tool"] = toolName,
                    ["target"] = target,
                    ["attempts_used"] = attempt,
                    ["aggressiveness"] = factor,
                });
                return new RetryOutcome<T>(result, true, attempt, null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (ScopeException)
            {
                // Scope violations propagate immediately — never retried.
                throw;
            }
            catch (Exception ex)
            {
                var classification = _classifier.Classify(
                    toolName: toolName,
                    exception: ex,
                    exitCode: null,
                    stderrOrOutput: ex.Message,
                    attempt: attempt);

                classification = MaybeEscalateToTargetDead(target, classification, toolName);
                lastFailure = classification;

                _audit.Record("retry.attempt", new Dictionary<string, object?>
                {
                    ["tool"] = toolName,
                    ["target"] = target,
                    ["attempt"] = attempt,
                    ["max_attempts"] = _maxAttempts,
                    ["aggressiveness"] = factor,
                    ["kind"] = classification.Kind,
                    ["recoverable"] = classification.Recoverable,
                    ["downgrade"] = classification.SuggestedDowngrade,
                    ["backoff_seconds"] = classification.SuggestedBackoff.TotalSeconds,
                    ["reason"] = classification.Reason,
                    ["exception_type"] = ex.GetType().Name,
                    ["message_sha256"] = HashTail(ex.Message),
                });

                if (classification.Kind == "account_lockout")
                {
                    PersistLockout(target, toolName);
                }

                if (!classification.Recoverable || attempt == _maxAttempts)
                {
                    break;
                }

                await _sleep(classification.SuggestedBackoff, ct).ConfigureAwait(false);
                factor = Math.Max(0.05, factor * 0.8);
            }
        }

        _audit.Record("retry.exhausted", new Dictionary<string, object?>
        {
            ["tool"] = toolName,
            ["target"] = target,
            ["attempts_used"] = _maxAttempts,
            ["final_kind"] = lastFailure?.Kind,
            ["final_reason"] = lastFailure?.Reason,
        });
        return new RetryOutcome<T>(default, false, _maxAttempts, lastFailure);
    }

    /// <summary>True if <paramref name="target"/> currently has an active lockout marker.</summary>
    public bool IsCurrentlyLockedOut(string target, out LockoutMarker? marker)
    {
        if (_activeLockouts.TryGetValue(target, out var m) && m.CooldownUntil > DateTimeOffset.UtcNow)
        {
            marker = m;
            return true;
        }

        // Re-hydrate from disk if available — supports cross-process / cross-tool sharing.
        var path = LockoutPathFor(target);
        if (path is not null && File.Exists(path))
        {
            try
            {
                var existing = JsonSerializer.Deserialize<List<LockoutMarker>>(File.ReadAllText(path)) ?? new();
                var active = existing
                    .Where(e => string.Equals(e.Target, target, StringComparison.OrdinalIgnoreCase)
                                && e.CooldownUntil > DateTimeOffset.UtcNow)
                    .OrderByDescending(e => e.CooldownUntil)
                    .FirstOrDefault();
                if (active is not null)
                {
                    _activeLockouts[target] = active;
                    marker = active;
                    return true;
                }
            }
            catch
            {
                // Treat unreadable lockout file as no-lockout; do not crash recon.
            }
        }

        marker = null;
        return false;
    }

    private FailureClass MaybeEscalateToTargetDead(string target, FailureClass classification, string toolName)
    {
        if (classification.Kind != "transient_network")
        {
            _consecutiveFailures.TryRemove(target, out _);
            return classification;
        }

        var count = _consecutiveFailures.AddOrUpdate(target, 1, (_, prev) => prev + 1);
        if (count > 3)
        {
            _audit.Record("retry.target_dead", new Dictionary<string, object?>
            {
                ["tool"] = toolName,
                ["target"] = target,
                ["consecutive_transient_failures"] = count,
            });
            return new FailureClass(
                Kind: "target_dead",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: $"target {target} appears dead after {count - 1} consecutive transient failures");
        }
        return classification;
    }

    private void ResetConsecutiveFailures(string target) => _consecutiveFailures.TryRemove(target, out _);

    private void PersistLockout(string target, string toolName)
    {
        var marker = new LockoutMarker(
            Target: target,
            ServiceProtocol: toolName,
            DetectedAt: DateTimeOffset.UtcNow,
            CooldownUntil: DateTimeOffset.UtcNow.AddMinutes(30));
        _activeLockouts[target] = marker;

        var path = LockoutPathFor(target);
        if (path is null) return;

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            List<LockoutMarker> existing = new();
            if (File.Exists(path))
            {
                try { existing = JsonSerializer.Deserialize<List<LockoutMarker>>(File.ReadAllText(path)) ?? new(); }
                catch { existing = new(); }
            }
            existing.Add(marker);
            File.WriteAllText(path, JsonSerializer.Serialize(existing, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            _audit.Record("retry.lockout_persist_error", new Dictionary<string, object?>
            {
                ["tool"] = toolName,
                ["target"] = target,
                ["error_type"] = ex.GetType().Name,
            });
        }
    }

    private string? LockoutPathFor(string target)
    {
        if (string.IsNullOrEmpty(_outDir)) return null;
        var safeHost = MakeSafeHostSegment(target);
        return Path.Combine(_outDir, safeHost, "lockouts.json");
    }

    private static string MakeSafeHostSegment(string target)
    {
        var sb = new StringBuilder(target.Length);
        foreach (var c in target)
        {
            sb.Append(char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' ? c : '_');
        }
        return sb.ToString();
    }

    private static string HashTail(string? message)
    {
        var s = message ?? string.Empty;
        if (s.Length > 256) s = s[^256..];
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
