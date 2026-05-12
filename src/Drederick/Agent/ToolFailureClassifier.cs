using System.Globalization;
using System.Net.Http;
using System.Net.Sockets;

namespace Drederick.Agent;

/// <summary>
/// Classification of a single tool invocation failure. Drives the
/// <see cref="FailureAwareRetryPolicy"/> retry/backoff decisions.
/// </summary>
/// <param name="Kind">Stable identifier (snake_case) for the failure class.</param>
/// <param name="Recoverable">True if a retry has any chance of succeeding.</param>
/// <param name="SuggestedBackoff">How long to wait before retrying.</param>
/// <param name="SuggestedDowngrade">
/// Hint for the retry: <c>reduce_concurrency</c>, <c>reduce_rps</c>,
/// <c>switch_to_fallback</c>, or null when no downgrade is suggested.
/// </param>
/// <param name="Reason">Short human-readable explanation.</param>
public sealed record FailureClass(
    string Kind,
    bool Recoverable,
    TimeSpan SuggestedBackoff,
    string? SuggestedDowngrade,
    string Reason);

/// <summary>
/// Classifies tool failures (exception + exit code + stderr/output snippet)
/// into one of the known <see cref="FailureClass"/> kinds. Pure / stateless;
/// per-target escalation lives in <see cref="FailureAwareRetryPolicy"/>.
/// </summary>
public sealed class ToolFailureClassifier
{
    private static readonly TimeSpan MaxNetworkBackoff = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan DefaultRateLimitBackoff = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Classify a tool failure.
    /// </summary>
    /// <param name="toolName">Name of the tool that just failed (audit only).</param>
    /// <param name="exception">Exception thrown (may be null when only an exit code is available).</param>
    /// <param name="exitCode">Subprocess exit code (null if not a subprocess).</param>
    /// <param name="stderrOrOutput">Captured stderr or output snippet — bounded by caller.</param>
    /// <param name="attempt">1-based attempt number; controls exponential backoff for transient classes.</param>
    /// <param name="responseHeaders">Optional HTTP response headers (e.g. <c>Retry-After</c>).</param>
    public FailureClass Classify(
        string toolName,
        Exception? exception,
        int? exitCode,
        string? stderrOrOutput,
        int attempt = 1,
        IReadOnlyDictionary<string, string>? responseHeaders = null)
    {
        _ = toolName;
        var snippet = (stderrOrOutput ?? string.Empty);
        var lower = snippet.ToLowerInvariant();

        // 1. Rate limited — check first so 429 with HttpRequestException still classifies as rate_limited.
        if (LooksLikeRateLimit(exception, lower))
        {
            var backoff = ParseRetryAfter(responseHeaders) ?? DefaultRateLimitBackoff;
            return new FailureClass(
                Kind: "rate_limited",
                Recoverable: true,
                SuggestedBackoff: backoff,
                SuggestedDowngrade: "reduce_rps",
                Reason: "rate-limited (HTTP 429 / too many requests)");
        }

        // 2. Account lockout — credential tools.
        if (LooksLikeLockout(lower))
        {
            return new FailureClass(
                Kind: "account_lockout",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: "credential service reported account lockout / repeated failed attempts");
        }

        // 3. Auth failed (no retry without new creds).
        if (LooksLikeAuthFailure(lower))
        {
            return new FailureClass(
                Kind: "auth_failed",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: "authentication failed (401/403/invalid credentials)");
        }

        // 4. Out-of-scope at runtime — scope exceptions must never be retried.
        if (exception is Scope.ScopeException)
        {
            return new FailureClass(
                Kind: "out_of_scope_runtime",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: "target rejected by scope mid-run");
        }

        // 5. Permission denied locally.
        if (LooksLikePermissionDenied(lower, exitCode))
        {
            return new FailureClass(
                Kind: "permission_denied",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: "local permission denied (EACCES / missing sudo)");
        }

        // 6. Interpreter / binary missing — doctor hint.
        if (LooksLikeInterpreterMissing(lower))
        {
            return new FailureClass(
                Kind: "interpreter_missing",
                Recoverable: false,
                SuggestedBackoff: TimeSpan.Zero,
                SuggestedDowngrade: null,
                Reason: "required interpreter or binary not found — run `drederick doctor`");
        }

        // 7. Tool crash — segfault / panic / core dump.
        if (LooksLikeToolCrash(lower, exitCode))
        {
            return new FailureClass(
                Kind: "tool_crash",
                Recoverable: true,
                SuggestedBackoff: TimeSpan.FromSeconds(10),
                SuggestedDowngrade: "switch_to_fallback",
                Reason: "subprocess crashed (segfault / panic / core dumped)");
        }

        // 8. Transient network — sockets, http connect, read timeouts.
        if (LooksLikeTransientNetwork(exception, lower))
        {
            var capped = ExponentialBackoff(attempt, baseSeconds: 5, cap: MaxNetworkBackoff);
            return new FailureClass(
                Kind: "transient_network",
                Recoverable: true,
                SuggestedBackoff: capped,
                SuggestedDowngrade: "reduce_concurrency",
                Reason: "transient network failure (socket / timeout / connection refused)");
        }

        // 9. Catch-all — conservative.
        return new FailureClass(
            Kind: "unknown",
            Recoverable: true,
            SuggestedBackoff: TimeSpan.FromSeconds(5),
            SuggestedDowngrade: "reduce_concurrency",
            Reason: exception?.GetType().Name ?? $"exit={exitCode?.ToString(CultureInfo.InvariantCulture) ?? "?"}");
    }

    private static bool LooksLikeRateLimit(Exception? ex, string lower)
    {
        if (lower.Contains("429") ||
            lower.Contains("too many requests") ||
            lower.Contains("rate limit") ||
            lower.Contains("rate-limited") ||
            lower.Contains("retry-after"))
        {
            return true;
        }
        if (ex is HttpRequestException hre && (int?)hre.StatusCode == 429)
        {
            return true;
        }
        return false;
    }

    private static bool LooksLikeLockout(string lower) =>
        lower.Contains("account locked") ||
        lower.Contains("account is locked") ||
        lower.Contains("locked out") ||
        lower.Contains("too many failed attempts") ||
        lower.Contains("password lockout") ||
        lower.Contains("krb5kdc_err_client_revoked") ||
        lower.Contains("as-rep lockout") ||
        lower.Contains("user disabled");

    private static bool LooksLikeAuthFailure(string lower)
    {
        if (lower.Contains("401") || lower.Contains("403") ||
            lower.Contains("unauthorized") || lower.Contains("forbidden") ||
            lower.Contains("invalid credentials") || lower.Contains("invalid password") ||
            lower.Contains("authentication failed") || lower.Contains("login failed") ||
            lower.Contains("permission denied (publickey"))
        {
            return true;
        }
        return false;
    }

    private static bool LooksLikePermissionDenied(string lower, int? exitCode)
    {
        if (lower.Contains("eacces") ||
            lower.Contains("operation not permitted") ||
            lower.Contains("you need root") ||
            lower.Contains("must be root") ||
            lower.Contains("requires sudo"))
        {
            return true;
        }
        // Bare "permission denied" without an SSH publickey context.
        if (lower.Contains("permission denied") && !lower.Contains("publickey"))
        {
            return true;
        }
        _ = exitCode;
        return false;
    }

    private static bool LooksLikeInterpreterMissing(string lower) =>
        lower.Contains("command not found") ||
        lower.Contains("no such file or directory") && (lower.Contains("/usr/bin/") || lower.Contains("python") || lower.Contains("ruby") || lower.Contains("perl")) ||
        lower.Contains(": not found") ||
        lower.Contains("env: ") && lower.Contains("no such file");

    private static bool LooksLikeToolCrash(string lower, int? exitCode)
    {
        if (lower.Contains("segmentation fault") ||
            lower.Contains("core dumped") ||
            lower.Contains("panic:") ||
            lower.Contains("fatal error:") ||
            lower.Contains("aborted (core dumped)"))
        {
            return true;
        }
        // POSIX SIGSEGV → 139, SIGABRT → 134.
        if (exitCode is 139 or 134)
        {
            return true;
        }
        return false;
    }

    private static bool LooksLikeTransientNetwork(Exception? ex, string lower)
    {
        if (ex is SocketException ||
            ex is TimeoutException ||
            ex is HttpRequestException)
        {
            return true;
        }
        if (lower.Contains("connection refused") ||
            lower.Contains("connection reset") ||
            lower.Contains("read timed out") ||
            lower.Contains("network is unreachable") ||
            lower.Contains("no route to host") ||
            lower.Contains("connection timed out") ||
            lower.Contains("temporary failure in name resolution"))
        {
            return true;
        }
        return false;
    }

    private static TimeSpan ExponentialBackoff(int attempt, double baseSeconds, TimeSpan cap)
    {
        // attempt is 1-based: attempt 1 → base, attempt 2 → 2x, attempt 3 → 4x ...
        var n = Math.Max(0, attempt - 1);
        var seconds = baseSeconds * Math.Pow(2, n);
        if (seconds > cap.TotalSeconds) seconds = cap.TotalSeconds;
        return TimeSpan.FromSeconds(seconds);
    }

    private static TimeSpan? ParseRetryAfter(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers is null) return null;
        foreach (var kv in headers)
        {
            if (!string.Equals(kv.Key, "Retry-After", StringComparison.OrdinalIgnoreCase)) continue;
            var v = kv.Value?.Trim();
            if (string.IsNullOrEmpty(v)) return null;
            if (double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var secs) && secs >= 0)
            {
                return TimeSpan.FromSeconds(Math.Min(secs, 600));
            }
            if (DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
            {
                var delta = when - DateTimeOffset.UtcNow;
                if (delta < TimeSpan.Zero) return TimeSpan.Zero;
                if (delta > TimeSpan.FromMinutes(10)) return TimeSpan.FromMinutes(10);
                return delta;
            }
        }
        return null;
    }
}
