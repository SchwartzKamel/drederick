using System.Security.Cryptography;
using System.Text;

namespace Drederick.Agent;

/// <summary>
/// GAP-055 — structured record describing a single LLM → deterministic
/// fallback inside <see cref="HybridAgentRunner"/>. Emitted to the audit
/// log as the <c>hybrid.fallback</c> event so operators can see every
/// silent fallback (no key, network blip, auth error, rate limit,
/// parse error, transient SDK error, budget exhaustion).
///
/// Plaintext exception messages are intentionally NOT included; LLM/SDK
/// error strings can echo prompt fragments, URLs, or tokens back at us.
/// A SHA-256 tail of the message is captured for correlation.
/// </summary>
public sealed record HybridFallbackEvent(
    DateTimeOffset Timestamp,
    string Stage,
    string Reason,
    string? ExceptionType,
    string? MessageHash,
    int? RetryHintSeconds,
    string FellBackTo)
{
    public const string EventName = "hybrid.fallback";

    public static class Stages
    {
        public const string Init = "init";
        public const string Plan = "plan";
        public const string ToolCall = "tool_call";
        public const string ResponseParse = "response_parse";
        public const string Budget = "budget";
        public const string Network = "network";
    }

    public static class Reasons
    {
        public const string NoApiKey = "no_api_key";
        public const string NetworkError = "network_error";
        public const string AuthError = "auth_error";
        public const string RateLimit = "rate_limit";
        public const string ParseError = "parse_error";
        public const string SdkError = "sdk_error";
        public const string BudgetExceeded = "budget_exceeded";
        public const string Other = "other";
    }

    public static class FellBack
    {
        public const string DeterministicRunner = "deterministic_runner";
        public const string CachedPlan = "cached_plan";
        public const string NoOp = "no_op";
    }

    /// <summary>
    /// Classify an exception into a (stage, reason) pair using only the
    /// runtime exception type and a case-insensitive scan of the message
    /// for well-known protocol tokens (e.g. "rate limit", "401"). The
    /// message itself is never propagated past this method.
    /// </summary>
    public static (string Stage, string Reason) Classify(Exception ex)
    {
        var typeName = ex.GetType().FullName ?? string.Empty;
        var msg = ex.Message ?? string.Empty;
        var msgLower = msg.ToLowerInvariant();

        if (ex is System.Net.Http.HttpRequestException
            || ex is System.Net.Sockets.SocketException
            || ex is TimeoutException
            || ex is TaskCanceledException
            || typeName.Contains("Http", StringComparison.OrdinalIgnoreCase)
                && (msgLower.Contains("timeout") || msgLower.Contains("connection") || msgLower.Contains("refused") || msgLower.Contains("dns")))
        {
            return (Stages.Network, Reasons.NetworkError);
        }

        if (msgLower.Contains("rate limit") || msgLower.Contains("429") || msgLower.Contains("too many requests"))
        {
            return (Stages.Plan, Reasons.RateLimit);
        }

        if (ex is UnauthorizedAccessException
            || msgLower.Contains("401") || msgLower.Contains("403")
            || msgLower.Contains("unauthorized") || msgLower.Contains("forbidden")
            || msgLower.Contains("invalid api key") || msgLower.Contains("authentication"))
        {
            return (Stages.Plan, Reasons.AuthError);
        }

        if (ex is System.Text.Json.JsonException || ex is FormatException)
        {
            return (Stages.ResponseParse, Reasons.ParseError);
        }

        if (msgLower.Contains("budget") && msgLower.Contains("exceed"))
        {
            return (Stages.Budget, Reasons.BudgetExceeded);
        }

        return (Stages.Plan, Reasons.SdkError);
    }

    /// <summary>
    /// Best-effort retry-hint extractor. Looks for an integer number of
    /// seconds following common phrases ("retry after N", "in N seconds").
    /// Returns null when nothing is found.
    /// </summary>
    public static int? ExtractRetryHintSeconds(Exception ex)
    {
        var msg = ex.Message ?? string.Empty;
        var m = System.Text.RegularExpressions.Regex.Match(
            msg,
            @"(?:retry[-\s]?after|in)\s+(\d{1,5})\s*(?:s|sec|seconds)?",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (m.Success && int.TryParse(m.Groups[1].Value, out var secs) && secs >= 0 && secs <= 86400)
        {
            return secs;
        }
        return null;
    }

    public static string Sha256Tail(string? s, int tailChars = 16)
    {
        var bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        var hex = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return hex.Length <= tailChars ? hex : hex[^tailChars..];
    }

    public IReadOnlyDictionary<string, object?> ToAuditFields() => new Dictionary<string, object?>
    {
        ["ts"] = Timestamp.ToString("o"),
        ["stage"] = Stage,
        ["reason"] = Reason,
        ["exception_type"] = ExceptionType,
        ["message_sha256"] = MessageHash,
        ["retry_hint_seconds"] = RetryHintSeconds,
        ["fell_back_to"] = FellBackTo,
    };
}
