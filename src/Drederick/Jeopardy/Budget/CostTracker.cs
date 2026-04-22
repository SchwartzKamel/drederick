using System.Collections.Concurrent;
using System.Globalization;
using Drederick.Audit;

namespace Drederick.Jeopardy.Budget;

/// <summary>
/// One recorded token-usage event annotated with its computed USD cost.
/// Immutable; safe to cross thread boundaries and serialize to the run
/// report.
/// </summary>
public sealed record TokenCost(
    string ModelId,
    int PromptTokens,
    int CompletionTokens,
    decimal UsdCost,
    DateTimeOffset At,
    string? ChallengeId,
    string? SolverId);

/// <summary>
/// Point-in-time view of all cost accounting. The dictionaries are deep
/// copies and safe to hand off to the reporter / UI / JSON serializer.
/// </summary>
public sealed record CostSnapshot(
    decimal TotalUsd,
    int TotalCalls,
    IReadOnlyDictionary<string, decimal> UsdByModel,
    IReadOnlyDictionary<string, decimal> UsdByChallenge);

/// <summary>
/// Thrown when a run- or challenge-scoped USD budget is (or would be)
/// exceeded. <see cref="Scope"/> is either "run" or "challenge:&lt;id&gt;".
/// </summary>
public sealed class BudgetExceededException : Exception
{
    public string Scope { get; }
    public decimal Cap { get; }
    public decimal Actual { get; }

    public BudgetExceededException(string scope, decimal cap, decimal actual)
        : base($"Budget exceeded (scope={scope}, cap=${cap:F4}, actual=${actual:F4})")
    {
        Scope = scope;
        Cap = cap;
        Actual = actual;
    }
}

/// <summary>
/// Per-million-token price table. Returns (0, 0) for unknown models; callers
/// must distinguish that from genuinely free models via an out-of-band
/// signal.
/// </summary>
public interface ICostPriceTable
{
    (decimal inputPerMTok, decimal outputPerMTok) For(string modelId);
}

public interface ICostTracker
{
    TokenCost Record(string modelId, int promptTokens, int completionTokens, string? challengeId, string? solverId);
    CostSnapshot Snapshot();
    decimal TotalUsd { get; }
    decimal UsdForChallenge(string challengeId);
    void AssertWithinBudget(string? challengeId);
}

/// <summary>
/// Thread-safe accounting of LLM token usage converted to USD with
/// optional per-run and per-challenge budget caps.
/// </summary>
/// <remarks>
/// Environment variables consulted when the matching constructor arg is
/// null:
/// <list type="bullet">
///   <item><c>DREDERICK_BUDGET_RUN_USD</c> — decimal, default null (unlimited).</item>
///   <item><c>DREDERICK_BUDGET_CHALLENGE_USD</c> — decimal, default null.</item>
///   <item><c>DREDERICK_BUDGET_STRICT</c> — "1" makes <see cref="Record"/>
///   auto-assert after each write; otherwise breaches are audit-logged only
///   via an explicit <see cref="AssertWithinBudget"/> call.</item>
/// </list>
/// Constructor arguments take precedence over env vars.
/// </remarks>
public sealed class CostTracker : ICostTracker
{
    private readonly AuditLog _audit;
    private readonly ICostPriceTable _prices;
    private readonly decimal? _runCapUsd;
    private readonly decimal? _challengeCapUsd;
    private readonly bool _strict;

    // Totals are accumulated as scaled integers (micro-dollars, 1e-6 USD)
    // so concurrent updates can use Interlocked on a long. Reads reconstruct
    // decimal on demand.
    private const decimal Scale = 1_000_000m;
    private long _totalMicroUsd;
    private long _totalCalls;

    private readonly ConcurrentDictionary<string, long> _byModel = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _byChallenge = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _unknownModelsWarned = new(StringComparer.OrdinalIgnoreCase);

    public CostTracker(
        AuditLog audit,
        decimal? runCapUsd = null,
        decimal? challengeCapUsd = null,
        ICostPriceTable? prices = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _prices = prices ?? Drederick.Jeopardy.Llm.CopilotPrices.PriceTable;

        _runCapUsd = runCapUsd ?? TryParseDecimalEnv("DREDERICK_BUDGET_RUN_USD");
        _challengeCapUsd = challengeCapUsd ?? TryParseDecimalEnv("DREDERICK_BUDGET_CHALLENGE_USD");
        _strict = string.Equals(
            Environment.GetEnvironmentVariable("DREDERICK_BUDGET_STRICT"),
            "1",
            StringComparison.Ordinal);
    }

    public decimal TotalUsd => FromMicro(Interlocked.Read(ref _totalMicroUsd));

    public TokenCost Record(
        string modelId,
        int promptTokens,
        int completionTokens,
        string? challengeId,
        string? solverId)
    {
        if (string.IsNullOrWhiteSpace(modelId)) modelId = "unknown";
        if (promptTokens < 0) promptTokens = 0;
        if (completionTokens < 0) completionTokens = 0;

        var (inPerM, outPerM) = _prices.For(modelId);
        var isUnknown = inPerM == 0m && outPerM == 0m;

        decimal usd = 0m;
        if (promptTokens > 0 || completionTokens > 0)
        {
            usd = ((decimal)promptTokens / 1_000_000m) * inPerM
                + ((decimal)completionTokens / 1_000_000m) * outPerM;
        }

        if (isUnknown && _unknownModelsWarned.TryAdd(modelId, 0))
        {
            _audit.Record("cost.unknown_model", new Dictionary<string, object?>
            {
                ["model"] = Scrub(modelId),
                ["prompt_tokens"] = promptTokens,
                ["completion_tokens"] = completionTokens,
            });
        }

        var micro = ToMicro(usd);
        Interlocked.Add(ref _totalMicroUsd, micro);
        Interlocked.Increment(ref _totalCalls);
        _byModel.AddOrUpdate(modelId, micro, (_, cur) => cur + micro);
        if (!string.IsNullOrEmpty(challengeId))
        {
            _byChallenge.AddOrUpdate(challengeId, micro, (_, cur) => cur + micro);
        }

        var tc = new TokenCost(
            modelId,
            promptTokens,
            completionTokens,
            usd,
            DateTimeOffset.UtcNow,
            challengeId,
            solverId);

        _audit.Record("cost.record", new Dictionary<string, object?>
        {
            ["model"] = Scrub(modelId),
            ["prompt_tokens"] = promptTokens,
            ["completion_tokens"] = completionTokens,
            ["usd_cost"] = Math.Round(usd, 6, MidpointRounding.AwayFromZero)
                .ToString("F6", CultureInfo.InvariantCulture),
            ["challenge_id"] = Scrub(challengeId),
            ["solver_id"] = Scrub(solverId),
        });

        if (_strict)
        {
            AssertWithinBudget(challengeId);
        }

        return tc;
    }

    public CostSnapshot Snapshot()
    {
        var byModel = _byModel.ToArray()
            .ToDictionary(kv => kv.Key, kv => FromMicro(kv.Value), StringComparer.OrdinalIgnoreCase);
        var byChallenge = _byChallenge.ToArray()
            .ToDictionary(kv => kv.Key, kv => FromMicro(kv.Value), StringComparer.Ordinal);
        return new CostSnapshot(
            FromMicro(Interlocked.Read(ref _totalMicroUsd)),
            (int)Interlocked.Read(ref _totalCalls),
            byModel,
            byChallenge);
    }

    public decimal UsdForChallenge(string challengeId)
    {
        if (string.IsNullOrEmpty(challengeId)) return 0m;
        return _byChallenge.TryGetValue(challengeId, out var m) ? FromMicro(m) : 0m;
    }

    public void AssertWithinBudget(string? challengeId)
    {
        if (_runCapUsd is decimal runCap)
        {
            var total = TotalUsd;
            if (total > runCap)
            {
                EmitBreach("run", runCap, total);
                throw new BudgetExceededException("run", runCap, total);
            }
        }
        if (!string.IsNullOrEmpty(challengeId) && _challengeCapUsd is decimal cCap)
        {
            var actual = UsdForChallenge(challengeId);
            if (actual > cCap)
            {
                var scope = "challenge:" + challengeId;
                EmitBreach(scope, cCap, actual);
                throw new BudgetExceededException(scope, cCap, actual);
            }
        }
    }

    private void EmitBreach(string scope, decimal cap, decimal actual)
    {
        _audit.Record("cost.budget_exceeded", new Dictionary<string, object?>
        {
            ["scope"] = Scrub(scope),
            ["cap_usd"] = cap.ToString("F6", CultureInfo.InvariantCulture),
            ["actual_usd"] = actual.ToString("F6", CultureInfo.InvariantCulture),
        });
    }

    private static long ToMicro(decimal usd) => (long)Math.Round(usd * Scale, MidpointRounding.AwayFromZero);
    private static decimal FromMicro(long micro) => (decimal)micro / Scale;

    private static decimal? TryParseDecimalEnv(string name)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return decimal.TryParse(raw, NumberStyles.Number, CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    // Newlines / control chars in audit fields would break the JSONL shape
    // (one-event-per-line) on readers that split pre-parse. Strip them.
    private static string? Scrub(string? s)
    {
        if (s is null) return null;
        if (s.Length == 0) return s;
        Span<char> buf = s.Length <= 256 ? stackalloc char[s.Length] : new char[s.Length];
        int n = 0;
        foreach (var c in s)
        {
            if (c == '\r' || c == '\n' || c == '\t' || char.IsControl(c)) buf[n++] = ' ';
            else buf[n++] = c;
        }
        return new string(buf[..n]);
    }
}
