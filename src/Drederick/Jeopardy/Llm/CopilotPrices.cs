using Drederick.Jeopardy.Budget;

namespace Drederick.Jeopardy.Llm;

/// <summary>
/// Per-1K-token prices (USD) for models exposed via the GitHub Copilot API.
/// Figures track the public 2026 rate card and are kept deliberately
/// conservative where a model has no published price. Unknown models return
/// zero from <see cref="TryGet"/>; callers must treat zero as "unknown", not
/// "free".
/// </summary>
public static class CopilotPrices
{
    public sealed record Price(decimal PromptPer1K, decimal CompletionPer1K);

    // Per-1K prices (USD). Source of truth: 2026 Copilot rate card snapshot.
    // Per-M-tok = PromptPer1K * 1000.
    private static readonly Dictionary<string, Price> _table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["gpt-5.4"] = new(0.002m, 0.008m),
        ["gpt-5.4-mini"] = new(0.00015m, 0.0006m),
        ["gpt-5.3-codex"] = new(0.004m, 0.012m),
        ["gpt-5.2-codex"] = new(0.004m, 0.012m),
        ["gpt-5.2"] = new(0.0045m, 0.0135m),
        ["gpt-4.1"] = new(0.002m, 0.008m),
        ["claude-opus-4.7"] = new(0.015m, 0.075m),
        ["claude-opus-4.6"] = new(0.015m, 0.075m),
        ["claude-opus-4.5"] = new(0.015m, 0.075m),
        ["claude-sonnet-4.6"] = new(0.003m, 0.015m),
        ["claude-sonnet-4.5"] = new(0.003m, 0.015m),
        ["claude-sonnet-4"] = new(0.003m, 0.015m),
        ["claude-haiku-4.5"] = new(0.0008m, 0.004m),
        ["gemini-2.5-pro"] = new(0.00125m, 0.010m),
        ["gemini-3-flash"] = new(0.000075m, 0.0003m),
        ["gemini-3.1-pro"] = new(0.00125m, 0.005m),
        ["grok-code-fast-1"] = new(0.0002m, 0.0015m),
        ["raptor-mini"] = new(0m, 0m),
        ["goldeneye"] = new(0m, 0m),
    };

    /// <summary>
    /// Singleton <see cref="ICostPriceTable"/> adapter over the shared price
    /// table. Returns per-million-token prices as required by the Budget
    /// subsystem.
    /// </summary>
    public static ICostPriceTable PriceTable { get; } = new CopilotPriceTable();

    private sealed class CopilotPriceTable : ICostPriceTable
    {
        public (decimal inputPerMTok, decimal outputPerMTok) For(string modelId)
        {
            if (TryGet(modelId, out var p))
            {
                return (p.PromptPer1K * 1000m, p.CompletionPer1K * 1000m);
            }
            return (0m, 0m);
        }
    }

    public static bool TryGet(string modelId, out Price price)
    {
        if (!string.IsNullOrWhiteSpace(modelId) && _table.TryGetValue(modelId, out var p))
        {
            price = p;
            return true;
        }
        price = new Price(0m, 0m);
        return false;
    }

    public static decimal EstimateCostUsd(string modelId, int promptTokens, int completionTokens)
    {
        if (!TryGet(modelId, out var p)) return 0m;
        return ((decimal)promptTokens / 1000m) * p.PromptPer1K
             + ((decimal)completionTokens / 1000m) * p.CompletionPer1K;
    }
}
