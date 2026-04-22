namespace Drederick.Jeopardy.Llm;

/// <summary>
/// Placeholder per-1K-token prices (USD) for models exposed via the GitHub
/// Copilot API. These numbers are deliberately conservative estimates; real
/// pricing lives in a follow-up once the published rate card stabilises.
/// Unknown models return zero from <see cref="TryGet"/>; callers must treat
/// zero as "unknown", not "free".
/// </summary>
public static class CopilotPrices
{
    public sealed record Price(decimal PromptPer1K, decimal CompletionPer1K);

    private static readonly Dictionary<string, Price> _table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["gpt-5.4"] = new(0.005m, 0.015m),
        ["gpt-5.4-mini"] = new(0.0003m, 0.0012m),
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
        ["gemini-2.5-pro"] = new(0.00125m, 0.005m),
        ["gemini-3-flash"] = new(0.0003m, 0.0012m),
        ["gemini-3.1-pro"] = new(0.0015m, 0.006m),
        ["grok-code-fast-1"] = new(0.0005m, 0.002m),
        ["raptor-mini"] = new(0.0002m, 0.0008m),
        ["goldeneye"] = new(0.001m, 0.004m),
    };

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
