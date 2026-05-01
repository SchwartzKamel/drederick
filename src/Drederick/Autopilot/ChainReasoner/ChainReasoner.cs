using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Memory;

namespace Drederick.Autopilot.ChainReasoner;

/// <summary>
/// Pluggable LLM hook. Implementations should return additional
/// <see cref="AttackChain"/> candidates derived from the same
/// <see cref="ChainFacts"/>. Any failure must be surfaced as an exception so
/// the reasoner can record an <c>chain.augmenter.error</c> audit event and
/// fall back to deterministic output. Implementations must not log plaintext
/// secrets; only <see cref="Drederick.Autopilot.CredentialRef"/>-style refs
/// should leave the boundary.
/// </summary>
public interface IChainAugmenter
{
    Task<IReadOnlyList<AttackChain>> AugmentAsync(ChainFacts facts, IReadOnlyList<AttackChain> baseline, CancellationToken ct);
}

/// <summary>Default no-op augmenter used when <c>--agent</c> is not set.</summary>
public sealed class NoOpChainAugmenter : IChainAugmenter
{
    public Task<IReadOnlyList<AttackChain>> AugmentAsync(ChainFacts facts, IReadOnlyList<AttackChain> baseline, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<AttackChain>>(Array.Empty<AttackChain>());
}

/// <summary>
/// Deterministic chain proposer. Reads predicates from the
/// <see cref="ChainFacts"/>, instantiates every <see cref="ChainTemplate"/>
/// whose <see cref="ChainTemplate.Requires"/> are satisfied, computes a
/// composite score (likelihood × impact − cost), optionally merges in
/// LLM-derived candidates from an <see cref="IChainAugmenter"/>, and returns
/// the top-N ordered list with explanations.
///
/// The reasoner does not touch the network and does not call
/// <see cref="Drederick.Scope.Scope"/> — it manipulates pure data. Tools that
/// later execute steps re-check scope as their first statement
/// (<c>@invariant-id:scope-in-every-tool</c>).
/// </summary>
public sealed class ChainReasoner
{
    private readonly AuditLog _audit;
    private readonly IReadOnlyList<ChainTemplate> _templates;

    public ChainReasoner(AuditLog audit, IReadOnlyList<ChainTemplate>? templates = null)
    {
        _audit = audit;
        _templates = templates ?? BuiltInChainTemplates.All;
    }

    public IReadOnlyList<AttackChain> Reason(KnowledgeBase kb, CredentialStore? creds, IReadOnlyList<string>? sessions, int top = 5)
        => ReasonAsync(kb, creds, sessions, top, augmenter: null, ct: default).GetAwaiter().GetResult();

    public async Task<IReadOnlyList<AttackChain>> ReasonAsync(
        KnowledgeBase kb,
        CredentialStore? creds,
        IReadOnlyList<string>? sessions,
        int top = 5,
        IChainAugmenter? augmenter = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kb);
        if (top < 1) top = 1;

        var facts = ChainFacts.From(kb, creds, sessions);

        var rule = new List<AttackChain>(_templates.Count);
        foreach (var t in _templates)
        {
            if (!AllSatisfied(t.Requires, facts)) continue;
            rule.Add(Instantiate(t, facts, source: "rule"));
        }

        var augmented = new List<AttackChain>();
        if (augmenter is not null)
        {
            try
            {
                var extra = await augmenter.AugmentAsync(facts, rule, ct).ConfigureAwait(false);
                if (extra is { Count: > 0 })
                {
                    augmented.AddRange(extra.Select(c => c with { Source = "llm" }));
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _audit.Record("chain.augmenter.error", new Dictionary<string, object?>
                {
                    ["error_type"] = ex.GetType().Name,
                    ["message"] = ex.Message,
                });
            }
        }

        // Dedup by Id, prefer rule-source over llm when ids collide.
        var byId = new Dictionary<string, AttackChain>(StringComparer.Ordinal);
        foreach (var c in rule) byId[c.Id] = c;
        foreach (var c in augmented)
        {
            if (string.IsNullOrEmpty(c.Id)) continue;
            if (!byId.ContainsKey(c.Id)) byId[c.Id] = c;
        }

        // Stable ordering: score desc, then id asc to keep determinism.
        var ranked = byId.Values
            .OrderByDescending(c => c.Score)
            .ThenBy(c => c.Id, StringComparer.Ordinal)
            .Take(top)
            .ToList();

        _audit.Record("chain.reasoned", new Dictionary<string, object?>
        {
            ["candidates"] = byId.Count,
            ["returned"] = ranked.Count,
            ["digest"] = ChainDigest(ranked),
            ["augmenter"] = augmenter?.GetType().Name ?? "none",
        });

        return ranked;
    }

    private static bool AllSatisfied(IReadOnlyList<string> requires, ChainFacts facts)
    {
        foreach (var p in requires)
            if (!facts.Has(p)) return false;
        return true;
    }

    private static AttackChain Instantiate(ChainTemplate t, ChainFacts facts, string source)
    {
        // Likelihood = geomean of step confidences.
        double likelihood = 1.0;
        int totalCost = 0;
        foreach (var s in t.Steps) { likelihood *= Math.Max(s.Confidence, 0.01); totalCost += s.Cost; }
        likelihood = t.Steps.Count == 0 ? 0.0 : Math.Pow(likelihood, 1.0 / t.Steps.Count);

        var score = likelihood * t.Impact - (totalCost / 1000.0);
        var matched = t.Requires.Where(facts.Has).ToList();
        var reason = matched.Count == 0
            ? "no preconditions"
            : $"matched {matched.Count}/{t.Requires.Count}: {string.Join(", ", matched)}";

        return new AttackChain
        {
            Id = t.Id,
            Name = t.Name,
            Steps = t.Steps,
            Targets = facts.Targets.ToList(),
            Likelihood = Math.Round(likelihood, 4),
            Impact = t.Impact,
            Cost = totalCost,
            Score = Math.Round(score, 4),
            Reason = reason,
            Source = source,
        };
    }

    public static string ChainDigest(IReadOnlyList<AttackChain> chains)
    {
        var json = JsonSerializer.Serialize(chains.Select(c => new { c.Id, c.Score, steps = c.Steps.Count }));
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(json), hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
