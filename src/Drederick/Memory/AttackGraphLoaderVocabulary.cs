using Drederick.Audit;

namespace Drederick.Memory;

/// <summary>
/// Vocabulary + alias resolver for attack-graph loaders. Real-world attack
/// graphs use many synonyms for the same concept (technique vs. tactic,
/// loot vs. credential, access vs. privilege, invalidated vs. stale, …).
///
/// This helper centralizes the mapping so a loader can:
///   - accept canonical terms verbatim;
///   - accept deprecated synonyms with an audit warning
///     (<c>attack_graph.deprecated_vocab</c>) recording old_term, new_term,
///     and node_id;
///   - reject genuinely unknown vocab when running in strict mode
///     (<c>--no-lab</c>), or warn-and-pass-through in lab mode.
///
/// Matching is case-insensitive. The helper is standalone and intended to
/// be wired into the YAML loader in a follow-up edit.
/// </summary>
public sealed class AttackGraphLoaderVocabulary
{
    /// <summary>Vocabulary field a term belongs to.</summary>
    public enum Field
    {
        Kind,
        State,
    }

    /// <summary>Loader strictness — mirrors the CLI <c>--no-lab</c> flag.</summary>
    public enum Mode
    {
        Lab,
        Strict,
    }

    /// <summary>Outcome of resolving a raw vocab term.</summary>
    /// <param name="Canonical">Canonical term (lower-case). Empty when <see cref="Rejected"/>.</param>
    /// <param name="Mapped">True when the input was a deprecated alias that was rewritten.</param>
    /// <param name="OriginalTerm">The raw input as written in the YAML, when an alias was applied.</param>
    /// <param name="Rejected">True when the term is unknown and the mode does not permit pass-through.</param>
    public sealed record Resolution(
        string Canonical,
        bool Mapped,
        string? OriginalTerm,
        bool Rejected);

    private static readonly HashSet<string> CanonicalKindsSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "service", "credential", "session", "flag", "identity", "artifact",
        "tactic", "privilege",
    };

    private static readonly HashSet<string> CanonicalStatesSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "unknown", "suspected", "known", "owned", "blocked", "stale",
    };

    private static readonly Dictionary<string, string> KindAliasesMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["technique"] = "tactic",
        ["procedure"] = "tactic",
        ["machine"] = "host",
        ["target"] = "host",
        ["node"] = "host",
        ["box"] = "host",
        ["port"] = "service",
        ["endpoint"] = "service",
        ["listener"] = "service",
        ["loot"] = "credential",
        ["creds"] = "credential",
        ["cred"] = "credential",
        ["secret"] = "credential",
        ["password"] = "credential",
        ["shell"] = "session",
        ["foothold"] = "session",
        ["access"] = "privilege",
        ["role"] = "privilege",
        ["goal"] = "flag",
        ["trophy"] = "flag",
        ["objective"] = "flag",
        ["user"] = "identity",
        ["account"] = "identity",
        ["principal"] = "identity",
        ["file"] = "artifact",
        ["payload"] = "artifact",
        ["binary"] = "artifact",
    };

    private static readonly Dictionary<string, string> StateAliasesMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["unverified"] = "suspected",
        ["possible"] = "suspected",
        ["maybe"] = "suspected",
        ["confirmed"] = "known",
        ["verified"] = "known",
        ["validated"] = "known",
        ["compromised"] = "owned",
        ["pwned"] = "owned",
        ["controlled"] = "owned",
        ["denied"] = "blocked",
        ["failed"] = "blocked",
        ["refused"] = "blocked",
        ["invalidated"] = "stale",
        ["expired"] = "stale",
        ["revoked"] = "stale",
        ["rotated"] = "stale",
    };

    /// <summary>Read-only view of canonical kinds (case-insensitive).</summary>
    public static IReadOnlySet<string> CanonicalKinds => CanonicalKindsSet;

    /// <summary>Read-only view of canonical states (case-insensitive).</summary>
    public static IReadOnlySet<string> CanonicalStates => CanonicalStatesSet;

    /// <summary>Read-only view of kind aliases (case-insensitive).</summary>
    public static IReadOnlyDictionary<string, string> KindAliases => KindAliasesMap;

    /// <summary>Read-only view of state aliases (case-insensitive).</summary>
    public static IReadOnlyDictionary<string, string> StateAliases => StateAliasesMap;

    /// <summary>
    /// Resolve a raw vocabulary term. Records
    /// <c>attack_graph.deprecated_vocab</c> when an alias is applied, and
    /// <c>attack_graph.vocab.unknown</c> when the term is neither canonical
    /// nor a known alias. In <see cref="Mode.Strict"/> unknown terms are
    /// rejected (caller should treat as a load error); in
    /// <see cref="Mode.Lab"/> they pass through unchanged.
    /// </summary>
    public Resolution Resolve(Field field, string term, Mode mode, string? nodeId, AuditLog? audit)
    {
        if (string.IsNullOrWhiteSpace(term))
            return new Resolution(string.Empty, false, null, false);

        var trimmed = term.Trim();
        var canonicalSet = field == Field.Kind ? CanonicalKindsSet : CanonicalStatesSet;
        var aliases = field == Field.Kind ? KindAliasesMap : StateAliasesMap;

        if (canonicalSet.Contains(trimmed))
        {
            return new Resolution(trimmed.ToLowerInvariant(), false, null, false);
        }

        if (aliases.TryGetValue(trimmed, out var canonical))
        {
            audit?.Record("attack_graph.deprecated_vocab", new Dictionary<string, object?>
            {
                ["field"] = field.ToString().ToLowerInvariant(),
                ["old_term"] = trimmed,
                ["new_term"] = canonical,
                ["node_id"] = nodeId ?? string.Empty,
                ["mode"] = mode.ToString().ToLowerInvariant(),
            });
            return new Resolution(canonical, true, trimmed, false);
        }

        audit?.Record("attack_graph.vocab.unknown", new Dictionary<string, object?>
        {
            ["field"] = field.ToString().ToLowerInvariant(),
            ["value"] = trimmed,
            ["node_id"] = nodeId ?? string.Empty,
            ["mode"] = mode.ToString().ToLowerInvariant(),
        });

        if (mode == Mode.Strict)
        {
            return new Resolution(string.Empty, false, trimmed, true);
        }

        return new Resolution(trimmed.ToLowerInvariant(), false, trimmed, false);
    }
}
