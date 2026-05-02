using Drederick.Audit;

namespace Drederick.Scaffolding;

/// <summary>
/// Orchestrates briefing + attack-graph + cornerman discovery per
/// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2. Returns a bundled
/// <see cref="ScaffoldingContext"/> the planner consults at runtime.
/// </summary>
public static class ScaffoldingDiscovery
{
    public static ScaffoldingContext Load(
        string scopePath,
        string? briefingOverride,
        string? attackGraphOverride,
        bool disabled,
        AuditLog audit)
    {
        if (disabled)
        {
            return new ScaffoldingContext(null, null, audit);
        }
        var scopeDir = Path.GetDirectoryName(Path.GetFullPath(scopePath)) ?? Directory.GetCurrentDirectory();

        var briefing = BriefingLoader.LoadOrAbsent(briefingOverride, scopeDir, audit);
        var graph = AttackGraphLoader.LoadOrAbsent(attackGraphOverride, scopeDir, audit);

        var cornerman = Path.Combine(scopeDir, "cornerman.md");
        if (File.Exists(cornerman))
        {
            try
            {
                var text = File.ReadAllText(cornerman);
                var sha = BriefingLoader.Sha256(text);
                var lines = text.Split('\n').Length;
                var lastRound = ParseLastRound(text);
                audit.Record("cornerman.read", new Dictionary<string, object?>
                {
                    ["path"] = cornerman,
                    ["sha256"] = sha,
                    ["lines"] = lines,
                    ["last_round_referenced"] = lastRound,
                });
            }
            catch { /* informational only */ }
        }

        return new ScaffoldingContext(briefing, graph, audit);
    }

    private static string? ParseLastRound(string text)
    {
        // Look for a header like "## Round 3" or "### r2" or "Round: 5".
        foreach (var line in text.Split('\n').Reverse())
        {
            var m = System.Text.RegularExpressions.Regex.Match(
                line, @"\b[Rr](?:ound)?\s*[:#]?\s*(\d+)\b");
            if (m.Success) return "r" + m.Groups[1].Value;
        }
        return null;
    }
}
