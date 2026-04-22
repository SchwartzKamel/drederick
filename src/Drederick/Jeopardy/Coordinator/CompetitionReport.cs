using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Drederick.Jeopardy.Solver;
using Drederick.Jeopardy.Swarm;

namespace Drederick.Jeopardy.Coordinator;

/// <summary>
/// Aggregated outcome of a full Jeopardy competition run. All monetary values
/// are in USD. Flags are never included in plaintext — the renderer hashes
/// <see cref="SolverRunResult.FlagSubmitted"/> before emitting the report.
/// </summary>
public sealed record CompetitionReport(
    DateTimeOffset StartedAt,
    DateTimeOffset? FinishedAt,
    int ChallengesDiscovered,
    int ChallengesSolved,
    int ChallengesAttempted,
    int PointsScored,
    decimal TotalUsdCost,
    IReadOnlyList<SwarmResult> PerChallenge,
    IReadOnlyDictionary<string, int> SolvesByModel,
    IReadOnlyDictionary<string, int> AttemptsByCategory);

public static class CompetitionReportRenderer
{
    private const string TatumIntro =
        "In this corner — drederick, weighing {0} solver slots — Drederick Tatum's Jeopardy division.";
    private const string TatumClose =
        "\"A fair fight is one you didn't prepare well enough for.\"";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToMarkdown(CompetitionReport r)
    {
        ArgumentNullException.ThrowIfNull(r);
        var sb = new StringBuilder();

        int slotCount = r.PerChallenge
            .SelectMany(pc => pc.PerSolver)
            .Select(s => s.ModelId)
            .Where(m => !string.IsNullOrEmpty(m))
            .Distinct(StringComparer.Ordinal)
            .Count();
        if (slotCount == 0) slotCount = 1;

        sb.AppendLine("# drederick — Jeopardy Competition Report");
        sb.AppendLine();
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, TatumIntro, slotCount));
        sb.AppendLine();
        sb.Append("- **Started:** ").AppendLine(r.StartedAt.ToString("u", CultureInfo.InvariantCulture));
        sb.Append("- **Finished:** ")
            .AppendLine(r.FinishedAt?.ToString("u", CultureInfo.InvariantCulture) ?? "(partial run)");
        sb.Append("- **Challenges discovered:** ").AppendLine(r.ChallengesDiscovered.ToString(CultureInfo.InvariantCulture));
        sb.Append("- **Challenges attempted:** ").AppendLine(r.ChallengesAttempted.ToString(CultureInfo.InvariantCulture));
        sb.Append("- **Challenges solved:** ").AppendLine(r.ChallengesSolved.ToString(CultureInfo.InvariantCulture));
        sb.Append("- **Points scored:** ").AppendLine(r.PointsScored.ToString(CultureInfo.InvariantCulture));
        sb.Append("- **Total cost:** $").AppendLine(r.TotalUsdCost.ToString("F4", CultureInfo.InvariantCulture));
        sb.AppendLine();

        sb.AppendLine("## Per-challenge");
        sb.AppendLine();
        sb.AppendLine("| ID | Challenge | Outcome | Winning model | USD | Flag SHA-256 |");
        sb.AppendLine("|---:|---|---|---|---:|---|");
        foreach (var pc in r.PerChallenge.OrderBy(x => x.ChallengeId))
        {
            var winSolver = pc.PerSolver.FirstOrDefault(s => s.Outcome == SolverOutcome.Solved);
            var flagHash = winSolver?.FlagSubmitted is { Length: > 0 } f
                ? Sha256Hex(f)
                : "";
            sb.Append("| ").Append(pc.ChallengeId)
                .Append(" | ").Append(EscapeMd(pc.ChallengeName))
                .Append(" | ").Append(pc.CombinedOutcome)
                .Append(" | ").Append(pc.WinningModelId ?? "—")
                .Append(" | ").Append(pc.TotalUsdCost.ToString("F4", CultureInfo.InvariantCulture))
                .Append(" | ").Append(flagHash.Length == 0 ? "—" : "`" + flagHash + "`")
                .AppendLine(" |");
        }
        sb.AppendLine();

        sb.AppendLine("## Per-model scoreboard");
        sb.AppendLine();
        sb.AppendLine("| Model | Solves |");
        sb.AppendLine("|---|---:|");
        foreach (var kv in r.SolvesByModel.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal))
        {
            sb.Append("| ").Append(kv.Key).Append(" | ").Append(kv.Value).AppendLine(" |");
        }
        sb.AppendLine();

        sb.AppendLine("## Attempts by category");
        sb.AppendLine();
        sb.AppendLine("| Category | Attempts |");
        sb.AppendLine("|---|---:|");
        foreach (var kv in r.AttemptsByCategory.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal))
        {
            sb.Append("| ").Append(kv.Key).Append(" | ").Append(kv.Value).AppendLine(" |");
        }
        sb.AppendLine();

        sb.AppendLine("## Cost breakdown");
        sb.AppendLine();
        sb.Append("- **Total USD:** $").AppendLine(r.TotalUsdCost.ToString("F6", CultureInfo.InvariantCulture));
        foreach (var pc in r.PerChallenge.OrderByDescending(x => x.TotalUsdCost))
        {
            sb.Append("- `chal:").Append(pc.ChallengeId).Append("` (")
                .Append(EscapeMd(pc.ChallengeName)).Append("): $")
                .AppendLine(pc.TotalUsdCost.ToString("F6", CultureInfo.InvariantCulture));
        }
        sb.AppendLine();

        sb.AppendLine("## Flag dedup (SHA-256 only)");
        sb.AppendLine();
        var flagHashes = CollectFlagHashes(r);
        if (flagHashes.Count == 0)
        {
            sb.AppendLine("_No flags submitted._");
        }
        else
        {
            foreach (var h in flagHashes)
            {
                sb.Append("- `").Append(h).AppendLine("`");
            }
        }
        sb.AppendLine();

        sb.AppendLine("---");
        sb.AppendLine(TatumClose);
        return sb.ToString();
    }

    public static string ToJson(CompetitionReport r)
    {
        ArgumentNullException.ThrowIfNull(r);

        var perChallenge = new List<Dictionary<string, object?>>();
        foreach (var pc in r.PerChallenge.OrderBy(x => x.ChallengeId))
        {
            var perSolver = new List<Dictionary<string, object?>>();
            foreach (var s in pc.PerSolver)
            {
                perSolver.Add(new Dictionary<string, object?>
                {
                    ["solver_id"] = s.SolverId,
                    ["model_id"] = s.ModelId,
                    ["outcome"] = s.Outcome.ToString(),
                    ["turns"] = s.Turns,
                    ["elapsed_ms"] = (long)s.Elapsed.TotalMilliseconds,
                    ["usd_cost"] = s.UsdCost,
                    ["loop_kind"] = s.LoopKind,
                    ["failure_reason"] = s.FailureReason,
                    ["flag_sha256"] = s.FlagSubmitted is { Length: > 0 } f ? Sha256Hex(f) : null,
                });
            }
            perChallenge.Add(new Dictionary<string, object?>
            {
                ["challenge_id"] = pc.ChallengeId,
                ["challenge_name"] = pc.ChallengeName,
                ["combined_outcome"] = pc.CombinedOutcome.ToString(),
                ["winning_solver_id"] = pc.WinningSolverId,
                ["winning_model_id"] = pc.WinningModelId,
                ["total_elapsed_ms"] = (long)pc.TotalElapsed.TotalMilliseconds,
                ["total_usd_cost"] = pc.TotalUsdCost,
                ["per_solver"] = perSolver,
            });
        }

        var header = string.Format(CultureInfo.InvariantCulture, TatumIntro,
            Math.Max(1, r.PerChallenge.SelectMany(pc => pc.PerSolver).Select(s => s.ModelId)
                .Where(m => !string.IsNullOrEmpty(m))
                .Distinct(StringComparer.Ordinal).Count()));

        var payload = new Dictionary<string, object?>
        {
            ["header"] = header,
            ["closing_quote"] = TatumClose,
            ["started_at"] = r.StartedAt,
            ["finished_at"] = r.FinishedAt,
            ["challenges_discovered"] = r.ChallengesDiscovered,
            ["challenges_attempted"] = r.ChallengesAttempted,
            ["challenges_solved"] = r.ChallengesSolved,
            ["points_scored"] = r.PointsScored,
            ["total_usd_cost"] = r.TotalUsdCost,
            ["solves_by_model"] = r.SolvesByModel,
            ["attempts_by_category"] = r.AttemptsByCategory,
            ["per_challenge"] = perChallenge,
            ["flag_sha256"] = CollectFlagHashes(r),
        };

        return JsonSerializer.Serialize(payload, JsonOpts);
    }

    private static IReadOnlyList<string> CollectFlagHashes(CompetitionReport r)
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var pc in r.PerChallenge)
        {
            foreach (var s in pc.PerSolver)
            {
                if (s.FlagSubmitted is { Length: > 0 } f)
                {
                    set.Add(Sha256Hex(f));
                }
            }
        }
        return set.ToArray();
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string EscapeMd(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
    }
}
