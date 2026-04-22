using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Drederick.Autopilot;

/// <summary>
/// Persists <see cref="AutopilotReport"/> to human-readable Markdown + JSON
/// and to the shared <c>findings.db</c> (flags + autopilot_actions tables).
/// All artefacts live under the run's <c>out/</c> directory.
/// </summary>
public static class AutopilotReporter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    public static void Write(string outputDir, AutopilotReport report)
    {
        ArgumentNullException.ThrowIfNull(outputDir);
        ArgumentNullException.ThrowIfNull(report);
        Directory.CreateDirectory(outputDir);

        WriteJson(Path.Combine(outputDir, "autopilot.json"), report);
        WriteMarkdown(Path.Combine(outputDir, "autopilot.md"), report);
        TryWriteSqlite(Path.Combine(outputDir, "findings.db"), report);
    }

    internal static void WriteJson(string path, AutopilotReport report)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
    }

    internal static void WriteMarkdown(string path, AutopilotReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Autopilot — fight card");
        sb.AppendLine();
        sb.AppendLine("> *\"Ladies and gentlemen…\"* — Drederick E. Tatum, cornerman of the");
        sb.AppendLine("> heavyweight harness. Every punch below was re-validated through");
        sb.AppendLine("> the scope + permission gates on the underlying tool. I must");
        sb.AppendLine("> dissent from any bypass.");
        sb.AppendLine();
        sb.AppendLine($"- rounds fought: **{report.Iterations}**");
        sb.AppendLine($"- punches thrown: **{report.Actions.Count}**");
        sb.AppendLine($"- connects: **{report.Actions.Count(a => a.Succeeded)}**");
        sb.AppendLine($"- slipped (skipped): **{report.Actions.Count(a => a.Skipped)}**");
        sb.AppendLine($"- knockouts (flags captured): **{report.Flags.Count}**");
        sb.AppendLine($"- sparring partners in the book (credentials): **{report.KnownCredentials.Count}**");
        sb.AppendLine();

        if (report.Flags.Count > 0)
        {
            sb.AppendLine("## Knockouts");
            sb.AppendLine();
            sb.AppendLine("| pattern | value | corner (source) |");
            sb.AppendLine("| --- | --- | --- |");
            foreach (var f in report.Flags)
            {
                sb.AppendLine($"| `{EscapeMd(TrimPattern(f.Pattern))}` | `{EscapeMd(f.Value)}` | `{EscapeMd(f.Source)}` |");
            }
            sb.AppendLine();
        }

        if (report.Actions.Count > 0)
        {
            sb.AppendLine("## Round-by-round");
            sb.AppendLine();
            sb.AppendLine("| tool | opponent | priority | result | notes |");
            sb.AppendLine("| --- | --- | --- | --- | --- |");
            foreach (var r in report.Actions.OrderByDescending(r => r.Action.Priority))
            {
                var status = r.Succeeded ? "✓ connect" : r.Skipped ? "⊘ slip" : "✗ miss";
                var tail = r.Skipped ? (r.SkipReason ?? "") : r.Error ?? r.Action.Reason;
                sb.AppendLine($"| {EscapeMd(r.Action.Tool)} | {EscapeMd(r.Action.Target)}:{r.Action.Port} | {r.Action.Priority} | {status} | {EscapeMd(tail)} |");
            }
            sb.AppendLine();
        }

        if (report.KnownCredentials.Count > 0)
        {
            sb.AppendLine("## Sparring partners (credential digests only)");
            sb.AppendLine();
            sb.AppendLine("> Plaintext stays in the locker room — we record SHA-256 only.");
            sb.AppendLine();
            sb.AppendLine("| user | realm | password_sha256 |");
            sb.AppendLine("| --- | --- | --- |");
            foreach (var c in report.KnownCredentials)
            {
                sb.AppendLine($"| {EscapeMd(c.User)} | {EscapeMd(c.Realm ?? "-")} | `{c.PasswordSha256[..16]}…` |");
            }
            sb.AppendLine();
        }

        File.WriteAllText(path, sb.ToString());
    }

    internal static void TryWriteSqlite(string dbPath, AutopilotReport report)
    {
        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            EnsureSchema(conn);

            using var tx = conn.BeginTransaction();
            foreach (var f in report.Flags)
            {
                using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = @"INSERT OR IGNORE INTO flags(value, value_sha256, pattern, source, captured_at)
VALUES ($v, $vs, $p, $s, $c);";
                cmd.Parameters.AddWithValue("$v", f.Value);
                cmd.Parameters.AddWithValue("$vs", f.ValueSha256);
                cmd.Parameters.AddWithValue("$p", f.Pattern);
                cmd.Parameters.AddWithValue("$s", f.Source);
                cmd.Parameters.AddWithValue("$c", DateTimeOffset.UtcNow.ToString("o"));
                cmd.ExecuteNonQuery();
            }

            foreach (var r in report.Actions)
            {
                using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = @"INSERT INTO autopilot_actions
(action_id, tool, target, port, priority, reason, succeeded, skipped, skip_reason, error, duration_ms, captured_at)
VALUES ($id, $tool, $t, $p, $pr, $rsn, $ok, $sk, $skr, $er, $d, $c);";
                cmd.Parameters.AddWithValue("$id", r.Action.Id);
                cmd.Parameters.AddWithValue("$tool", r.Action.Tool);
                cmd.Parameters.AddWithValue("$t", r.Action.Target);
                cmd.Parameters.AddWithValue("$p", r.Action.Port);
                cmd.Parameters.AddWithValue("$pr", r.Action.Priority);
                cmd.Parameters.AddWithValue("$rsn", r.Action.Reason);
                cmd.Parameters.AddWithValue("$ok", r.Succeeded ? 1 : 0);
                cmd.Parameters.AddWithValue("$sk", r.Skipped ? 1 : 0);
                cmd.Parameters.AddWithValue("$skr", (object?)r.SkipReason ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$er", (object?)r.Error ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$d", r.DurationMs);
                cmd.Parameters.AddWithValue("$c", DateTimeOffset.UtcNow.ToString("o"));
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
        catch (SqliteException)
        {
            // findings.db may not exist yet if the earlier SqliteReport didn't
            // run (e.g. all findings filtered out). Silent swallow keeps
            // autopilot non-fatal; autopilot.json is authoritative.
        }
    }

    internal static void EnsureSchema(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS flags(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    value_sha256 TEXT NOT NULL UNIQUE,
    pattern TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS autopilot_actions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    reason TEXT,
    succeeded INTEGER NOT NULL,
    skipped INTEGER NOT NULL,
    skip_reason TEXT,
    error TEXT,
    duration_ms INTEGER NOT NULL,
    captured_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autopilot_target ON autopilot_actions(target);
CREATE INDEX IF NOT EXISTS idx_flags_source ON flags(source);";
        cmd.ExecuteNonQuery();
    }

    private static string EscapeMd(string? s) => (s ?? "")
        .Replace("|", "\\|")
        .Replace("\n", " ")
        .Replace("\r", "");

    private static string TrimPattern(string p) => p.Length <= 40 ? p : p[..37] + "...";
}
