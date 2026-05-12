using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;

namespace Drederick.Ops.FlagSubmission;

// --- htb-flag-submission ---

/// <summary>
/// Result of submitting a detected flag to an operator-side grading API
/// (HackTheBox v4 or a CTFd instance). Never carries the plaintext flag
/// or token — flags are referenced by SHA-256 digest only.
/// </summary>
public sealed class FlagSubmissionResult
{
    [JsonPropertyName("platform")] public string Platform { get; set; } = "";
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("response_code")] public int ResponseCode { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("flag_sha256")] public string FlagSha256 { get; set; } = "";
    [JsonPropertyName("submitted_at")] public DateTimeOffset SubmittedAt { get; set; }

    /// <summary>Optional context: which platform-side id was targeted
    /// (machine id for HTB machine, challenge id for HTB challenge / CTFd).
    /// Persisted alongside the result so a single operator can correlate
    /// submissions across multiple boxes.</summary>
    [JsonPropertyName("target_id")] public int? TargetId { get; set; }

    /// <summary>Optional kind discriminator: "machine" | "challenge".</summary>
    [JsonPropertyName("kind")] public string? Kind { get; set; }

    public static string Sha256Hex(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        var digest = SHA256.HashData(bytes);
        var sb = new StringBuilder(digest.Length * 2);
        foreach (var b in digest) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Append a result to <paramref name="path"/> as a JSON array
    /// (creates or updates idempotently). Stable enough for the operator
    /// to grep, jq, or open in any text editor.</summary>
    public static void AppendToJson(string path, FlagSubmissionResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        List<FlagSubmissionResult> list;
        if (File.Exists(path))
        {
            try
            {
                var existing = File.ReadAllText(path);
                list = string.IsNullOrWhiteSpace(existing)
                    ? new List<FlagSubmissionResult>()
                    : JsonSerializer.Deserialize<List<FlagSubmissionResult>>(existing) ?? new();
            }
            catch (JsonException)
            {
                list = new List<FlagSubmissionResult>();
            }
        }
        else
        {
            list = new List<FlagSubmissionResult>();
        }

        list.Add(result);
        File.WriteAllText(path, JsonSerializer.Serialize(list, JsonOpts));
    }

    /// <summary>Idempotent schema: creates <c>flag_submissions</c> if absent,
    /// then inserts. Dedupe on <c>(platform, target_id, flag_sha256)</c>.</summary>
    public static void PersistToSqlite(string dbPath, FlagSubmissionResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using (var ddl = conn.CreateCommand())
        {
            ddl.CommandText = @"
CREATE TABLE IF NOT EXISTS flag_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    kind TEXT,
    target_id INTEGER,
    flag_sha256 TEXT NOT NULL,
    success INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    message TEXT,
    submitted_at TEXT NOT NULL,
    UNIQUE(platform, target_id, flag_sha256)
);";
            ddl.ExecuteNonQuery();
        }
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO flag_submissions
    (platform, kind, target_id, flag_sha256, success, response_code, message, submitted_at)
VALUES ($p, $k, $t, $s, $ok, $rc, $m, $ts);";
        cmd.Parameters.AddWithValue("$p", result.Platform ?? "");
        cmd.Parameters.AddWithValue("$k", (object?)result.Kind ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$t", (object?)result.TargetId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", result.FlagSha256 ?? "");
        cmd.Parameters.AddWithValue("$ok", result.Success ? 1 : 0);
        cmd.Parameters.AddWithValue("$rc", result.ResponseCode);
        cmd.Parameters.AddWithValue("$m", (object?)result.Message ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ts", result.SubmittedAt.ToString("o", CultureInfo.InvariantCulture));
        cmd.ExecuteNonQuery();
    }
}

// --- end htb-flag-submission ---
