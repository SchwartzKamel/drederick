using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

namespace Drederick.Telemetry;

/// <summary>
/// Singleton-scoped per-attempt telemetry recorder. Writes structured rows to
/// <c>out/telemetry.db</c> (SQLite) for the self-improving feedback loop
/// described in <c>docs/LEARNING_LOOP.md</c>.
///
/// <para><b>Distinct from <see cref="Drederick.Audit.AuditLog"/>.</b> The audit
/// log is the immutable JSONL safety record; the telemetry DB is the analytics
/// substrate. Telemetry is additive — never replaces audit entries.</para>
///
/// <para><b>Thread safety.</b> Writes serialize behind a
/// <see cref="SemaphoreSlim"/>(1). Reads open their own connection and may run
/// concurrently with writes (SQLite handles this safely).</para>
///
/// <para><b>Privacy invariants.</b>
///   • RFC1918 / RFC4193 / loopback / link-local target hosts are redacted to
///     their first <c>/24</c> (v4) or <c>/48</c> (v6) before persistence.
///   • Plaintext secrets MUST NOT appear in any field — telemetry echoes the
///     same no-plaintext-secrets invariant the audit log enforces.</para>
///
/// <para><b>Off switch.</b> When constructed with <c>enabled: false</c>
/// (CLI <c>--no-telemetry</c>), <see cref="RecordAsync"/> is a no-op and
/// <see cref="QueryAsync"/> yields nothing — no DB file is created.</para>
/// </summary>
public sealed class TelemetryRecorder : IAsyncDisposable, IDisposable
{
    private readonly string _dbPath;
    private readonly bool _enabled;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private bool _schemaEnsured;
    private readonly Lock _schemaGate = new();

    public string DatabasePath => _dbPath;
    public bool Enabled => _enabled;

    public TelemetryRecorder(string dbPath, bool enabled = true)
    {
        if (string.IsNullOrWhiteSpace(dbPath))
            throw new ArgumentException("dbPath is required", nameof(dbPath));
        _dbPath = dbPath;
        _enabled = enabled;
    }

    private void EnsureSchema()
    {
        if (_schemaEnsured) return;
        lock (_schemaGate)
        {
            if (_schemaEnsured) return;
            var dir = Path.GetDirectoryName(_dbPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = SchemaSql;
            cmd.ExecuteNonQuery();
            _schemaEnsured = true;
        }
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        return conn;
    }

    /// <summary>Idempotent migration. <c>CREATE TABLE/INDEX IF NOT EXISTS</c>.</summary>
    internal const string SchemaSql = @"
CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    fight_id TEXT,
    technique_id TEXT NOT NULL,
    target_archetype TEXT,
    target_host TEXT,
    service TEXT,
    port INTEGER,
    outcome TEXT NOT NULL CHECK(outcome IN ('success','fail','error','skipped')),
    time_ms INTEGER NOT NULL,
    llm_cost_tokens INTEGER,
    audit_correlation_id TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_telemetry_archetype_technique ON telemetry_events(target_archetype, technique_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_fight ON telemetry_events(fight_id);
";

    public async Task RecordAsync(TelemetryEvent ev, CancellationToken ct = default)
    {
        if (!_enabled) return;
        ArgumentNullException.ThrowIfNull(ev);
        if (string.IsNullOrWhiteSpace(ev.TechniqueId))
            throw new ArgumentException("technique_id is required", nameof(ev));
        if (!TelemetryOutcome.IsValid(ev.Outcome))
            throw new ArgumentException(
                $"outcome must be one of success/fail/error/skipped, got '{ev.Outcome}'",
                nameof(ev));

        var ts = string.IsNullOrEmpty(ev.Timestamp)
            ? DateTimeOffset.UtcNow.ToString("o")
            : ev.Timestamp;

        var redactedHost = RedactHost(ev.TargetHost);

        EnsureSchema();
        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
INSERT INTO telemetry_events
(timestamp, fight_id, technique_id, target_archetype, target_host, service, port,
 outcome, time_ms, llm_cost_tokens, audit_correlation_id, notes)
VALUES ($ts, $fid, $tid, $arch, $host, $svc, $port, $out, $ms, $tok, $aud, $notes);
";
            cmd.Parameters.AddWithValue("$ts", ts);
            cmd.Parameters.AddWithValue("$fid", (object?)ev.FightId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$tid", ev.TechniqueId);
            cmd.Parameters.AddWithValue("$arch", (object?)ev.TargetArchetype ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$host", (object?)redactedHost ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$svc", (object?)ev.Service ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$port", (object?)ev.Port ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$out", ev.Outcome);
            cmd.Parameters.AddWithValue("$ms", ev.TimeMs);
            cmd.Parameters.AddWithValue("$tok", (object?)ev.LlmCostTokens ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$aud", (object?)ev.AuditCorrelationId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$notes", (object?)ev.Notes ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async IAsyncEnumerable<TelemetryEvent> QueryAsync(
        TelemetryQuery q,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(q);
        if (!_enabled || !File.Exists(_dbPath)) yield break;

        EnsureSchema();

        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        var sql = new System.Text.StringBuilder(@"
SELECT id, timestamp, fight_id, technique_id, target_archetype, target_host,
       service, port, outcome, time_ms, llm_cost_tokens, audit_correlation_id, notes
FROM telemetry_events
WHERE 1=1");
        if (q.FightId is not null)        { sql.Append(" AND fight_id = $fid");          cmd.Parameters.AddWithValue("$fid", q.FightId); }
        if (q.TechniqueId is not null)    { sql.Append(" AND technique_id = $tid");      cmd.Parameters.AddWithValue("$tid", q.TechniqueId); }
        if (q.TargetArchetype is not null){ sql.Append(" AND target_archetype = $arch"); cmd.Parameters.AddWithValue("$arch", q.TargetArchetype); }
        if (q.Service is not null)        { sql.Append(" AND service = $svc");           cmd.Parameters.AddWithValue("$svc", q.Service); }
        if (q.Outcome is not null)        { sql.Append(" AND outcome = $out");           cmd.Parameters.AddWithValue("$out", q.Outcome); }
        if (q.SinceTimestamp is not null) { sql.Append(" AND timestamp >= $since");      cmd.Parameters.AddWithValue("$since", q.SinceTimestamp); }
        if (q.UntilTimestamp is not null) { sql.Append(" AND timestamp <  $until");      cmd.Parameters.AddWithValue("$until", q.UntilTimestamp); }
        sql.Append(" ORDER BY id ASC LIMIT $limit");
        cmd.Parameters.AddWithValue("$limit", Math.Max(0, q.Limit));
        cmd.CommandText = sql.ToString();

        using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            yield return new TelemetryEvent
            {
                Id = reader.GetInt64(0),
                Timestamp = reader.GetString(1),
                FightId = reader.IsDBNull(2) ? null : reader.GetString(2),
                TechniqueId = reader.GetString(3),
                TargetArchetype = reader.IsDBNull(4) ? null : reader.GetString(4),
                TargetHost = reader.IsDBNull(5) ? null : reader.GetString(5),
                Service = reader.IsDBNull(6) ? null : reader.GetString(6),
                Port = reader.IsDBNull(7) ? null : reader.GetInt32(7),
                Outcome = reader.GetString(8),
                TimeMs = reader.GetInt64(9),
                LlmCostTokens = reader.IsDBNull(10) ? null : reader.GetInt64(10),
                AuditCorrelationId = reader.IsDBNull(11) ? null : reader.GetString(11),
                Notes = reader.IsDBNull(12) ? null : reader.GetString(12),
            };
        }
    }

    /// <summary>Redact private hosts to /24 (v4) / /48 (v6). Pass-through otherwise.</summary>
    public static string? RedactHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return host;
        if (!IPAddress.TryParse(host, out var ip)) return host;
        if (!IsPrivate(ip)) return host;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return $"{b[0]}.{b[1]}.{b[2]}.0/24";
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return string.Format(
                "{0:x}:{1:x}:{2:x}::/48",
                (b[0] << 8) | b[1], (b[2] << 8) | b[3], (b[4] << 8) | b[5]);
        }
        return host;
    }

    private static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 127) return true;
            return false;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
            var b = ip.GetAddressBytes();
            if ((b[0] & 0xfe) == 0xfc) return true;
            return false;
        }
        return false;
    }

    public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    public void Dispose() => _writeGate.Dispose();
}
