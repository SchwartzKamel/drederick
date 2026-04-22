using System.Data;
using Microsoft.Data.Sqlite;

namespace Drederick.Web.Data;

/// <summary>
/// Read-only query facade over <c>findings.db</c>. Every query is
/// parametrized; no string concatenation of caller input. Opens a fresh
/// <see cref="SqliteConnection"/> per call — the DB is sized for operator
/// triage, not high throughput, and per-call connections keep reader
/// isolation clean across concurrent HTTP requests.
///
/// <para>
/// Invariant posture:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — the owning
///     endpoint records a <c>web.findings.query</c> event; this class is
///     strictly read-only and never writes to either the DB or the audit
///     log.</description></item>
///   <item><description><c>@invariant-id:no-exfiltration</c> — the
///     <c>loot</c> table is exposed via <see cref="ListLoot"/> which
///     projects only <c>value_sha256</c>-shaped columns; the underlying
///     schema has no plaintext <c>value</c> column, and
///     <c>metadata</c> is a source-tool controlled JSON string that
///     <see cref="Drederick.Reporting.SqliteReport"/> only populates with
///     non-secret envelope data.</description></item>
/// </list>
/// </para>
/// </summary>
public sealed class FindingsQueries
{
    private readonly WebAppSettings _settings;

    public FindingsQueries(WebAppSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public string DatabasePath => Path.Combine(_settings.OutputDir, "findings.db");

    public bool DatabaseExists() => File.Exists(DatabasePath);

    private SqliteConnection Open()
    {
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared,
        }.ToString();
        var conn = new SqliteConnection(cs);
        conn.Open();
        return conn;
    }

    public static int ClampLimit(int? limit) =>
        Math.Clamp(limit ?? 100, 1, 1000);

    public static int ClampOffset(int? offset) =>
        Math.Max(0, offset ?? 0);

    /// <summary>
    /// Map a CVSS v3 base score to a severity bucket. Uses the standard
    /// FIRST.org ranges: critical (9.0+), high (7.0–8.9), medium (4.0–6.9),
    /// low (0.1–3.9).
    /// </summary>
    public static string CvssToSeverity(double? cvss)
    {
        if (cvss is null) return "unknown";
        var v = cvss.Value;
        if (v >= 9.0) return "critical";
        if (v >= 7.0) return "high";
        if (v >= 4.0) return "medium";
        if (v > 0) return "low";
        return "unknown";
    }

    public static (double lo, double hi) SeverityRange(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" => (9.0, 10.01),
            "high" => (7.0, 9.0),
            "medium" => (4.0, 7.0),
            "low" => (0.01, 4.0),
            _ => (-1.0, -1.0),
        };

    // ---------- hosts ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListHosts(
        string? q, int limit, int offset)
    {
        using var conn = Open();
        var where = string.IsNullOrWhiteSpace(q)
            ? ""
            : "WHERE h.address LIKE @q OR COALESCE(h.hostname,'') LIKE @q";

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM hosts h {where};",
            p => { if (!string.IsNullOrWhiteSpace(q)) p.AddWithValue("@q", "%" + q + "%"); });

        var items = Query(conn, $@"
SELECT h.id, h.address, h.hostname, h.first_seen, h.last_seen,
       (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id) AS services_count
FROM hosts h
{where}
ORDER BY h.id
LIMIT @limit OFFSET @offset;", p =>
        {
            if (!string.IsNullOrWhiteSpace(q)) p.AddWithValue("@q", "%" + q + "%");
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    public Dictionary<string, object?>? GetHost(long id)
    {
        using var conn = Open();
        var rows = Query(conn, @"
SELECT h.id, h.address, h.hostname, h.first_seen, h.last_seen,
       (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id) AS services_count,
       (SELECT COUNT(*) FROM findings f WHERE f.host_id = h.id) AS findings_count,
       (SELECT COUNT(*)
          FROM findings f
          WHERE f.host_id = h.id
            AND json_extract(f.data_json, '$.cve_id') IS NOT NULL) AS cves_count
FROM hosts h
WHERE h.id = @id
LIMIT 1;", p => p.AddWithValue("@id", id));
        return rows.Count == 0 ? null : rows[0];
    }

    // ---------- services ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListServices(
        long? hostId, int limit, int offset)
    {
        using var conn = Open();
        var where = hostId.HasValue ? "WHERE host_id = @host" : "";

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM services {where};",
            p => { if (hostId.HasValue) p.AddWithValue("@host", hostId.Value); });

        var items = Query(conn, $@"
SELECT id, host_id, port, proto AS protocol, service AS service_name,
       product, version
FROM services
{where}
ORDER BY host_id, port
LIMIT @limit OFFSET @offset;", p =>
        {
            if (hostId.HasValue) p.AddWithValue("@host", hostId.Value);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    public Dictionary<string, object?>? GetService(long id)
    {
        using var conn = Open();
        var rows = Query(conn, @"
SELECT id, host_id, port, proto AS protocol, service AS service_name,
       product, version
FROM services WHERE id = @id LIMIT 1;", p => p.AddWithValue("@id", id));
        if (rows.Count == 0) return null;

        var cves = Query(conn, @"
SELECT DISTINCT json_extract(f.data_json, '$.cve_id') AS cve_id,
       c.cvss, c.summary, c.published
FROM findings f
LEFT JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id')
WHERE f.service_id = @sid
  AND json_extract(f.data_json, '$.cve_id') IS NOT NULL
ORDER BY c.cvss DESC;", p => p.AddWithValue("@sid", id));

        foreach (var c in cves)
        {
            c["severity"] = CvssToSeverity(c.TryGetValue("cvss", out var cv) ? cv as double? : null);
        }

        rows[0]["cves"] = cves;
        return rows[0];
    }

    // ---------- cves ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListCves(
        long? hostId, long? serviceId, string? severity, int limit, int offset)
    {
        using var conn = Open();
        var clauses = new List<string>();
        Action<SqliteParameterCollection> bind;

        string sql;
        string countSql;

        (double lo, double hi) range = (-1, -1);
        if (!string.IsNullOrWhiteSpace(severity))
        {
            range = SeverityRange(severity);
            if (range.lo < 0)
            {
                return (Array.Empty<Dictionary<string, object?>>(), 0);
            }
        }

        if (hostId.HasValue || serviceId.HasValue)
        {
            var filterClauses = new List<string>
            {
                "json_extract(f.data_json, '$.cve_id') IS NOT NULL",
            };
            if (hostId.HasValue) filterClauses.Add("f.host_id = @host");
            if (serviceId.HasValue) filterClauses.Add("f.service_id = @svc");
            if (range.lo >= 0) filterClauses.Add("c.cvss >= @sev_lo AND c.cvss < @sev_hi");

            var filterSql = "WHERE " + string.Join(" AND ", filterClauses);

            countSql = $@"
SELECT COUNT(*) FROM (
  SELECT DISTINCT json_extract(f.data_json, '$.cve_id') AS cve_id
  FROM findings f
  LEFT JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id')
  {filterSql}
);";
            sql = $@"
SELECT DISTINCT json_extract(f.data_json, '$.cve_id') AS cve_id,
       c.cvss, c.summary, c.published
FROM findings f
LEFT JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id')
{filterSql}
ORDER BY c.cvss DESC
LIMIT @limit OFFSET @offset;";
            bind = p =>
            {
                if (hostId.HasValue) p.AddWithValue("@host", hostId.Value);
                if (serviceId.HasValue) p.AddWithValue("@svc", serviceId.Value);
                if (range.lo >= 0)
                {
                    p.AddWithValue("@sev_lo", range.lo);
                    p.AddWithValue("@sev_hi", range.hi);
                }
                p.AddWithValue("@limit", limit);
                p.AddWithValue("@offset", offset);
            };
        }
        else
        {
            if (range.lo >= 0) clauses.Add("cvss >= @sev_lo AND cvss < @sev_hi");
            var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);

            countSql = $"SELECT COUNT(*) FROM cves {where};";
            sql = $@"
SELECT cve_id, cvss, summary, published
FROM cves {where}
ORDER BY cvss DESC
LIMIT @limit OFFSET @offset;";
            bind = p =>
            {
                if (range.lo >= 0)
                {
                    p.AddWithValue("@sev_lo", range.lo);
                    p.AddWithValue("@sev_hi", range.hi);
                }
                p.AddWithValue("@limit", limit);
                p.AddWithValue("@offset", offset);
            };
        }

        var total = Scalar<long>(conn, countSql, p =>
        {
            if (hostId.HasValue) p.AddWithValue("@host", hostId.Value);
            if (serviceId.HasValue) p.AddWithValue("@svc", serviceId.Value);
            if (range.lo >= 0)
            {
                p.AddWithValue("@sev_lo", range.lo);
                p.AddWithValue("@sev_hi", range.hi);
            }
        });
        var items = Query(conn, sql, bind);
        foreach (var r in items)
        {
            r["severity"] = CvssToSeverity(r.TryGetValue("cvss", out var cv) ? cv as double? : null);
        }
        return (items, (int)total);
    }

    public Dictionary<string, object?>? GetCve(string cveId)
    {
        using var conn = Open();
        var rows = Query(conn, @"
SELECT cve_id, cvss, summary, published
FROM cves WHERE cve_id = @id LIMIT 1;", p => p.AddWithValue("@id", cveId));
        if (rows.Count == 0) return null;
        rows[0]["severity"] = CvssToSeverity(
            rows[0].TryGetValue("cvss", out var cv) ? cv as double? : null);
        var pocs = Query(conn, @"
SELECT id, cve_id, source, url, external_id, local_path, fetched_at
FROM poc_refs WHERE cve_id = @id
ORDER BY id;", p => p.AddWithValue("@id", cveId));
        rows[0]["poc_refs"] = pocs;
        return rows[0];
    }

    // ---------- poc_refs ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListPocRefs(
        string? cveId, string? source, int limit, int offset)
    {
        using var conn = Open();
        var clauses = new List<string>();
        if (!string.IsNullOrWhiteSpace(cveId)) clauses.Add("pr.cve_id = @cve");
        if (!string.IsNullOrWhiteSpace(source)) clauses.Add("pr.source = @src");
        var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM poc_refs pr {where};", p =>
        {
            if (!string.IsNullOrWhiteSpace(cveId)) p.AddWithValue("@cve", cveId);
            if (!string.IsNullOrWhiteSpace(source)) p.AddWithValue("@src", source);
        });

        // Join poc_sources on (source, external_id) so callers get the
        // cached-artifact SHA-256 when one exists. match_confidence is not
        // currently persisted by SqliteReport — surfaced as NULL; Phase 3
        // can wire it once the column is added.
        var items = Query(conn, $@"
SELECT pr.id, pr.cve_id, pr.source, pr.url, pr.external_id,
       pr.local_path, pr.fetched_at,
       ps.sha256 AS sha256,
       NULL AS match_confidence
FROM poc_refs pr
LEFT JOIN poc_sources ps
  ON ps.source = pr.source AND ps.external_id = pr.external_id
{where}
ORDER BY pr.id
LIMIT @limit OFFSET @offset;", p =>
        {
            if (!string.IsNullOrWhiteSpace(cveId)) p.AddWithValue("@cve", cveId);
            if (!string.IsNullOrWhiteSpace(source)) p.AddWithValue("@src", source);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    // ---------- exploit_runs ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListExploitRuns(
        string? target, string? tool, string? category, int limit, int offset)
    {
        using var conn = Open();
        var clauses = new List<string>();
        if (!string.IsNullOrWhiteSpace(target)) clauses.Add("target = @t");
        if (!string.IsNullOrWhiteSpace(tool)) clauses.Add("tool = @tool");
        if (!string.IsNullOrWhiteSpace(category)) clauses.Add("category = @cat");
        var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM exploit_runs {where};", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(tool)) p.AddWithValue("@tool", tool);
            if (!string.IsNullOrWhiteSpace(category)) p.AddWithValue("@cat", category);
        });

        // NOTE: stdout / stderr content is intentionally NOT projected.
        // Only bytes + sha256 + work_dir pointer. See
        // @invariant-id:no-exfiltration.
        var items = Query(conn, $@"
SELECT id, invocation_id, target, tool, category, artifact, artifact_sha256,
       argv_digest, exit_code, started_at, finished_at,
       stdout_bytes, stdout_sha256, stderr_bytes, stderr_sha256,
       work_dir, error
FROM exploit_runs
{where}
ORDER BY id DESC
LIMIT @limit OFFSET @offset;", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(tool)) p.AddWithValue("@tool", tool);
            if (!string.IsNullOrWhiteSpace(category)) p.AddWithValue("@cat", category);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    // ---------- sessions ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListSessions(
        string? target, string? protocol, string? state, int limit, int offset)
    {
        using var conn = Open();
        var clauses = new List<string>();
        if (!string.IsNullOrWhiteSpace(target)) clauses.Add("target = @t");
        if (!string.IsNullOrWhiteSpace(protocol)) clauses.Add("protocol = @p");
        if (string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
            clauses.Add("closed_at IS NULL");
        else if (string.Equals(state, "closed", StringComparison.OrdinalIgnoreCase))
            clauses.Add("closed_at IS NOT NULL");
        var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM sessions {where};", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(protocol)) p.AddWithValue("@p", protocol);
        });

        var items = Query(conn, $@"
SELECT id, session_id, target, protocol, via_tool, opened_at, closed_at,
       CASE WHEN closed_at IS NULL THEN 'open' ELSE 'closed' END AS state
FROM sessions
{where}
ORDER BY id DESC
LIMIT @limit OFFSET @offset;", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(protocol)) p.AddWithValue("@p", protocol);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    // ---------- loot ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListLoot(
        string? target, string? kind, int limit, int offset)
    {
        using var conn = Open();
        var clauses = new List<string>();
        if (!string.IsNullOrWhiteSpace(target)) clauses.Add("target = @t");
        if (!string.IsNullOrWhiteSpace(kind)) clauses.Add("kind = @k");
        var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM loot {where};", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(kind)) p.AddWithValue("@k", kind);
        });

        // The loot schema has no plaintext `value` column — SqliteReport
        // only ever inserts (target, kind, value_sha256, source_tool,
        // captured_at, metadata). We project the existing non-secret
        // columns only; the `metadata` field is tool-controlled JSON and
        // MAY contain captured plaintext depending on the source tool, so
        // per @invariant-id:no-exfiltration we redact it at the query
        // boundary. Operators who need metadata can read findings.db
        // directly via datasette (same host, same auth posture).
        var items = Query(conn, $@"
SELECT id, target, kind, value_sha256, source_tool, captured_at
FROM loot
{where}
ORDER BY id DESC
LIMIT @limit OFFSET @offset;", p =>
        {
            if (!string.IsNullOrWhiteSpace(target)) p.AddWithValue("@t", target);
            if (!string.IsNullOrWhiteSpace(kind)) p.AddWithValue("@k", kind);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    // ---------- findings (generic) ----------

    public (IReadOnlyList<Dictionary<string, object?>> items, int total) ListFindings(
        long? hostId, int limit, int offset)
    {
        using var conn = Open();
        var where = hostId.HasValue ? "WHERE host_id = @h" : "";

        var total = Scalar<long>(conn, $"SELECT COUNT(*) FROM findings {where};",
            p => { if (hostId.HasValue) p.AddWithValue("@h", hostId.Value); });

        var items = Query(conn, $@"
SELECT id, host_id, service_id, kind, data_json, created_at
FROM findings
{where}
ORDER BY id DESC
LIMIT @limit OFFSET @offset;", p =>
        {
            if (hostId.HasValue) p.AddWithValue("@h", hostId.Value);
            p.AddWithValue("@limit", limit);
            p.AddWithValue("@offset", offset);
        });

        return (items, (int)total);
    }

    // ---------- summary ----------

    public Dictionary<string, object?> Summary()
    {
        using var conn = Open();
        var result = new Dictionary<string, object?>
        {
            ["hosts"] = Scalar<long>(conn, "SELECT COUNT(*) FROM hosts;", _ => { }),
            ["services"] = Scalar<long>(conn, "SELECT COUNT(*) FROM services;", _ => { }),
            ["findings"] = Scalar<long>(conn, "SELECT COUNT(*) FROM findings;", _ => { }),
            ["poc_refs"] = Scalar<long>(conn, "SELECT COUNT(*) FROM poc_refs;", _ => { }),
        };

        var sev = new Dictionary<string, long>
        {
            ["critical"] = 0,
            ["high"] = 0,
            ["medium"] = 0,
            ["low"] = 0,
            ["unknown"] = 0,
        };
        foreach (var row in Query(conn, "SELECT cvss FROM cves;", _ => { }))
        {
            sev[CvssToSeverity(row["cvss"] as double?)] += 1;
        }
        result["cves_by_severity"] = sev;
        result["cves"] = sev.Values.Sum();

        var byCat = new Dictionary<string, long>();
        foreach (var row in Query(conn,
            "SELECT category, COUNT(*) AS n FROM exploit_runs GROUP BY category;", _ => { }))
        {
            var cat = row["category"] as string ?? "unknown";
            byCat[cat] = row["n"] as long? ?? 0;
        }
        result["exploit_runs_by_category"] = byCat;
        result["exploit_runs"] = byCat.Values.Sum();

        result["sessions_open"] = Scalar<long>(conn,
            "SELECT COUNT(*) FROM sessions WHERE closed_at IS NULL;", _ => { });
        result["sessions_closed"] = Scalar<long>(conn,
            "SELECT COUNT(*) FROM sessions WHERE closed_at IS NOT NULL;", _ => { });

        var byKind = new Dictionary<string, long>();
        foreach (var row in Query(conn,
            "SELECT kind, COUNT(*) AS n FROM loot GROUP BY kind;", _ => { }))
        {
            var k = row["kind"] as string ?? "unknown";
            byKind[k] = row["n"] as long? ?? 0;
        }
        result["loot_by_kind"] = byKind;
        result["loot"] = byKind.Values.Sum();

        return result;
    }

    // ---------- helpers ----------

    private static List<Dictionary<string, object?>> Query(
        SqliteConnection conn, string sql, Action<SqliteParameterCollection> bind)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        bind(cmd.Parameters);
        using var r = cmd.ExecuteReader();
        var rows = new List<Dictionary<string, object?>>();
        while (r.Read())
        {
            var row = new Dictionary<string, object?>(capacity: r.FieldCount);
            for (int i = 0; i < r.FieldCount; i++)
            {
                var name = r.GetName(i);
                row[name] = r.IsDBNull(i) ? null : r.GetValue(i);
            }
            rows.Add(row);
        }
        return rows;
    }

    private static T Scalar<T>(SqliteConnection conn, string sql,
        Action<SqliteParameterCollection> bind) where T : struct
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        bind(cmd.Parameters);
        var v = cmd.ExecuteScalar();
        if (v is null || v is DBNull) return default;
        return (T)Convert.ChangeType(v, typeof(T));
    }
}
