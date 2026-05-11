using System.Text.Json;
using Drederick.Recon;
using Microsoft.Data.Sqlite;

namespace Drederick.Reporting;

public sealed class SqliteReport
{
    private readonly string _dbPath;

    public SqliteReport(string outputDir)
    {
        if (string.IsNullOrEmpty(outputDir))
        {
            throw new ArgumentException("outputDir is required", nameof(outputDir));
        }
        Directory.CreateDirectory(outputDir);
        _dbPath = Path.Combine(outputDir, "findings.db");
    }

    public string DatabasePath => _dbPath;

    private SqliteConnection OpenAndEnsureSchema()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        EnsureSchema(conn);
        return conn;
    }

    private static void EnsureSchema(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  hostname TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  UNIQUE(host_id, port, proto)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  service_id INTEGER REFERENCES services(id),
  kind TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
  ON findings(host_id, COALESCE(service_id, 0), kind, data_json);
CREATE TABLE IF NOT EXISTS cves (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  cvss REAL,
  summary TEXT,
  published TEXT
);
CREATE TABLE IF NOT EXISTS poc_refs (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT,
  external_id TEXT,
  local_path TEXT,
  fetched_at TEXT,
  UNIQUE(cve_id, source, external_id)
);
CREATE TABLE IF NOT EXISTS poc_sources (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  source_url TEXT,
  UNIQUE(source, external_id)
);
CREATE TABLE IF NOT EXISTS tooling (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT,
  source TEXT,
  path TEXT,
  detected_at TEXT NOT NULL,
  UNIQUE(name)
);
CREATE TABLE IF NOT EXISTS exploit_runs (
  id INTEGER PRIMARY KEY,
  tool TEXT NOT NULL,
  target TEXT NOT NULL,
  category TEXT NOT NULL,
  invocation_id TEXT NOT NULL UNIQUE,
  artifact TEXT,
  artifact_sha256 TEXT,
  argv_digest TEXT NOT NULL,
  exit_code INTEGER,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  stdout_bytes INTEGER,
  stdout_sha256 TEXT,
  stderr_bytes INTEGER,
  stderr_sha256 TEXT,
  work_dir TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_exploit_runs_target ON exploit_runs(target);
CREATE INDEX IF NOT EXISTS idx_exploit_runs_tool ON exploit_runs(tool);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  target TEXT NOT NULL,
  protocol TEXT NOT NULL,
  via_tool TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);
CREATE TABLE IF NOT EXISTS loot (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  kind TEXT NOT NULL,
  value_sha256 TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  metadata TEXT,
  UNIQUE(target, kind, value_sha256)
);
CREATE INDEX IF NOT EXISTS idx_loot_target ON loot(target);
-- --- phpinfo additions (GAP-054) ---
CREATE TABLE IF NOT EXISTS phpinfo_findings (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  source_url TEXT NOT NULL,
  php_version TEXT,
  disable_functions TEXT,
  open_basedir TEXT,
  allow_url_fopen TEXT,
  allow_url_include TEXT,
  file_uploads TEXT,
  upload_max_filesize TEXT,
  upload_tmp_dir TEXT,
  user_ini_filename TEXT,
  session_save_path TEXT,
  include_path TEXT,
  fpm_user TEXT,
  fpm_group TEXT,
  rce_on_write_likely INTEGER NOT NULL DEFAULT 0,
  user_ini_injection_likely INTEGER NOT NULL DEFAULT 0,
  captured_at TEXT NOT NULL,
  UNIQUE(target, source_url)
);
CREATE INDEX IF NOT EXISTS idx_phpinfo_target ON phpinfo_findings(target);
" + NotesSchema.GetCreateTableDdl() + @"
";
        cmd.ExecuteNonQuery();
    }

    public void WriteReport(IEnumerable<HostFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        using var conn = OpenAndEnsureSchema();
        using var tx = conn.BeginTransaction();
        var now = DateTimeOffset.UtcNow.ToString("o");

        foreach (var host in findings)
        {
            if (host is null || string.IsNullOrWhiteSpace(host.Target)) continue;
            var hostId = UpsertHost(conn, tx, host.Target, host.Dns?.Forward ?? host.Dns?.Reverse, now);

            if (host.Nmap is not null)
            {
                foreach (var p in host.Nmap.OpenPorts)
                {
                    var serviceId = UpsertService(conn, tx, hostId, p.Port, p.Protocol, p.Service, p.Product, p.Version);
                    var portData = JsonSerializer.Serialize(p);
                    InsertFinding(conn, tx, hostId, serviceId, "nmap", portData, now);
                    foreach (var s in p.Scripts)
                    {
                        InsertFinding(conn, tx, hostId, serviceId, "nmap-script",
                            JsonSerializer.Serialize(s), now);
                    }
                }
            }

            // GAP-040: also persist native-scan fallback open ports. Without
            // this block the services table is empty when nmap is missing
            // or returns empty (e.g. PingPong R1: 9 scans → 0 services rows).
            if (host.NativeScan is not null)
            {
                foreach (var p in host.NativeScan.OpenPorts)
                {
                    var serviceId = UpsertService(conn, tx, hostId, p.Port, p.Protocol, p.Service, p.Product, p.Version);
                    var portData = JsonSerializer.Serialize(p);
                    InsertFinding(conn, tx, hostId, serviceId, "native_scan", portData, now);
                }
            }

            foreach (var h in host.Http)
            {
                InsertFinding(conn, tx, hostId, null, "http", JsonSerializer.Serialize(h), now);
            }

            foreach (var t in host.Tls)
            {
                long? serviceId = null;
                if (t.Port > 0)
                {
                    serviceId = FindServiceId(conn, tx, hostId, t.Port, "tcp");
                }
                InsertFinding(conn, tx, hostId, serviceId, "tls", JsonSerializer.Serialize(t), now);
            }

            if (host.Dns is not null)
            {
                InsertFinding(conn, tx, hostId, null, "dns", JsonSerializer.Serialize(host.Dns), now);
            }
        }

        tx.Commit();
    }

    private static long UpsertHost(SqliteConnection conn, SqliteTransaction tx, string address, string? hostname, string now)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO hosts(address, hostname, first_seen, last_seen)
VALUES($address, $hostname, $now, $now)
ON CONFLICT(address) DO UPDATE SET
  hostname = COALESCE(excluded.hostname, hosts.hostname),
  last_seen = excluded.last_seen
RETURNING id;";
        cmd.Parameters.AddWithValue("$address", address);
        cmd.Parameters.AddWithValue("$hostname", (object?)hostname ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$now", now);
        var result = cmd.ExecuteScalar();
        return Convert.ToInt64(result);
    }

    private static long UpsertService(SqliteConnection conn, SqliteTransaction tx,
        long hostId, int port, string proto, string? service, string? product, string? version)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO services(host_id, port, proto, service, product, version)
VALUES($host_id, $port, $proto, $service, $product, $version)
ON CONFLICT(host_id, port, proto) DO UPDATE SET
  service = COALESCE(excluded.service, services.service),
  product = COALESCE(excluded.product, services.product),
  version = COALESCE(excluded.version, services.version)
RETURNING id;";
        cmd.Parameters.AddWithValue("$host_id", hostId);
        cmd.Parameters.AddWithValue("$port", port);
        cmd.Parameters.AddWithValue("$proto", proto ?? "tcp");
        cmd.Parameters.AddWithValue("$service", (object?)service ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$product", (object?)product ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$version", (object?)version ?? DBNull.Value);
        var result = cmd.ExecuteScalar();
        return Convert.ToInt64(result);
    }

    private static long? FindServiceId(SqliteConnection conn, SqliteTransaction tx, long hostId, int port, string proto)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT id FROM services WHERE host_id=$h AND port=$p AND proto=$pr LIMIT 1;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$p", port);
        cmd.Parameters.AddWithValue("$pr", proto);
        var result = cmd.ExecuteScalar();
        if (result is null || result is DBNull) return null;
        return Convert.ToInt64(result);
    }

    private static void InsertFinding(SqliteConnection conn, SqliteTransaction tx,
        long hostId, long? serviceId, string kind, string dataJson, string now)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO findings(host_id, service_id, kind, data_json, created_at)
VALUES($h, $s, $k, $d, $c)
ON CONFLICT(host_id, COALESCE(service_id, 0), kind, data_json) DO NOTHING;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$s", (object?)serviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$k", kind);
        cmd.Parameters.AddWithValue("$d", dataJson);
        cmd.Parameters.AddWithValue("$c", now);
        cmd.ExecuteNonQuery();
    }

    public void UpsertCve(string cveId, double? cvss = null, string? summary = null, string? published = null)
    {
        if (string.IsNullOrWhiteSpace(cveId)) throw new ArgumentException("cveId required", nameof(cveId));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO cves(cve_id, cvss, summary, published)
VALUES($id, $cvss, $summary, $published)
ON CONFLICT(cve_id) DO UPDATE SET
  cvss = COALESCE(excluded.cvss, cves.cvss),
  summary = COALESCE(excluded.summary, cves.summary),
  published = COALESCE(excluded.published, cves.published);";
        cmd.Parameters.AddWithValue("$id", cveId);
        cmd.Parameters.AddWithValue("$cvss", (object?)cvss ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$summary", (object?)summary ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$published", (object?)published ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void UpsertPocRef(string cveId, string source, string? url = null,
        string? externalId = null, string? localPath = null, string? fetchedAt = null)
    {
        if (string.IsNullOrWhiteSpace(cveId)) throw new ArgumentException("cveId required", nameof(cveId));
        if (string.IsNullOrWhiteSpace(source)) throw new ArgumentException("source required", nameof(source));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO poc_refs(cve_id, source, url, external_id, local_path, fetched_at)
VALUES($cve, $src, $url, $ext, $lp, $fa)
ON CONFLICT(cve_id, source, external_id) DO UPDATE SET
  url = COALESCE(excluded.url, poc_refs.url),
  local_path = COALESCE(excluded.local_path, poc_refs.local_path),
  fetched_at = COALESCE(excluded.fetched_at, poc_refs.fetched_at);";
        cmd.Parameters.AddWithValue("$cve", cveId);
        cmd.Parameters.AddWithValue("$src", source);
        cmd.Parameters.AddWithValue("$url", (object?)url ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ext", (object?)externalId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lp", (object?)localPath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$fa", (object?)fetchedAt ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void UpsertPocSource(string source, string externalId, string sha256, string path,
        string? fetchedAt = null, string? sourceUrl = null)
    {
        if (string.IsNullOrWhiteSpace(source)) throw new ArgumentException("source required", nameof(source));
        if (string.IsNullOrWhiteSpace(externalId)) throw new ArgumentException("externalId required", nameof(externalId));
        if (string.IsNullOrWhiteSpace(sha256)) throw new ArgumentException("sha256 required", nameof(sha256));
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("path required", nameof(path));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO poc_sources(source, external_id, sha256, path, fetched_at, source_url)
VALUES($src, $ext, $sha, $p, $fa, $url)
ON CONFLICT(source, external_id) DO UPDATE SET
  sha256 = excluded.sha256,
  path = excluded.path,
  fetched_at = excluded.fetched_at,
  source_url = COALESCE(excluded.source_url, poc_sources.source_url);";
        cmd.Parameters.AddWithValue("$src", source);
        cmd.Parameters.AddWithValue("$ext", externalId);
        cmd.Parameters.AddWithValue("$sha", sha256);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$fa", fetchedAt ?? DateTimeOffset.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$url", (object?)sourceUrl ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Persist an <see cref="Drederick.Exploit.ExploitRunRecord"/> into the
    /// <c>exploit_runs</c> table. Invocation id is the unique key; upsert
    /// semantics keep the final (finished) version.
    /// </summary>
    public void UpsertExploitRun(Drederick.Exploit.ExploitRunRecord r)
    {
        ArgumentNullException.ThrowIfNull(r);
        if (string.IsNullOrEmpty(r.InvocationId))
            throw new ArgumentException("ExploitRunRecord.InvocationId is required.", nameof(r));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO exploit_runs(tool, target, category, invocation_id, artifact, artifact_sha256,
                          argv_digest, exit_code, started_at, finished_at,
                          stdout_bytes, stdout_sha256, stderr_bytes, stderr_sha256, work_dir, error)
VALUES($tool, $target, $cat, $inv, $art, $artsha, $digest, $exit, $start, $finish,
       $sob, $sos, $seb, $ses, $wd, $err)
ON CONFLICT(invocation_id) DO UPDATE SET
  exit_code = excluded.exit_code,
  finished_at = excluded.finished_at,
  stdout_bytes = excluded.stdout_bytes,
  stdout_sha256 = excluded.stdout_sha256,
  stderr_bytes = excluded.stderr_bytes,
  stderr_sha256 = excluded.stderr_sha256,
  error = excluded.error;";
        cmd.Parameters.AddWithValue("$tool", r.Tool);
        cmd.Parameters.AddWithValue("$target", r.Target);
        cmd.Parameters.AddWithValue("$cat", r.Category);
        cmd.Parameters.AddWithValue("$inv", r.InvocationId);
        cmd.Parameters.AddWithValue("$art", (object?)r.Artifact ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$artsha", (object?)r.ArtifactSha256 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$digest", r.ArgvDigest);
        cmd.Parameters.AddWithValue("$exit", r.ExitCode);
        cmd.Parameters.AddWithValue("$start", r.StartedAt);
        cmd.Parameters.AddWithValue("$finish", r.FinishedAt);
        cmd.Parameters.AddWithValue("$sob", r.StdoutBytes);
        cmd.Parameters.AddWithValue("$sos", r.StdoutSha256);
        cmd.Parameters.AddWithValue("$seb", r.StderrBytes);
        cmd.Parameters.AddWithValue("$ses", r.StderrSha256);
        cmd.Parameters.AddWithValue("$wd", r.WorkDir);
        cmd.Parameters.AddWithValue("$err", (object?)r.Error ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Persist an opened / closed interactive session.</summary>
    public void UpsertSession(Drederick.Exploit.SessionRecord s)
    {
        ArgumentNullException.ThrowIfNull(s);
        if (string.IsNullOrEmpty(s.SessionId))
            throw new ArgumentException("SessionRecord.SessionId is required.", nameof(s));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO sessions(session_id, target, protocol, via_tool, opened_at, closed_at)
VALUES($sid, $target, $proto, $via, $opened, $closed)
ON CONFLICT(session_id) DO UPDATE SET
  closed_at = COALESCE(excluded.closed_at, sessions.closed_at);";
        cmd.Parameters.AddWithValue("$sid", s.SessionId);
        cmd.Parameters.AddWithValue("$target", s.Target);
        cmd.Parameters.AddWithValue("$proto", s.Protocol);
        cmd.Parameters.AddWithValue("$via", s.ViaTool);
        cmd.Parameters.AddWithValue("$opened", s.OpenedAt);
        cmd.Parameters.AddWithValue("$closed", (object?)s.ClosedAt ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Persist a captured credential/hash/ticket/secret. Only the
    /// SHA-256 of the value is stored centrally; plaintext stays in per-host
    /// loot files. <c>@invariant-id:no-exfiltration</c>.</summary>
    public void UpsertLoot(Drederick.Exploit.LootRecord l)
    {
        ArgumentNullException.ThrowIfNull(l);
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO loot(target, kind, value_sha256, source_tool, captured_at, metadata)
VALUES($t, $k, $sha, $src, $ts, $meta)
ON CONFLICT(target, kind, value_sha256) DO UPDATE SET
  metadata = COALESCE(excluded.metadata, loot.metadata),
  captured_at = excluded.captured_at;";
        cmd.Parameters.AddWithValue("$t", l.Target);
        cmd.Parameters.AddWithValue("$k", l.Kind);
        cmd.Parameters.AddWithValue("$sha", l.ValueSha256);
        cmd.Parameters.AddWithValue("$src", l.SourceTool);
        cmd.Parameters.AddWithValue("$ts", l.CapturedAt);
        cmd.Parameters.AddWithValue("$meta", (object?)l.Metadata ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void UpsertTooling(string name, string? version = null, string? source = null,
        string? path = null, string? detectedAt = null)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("name required", nameof(name));
        using var conn = OpenAndEnsureSchema();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO tooling(name, version, source, path, detected_at)
VALUES($n, $v, $s, $p, $da)
ON CONFLICT(name) DO UPDATE SET
  version = COALESCE(excluded.version, tooling.version),
  source = COALESCE(excluded.source, tooling.source),
  path = COALESCE(excluded.path, tooling.path),
  detected_at = excluded.detected_at;";
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$v", (object?)version ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", (object?)source ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$p", (object?)path ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$da", detectedAt ?? DateTimeOffset.UtcNow.ToString("o"));
        cmd.ExecuteNonQuery();
    }
}
