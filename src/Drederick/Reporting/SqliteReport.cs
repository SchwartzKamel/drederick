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
