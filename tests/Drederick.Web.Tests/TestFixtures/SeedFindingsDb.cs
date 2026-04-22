using Microsoft.Data.Sqlite;

namespace Drederick.Web.Tests.TestFixtures;

/// <summary>
/// Creates and seeds a throw-away <c>findings.db</c> with deterministic
/// canned rows: 3 hosts, 10 services, 20 cves, 30 poc_refs, 5 exploit_runs,
/// 2 sessions, 4 loot rows. The schema DDL mirrors
/// <see cref="Drederick.Reporting.SqliteReport"/> exactly — tests use the
/// schema that production code writes, not a simplified version.
///
/// <para>
/// One of the four seeded loot rows carries the canary metadata string
/// <c>flag{canary_loot_xyz}</c>. The
/// <c>Loot_List_NeverReturnsPlaintextValue</c> test asserts this string
/// never appears in a response body — a regression check against the
/// endpoint ever projecting tool-controlled metadata or (via schema drift)
/// a plaintext value column.
/// </para>
/// </summary>
internal static class SeedFindingsDb
{
    public const string LootCanary = "flag{canary_loot_xyz}";

    public static void CreateAndSeed(string dbPath)
    {
        if (File.Exists(dbPath)) File.Delete(dbPath);
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);

        var cs = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();
        using var conn = new SqliteConnection(cs);
        conn.Open();
        CreateSchema(conn);
        Seed(conn);
    }

    private static void CreateSchema(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
PRAGMA foreign_keys = ON;
CREATE TABLE hosts (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  hostname TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE services (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  UNIQUE(host_id, port, proto)
);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  service_id INTEGER REFERENCES services(id),
  kind TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE cves (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  cvss REAL,
  summary TEXT,
  published TEXT
);
CREATE TABLE poc_refs (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT,
  external_id TEXT,
  local_path TEXT,
  fetched_at TEXT,
  UNIQUE(cve_id, source, external_id)
);
CREATE TABLE poc_sources (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  source_url TEXT,
  UNIQUE(source, external_id)
);
CREATE TABLE exploit_runs (
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
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  target TEXT NOT NULL,
  protocol TEXT NOT NULL,
  via_tool TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE TABLE loot (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  kind TEXT NOT NULL,
  value_sha256 TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  metadata TEXT,
  UNIQUE(target, kind, value_sha256)
);
";
        cmd.ExecuteNonQuery();
    }

    private static void Seed(SqliteConnection conn)
    {
        using var tx = conn.BeginTransaction();
        var now = "2024-01-01T00:00:00Z";

        var hostAddrs = new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3" };
        for (int i = 0; i < hostAddrs.Length; i++)
        {
            Exec(conn, tx,
                "INSERT INTO hosts(id, address, hostname, first_seen, last_seen) VALUES ($id,$a,$h,$f,$l);",
                ("$id", i + 1), ("$a", hostAddrs[i]), ("$h", $"host{i + 1}.lab"),
                ("$f", now), ("$l", now));
        }

        var services = new (int host, int port, string proto, string svc, string product, string version)[]
        {
            (1, 22, "tcp", "ssh", "OpenSSH", "7.4"),
            (1, 80, "tcp", "http", "nginx", "1.14.0"),
            (1, 443, "tcp", "https", "nginx", "1.14.0"),
            (1, 3306, "tcp", "mysql", "MySQL", "5.7.32"),
            (2, 22, "tcp", "ssh", "OpenSSH", "8.2"),
            (2, 445, "tcp", "smb", "Samba", "4.11.6"),
            (2, 5985, "tcp", "winrm", "Microsoft", "10.0"),
            (3, 21, "tcp", "ftp", "vsftpd", "2.3.4"),
            (3, 8080, "tcp", "http", "Apache", "2.4.49"),
            (3, 9200, "tcp", "elasticsearch", "Elastic", "6.8.0"),
        };
        for (int i = 0; i < services.Length; i++)
        {
            var s = services[i];
            Exec(conn, tx,
                "INSERT INTO services(id, host_id, port, proto, service, product, version) VALUES ($id,$h,$p,$pr,$s,$pd,$v);",
                ("$id", i + 1), ("$h", s.host), ("$p", s.port), ("$pr", s.proto),
                ("$s", s.svc), ("$pd", s.product), ("$v", s.version));
        }

        var cves = new List<(string id, double cvss)>();
        for (int i = 0; i < 5; i++) cves.Add(($"CVE-2024-{1000 + i}", 9.5));
        for (int i = 0; i < 5; i++) cves.Add(($"CVE-2024-{2000 + i}", 7.5));
        for (int i = 0; i < 5; i++) cves.Add(($"CVE-2024-{3000 + i}", 5.0));
        for (int i = 0; i < 5; i++) cves.Add(($"CVE-2024-{4000 + i}", 2.5));
        for (int i = 0; i < cves.Count; i++)
        {
            Exec(conn, tx,
                "INSERT INTO cves(id, cve_id, cvss, summary, published) VALUES ($id,$c,$v,$s,$p);",
                ("$id", i + 1), ("$c", cves[i].id), ("$v", cves[i].cvss),
                ("$s", $"Test CVE {cves[i].id}"), ("$p", now));
        }

        var links = new (int hostId, int svcId, string cveId)[]
        {
            (1, 4, "CVE-2024-1000"),
            (1, 2, "CVE-2024-2000"),
            (3, 8, "CVE-2024-1001"),
            (3, 9, "CVE-2024-2001"),
            (2, 6, "CVE-2024-3000"),
        };
        foreach (var l in links)
        {
            Exec(conn, tx,
                "INSERT INTO findings(host_id, service_id, kind, data_json, created_at) VALUES ($h,$s,'cve',$d,$c);",
                ("$h", l.hostId), ("$s", l.svcId),
                ("$d", $"{{\"cve_id\":\"{l.cveId}\"}}"), ("$c", now));
        }

        int pocCount = 0;
        for (int c = 0; c < 15 && pocCount < 30; c++)
        {
            foreach (var src in new[] { "exploit-db", "github" })
            {
                if (pocCount >= 30) break;
                Exec(conn, tx,
                    "INSERT INTO poc_refs(cve_id, source, url, external_id, local_path, fetched_at) VALUES ($c,$s,$u,$e,$l,$f);",
                    ("$c", cves[c].id), ("$s", src),
                    ("$u", $"https://example.test/{src}/{cves[c].id}"),
                    ("$e", $"{src}-{cves[c].id}"),
                    ("$l", $"out/poc_cache/{src}/{cves[c].id}"),
                    ("$f", now));
                pocCount++;
            }
        }

        var runs = new (string tool, string target, string cat, string invId, int exit)[]
        {
            ("metasploit", "10.0.0.1", "exploit", "inv-1", 0),
            ("hydra", "10.0.0.2", "cred", "inv-2", 1),
            ("nuclei", "10.0.0.3", "exploit", "inv-3", 0),
            ("searchsploit-poc", "10.0.0.1", "exploit", "inv-4", 2),
            ("msfvenom", "10.0.0.2", "payload", "inv-5", 0),
        };
        for (int i = 0; i < runs.Length; i++)
        {
            var r = runs[i];
            Exec(conn, tx, @"
INSERT INTO exploit_runs(tool, target, category, invocation_id, artifact, artifact_sha256,
                         argv_digest, exit_code, started_at, finished_at,
                         stdout_bytes, stdout_sha256, stderr_bytes, stderr_sha256,
                         work_dir, error)
VALUES ($tool,$t,$cat,$inv,$art,$asha,$argv,$ec,$s,$f,$sb,$ssha,$eb,$esha,$wd,NULL);",
                ("$tool", r.tool), ("$t", r.target), ("$cat", r.cat), ("$inv", r.invId),
                ("$art", $"artifact-{i}"), ("$asha", new string('a', 64)),
                ("$argv", new string('d', 64)), ("$ec", r.exit),
                ("$s", now), ("$f", now),
                ("$sb", 1024), ("$ssha", new string('b', 64)),
                ("$eb", 512), ("$esha", new string('c', 64)),
                ("$wd", $"out/{r.target}/{r.tool}"));
        }

        Exec(conn, tx,
            "INSERT INTO sessions(session_id, target, protocol, via_tool, opened_at, closed_at) VALUES ($id,$t,$p,$v,$o,NULL);",
            ("$id", "sess-open-1"), ("$t", "10.0.0.1"), ("$p", "meterpreter"),
            ("$v", "metasploit"), ("$o", now));
        Exec(conn, tx,
            "INSERT INTO sessions(session_id, target, protocol, via_tool, opened_at, closed_at) VALUES ($id,$t,$p,$v,$o,$c);",
            ("$id", "sess-closed-1"), ("$t", "10.0.0.2"), ("$p", "ssh"),
            ("$v", "evil-winrm"), ("$o", now), ("$c", now));

        // First loot row carries the plaintext canary inside metadata. This
        // simulates the worst case where a source tool wrote sensitive
        // material into metadata JSON. FindingsQueries.ListLoot must NOT
        // project metadata; the canary test enforces that guarantee.
        var loot = new (string t, string k, string sha, string tool, string meta)[]
        {
            ("10.0.0.1", "password",
             new string('1', 64), "hydra",
             "{\"user\":\"admin\",\"canary\":\"" + LootCanary + "\"}"),
            ("10.0.0.1", "hash",
             new string('2', 64), "secretsdump", "{\"user\":\"admin\"}"),
            ("10.0.0.2", "ticket",
             new string('3', 64), "rubeus", "{\"spn\":\"mssql\"}"),
            ("10.0.0.3", "password",
             new string('4', 64), "hydra", "{\"user\":\"root\"}"),
        };
        foreach (var l in loot)
        {
            Exec(conn, tx,
                "INSERT INTO loot(target, kind, value_sha256, source_tool, captured_at, metadata) VALUES ($t,$k,$v,$s,$c,$m);",
                ("$t", l.t), ("$k", l.k), ("$v", l.sha),
                ("$s", l.tool), ("$c", now), ("$m", l.meta));
        }

        tx.Commit();
    }

    private static void Exec(SqliteConnection conn, SqliteTransaction tx,
        string sql, params (string name, object? val)[] parms)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in parms) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
}
