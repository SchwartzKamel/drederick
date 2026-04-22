import * as fs from "node:fs";
import * as path from "node:path";
import Database from "better-sqlite3";
import {
  FINDINGS_DB,
  OUT_DIR,
  CANARY_LOOT_SHA256,
  CANARY_JEOPARDY_FLAG_SHA256,
  CANARY_AUDIT_PLAINTEXT,
  AUDIT_LOG,
} from "./constants";

/**
 * Build a minimal findings.db with canary rows for invariant tests.
 *
 * Schema is mirrored from src/Drederick/Reporting/SqliteReport.cs (the
 * authoritative DDL). We DO NOT import or run the C# schema — tests stay
 * independent of build output — but we match the shape well enough that
 * the backend's read-only queries return rows.
 *
 * NOTE on the loot-plaintext invariant test: the production schema has
 * NO plaintext `value` column (value_sha256 only). This means we cannot
 * literally insert `flag{canary_loot_xyz}` into the table — the schema
 * itself enforces the invariant. The test therefore also plants the
 * plaintext canary in the `metadata` JSON column (a source-tool controlled
 * field); the backend's loot projection should never surface that either,
 * but even if it did today, the read-only invariant is that loot plaintext
 * should never reach the DOM.
 */
export function seedFindingsDb(): void {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  // Remove a stale DB from a previous run.
  if (fs.existsSync(FINDINGS_DB)) fs.unlinkSync(FINDINGS_DB);

  const db = new Database(FINDINGS_DB);
  db.pragma("journal_mode = WAL");

  // Schema DDL — mirror of SqliteReport.cs. Kept minimal; any column the
  // production writer sets that we don't seed is allowed to be NULL.
  db.exec(`
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
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY,
      session_id TEXT NOT NULL UNIQUE,
      target TEXT NOT NULL,
      protocol TEXT NOT NULL,
      via_tool TEXT NOT NULL,
      opened_at TEXT NOT NULL,
      closed_at TEXT
    );
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
  `);

  const now = new Date().toISOString();

  // --- hosts ---
  const insertHost = db.prepare(
    `INSERT INTO hosts (address, hostname, first_seen, last_seen)
     VALUES (?, ?, ?, ?)`,
  );
  const host1 = insertHost.run("10.0.0.10", "opponent-1.ring.local", now, now);
  const host2 = insertHost.run("10.0.0.11", "opponent-2.ring.local", now, now);

  // --- services ---
  const insertSvc = db.prepare(
    `INSERT INTO services (host_id, port, proto, service, product, version)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  const svc1 = insertSvc.run(host1.lastInsertRowid, 22, "tcp", "ssh", "OpenSSH", "8.2p1");
  const svc2 = insertSvc.run(host1.lastInsertRowid, 80, "tcp", "http", "nginx", "1.18.0");
  insertSvc.run(host2.lastInsertRowid, 445, "tcp", "microsoft-ds", "Samba", "4.11.6");

  // --- cves ---
  const insertCve = db.prepare(
    `INSERT INTO cves (cve_id, cvss, summary, published) VALUES (?, ?, ?, ?)`,
  );
  insertCve.run("CVE-2020-14145", 5.9, "OpenSSH observable discrepancy", now);
  insertCve.run("CVE-2021-23017", 9.4, "nginx DNS resolver off-by-one heap write", now);
  insertCve.run("CVE-2017-7494", 9.8, "SambaCry — SMB remote code execution", now);

  // --- findings ---
  const insertFinding = db.prepare(
    `INSERT INTO findings (host_id, service_id, kind, data_json, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  );
  insertFinding.run(
    host1.lastInsertRowid, svc2.lastInsertRowid, "cve-match",
    JSON.stringify({ cve_id: "CVE-2021-23017", cvss: 9.4, severity: "critical", summary: "nginx 1.18.0 matches CVE-2021-23017" }),
    now,
  );
  insertFinding.run(
    host1.lastInsertRowid, svc1.lastInsertRowid, "cve-match",
    JSON.stringify({ cve_id: "CVE-2020-14145", cvss: 5.9, severity: "medium", summary: "OpenSSH 8.2p1 matches CVE-2020-14145" }),
    now,
  );

  // --- poc_refs ---
  const insertPoc = db.prepare(
    `INSERT INTO poc_refs (cve_id, source, url, external_id, local_path, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  insertPoc.run("CVE-2021-23017", "exploit-db", "https://example.test/edb/50000", "50000", "poc_cache/exploit-db/50000/exploit.py", now);
  insertPoc.run("CVE-2017-7494", "metasploit", "https://example.test/msf/sambacry", "sambacry", "poc_cache/metasploit/sambacry.rb", now);

  // --- exploit_runs ---
  const insertRun = db.prepare(
    `INSERT INTO exploit_runs (tool, target, category, invocation_id, artifact, argv_digest, exit_code, started_at, finished_at, stdout_sha256, stderr_sha256, stdout_bytes, stderr_bytes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  insertRun.run(
    "metasploit", "10.0.0.11", "exec-poc", "inv-canary-1",
    "poc_cache/metasploit/sambacry.rb",
    "aa".repeat(32), 0, now, now,
    "bb".repeat(32), "cc".repeat(32), 1024, 0,
  );

  // --- sessions ---
  const insertSession = db.prepare(
    `INSERT INTO sessions (session_id, target, protocol, via_tool, opened_at, closed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  insertSession.run("sess-canary-1", "10.0.0.11", "smb", "metasploit", now, null);

  // --- loot (canary) ---
  // Plaintext is NOT inserted into a dedicated column (schema doesn't have
  // one). We plant the canary inside the metadata JSON blob as well — if
  // either the backend or the SPA surfaces that field, the loot-plaintext
  // invariant test will fail loudly.
  const insertLoot = db.prepare(
    `INSERT INTO loot (target, kind, value_sha256, source_tool, captured_at, metadata)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  insertLoot.run(
    "10.0.0.11",
    "credential",
    CANARY_LOOT_SHA256,
    "secretsdump.py",
    now,
    JSON.stringify({
      hint: "canary metadata blob — must never appear in DOM",
      _canary_plaintext: "flag{canary_loot_xyz}",
    }),
  );

  db.close();

  // --- audit.jsonl canary ---
  // Plant a canary plaintext inside an audit record's `extra` payload.
  // The audit redaction scanner (if any) or the audit page filter should
  // either redact or at least not re-surface the raw plaintext in the DOM.
  fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
  const entry = {
    ts: now,
    event: "test.canary.audit",
    data: {
      note: "canary audit entry — plaintext must not reach DOM",
      _canary: CANARY_AUDIT_PLAINTEXT,
    },
  };
  // Append so we don't clobber events the backend writes at startup.
  fs.appendFileSync(AUDIT_LOG, JSON.stringify(entry) + "\n");
}

/**
 * Utility: read the scope-file mtime (ns) for before/after comparison.
 */
export function scopeMtime(scopePath: string): number {
  const st = fs.statSync(scopePath);
  return Number(st.mtimeMs);
}
