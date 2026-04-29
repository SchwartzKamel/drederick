---
title: findings.db schema (machine-readable)
audience: [agents]
primary: agents
stability: stable
last_audited: 2026-04
related:
  - DATASETTE.md
  - EMPIRE.md
  - C2_INTEGRATION.md
  - ARCHITECTURE.md
  - ../AGENTS.md
  - ../src/Drederick/Reporting/SqliteReport.cs
---

# findings.db — schema reference

> **Authoritative DDL:** [`src/Drederick/Reporting/SqliteReport.cs`](../src/Drederick/Reporting/SqliteReport.cs),
> method `EnsureSchema`. This doc mirrors it. If the two disagree, the code
> wins and this doc is stale — file a PR.
>
> **Human-oriented walkthrough:** [`DATASETTE.md`](DATASETTE.md).

<a id="overview"></a>
## Overview

- Engine: SQLite 3, `PRAGMA foreign_keys = ON`.
- File path: `out/findings.db` (override via `drederick --out <dir>`).
- 11 tables, idempotent upserts across runs. The recon/enrichment core
  (`hosts`, `services`, `findings`, `cves`, `poc_refs`, `poc_sources`,
  `tooling`) is augmented by the offensive-harness tables
  (`exploit_runs`, `sessions`, `loot`) and the operator-annotation table
  (`notes`, DDL in
  [`NotesSchema.cs`](../src/Drederick/Reporting/NotesSchema.cs)).
- Convention: all timestamps are **ISO-8601 strings** in UTC.

<a id="tables"></a>
## Tables

### `hosts` {#table-hosts}

One row per in-scope target that produced at least one finding.

| column      | type    | constraints                | notes |
| ----------- | ------- | -------------------------- | ----- |
| `id`        | INTEGER | PRIMARY KEY                |       |
| `address`   | TEXT    | NOT NULL, UNIQUE           | IPv4/IPv6 literal. Datasette label column. |
| `hostname`  | TEXT    |                            | Forward or reverse DNS; may be NULL. |
| `first_seen` | TEXT   | NOT NULL                   | ISO-8601 UTC. |
| `last_seen`  | TEXT   | NOT NULL                   | ISO-8601 UTC; updated on re-run. |

### `services` {#table-services}

TCP/UDP services discovered by `NmapTool`.

| column    | type    | constraints                          | notes |
| --------- | ------- | ------------------------------------ | ----- |
| `id`      | INTEGER | PRIMARY KEY                          |       |
| `host_id` | INTEGER | NOT NULL, FK → `hosts(id)`           |       |
| `port`    | INTEGER | NOT NULL                             |       |
| `proto`   | TEXT    | NOT NULL                             | `tcp` or `udp`. |
| `service` | TEXT    |                                      | nmap-reported label (`http`, `microsoft-ds`, …). |
| `product` | TEXT    |                                      | nmap `-sV` product. |
| `version` | TEXT    |                                      | nmap `-sV` version. |
| —         | —       | `UNIQUE(host_id, port, proto)`       | One row per (host, port, proto). |

### `findings` {#table-findings}

Raw probe payloads. `data_json` shape depends on `kind`.

| column       | type    | constraints                     | notes |
| ------------ | ------- | ------------------------------- | ----- |
| `id`         | INTEGER | PRIMARY KEY                     |       |
| `host_id`    | INTEGER | NOT NULL, FK → `hosts(id)`      |       |
| `service_id` | INTEGER | FK → `services(id)` (nullable)  | NULL for host-level kinds (e.g. `dns`). |
| `kind`       | TEXT    | NOT NULL                        | See [`kind` vocabulary](#kind-vocab). |
| `data_json`  | TEXT    | NOT NULL                        | Typed payload serialised as JSON. |
| `created_at` | TEXT    | NOT NULL                        | ISO-8601 UTC. |
| —            | —       | `UNIQUE INDEX idx_findings_unique(host_id, COALESCE(service_id, 0), kind, data_json)` | Dedup across re-runs. |

<a id="kind-vocab"></a>
#### `kind` vocabulary (controlled)

| `kind` | Emitter | `data_json` shape |
| ------ | ------- | ----------------- |
| `nmap`         | `NmapTool`               | Serialised `NmapPort`. |
| `nmap-script`  | `NmapTool`               | One NSE script result. |
| `http`         | `HttpProbeTool`          | `HttpResult`. |
| `tls`          | `TlsProbeTool`           | `TlsResult`. |
| `dns`          | `DnsProbeTool`           | `DnsResult`. |
| `smb`          | `SmbTool`                | `SmbResult`. |
| `ftp`          | `FtpTool`                | `FtpResult`. |
| `ssh`          | `SshTool`                | `SshResult`. |
| `snmp`         | `SnmpTool`               | SNMP system OID entries. |
| `ldap`         | `LdapTool`               | `LdapResult`. |
| `rpc`          | `RpcTool`                | `RpcResult`. |
| `kerberos`     | `KerberosTool`           | `KerberosResult` (SPN list only). |
| `dns-axfr`     | `DnsZoneTransferTool`    | `DnsZoneTransferResult`. |
| `http-content-discovery` | `HttpContentDiscoveryTool` | `HttpContentDiscoveryResult`. |
| `tls-cipher-enum` | `TlsCipherEnumTool`   | `TlsCipherEnumResult`. |
| `cve`          | `CveAnnotator`           | `{ cve_id, cvss, product, version }`. |

### `cves` {#table-cves}

| column      | type    | constraints          | notes |
| ----------- | ------- | -------------------- | ----- |
| `id`        | INTEGER | PRIMARY KEY          |       |
| `cve_id`    | TEXT    | NOT NULL, UNIQUE     | e.g. `CVE-2024-1234`. Datasette label column. |
| `cvss`      | REAL    |                      | CVSS base, 0.0–10.0; may be NULL. |
| `summary`   | TEXT    |                      | NVD short description. |
| `published` | TEXT    |                      | ISO-8601 UTC. |

### `poc_refs` {#table-poc-refs}

Pointers to public PoC material.

| column         | type    | constraints                              | notes |
| -------------- | ------- | ---------------------------------------- | ----- |
| `id`           | INTEGER | PRIMARY KEY                              |       |
| `cve_id`       | TEXT    | NOT NULL                                 | Logical FK → `cves.cve_id`. |
| `source`       | TEXT    | NOT NULL                                 | `exploit-db` / `github` / `metasploit` / `nuclei`. |
| `url`          | TEXT    |                                          | Upstream URL when known. |
| `external_id`  | TEXT    |                                          | EDB id / GHSA id / module name / template id. |
| `local_path`   | TEXT    |                                          | `out/poc_cache/<source>/<external_id>/…` if cached. |
| `fetched_at`   | TEXT    |                                          | ISO-8601 UTC. |
| —              | —       | `UNIQUE(cve_id, source, external_id)`    | One pointer per upstream. |

### `poc_sources` {#table-poc-sources}

Local cache of fetched PoC artifacts (SHA-256 provenance).

| column        | type    | constraints                        | notes |
| ------------- | ------- | ---------------------------------- | ----- |
| `id`          | INTEGER | PRIMARY KEY                        |       |
| `source`      | TEXT    | NOT NULL                           | Same vocabulary as `poc_refs.source`. |
| `external_id` | TEXT    | NOT NULL                           | Same as `poc_refs.external_id`. |
| `sha256`      | TEXT    | NOT NULL                           | Integrity of cached artifact. |
| `path`        | TEXT    | NOT NULL                           | Absolute path on disk. |
| `fetched_at`  | TEXT    | NOT NULL                           | ISO-8601 UTC. |
| `source_url`  | TEXT    |                                    | Where it was fetched from. |
| —             | —       | `UNIQUE(source, external_id)`      | One cached artifact per upstream id. |

### `tooling` {#table-tooling}

Result of `drederick doctor`.

| column        | type    | constraints          | notes |
| ------------- | ------- | -------------------- | ----- |
| `id`          | INTEGER | PRIMARY KEY          |       |
| `name`        | TEXT    | NOT NULL, UNIQUE     | `nmap` / `searchsploit` / `python3` / …. Datasette label column. |
| `version`     | TEXT    |                      | Detected version string. |
| `source`      | TEXT    |                      | `apt` / `dnf` / `pacman` / `zypper` / `brew` / `pipx` / `uv` / `go` / `gem` / `path`. |
| `path`        | TEXT    |                      | Binary path. |
| `detected_at` | TEXT    | NOT NULL             | ISO-8601 UTC. |

### `exploit_runs` {#table-exploit-runs}

One row per spawned offensive invocation (nuclei, msfconsole PoC,
password spray, cached exploit). Written by `SqliteReport.UpsertExploitRun`
from an `ExploitRunRecord`
([`Exploit/ExploitResult.cs`](../src/Drederick/Exploit/ExploitResult.cs)).

| column            | type    | constraints                | notes |
| ----------------- | ------- | -------------------------- | ----- |
| `id`              | INTEGER | PRIMARY KEY                |       |
| `tool`            | TEXT    | NOT NULL                   | Kebab-case `IExploitTool.Name` (`nuclei-runner`, `msf-rc-runner`, `password-spray`, …). |
| `target`          | TEXT    | NOT NULL                   | Primary scope-validated target (IP / host / URL). |
| `category`        | TEXT    | NOT NULL                   | `ExecPocs` / `CredAttacks` / `Payloads` / `Destructive` / `Dos`. See [`ExploitCategory.cs`](../src/Drederick/Exploit/ExploitCategory.cs). |
| `invocation_id`   | TEXT    | NOT NULL, UNIQUE           | 16-hex-char id minted by `ExploitRunner.NewWorkingDir`; matches the working-dir segment. |
| `artifact`        | TEXT    |                            | Path to cached PoC / module / template that was executed (nullable for ad-hoc). |
| `artifact_sha256` | TEXT    |                            | SHA-256 of `artifact` when present. |
| `argv_digest`     | TEXT    | NOT NULL                   | SHA-256 over `binary + " " + arguments`; stable for identical argv across runs. |
| `exit_code`       | INTEGER |                            | Subprocess exit code; NULL until finish upsert. |
| `started_at`      | TEXT    | NOT NULL                   | ISO-8601 UTC. |
| `finished_at`     | TEXT    |                            | ISO-8601 UTC; NULL while in-flight. |
| `stdout_bytes`    | INTEGER |                            | Full (un-truncated) stdout size. |
| `stdout_sha256`   | TEXT    |                            | SHA-256 of full stdout. |
| `stderr_bytes`    | INTEGER |                            | Full stderr size. |
| `stderr_sha256`   | TEXT    |                            | SHA-256 of full stderr. |
| `work_dir`        | TEXT    |                            | `out/<sanitized-target>/<tool>/<invocation_id>/`. |
| `error`           | TEXT    |                            | Runner-level error (timeout, spawn failure) — not subprocess stderr. |

Indices: `idx_exploit_runs_target(target)`, `idx_exploit_runs_tool(tool)`.
Note: truncated stdout/stderr live **only** in `ExploitRunRecord` JSON
(reports / audit entries), never in SQLite — SHA-256 + byte count is the
contract.

### `sessions` {#table-sessions}

One row per opened interactive session (Meterpreter, SSH, WinRM, …).
Written by `SqliteReport.UpsertSession` from a `SessionRecord`.

| column       | type    | constraints          | notes |
| ------------ | ------- | -------------------- | ----- |
| `id`         | INTEGER | PRIMARY KEY          |       |
| `session_id` | TEXT    | NOT NULL, UNIQUE     | Opaque id assigned by `SessionManager`. |
| `target`     | TEXT    | NOT NULL             | Scope-validated target the session is on. |
| `protocol`   | TEXT    | NOT NULL             | `meterpreter` / `ssh` / `winrm` / …. |
| `via_tool`   | TEXT    | NOT NULL             | `IExploitTool.Name` that opened the session. |
| `opened_at`  | TEXT    | NOT NULL             | ISO-8601 UTC. |
| `closed_at`  | TEXT    |                      | ISO-8601 UTC; NULL while session is live. |

Index: `idx_sessions_target(target)`.

### `loot` {#table-loot}

One row per captured secret (credential, hash, Kerberos ticket, file).
Only the SHA-256 of the secret is stored here; plaintext stays in
`out/<host>/loot/` — see
[`@invariant-id:no-exfiltration`](../docs/SCOPE_AND_LEGAL.md#invariants).

| column         | type    | constraints                          | notes |
| -------------- | ------- | ------------------------------------ | ----- |
| `id`           | INTEGER | PRIMARY KEY                          |       |
| `target`       | TEXT    | NOT NULL                             | Scope-validated target the loot was captured from. |
| `kind`         | TEXT    | NOT NULL                             | `credential` / `nt-hash` / `kerberos-ticket` / `session-key` / `secret-file` / …. |
| `value_sha256` | TEXT    | NOT NULL                             | SHA-256 of the captured secret. Plaintext never appears in this table. |
| `source_tool`  | TEXT    | NOT NULL                             | `IExploitTool.Name` that captured it. |
| `captured_at`  | TEXT    | NOT NULL                             | ISO-8601 UTC. |
| `metadata`     | TEXT    |                                      | Optional JSON (realm, username, filename, …). |
| —              | —       | `UNIQUE(target, kind, value_sha256)` | Dedup across re-runs. |

Index: `idx_loot_target(target)`.

### `notes` {#table-notes}

Operator/CTF annotations (flags, credentials, screenshots, commands).
DDL is owned by
[`NotesSchema.cs`](../src/Drederick/Reporting/NotesSchema.cs) and
appended to the core schema by `SqliteReport.EnsureSchema`. Highlights:
`category` is `CHECK`-constrained to
`('flag','credential','exploit','screenshot','command','note')`;
`source` to `('cli','ui','import')`. `host_id` is TEXT (not a SQL FK)
because notes may attach to a free-form host label; `service_id` is a
nullable `INTEGER`. Full column list and facet configuration are in
[`datasette/metadata.json`](../datasette/metadata.json).

<a id="foreign-keys"></a>
## Foreign keys + cross-table links

| From                         | To                    | Kind | Notes |
| ---------------------------- | --------------------- | ---- | ----- |
| `services.host_id`           | `hosts.id`            | SQL FK | Strict. |
| `findings.host_id`           | `hosts.id`            | SQL FK | Strict. |
| `findings.service_id`        | `services.id`         | SQL FK (nullable) | NULL for host-level kinds. |
| `findings.data_json$.cve_id` | `cves.cve_id`         | **Logical** (JSON) | Use `json_extract(f.data_json, '$.cve_id')`. Not a SQL FK. |
| `poc_refs.cve_id`            | `cves.cve_id`         | Logical | Matched by string equality. |
| `poc_sources.(source, external_id)` | `poc_refs.(source, external_id)` | Logical | Same compound key, no SQL FK. |
| `exploit_runs.artifact` → `poc_sources.path` | | Logical (path match) | When an `ExecPocs` run fires a cached PoC, `artifact` is the `poc_sources.path` value and `artifact_sha256` equals `poc_sources.sha256`. |
| `sessions.via_tool` → `exploit_runs.tool`    | | Logical | Same kebab-case `IExploitTool.Name` vocabulary. |
| `loot.source_tool` → `exploit_runs.tool`     | | Logical | Same kebab-case `IExploitTool.Name` vocabulary. |

<a id="joins"></a>
## Common JOIN patterns

### Host → service → finding

```sql
SELECT h.address, s.port, s.service, f.kind, f.data_json
FROM hosts h
JOIN services s  ON s.host_id = h.id
JOIN findings f  ON f.service_id = s.id
WHERE h.address = :address;
```

### Service → CVE (via JSON bridge)

```sql
SELECT h.address, s.port, s.product, s.version, c.cve_id, c.cvss
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c     ON c.cve_id = json_extract(f.data_json, '$.cve_id');
```

### CVE → PoC (pointer + cached source)

```sql
SELECT c.cve_id, p.source, p.external_id, p.url,
       ps.path, ps.sha256
FROM cves c
JOIN poc_refs p    ON p.cve_id = c.cve_id
LEFT JOIN poc_sources ps
       ON ps.source = p.source
      AND ps.external_id = p.external_id;
```

### Tooling snapshot

```sql
SELECT name, version, source, path, detected_at
FROM tooling
ORDER BY name;
```

<a id="example-queries"></a>
## Example queries

The first five match the Datasette canned queries in
[`datasette/metadata.json`](../datasette/metadata.json); the last three are
lifted from the operator playbook in [`DATASETTE.md`](DATASETTE.md).

### 1. `cves_by_host` — where do I start?

```sql
SELECT h.address, s.port, s.service, s.product, s.version,
       c.cve_id, c.cvss
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c     ON c.cve_id = json_extract(f.data_json, '$.cve_id')
ORDER BY c.cvss DESC NULLS LAST;
```

### 2. `services_with_pocs` — primary PoC-triage query

```sql
SELECT h.address, s.port, s.product, s.version,
       c.cve_id, c.cvss,
       p.source, p.external_id, p.local_path
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c     ON c.cve_id = json_extract(f.data_json, '$.cve_id')
JOIN poc_refs p ON p.cve_id = c.cve_id
ORDER BY c.cvss DESC NULLS LAST;
```

### 3. `pocs_by_source`

```sql
SELECT source, COUNT(*) AS refs
FROM poc_refs
GROUP BY source
ORDER BY refs DESC;
```

### 4. `tooling_detected`

```sql
SELECT name, version, source, path
FROM tooling
ORDER BY name;
```

### 5. `top_cves_by_cvss`

```sql
SELECT cve_id, cvss, published, summary
FROM cves
ORDER BY cvss DESC NULLS LAST, published DESC
LIMIT 50;
```

### 6. Top 10 hosts by CVE count

```sql
SELECT h.address, COUNT(DISTINCT c.id) AS cve_count
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c     ON c.cve_id = json_extract(f.data_json, '$.cve_id')
GROUP BY h.address
ORDER BY cve_count DESC
LIMIT 10;
```

### 7. Critical-CVSS PoCs not yet cached

```sql
SELECT c.cve_id, c.cvss, p.source, p.external_id, p.url
FROM cves c
JOIN poc_refs p ON p.cve_id = c.cve_id
WHERE c.cvss >= 9.0
  AND p.local_path IS NULL
ORDER BY c.cvss DESC;
```

### 8. SMB hosts with signing **not** required

```sql
SELECT h.address, f.data_json
FROM hosts h
JOIN findings f ON f.host_id = h.id
WHERE f.kind = 'smb'
  AND json_extract(f.data_json, '$.signing_required') = 0;
```

<a id="schema-invariants"></a>
## Stable invariants about the schema

Downstream code (queries, exports, dashboards, agent tools) may rely on the
following. Breaking any of these requires a migration + a changelog note.

| id | Invariant |
| -- | --------- |
| `@schema:core-tables-stable` | These tables won't be renamed or dropped: `hosts`, `services`, `findings`, `cves`, `poc_refs`, `poc_sources`, `tooling`, `exploit_runs`, `sessions`, `loot`, `notes`. New tables may be added. |
| `@schema:idempotent-upsert` | Every writer is idempotent — re-running a scan does not duplicate rows. |
| `@schema:findings-dedup-index` | `UNIQUE INDEX idx_findings_unique(host_id, COALESCE(service_id, 0), kind, data_json)` is the dedup contract. |
| `@schema:cve-join-via-json` | `findings ↔ cves` joins go through `json_extract(findings.data_json, '$.cve_id')`. Do not add a SQL FK — the `cves.cve_id` pool is larger than `findings`. |
| `@schema:iso8601-utc` | All timestamp columns are ISO-8601 strings in UTC. |
| `@schema:poc-cache-provenance` | Every row in `poc_sources` carries a non-null `sha256`. Readers may treat mismatch vs on-disk file as a cache-poisoning signal. |
| `@schema:label-columns` | Datasette label columns: `hosts.address`, `cves.cve_id`, `tooling.name`, `notes.title`. These stay stable so facet navigation doesn't break. |
| `@schema:kind-vocab-controlled` | New `findings.kind` values require an entry in [`kind` vocabulary](#kind-vocab). Do not invent ad-hoc kinds. |
| `@schema:loot-digest-only` | `loot.value_sha256` is the **only** representation of a captured secret in SQLite — plaintext never appears in any column of any table. See [`@invariant-id:no-exfiltration`](SCOPE_AND_LEGAL.md#invariants). |
| `@schema:exploit-runs-append-mostly` | `exploit_runs` is upserted by `invocation_id`; `started_at` is immutable after first insert, only `finished_at` / `exit_code` / stdout-stderr digests / `error` change on the finish upsert. |
| `@schema:argv-digest-stable` | `exploit_runs.argv_digest` = `sha256(binary + " " + arguments)`. Stable across runs — safe to use as a correlation key in dashboards and cross-session queries. |
