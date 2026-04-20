# Datasette dashboard

`drederick serve` launches [Datasette](https://datasette.io/) against
`out/findings.db` — the SQLite database written by
[`SqliteReport`](../src/Drederick/Reporting/SqliteReport.cs) at the end of
every run. The bundled [`datasette/metadata.json`](../datasette/metadata.json)
adds human-readable labels, clickable facets, and canned queries so the
database is immediately useful.

**This is the current web UI.** The planned React dashboard
([`UI_GUIDE.md`](./UI_GUIDE.md)) is still roadmap; Datasette is what you
use today.

## Launching

```bash
DRED=./src/Drederick/bin/Debug/net10.0/drederick

# Default: 127.0.0.1:8001, opens your browser.
$DRED serve --out out/

# LAN-bind (e.g. VPN-connected team lab). Use carefully — no auth yet.
$DRED serve --out out/ --host 0.0.0.0 --port 8001

# Don't open the browser (useful when SSH-tunneling).
$DRED serve --out out/ --no-open
```

Flags (apply only to `serve`):

| Flag            | Default         | Effect                                                   |
| --------------- | --------------- | -------------------------------------------------------- |
| `--host <ip>`   | `127.0.0.1`     | Bind address for the Datasette HTTP server.              |
| `--port <n>`    | `8001`          | TCP port (1–65535).                                      |
| `--no-open`     | open browser    | Skip the `--open` flag passed to Datasette.              |
| `-o, --out`     | `out`           | Output directory — the `findings.db` to serve.           |
| `--datasette-path <p>` | _(auto)_ | Use an explicit datasette binary; skip discovery + bootstrap. |
| `--no-auto-install` | install on    | Fail (exit 127) instead of installing datasette if missing. |
| `-y, --yes`     | prompt in TTY   | Auto-approve the install consent prompt.                 |

### Auto-bootstrap

`drederick serve` discovers `datasette` in this order, and auto-installs it
the first time if none of the earlier steps succeed:

1. `--datasette-path <path>` if supplied.
2. `datasette` on `PATH`.
3. Previously managed install under
   `~/.drederick/venv/datasette/bin/datasette`, or a pointer recorded at
   `~/.drederick/bin/datasette.path` from an earlier bootstrap.
4. Install via, in preference order: `uv tool install datasette` →
   `pipx install datasette` → `python3 -m venv ~/.drederick/venv/datasette
    && <venv>/bin/pip install --upgrade pip datasette`. Requires
   `python3 >= 3.9`. The resolved binary path is cached under
   `~/.drederick/bin/datasette.path` so subsequent runs skip re-discovery.

The consent prompt is auto-approved when `-y / --yes` is passed or when
stdin isn't a TTY (headless / CI). Pass `--no-auto-install` to refuse
auto-install and surface a clear error instead — useful on locked-down
workstations or when you want `drederick doctor --install` to own the
install step (it primes the same cache).

If `datasette` still isn't on `PATH`, `drederick serve` will call
`drederick doctor --install` for you if you'd rather install via your
system package manager (`pipx`/`uv tool install`/`brew`/`apt`/etc.).

Equivalent one-liner without the wrapper:

```bash
datasette serve out/findings.db --metadata datasette/metadata.json \
    --host 127.0.0.1 --port 8001 --open
```

## First 30 seconds

1. **Home page** (`/`) — lists the databases. You'll see one: `findings`.
2. **Database page** (`/findings`) — lists all seven tables with row counts
   and the five canned queries.
3. **Table page** (`/findings/<table>`) — rows with clickable facets in the
   sidebar. `?service=http` or `?proto=tcp` filters in place.
4. **Row page** (`/findings/<table>/<id>`) — single-row view with foreign-key
   labels resolved (e.g. `host_id` shown as the host's address).
5. **Canned query** (`/findings/<query>`) — prewritten SQL; add `?name=...`
   for bound parameters where the query has them.
6. **Custom SQL** (`/findings?sql=...`) — paste anything. Read-only by
   default; Datasette parameterises and safeguards queries.

## Schema walkthrough

Seven tables, all emitted by `SqliteReport.EnsureSchema`. One row per real
thing; idempotent upserts across runs.

### `hosts`

One row per in-scope target that produced at least one finding.

| Column | Meaning |
| ------ | ------- |
| `id`        | Primary key. |
| `address`   | IPv4/IPv6 literal. **Label column** — shown anywhere another table references `hosts.id`. |
| `hostname`  | Forward or reverse DNS, when known. |
| `first_seen` / `last_seen` | ISO-8601 timestamps. |

### `services`

TCP/UDP services discovered by the nmap probe. Unique on
`(host_id, port, proto)`.

| Column | Meaning |
| ------ | ------- |
| `host_id`  | FK → `hosts.id`. |
| `port`     | TCP/UDP port number. |
| `proto`    | `tcp` or `udp`. |
| `service`  | nmap-reported service label (`http`, `microsoft-ds`, …). |
| `product`  | nmap `-sV` product (e.g. `Apache httpd`). |
| `version`  | nmap `-sV` version (e.g. `2.4.54`). |

### `findings`

Raw probe payloads. `data_json` is the structured output — the shape depends
on `kind`.

| `kind`         | Emitted by         | `data_json` holds                         |
| -------------- | ------------------ | ------------------------------------------ |
| `nmap`         | NmapTool           | Serialized `NmapPort`.                     |
| `nmap-script`  | NmapTool           | One NSE script result.                     |
| `http`         | HttpProbeTool      | `HttpResult` (status, title, server, …).   |
| `tls`          | TlsProbeTool       | `TlsResult` (cert subject/SAN/issuer).     |
| `dns`          | DnsProbeTool       | `DnsResult` (forward + reverse).           |
| `smb` / `ftp` / `ssh` / `snmp` / `ldap` / `rpc` / `kerberos` / `dns-axfr` / `http-content-discovery` / `tls-cipher-enum` | the matching scanner | the scanner's typed result. |
| `cve`          | CveAnnotator       | `{ cve_id, cvss, product, version }`.      |

Unique index: `(host_id, COALESCE(service_id, 0), kind, data_json)` — re-runs
don't duplicate rows.

### `cves`

CVE records annotated onto services. Unique on `cve_id`.

| Column | Meaning |
| ------ | ------- |
| `cve_id`    | e.g. `CVE-2024-1234`. **Label column.** |
| `cvss`      | CVSS base score (`0.0`–`10.0`). |
| `summary`   | NVD description (short). |
| `published` | ISO-8601 timestamp. |

### `poc_refs`

Pointers to public PoC material. Unique on
`(cve_id, source, external_id)`.

| Column | Meaning |
| ------ | ------- |
| `cve_id`      | FK-ish → `cves.cve_id`. |
| `source`      | `exploit-db`, `github`, `metasploit`, `nuclei`. |
| `url`         | Upstream URL when available. |
| `external_id` | Source-specific identifier (EDB id, GHSA id, module name, template id). |
| `local_path`  | Path under `out/poc_cache/<source>/<external_id>/` if cached. |
| `fetched_at`  | ISO-8601. |

### `poc_sources`

Local cache of fetched PoC artifacts. Unique on `(source, external_id)`.

| Column | Meaning |
| ------ | ------- |
| `source` / `external_id` | Same as in `poc_refs`. |
| `sha256`     | SHA-256 of the cached artifact — provenance integrity. |
| `path`       | Absolute path to the cached file on disk. |
| `source_url` | Where it was fetched from. |
| `fetched_at` | ISO-8601. |

### `tooling`

Result of `drederick doctor`. Unique on `name`.

| Column | Meaning |
| ------ | ------- |
| `name`    | `nmap`, `searchsploit`, `python3`, … **Label column.** |
| `version` | Detected version string. |
| `source`  | `apt` / `dnf` / `pacman` / `zypper` / `brew` / `pipx` / `uv` / `go` / `gem` / `path`. |
| `path`    | Binary path on `PATH`. |

### How the tables join

```
hosts 1─┬─< services 1─< findings >─1 cves 1─< poc_refs >─1 poc_sources
        │                              (via json_extract(data_json,'$.cve_id'))
        └─< findings (host-level kinds like 'dns')
```

The `findings ↔ cves` join is not a SQL foreign key — `findings.data_json`
carries the `cve_id` under the JSON key `$.cve_id`, and every canned query
uses `json_extract(f.data_json, '$.cve_id')` to cross the bridge.

## Facet navigation walkthrough

1. Open `/findings/services`.
2. Click the `service` facet in the sidebar; pick `http`.
3. URL becomes `/findings/services?service=http` — all rows narrow to HTTP
   services.
4. Click a row; the service page shows the referencing `findings` rows
   (nmap output, HTTP probe, content discovery).
5. From a finding of `kind=cve`, click into the linked `cve_id` → `cves`
   row → `poc_refs` sub-table → click `local_path` to open the cached
   PoC source in your editor.

## Canned queries

All live at `/findings/<name>`.

| Name                  | What it answers                                         |
| --------------------- | ------------------------------------------------------- |
| `cves_by_host`        | Every (host, service) with a CVE finding, CVSS-sorted. Useful as the "where do I start?" landing query. |
| `services_with_pocs`  | Subset of the above where a public PoC exists. Primary PoC-triage query. |
| `pocs_by_source`      | Count of PoC references per upstream source (`exploit-db`, `github`, …). |
| `tooling_detected`    | Alphabetical dump of the `tooling` table. Run after `drederick doctor`. |
| `top_cves_by_cvss`    | Top 50 CVEs by CVSS (NULLs last). Broad severity skim. |

## Custom SQL recipes

Paste into `/findings?sql=<...>`.

### Top 10 hosts by CVE count

```sql
SELECT h.address, COUNT(DISTINCT c.id) AS cve_count
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id')
GROUP BY h.address
ORDER BY cve_count DESC
LIMIT 10;
```

### Critical-CVSS PoCs I haven't cached yet

```sql
SELECT c.cve_id, c.cvss, p.source, p.external_id, p.url
FROM cves c
JOIN poc_refs p ON p.cve_id = c.cve_id
WHERE c.cvss >= 9.0
  AND p.local_path IS NULL
ORDER BY c.cvss DESC;
```

### Services whose cached PoC source is present

```sql
SELECT h.address, s.port, s.product, s.version, c.cve_id, c.cvss,
       ps.source, ps.path, ps.sha256
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN findings f ON f.service_id = s.id AND f.kind = 'cve'
JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id')
JOIN poc_sources ps ON ps.external_id IN (
    SELECT external_id FROM poc_refs WHERE cve_id = c.cve_id
)
ORDER BY c.cvss DESC;
```

### All SMB hosts with signing **not** required

```sql
SELECT h.address, f.data_json
FROM hosts h
JOIN findings f ON f.host_id = h.id
WHERE f.kind = 'smb'
  AND json_extract(f.data_json, '$.signing_required') = 0;
```

### Diff between two scan runs (services seen today vs. the cross-run KB)

Datasette shows the **current** `findings.db`; for cross-run deltas the
authoritative source is `memory/findings.json`. Attach it ad-hoc:

```sql
-- Services present in findings.db but not yet merged into memory/
-- (run via: datasette out/findings.db memory/findings.db --metadata ...)
SELECT h.address, s.port, s.service
FROM findings.hosts h
JOIN findings.services s ON s.host_id = h.id
WHERE NOT EXISTS (
    SELECT 1 FROM memory.services ms
    WHERE ms.host_id = h.id AND ms.port = s.port AND ms.proto = s.proto
);
```

## PoC triage workflow

The intended path from "scan finished" to "I know what to manually try":

1. **Start at `services_with_pocs`.** This query returns every service with
   at least one public PoC, sorted by CVSS. If it's empty, there's nothing
   to triage on this run.
2. **Filter by CVSS.** Append `&c.cvss=9.8` or use the `cvss` facet on
   `/findings/cves`. Decide your severity floor.
3. **Click through to `poc_refs`.** From a row, click the `cve_id` → `cves`
   row → "rows from poc_refs" panel. You see every public pointer across
   all sources.
4. **Open `local_path`.** For `exploit-db` and similar, Drederick caches
   the PoC source under `out/poc_cache/<source>/<external_id>/`. Open it
   in your editor. Read it. This is where your brain earns its keep.
5. **Cross-check with `poc_sources`.** Confirm the `sha256` matches what's
   on disk — guard against stale cache or tampering.
6. **Decide**. If you choose to run the PoC, do it **outside Drederick**,
   from a host you control, against a target you are authorized to
   compromise. Drederick will not invoke the PoC for you, and that is not
   a feature gap — see [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md).

## Security notes

- **Binds to `127.0.0.1` by default.** `--host 0.0.0.0` is available but
  there is **no authentication yet** — exposing Datasette on a LAN means
  anyone on that LAN can read your recon output, including cached PoC
  source paths. A one-time token model is planned (same pattern as the
  future `src/Drederick.Web` host) but not yet implemented.
- **Read-only by default.** Datasette doesn't expose `INSERT`/`UPDATE`
  unless you configure write plugins. Don't configure them.
- **No public exposure.** `out/findings.db` contains CVE mappings, cached
  PoC paths, and discovered services. Treat it like any other recon
  output — same handling as your `notes.md`.
- **Enrichment outbound is metadata-only.** The `poc_sources` rows may
  include URLs to public archives (`exploit-db.com`, `github.com`, …).
  These were visited by Drederick's enrichment layer — **not** by the
  Datasette view.
