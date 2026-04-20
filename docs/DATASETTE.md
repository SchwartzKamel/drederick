# Datasette dashboard

Every `drederick` run writes `out/findings.db` — a small SQLite database
produced by [`SqliteReport`](../src/Drederick/Reporting/SqliteReport.cs).
The bundled [`datasette/metadata.json`](../datasette/metadata.json) adds
human-readable labels, clickable facets, and canned queries so the
database is immediately useful in [Datasette](https://datasette.io/).

## Launching

```bash
# Via the wrapper subcommand (preferred).
drederick serve --out out/

# Customise bind / browser.
drederick serve --out out/ --host 0.0.0.0 --port 8001 --no-open

# Or directly:
datasette serve out/findings.db --metadata datasette/metadata.json
```

If `datasette` isn't on PATH, `drederick serve` exits with a hint to run
`drederick doctor --install` (which picks it up via the detected package
manager).

## Schema

All schema is emitted by `SqliteReport.EnsureSchema` — see that file for
the authoritative DDL.

| Table          | Purpose                                                      | Key columns                                   |
| -------------- | ------------------------------------------------------------ | --------------------------------------------- |
| `hosts`        | One row per in-scope target with at least one finding.       | `address` (unique), `hostname`, `last_seen`   |
| `services`     | TCP/UDP services discovered by the nmap probe.               | `(host_id, port, proto)`, `service`, `product`, `version` |
| `findings`     | Raw probe payloads; `data_json` holds the structured output. | `kind`, `host_id`, `service_id`               |
| `cves`         | CVE records annotated onto services by the enrichment layer. | `cve_id` (unique), `cvss`, `published`        |
| `poc_refs`     | Pointers to public PoC material (ExploitDB, GitHub, MSF, …). | `(cve_id, source, external_id)`               |
| `poc_sources`  | Local cache of fetched PoC artifacts with SHA-256.           | `(source, external_id)`, `sha256`, `path`     |
| `tooling`      | Detected operator-workstation tools (from `drederick doctor`). | `name` (unique), `version`, `source`        |

## Facets

The metadata file declares the following facets (clickable filters in the
Datasette UI):

- **services** — `proto`, `service`, `product`
- **findings** — `kind`, `host_id`
- **cves** — `cvss`, `published` (raw values; use the canned queries for
  bucketed views)
- **poc_refs** — `source`
- **poc_sources** — `source`
- **tooling** — `source`

## Labels

Datasette shows a row's `label_column` wherever the row is referenced
from another table. Labels configured here:

- `hosts.address`
- `cves.cve_id`
- `tooling.name`

## Canned queries

Each of these is available at `/findings/<name>` in the Datasette UI.

| Name                  | What it answers                                         |
| --------------------- | ------------------------------------------------------- |
| `cves_by_host`        | Which CVE lands on which host/service, CVSS-sorted.     |
| `services_with_pocs`  | As above but only where a public PoC exists.            |
| `pocs_by_source`      | How many PoC references we have per upstream source.    |
| `tooling_detected`    | Alphabetical dump of the `tooling` table.               |
| `top_cves_by_cvss`    | Top 50 CVEs by CVSS (NULLs last).                       |

The `cves_by_host` and `services_with_pocs` queries join `findings` to
`cves` via `json_extract(data_json, '$.cve_id')` — the CVE annotator
writes CVE ids into `findings.data_json` under that key.
