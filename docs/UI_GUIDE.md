---
title: UI guide
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-05
related:
  - UI.md
  - DATASETTE.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
---

# UI guide

> **Consolidation note.** This file used to describe a planned React
> dashboard that was never built. The Avalonia operator console landed
> instead (see [`UI.md`](./UI.md)). Most of this file is now a thin
> pointer into the two canonical UI docs; it is flagged for
> consolidation — the main agent can decide whether to fold it into
> UI.md or keep it as a landing page.

Drederick ships two operator-facing UIs:

| Surface | Purpose | Authoritative doc |
| ------- | ------- | ----------------- |
| **Avalonia operator console** (`Drederick.UI`) | Live launcher: compose scope, pick targets, launch recon, watch progress, triage findings, author notes, detect operator tooling. | [`UI.md`](./UI.md) |
| **Datasette** (`drederick serve`) | Post-run SQL triage over `out/findings.db` with canned queries for CVE/PoC workflows. | [`DATASETTE.md`](./DATASETTE.md) |

## Quickstart

```bash
# Live operator console (Avalonia, net10):
dotnet run --project src/Drederick.UI

# Post-run SQL triage (Datasette):
drederick serve --out out/
# → http://127.0.0.1:8001
```

Both surfaces are localhost-only and both rely on the same
scope-enforced engine. Targets entered in the Avalonia console are
re-validated by `_scope.Require(target)` *inside each tool*, not at the
UI boundary — the UI cannot escape the allow-list. The UI loads scope
via the same `ScopeLoader` as the CLI (default-deny, wildcard refusal,
prefix caps) and never writes back to the scope file the operator
loaded (the `scope-file-read-only` invariant).

## What lives where

- **Scope composition / run launching / progress stream / notes /
  findings browser / binary analysis / first-run init / operator
  tooling doctor** — Avalonia console ([`UI.md`](./UI.md)).
- **Ad-hoc SQL over `findings.db` (hosts, services, findings, cves,
  poc_refs, poc_sources, exploit_runs, sessions, loot, tooling)** —
  Datasette ([`DATASETTE.md`](./DATASETTE.md)). The Avalonia console's
  **Findings → Open in Datasette** button launches `drederick serve`
  against the currently selected output directory.

## What's still CLI-only

The offensive engine (`ExploitRunner`, `MsfDriver`, `CredRunner`,
`PayloadStager`, session tracking) and the Jeopardy CTF subsystem ship
today as CLI features. Run them with the per-category opt-in flags
(`--allow-exec-pocs`, `--allow-cred-attacks`, `--allow-payloads`,
`--allow-destructive`, `--allow-dos`, `--acknowledge-lockout-risk`).
Surfacing them in the Avalonia console is tracked in [`UI.md`
§Deferred](./UI.md#first-iteration-scope).

## Until consolidation

- **Scope editing** — Avalonia's Scope tab (inline CIDR editor or
  file browse) or edit `scope.yaml` by hand; `ScopeLoader` validates
  either path.
- **Run launching** — Avalonia's Run tab, or
  `drederick --scope … --target … --out …`.
- **Live feed** — Avalonia's Progress tab (bound to `ScanEvent`), or
  `tail -f out/audit.jsonl` during the run.
- **Report viewing** — `out/report.md`, `out/report.json`,
  Avalonia's Findings tab, or Datasette.
- **CVE / PoC triage** — Datasette canned queries
  (see [`DATASETTE.md`](./DATASETTE.md)).
- **Notes** — Avalonia's Notes tab (CRUD over `findings.db` notes
  table).
- **Manual cheatsheet** — `out/<host>/manual_commands.txt`.

