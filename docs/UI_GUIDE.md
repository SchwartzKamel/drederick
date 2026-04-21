---
title: UI guide
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - DATASETTE.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
---

# UI guide

> **TL;DR.** Current UI = Datasette (`drederick serve`). React dashboard is
> **planned, not implemented**. Use the CLI + Datasette until
> `src/Drederick.Web` lands.

Drederick has two UIs on its roadmap. Datasette is the **usable-today UI**;
the React dashboard is the **planned forward-looking UI**.

## Current UI: Datasette

Every run writes `out/findings.db`. `drederick serve` launches
[Datasette](https://datasette.io/) against it with labelled tables, facets,
and five canned queries tuned for CVE / PoC / tooling triage.

```bash
drederick serve --out out/
# → http://127.0.0.1:8001
```

For the full schema walkthrough, facet navigation, canned-query reference,
custom SQL recipes, and the PoC triage workflow, see
[**`DATASETTE.md`**](./DATASETTE.md) — that is the authoritative doc for
the current UI.

## Planned: React dashboard

> **Status: WIP.** The React + TypeScript point-and-click UI described below
> is not yet implemented. This section captures the intended design so it
> can be picked up in a follow-up PR. Until it lands, use `drederick serve`
> (Datasette) or the CLI directly.

### Goals

- Point-and-click orchestration for lab/CTF operators.
- Localhost-only. No remote mode, no cloud mode, no "share scan" button.
- Surface the scope allow-list prominently: you should always be able to see
  which targets Drederick will and will not touch.
- Stream findings live as scanners emit them (Datasette is post-run only).

### Planned architecture

```text
  Browser (React/TS/Tailwind)
        │  fetch + SignalR
        ▼
  ASP.NET Core host (src/Drederick.Web)
        │
        ▼
  Drederick core (Recon / Scope / Audit / Memory / Enrichment)
```

- **Bind:** `127.0.0.1` only.
- **Auth:** one-time token printed on the CLI by `drederick ui` and also
  written to `~/.drederick/ui.token`. No password, no user accounts.
- **Transport:** REST for configuration + commands; SignalR for the live
  finding/audit stream.

### Planned views

#### 1. Scope editor

- Load/save the YAML scope file.
- Inline validation against the same rules as `ScopeLoader` (wildcard refusal,
  prefix caps, syntax).
- Prominent lab/CTF-only banner.
- `--lab` toggle is explicit; switching to strict mode or enabling
  `--allow-broad` is logged to `audit.jsonl`.

#### 2. Run launcher

- Pick scope + targets (or `--expand`).
- Pick concurrency (`--host-concurrency`, `--service-concurrency`).
- Pick which tiers to enable (top-1000 TCP → full-range TCP → top-100 UDP).
- Toggle `--content-discovery` and `--no-fetch-poc` explicitly.
- Preview of what *will* run (services, expected ports, estimated scanner
  count).
- "Start" button and "Stop all" kill-switch.

#### 3. Live dashboard

- Per-host cards with status pills per service.
- Streaming findings table, SignalR-backed.
- Per-scanner progress bars.
- Kill-switch per job or global.
- Live audit tail (read-only).

#### 4. Report viewer

- Renders the existing `report.md` and `report.json`.
- Diff against the previous run from `memory/findings.json`.
- Export to Markdown / JSON.
- Embedded CVE / PoC triage pane (same data as the Datasette
  `services_with_pocs` canned query, but wired into the React graph).

#### 5. Manual commands

- Renders `out/<host>/manual_commands.txt` with copy buttons.
- Clearly marked *"run at your own discretion, outside Drederick"* — copying a
  command does not make Drederick execute it.

### What the UI will never do

- Send findings to a third party.
- Execute a cached PoC or make the request a PoC would have made.
- Expose an "I'm authorized" toggle that disables the scope check.
- Offer exploit, brute-force, or payload-delivery actions — even behind an
  "advanced" submenu. These are not supported features of Drederick and
  won't be supported through a UI either.

### Until the React UI lands

Use the CLI + Datasette. Every piece of data the React UI will eventually
wrap is already available:

- **Scope editing** — edit `scope.yaml` in your favorite editor;
  `ScopeLoader` validates on run.
- **Run launching** — `drederick --scope … --target … --out …` with
  `--host-concurrency` / `--service-concurrency` / `--content-discovery`
  / `--no-fetch-poc`.
- **Live feed** — `tail -f out/audit.jsonl` during the run.
- **Report viewing** — `out/report.md`, `out/report.json`, and Datasette.
- **CVE / PoC triage** — the `services_with_pocs` canned query in
  [`DATASETTE.md`](./DATASETTE.md).
- **Manual commands** — `out/<host>/manual_commands.txt`.
