# UI guide

> **Status: WIP.** The React + TypeScript point-and-click UI described in the
> plan is not yet implemented. This document captures the intended design so
> it can be picked up in a follow-up PR. The CLI is fully functional today —
> see the top-level [`README.md`](../README.md).

## Goals

- Point-and-click orchestration for lab/CTF operators.
- Localhost-only. No remote mode, no cloud mode, no "share scan" button.
- Surface the scope allow-list prominently: you should always be able to see
  which targets Drederick will and will not touch.
- Stream findings live as scanners emit them.

## Planned architecture

```
  Browser (React/TS/Tailwind)
        │  fetch + SignalR
        ▼
  ASP.NET Core host (src/Drederick.Web)
        │
        ▼
  Drederick core (Recon / Scope / Audit / Memory)
```

- **Bind:** `127.0.0.1` only.
- **Auth:** one-time token printed on the CLI by `drederick ui` and also
  written to `~/.drederick/ui.token`. No password, no user accounts.
- **Transport:** REST for configuration + commands; SignalR for the live
  finding/audit stream.

## Planned views

### 1. Scope editor

- Load/save the YAML scope file.
- Inline validation against the same rules as `ScopeLoader` (wildcard refusal,
  prefix caps, syntax).
- Prominent lab/CTF-only banner.
- `--lab` toggle is explicit; switching to strict mode or enabling
  `--allow-broad` is logged to `audit.jsonl`.

### 2. Run launcher

- Pick scope + targets (or `--expand`).
- Pick concurrency (`--host-concurrency`, `--service-concurrency`).
- Pick which tiers to enable (top-1000 TCP → full-range TCP → top-100 UDP).
- Preview of what *will* run (services, expected ports, estimated scanner
  count).
- "Start" button and "Stop all" kill-switch.

### 3. Live dashboard

- Per-host cards with status pills per service.
- Streaming findings table.
- Per-scanner progress bars.
- Kill-switch per job or global.
- Live audit tail (read-only).

### 4. Report viewer

- Renders the existing `report.md` and `report.json`.
- Diff against the previous run from `memory/findings.json`.
- Export to Markdown / JSON.

### 5. Manual commands

- Renders `out/<host>/manual_commands.txt` with copy buttons.
- Clearly marked *"run at your own discretion, outside Drederick"* — copying a
  command does not make Drederick execute it.

## What the UI will never do

- Send findings to a third party.
- Fetch PoC code from the internet.
- Expose an "I'm authorized" toggle that disables the scope check.
- Offer exploit, brute-force, or payload-delivery actions — even behind an
  "advanced" submenu. These are not supported features of Drederick and won't
  be supported through a UI either.

## Until the UI lands

Use the CLI. Every feature the UI will eventually wrap is already available on
the command line — see [`../README.md`](../README.md).
