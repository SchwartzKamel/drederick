# Architecture

Drederick is a scope-enforced, adaptive reconnaissance harness built on
**.NET 10** and the **Microsoft Agent Framework**. It performs discovery and
fingerprinting only — no exploitation, credential attacks, brute force, or
payload delivery.

This document describes the current architecture. Planned additions (web UI,
bounded worker pool, additional service scanners) are marked **(planned)**.

## Layers

```
                      ┌───────────────────────────┐
                      │   CLI  (Drederick.Cli)    │
                      │   Options, help, flags    │
                      └─────────────┬─────────────┘
                                    ▼
                      ┌───────────────────────────┐
                      │   Scope (default-deny)    │  lab: /8 v4, /32 v6
                      │   ScopeLoader → Scope     │  strict: /16 v4, /48 v6
                      └─────────────┬─────────────┘
                                    ▼
        ┌────────────────── ReconToolbox ─────────────────┐
        │                      │                          │
        │   Audit (JSONL)   Budget (per-tool caps)        │
        │                                                 │
        │   NmapTool    HttpProbeTool    TlsProbeTool     │
        │                    DnsProbeTool                 │
        └─────────────────────┬───────────────────────────┘
                              ▼
           ┌───────────── Runner ──────────────┐
           │                                   │
           │   AdaptiveRunner (deterministic)  │
           │   MicrosoftAgentRunner (LLM)      │
           └──────────────────┬────────────────┘
                              ▼
                ┌──────── Reporting ─────────┐
                │  JsonReport  MarkdownReport│
                │  ManualCommandsCheatsheet  │
                └──────────────┬─────────────┘
                               ▼
                ┌──────── Memory (KB) ────────┐
                │   memory/findings.json      │
                │   Loaded on next run        │
                └─────────────────────────────┘
```

## Components

### `Drederick.Scope`

Default-deny allow-list. A `Scope` is constructed only via `ScopeLoader`, which
enforces:

- No empty scopes.
- No wildcard entries (`0.0.0.0/0`, `::/0`).
- Prefix-length caps:
  - **Lab mode (default):** `/8` (v4), `/32` (v6).
  - **Strict mode (`--no-lab`):** `/16` (v4), `/48` (v6).
- `--allow-broad` overrides the cap but cannot override the wildcard refusal.

Every tool calls `Scope.Require(target)` at its entry point. A target outside
the scope throws `ScopeException`, which is logged and skipped.

### `Drederick.Recon`

Four scanners today: `NmapTool`, `HttpProbeTool`, `TlsProbeTool`,
`DnsProbeTool`. `NmapTool` uses service/version detection plus an
enumeration-only NSE category set:

- **Lab mode:** `safe,default,discovery,version`
- **Strict mode:** `safe,default`

Neither mode enables `exploit`, `intrusive`, `brute`, `vuln`, `dos`, or
`malware` — that is a hard-coded guarantee.

**Planned:** `IReconTool` interface + concrete scanners for SMB, FTP, SSH,
SNMP, LDAP, RPC, Kerberos (SPN listing only), HTTP content-discovery, TLS
cipher enumeration, and DNS AXFR — each re-checking scope inside the tool.

### `Drederick.Reporting`

- `JsonReport` — machine-readable `report.json`.
- `MarkdownReport` — per-host summary `report.md`.
- `ManualCommandsCheatsheet` — AutoRecon-style per-host working directory
  (`out/<host>/{scans,loot,notes.md}`) plus, in lab mode only,
  `out/<host>/manual_commands.txt`: a list of enumeration commands the
  operator *may* choose to run themselves. Drederick never executes these.

### `Drederick.Memory`

`KnowledgeBase` persists findings between runs. The next run starts with the
prior map, so repeated passes converge on deltas.

### `Drederick.Audit`

Append-only JSONL log capturing every tool call, scope decision, and session
event. Used by tests, forensics, and the (planned) live UI stream.

### Orchestration

- `AdaptiveRunner` — deterministic, rule-driven loop. No network egress outside
  the scanners themselves.
- `MicrosoftAgentRunner` — uses the Microsoft Agent Framework to let an LLM
  choose which tool to call next. The tools still enforce scope internally —
  the model cannot escape the allow-list.

## Planned additions

- **Bounded worker pool:** replace the current per-host loop with a
  `Channel<ScanJob>` + configurable `--host-concurrency` / `--service-concurrency`.
- **ASP.NET Core host (`src/Drederick.Web`):** minimal API + SignalR stream for
  the React UI. Binds to `127.0.0.1` only; authenticates with a one-time token
  written to `~/.drederick/ui.token`.
- **React UI (`web/`):** Vite + TypeScript + Tailwind. Five views — scope
  editor, run launcher, live dashboard, report viewer, manual-commands viewer.
  No remote mode, no cloud mode, no "share scan" feature.

See [`COMPARISON.md`](./COMPARISON.md) for how Drederick differs from
AutoRecon, nmapAutomator, and Reconnoitre.
