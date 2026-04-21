---
title: Architecture
audience: [humans, agents]
primary: both
stability: stable
last_audited: 2026-04
related:
  - SCOPE_AND_LEGAL.md
  - MODULES.md
  - DEVELOPING.md
  - DATASETTE.md
  - ../AGENTS.md
---

# Architecture

> **TL;DR.** Seven layers: `CLI → Scope → Doctor → ReconToolbox (14
> `IReconTool`s) → HostWorkerPool → Runner (AdaptiveRunner or
> MicrosoftAgentRunner) → Enrichment (NVD + PoC) → Reporting (JSON /
> Markdown / SqliteReport) → Presentation (Datasette today; React planned) +
> Memory (`memory/findings.json`)`. Scope is enforced *inside every tool*;
> `AuditLog` and `KnowledgeBase` are the only thread-safe shared state. Read
> [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) for hard guarantees before
> editing anything in this doc's blast radius.

<a id="intro"></a>
## Overview

Drederick is a scope-enforced, adaptive reconnaissance harness built on
**.NET 10** and the **Microsoft Agent Framework**. It performs discovery,
fingerprinting, and CVE/PoC *aggregation* only — no exploitation, credential
attacks, brute force, payload delivery, or PoC execution.

This document describes the current architecture. Items marked **(planned)**
are still in the roadmap; everything else is in the tree today.

## Layers {#layers}

```text
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
                      ┌───────────────────────────┐
                      │   Doctor (preflight)      │  optional; `drederick
                      │   detects / installs      │  doctor [--install]`
                      │   operator tooling        │
                      └─────────────┬─────────────┘
                                    ▼
        ┌────────────────── ReconToolbox ─────────────────┐
        │   Audit (JSONL) │ Budget │ IReadOnlyList<IReconTool>
        │                                                 │
        │   NmapTool    HttpProbeTool   TlsProbeTool      │
        │   DnsProbeTool                                  │
        │   SmbTool     FtpTool         SshTool           │
        │   SnmpTool    LdapTool        RpcTool           │
        │   KerberosTool (SPN listing only)               │
        │   DnsZoneTransferTool (AXFR)                    │
        │   HttpContentDiscoveryTool (path-only)          │
        │   TlsCipherEnumTool                             │
        └─────────────────────┬───────────────────────────┘
                              ▼
                   ┌── HostWorkerPool ──┐
                   │ bounded Channel<…> │
                   │ --host-concurrency │
                   │ --service-conc.    │
                   └──────────┬─────────┘
                              ▼
           ┌───────────── Runner ──────────────┐
           │   AdaptiveRunner (deterministic)  │
           │   MicrosoftAgentRunner (LLM)      │
           └──────────────────┬────────────────┘
                              ▼
                ┌──────── Enrichment ──────────┐
                │   CveAnnotator (NVD 2.0)     │
                │   PocAggregator (searchsploit│
                │   / GHSA / MSF / nuclei)     │
                │   — aggregate + present,     │
                │     never execute.           │
                └──────────────┬───────────────┘
                               ▼
                ┌──────── Reporting ──────────┐
                │  JsonReport  MarkdownReport │
                │  ManualCommandsCheatsheet   │
                │  SqliteReport (findings.db) │
                └──────────────┬──────────────┘
                               ▼
           ┌───────── Presentation / Memory ─────────┐
           │  `drederick serve` → Datasette          │
           │  Planned: Drederick.Web + React UI      │
           │  KnowledgeBase (memory/findings.json)   │
           └─────────────────────────────────────────┘
```

## Components {#components}

### `Drederick.Scope` {#layer-scope}

Default-deny allow-list. A `Scope` is constructed only via `ScopeLoader`, which
enforces:

- No empty scopes.
- No wildcard entries (`0.0.0.0/0`, `::/0`) — even with `--allow-broad`.
- Prefix-length caps:
  - **Lab mode (default):** `/8` (v4), `/32` (v6).
  - **Strict mode (`--no-lab`):** `/16` (v4), `/48` (v6).
- `--allow-broad` overrides the cap but cannot override the wildcard refusal.

Every tool calls `Scope.Require(target)` at its entry point. A target outside
the scope throws `ScopeException`, which is logged and skipped. **There is no
flag, env var, or debug build that turns this off.**

### `Drederick.Doctor` {#layer-doctor}

Operator-workstation preflight (`drederick doctor` / `drederick doctor
--install`). Detects: `nmap`, `searchsploit`, `python3`, `python2`, `go`,
`ruby`, `git`, `curl`, `jq`, `datasette`. Picks the first available of
`apt`/`dnf`/`pacman`/`zypper`/`brew` for system installs; falls back to
`pipx`/`uv`/`go install`/`gem install --user-install` when the system
package is stale or missing. Never re-execs as root — prints the exact
`sudo` command and asks `[y/N]`. Records every detection and install to
`audit.jsonl` (`doctor.detect`, `doctor.install`) and to the `tooling`
table in `findings.db`. **Doctor modifies the operator workstation
only. It never scans, modifies, or reaches out to any target.**

### `Drederick.Recon` {#layer-recon}

Fourteen scanners, all implementing `IReconTool` (a metadata-only interface
carrying `Name` and `Description`). Call signatures remain typed per-scanner
because recon surfaces are intentionally heterogeneous — nmap takes a port
spec, http takes port + TLS, DNS-AXFR takes (domain, nameserver), etc. The
toolbox dispatches by concrete type via `OfType<T>()`.

Every scanner:

1. Accepts `Scope.Scope` and `Audit.AuditLog` via the constructor — no
   ambient state.
2. Calls `_scope.Require(target)` as the first statement of its public
   scan method.
3. Brackets work with `audit.Record("<name>.start" / ".finish", …)`.
4. Returns a typed result onto `HostFinding` (never raw stdout except as a
   bounded error field).
5. Validates LLM-chosen subprocess args. See `NmapTool.RejectUnsafePortSpec`
   and `SmbTool.AssertNoForbiddenScripts` for the pattern.

`NmapTool` uses the enumeration-only NSE category set:

- **Lab mode:** `safe,default,discovery,version`
- **Strict mode:** `safe,default`

`exploit`, `intrusive`, `brute`, `vuln`, `dos`, and `malware` are hard-coded
excluded. Per-scanner documentation lives in [`MODULES.md`](./MODULES.md).

### `Drederick.Agent` — orchestration + worker pool {#layer-agent}

- `AdaptiveRunner` — deterministic, rule-driven planner. Runs `dns` + `nmap`
  first; then fans out per-service dispatch actions (`tls`, `http`,
  `tls-cipher-enum`, `smb`, `ftp`, `ssh`, `snmp`, `ldap`, `kerberos`, `rpc`,
  `http-content-discovery` when `--content-discovery` is set).
- `MicrosoftAgentRunner` — LLM-driven. Every `IReconTool` method exposed by
  `ReconToolbox` is registered as an `AIFunction` with its `[Description]`
  attribute. The LLM chooses tool calls; scope is re-checked inside every
  tool, so the model cannot escape the allow-list.
- `HostWorkerPool` — bounded `Channel<ScanJob>` worker pool backing
  `--host-concurrency` (default 4, max 32). Inside each host worker,
  per-service probes fan out in parallel bounded by `--service-concurrency`
  (default 8, max 64).

### `Drederick.Enrichment` {#layer-enrichment}

- `NvdCache` — downloads the NVD 2.0 JSON feed for the last ~5 years plus
  the `modified` feed to `~/.drederick/nvd/` (with an ETag-aware refresh).
  If no cache exists and network is unavailable, enrichment is skipped.
  If a stale cache exists, enrichment proceeds against it.
- `CpeMatcher` — matches a fingerprinted `(product, version)` against the
  loaded NVD entries.
- `CveAnnotator` — for every nmap port with `product/version`, writes CVE
  rows and `kind = "cve"` findings. Idempotent upserts.
- `IPocSource` / `SearchsploitSource` (+ planned GHSA / Metasploit / nuclei
  sources) — resolve PoC references per CVE, cache source under
  `out/poc_cache/<source>/<external-id>/`, SHA-256 provenance recorded in
  `poc_sources`. **Drederick never executes PoCs and never initiates
  outbound requests from fetched PoC code.**

Opt-outs:

- `DREDERICK_SKIP_CVE=1` — skip CVE annotation entirely.
- `--no-fetch-poc` — skip PoC fetching (pointers may still be recorded from
  offline sources like `searchsploit`'s local archive).

### `Drederick.Reporting` {#layer-reporting}

- `JsonReport` — machine-readable `out/report.json`.
- `MarkdownReport` — per-host summary `out/report.md`.
- `ManualCommandsCheatsheet` — AutoRecon-style per-host working directory
  (`out/<host>/{scans,loot,notes.md}`) plus, in lab mode only,
  `out/<host>/manual_commands.txt`: enumeration commands the operator
  *may* run themselves. Drederick never executes these, and deliberately
  omits exploit, brute-force, password-spray, and payload-delivery commands.
- `SqliteReport` — `out/findings.db` with seven tables: `hosts`, `services`,
  `findings`, `cves`, `poc_refs`, `poc_sources`, `tooling`. Authoritative
  DDL lives in `SqliteReport.EnsureSchema`; doc mirror in
  [`DB_SCHEMA.md`](./DB_SCHEMA.md). Idempotent upserts. Browsed via
  [Datasette](./DATASETTE.md).

### `Drederick.Memory` — cross-run knowledge base {#layer-memory}

`KnowledgeBase` persists findings between runs (`memory/findings.json`). The
next run starts with the prior map and writes back merged state, so repeat
passes converge on deltas rather than re-discovering the whole surface.

### `Drederick.Audit` {#layer-audit}

Append-only JSONL log (`out/audit.jsonl`) capturing every tool call, scope
decision, doctor detection/install, and session event. Used by tests,
forensics, and the planned live UI stream.

## Thread-safety {#thread-safety}

`HostWorkerPool` runs scanners concurrently, so any state shared across hosts
must be thread-safe:

- **`AuditLog`** — writes are serialized behind an internal lock; safe to
  `Record` from any thread.
- **`KnowledgeBase`** — in-memory mutations are guarded; the on-disk
  `memory/findings.json` is written once at run-end from a single thread.
- **`ReconToolbox`** — per-host `HostFinding` objects live in a
  `ConcurrentDictionary<string, HostFinding>` keyed by target; `Charge()`
  uses atomic `AddOrUpdate` + `Interlocked.Increment` for per-tool and
  global call budgets.
- **Individual scanners** — stateless after construction; safe to invoke
  concurrently across targets.

New scanners inherit this contract: **no shared mutable state outside
`KnowledgeBase` and `AuditLog`, both of which must stay thread-safe**. If you
need per-run state, keep it inside `HostFinding` (one per target).

## Presentation layer {#layer-presentation}

### Current: Datasette {#layer-presentation-datasette}

`drederick serve` shells to `datasette serve out/findings.db --metadata
datasette/metadata.json --host 127.0.0.1 --port 8001 --open`. Bound to
localhost by default. See [`DATASETTE.md`](./DATASETTE.md) for the full
schema walkthrough, facet guide, and PoC triage workflow.

### Planned: React dashboard {#layer-presentation-react}

- `src/Drederick.Web` — ASP.NET Core host, minimal API + SignalR stream.
  Binds `127.0.0.1` only; one-time token written to `~/.drederick/ui.token`.
- `web/` — Vite + TypeScript + Tailwind. Five views: scope editor, run
  launcher, live dashboard, report viewer, manual-commands viewer.
  No remote mode, no cloud mode, no "share scan" feature.

See [`UI_GUIDE.md`](./UI_GUIDE.md).

## See also

- [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) — the hard guarantees; changes
  that weaken any of them need discussion first.
- [`MODULES.md`](./MODULES.md) — scanner-by-scanner contracts.
- [`COMPARISON.md`](./COMPARISON.md) — Drederick vs AutoRecon / nmapAutomator
  / Reconnoitre.
