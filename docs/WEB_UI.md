---
title: Web UI — browser-based operator pane
audience: [humans, operators]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - ARCHITECTURE.md
  - UI.md
  - DATASETTE.md
  - SCOPE_AND_LEGAL.md
  - LLM_SETUP.md
  - JEOPARDY.md
  - POST_EXPLOITATION.md
---

# Web UI — browser-based operator pane

<a id="tatum-intro"></a>
## The fight starts in the browser

> **Tatum:** *"A fair fight is one you didn't prepare well enough for."*

The Web UI is the new primary operator pane for Drederick. It's a
single-page React app served by an embedded ASP.NET Core host that
drives the same scope-enforced tools the CLI drives. Start a run,
watch the live `ScanEvent` stream, stage a cached PoC, tail
`audit.jsonl`, and run a Jeopardy swarm across every challenge — all
from one tab.

The Avalonia desktop console ([`UI.md`](UI.md)) stays where it is —
local, offline, zero-daemon. Datasette ([`DATASETTE.md`](DATASETTE.md))
stays where it is — the power tool for ad-hoc SQL across
`findings.db`. The Web UI is where *new* capability surfaces land
first: live orchestration, the Jeopardy live dashboard, the audit
tail, the scope viewer, and the offensive control panel that drives
`ExploitRunner` / `CredRunner` / `PayloadStager`.

None of that weakens the posture. The UI is a thin control surface
over `DrederickHost`; every endpoint that touches the network resolves
targets through the same `_scope.Require` path the CLI uses. No
bypass, no kill switch — see [Invariants](#invariants).

<a id="architecture"></a>
## Architecture

```
Browser (React SPA)
   │ REST /api/*           ┐
   │ SignalR /hubs/events  │  same-origin, loopback default
   ↓                       ┘
Drederick.Web (ASP.NET Core minimal API)
   │ Bearer-token middleware (non-loopback binds)
   ↓
DrederickHost façade  ──→ same scope-enforced tools the CLI uses
   │
   ↓
Scope / AuditLog / SqliteReport / Jeopardy.CtfCoordinator
```

Key points:

- The SPA is served from `wwwroot/` inside the web host. A single
  `dotnet publish` (or `make publish`) embeds the built assets — one
  binary, one port, nothing extra to run.
- **Dev mode.** Vite serves the SPA on `:5173` and proxies `/api/*`
  and `/hubs/*` to the backend on `:7070`. Hot-reload on the SPA,
  `dotnet watch` on the host.
- **Production.** One binary, one port (default `127.0.0.1:7070`).
  No reverse proxy required for local use; put one with TLS in front
  for any non-loopback bind.
- **No direct tool access from the browser.** The SPA calls REST /
  SignalR only; the host calls `DrederickHost`, which is the same
  façade [`src/Drederick.UI/`](UI.md) uses. Scope lives inside the
  tools, not in the web layer.

<a id="launch"></a>
## Launch

```bash
# Default: loopback only, no auth. Single-operator workstation.
drederick web

# Different port, still loopback.
drederick web --web-port 8080

# Remote access: bind beyond loopback; bearer token required.
drederick web --web-bind 0.0.0.0 --web-token <token>
```

If `--web-bind` resolves to anything other than `127.0.0.1` / `::1`
and `--web-token` is not provided, Drederick auto-generates a 32-byte
URL-safe token, writes it to `out/web-token.txt` (mode `0600`), and
prints it to stdout once. Use it on every request:

```http
GET /api/findings HTTP/1.1
Authorization: Bearer <token>
```

The SPA picks up the token from `localStorage` after the first
interactive prompt; REST and SignalR share the same header.

<a id="threat-model"></a>
## Threat model

Honest version. The Web UI is operator tooling, not a hardened
service. Read this before you expose it.

- **Default bind is loopback, no auth.** Any local user on the host
  can poke the UI. That's fine for a single-operator workstation; not
  fine for a shared jump box. If other users live on the machine,
  either keep it off or use the remote-bind + token path and protect
  `out/web-token.txt`.
- **Non-loopback binds require a bearer token**, but the transport is
  still cleartext HTTP. For anything beyond a lab, put a reverse
  proxy with TLS (and ideally mTLS) in front. Don't expose this to
  the internet.
- **No CSRF protection.** The API is bearer-token auth; SPA and API
  share origin; every state-changing endpoint requires the
  `Authorization` header. That's the whole story — no cookie-auth
  flow, no double-submit tokens.
- **No rate limiting yet.** The design assumes a trusted local
  caller.
- **Scope still gates everything.** The UI cannot escape the scope
  file. No endpoint writes to the scope file; every tool invocation
  re-checks the scope allow-list via `_scope.Require` before exec,
  same as the CLI path. See
  [`SCOPE_AND_LEGAL.md#invariants`](SCOPE_AND_LEGAL.md#invariants).
- **Every web request is audited.** The host emits `web.request`
  audit events with method, path, remote endpoint, and auth status.
  Every tool invocation the UI kicks off emits the same `*.start` /
  `*.finish` audit events a CLI-driven invocation would — target,
  argv digest (SHA-256), timestamp.
- **No loot rendering.** Credentials, flags, captured tickets,
  captured secrets: all SHA-256 digests, never plaintext. The SPA
  renders them through a `<RedactedDigest />` component that refuses
  to display anything longer than a hex digest. The backend never
  sends the plaintext.
- **No outbound telemetry.** The SPA fetches only same-origin
  endpoints. Third-party CDN, analytics, and error reporters are not
  used.

<a id="surfaces"></a>
## Surfaces

Per-page sketch. Phase-by-phase delivery is tracked in
[Roadmap](#roadmap); assume Phase 2+ items are upcoming unless this
doc says otherwise.

| Page         | Purpose |
| ------------ | ------- |
| **Runs**     | Start/stop recon passes against a target set; watch the live `ScanEvent` stream over SignalR; cancel in flight. |
| **Findings** | Hosts, services, CVEs, PoC refs, exploit runs, sessions, loot. Digest-only for anything sensitive. Schema matches [`DB_SCHEMA.md`](DB_SCHEMA.md). |
| **Jeopardy** | Live swarm dashboard — per-challenge, which models are racing, the current turn, token/time budget, and a hint-injection form that mirrors `drederick ctf-msg`. The session-start form carries an `llm_provider` selector (`copilot` / `azure` / `llamacpp`) — the same three backends `--llm-provider` picks on the CLI ([details](LLM_SETUP.md#web-ui-provider)). See [`JEOPARDY.md`](JEOPARDY.md). |
| **Offensive**| `ExploitRunner` / `CredRunner` / `PayloadStager` invocations, gated by the same per-run opt-ins as the CLI (`--allow-exec-pocs`, `--allow-cred-attacks`, `--allow-payloads`, `--allow-destructive`, `--allow-dos`). Post-exploitation hand-offs link to [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md). |
| **Audit**    | Tail of `audit.jsonl` with filtering by tool / target / event type. Append-only at the sink; the UI is read-only. |
| **Scope**    | Read-only viewer of the currently loaded scope file + a validator that previews which hosts an entry would resolve to. No edit path. |
| **Doctor**   | Workstation preflight status — which tools are present, which are missing, which have an update available. Mirrors `drederick doctor`. |
| **Notes**    | Operator's free-form notepad, backed by the `notes` table in `findings.db`. Survives reloads and restarts. |

<a id="invariants"></a>
## Invariants

Web-specific restatement of the guarantees in
[`../AGENTS.md#invariants`](../AGENTS.md#invariants) and
[`SCOPE_AND_LEGAL.md#invariants`](SCOPE_AND_LEGAL.md#invariants).

- **Default bind is `127.0.0.1`.** Any non-loopback bind requires a
  bearer token; one is auto-generated if the operator doesn't supply
  one.
- **Scope file is read-only from code.** The UI is no exception. No
  endpoint writes to the scope file.
- **No plaintext credentials, flags, or captured secrets are rendered.**
  SHA-256 digests only; the `<RedactedDigest />` component enforces
  the client-side half and the backend never serializes plaintext.
- **`audit.jsonl` is append-only.** The UI never rewrites, redacts,
  or deletes entries — it only tails.
- **Every tool-invoking endpoint** goes through the same
  scope-enforced path as the CLI (`DrederickHost` →
  `_scope.Require`). No bypass.
- **No outbound telemetry.** The SPA fetches same-origin only.
- **Destructive / high-blast-radius operations are opt-in per run**
  (`--allow-exec-pocs`, `--allow-cred-attacks`, `--allow-payloads`,
  `--allow-destructive`, `--allow-dos`,
  `--acknowledge-lockout-risk`). The UI shows these as toggles on
  the Runs page; they cannot be flipped after a run has started.

<a id="development"></a>
## Development

Two shells.

```bash
# Shell 1 — SPA dev server (Vite on 5173, HMR).
cd web/
pnpm install
pnpm dev
```

```bash
# Shell 2 — ASP.NET Core host (proxied to by Vite).
dotnet run --project src/Drederick.Web -- --web-port 7070
```

Other useful scripts:

```bash
pnpm generate:api    # regenerate the typed API client from the live OpenAPI spec
pnpm build           # production SPA → src/Drederick.Web/wwwroot/
pnpm test            # SPA unit + component tests
```

Shipping build — a single `dotnet publish` (or `make publish`)
produces the `drederick` binary with the built SPA embedded under
`wwwroot/`. No separate Node runtime on the operator's host.

<a id="comparison"></a>
## Comparison to existing surfaces

| Surface                                 | Stays? | Best at                                                                          |
| --------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| **Avalonia** ([`UI.md`](UI.md))         | yes    | Local desktop use, scope viewer, notes, findings browse — no web host required.  |
| **Datasette** ([`DATASETTE.md`](DATASETTE.md)) | yes | Deep ad-hoc SQL across `findings.db`. Analyst / triage workflow.                 |
| **Web UI** (this doc)                   | new    | Live orchestration: runs, Jeopardy swarm, offensive control, audit tail. Primary pane for a new engagement; first stop for a new run. |

Datasette remains the power tool for ad-hoc SQL. The Web UI replaces
it as the *first stop* for starting and watching a run — you'll still
drop into Datasette when you need a join the canned views don't
cover.

<a id="roadmap"></a>
## Roadmap

**Phases 1–4 have shipped in v0.3.0** — the scaffold, REST + SignalR
endpoints, all 8 operator pages, and the Playwright E2E suite are in
tree. Remaining follow-ups:

- **Accessibility + keyboard shortcuts** pass across all 8 pages.
- **Dark mode** refinement.
- **Rate limiting** on the API for non-loopback binds.
- **TLS termination** guidance (reference reverse-proxy config) for
  anything beyond a lab jump box.

Historical phase breakdown (shipped):

- **Phase 1 — scaffold.** `src/Drederick.Web/` host, `web/` Vite +
  React + TypeScript project, `drederick web` subcommand,
  bearer-token middleware, `wwwroot/` embed path.
- **Phase 2 — endpoints + SignalR hub.** `/api/scope`, `/api/runs`,
  `/api/findings`, `/api/audit`, `/api/jeopardy`, `/api/offensive`,
  `/api/doctor`, `/api/notes`. Live `ScanEvent` / audit / Jeopardy
  turn feed over SignalR.
- **Phase 3 — views.** All pages in [Surfaces](#surfaces) wired to
  real data. Opt-in toggles on Runs. `<RedactedValue />` + Tatum
  microcopy library landed.
- **Phase 4 — E2E.** Playwright smoke suite (`web/e2e/`) with 23
  passing invariants — scope-file mtime stability, loot-never-plaintext,
  wildcard refusal, 8-route smoke, exploit-run redaction, no-database
  shape.

<a id="see-also"></a>
## See also

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — layers, threading, where
  `DrederickHost` sits.
- [`UI.md`](UI.md) — the Avalonia desktop console this UI sits
  alongside.
- [`DATASETTE.md`](DATASETTE.md) — the SQL power tool that stays.
- [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) — the guarantees the UI
  must not weaken.
- [`JEOPARDY.md`](JEOPARDY.md) — what the Jeopardy page drives.
- [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) — what the
  Offensive page hands off to.
- [`LLM_SETUP.md`](LLM_SETUP.md) — wiring the models the Runs /
  Jeopardy pages orchestrate.

<a id="running-e2e"></a>
## Running E2E

End-to-end tests live in `web/e2e/` and drive the real backend — the
`drederick-web` ASP.NET process serving the built SPA from `wwwroot/`.
Playwright spawns the backend itself via its `webServer` config, so
there is nothing to start by hand.

### Setup

```bash
cd web
pnpm install
pnpm e2e:install      # one-time: Chromium + system deps for Playwright
```

### Run

```bash
cd web
pnpm build            # build the SPA into ../src/Drederick.Web/wwwroot
pnpm e2e              # run all specs headless against a fresh backend
pnpm e2e:ui           # Playwright UI mode for interactive debugging
```

From the repo root you can also use `make e2e` (builds web, runs
tests). First-time contributors want `make e2e-install` once.

### What it covers

- **Shell smoke** — SPA boots, sidebar renders the 8 sections, Tatum
  billing line surfaces, health endpoint green.
- **On-voice copy** — every route renders a Tatumism so empty states
  stay on-voice.
- **Findings invariants** — `no_database` graceful handling; loot
  projection never leaks plaintext (canary string); exploit-run rows
  expose `stdout_sha256` only.
- **Runs scope enforcement** — out-of-scope targets rejected by
  `/api/runs`.
- **Scope read-only** — `/scope` exposes no edit surface, issues no
  write requests, and the scope file's mtime is unchanged after
  visiting the page and running the validator.
- **Doctor read-only** — no install/fix/apply buttons.
- **Audit redaction** — canary plaintext seeded into `audit.jsonl`
  never reaches the DOM.

A handful of tests are currently marked `test.fixme` with a clear
reason pointing at the specific SPA component or backend seed hook
that needs to land before the scenario can be asserted cleanly. These
are breadcrumbs — not silent skips — and will flip to real assertions
as those hooks arrive.

### Artefacts

- `web/playwright-report/` — HTML report (viewable via
  `pnpm exec playwright show-report`).
- `web/test-results/` — trace/video/screenshot attachments on failure.
- `web/e2e/.tmp-out/` — per-run findings.db + audit.jsonl the test
  backend writes to. Safe to delete.

All of these paths are in `.gitignore` under the `# --- e2e artifacts ---`
anchor.
