# drederick

> **Drederick E. Tatum** — Heavyweight HTB/CTF champion.

![Drederick Tatum](https://comb.io/NOqy8w.gif)


Drederick is a scope-enforced, adaptive reconnaissance harness for **authorized
lab and CTF environments only** (Hack The Box, TryHackMe, CTF ranges, Vulnhub,
vulhub, or infrastructure you are explicitly authorized to assess). It performs
discovery and fingerprinting only — **no exploitation, no credential attacks,
no brute force, no payload delivery**.

Built in C# on **.NET 10** with the **Microsoft Agent Framework**.

## Authorized use only

The only permitted use of this tool is against lab/CTF targets you are
explicitly authorized to assess. Drederick runs exclusively against targets
listed in a scope file. There is no default scope, no implicit allow-list, and
the tool refuses wildcard or over-broad entries. By pointing it at any target
you assert that you are authorized to test that target. Unauthorized testing of
third-party systems is illegal in most jurisdictions; don't do it.

See [`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) for the full policy.

## What it does

- **Scoped nmap** — TCP service/version scan with enumeration NSE categories
  only. Lab mode uses `safe,default,discovery,version`; strict mode
  (`--no-lab`) uses `safe,default`. Exploit, intrusive, brute, vuln, dos, and
  malware scripts are **always** excluded.
- **HTTP probe** — status, title, `Server`, and which of the common security
  headers are missing.
- **TLS probe** — peer certificate subject/SAN/issuer/expiry and negotiated
  TLS version.
- **DNS probe** — forward + reverse.
- **Adaptive orchestration** — an agent plans the next probe from prior
  findings (deterministic runner out of the box, or the Microsoft Agent
  Framework runner when an OpenAI-compatible key is supplied).
- **Per-host working directory (AutoRecon-style)** — `out/<host>/scans/`,
  `out/<host>/loot/`, `out/<host>/notes.md`.
- **Manual-commands cheatsheet** (lab mode) — `out/<host>/manual_commands.txt`
  with enumeration commands the operator *may* choose to run themselves.
  Drederick never executes these, and never suggests exploit, brute-force, or
  payload-delivery commands.
- **Cross-run memory** — every run updates `memory/findings.json`; the next
  run starts with the prior map in hand, so repeated passes converge on
  deltas (expired certs, new services, drift) rather than re-discovering
  the whole surface.

## Build & test

```bash
dotnet build
dotnet test
```

`nmap` should be installed on the host that runs the recon. The unit tests do
not require it.

## Usage

```bash
# Minimal: explicit targets, deterministic runner (lab mode is on by default)
./src/Drederick/bin/Debug/net10.0/drederick \
    --scope scope.yaml \
    --target 10.10.10.5 \
    --target 10.10.10.6 \
    --out out/

# Enumerate everything in a small scope
drederick --scope scope.yaml --expand --out out/

# Opt into the strictest posture (no cheatsheet, tighter scope cap,
# safe+default NSE only)
drederick --scope scope.yaml --target 10.10.10.5 --no-lab --out out/

# Use the Microsoft Agent Framework runner (needs OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
export DREDERICK_MODEL=gpt-4o-mini     # optional; default is gpt-4o-mini
drederick --scope scope.yaml --target 10.10.10.5 --agent --out out/
```

### Lab mode (default) vs strict mode

| Flag        | Default | Effect                                                                 |
| ----------- | ------- | ---------------------------------------------------------------------- |
| `--lab`     | **on**  | /8 v4 / /32 v6 scope cap; `safe,default,discovery,version` NSE; emits `manual_commands.txt` |
| `--no-lab`  | off     | /16 v4 / /48 v6 scope cap; `safe,default` NSE only; no cheatsheet      |

Both modes **always** refuse wildcard scopes and **always** exclude
`exploit`, `intrusive`, `brute`, `vuln`, `dos`, and `malware` NSE categories.
Those exclusions are not configurable. See
[`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md).

### Scope file

One CIDR, IP, or comment per line. `#` starts a comment.

```
# A single HTB box
10.10.10.5

# A CTF /24 I own
192.168.56.0/24

# An IPv6 lab range
fd00:dead:beef::/64
```

Entries broader than the active cap (`/8`/`/32` in lab mode, `/16`/`/48` in
strict mode) require `--allow-broad`. The wildcard entries `0.0.0.0/0` and
`::/0` are always refused.

### Output

```
out/
├── report.json           # machine-readable consolidated findings
├── report.md             # per-host markdown summary
├── audit.jsonl           # one JSON object per scope decision / tool call
└── <host>/
    ├── scans/            # raw scanner outputs (planned: filled by IReconTool)
    ├── loot/             # empty by default
    ├── notes.md          # safe to hand-edit; drederick won't overwrite
    └── manual_commands.txt  # lab mode only
memory/
└── findings.json   # cross-run knowledge base (loaded on next run)
```

## Datasette dashboard

Every run writes `out/findings.db` — a small SQLite database produced by
[`SqliteReport`](src/Drederick/Reporting/SqliteReport.cs). It contains
normalised `hosts`, `services`, `findings`, `cves`, `poc_refs`,
`poc_sources`, and `tooling` tables, so you can browse a recon pass
point-and-click instead of grepping `report.md`.

A ready-to-use [Datasette](https://datasette.io/) metadata file lives at
[`datasette/metadata.json`](datasette/metadata.json) with labelled tables,
sensible facets (`proto`/`service`/`product`, CVE CVSS + published date,
PoC source, ...), and canned queries (top CVEs by CVSS, services with
public PoCs, PoC refs grouped by source, ...). See
[`docs/DATASETTE.md`](docs/DATASETTE.md) for the full schema reference.

Launch it via the built-in subcommand (requires the `datasette` binary —
`drederick doctor --install` will fetch it):

```bash
drederick serve --out out/
# or customise:
drederick serve --out out/ --host 0.0.0.0 --port 8001 --no-open
```

Equivalent one-liner without the wrapper:

```bash
datasette serve out/findings.db --metadata datasette/metadata.json
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers, components, planned
  additions.
- [`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) — authorized use,
  precise `--lab` semantics, incident response.
- [`docs/MODULES.md`](docs/MODULES.md) — per-scanner contracts and planned
  scanners.
- [`docs/DEVELOPING.md`](docs/DEVELOPING.md) — adding a new `IReconTool`,
  testing conventions, scope re-check pattern.
- [`docs/COMPARISON.md`](docs/COMPARISON.md) — Drederick vs AutoRecon /
  nmapAutomator / Reconnoitre.
- [`docs/UI_GUIDE.md`](docs/UI_GUIDE.md) — planned point-and-click UI (WIP).
- [`docs/DATASETTE.md`](docs/DATASETTE.md) — `out/findings.db` schema
  reference, facets, and canned queries for the Datasette dashboard.

## Architecture (short version)

```
CLI ──► Scope (default-deny allow-list; lab/strict prefix caps)
         │
         ▼
    ReconToolbox  ◄── AuditLog (JSONL)
         │
   ┌─────┴──────┐
   │            │
 nmap        http / tls / dns
   │            │
   └────┬───────┘
        ▼
  AdaptiveRunner  or  MicrosoftAgentRunner
        │                     │
        │           (LLM chooses tool calls;
        │            scope re-checked inside
        │            every tool — the model
        │            cannot escape the allow-list)
        ▼
  KnowledgeBase + JSON/Markdown reports + per-host workdir + cheatsheet
```

Scope enforcement lives **inside every tool**, not at the CLI boundary.
Whichever runner is driving — deterministic or LLM — a target outside the
scope file causes the tool to throw a `ScopeException`, which is logged and
skipped. There is no flag, no prompt, and no environment variable that
disables this check.

## Roadmap

Tracked in follow-up PRs:

- `IReconTool` refactor + bounded `Channel<T>` worker pool with
  `--host-concurrency` / `--service-concurrency`.
- Additional enumeration scanners: SMB, FTP, SSH, SNMP, LDAP, RPC, Kerberos
  (SPN listing only), HTTP content-discovery, TLS cipher enumeration, DNS
  AXFR.
- `src/Drederick.Web` ASP.NET Core host + SignalR live feed.
- `web/` Vite + React + TypeScript + Tailwind point-and-click UI.
- Bundled wordlist, pinned NSE-script list, local NVD-feed CVE annotation.
- Integration tests against `vulhub` (env-gated) + Playwright UI smoke tests.
- Self-contained `dotnet publish` with embedded web assets.

