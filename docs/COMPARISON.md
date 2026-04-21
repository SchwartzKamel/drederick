---
title: Comparison — drederick vs AutoRecon / nmapAutomator / Reconnoitre
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - ../README.md
  - SCOPE_AND_LEGAL.md
  - ARCHITECTURE.md
---

# Comparison: Drederick vs AutoRecon / nmapAutomator / Reconnoitre

> **TL;DR — when to pick drederick.** You want scope enforcement baked
> into every tool (not a forgettable flag), hard-excluded
> `exploit`/`brute`/`vuln` NSE, offline CVE annotation against an NVD
> cache, locally cached PoC source with SHA-256 provenance, and an
> LLM-assisted planner that can't escape the allow-list. Everything else,
> prefer the peer tools below.

A frank look at what Drederick does, what it doesn't, and when you'd reach for
one of the other tools instead.

| Capability                                  | Drederick              | AutoRecon              | nmapAutomator     | Reconnoitre         |
| ------------------------------------------- | ---------------------- | ---------------------- | ----------------- | ------------------- |
| Runtime                                     | .NET 10 / C#           | Python (asyncio)       | Bash              | Python              |
| Scope allow-list (refuses out-of-scope)     | **yes, in every tool** | configurable           | no                | no                  |
| Hard-excludes `exploit`/`brute`/`vuln` NSE  | **yes (non-bypassable)** | no (defaults safe)   | no                | no                  |
| Credential brute force                      | **no**                 | no (by default)        | no                | no                  |
| Per-service scanner fan-out                 | **14 scanners**        | ~20+ scanners          | limited (nmap tiers) | ~10 scanners     |
| Bounded worker pool                         | **yes (`Channel<T>`)** | yes (asyncio)          | no                | limited             |
| Adaptive / agentic planning                 | **yes (LLM optional)** | no                     | no                | no                  |
| Cross-run knowledge base                    | **yes (`memory/findings.json`)** | no           | no                | no                  |
| Per-host working dir + notes                | yes                    | yes                    | yes               | yes                 |
| Manual-commands cheatsheet                  | **yes (lab mode)**     | yes                    | partial           | yes                 |
| CVE annotation (offline NVD feed)           | **yes**                | no                     | no                | no                  |
| PoC aggregation (Exploit-DB / GHSA / MSF / nuclei) | **yes (cached locally)** | partial (searchsploit pointers only) | no | no    |
| Executes PoCs                               | **never**              | never                  | never             | never               |
| SQLite findings DB                          | **yes (`findings.db`)** | no                    | no                | no                  |
| Point-and-click dashboard                   | **yes (Datasette today, React planned)** | no     | no                | no                  |
| Operator-workstation preflight / installer  | **yes (`drederick doctor`)** | partial (pip)    | no                | partial (`setup.py`) |
| Distribution                                | `dotnet publish` binary (self-contained planned) | `pip install` | shell script | `pip install` |

## When to pick what

- **Pick AutoRecon** if you want the most battle-tested CTF enumeration
  tool and you're comfortable running it from a Python environment. Its
  per-service scanner catalogue is still deeper than ours on niche
  services (e.g. Oracle TNS, Redis info).
- **Pick nmapAutomator** for a lightweight shell script that wraps nmap
  tiers without much ceremony — no Python, no toolchain, just bash.
- **Pick Reconnoitre** for a long-standing OSCP-style enumeration
  workflow with a focused directory layout and reporting template.
- **Pick Drederick** when you need:
  - Strict default-deny scope enforcement baked into every tool, not a
    CLI flag someone can forget.
  - Hard, non-bypassable exclusion of exploit/brute/vuln NSE.
  - An LLM-assisted adaptive planner that cannot escape the allow-list.
  - A cross-run knowledge base that treats repeat passes as deltas
    (new services, expired certs, drift).
  - **Offline CVE annotation** against a local NVD cache, merged into a
    SQLite database you can browse in Datasette.
  - **PoC source caching** with SHA-256 provenance, so you can triage a
    CTF box offline with the exploit source in hand — but with a
    hard-coded "aggregate + present, never execute" invariant.
  - A point-and-click dashboard today (Datasette) and a richer React UI
    on the roadmap.

## What Drederick intentionally does not do

- Run exploits or PoCs. Cached PoC source is for the practitioner to
  read, not for Drederick to spawn.
- Brute-force credentials.
- Deliver payloads.
- Auto-run `msfconsole`'s exploit modules, `hydra`, `medusa`, or
  `crackmapexec`'s attack modes.
- Make outbound requests *to a target* during CVE annotation or doctor.
- Offer an "I promise I'm authorized" flag that disables the scope check.

See [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) for the full policy and
the aggregate-vs-execute line.
