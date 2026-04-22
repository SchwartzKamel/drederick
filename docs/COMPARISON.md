---
title: Comparison — drederick vs the field
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - ../README.md
  - SCOPE_AND_LEGAL.md
  - ARCHITECTURE.md
  - JEOPARDY.md
  - LLM_SETUP.md
  - POST_EXPLOITATION.md
---

# Comparison: Drederick vs the field

> **"A fair fight is one you didn't prepare well enough for." — Drederick Tatum**
>
> **TL;DR — when to pick drederick.** You want a **full-auto offensive
> harness** that (a) enumerates, (b) annotates with CVEs, (c) caches PoC
> source, (d) **executes matching exploits**, (e) runs credential
> attacks, (f) delivers payloads, and (g) handles post-exploitation
> pivot — all inside a default-deny scope allow-list that no flag, env
> var, debug build, or LLM prompt can disable. Plus a **Jeopardy CTF
> mode** that races multiple LLM models against every challenge for
> first-to-flag wins. Outside scope it does nothing.

Drederick now spans three distinct fronts: **recon automation**,
**offensive security automation**, and **Jeopardy CTF solving**. Each
front has a different peer set. Pick the comparison table that matches
what you're trying to do.

---

## Front 1: Recon automation

Peers: [AutoRecon](https://github.com/Tib3rius/AutoRecon),
[nmapAutomator](https://github.com/21y4d/nmapAutomator),
[Reconnoitre](https://github.com/codingo/Reconnoitre).

| Capability                                  | Drederick | AutoRecon | nmapAutomator | Reconnoitre |
| ------------------------------------------- | --------- | --------- | ------------- | ----------- |
| Runtime                                     | .NET 10 / C# | Python (asyncio) | Bash | Python |
| Scope allow-list enforced **in every tool** | **yes**   | configurable | no | no |
| Per-service scanner fan-out                 | **14+ scanners** | ~20+ scanners | nmap tiers | ~10 scanners |
| Bounded worker pool                         | **yes (`Channel<T>`)** | yes (asyncio) | no | limited |
| Cross-run knowledge base                    | **yes (`memory/findings.json`)** | no | no | no |
| Per-host working dir + notes                | yes | yes | yes | yes |
| Manual-commands cheatsheet                  | **yes (lab mode)** | yes | partial | yes |
| CVE annotation (offline NVD feed)           | **yes** | no | no | no |
| PoC aggregation (ExploitDB/GHSA/MSF/nuclei) | **yes (cached locally)** | partial (searchsploit pointers) | no | no |
| SQLite findings DB                          | **yes (`findings.db`)** | no | no | no |
| Point-and-click dashboard                   | **yes (Datasette + Avalonia UI)** | no | no | no |
| Operator-workstation preflight / installer  | **yes (`drederick doctor`)** | partial (pip) | no | partial |

**Pick AutoRecon** if you want the most battle-tested CTF enumeration
tool in Python and you don't need exploitation or LLM planning. Its
per-service scanner catalogue is still deeper than ours on niche
services (Oracle TNS, Redis info).

**Pick nmapAutomator** for a lightweight bash wrapper over nmap tiers
— no toolchain, no ceremony.

**Pick Reconnoitre** for OSCP-style enumeration with a focused
directory layout and reporting template.

**Pick Drederick** when recon is step one of a *chain* that ends in
exploitation, credential attack, and flag or shell extraction — and
you want the scope gate to protect you at every step.

---

## Front 2: Full-auto offensive automation

Peers: [PentestGPT](https://github.com/GreyDGL/PentestGPT),
[HackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT),
[AutoAttacker](https://arxiv.org/abs/2403.01038),
[Metasploit Pro automation](https://docs.rapid7.com/metasploit/),
[Sliver](https://github.com/BishopFox/sliver) (C2).

| Capability | Drederick | PentestGPT | HackingBuddyGPT | Metasploit Pro |
| ---------- | --------- | ---------- | --------------- | -------------- |
| Default-deny scope allow-list enforced in every tool | **yes** | no | no | no |
| LLM cannot escape scope via prompt injection | **yes (tool-level `_scope.Require`)** | n/a | n/a | n/a |
| Auto-runs exploits against matched CVEs | **yes (`ExploitRunner`)** | guided | yes (Linux priv-esc focus) | yes |
| Credential attack chain (spray / brute / AS-REP / kerberoast / PtH) | **yes (`CredRunner`)** | no | no | yes |
| Payload generation + delivery | **yes (`PayloadStager`, msfvenom-backed)** | no | no | yes |
| Session tracking + post-ex pivot | **yes (`out/sessions/`)** | no | partial | yes |
| Multi-stage chain planner | **yes (adaptive + LLM runners)** | yes | yes | no |
| Multi-model LLM (Copilot SDK → GPT / Claude / Gemini / Grok) | **yes** | single-model | single-model | no |
| Azure OpenAI + llama.cpp backends | **yes** | partial | varies | no |
| Append-only audit log with SHA-256 argv digests | **yes (`audit.jsonl`)** | no | no | enterprise tier |
| Plaintext credentials never logged (SHA-256 only) | **yes** | no | no | no |
| Offline PoC corpus from 12+ sources with liberal CVE matching | **yes** | no | no | no |
| Destructive categories opt-in per run | **yes (`--allow-dos`, `--allow-destructive`, etc.)** | n/a | n/a | per-module |
| Open source | **yes** | yes | yes | no (Pro) |

**Pick PentestGPT** if you want a conversational co-pilot that guides
you through a pentest step-by-step — it's advisory, not autonomous.

**Pick HackingBuddyGPT** for academic-style Linux privilege-escalation
experiments with LLM-driven SSH loops.

**Pick Metasploit Pro** if you're in an enterprise budget with
compliance requirements and want vendor support on the exploit
database itself.

**Pick Drederick** when you want:

- One tool that enumerates, exploits, attacks credentials, drops
  payloads, and handles sessions — but **cannot** touch anything
  outside the scope file.
- Multi-model LLM planning (Copilot SDK surfaces GPT-5.x + Claude 4.x
  + Gemini 3.x + Grok via a single token) with a hard tool-level
  authorization boundary the model cannot bypass via prompt.
- A paper-trail — every PoC fetch, exploit spawn, credential attempt,
  and payload drop in append-only JSONL, keyed by SHA-256 of argv and
  of any attempted secret, with no phone-home.
- Local-first everything: loot stays in `out/`, no telemetry, no
  cloud sync.

---

## Front 3: Jeopardy CTF solving

Peers: [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent)
(BSidesSF 2026 Jeopardy winner; direct competitor),
[EnIGMA](https://github.com/princeton-nlp/enigma-eval) (Princeton NLP
CTF benchmark),
[CAI](https://github.com/aliasrobotics/cai-framework) (Cybersecurity AI
framework),
[PentestGPT-CTF mode](https://github.com/GreyDGL/PentestGPT).

| Capability | Drederick | ctf-agent | EnIGMA | CAI |
| ---------- | --------- | --------- | ------ | --- |
| CTFd v3 API native client | **yes (`CtfdClient`)** | yes | no | no |
| Automatic flag submission with dedup | **yes (`FlagSubmitCoordinator`)** | yes | manual | varies |
| Multi-model **race per challenge** (first-to-solve wins) | **yes (`SolverSwarm`)** | no (single model) | no | no |
| Cross-solver hint bus (solver A's finding reaches solver B) | **yes (`SolverMessageBus`)** | no | no | no |
| Mid-run operator hint injection | **yes (`drederick ctf-msg`)** | no | no | no |
| Category-specific prompts (web / crypto / pwn / rev / forensics / misc / osint) | **yes (Tatum-voiced)** | partial | no | no |
| Docker-isolated solver sandbox with ~75 CTF tools | **yes (`sandbox/Dockerfile.jeopardy-sandbox`)** | yes | partial | yes |
| Sandbox default network policy | **`--network none`** (opt-in only when target reachable is in scope) | varies | n/a | varies |
| Loop / stuck detection (exact-repeat, AB-oscillation, no-progress) | **yes (`LoopDetector`)** | no | no | no |
| Per-challenge token budget enforcement | **yes (`CostTracker`, `BudgetExceededException`)** | no | n/a | no |
| Scope allow-list protects CTFd host + any referenced infra | **yes** | no | no | no |
| Plaintext flag never logged (SHA-256 audit only) | **yes** | no | no | no |
| LLM backend | Copilot SDK (multi-model) + Azure OpenAI + llama.cpp | OpenAI-only | varies | multi |
| BSidesSF 2026 winner | contender | **yes** ($1,500 prize, 52/52) | n/a | n/a |

**Pick ctf-agent** if you want the proven winner from BSidesSF 2026
out of the box. It's the bar we're aiming to clear.

**Pick EnIGMA / CAI** for research benchmarks and academic
reproducibility.

**Pick Drederick's Jeopardy mode** when you want:

- A **swarm** of models racing each challenge in parallel — faster
  models cover breadth, deeper models chew on the hard ones, first
  flag wins and the losers are canceled so budget isn't wasted.
- A **cross-solver bus** so credential or endpoint discoveries from
  one solver instantly feed every other live solver on the same
  challenge.
- **Operator-in-the-loop hints** via `drederick ctf-msg` without
  killing the run.
- The same scope/audit guarantees that protect your engagements —
  ported into a CTF harness that still can't touch out-of-scope
  infrastructure.

See [`JEOPARDY.md`](JEOPARDY.md) for the operator playbook.

---

## Hard boundaries (non-negotiable, across all fronts)

What drederick will *never* do, regardless of mode:

- Act outside the scope file. Every network-touching method calls
  `_scope.Require(target)` as its first statement. Wildcards
  (`0.0.0.0/0`, `::/0`) are always refused. No flag, env var, or LLM
  prompt disables the check.
- Silently elevate privileges. `drederick doctor` asks before
  installing; never re-execs as root; never touches the scope file
  from code.
- Exfiltrate loot. Credentials, hashes, tickets, captured secrets all
  stay local to `out/` and `audit.jsonl`. No telemetry, no cloud
  sync, no phone-home from the harness itself.
- Log plaintext secrets. Attempted passwords, flag submissions, and
  tool arguments are recorded as SHA-256 digests only.
- Compact or redact `audit.jsonl`. Append-only, one way.

See [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) for the verbatim
invariants.

---

## What changed from the previous comparison

The earlier version of this doc described drederick as an
"aggregate + present, never execute" recon tool. That stance is
obsolete. Drederick is now a full-auto offensive harness — scope is
the authorization boundary, not a "we won't exploit" promise. Inside
scope the fangs are sharp; outside scope the tool is inert. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) for the current
capability surface, and [`JEOPARDY.md`](JEOPARDY.md) for the CTF
mode.
