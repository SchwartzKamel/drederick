---
title: Jeopardy CTF mode — racing a swarm at a CTFd event
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - README.md
  - SCOPE_AND_LEGAL.md
  - LLM_SETUP.md
  - ARCHITECTURE.md
  - DEVELOPING.md
  - DATASETTE.md
  - TROUBLESHOOTING.md
  - ../AGENTS.md
---

# Jeopardy CTF mode — racing a swarm at a CTFd event

> *"A fair fight is one you didn't prepare well enough for."*
> — **Drederick Tatum**, pre-bout press conference

Let's be honest: solo flag-hunting at a Jeopardy CTF is a workload
mismatch. You've got six categories, forty challenges, a clock that
doesn't blink, and one brain. Drederick's `ctf-solve` mode turns the
harness into a **parallel CTF solver**: for every challenge on the
scoreboard it stands up a *swarm* of LLM fighters, races them through a
Dockerised toolbox, and submits the first real flag that lands. The
loser models get their gloves cut off the moment a sibling wins —
budget saved, next challenge started.

This is the same Drederick you already know — scope-gated, audit-logged,
no loot exfiltration, no kill switch — pointed at a specific weight
class. Under the hood it's the Jeopardy subsystem under
[`src/Drederick/Jeopardy/`](../src/Drederick/Jeopardy/): a CTFd client,
a Docker sandbox runtime, a solver swarm, a cross-solver message bus,
and a flag-submit coordinator that dedupes racing winners.

**Authorized events only.** Use this on CTFs you are allowed to play —
your own, a sanctioned competition, a lab you pay for. The scope file
still applies: every HTTP target the solvers reach (the CTFd API host,
any per-challenge infrastructure the event rules list) must be inside
`scope.yaml`. See [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) for the
authorization model. If the event rules don't explicitly allow
automated tooling, don't register the CTFd host in your scope. Simple
as.

- [Quickstart](#quickstart)
- [Prerequisites](#prereqs)
- [How it works](#architecture)
- [Swarm config — racing multiple models](#swarm)
- [Category-specific strategy](#categories)
- [Mid-run operator hints](#hints)
- [Budget + safety rails](#budget)
- [Scope + audit](#scope-audit)
- [Datasette browsing](#datasette)
- [Troubleshooting](#troubleshooting)
- [Beating the competition](#competition)

<a id="quickstart"></a>
## Quickstart

Minimum viable command:

```bash
gh auth login --web

drederick ctf-solve \
  --scope scope.yaml \
  --ctfd https://ctf.example.com \
  --ctfd-token <ctfd_api_token> \
  --report-dir out/ctf-report/
```

What each piece does:

- `--scope scope.yaml` — default-deny allow-list. Must include the CTFd
  host and any per-challenge infrastructure referenced by the event
  rules. Every HTTP/socket touch goes through this gate.
- `--ctfd <url>` — CTFd base URL. Falls back to `$CTFD_URL` if omitted.
- `--ctfd-token <tok>` — a CTFd API token. Falls back to `$CTFD_TOKEN`.
  See [Prerequisites](#prereqs) for how to mint one.
- `--report-dir` — where `report.json`, `report.md`, and `audit.jsonl`
  land. Defaults to `out/ctf-report/`.
- `--llm-provider {copilot|azure|llamacpp}` — which LLM backend the
  swarm races. Defaults to `copilot`. Azure OpenAI and llama.cpp are
  wired through [`LlmProviderFactory`](../src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs);
  per-provider flags (`--azure-endpoint`, `--azure-deployment`,
  `--llamacpp-url`, `--llamacpp-model`) are documented in
  [`LLM_SETUP.md#ctf-solve-cli-recipes`](LLM_SETUP.md#ctf-solve-cli-recipes).

**What "in scope" means for a Jeopardy CTF.** The CTFd host is the
obvious one. Many events also spin up per-challenge boxes
(`ssh.chal.example.com:31337`, `web-svc.chal.example.com`) whose
hostnames/IPs are listed in the challenge description or event rules.
Add every one of them to `scope.yaml` *before* starting the swarm.
Anything missing gets a clean `ScopeException` at the tool layer and
the solver moves on — no quiet bypass.

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0`  | At least one challenge solved. |
| `1`  | Hard error (missing scope/token, unreachable CTFd, setup exception). |
| `2`  | Ran cleanly but no solves (timeout, all incorrect, budget exhausted). |

<a id="prereqs"></a>
## Prerequisites

| Requirement | How to satisfy it |
| ----------- | ----------------- |
| **Docker** (sandbox runtime) | Install via your package manager, then `docker info` should succeed. Run `drederick doctor --category=jeopardy` to verify (`DockerInstalledCheck`, `DockerDaemonCheck` in [`JeopardyDoctorChecks.cs`](../src/Drederick/Doctor/JeopardyDoctorChecks.cs)). |
| **GitHub Copilot token** (first-class) | Run `gh auth login --web` (preferred local setup), or set `COPILOT_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN`. Resolution precedence is `COPILOT_TOKEN > GH_TOKEN > GITHUB_TOKEN > gh auth token`. Full recipe — plus Azure OpenAI and llama.cpp as alternate backends — in [`LLM_SETUP.md`](LLM_SETUP.md). |
| **CTFd API token** | In the CTFd UI: click your profile → **Settings** → **Access Tokens** → generate one. Keep it in `$CTFD_TOKEN` or pass `--ctfd-token`; the token is never logged — only its SHA-256 lands in `audit.jsonl`. |
| **Sandbox image** | Build it once per host: `docker build -t drederick/jeopardy-sandbox -f sandbox/Dockerfile.jeopardy-sandbox sandbox/`. The image is `ubuntu:24.04` with the full CTF toolchain preinstalled (see [`sandbox/jeopardy-tools.txt`](../sandbox/jeopardy-tools.txt)). |
| **Scope file** | At minimum, the CTFd host. Ideally every challenge infra host as well. |

Run the preflight once; it prints a ✓/⚠/✗ summary:

```bash
drederick doctor --category=jeopardy
```

<a id="architecture"></a>
## How it works — the architecture in one diagram

```
                                 operator
                                    │
                                    │ drederick ctf-msg --kind hint ...
                                    ▼
          ┌──────────────────  OperatorInbox  (JSONL file)  ──────────────┐
          │                         │                                      │
          ▼                         ▼                                      │
   ┌─────────────┐           ┌─────────────┐                               │
   │ CtfdPoller  │──list────▶│ CtfCoordin- │◀──SolverMessageBus (hints,    │
   │ (CTFd API)  │ challenges│ ator        │   shared findings, fanout)────┘
   └─────────────┘           └─────┬───────┘
                                   │ one Swarm per challenge
                                   ▼
                         ┌──────── SolverSwarm ────────┐
                         │                              │
                         ▼              ▼              ▼
                    ┌─────────┐   ┌─────────┐   ┌─────────┐
                    │ Solver  │   │ Solver  │   │ Solver  │   ← N models
                    │ (gpt)   │   │ (opus)  │   │ (gemini)│     racing in
                    └────┬────┘   └────┬────┘   └────┬────┘     parallel
                         │             │              │
                         ▼             ▼              ▼
                    ┌────────────── Sandbox pool ────────────┐
                    │  docker run drederick/jeopardy-sandbox │
                    │  (pwntools, gdb, radare2, sqlmap, …)   │
                    └──────────────────┬─────────────────────┘
                                       │ first good flag
                                       ▼
                          ┌──────────────────────────┐
                          │ FlagSubmitCoordinator    │──POST /flags──▶ CTFd
                          │ (dedupe, confirm, cancel │
                          │  losing solvers)         │
                          └──────────────────────────┘
                                       │
                                       ▼
                            CostTracker  +  LoopDetector
                         (stop-loss budget / stuck-solver kill)
                                       │
                                       ▼
                            report.json / report.md
                            audit.jsonl (SHA-256 only)
```

Moving parts, each with source links:

- **`CtfdPoller` + `CtfdClient`** discover challenges and submit flags
  via the CTFd REST API ([`src/Drederick/Jeopardy/Ctfd/`](../src/Drederick/Jeopardy/Ctfd/)).
- **`CtfCoordinator`** ([`src/Drederick/Jeopardy/Coordinator/`](../src/Drederick/Jeopardy/Coordinator/))
  owns the per-challenge dispatch loop, bounded by
  `--max-concurrent`.
- **`SolverSwarm`** launches one `ChallengeSolver` per model
  (`--models`). First to emit a correct flag wins; the coordinator
  cancels the others.
- **`ChallengeSolver`** drives its LLM through tool calls inside the
  Docker sandbox ([`Jeopardy/Solver/`](../src/Drederick/Jeopardy/Solver/)).
- **`SandboxManager` / `SandboxSession`** ([`Jeopardy/Sandbox/`](../src/Drederick/Jeopardy/Sandbox/))
  run each tool call as `docker exec` inside an isolated container
  built from [`sandbox/Dockerfile.jeopardy-sandbox`](../sandbox/Dockerfile.jeopardy-sandbox).
- **`SolverMessageBus`** ([`Jeopardy/Bus/SolverMessageBus.cs`](../src/Drederick/Jeopardy/Bus/SolverMessageBus.cs))
  fans out cross-solver events. If solver A recovers a credential or
  a partial flag, solver B sees it on the next tool-call boundary.
- **`CostTracker`** ([`Jeopardy/Budget/CostTracker.cs`](../src/Drederick/Jeopardy/Budget/CostTracker.cs))
  enforces per-run and per-challenge USD caps.
- **`LoopDetector`** ([`Jeopardy/Detection/LoopDetector.cs`](../src/Drederick/Jeopardy/Detection/LoopDetector.cs))
  notices a solver spinning on the same tool call and terminates it.
- **`FlagSubmitCoordinator`** ([`Jeopardy/Submit/`](../src/Drederick/Jeopardy/Submit/))
  dedupes concurrent submits and cancels losing siblings the moment
  CTFd confirms a flag.
- **`OperatorInbox`** ([`Jeopardy/Ops/`](../src/Drederick/Jeopardy/Ops/))
  watches a local JSONL file for `drederick ctf-msg` directives.

<a id="swarm"></a>
## Swarm config — racing multiple models

Your opponent is the clock. Every second a model spends on a challenge
it can't solve is a second the other fighters in your corner aren't
swinging. The swarm fixes that — pick a diverse roster and let them
race.

Pass `--models` as a comma-separated list. Default roster:

```
claude-opus-4.7, gpt-5.4, gemini-3.1-pro
```

Recommended roster (leans on Copilot's multi-model access; the same
`--models` syntax works against Azure deployments and llama.cpp models
too — pick the backend with `--llm-provider` and supply the per-provider
config flags. Full recipes in [`LLM_SETUP.md`](LLM_SETUP.md#ctf-solve-cli-recipes)):

| Model | Why it's on the card |
| ----- | -------------------- |
| `gpt-5.4` | Fast generalist. Cheap jabs against web/misc. |
| `claude-opus-4.7` | Deep reasoning. The hard pwn/crypto closer. |
| `claude-sonnet-4.6` | Balanced, strong tool use. Solid body work. |
| `gemini-3.1-pro` | Math and crypto specialist. |
| `grok-code-fast-1` | Quick on rev/pwn code tasks. |

Sample command:

```bash
drederick ctf-solve \
  --scope scope.yaml \
  --ctfd https://ctf.example.com \
  --ctfd-token "$CTFD_TOKEN" \
  --models gpt-5.4,claude-opus-4.7,claude-sonnet-4.6,gemini-3.1-pro,grok-code-fast-1 \
  --max-concurrent 4 \
  --wall-clock-min 20 \
  --run-budget-usd 100 \
  --challenge-budget-usd 5
```

**Race semantics.** The first solver to submit a flag that CTFd accepts
wins the challenge. `FlagSubmitCoordinator` cancels the remaining
solvers, their token spend stops immediately, and their containers are
torn down. Losing solvers do not count against the run budget for work
they didn't finish.

<a id="categories"></a>
## Category-specific strategy

Category detection drives which prompt fragment the swarm gets. The
authoritative fragments live in
[`src/Drederick/Jeopardy/Prompts/PromptLibrary.cs`](../src/Drederick/Jeopardy/Prompts/PromptLibrary.cs);
unknown categories fall back to `misc`. Sandbox tool inventory is in
[`sandbox/jeopardy-tools.txt`](../sandbox/jeopardy-tools.txt).

| Category | Prompt focus | Key sandbox tools |
| -------- | ------------ | ----------------- |
| `web` | Auth bypass, SQLi, SSRF, deserialisation, JS review. | `ffuf`, `gobuster`, `sqlmap`, `wfuzz`, `curl`, `httpx`, `playwright`, `beautifulsoup4`, `nmap`. |
| `crypto` | RSA weaknesses, factoring, oracle attacks, AES mode bugs. | `sagemath`, `RsaCtfTool`, `factordb-pycli`, `primefac`, `gmpy2`, `sympy`, `pycryptodome`, `z3-solver`, `openssl`, `cado-nfs`, `fermat-factor`. |
| `pwn` | ROP, leaks, heap, one-gadgets, libc versioning. | `pwntools`, `gdb` + `pwndbg`/`peda`, `radare2`, `ROPgadget`, `ropper`, `one_gadget`, `libc-database`, `angr`, `seccomp-tools`, `patchelf`. |
| `rev` | Static + dynamic analysis, decompilation, anti-debug. | `radare2`, `gdb-multiarch`, `ltrace`, `strace`, `binwalk`, `strings`, `nm`, `objdump`, `readelf`, `upx-ucl`, `angr`, `capstone`, `unicorn`. |
| `forensics` | Carving, memory dumps, metadata, filesystems. | `binwalk`, `foremost`, `scalpel`, `photorec`, `sleuthkit`/`testdisk`, `exiftool`, `volatility3`, `hachoir`, `tshark`, `tcpdump`. |
| `stego` | LSB, palette tricks, audio spectra, OCR. | `steghide`, `stegseek`, `zsteg` (ruby), `pngcheck`, `imagemagick`, `exiftool`, `tesseract-ocr`, `sox`, `ffmpeg`, StegSolve (jar). |
| `misc` | Everything else — base-N chains, puzzles, ad-hoc protocols. | `python3` + `ipython3`, `jq`, `xxd`, `hexyl`, `ripgrep`, `socat`, `netcat-traditional`. |

There is no dedicated `osint` fragment; OSINT-flavoured challenges hit
the `misc` prompt and rely on the sandbox's generic HTTP clients. If
your event uses `osint` heavily, consider adding a fragment — see
[`DEVELOPING.md`](DEVELOPING.md).

<a id="hints"></a>
## Mid-run operator hints

You're still in the corner. When the swarm is clearly off-course,
inject a hint — it fans out through the `SolverMessageBus` to every
live solver on the next tool-call boundary.

```bash
drederick ctf-msg \
  --kind hint \
  --chal "babyweb" \
  --body "Try ../../../etc/passwd on the /file endpoint"
```

`--kind` accepts these values
([`CtfMsgRunner.ValidKinds`](../src/Drederick/Jeopardy/Cli/CtfMsgRunner.cs)):

| Kind | Effect |
| ---- | ------ |
| `hint` | Broadcast hint text (requires `--body`). Scoped to one challenge via `--chal`, or fanned out to all live solvers if `--chal` is omitted. |
| `focus` | Cancel all other in-flight challenges; concentrate the pool on `--chal`. |
| `skip`  | Abort the active swarm for `--chal`. |
| `stop`  | Alias for clean halt of a specific challenge / solver (see `--solver`). |
| `shutdown` | Cleanly shut the coordinator down; a partial report still gets written. |

The directive is appended as one JSONL line to the inbox
(`~/.drederick/jeopardy-inbox.jsonl` by default, overridable with
`--inbox`). The coordinator tails that file; hint bodies are hashed
(SHA-256) into the audit log but never stored in plaintext there.

<a id="budget"></a>
## Budget + safety rails

| Knob | Default | Purpose |
| ---- | ------- | ------- |
| `--wall-clock-min` | `20` | Per-challenge wall-clock ceiling (minutes). |
| `--run-budget-usd` | *unset* | Hard cap on total LLM spend for the run. `CostTracker` halts new work once tripped. |
| `--challenge-budget-usd` | *unset* | Per-challenge cap. When a challenge's swarm trips this, it's abandoned and the run continues. |
| `--max-concurrent` | `4` | Max challenges worked in parallel. Doubles as the upper bound on concurrent sandboxes. |
| `--poll-interval-sec` | `5` | CTFd scoreboard poll cadence. |
| `--category-filter` | *unset* | Comma-separated allowlist (e.g. `pwn,crypto`). |
| `--challenge-ids` | *unset* | Exact CTFd challenge-id filter. |

When `CostTracker` trips a cap, the owning solver exits cleanly; if a
valid flag was cached before the trip, it's still emitted. The
`LoopDetector` independently kills a solver stuck in a tool-call cycle,
so a stalled model won't burn its full per-challenge budget.

<a id="scope-audit"></a>
## Scope + audit

The same invariants that govern the rest of the harness apply here —
see [`SCOPE_AND_LEGAL.md#invariants`](SCOPE_AND_LEGAL.md#invariants)
and [`AGENTS.md#invariants`](../AGENTS.md#invariants).

- **`scope.yaml` still gates every network target** the solvers touch
  — the CTFd API host, per-challenge boxes, any URL the LLM decides to
  fetch. `CtfdClient` and `SandboxManager` both re-check scope at the
  tool boundary. The LLM cannot escape it, regardless of prompt.
- **`audit.jsonl` records everything.** Every LLM call, tool spawn,
  flag attempt, operator directive, and budget event is logged with
  timestamps and SHA-256 digests. Tokens are redacted in the banner
  and hashed in the audit records; flag plaintext is never stored —
  only its SHA-256.
- **No loot exfiltration.** Solver containers are torn down; any
  artifacts captured (files, tool output) stay under the
  `--report-dir` tree and `audit.jsonl`. No telemetry, no cloud sync,
  no phone-home.
- **No scope kill switch.** There is no flag, env var, or `ctf-msg`
  directive that disables scope or the audit log.

<a id="datasette"></a>
## Datasette browsing

After the run, browse the results the same way you'd triage a recon
run:

```bash
drederick serve --out out/
```

The CTF run writes its own `report.json` / `report.md` into
`--report-dir`, and — when your run also produces a `findings.db`
(e.g. you combined `ctf-solve` with a recon pass) — Datasette picks it
up. See [`DATASETTE.md`](DATASETTE.md) for facets, canned queries, and
PoC triage workflow.

<a id="troubleshooting"></a>
## Troubleshooting

| Symptom | Fix |
| ------- | --- |
| `Docker is required to run the Jeopardy sandbox` | Install Docker via your package manager; `drederick doctor --category=jeopardy` walks you through the detection. The doctor will **not** auto-install Docker (too much blast radius) — pick the recipe for your distro. |
| `Docker daemon not reachable` | Start the daemon (`systemctl start docker`) and add your user to the `docker` group; re-login; rerun the doctor. |
| `401` / `403` from CTFd | Re-mint the CTFd API token (Settings → Access Tokens). Confirm the token belongs to a registered, rules-accepted account. |
| `no Copilot token found (set COPILOT_TOKEN, GH_TOKEN, or GITHUB_TOKEN)` | Run `gh auth login --web` or export one of those env vars. Precedence is `COPILOT_TOKEN > GH_TOKEN > GITHUB_TOKEN > gh auth token`. See [`LLM_SETUP.md`](LLM_SETUP.md). |
| `CTFd host '…' is not in scope` | Add the CTFd host to `scope.yaml` and retry. The CLI surface-checks IP-literal hosts; hostnames are resolved and scope-checked at the client boundary. |
| Solver stuck repeating the same tool call | `LoopDetector` terminates it and moves on. If it's still spinning, inject a `--kind hint` via `ctf-msg` or `--kind skip` the challenge. |
| Budget exhausted mid-run | `CostTracker` halts new work; in-flight solvers finish their current step and exit. Rerun with a higher `--run-budget-usd` or tighter `--category-filter`. |

More general diagnostics in
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

<a id="competition"></a>
## Beating the competition

The reference point is
[`verialabs/ctf-agent`](https://github.com/verialabs/ctf-agent) — the
proven single-agent, single-model CTFd solver. Credit where it's due;
its sandbox tool list directly influenced ours. Drederick's design
choices aim higher:

| Dimension | `ctf-agent` | `drederick ctf-solve` |
| --------- | ----------- | --------------------- |
| Model plurality | One model per run. | Swarm races N models per challenge (`--models`). First good flag wins; losers are canceled. |
| Cross-solver learning | None. | `SolverMessageBus` fans discoveries (creds, partial flags, category hints) across sibling solvers live. |
| Scope enforcement | Implicit (operator discipline). | Default-deny allow-list, enforced inside every tool. LLM cannot escape. |
| Audit | Ad-hoc logs. | Append-only `audit.jsonl` with argv-digest / prompt-digest SHA-256, never plaintext secrets. |
| Operator control mid-run | Stop the process. | `ctf-msg --kind hint/focus/skip/stop/shutdown` fanned out via the bus. |
| Prompt voice | Generic. | Tatum-voiced — confident, direct, terse. See [`PromptLibrary.cs`](../src/Drederick/Jeopardy/Prompts/PromptLibrary.cs). |

The differentiators aren't marketing — they're what lets the harness
*keep punching* after the first model hits a wall. Race more fighters,
share more corner advice, enforce a harder scope boundary, and keep a
receipt for every swing.
