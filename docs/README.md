---
title: Documentation index
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-05
related:
  - ../README.md
  - ../AGENTS.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
  - DEVELOPING.md
  - MODULES.md
  - SELF_SUFFICIENCY.md
  - DATASETTE.md
  - DB_SCHEMA.md
  - UI.md
  - UI_GUIDE.md
  - COMPARISON.md
  - LLM_SETUP.md
  - MODEL_BEHAVIOR.md
  - POST_EXPLOITATION.md
  - EMPIRE.md
  - C2_INTEGRATION.md
  - JEOPARDY.md
  - CREDENTIALS.md
  - GETTING_STARTED.md
  - TROUBLESHOOTING.md
  - COMPARISON.md
---

# drederick documentation index

> **TL;DR.** This is the map. Humans scan the tables; LLM agents jump to the
> [file-concept map](../AGENTS.md#file-concept-map) and the
> [invariants](#invariants-cheatsheet). Every doc in `docs/` carries YAML
> frontmatter; every major heading has a stable anchor.

<a id="quick-links"></a>
## Quick links

- **Install (fastest):** `curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash` — downloads the latest signed release binary to `~/.local/bin`.
- **Install (from source):** `make quickstart` — deps + build + publish + userspace install.
- **Scan your first HTB box:** `drederick --scope scope.yaml --target 10.10.10.5 --out out/`
- **Turn on the LLM cornerman:** [`LLM_SETUP.md`](LLM_SETUP.md) — provider wiring for `--agent`, `--agent=hybrid`, and `ctf-solve`.
- **Pick the right model for the round:** [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md) — fight notes, compliance limits, and price-to-performance fields.
- **Open the dashboard:** `drederick serve --out out/` → <http://127.0.0.1:8001>
- **Read the invariants:** [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) ·
  summary below at [Invariants cheatsheet](#invariants-cheatsheet).
- **Something broken?** [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) —
  doctor / scope / Datasette symptom-to-fix playbook.

<a id="documentation-map"></a>
## Documentation map

| File | Audience | When to read | Primary |
| ---- | -------- | ------------ | ------- |
| [`../README.md`](../README.md) | humans | First time using drederick; quick start, features, flags. | human |
| [`../AGENTS.md`](../AGENTS.md) | agents | Any LLM session touching this repo. Invariants, commands, file→concept map, safety triggers. | agent |
| [`../.github/copilot-instructions.md`](../.github/copilot-instructions.md) | agents (Copilot) | GitHub Copilot sessions — vendor-specific mirror of `AGENTS.md`. | agent |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | humans + agents | Before non-trivial changes; layers, runners, enrichment, threading. | both |
| [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) | humans + agents | **Always, before touching scope/NSE/enrichment.** Hard guarantees. | both |
| [`MODULES.md`](MODULES.md) | humans + agents | Adding/changing a scanner; per-scanner contracts. | both |
| [`DEVELOPING.md`](DEVELOPING.md) | humans | Contributor quickstart, extension points, tests. | human |
| [`DATASETTE.md`](DATASETTE.md) | humans | Triaging findings in the current UI. | human |
| [`DB_SCHEMA.md`](DB_SCHEMA.md) | agents | Machine-readable schema, JOIN patterns, stable invariants. | agent |
| [`UI_GUIDE.md`](UI_GUIDE.md) | humans | Current vs planned UI; React dashboard design. | human |
| [`UI.md`](UI.md) | humans | Avalonia point-and-click operator console (`Drederick.UI`): quickstart, invariants, tests. | human |
| [`WEB_UI.md`](WEB_UI.md) | humans + operators | Browser-based operator pane (`Drederick.Web` + `web/` SPA): architecture, threat model, launch, surfaces. | human |
| [`COMPARISON.md`](COMPARISON.md) | humans | Drederick vs peers across three fronts: recon (AutoRecon / nmapAutomator / Reconnoitre), full-auto offensive (PentestGPT / HackingBuddyGPT / Metasploit Pro), and Jeopardy CTF solving (ctf-agent / EnIGMA / CAI). | human |
| [`GETTING_STARTED.md`](GETTING_STARTED.md) | humans | End-to-end first-run walkthrough. | human |
| [`CREDENTIALS.md`](CREDENTIALS.md) | humans + agents | Credential-attack subsystem: `CredRunner`, spray/brute/AS-REP/kerberoast/PtH, lockout throttling, secret-hashing rules. | both |
| [`LLM_SETUP.md`](LLM_SETUP.md) | humans | Wiring Copilot, Azure, or OpenAI for `--agent`; provider recipes; safety. | human |
| [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md) | humans + agents | Model behavior on authorized offsec work: compliance limits, Lame fight lesson, routing card, multi-model playbook, and benchmark fields. | agent |
| [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) | humans | After the session opens: `SessionManager`, `PostExLinux` / `PostExWindows`, pivot probes, Empire C2 agent dispatch, flag extraction, multi-stage chain. | human |
| [`EMPIRE.md`](EMPIRE.md) | operators | Empire C2 integration: agent types, platform-specific payload generation (PowerShell, Python, Bash), privilege escalation + lateral movement modules, operational patterns, troubleshooting. | human |
| [`C2_INTEGRATION.md`](C2_INTEGRATION.md) | contributors | C2 subsystem architecture: `EmpireAgentStager` / `EmpireModuleExecutor` / `EmpireApiClient` contracts, thread-safety, audit invariants, extension points for new C2 frameworks. | both |
| [`FUZZING.md`](FUZZING.md) | humans + agents | Fuzz subsystem: 10 `IFuzzTool`s (web-param, vhost, subdomain, api-endpoint, graphql, jwt, header, protocol, file-format, llm-payload), `FuzzToolbox` budgets, AdaptiveRunner scheduling. | both |
| [`JEOPARDY.md`](JEOPARDY.md) | humans | Jeopardy CTF mode: `ctf-solve` swarm, `ctf-msg` operator hints, sandbox image, budget/scope rails. | human |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | humans + agents | Symptom-to-fix: doctor detection, scope refusals, Datasette launch, NVD cache, PoC cache. | both |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | humans | Contributor workflow: branch, test, PR etiquette. | human |
| [`../SECURITY.md`](../SECURITY.md) | humans | Private security-bug reporting channel + disclosure posture. | human |
| [`../CHANGELOG.md`](../CHANGELOG.md) | humans | Release notes, breaking-change log. | human |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | humans | Community expectations for issues, PRs, discussions. | human |
| [`SELF_SUFFICIENCY.md`](SELF_SUFFICIENCY.md) | operators + contributors | Native-first architecture: what's built in vs what stays external, zero-dep recon mode, NuGet packages, performance gains, multi-tier roadmap. | both |
| [`PLUGIN_STRATEGY.md`](PLUGIN_STRATEGY.md) | contributors + agents | Patterns 1–4 of the self-sufficiency strategy: graceful enrichment, embedded community data, ported community logic, original Drederick tooling. | both |
| [`LEARNING_LOOP.md`](LEARNING_LOOP.md) | contributors + agents | Pattern 5 — self-improving feedback loop: fight telemetry, corpus, archetypes, planner self-tune, tool-forge. | both |

<a id="by-role"></a>
## By role

### Contributor

1. [`../README.md`](../README.md) — install and run a scan.
2. [`DEVELOPING.md`](DEVELOPING.md) — `make quickstart`, tests, conventions.
3. [`ARCHITECTURE.md`](ARCHITECTURE.md) — layers and thread-safety.
4. [`MODULES.md`](MODULES.md) — the scanner you're about to extend.
5. [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) — what your change **must not**
   weaken.

### Operator (CTF/lab user)

1. [`../README.md`](../README.md) — quick start + flags.
2. [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) — authorized-use posture + `--lab`
   semantics.
3. [`DATASETTE.md`](DATASETTE.md) — dashboard + PoC triage workflow.
4. [`UI_GUIDE.md`](UI_GUIDE.md) — what exists today (Datasette) vs planned.
5. [`LLM_SETUP.md`](LLM_SETUP.md) — turn on the cornerman; combine `--agent` with `--autopilot`.
6. [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md) — route models by fight data and cost, not vibes.
7. [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) — after the bell: session dispatch, Linux/Windows enumeration, pivot discovery, flag extraction.
8. [`JEOPARDY.md`](JEOPARDY.md) — Jeopardy CTF mode: `ctf-solve` swarm, mid-run `ctf-msg` hints, sandbox image.
9. [`COMPARISON.md`](COMPARISON.md) — when to pick drederick vs peers.

### Reviewer

1. [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) — hard guarantees first.
2. [`ARCHITECTURE.md`](ARCHITECTURE.md) — blast radius of the change.
3. [`MODULES.md`](MODULES.md) — scanner contract the PR claims to preserve.
4. [`DEVELOPING.md`](DEVELOPING.md) — tests required for new scanner/source.
5. [`DB_SCHEMA.md`](DB_SCHEMA.md) — if schema touched, verify invariants.

### LLM agent

1. [`../AGENTS.md`](../AGENTS.md) — the map.
2. [`SCOPE_AND_LEGAL.md#invariants`](SCOPE_AND_LEGAL.md#invariants) + the
   [cheatsheet below](#invariants-cheatsheet).
3. [`../AGENTS.md#safety-triggers`](../AGENTS.md#safety-triggers) — hard
   refusal list.
4. [`../AGENTS.md#file-concept-map`](../AGENTS.md#file-concept-map) —
   path → concept resolution.
5. [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md) — before touching LLM/model
   routing, prompts, hybrid fallback, or benchmark reporting.
6. [`DB_SCHEMA.md`](DB_SCHEMA.md) — queryable contract for `findings.db`.

<a id="invariants-cheatsheet"></a>
## Invariants cheatsheet

Depth: [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md). Stable ids:
[`../AGENTS.md#invariants`](../AGENTS.md#invariants).

- **Scope is enforced inside every tool** — `_scope.Require(target)` is the
  first statement of any network-touching method (recon, exploit, credential,
  payload).
- **Scope is the authorization boundary** — inside scope, Drederick
  executes exploits, runs credential attacks, delivers payloads, and
  handles post-exploitation. Outside scope, it does nothing.
- **Wildcards (`0.0.0.0/0`, `::/0`) are always refused** — even with
  `--allow-broad`.
- **Subprocess argv is validated** — every host/IP/URL in argv is
  resolved through `_scope.Require` before exec (nmap, `msfconsole -r`,
  `hydra`, `netexec`, cached PoCs, all of them).
- **PoC cache is verbatim** — no rewriting, no phone-home stripping, no
  sanitization. `ExploitRunner` spawns cached PoCs against scope-validated
  targets only.
- **LLM cannot escape scope** — LLM-exposed tools re-check scope internally;
  no prompt, jailbreak, or forged tool call disables this.
- **Audit is append-only** — every PoC fetch, PoC spawn, credential
  attempt, payload drop, and session open/close is recorded with target,
  tool, argv digest (SHA-256), and timestamp.
- **Plaintext secrets are never logged** — attempted passwords are
  recorded as SHA-256 digests only.
- **No exfiltration** — loot stays in `out/` and `audit.jsonl`. No
  telemetry, no cloud sync, no phone-home from the harness itself.
- **Destructive categories are opt-in per run** — `--allow-dos`,
  `--allow-destructive`, `--allow-exec-pocs`, `--allow-cred-attacks`,
  `--allow-payloads`, `--acknowledge-lockout-risk`. Defaults on in lab
  mode except `--allow-dos`; required explicitly in strict mode.
- **Doctor modifies the operator workstation only** — never scans a target,
  never re-execs as root.
- **`AuditLog` and `KnowledgeBase` are thread-safe** — everything else is
  stateless after construction.
- **There is no scope kill-switch** — no flag, env var, debug build, or
  prompt disables the scope check or the audit log.

<a id="conventions"></a>
## Conventions used in these docs

### Frontmatter schema

Every doc in `docs/` (and the root-level `AGENTS.md`) starts with a YAML
frontmatter block:

```yaml
---
title: <human-readable title>
audience: [humans, agents]          # one or both
primary: humans                     # or: agents
stability: stable | evolving | wip
last_audited: YYYY-MM
related:
  - docs/OTHER.md
  - ../AGENTS.md
---
```

- `stability: stable` — contract-grade; breaking changes require discussion.
- `stability: evolving` — expected to shift; don't cite it as the source of
  truth.
- `stability: wip` — placeholder/roadmap; treat as informational.

### Anchor convention

- **H2/H3 sections** carry either `{#kebab-case-id}` suffixes (GitHub-style
  auto-anchor augmented) or an `<a id="kebab-case-id"></a>` line immediately
  before the heading. Either is fine; both are crawled by GitHub.
- Once published, an anchor id is **stable**. Renames require a redirect
  comment (`<!-- moved from #old-id -->`) next to the new anchor.
- Invariant ids are of the form `@invariant-id:<short-slug>` and live in
  [`../AGENTS.md#invariants`](../AGENTS.md#invariants).

### `@agent:` marker blocks

Inside prose, LLM-only hints may be emitted as HTML comments:

```html
<!-- @agent:note
  Keep this scanner's subprocess args validated by AssertNoForbiddenScripts;
  any PR adding a new nmap script must also update the denylist tests.
-->
```

These are invisible to readers but greppable by agents. Do not rely on
them for information a human reviewer also needs.

### Tables vs prose

- **Invariants, commands, flag tables, schema columns, and FKs ALWAYS use
  tables.** Never re-describe them in prose.
- **Rationale, walkthroughs, and worked examples use prose.**
- If a section starts drifting into bullet+colon+description, convert it to
  a table.

### Cross-link convention

- Links between docs use relative paths (`DATASETTE.md`, `../AGENTS.md`),
  not absolute URLs.
- Links into code use repo-relative paths from the doc's directory (e.g.
  `../src/Drederick/Reporting/SqliteReport.cs` from `docs/`).
- Never hot-link to a line number; link to the file and, if specific,
  mention the symbol (`SqliteReport.EnsureSchema`).
