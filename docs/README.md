---
title: Documentation index
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - ../README.md
  - ../AGENTS.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
  - DEVELOPING.md
  - MODULES.md
  - DATASETTE.md
  - DB_SCHEMA.md
  - UI.md
  - UI_GUIDE.md
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
| [`COMPARISON.md`](COMPARISON.md) | humans | Choosing between drederick / AutoRecon / nmapAutomator / Reconnoitre. | human |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | humans + agents | Symptom-to-fix: doctor detection, scope refusals, Datasette launch, NVD cache, PoC cache. | both |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | humans | Contributor workflow: branch, test, PR etiquette. | human |
| [`../SECURITY.md`](../SECURITY.md) | humans | Private security-bug reporting channel + disclosure posture. | human |
| [`../CHANGELOG.md`](../CHANGELOG.md) | humans | Release notes, breaking-change log. | human |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | humans | Community expectations for issues, PRs, discussions. | human |

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
5. [`COMPARISON.md`](COMPARISON.md) — when to pick drederick vs peers.

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
5. [`DB_SCHEMA.md`](DB_SCHEMA.md) — queryable contract for `findings.db`.

<a id="invariants-cheatsheet"></a>
## Invariants cheatsheet

Depth: [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md). Stable ids:
[`../AGENTS.md#invariants`](../AGENTS.md#invariants).

- **Scope is enforced inside every tool** — `_scope.Require(target)` is the
  first statement of any network-touching method.
- **Wildcards (`0.0.0.0/0`, `::/0`) are always refused** — even with
  `--allow-broad`.
- **NSE categories `exploit`/`intrusive`/`brute`/`vuln`/`dos`/`malware` are
  hard-coded excluded** in lab and strict modes.
- **Aggregate + present, never execute** — PoCs are cached verbatim with
  SHA-256 provenance; never chmod'd, never spawned, never phoned home for.
- **No credential attacks** — no brute force, spray, AS-REP roast,
  kerberoast, dictionary. SPN listing is anonymous-bind read only.
- **No payload delivery** — no shells, implants, webshells, persistence.
- **LLM cannot escape scope** — `MicrosoftAgentRunner` tools re-check scope
  internally; no prompt disables this.
- **Doctor modifies the operator workstation only** — never scans a target,
  never re-execs as root.
- **`AuditLog` and `KnowledgeBase` are thread-safe** — everything else is
  stateless after construction.
- **There is no scope kill-switch** — no flag, env var, debug build, or
  prompt disables the scope check.

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
