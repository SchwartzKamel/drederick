<!--
---
title: LEARNING_LOOP.md — How Drederick learns from each fight
audience: [contributors, operators, agents]
primary: contributors
stability: stable
last_audited: 2026-05
related:
  - docs/SELF_SUFFICIENCY.md
  - docs/PLUGIN_STRATEGY.md
  - docs/ARCHITECTURE.md
  - docs/FIGHTS.md
  - .github/fight-gaps.md
  - .github/fight-history/INDEX.md
---
-->

# The training arc — Drederick's learning loop

> "Between bouts, the champ studies the tape." Drederick records every action,
> reviews every fight, and tunes its own toolset before the next match.
> This doc describes the feedback loop architecture: what gets recorded,
> where it's stored, how reviews work, and how learnings feed back into
> tool selection, priorities, and even auto-generated tool scaffolds.
>
> **Looking for the fights themselves?** The tape room is surfaced in
> [`FIGHTS.md`](FIGHTS.md) — chronological roll call, lessons learned,
> and recurring patterns.

## TL;DR

| Phase | What happens | Where it's stored |
|---|---|---|
| During fight | Every action emits structured telemetry | `out/telemetry.db` (SQLite, per-run) |
| Post-fight | Operator commits engagement record | `~/HTB/fight-log.yaml` (schema v1, curated) |
| Between fights | `drederick review` analyzes history | `out/review.md`, `out/review.json` |
| Next fight | Tuned priorities + grown fingerprints + new tool scaffolds | `playbooks/*.yaml`, `memory/learned-fingerprints.json`, scaffolded `IReconTool`s |

<a id="record-stores"></a>
## The two record stores

Drederick reads from BOTH layers; neither is the source of truth alone.

### `~/HTB/` — curated engagement corpus (private)

- **`~/HTB/fight-log.yaml`** — structured, schema-versioned record of every engagement.
  - Schema v1 fields: `id, box, date, target_ip, difficulty, outcome, rematch_of, gaps_addressed[], delta, services_found[], vulns_identified[], exploits_attempted[]`.
  - Hand-curated by the operator after each engagement (drafts come from `drederick log-fight`).
  - This is the **long-term training corpus**.
- **`~/HTB/SCOREBOARD.md`** — human-readable W/L tracker referencing GAP-IDs.
- **`~/HTB/REMATCH_PROTOCOL.md`** — the rematch process Drederick follows when re-fighting a box.
- **`~/HTB/machines/<box>/`** — per-box folders with the operator's writeup, drafts, payloads, etc.

Intentionally a separate private git repo so engagement details (target IPs, captured creds, lab access) stay out of the public Drederick repo.

### `.github/` — public learning artifacts (in drederick repo)

- **`.github/fight-history/<box>-<date>.md`** — narrative writeups (Tatum-voiced).
- **`.github/fight-gaps.md`** — **canonical GAP-NNN registry**. The HTB SCOREBOARD references the same ID space.
- **`.github/fight-history/INDEX.md`** — chronological index of all fights.

### Discovery

The harness must work without `~/HTB/` present (Pattern 1: graceful enrichment).

- **`DREDERICK_FIGHT_CORPUS`** env var — explicit override.
- **`--fight-corpus <path>`** CLI flag — per-invocation override.
- Default: auto-detect `~/HTB/` if it exists; otherwise no-op.
- **Never auto-commits** to the corpus — it's operator-curated. `drederick log-fight` writes drafts; operator reviews + commits manually.

<a id="telemetry"></a>
## Telemetry — `out/telemetry.db`

Every fight produces a fine-grained telemetry trail.

### Schema (informal — formalize in `fight-telemetry` task)

```sql
CREATE TABLE telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                -- ISO 8601 UTC
    fight_id TEXT,                          -- correlates to fight-log.yaml id when known
    technique_id TEXT NOT NULL,             -- e.g. "nmap.scan", "smb.enum-shares", "msfrc.exploit/multi/samba/usermap_script"
    target_archetype TEXT,                  -- "htb-linux-easy", "htb-windows-ad", etc.
    target_host TEXT,                       -- redacted to first /24 if private
    service TEXT,                           -- "smb", "http", "snmp"
    port INTEGER,
    outcome TEXT NOT NULL CHECK(outcome IN ('success','fail','error','skipped')),
    time_ms INTEGER NOT NULL,
    llm_cost_tokens INTEGER,                -- for LLM-driven actions
    audit_correlation_id TEXT,              -- SHA-256 from audit.jsonl
    notes TEXT
);
CREATE INDEX idx_telemetry_archetype_technique ON telemetry_events(target_archetype, technique_id);
CREATE INDEX idx_telemetry_fight ON telemetry_events(fight_id);
```

### Why separate from `audit.jsonl`?

- `audit.jsonl` is the **immutable safety record** — every privileged action, append-only, never edited. It's the legal/audit log.
- `telemetry.db` is the **learning data** — analytics-friendly schema, queryable, can be vacuumed/aggregated.
- Both reference each other via `audit_correlation_id`.

<a id="review-workflow"></a>
## The review workflow

```bash
drederick review --since 2026-04-01
drederick review --fight lame-2026-04-30
drederick review --apply         # commits suggested priority changes
```

`drederick review` reads:

1. `out/telemetry.db` — recent runs (default: last 30 days).
2. `~/HTB/fight-log.yaml` — full curated history.
3. `.github/fight-history/*.md` — narrative writeups.
4. `.github/fight-gaps.md` — canonical GAP registry.

It produces:

- **`out/review.md`** — human-readable analysis: technique success rates per archetype, time-to-flag distributions, candidate gaps (with proposed GAP-NNN slots), priority adjustment suggestions, fingerprint candidates.
- **`out/review.json`** — machine-consumable for `--apply` automation.

### Sample review output

```markdown
# Drederick fight review — 2026-04-01 to 2026-05-01

## Scoreboard
- 5 fights: 3W / 2L (60%)
- 1 rematch (lame) — won

## Technique success rates by archetype

### htb-linux-easy
| Technique | Attempts | Success | Rate |
|---|---|---|---|
| msfrc/exploit/multi/samba/usermap_script | 2 | 2 | 100% |
| msfrc/auxiliary/scanner/ftp/ftp_version | 1 | 1 | 100% |
| nuclei (CVE-2007-2447) | 3 | 0 | 0%   ← waste, demote priority |

### htb-windows-ad
| Technique | Attempts | Success | Rate |
|---|---|---|---|
| (no fights yet) | | | |

## Suggested priority adjustments
- DEMOTE `nuclei` for samba services on htb-linux-easy (0/3 success rate)
- PROMOTE `msfrc` for samba services on htb-linux-easy (2/2 success rate)
  → run `drederick review --apply` to commit

## Candidate fingerprints
- Banner `Samba smbd 3.0.20-Debian` on port 445 → CPE `cpe:2.3:a:samba:samba:3.0.20`
  observed in 2/2 successful fights → propose adding to fingerprint-stack
```

<a id="self-tuning"></a>
## Self-tuning the planner

`ExploitationPlanner` priority bands learn from telemetry + corpus.

- Win rate boosts +50 priority.
- Budget-wasters (>3 attempts, 0 successes) get -100.
- Time-decayed (older data weighs less; recent fights dominate).
- Stored as overlay: `memory/learned-priorities.json` (operator can `git revert` if they hate the changes).
- Off by default in strict mode; opt-in via `--learn`.

<a id="fingerprint-growth"></a>
## Growing the fingerprint corpus

When the same banner+port consistently maps to the same product+version in winning fights, that mapping is added to `out/memory/learned-fingerprints.json` with a confidence score. The next fight's `fingerprint-stack` uses the grown corpus automatically.

> **Status: live as of commit `8251ab3`.** The store is implemented in
> [`src/Drederick/Enrichment/FingerprintStack/LearnedFingerprintStore.cs`](../src/Drederick/Enrichment/FingerprintStack/LearnedFingerprintStore.cs)
> and harvested by
> [`FingerprintLearner`](../src/Drederick/Enrichment/FingerprintStack/FingerprintLearner.cs).
> The memory layer therefore now has **two** persisted artefacts under `out/memory/`:
>
> - `findings.json` — the per-host
>   [`KnowledgeBase`](../src/Drederick/Memory/KnowledgeBase.cs) (services,
>   CVEs, captured creds, opened sessions). Cross-run state for a single
>   target.
> - `learned-fingerprints.json` — Server / TLS / SSH / SMB signal →
>   product + version mappings harvested across **every** fight and
>   reused as a confidence-weighted prior for `FingerprintAggregator`.
>   Cross-run, cross-target state.

Operator review: `drederick review` flags new fingerprint candidates with their confidence; operator can accept individually or `--apply --fingerprints`.

<a id="fight-notebook"></a>
## The fight notebook — append-only LLM journal

> **Status: live as of v0.4.0 (PR #13).** The notebook is the long-term
> *narrative* memory that complements the structured stores above. Where
> `findings.json` and `learned-fingerprints.json` capture *what was true
> on the wire*, the notebook captures *what the planner thought, what
> worked, what didn't, and what to try next time* — in operator-readable
> English.

### The pieces

| Piece | Path | Role |
|---|---|---|
| [`FightNote`](../src/Drederick/Learning/FightNote.cs) | record type | Typed note: `timestamp`, `fight_id`, `category`, `body`, `body_sha256`, `tags[]`, `target_host`, `target_archetype`, `source`. |
| [`FightNotebook`](../src/Drederick/Learning/FightNotebook.cs) | append-only writer | JSONL writer with secret redaction + `/24` host reduction; `SemaphoreSlim`-serialized writes, concurrent reads. |
| [`LlmNotebookTool`](../src/Drederick/Agent/LlmNotebookTool.cs) | `AIFunction` | Exposes `take_note` to the LLM via `LlmToolCatalog` → `MicrosoftAgentRunner` + `CopilotSdkAgentRunner`. |
| [`NotebookCommand`](../src/Drederick/Learning/Cli/NotebookCommand.cs) | operator reader | `drederick notebook [list\|tail\|show\|help]` — newest-first table or JSON dump. |

### Two sinks per note (both append-only)

- **`out/fight-notes.jsonl`** — per-fight notes alongside `report.json` /
  `audit.jsonl`. Scoped to the current run.
- **`~/.drederick/fight-notebook.jsonl`** — cross-fight aggregate. The
  operator's `drederick notebook list` reads both by default; pass
  `--notebook-no-aggregate` to scope to the current run only.

Neither file is ever rewritten. The notebook **survives across runs** so
reviews, replays, and fleet-wide learning can pull recent lessons
regardless of which engagement produced them.

### Categories (canonical, in `FightNoteCategory`)

`observation`, `tactic`, `gap`, `mistake`, `winning_move`, `lesson`,
`general`. Free-form strings accepted; unknown values are coerced to
`general`.

### Redaction policy — invariants

The notebook mirrors the same rules as `audit.jsonl`/`telemetry.db`. See
`FightNotebook.RedactSecrets`:

- **No plaintext secrets on disk.** Bodies are passed through a
  conservative regex stack before write — passwords, hashes, NT/LM
  pairs, PEM private keys, bearer tokens, JWTs, Basic-auth URLs, and
  high-entropy hex blobs (≥40 chars) are replaced with
  `[REDACTED:<kind>]` markers.
- **Host redaction.** `target_host` is reduced to `/24` (v4) or `/48`
  (v6) for RFC1918 / loopback / link-local — same path as
  `TelemetryRecorder.RedactHost`.
- **Audit shape.** Every `take_note` writes a `notebook.take_note` row
  to `audit.jsonl` carrying `body_sha256` only — never the body. The
  SHA-256 is computed against the *redacted* body so it correlates
  cleanly across runs.
- **The model should not paste secrets in the first place.** The
  `take_note` tool description tells it so. Redaction is a backstop, not
  an excuse.

### Operator review — `drederick notebook`

```bash
# Newest 50 notes from per-run + cross-fight aggregate.
drederick notebook list

# Filter by category.
drederick notebook list --notebook-category lesson
drederick notebook list --notebook-category mistake
drederick notebook list --notebook-category winning_move

# Filter by tag (repeatable; any-match).
drederick notebook list --notebook-tag smb --notebook-tag GAP-046

# Just the current run (no aggregate).
drederick notebook tail

# Skip the cross-fight file even on `list`.
drederick notebook list --notebook-no-aggregate

# Bump the result cap (default 50).
drederick notebook list --notebook-limit 200

# JSON dump — pipe into review tooling.
drederick notebook show --notebook-category gap | jq '.[] | {ts: .timestamp, body}'
```

Render shape (newest-first):

```text
- [2026-05-12T14:22:01] mistake  (10.10.11.0/24)  [smb, GAP-046]
    Tried evil-winrm before confirming RID brute had landed. Wasted budget;
    next time gate WinRM auth on a known-valid (user, hash) tuple.
```

### How notes feed forward

> **Today (v0.4.0):** notes are persisted, redacted, and reviewable via
> `drederick notebook`. They are wired into the LLM agents through
> `LlmNotebookTool` so the model can **write** notes mid-fight.
>
> **TODO — replay into next-fight prompts.** Wiring the notebook *back*
> into the system prompt of subsequent runs (so the LLM reads recent
> `lesson` / `winning_move` / `mistake` entries before planning) is on
> the roadmap but not yet shipped. Tracked alongside `planner-self-tune`
> and the archetype-playbook overlay. Until then the operator is the
> replay channel: read with `drederick notebook list --notebook-category
> lesson` between fights and feed the relevant lessons forward by hand or
> via `--prompt-prefix`.

The downstream consumers in scope when that lands:

1. `MicrosoftAgentRunner` / `CopilotSdkAgentRunner` system prompt — load
   the most recent N notes for the matching `target_archetype` /
   matching tag set.
2. `drederick review` — group notes by category, surface recurring
   `mistake` patterns next to the technique-success-rate tables.
3. `tool-forge` — `gap`-category notes are first-class signal for new
   tool scaffolds.

### See also

- [`FIGHTS.md` § post-fight notebook review](FIGHTS.md#fight-notebook) —
  what to look for between bouts.
- [`MODEL_BEHAVIOR.md` § take_note prompt guidance](MODEL_BEHAVIOR.md#take-note) —
  when the model should commit a note.

<a id="archetype-playbooks"></a>
## Archetype playbooks

> **Status: classifier live as of commit `fd8e8a2`.** The
> [`TargetArchetype`](../src/Drederick/Learning/TargetArchetype.cs)
> enum and
> [`ArchetypeClassifier`](../src/Drederick/Learning/ArchetypeClassifier.cs)
> tag every fight target so the planner can load the right playbook
> overlay before action selection. Hand-curated YAML lives under
> `playbooks/`; learned overlays from `planner-self-tune` are layered
> on top.

```bash
drederick warmup --archetype htb-linux-easy
drederick warmup --archetype htb-windows-ad
```

Each archetype has a YAML playbook in `playbooks/<archetype>.yaml`:

```yaml
archetype: htb-linux-easy
priority_overlay:
  msfrc/exploit/multi/samba/usermap_script: +200
  smb.enum-shares: +50
  nuclei: -50
warmup_actions:
  - smb.enum-shares
  - ftp.banner
  - http.title
budget:
  llm_tokens: 5000
  exploit_attempts: 20
  total_minutes: 15
```

Hand-curated baseline + learned overlays from `planner-self-tune`. Operator-editable.

<a id="tool-forge"></a>
## The tool forge

When the operator (or LLM) identifies a new technique pattern in fight history that isn't covered by an existing tool:

```bash
drederick forge --from jobtwo-2026-05-01 --pattern "exiftool-cve-injection"
```

Generates a scaffold:
- `src/Drederick/Recon/ExiftoolCveInjectionTool.cs` — IReconTool stub with scope/audit boilerplate, ready to fill in.
- `tests/Drederick.Tests/Recon/ExiftoolCveInjectionToolTests.cs` — test stubs (scope rejection, fixture parse).
- DI wiring snippet in a comment block (operator copies into Program.cs under the right anchor).

Operator (or LLM, in autopilot mode) fills in the body. The scaffold ensures invariants are followed by default — every native tool starts the same way.

This closes the loop: Drederick observes, proposes, scaffolds — and over time, builds its own toolset shaped by its actual fights.

<a id="end-to-end"></a>
## End-to-end diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ DURING FIGHT                                                     │
│   recon/exploit/post-ex actions → TelemetryRecorder              │
│                                  → out/telemetry.db (per-run)    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ POST-FIGHT                                                       │
│   drederick log-fight → FightCorpusWriter drafts:                │
│     • ~/HTB/fight-log.yaml entry (schema v1)                     │
│     • ~/HTB/machines/<box>/<date>-drederick-draft.md             │
│   operator reviews + commits to private corpus                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ BETWEEN FIGHTS — drederick review                                │
│   FightReviewer reads:                                           │
│     • out/telemetry.db (recent runs)                             │
│     • ~/HTB/fight-log.yaml (curated history, all-time)           │
│     • .github/fight-history/*.md (narrative writeups)            │
│     • .github/fight-gaps.md (canonical GAP registry)             │
│   produces:                                                      │
│     • out/review.md (operator reading)                           │
│     • out/review.json (machine-consumable)                       │
│     • candidate priority adjustments → planner-self-tune         │
│     • candidate fingerprints → fingerprint-grow                  │
│     • candidate gaps → suggest GAP-NNN entries                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ NEXT FIGHT                                                       │
│   ArchetypeClassifier tags target → archetype-playbook loads     │
│   tuned priorities → ExploitationPlanner uses learned bands      │
│   FingerprintStack uses grown corpus                             │
│   tool-forge has produced scaffolds for new technique patterns   │
└─────────────────────────────────────────────────────────────────┘
```

Each match leaves Drederick stronger.

<a id="invariants"></a>
## Invariants — what the learning loop must NOT do

- **Never bypass scope**: a learned playbook is still subject to `_scope.Require`. Learning a winning technique on box A does not authorize running it on box B.
- **Never auto-commit private corpus**: `~/HTB/` is operator-curated. Drederick drafts entries; the operator commits.
- **Never auto-apply priority changes in strict mode**: `--learn` flag is opt-in; strict-mode runs use baseline priorities.
- **Never elevate budget without operator consent**: `archetype-playbook` budgets are an upper bound, not a starting bid.
- **Never log plaintext secrets in telemetry**: same rule as `audit.jsonl` — SHA-256 of credential pairs only.
- **Never log plaintext secrets in the fight notebook**: bodies are run through `FightNotebook.RedactSecrets` before disk; the `take_note` tool description forbids pasting credentials in the first place. Audit records carry `body_sha256` only.
- **Never drift schema silently**: `fight-log.yaml` schema version is checked on load; mismatches fail with a clear migration message.

<a id="see-also"></a>
## See also

- [SELF_SUFFICIENCY.md](SELF_SUFFICIENCY.md)
- [PLUGIN_STRATEGY.md](PLUGIN_STRATEGY.md) — patterns 1–4
- [ARCHITECTURE.md](ARCHITECTURE.md) — `AutopilotRunner` is the autopilot loop that consumes the learned priorities
- [.github/fight-gaps.md](../.github/fight-gaps.md) — canonical GAP registry
- [.github/fight-history/INDEX.md](../.github/fight-history/INDEX.md) — chronological fight index
