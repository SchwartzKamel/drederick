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
  - docs/AUTOPILOT.md
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

When the same banner+port consistently maps to the same product+version in winning fights, that mapping is added to `memory/learned-fingerprints.json` with a confidence score. The next fight's `fingerprint-stack` uses the grown corpus automatically.

Operator review: `drederick review` flags new fingerprint candidates with their confidence; operator can accept individually or `--apply --fingerprints`.

<a id="archetype-playbooks"></a>
## Archetype playbooks

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
- **Never drift schema silently**: `fight-log.yaml` schema version is checked on load; mismatches fail with a clear migration message.

<a id="see-also"></a>
## See also

- [SELF_SUFFICIENCY.md](SELF_SUFFICIENCY.md)
- [PLUGIN_STRATEGY.md](PLUGIN_STRATEGY.md) — patterns 1–4
- [AUTOPILOT.md](AUTOPILOT.md) — the autopilot runner that consumes the learned priorities
- [.github/fight-gaps.md](../.github/fight-gaps.md) — canonical GAP registry
- [.github/fight-history/INDEX.md](../.github/fight-history/INDEX.md) — chronological fight index
