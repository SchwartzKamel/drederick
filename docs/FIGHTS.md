<!--
---
title: FIGHTS.md — The tape room, surfaced
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-05
related:
  - .github/fight-history/INDEX.md
  - .github/fight-gaps.md
  - docs/LEARNING_LOOP.md
  - docs/SELF_SUFFICIENCY.md
---
-->

# Fights — the tape room, surfaced

> "And now, ladies and gentlemen, between bouts the champ studies the tape."

Every authorized engagement Drederick walks into gets recorded. Wins, losses,
losses-by-no-punch, model benchmarks — all of it. The canonical tapes live
under [`.github/fight-history/`](../.github/fight-history/) (the tape room);
this doc is the **reading room** — a docs-side synthesis so contributors,
operators, and agents can find the lessons without spelunking through
`.github/`.

If you want the raw chronological log, jump to
[`.github/fight-history/INDEX.md`](../.github/fight-history/INDEX.md).
If you want the gap registry that fights feed, jump to
[`.github/fight-gaps.md`](../.github/fight-gaps.md).
If you want the architecture of the feedback loop, jump to
[`LEARNING_LOOP.md`](LEARNING_LOOP.md).

---

## How to read this room

Every fight produces three artifacts:

| Artifact | Path | Audience |
| -------- | ---- | -------- |
| **Tape** (Tatum-voiced narrative writeup) | `.github/fight-history/<box>-<date>[-<round>].md` | humans + agents |
| **Log entry** (structured YAML record) | `~/HTB/fight-log.yaml` (operator-curated, not in repo) | operator |
| **Gap entries** (registry deltas) | `.github/fight-gaps.md` (`GAP-NNN`) | contributors |

The tape is the story. The log is the schema. The gaps are the work.
Read tapes for context; mine gaps for tasks.

---

## Roll call (chronological)

| # | Box | Difficulty | Date | Outcome | Tape | New gaps |
|---|-----|-----------|------|---------|------|----------|
| 1 | Lame | Easy | 2026-04-30 | ❌ Loss (R1) | [tape](../.github/fight-history/lame-2026-04-30.md) | GAP-001..009 |
| 2 | Lame | Easy | 2026-04-30 | ✅ Win (rematch) | [tape](../.github/fight-history/lame-2026-04-30-rematch.md) | — |
| 3 | Lame | Easy | 2026-04-30 | 🏆 Benchmark (10W / 4🚫 / 2❌) | [tape](../.github/fight-history/lame-model-benchmark-2026-04-30.md) | model routing card |
| 4 | JobTwo | Hard | 2026-05-01 | ❌ Loss (R1) | [tape](../.github/fight-history/jobtwo-2026-05-01.md) | GAP-010..012 |
| 5 | JobTwo | Hard | 2026-05-01 | ❌ Loss (rematch) | [tape](../.github/fight-history/jobtwo-2026-05-01-rematch.md) | GAP-022, 024, 025 |
| 6 | JobTwo | Hard | 2026-05-01 | ❌ Loss-by-no-punch (R4) | [tape](../.github/fight-history/jobtwo-2026-05-01-r4.md) | GAP-026..028 |
| 7 | JobTwo | Hard | 2026-05-02 | ❌ Loss (R5) — 30 sprays / 0 connects | [tape](../.github/fight-history/jobtwo-2026-05-02-r5.md) | GAP-029..031 |
| 8 | Facts | Easy | 2026-05-02 | ❌ Loss (R1+R2) | [tape](../.github/fight-history/facts-2026-05-02.md) | GAP-032, 033 |
| 9 | Facts | Easy | 2026-05-02 | ❌ Loss (R3+R4) — vhost fix firing, 640/640 cve-leads unfetchable | [tape](../.github/fight-history/facts-2026-05-02-r3-r4.md) | GAP-034, 035 |
| 10 | Facts | Easy | 2026-05-02 | ✅ **Win (R5, Copilot-driver)** — both flags | _pending tape_ | GAP-036..041 |
| 11 | Pingpong | — | 2026-05-02 | ⏳ In-flight | _pending tape_ | _pending_ |

> **R5 on Facts is the breakthrough fight.** Copilot CLI drove drederick as a
> tool and finished the chain in 11 steps: register → CVE-2025-2304
> mass-assignment → CVE-2026-1776 path traversal → SQLite pillage →
> S3/MinIO bucket raid → ed25519 SSH key → paramiko brute → user shell →
> `sudo facter --custom-dir` → root. The "no training wheels" arc is about
> teaching autopilot to do that on its own.

---

## What the tapes have taught us

### Lame (Easy, Linux) — the first arc

R1 lost to a tool-mapping miss (Samba `usermap_script` was visible but never
fired). Rematch won after wiring exploit selection to fingerprint hits.
Then the **model benchmark** fight ran the same box across the model fleet:
10 wins, 4 outright refusals (compliance), 2 stalls. Drove the routing card
in [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md).

**Lessons that landed:** scope-validated subprocess argv, exploit→fingerprint
mapping, model routing by compliance posture.

### JobTwo (Hard, Linux) — the long grind

Five rounds, five losses. Each round closed a class of gap and exposed a new
one. R5 is the canonical "30 sprays, 0 connects" tape — every spray attempt
hit a closed/filtered service because vhost-aware routing wasn't in the
exploit side yet (gap-032b, in flight as of this writing).

**Lessons that landed:** stop-on-detection rails, evidence-chain audit,
vhost-aware exploitation (in flight).

### Facts (Easy, Linux) — the breakthrough

Five rounds. R1+R2 lost to vhost-blind HTTP probing (Host header missing).
R3+R4 ran with the `gap-032` fix in production — http_probe usage went
0 → 35 → 48 across the rounds, the densest fights ever recorded. Both still
lost: 640/640 cve-leads were unfetchable because the on-demand PoC source
fleet (gap-031b-2) wasn't shipped yet.

**R5 won via Copilot-driver.** The win exposed six new gaps that, when
shipped together, are the path to autopilot taking facts-class boxes solo:

| Gap | What | Status |
|-----|------|--------|
| GAP-036 | CMS fingerprint (CameleonCMS, etc.) as IReconTool | pending |
| GAP-037 | MinIO / S3 service prober | in flight |
| GAP-038 | SQLite credential pillage (auto-mine `cama_metas` / `wp_options` / `auth_user`) | in flight |
| GAP-039 | SSH key passphrase brute (paramiko-style) | pending |
| GAP-040 | `sudo -l` + GTFOBins privesc lookup | pending |
| GAP-041 | CMS chain templates (depends on GAP-036) | pending |

### Pingpong — the next box

In-flight as of 2026-05-02. Tape pending.

---

## Recurring patterns (mine these first)

These are the categories that keep showing up across multiple fights. If
you're picking up a contribution and don't know where to start, start here:

1. **Scope-aware HTTP** — Host header, vhost detection, hostname → IP resolve
   with scope-validation on the resolved IP. The single most-reused pattern.
   See `Recon/HttpProbeTool.cs` for the canonical shape (gap-032).
2. **On-demand PoC fetch** — when CVE-leads land but no cached PoC matches,
   fetch from Metasploit / nuclei-templates / PoC-in-GitHub before giving
   up. See `Enrichment/*GitSource.cs` (gap-031b-2 in flight).
3. **Post-ex pillage** — every shell, every file disclosure, every captured
   DB is a credential vending machine. Auto-mine.
4. **LLM exec_shell** — the load-bearing primitive that turned drederick
   from a recon tool into an offensive harness in the Copilot-driver win.
   See `Exploit/LlmExecShellTool.cs` (in flight).
5. **Vhost-aware exploit side** — same shape as gap-032 but for spray /
   exploit / payload tools. See `Exploit/NativeHttpSprayTool.cs`
   (gap-032b in flight).

---

## Adding a tape

The full procedure lives in [`LEARNING_LOOP.md`](LEARNING_LOOP.md).
Quick version:

1. After the fight: `drederick log-fight` writes a YAML draft (operator
   reviews + commits to `~/HTB/fight-log.yaml` — out-of-repo).
2. Author a Tatum-voiced tape under `.github/fight-history/<box>-<date>[-<round>].md`.
   Read existing tapes for tone (formal grammar on violent verbs, ring-announcer
   cadence, scope/audit = "governing body", no profanity).
3. Add a row to [`INDEX.md`](../.github/fight-history/INDEX.md).
4. Add a row to the **Roll call** table above (this file).
5. File new gaps in [`fight-gaps.md`](../.github/fight-gaps.md) as `GAP-NNN`.

---

## See also

- [`LEARNING_LOOP.md`](LEARNING_LOOP.md) — the architecture this room feeds.
- [`SELF_SUFFICIENCY.md`](SELF_SUFFICIENCY.md) — the "no training wheels" goal.
- [`MODEL_BEHAVIOR.md`](MODEL_BEHAVIOR.md) — what the model benchmark fight produced.
- [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) — the layer R5-copilot exercised hardest.
- [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) — the governing body. Read before every bout.
