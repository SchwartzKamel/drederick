# Drederick — Fight Feedback Loop

> How fight results feed back into development. Every engagement is a
> training round — gaps found in the ring drive the next development cycle.

---

## The Feedback Loop

```
 ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
 │  1. FIGHT   │────▶│  2. TRIAGE   │────▶│  3. DEVELOP  │
 │  Run engage │     │  ID + score  │     │  Fix gaps    │
 └─────────────┘     │  gaps        │     └──────┬───────┘
       ▲             └──────────────┘            │
       │                                         │
 ┌─────┴─────────┐                     ┌─────────▼──────┐
 │  5. CLOSE     │◀────────────────────│  4. REMATCH    │
 │  Update docs  │                     │  Re-run box    │
 └───────────────┘                     └────────────────┘
```

---

## Step 1: Fight — Run an Engagement

After every engagement against an HTB machine (or real target):

1. **Run drederick** against the target as normal
2. **Generate a fight-log entry** in the engagement directory:
   - File: `~/HTB/machines/<box>/fight-log.md`
   - Records: timeline, tools used, findings, what worked, what didn't
3. **Generate a gaps analysis**:
   - File: `~/HTB/machines/<box>/drederick-gaps.md`
   - Documents every capability gap that prevented full automation

### Naming Convention

Fights are identified as `<box>-<date>`:
- `lame-2026-04-30` — first engagement against Lame
- `lame-2026-05-15` — rematch after fixes

---

## Step 2: Triage — Assign IDs and Severity

After generating the gaps analysis:

1. **Open** `~/tools/drederick/.github/fight-gaps.md`
2. **Check for duplicates** — does the gap match an existing GAP-NNN entry?
   - If yes: add the new fight to the "Exposed by" list
   - If no: assign the next available GAP-NNN ID
3. **Assign severity:**
   - **critical** — Prevents exploitation of a known-vulnerable target
   - **high** — Significant capability missing but workarounds exist
   - **medium** — Inefficiency or reliability issue
   - **low** — Nice-to-have improvement
4. **Update the statistics table** at the bottom of fight-gaps.md
5. **Log the triage** in the changelog section

---

## Step 3: Develop — Fix the Gaps

When working on gap fixes:

1. **Reference GAP-IDs** in all commits and PRs:
   ```
   fix(planner): add version-to-exploit lookup table

   Adds a curated mapping of service fingerprints to Metasploit modules,
   nuclei templates, and standalone PoCs. The planner now generates
   exploit actions when high-confidence version matches are found.

   Addresses: GAP-001
   ```

2. **Update gap status** to `in-progress` in fight-gaps.md when work begins
3. **Group related gaps** into logical PRs — e.g., GAP-001 + GAP-002 + GAP-006
   naturally form an "exploit execution pipeline" PR

---

## Step 4: Rematch — Validate the Fixes

After fixing one or more gaps:

1. **Re-run drederick** against the same box that exposed the gap
2. **Compare results** to the original fight-log:
   - Did the gap behavior disappear?
   - Did drederick get further in the kill chain?
   - Any new gaps exposed?
3. **Generate a new fight-log entry** with the rematch date
4. **Generate a new gaps analysis** — this should show fewer gaps

---

## Step 5: Close the Loop — Update Tracking

After a successful rematch:

1. **Update fight-gaps.md:**
   - Set status to `resolved`
   - Fill in the "Resolution" field with what was done and which commit/PR fixed it
   - Update the statistics table
2. **Update the fight-log** with rematch results and link to the original
3. **If new gaps emerged**, go back to Step 2 and triage them

---

## Quick Reference

### File Locations

| File | Path | Purpose |
|------|------|---------|
| Fight gaps tracker | `~/tools/drederick/.github/fight-gaps.md` | Aggregated gaps across all fights |
| Feedback process | `~/tools/drederick/.github/FIGHT_FEEDBACK.md` | This document |
| Copilot instructions | `~/tools/drederick/.github/copilot-instructions.md` | AI coding assistant context |
| Engagement directory | `~/HTB/machines/<box>/` | Per-box engagement data |
| Fight log | `~/HTB/machines/<box>/fight-log.md` | Per-box fight timeline and results |
| Gaps analysis | `~/HTB/machines/<box>/drederick-gaps.md` | Per-box gap identification |

### Workflow Commands

```bash
# After an engagement — triage new gaps
cd ~/tools/drederick
# Review the gaps analysis from the fight
cat ~/HTB/machines/<box>/drederick-gaps.md

# Edit the aggregated tracker to add/update gaps
$EDITOR .github/fight-gaps.md

# During development — reference gap IDs in commits
git commit -m "fix(scanner): crash-resilient nmap fallback chain

Addresses: GAP-003"

# Before a rematch — check which gaps are marked resolved
grep -E "^- \*\*Status:\*\*" .github/fight-gaps.md

# After a rematch — update resolved gaps
$EDITOR .github/fight-gaps.md
```

### Severity Guide

| Severity | Criteria | Example |
|----------|----------|---------|
| critical | Prevents exploitation of a known-vulnerable target | Can't fire exploits despite fingerprinting vulnerable versions |
| high | Major capability gap, workarounds may exist | No post-exploitation loot collection |
| medium | Reliability or efficiency issue | Runner repeats crashing commands |
| low | Enhancement or polish | Automated HTB flag submission |

### Gap ID Format

- IDs are sequential: `GAP-001`, `GAP-002`, ..., `GAP-NNN`
- IDs are **stable** — never reused or renumbered
- A resolved gap keeps its ID forever
