# Fight History Index

> Drederick's tape room. Review before developing, review before rematching.

---

## All Fights

| ID | Box | Date | Difficulty | Outcome | Key Gaps | Rematch? |
|----|-----|------|-----------|---------|----------|----------|
| [lame-2026-04-30](lame-2026-04-30.md) | Lame | 2026-04-30 | Easy | ❌ Loss | GAP-001,002,003 | ✅ Won on rematch |
| [lame-2026-04-30-rematch](lame-2026-04-30-rematch.md) | Lame | 2026-04-30 | Easy | ✅ Win (rematch) | — | — |
| [lame-model-benchmark](lame-model-benchmark-2026-04-30.md) | Lame | 2026-04-30 | Easy | 🏆 Benchmark (10W/4🚫/2❌) | — | — |

---

## Filters

### By Outcome

| Outcome | Count | Fights |
|---------|-------|--------|
| ❌ Loss | 1 | lame-2026-04-30 |
| ✅ Win | 1 | lame-2026-04-30-rematch |

### By Gap Type

| Gap Category | GAP IDs | Affected Fights |
|-------------|---------|-----------------|
| Exploit mapping | GAP-001 | lame-2026-04-30 |
| Exploit execution | GAP-002, GAP-005, GAP-006 | lame-2026-04-30 |
| Scanner reliability | GAP-003, GAP-007 | lame-2026-04-30 |
| Post-exploitation | GAP-004 | lame-2026-04-30 |
| Result accuracy | GAP-008, GAP-009 | lame-2026-04-30 |

### By Service

| Service | Fights | Best Outcome |
|---------|--------|-------------|
| Samba (SMB) | lame-2026-04-30, lame-2026-04-30-rematch | ✅ Win |
| vsftpd (FTP) | lame-2026-04-30, lame-2026-04-30-rematch | ✅ Win |
| OpenSSH (SSH) | lame-2026-04-30, lame-2026-04-30-rematch | ✅ Win |

---

## How to Use This Index

- **Before developing:** Check which gaps recur across multiple fights — prioritize those.
- **Before a rematch:** Read the fight brief for the box. Confirm the relevant gaps are resolved.
- **After a fight:** Add a row to the table, create a fight brief, and triage new gaps per [FIGHT_FEEDBACK.md](../FIGHT_FEEDBACK.md).
