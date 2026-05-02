# Fight History Index

> Drederick's tape room. Review before developing, review before rematching.

---

## All Fights

| ID | Box | Date | Difficulty | Outcome | Key Gaps | Rematch? |
|----|-----|------|-----------|---------|----------|----------|
| [lame-2026-04-30](lame-2026-04-30.md) | Lame | 2026-04-30 | Easy | ❌ Loss | GAP-001,002,003 | ✅ Won on rematch |
| [lame-2026-04-30-rematch](lame-2026-04-30-rematch.md) | Lame | 2026-04-30 | Easy | ✅ Win (rematch) | — | — |
| [lame-model-benchmark](lame-model-benchmark-2026-04-30.md) | Lame | 2026-04-30 | Easy | 🏆 Benchmark (10W/4🚫/2❌) | — | — |
| [jobtwo-2026-05-01](jobtwo-2026-05-01.md) | JobTwo | 2026-05-01 | Hard | ❌ Loss | GAP-001,002,010,011,012 | ⏳ Pending |
| [jobtwo-2026-05-01-rematch](jobtwo-2026-05-01-rematch.md) | JobTwo | 2026-05-01 | Hard | ❌ Loss (rematch) | GAP-022,024,025 | ⏳ Pending |
| [jobtwo-2026-05-01-r4](jobtwo-2026-05-01-r4.md) | JobTwo | 2026-05-01 | Hard | ❌ Loss-by-no-punch (r4) | GAP-026,027,028 | ⏳ Pending |
| [jobtwo-2026-05-02-r5](jobtwo-2026-05-02-r5.md) | JobTwo | 2026-05-02 | Hard | ❌ Loss (r5) — 30 sprays, 0 connects | GAP-029,030,031 (GAP-025 partial) | ⏳ Pending |
| [facts-2026-05-02 (R1)](facts-2026-05-02.md) | Facts | 2026-05-02 | Easy | ❌ Loss (R1) — cleanest tape, 6 min, 0 errors, 0 denials | GAP-032 | ⏳ Same-day rematch (R2) |
| [facts-2026-05-02 (R2)](facts-2026-05-02.md) | Facts | 2026-05-02 | Easy | ❌ Loss (R2) — 1611 events / 6 min, 31 CVEs, 1271 cve-leads slipped | GAP-032,033 (GAP-025 resolved) | ⏳ Pending |
| [facts-2026-05-02 (R3)](facts-2026-05-02-r3-r4.md) | Facts | 2026-05-02 | Easy | ❌ Loss (R3) — vhost fix firing, `http_probe` 35 calls, 640/640 cve-lead unfetchable | GAP-034, GAP-035 (GAP-032 ✅, GAP-033 ⚠️) | ⏳ Pending |
| [facts-2026-05-02 (R4)](facts-2026-05-02-r3-r4.md) | Facts | 2026-05-02 | Easy | ❌ Loss (R4) — 42 LLM calls / 1785 events (densest ever); operator caught flag manually off-harness | GAP-034, GAP-035 | ⏳ Pending |

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
