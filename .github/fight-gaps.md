# Drederick — Fight Gaps Tracker

> Aggregated from HTB engagements. Each gap links back to the fight(s)
> that exposed it and tracks resolution status.
>
> **Usage:** After each engagement, append new gaps with the next available
> GAP-NNN ID. Reference GAP-IDs in commits and PRs when fixing issues.
> Update status and resolution notes when work is completed.

---

## Critical Gaps

### GAP-001: Version-to-Exploit Module Mapping
- **Exposed by:** lame-2026-04-30
- **Severity:** critical
- **Impact:** Autopilot can't fire exploits for known-vulnerable versions — fight plan had `nuclei=0, msfrc=0` despite fingerprinting Samba 3.0.20 and vsftpd 2.3.4
- **Status:** workaround
- **Description:** No version→exploit lookup table exists. The planner doesn't cross-reference service fingerprints against known exploit modules (Metasploit, nuclei, standalone PoCs). Version-exact matches on known-RCE modules should rank higher than password spraying, but currently no exploit actions are generated at all.
- **Suggested fix:** Build a curated version→exploit catalog mapping service fingerprints to Metasploit modules, nuclei templates, and standalone PoCs. Integrate into the planner so high-confidence version matches generate exploit actions with priority above spray (currently 200).
- **Resolution:** Copilot fills this gap as human-in-the-loop; drederick code still needs the fix for autonomous operation. (lame-2026-04-30-rematch)

### GAP-002: Metasploit RC Generation and Execution
- **Exposed by:** lame-2026-04-30
- **Severity:** critical
- **Impact:** The `msf-rc` tool is wired into the exploit toolbox (7 tools ready) but was never invoked — no exploit was ever attempted
- **Status:** workaround
- **Description:** Autopilot doesn't generate `.rc` scripts for high-confidence exploits. After a shell lands, there's no logic to detect shell type (root vs user), grab flags, record loot, or queue privesc. The `sessions` table and `session.manager.ready` event exist but aren't wired to Metasploit session callbacks.
- **Suggested fix:** Generate `.rc` files for high-confidence exploits (e.g., `use exploit/multi/samba/usermap_script` with appropriate RHOSTS/LHOST/PAYLOAD). Wire session callbacks to detect shell type, grab flags from standard locations, record loot in `findings.db`, and queue privesc if user-level.
- **Resolution:** Copilot fills this gap as human-in-the-loop; drederick code still needs the fix for autonomous operation. (lame-2026-04-30-rematch)

### GAP-003: Crash-Resilient Nmap Scanning
- **Exposed by:** lame-2026-04-30
- **Severity:** critical
- **Impact:** nmap 7.98 `auth` and `intrusive` NSE categories crash with SIGABRT (exit 134), causing drederick to report "no open ports" — total recon failure
- **Status:** open
- **Description:** No crash detection or fallback logic. When nmap crashes, all port results are lost. Port 3632 (distccd) was missed entirely because the full-port scan never completed. Port discovery and script scanning aren't separated.
- **Suggested fix:** Implement a fallback chain: full scripts → drop auth+intrusive → safe+default → `-sV` only. Separate port discovery (`-sS`/`-sT` port-only) from script scanning (per-port). Parse partial XML output from crashed scans. Ensure full-port scan (`-p 1-65535`) completes before the adaptive runner gives up.
- **Resolution:**

---

## High Gaps

### GAP-004: Post-Exploitation Loot Collection
- **Exposed by:** lame-2026-04-30
- **Severity:** high
- **Impact:** Even if a shell were established, no automated loot collection occurs — flags, credentials, and pivot data are all missed
- **Status:** open
- **Description:** No post-exploitation playbook exists. Missing: whoami/id for privilege level, flag file reads, /etc/shadow dump and hash cracking, SSH key harvesting, internal network enumeration for pivoting. Loot table exists but nothing populates it.
- **Suggested fix:** Build an auto-running post-exploitation playbook for new sessions: record privilege level, grab flags (`/root/root.txt`, `/home/*/user.txt`), dump credentials, harvest SSH keys, enumerate internal networks. Store structured loot in the existing `loot` table with type/path/content-hash/session metadata.
- **Resolution:**

### GAP-005: Standalone PoC Execution
- **Exposed by:** lame-2026-04-30
- **Severity:** high
- **Impact:** Many CTF/real-world exploits lack Metasploit modules — without standalone PoC execution, entire exploit classes are unreachable
- **Status:** open
- **Description:** The `--allow-exec-pocs` flag exists but no PoCs were fetched or executed. No integration with ExploitDB/searchsploit (detected but unused), GitHub PoC repos, or custom scripts. No PoC sandbox for safety review.
- **Suggested fix:** Integrate with ExploitDB/searchsploit and GitHub PoC repos. Build a PoC execution sandbox: fetch based on CVE/service match, review for safety (block destructive ops unless `--allow-destructive`), set up listener if needed, execute with scope-validated target, capture output and detect shells.
- **Resolution:**

### GAP-006: LLM-Guided Exploit Planning
- **Exposed by:** lame-2026-04-30
- **Severity:** high
- **Impact:** LLM exploit planning is partially wired (`llm.exploit_tools.ready` fires with count=7) but never produces exploit actions — only sprays
- **Status:** open
- **Description:** When the autopilot has version fingerprints and CVE data, it doesn't query the LLM to generate prioritized exploit plans. The LLM could produce actionable exploit actions (RHOSTS, LHOST, PAYLOAD) ranked higher than credential spraying, but this path is never taken.
- **Suggested fix:** When version fingerprints + CVE data are available, prompt the LLM with service/version/CVE context and available tools to generate a prioritized exploit plan. Execute plans round-by-round with higher priority than credential spraying.
- **Resolution:**

---

## Medium Gaps

### GAP-007: Failure-Aware Adaptive Runner
- **Exposed by:** lame-2026-04-30
- **Severity:** medium
- **Impact:** Runner repeats crashing invocations verbatim instead of learning from failures — wastes cycles and delays results
- **Status:** open
- **Description:** When nmap crashed (exit 134), the runner logged "no ports on first pass; widening" and retried with identical crashing arguments. No failure-aware adaptation, no partial result extraction from crashed scans, no parallel lightweight probes as fallback.
- **Suggested fix:** Don't repeat failed invocations — reduce aggressiveness on retry. Parse partial XML from crashed nmap scans (nmap streams results). Fire parallel quick TCP connect probes (or masscan/rustscan) to known-interesting ports while heavy scans run.
- **Resolution:**

### GAP-008: False-Positive Flag Filtering
- **Exposed by:** lame-2026-04-30
- **Severity:** medium
- **Impact:** 12 "knockouts" were false positives — Vulners exploit pack IDs matching the flag regex, polluting results
- **Status:** open
- **Description:** Flag detection matches hex strings inside URLs, JSON keys, and known tool output formats (Vulners IDs, GUID segments). No context-aware filtering or source prioritization. No HTB API validation of candidate flags.
- **Suggested fix:** Context-aware flag filtering: exclude hex strings inside URLs, JSON keys, and known tool output formats. Prioritize flags from shell output and file reads over scan metadata. If an HTB API token is available, validate candidate flags before recording as knockouts.
- **Resolution:**

---

## Low Gaps

### GAP-009: HTB Flag Submission and Validation
- **Exposed by:** lame-2026-04-30
- **Severity:** low
- **Impact:** No automated flag submission — manual step required even after flags are found
- **Status:** open
- **Description:** No integration with HTB API for automated flag validation and submission. Candidate flags must be manually reviewed and submitted.
- **Suggested fix:** Integrate HTB API for automated flag submission when high-confidence flags are found in shell/file-read output. Require API token configuration. Log submission results.
- **Resolution:**

---

## Statistics

| Severity | Total | Open | In Progress | Resolved | Workaround |
|----------|-------|------|-------------|----------|------------|
| Critical | 3     | 1    | 0           | 0        | 2 workaround |
| High     | 3     | 3    | 0           | 0        | |
| Medium   | 2     | 2    | 0           | 0        | |
| Low      | 1     | 1    | 0           | 0        | |
| **Total**| **9** | **7**| **0**       | **0**    | **2 workaround** |

---

## Changelog

- **2026-04-30:** Initial gaps from HTB Lame engagement (GAP-001 through GAP-009)
- **2026-04-30:** GAP-001 and GAP-002 → workaround (Copilot fills as human-in-the-loop; lame-2026-04-30-rematch WIN)
