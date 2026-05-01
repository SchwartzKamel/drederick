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

## High Gaps (continued)

### GAP-010: Copilot SDK Native Sidecar Missing From Installed Binary
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** high
- **Impact:** `--agent=hybrid --llm-provider copilot` audited `runner.agent_error` + `hybrid.llm_fallback`, then ran the deterministic planner. Operator-facing report did not surface the fallback, so it looked like the LLM had run.
- **Status:** resolved
- **Description:** `CopilotClientOptions` resolves the Copilot CLI under `AppContext.BaseDirectory/runtimes/<rid>/native/copilot`. The SDK target copies the binary into `bin/.../<rid>/runtimes/...`, but `make publish` produced a single-file binary and `make install` only installed `drederick` itself. Released tarballs and `scripts/install.sh` had the same hole.
- **Resolution:** Added `_CopyCopilotCliToPublishDir` MSBuild target so the sidecar lands in `publish/<rid>/runtimes/<rid>/native/copilot`. `Makefile install`, `.github/workflows/release.yml`, and `scripts/install.sh` now ship and install the `runtimes/` tree with the executable bit preserved.

---

## Medium Gaps (continued)

### GAP-011: SMTP User and Config Enumeration
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** medium
- **Impact:** hMailServer on port 25 was fingerprinted but never probed for users, relay, or config disclosure
- **Status:** open
- **Description:** SMTP services should be probed with VRFY/EXPN/RCPT TO for user enumeration. hMailServer specifically stores config files with encrypted credentials — the scanner should attempt to discover config file paths and read accessible configs.
- **Suggested fix:** Add an SMTP enumeration scanner: VRFY/EXPN user enumeration, relay testing, banner analysis. For known SMTP products (hMailServer, Postfix, etc.), check for config file disclosure paths.
- **Resolution:**

### GAP-012: NFS Share Enumeration
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** medium
- **Impact:** Port 2049 (NFS/rpcbind) was open but never enumerated for mountable shares
- **Status:** open
- **Description:** NFS shares can expose sensitive files (home directories, config files, credentials). drederick detected rpcbind but didn't run showmount or attempt NFS share enumeration.
- **Suggested fix:** Add NFS enumeration: `showmount -e`, attempt mount of world-readable shares, list contents, flag credentials/keys/configs.
- **Resolution:**

### GAP-013: Web Content Discovery
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** medium
- **Impact:** Ports 80/443 returned 404 default pages but no directory brute-force was attempted
- **Status:** open
- **Description:** The `--content-discovery` flag exists but is off by default. Even when HTTP services return 404 on root, directory brute-forcing may reveal hidden paths (admin panels, API endpoints, backup files).
- **Suggested fix:** Consider auto-enabling content discovery when HTTP services return 404/403 on root — this often indicates hidden paths. Use a small focused wordlist for speed.
- **Resolution:**

### GAP-014: SSL Cert Hostname Auto-Addition
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** low
- **Impact:** SSL cert CN=www.job2.vl and SAN=job2.vl were discovered but not added to /etc/hosts for vhost-based recon
- **Status:** open
- **Description:** When TLS certificates reveal hostnames, those hostnames should be added to /etc/hosts (or DNS resolution) and re-scanned for virtual host content that differs from IP-based access.
- **Suggested fix:** Auto-extract hostnames from SSL certs and add to /etc/hosts. Re-run HTTP recon against those hostnames. Flag when vhost content differs from IP-based content.
- **Resolution:**

### GAP-015: Autopilot Did Not Drive CVEs Into Exploit Actions
- **Exposed by:** jobtwo-2026-05-01
- **Severity:** high
- **Impact:** JobTwo recon found CVE evidence (NSE `vulners`/`http-*` script output, enriched `findings.db`), and the scope's known attack chain centred on Veeam CVE-2024-29849 — but autopilot emitted 39 password sprays and zero CVE/PoC actions because the planner only knew how to match nuclei templates by product token.
- **Status:** resolved
- **Description:** `ExploitationPlanner` only scanned `out/poc_cache/nuclei` for filename token matches against `port.Product`. It ignored NSE script CVE IDs, the enriched `findings.kind='cve'` rows, and the `poc_refs` table populated by `PocAggregator` (which already pulls Metasploit module names and nuclei template paths per CVE). It also had no `msfrc` execution path.
- **Resolution:** `ExploitationPlanner` now extracts CVE IDs from NSE script output (`port.Scripts[].Id` and `.Output`) and from `findings.db` (joined to host+service), then queries `poc_refs` for matching `nuclei` templates and `metasploit` modules. It emits `nuclei` (priority 500) and `msfrc` (priority 490) actions strictly above credential sprays (300/200). `AutopilotRunner` gained an `msfrc` branch that drives `MsfRcRunner` (module + whitelisted options, host-bearing values re-validated). Action IDs are now content-addressed so iteration dedup persists across re-plans.

---

## Statistics

| Severity | Total | Open | In Progress | Resolved | Workaround |
|----------|-------|------|-------------|----------|------------|
| Critical | 3     | 1    | 0           | 0        | 2 workaround |
| High     | 5     | 3    | 0           | 2        | |
| Medium   | 5     | 5    | 0           | 0        | |
| Low      | 2     | 2    | 0           | 0        | |
| **Total**| **15**| **11**| **0**      | **2**    | **2 workaround** |

---

## Changelog

- **2026-04-30:** Initial gaps from HTB Lame engagement (GAP-001 through GAP-009)
- **2026-04-30:** GAP-001 and GAP-002 → workaround (Copilot fills as human-in-the-loop; lame-2026-04-30-rematch WIN)
- **2026-05-01:** New gaps from HTB JobTwo engagement (GAP-010 through GAP-014) — hard Windows box exposed enumeration and LLM runner gaps
- **2026-05-01:** GAP-010 resolved — Copilot SDK native sidecar now packaged in publish/install/release; GAP-015 added and resolved — autopilot now CVE-driven (NSE + findings.db → nuclei/msfrc above sprays)
