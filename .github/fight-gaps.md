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

### GAP-016: External Binary Dependency Audit
- **Exposed by:** architecture review 2026-05
- **Severity:** medium
- **Impact:** 15+ external binaries required for recon/analysis: `nmap` (port scan), `dig` (DNS queries and AXFR), `snmpwalk` (SNMP), `file`/`readelf`/`nm`/`strings`/`objdump` (binary analysis), `netexec` HTTP layer (HTTP credential spray), `which` (tool-presence checks). Absent tooling degraded enumeration coverage silently.
- **Status:** resolved
- **Description:** Drederick required external binary installation for core recon operations. Missing tools caused silent gaps in enumeration coverage without clear operator feedback. No .NET-native fallback existed for TCP port scanning, DNS resolution, SNMP, or binary analysis.
- **Resolution:** `NativeScannerTool` (async TCP scanner + TLS/Redis probes, pure `System.Net.Sockets`, replaces nmap for basic port enumeration), `NativeDnsTool` (`DnsClient.NET`, replaces `dig` for A/AAAA/MX/NS/TXT/SOA/PTR), `DnsZoneTransferTool` rewritten (`DnsClient.NET` AXFR, replaces `dig axfr`), `SnmpTool` rewritten (`Lextm.SharpSnmpLib`, 7 communities / 3 OID subtrees, replaces `snmpwalk`), `ElfParser`/`PeParser`/`BinaryAnalyzer` (native byte parsing, replaces `file`/`readelf`/`nm`/`strings`/`objdump`, 46 new parser tests), `NativeHttpSprayTool` (pure-.NET HTTP spray: Basic/Digest/Tomcat/Jenkins/Grafana/WordPress/phpMyAdmin/OWA/WinRM, replaces `netexec` HTTP layer), `PathResolver.Which()` (PATH env scan, replaces `which` subprocesses). 10+ subprocess dependencies eliminated. External tools remain available as optional enrichment (NSE scripts, msfconsole, nuclei, hashcat).

---

## Roadmap Gaps

### GAP-017: Plugin Ecosystem Hybridization Strategy
- **Exposed by:** roadmap 2026-05 (Tier 3)
- **Severity:** medium
- **Impact:** Without a structured strategy for incorporating community work, Drederick risks reinventing capability while missing well-tested community knowledge (NSE scripts, vendor MIBs, libmagic signatures, YARA rules, NetExec modules)
- **Status:** planned
- **Description:** Drederick's native-first internalization (GAP-016) eliminated subprocess dependencies, but the community plugin ecosystems (NSE scripts, vendor MIBs, libmagic signatures, YARA rules, NetExec modules) still hold significant accumulated value. Without a structured strategy for incorporating community work, Drederick risks reinventing capability while missing well-tested community knowledge.
- **Resolution plan:**
  - Document four-pattern capability strategy in `docs/PLUGIN_STRATEGY.md` (graceful enrichment / embedded data / ported logic / original tooling).
  - Implement Tier-3 todos: `nse-proxy` (Pattern 1), `mib-bundle` / `magic-bundle` / `yara-integration` (Pattern 2), `nse-port-top` (Pattern 3).
- **Tracking:** todos `nse-proxy`, `nse-port-top`, `mib-bundle`, `magic-bundle`, `yara-integration` in project todo store.

### GAP-018: Drederick-Original Signature Capabilities
- **Exposed by:** roadmap 2026-05 (Tier 4)
- **Severity:** high
- **Impact:** Drederick currently re-implements capabilities that exist elsewhere; to become the heavyweight champ pick rather than a wrapper, it needs original capabilities no other tool does cleanly
- **Status:** planned
- **Description:** Drederick currently re-implements capabilities that exist elsewhere. To become the heavyweight champ pick rather than a wrapper, it needs original capabilities no other tool does cleanly: cross-protocol credential replay, multi-signal fingerprinting → CVE inference, global lockout-aware spray scheduling, and multi-stage attack chain reasoning.
- **Resolution plan:**
  - `xprotocol-replay` — Replay creds in parallel across SMB/WinRM/MSSQL/LDAP/SSH/HTTP/RDP.
  - `fingerprint-stack` — port + banner + TLS cert + HTTP headers + favicon + JA3/JA4 → ranked CPE → CVE.
  - `lockout-scheduler` — Global AD-lockout-aware throttling shared across all spray tools.
  - `chain-reasoner` — Multi-stage attack chain proposer with explainability.
- **Tracking:** todos `xprotocol-replay`, `fingerprint-stack`, `lockout-scheduler`, `chain-reasoner`.

### GAP-019: Self-Improving Feedback Loop (Training Arc)
- **Exposed by:** roadmap 2026-05 (Tier 5)
- **Severity:** critical
- **Impact:** Drederick currently does not learn between fights — each engagement starts from the same baseline priorities, fingerprints, and tool inventory; lessons from prior fights do not feed back into tool selection or priority adjustment
- **Status:** planned
- **Description:** Drederick currently does not learn between fights. Each engagement starts from the same baseline priorities, fingerprints, and tool inventory — none of the lessons from prior fights (`~/HTB/fight-log.yaml`, `.github/fight-history/`) feed back into tool selection or priority adjustment. The harness should review every fight, record what worked, tune its own priorities, grow its fingerprint corpus, and scaffold new tools from observed patterns.
- **Resolution plan:**
  - Document training arc in `docs/LEARNING_LOOP.md`.
  - Foundation: `fight-telemetry` (per-attempt structured telemetry → `out/telemetry.db`), `fight-corpus-loader` (read `~/HTB/fight-log.yaml` schema v1).
  - Layer: `fight-archetype` (target archetype classifier), `fight-review` (`drederick review` subcommand), `fight-corpus-writer` (drafts post-fight entries; never auto-commits).
  - Self-tuning: `planner-self-tune`, `fingerprint-grow`, `archetype-playbook`, `tool-forge`.
- **Tracking:** todos `fight-telemetry`, `fight-corpus-loader`, `fight-corpus-writer`, `fight-archetype`, `fight-review`, `planner-self-tune`, `fingerprint-grow`, `archetype-playbook`, `tool-forge`.

### GAP-020: Multi-Choice Response Parsing (Copilot API)
- **Exposed by:** jobtwo-2026-05-01-rematch
- **Severity:** critical
- **Impact:** Copilot API returns tool_calls in separate choices (choice 0 = text, choices 1+ = individual tool_calls). ParseResponse only read choices[0], missing all tool calls.
- **Status:** ✅ resolved
- **Resolution:** Iterate ALL choices in ParseResponse(), merging text + tool_calls into single ChatMessage. Prefer tool_calls finish_reason over stop.

### GAP-021: Copilot SDK SendAndWaitAsync Hang
- **Exposed by:** jobtwo-2026-05-01-rematch
- **Severity:** critical
- **Impact:** SDK 0.3.0 SendAndWaitAsync hangs indefinitely — authenticates OK but never receives response.
- **Status:** ✅ resolved (bypassed)
- **Resolution:** Bypass SDK entirely. Route LlmProvider.Copilot to AzureOpenAiChatClient in copilotMode (direct HTTP to api.githubcopilot.com).

### GAP-022: Nmap Exploit NSE Script Timeout
- **Exposed by:** jobtwo-2026-05-01-rematch
- **Severity:** high
- **Impact:** LLM requests nmap with `--script exploit` which runs 30-60+ minutes on Windows hosts with many ports, blocking all other probes.
- **Status:** ✅ resolved
- **Resolution:** Removed `exploit` NSE category from NmapTool.BuildNseCategories(). Added `--host-timeout 300` to cap per-host runtime at 5 minutes.

### GAP-023: Sequential Tool Execution Bottleneck
- **Exposed by:** jobtwo-2026-05-01-rematch
- **Severity:** medium
- **Impact:** FunctionInvokingChatClient processes tools sequentially. Network-bound probes (nmap, http, smb) should run in parallel.
- **Status:** ⚠️ blocked
- **Resolution notes:** AllowConcurrentInvocation=true causes Claude via Copilot to reject conversation (strict tool_use→tool_result ordering). Needs custom parallel execution with ordered result assembly.

### GAP-024: Multi-Result Tool Serialization
- **Exposed by:** jobtwo-2026-05-01-R4
- **Severity:** critical
- **Impact:** BuildRequestBody only serialized first FunctionResultContent per ChatMessage. When FunctionInvokingChatClient batches 9 tool results in one message, 8 results were dropped. Claude rejected with "tool_use ids without tool_result blocks".
- **Status:** ✅ resolved
- **Resolution:** BuildRequestBody now expands ChatMessages with multiple FunctionResultContent into separate "role":"tool" messages.

### GAP-025: LLM Stops After Enumeration
- **Exposed by:** jobtwo-2026-05-01-R4
- **Severity:** high
- **Impact:** After completing enumeration (4 LLM calls, 21 tools), the LLM chose finish_reason=stop and generated a report instead of requesting exploitation tools (nuclei, msf-rc, cred attacks). The system prompt may need stronger guidance to attempt exploitation in lab/CTF mode.
- **Status:** ✅ resolved (facts-2026-05-02-R1/R2)
- **Resolution plan:** Review system prompt to emphasize exploitation phase. Ensure exploit tools are clearly described and available. Consider adding "exploitation required" directive in lab mode.
- **Resolution (R5):** `claude-sonnet-4.6` via Copilot (hybrid agent) on jobtwo-2026-05-02-R5 called `exploit_plan`, `run_multi_stage`, and `execute_cred_spray` ×5 without prompting — the willingness half of GAP-025 closed.
- **Resolution (facts R1/R2):** On facts-2026-05-02-R1/R2 the same model called `exploit_plan` (returned `ok=true` for the first time on this box), `run_multi_stage` (×3), `execute_cred_spray` (×5), **and `extract_flags_from_dir` proactively** — the model now plans exploitation, executes exploitation, and looks for results without prompting. The "non-spray exploit selection" depth concern is now correctly attributed downstream of GAP-031 (cache breadth) and GAP-033 (cve-lead routing), not GAP-025 (LLM willingness). Operator hot-fix `b9bbdb5` *"Remove nmap from LLM tools, prefer native probes in system prompt"* is the load-bearing piece of the resolution: the LLM's hands are now free for exploitation and follow-through instead of looping on nmap. Status: closed.

### GAP-026: Nmap-vs-Native Port-Truth Divergence
- **Exposed by:** jobtwo-2026-05-01-R4
- **Severity:** critical
- **Impact:** Nmap returned `open_ports=[]` against 10.129.238.35 (Windows host, ~6 min runtime, returncode 0). Native HTTP probes from the same run succeeded against 80, 443, and 5985 (Microsoft-HTTPAPI/2.0 / WinRM). Native TLS probes attempted handshakes on 443/10001/10002. Yet the autopilot planner only consulted `Nmap.OpenPorts` and produced 0 actions. Drederick stood in the ring with the gloves still in the bag.
- **Status:** ✅ resolved
- **Resolution:** `ExploitationPlanner.HarvestPortsFromAllSignals` now unifies port-presence evidence from `Nmap.OpenPorts` + `NativeScan.OpenPorts` + every protocol result array (`Http`/`Tls`/`Ssh`/`Smb`/`Ftp`/`Snmp`/`Ldap`/`Rpc`/`Kerberos` and the `*Anon`/`SslCert`/`SshHostkey`/`LdapRootDse`/`HttpTitle`/`HttpHeaders`/`HttpRobots`/`HttpMethods`/`HttpContentDiscovery`/`TlsCipherEnum` siblings). Real `NmapPort` entries always win on collision; URL-only signals synthesize `NmapPort` with an inferred `Service` so PlanForPort routes correctly. Regression test in `ExploitationPlannerTests.Plan_Harvests_Ports_From_Http_When_Nmap_Empty`.

### GAP-027: SslStream Double-Set RemoteCertificateValidationCallback
- **Exposed by:** jobtwo-2026-05-01-R4
- **Severity:** high
- **Impact:** `TlsProbeTool` and `NativeScannerTool` both passed a callback to the `SslStream` ctor AND set `SslClientAuthenticationOptions.RemoteCertificateValidationCallback`. .NET 10 throws `InvalidOperationException: RemoteCertificateValidationCallback option was already set in the SslStream constructor.` All three TLS attempts (443, 10001, 10002) on the JobTwo r4 run errored out — losing TLS-only port-presence evidence.
- **Status:** ✅ resolved
- **Resolution:** Drop the ctor callback in both tools; set the callback once via `SslClientAuthenticationOptions` only. `SslCertTool` was already single-source via ctor — left untouched.

### GAP-028: Autopilot Planner Ignored Non-Nmap Port Evidence
- **Exposed by:** jobtwo-2026-05-01-R4
- **Severity:** critical
- **Impact:** `ExploitationPlanner.Plan` short-circuited on `host.Nmap is null` and only iterated `host.Nmap.OpenPorts`. Even with 5 lab-default credentials in the store and a confirmed WinRM 5985 response in the recon findings, the planner emitted `total=0` actions. JobTwo r4 audit shows `autopilot.plan.built total=0` and the bell rang on a 0-punch fight. **Sister gap to GAP-026** — same root cause, different surface.
- **Status:** ✅ resolved
- **Resolution:** Same patch as GAP-026 — planner now consumes the unified port set, not just nmap. Regression test added.

### GAP-029: Tool Budget Caps Too Restrictive for Hard Boxes
- **Exposed by:** jobtwo-2026-05-02-R5
- **Severity:** high
- **Impact:** R5 audit shows `runner.agent_error  Budget exceeded: http called 17 times on 10.129.238.35 (cap 3).` and `runner.host_error  Budget exceeded: nmap called 4 times on 10.129.238.35 (cap 3).` The LLM legitimately wanted more `http` calls to enumerate IIS / WinRM virtual hosts, and the 3-per-tool cap starved enumeration mid-round on a Hard Windows host with a deep content-discovery surface.
- **Status:** open
- **Description:** Default `(3 per tool per target, 200 global)` was tuned for Easy boxes. There is no per-tool override flag and no archetype-aware scaling, so the same caps apply whether the target is Lame or JobTwo.
- **Suggested fix:** Raise per-tool defaults; expose `--tool-budget=<tool>:<cap>` overrides on `CommandLineOptions`; scale caps with `--difficulty=hard` or with archetype classification (`ArchetypeClassifier` already biases enumeration depth — budgets should follow). Audit every cap-hit as `tool_budget.exceeded` with tool name + count + target so future tape studies can see starvation immediately.
- **Code path:** `src/Drederick/Audit/ToolBudget.cs`, `src/Drederick/Cli/CommandLineOptions.cs`.
- **Resolution:**

### GAP-030: No Phishing / Macro / Payload-Bait Subsystem
- **Exposed by:** jobtwo-2026-05-02-R5
- **Severity:** critical
- **Impact:** JobTwo's documented attack chain is **macro phishing → user shell → Veeam privesc**. Drederick can stage an Empire agent post-foothold but cannot **craft** or **deliver** a phishing payload — no .docx/.xlsm/.lnk/HTA generator, no SMTP client for spearphish delivery, no callback-listener provisioning tied to the bait. Hard boxes that gate user shells behind a click are unreachable end-to-end; the harness can only join the fight after the operator manually delivers a foothold.
- **Status:** open
- **Description:** Empire's `EmpireAgentStager` produces post-foothold agents (`IPayloadTool`); there is no parallel `IPhishingTool` / `Exploit/Phishing/` subsystem for pre-foothold bait. Affected fights: jobtwo-2026-05-02-R5; will affect any Devel-class IIS-with-uploads box, ClickOnce/HTA-gated targets, and CTFs that ship a malicious-doc as the entry point.
- **Suggested fix:** New subsystem under `src/Drederick/Exploit/Phishing/` with `IPhishingTool` parallel to `IPayloadTool`. Start with macro-doc generation (msfvenom-backed + custom DDE templates), then SMTP delivery, then HTA/LNK/ClickOnce. Scope check on every recipient address (`_scope.Require` on the SMTP target *and* on any callback host). Audit shape: `phishing.payload.start/finish`, `phishing.deliver.start/finish`, payload SHA-256 in event, no plaintext recipient address bodies. Wire callback through the existing session manager so a clicked link lands in `out/sessions/` like any other shell. Gate the whole subsystem behind `--allow-payloads` (already exists).
- **Code path:** none — new subsystem. Owner zone: `exploit-*` (extend, do not touch `empire-c2` subdirectory). `src/Drederick/Exploit/IPayloadTool.cs` is the existing interface to mirror.
- **Resolution:**

### GAP-032: Native HTTP Probes Can't Use Host Header / Hostname Targets
- **Exposed by:** facts-2026-05-02-R1, facts-2026-05-02-R2
- **Severity:** critical
- **Impact:** The Facts box serves its app behind the `facts.htb` vhost; raw-IP requests return `302 Location: http://facts.htb/`. Native `http_probe` accepts `(target, port)` and emits `Host: <ip>:<port>` — there is no parameter for a vhost hostname or a custom `Host` header. R2 had twenty-one LLM calls in six minutes with the model **correctly identifying** the vhost requirement (it read the 302) and **unable to act on it** because the toolbox could not type the right request. 35 of 42 R2 `http.start` events errored. The application content was unreachable from the harness's recon stack the entire fight, even after the operator added `facts.htb` to `/etc/hosts` for R2. Affects every vhost-gated app behind nginx / Apache / IIS where IP-only requests redirect or 404.
- **Status:** open
- **Description:** The native HTTP probe stack under `src/Drederick/Recon/Native/` and the LLM-visible `http_probe` `AIFunction` in `src/Drederick/Agent/LlmReconTools.cs` both treat the target as an `(ip, port)` pair. Vhost hostnames extracted from 302 `Location` headers and TLS `CN`/`SAN` are not auto-followed; there is no `host=` parameter on the probe; and the system prompt does not teach the planner that a 302 → `Location` is a vhost lead with a specific tool follow-up.
- **Suggested fix:** Add an optional `Host` header / hostname target to native HTTP probes (default = target IP; override per call). Auto-extract vhost hostnames from 302 `Location`, TLS `CN`/`SAN`, and HTML `<meta>` tags into `findings.db`. Teach `AdaptiveRunner` to re-probe discovered vhosts. Surface `host=` on the LLM `http_probe` `AIFunction` parameter set with a clear `[Description(…)]` hint that 302 / vhost cert reveals are the trigger to set it. Scope-validate every hostname against its resolved IP before issuing the probe (the IP must already be in scope). Mirror on `https_probe` and `http_content_discovery`.
- **Code path:** `src/Drederick/Recon/Native/` (HTTP probe stack); `src/Drederick/Agent/LlmReconTools.cs` (LLM tool surface); `MicrosoftAgentRunner.BuildSystemPrompt` / `BuildUserMessage` (planner hint).
- **Resolution:**

### GAP-033: cve-lead Autopilot Actions All Skipped (No Router)
- **Exposed by:** facts-2026-05-02-R2
- **Severity:** high
- **Impact:** R2's second plan iteration recorded `autopilot.plan.built total=1291 nuclei=0 spray=20 msfrc=0 cve_lead=1271 cve_driven=1271`. Of 640 actions actually executed, **640 of 640 were `autopilot.action.skip`** with `reason="cve-lead: <CVE-ID> — no cached PoC artifact, route to PoC fetch / LLM"`. The autopilot's `case "cve-lead":` records the lead in audit and skips the action. The "route to PoC fetch / LLM" the skip reason references **does not exist** — nothing fetches the artifact on demand, nothing hands the lead to the LLM with sufficient context. 31 CVEs matched on the box (incl. CVE-2026-27944 Nginx UI CVSS 9.8 and CVE-2023-23596 NPM OS-cmd-injection CVSS 8.8); none were exploited. This supersedes the session-end note `gap-032-cve-lead-routing`; GAP-033 is the canonical ID.
- **Status:** open
- **Description:** `ExploitationPlanner` correctly emits `cve-lead` actions when a `findings.kind='cve'` row exists and no `poc_refs` row matches in the local cache. The action type is honest about what it is — a lead, not an exploit. But the executor leg in `AutopilotRunner` is skip-only. The cache-priming fix `d773904` (GAP-031b) closes part of this loop *before* plan time by warming msf modules + nuclei templates; an on-demand fetch + LLM-handoff path closes the rest *at* plan time.
- **Suggested fix:** Promote `cve-lead` from skip to real action.
  1. `PocAggregator.FetchForCveAsync(cveId)` — single-CVE on-demand fetch against the configured sources (Metasploit module index, nuclei templates, ExploitDB, GitHub PoC-in-CVE). Respect rate limits + global PoC byte cap.
  2. On cache hit, the action self-promotes to `nuclei` or `msfrc` and re-enters the action queue via the next plan iteration (action ID stable so dedup holds).
  3. On cache miss, hand the CVE to the LLM with `(service, version, CVE, NVD description, NSE script output)` context and let it plan a manual exploit via `exploit_plan` / `run_multi_stage`.
  4. Audit every step: `cve_lead.fetch.start/finish`, `cve_lead.promote`, `cve_lead.llm_handoff` so future tape studies can distinguish the failure modes.
- **Code path:** `src/Drederick/Autopilot/AutopilotRunner.cs` (`case "cve-lead":` — replace skip-only with the dispatch above); `src/Drederick/Enrichment/PocAggregator.cs` (add `FetchForCveAsync`); `src/Drederick/Autopilot/ExploitationPlanner.cs` (re-emit promoted actions on next iteration).
- **Resolution:**

### GAP-031: Autopilot Plan 100% Spray-Based Despite CVE Evidence
- **Exposed by:** jobtwo-2026-05-02-R5
- **Severity:** high
- **Impact:** Two of three R5 plan iterations recorded `autopilot.plan.built total=30 nuclei=0 spray=30 msfrc=0 cve_driven=0` and `total=14 nuclei=0 spray=14 msfrc=0 cve_driven=0`. Recon populated `findings.db` with CVE candidates (Veeam-shaped, IIS-shaped). GAP-015's resolution landed CVE-driven action emission, but on R5 it produced **zero** CVE-driven actions across two iterations. Either the join from `findings` to `poc_refs` returned empty (no nuclei templates / msf modules cached for the matched CVEs), or the matcher is too strict and the product token did not match.
- **Status:** open
- **Description:** GAP-015's resolution wired `nuclei` (priority 500) and `msfrc` (priority 490) action emission strictly above credential sprays (300/200). On R5 the planner emitted neither. This is the depth half of GAP-025 — the LLM and the deterministic planner now both commit to exploitation, but neither selects CVE-driven artifacts when they're the right answer. Reproduce by inspecting `out-r5/findings.db`: `SELECT * FROM findings WHERE kind='cve';` then `SELECT * FROM poc_refs WHERE cve_id IN (…);` and check whether the planner's `nuclei` / `metasploit` source filters returned anything.
- **Suggested fix:** Loosen match policy per the maximalist matching contract (CPE-exact → product + version range → product-only → banner keyword → one-hop related-CVE) so a `findings.kind='cve'` row produces *something* even when the cache is thin. Guarantee at least one CVE-driven action when any CVE row exists for a service; audit every join miss as `autopilot.cve.no_poc_refs` so future tape studies can distinguish "no CVE matched" from "CVE matched but no PoC cached" from "PoC cached but planner ignored". Consider warming `PocAggregator` more aggressively for matched CVEs before plan time.
- **Code path:** `src/Drederick/Autopilot/ExploitationPlanner.cs` (CVE → `poc_refs` join, product-token match, action priority constants); `src/Drederick/Enrichment/PocAggregator.cs` (cache breadth, match confidence).
- **Resolution:**

---

## Statistics

| Severity | Total | Open | In Progress | Resolved | Workaround | Planned | Partial |
|----------|-------|------|-------------|----------|------------|---------|---------|
| Critical | 11    | 3    | 0           | 5        | 2 workaround | 1     | 0       |
| High     | 12    | 7    | 0           | 5        |            | 1       | 0       |
| Medium   | 8     | 5    | 1 blocked   | 1        |            | 1       | 0       |
| Low      | 2     | 2    | 0           | 0        |            | 0       | 0       |
| **Total**| **33**| **17**| **1**      | **11**   | **2 workaround** | **3** | **0**   |

---

## Changelog

- **2026-04-30:** Initial gaps from HTB Lame engagement (GAP-001 through GAP-009)
- **2026-04-30:** GAP-001 and GAP-002 → workaround (Copilot fills as human-in-the-loop; lame-2026-04-30-rematch WIN)
- **2026-05-01:** New gaps from HTB JobTwo engagement (GAP-010 through GAP-014) — hard Windows box exposed enumeration and LLM runner gaps
- **2026-05-01:** GAP-010 resolved — Copilot SDK native sidecar now packaged in publish/install/release; GAP-015 added and resolved — autopilot now CVE-driven (NSE + findings.db → nuclei/msfrc above sprays)
- **2026-05:** GAP-016 added and resolved — NativeScannerTool, NativeDnsTool, SharpSNMP SnmpTool, native DnsZoneTransferTool, ElfParser/PeParser, NativeHttpSprayTool, PathResolver eliminate 10+ external subprocess dependencies
- **2026-05-01:** Added GAP-017 (plugin ecosystem hybridization), GAP-018 (Drederick-original signature capabilities), GAP-019 (self-improving feedback loop / training arc) — all planned.
- **2026-05-01:** GAP-020→024 resolved — multi-choice parsing, SDK bypass, nmap timeout, multi-result serialization. GAP-023 blocked (Claude ordering). GAP-025 added (LLM won't exploit).
- **2026-05-01:** GAP-026, GAP-027, GAP-028 added and resolved — JobTwo r4 tape revealed nmap-vs-native port-truth divergence, SslStream double-set ctor callback, and autopilot planner ignoring non-nmap port signals. Unified port harvest + single-source TLS callback. The champ studied the tape.
- **2026-05-02:** GAP-029 (high — tool budget caps starve Hard boxes), GAP-030 (critical — no phishing/macro subsystem), GAP-031 (high — autopilot plan 100% spray-based despite CVE evidence) added from JobTwo r5 tape (30 sprays / 0 connects / 34 min). GAP-025 status moves `open` → `partially resolved` — `claude-sonnet-4.6` via Copilot called `exploit_plan` / `run_multi_stage` / `execute_cred_spray` ×5 unprompted; depth half tracked under GAP-031.
- **2026-05-02:** GAP-032 (critical — native HTTP probes can't use Host header / hostname targets) and GAP-033 (high — `cve-lead` autopilot actions all skipped, no router from lead → PoC fetch → LLM handoff) added from facts-2026-05-02-R1/R2 (two losses, 6 min each, 0 errors / 0 budget denials, 1,611 audit events on R2 — densest fight on file; 1,271 cve-leads slipped on R2 with 31 CVEs matched). GAP-025 status moves `partially resolved` → `resolved` — facts-R2 had `claude-sonnet-4.6` calling `exploit_plan` (`ok=true`), `run_multi_stage`, `execute_cred_spray`, **and `extract_flags_from_dir` proactively**; remaining "non-spray exploit selection" reattributed to GAP-031 (cache breadth) + GAP-033 (cve-lead routing). Production-tape credit landings: `26f72e4` (GAP-029 tunable per-tool budget — 0 denials), `b9bbdb5` (no-nmap-from-LLM — 0 LLM-issued nmap calls), `1808cea` (tunable native HTTP timeout), `d773904` (GAP-031b PoC cache priming — 31 CVEs into the planner).
