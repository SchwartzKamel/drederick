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
- **Status:** ✅ resolved
- **Resolution:** Commit `a9e305a` — native `http_probe` accepts hostname + Host header + SNI; vhost auto-detect on `3xx → Location`; `_scope.Require` runs on the resolved IP via `SocketsHttpHandler.ConnectCallback` (DNS-rebinding-proof).
- **✅ Confirmed firing in facts R3+R4 production tape:** `http_probe` usage `0 → 35 → 48` across `R2 → R3 → R4`. The native HTTP stack now wears a Host header in production. The planner picks it up without prompting. Sister gap GAP-032b (vhost-aware credential sprays — `execute_cred_spray` does not yet wear the Host header) tracked separately.
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
- **Status:** ✅ resolved (router); ⚠️ **effective only when PoC sources have artifacts**
- **Resolution:** Commit `8751e4a` — `cve-lead` action calls `PocAggregator.FetchOnDemandAsync(cveId)` then re-plans via `StableId` divergence; per-run loop guard; `--no-fetch-poc` honored.
- **⚠️ R3+R4 production tape:** 640/640 leads still skipped per fight because the cache has no artifacts for the box's CVEs. `PocAggregator` currently only carries on-disk probe sources (msf-on-disk, nuclei-templates-on-disk); the operator's box has neither installed. The router invokes `FetchOnDemandAsync` exactly as designed; every fetch returns unfetchable. **The downstream blocker is git-clone PoC sources (todo `gap-031b-2`)** — escalated and tracked under GAP-035.

### GAP-034: HTTP Error Events Lack Reason Taxonomy
- **Exposed by:** facts-2026-05-02-R3, facts-2026-05-02-R4
- **Severity:** medium
- **Impact:** Each fight produces 30-34 `http.error` events with a freeform `error` string only. R3+R4 tape diagnosis required a manual `tail | grep` to discover the cluster was dominated by `Connection refused` on closed ports the planner explored (443, 8080, 8443, 3000, 5000, 9000, …) — **not** 302 redirect loops the GAP-032 vhost fix should have prevented. A reason bucket would turn a manual tail-grep into a one-line query and surface real vhost / DNS / TLS regressions cleanly when they happen.
- **Status:** open
- **Description:** `http.error` events emit `{target, url, error: <freeform string>}`. There is no machine-readable bucket for `connection_refused` / `timeout` / `dns_unresolved` / `redirect_loop` / `tls_handshake` / `http_status_4xx` / `http_status_5xx` / `host_header_rejected`. Future tape studies (and any UI / Datasette canned query) cannot distinguish "planner explored a closed port" from "vhost fix regressed" without prose-grep.
- **Suggested fix:** Add a `reason` enum field on `http.error` audit events (and on the corresponding `HostFinding.Http.Error` shape if it carries one). Bucket at the catch site in `HttpProbeTool` — `SocketException` → `connection_refused`, `TaskCanceledException` → `timeout`, redirect chain length cap hit → `redirect_loop`, etc. Keep the freeform `error` for forensics but query off `reason`. Mirror on `https_probe` and `http_content_discovery`. Also worth surfacing in a Datasette canned query under `databases.findings.queries.http_errors_by_reason`.
- **Code path:** `src/Drederick/Recon/HttpProbeTool.cs` (catch sites + audit shape); `src/Drederick/Recon/HostFinding.cs` (typed result); `datasette/metadata.json` (canned query).
- **Companion:** the `extract_flags_from_dir.refused` event observed once per fight on R3+R4 with `reason="path_outside_out"` belongs in the same prompt-teaching pass — the LLM passed `out/` (relative), which resolved to `/home/lafiamafia/HTB/machines/facts/out/` while the run dir was `out-r3` / `out-r4`. Out-of-scope on the flag-extractor's `out_root` boundary, not on `Scope`. A one-line system-prompt nudge to use the configured `out_root` closes it.
- **Resolution:**

### GAP-035: Escalate gap-031b-2 (Git-Clone PoC Sources) — Load-Bearing for Auto-Takedown
- **Exposed by:** facts-2026-05-02-R3, facts-2026-05-02-R4
- **Severity:** high (meta — escalation, not new fix)
- **Status (update 2026-05-02 later):** ✅ resolved as escalation — the
  todo `gap-031b-2-git-poc-sources` is in flight (concurrent agent zone
  `gap-031b-2-git-poc-sources` — `MetasploitGitSource`,
  `NucleiTemplatesGitSource`, `PocInGitHubSource`, `GitPocSourceShared`
  staged in working tree). Close on landing; production-tape credit
  pending the next CVE-driven box.
- **Impact:** The GAP-033 cve-lead router (`8751e4a`) is sound — production tape confirms it invokes `PocAggregator.FetchOnDemandAsync` per CVE. But every fetch returns unfetchable on R3+R4 because `PocAggregator` only ships on-disk probe sources (msf-on-disk, nuclei-templates-on-disk) and the operator workstation has neither installed. **640 of 640 cve-leads slipped per fight, both fights**, despite 31 CVEs matched on the box. This is now the single biggest blocker between Drederick's recon stack and an autonomous takedown. Without git-clone PoC sources, the router has nowhere to fetch from; with them, the router pulls from `rapid7/metasploit-framework`, `projectdiscovery/nuclei-templates`, `nomi-sec/PoC-in-GitHub`, `trickest/cve` on demand and the cve-lead action self-promotes to `nuclei`/`msfrc` as designed.
- **Status:** open, **escalated to top priority**
- **Description:** This gap does not introduce a new fix — it surfaces that the existing todo `gap-031b-2-git-poc-sources` (sparse-checkout-based on-demand git-clone PoC sources matching the maximalist matching contract) has become load-bearing in production. Until it lands, GAP-033's router runs unfed and every CVE-driven box where the operator workstation lacks pre-installed msf modules / nuclei templates loses on the autopilot card.
- **Suggested fix:** Ship `gap-031b-2`. Implement `IPocSource` for each of: `metasploit-framework` (sparse-checkout `modules/exploits/**`, `modules/auxiliary/**`, `modules/post/**`), `nuclei-templates` (sparse-checkout CVE folder), `PoC-in-GitHub` and `trickest/cve` (raw-fetch referenced files). Cache to `out/poc_cache/<source>/<external_id>/` with provenance per `docs/MODULES.md`. Use `git clone --depth=1 --filter=blob:none` then `sparse-checkout set` for repo-shaped sources. Use `GITHUB_TOKEN` when set. Respect the existing 5 MB / 2 GB caps. Audit every fetch as `poc.fetch`. Once shipped, GAP-033's `FetchOnDemandAsync` has somewhere to call and the cve-lead → `nuclei`/`msfrc` self-promotion path closes end-to-end.
- **Code path:** `src/Drederick/Enrichment/PocAggregator.cs`, new `IPocSource` implementations alongside `SearchsploitSource.cs`. Owner zone: `enrichment-*`.
- **Resolution:** unblocks once `gap-031b-2` ships; close GAP-035 the same day.

### GAP-036: CMS Fingerprinting Tool
- **Exposed by:** facts-2026-05-02-R5-copilot (operator yaml numbers this GAP-034 — registry uses GAP-036, see changelog)
- **Severity:** high
- **Impact:** Drederick's banner-only fingerprint stack failed to identify
  CameleonCMS 2.9.0 across R1-R4 on Facts despite `cama_*` cookie names,
  Rails 8.0.2 generator metadata, and theme asset paths being present in
  every `http_probe` response. Cornerman fingerprinted it manually by
  eyeball in seconds. Without CMS identification the GAP-041 chain
  templates have nothing to dispatch on; this is the upstream blocker
  for the entire CMS exploitation pattern (CameleonCMS, WordPress,
  Joomla, Drupal, Ghost, Strapi, …).
- **Status:** open
- **Description:** Add a CMS fingerprint tool that reads cookie names,
  HTML `<meta name="generator">`, theme asset paths
  (`/assets/<theme>/...`), CSS class prefixes, JavaScript globals, and
  HTTP headers, and matches against a CMS fingerprint corpus
  (CameleonCMS, WordPress, Joomla, Drupal, Ghost, Strapi, Shopify,
  Magento, …). Should plug into the existing `LearnedFingerprintStore`
  so successful fingerprints persist across fights.
- **Suggested fix:** New `IReconTool` `CmsFingerprintTool` under
  `src/Drederick/Recon/` (or as part of the fingerprint stack under
  `src/Drederick/Enrichment/FingerprintStack/`). Seed the corpus from
  Wappalyzer's open-source rule database. Emit `cms.fingerprint` audit
  events; record `(product, version, confidence)` tuples on
  `HostFinding.Http`. Expose to the LLM with a precise `[Description]`
  so the planner picks it after `http_probe`.
- **Code path:** new `src/Drederick/Recon/CmsFingerprintTool.cs` or
  `src/Drederick/Enrichment/FingerprintStack/CmsFingerprinter.cs`;
  wire into `ReconToolbox`. Owner zone: `recon-*` or
  `enrichment-fingerprint`.
- **Resolution:**

### GAP-037: MinIO/S3 Service Prober
- **Exposed by:** facts-2026-05-02-R5-copilot
- **Severity:** high
- **Impact:** Port 54321/tcp on Facts was the pivot — internal MinIO
  bucket carrying the `trivia` ed25519 SSH key. Drederick's autopilot
  saw it as "unknown service" because no probe in the bag speaks the
  S3 API on non-standard ports. Cornerman pivoted with `aws-cli
  --endpoint http://10.129.30.236:54321`. Without an S3-aware probe
  every backup-bucket-pivot box stays opaque.
- **Status:** open
- **Description:** S3-compatible storage (MinIO, Ceph RGW, Wasabi,
  AWS S3 directly) frequently runs on non-standard ports in lab/CTF
  scenarios. The probe should detect S3 API surface from
  `ListBuckets` / `GetBucketLocation` / `?versioning` responses,
  enumerate buckets when credentials land in the credential store,
  and list keys recursively into the `loot` table.
- **Suggested fix:** New `IReconTool` `MinioProbeTool` (and/or
  `S3ProbeTool`) under `src/Drederick/Recon/`. Detect S3 surface via
  the unauthenticated `GET /` XML envelope and HTTP headers
  (`x-amz-*`). Once Drederick's `CredentialStore` carries S3
  access/secret pairs, escalate to authenticated `ListBuckets` /
  `ListObjectsV2` and stream artifacts into `out/<host>/s3/` with
  SHA-256 + provenance.
- **Code path:** new `src/Drederick/Recon/MinioProbeTool.cs`; wire
  into `ReconToolbox` and the `ExploitationPlanner` port-harvest
  signal. Owner zone: `recon-*`.
- **Resolution:**

### GAP-038: SQLite Credential Pillage Post-Ex
- **Exposed by:** facts-2026-05-02-R5-copilot
- **Severity:** high
- **Impact:** `production.sqlite3` exfiltrated in step 5 of the chain
  carried MinIO access/secret in plaintext in the `cama_metas` table.
  Without an automated DB pillage step, every captured DB file
  becomes manual-cornerman work. Pattern repeats across Rails / Django
  / Laravel / WordPress / Joomla / Drupal / Strapi — the credentials
  table is always somewhere on disk and always plaintext-or-decryptable.
- **Status:** open
- **Description:** Post-exploitation step that walks any captured
  `.sqlite*` / `.db` / `.mdb` / `.sqlitedb` file (and SQL dumps),
  enumerates tables, and grep-extracts likely credential fields
  (`password`, `secret`, `key`, `token`, `access_key`, `aws_*`,
  `s3_*`, `smtp_*`, `db_*`, `_credential`, `_token`, `_key`). Emit
  to `loot` with SHA-256 of the secret value (per
  `@invariant-id:audit-everything`).
- **Suggested fix:** New post-ex tool under
  `src/Drederick/PostEx/` (or `src/Drederick/Exploit/PostEx/`)
  `SqlitePillageTool` that takes a path on a session, downloads via
  the session, opens with `Microsoft.Data.Sqlite`, enumerates schema,
  matches credential columns against a regex bank, writes findings
  to `KnowledgeBase.CredentialStore` and `loot`.
- **Code path:** new tool under `src/Drederick/PostEx/`; wire into
  the post-ex dispatcher. Owner zone: post-ex.
- **Resolution:**

### GAP-039: SSH Key Passphrase Brute
- **Exposed by:** facts-2026-05-02-R5-copilot
- **Severity:** high
- **Impact:** ed25519 key for `trivia` came out of the MinIO bucket
  passphrase-encrypted. Cornerman cracked `dragonballz` in 3,185
  tries against rockyou-1k via paramiko. Without this capability,
  any captured key with a passphrase becomes manual work.
- **Status:** open
- **Description:** Take a captured private key file
  (`-----BEGIN OPENSSH PRIVATE KEY-----` / RSA / ECDSA / DSA),
  attempt empty passphrase, then iterate a wordlist with
  lockout-aware throttling defaults-on. Record SHA-256 of attempted
  passphrase only — never plaintext. On crack, decrypt the key,
  store in `CredentialStore`, optionally chain into `ssh` session
  open against any host where the key's `comment` field maps.
- **Suggested fix:** New `ICredTool` `SshKeyPassphraseTool` under
  `src/Drederick/Exploit/` (or `src/Drederick/PostEx/Cred/`).
  Default wordlist: rockyou-1k. Cap attempts at 100k by default;
  bcrypt-rounds-aware sizing for ed25519. Audit shape:
  `ssh-key-brute.{start,attempt,finish}` with `secret_digest`
  field per `@invariant-id:audit-everything`.
- **Code path:** new `src/Drederick/Exploit/SshKeyPassphraseTool.cs`;
  wire into `ExploitToolbox` and `CredentialStore`. Owner zone:
  `exploit-*`.
- **Resolution:**

### GAP-040: sudo -l Enum + GTFOBins-Aware Privesc
- **Exposed by:** facts-2026-05-02-R5-copilot
- **Severity:** critical
- **Impact:** `sudo -l` showed `(root) NOPASSWD: /usr/bin/facter` —
  GTFOBins-canonical for sudo privesc via `--custom-dir`. Cornerman
  loaded a custom Ruby fact and got root in one shot. Without this,
  every "Linux user shell → root via sudo entry" path is manual.
  On Linux easy-medium boxes this is the most common privesc vector.
- **Status:** open
- **Description:** Post-ex step that runs `sudo -l` on a Linux
  session, parses the entry list, looks each binary up in a local
  GTFOBins corpus, and synthesizes the exploit command. Should
  cover the GTFOBins `sudo` taxonomy: shell, command, file-read,
  file-write, library-load, environment, capabilities, suid.
- **Suggested fix:** New post-ex tool under
  `src/Drederick/PostEx/` `SudoEnumTool` + a GTFOBins corpus
  embedded as a JSON resource (sourced from the
  `GTFOBins/GTFOBins.github.io` repo data files). On a match,
  return the synthesized command and (lab mode) execute via the
  session; (strict mode) require `--allow-exec-pocs`. Audit shape:
  `sudo-l.{start,parse,exploit}.{start,finish}` with target,
  binary, and gtfobins-id.
- **Code path:** new `src/Drederick/PostEx/SudoEnumTool.cs` +
  `src/Drederick/PostEx/GtfoBinsCorpus.cs` (embedded JSON). Owner
  zone: post-ex.
- **Resolution:**

### GAP-041: CMS Chain Templates (Multi-Stage)
- **Exposed by:** facts-2026-05-02-R5-copilot
- **Severity:** high
- **Depends on:** GAP-036 (CMS fingerprint must fire first to pick
  the right template)
- **Impact:** CameleonCMS chain on Facts ran 5 conceptual steps
  (register → mass-assign → traversal → DB exfil → S3 pivot) before
  pivoting off the CMS surface. The same shape applies to
  WordPress, Joomla, Drupal, Ghost, Strapi, Magento — register
  endpoint → role escalation primitive → file read primitive →
  credential database → service-credential pivot. Without
  templated chains the LLM has to re-derive the pattern every box.
- **Status:** open (blocked on GAP-036)
- **Description:** A multi-stage chain bank under
  `src/Drederick/Autopilot/Chains/` keyed by `(cms_product,
  cms_version_range)`. Each chain is a sequence of named steps
  with parameter-binding contracts (output of step N → input of
  step N+1). The `MicrosoftAgentRunner` and `AdaptiveRunner` both
  consult the bank when GAP-036 produces a CMS fingerprint hit.
- **Suggested fix:** New `IExploitChain` interface under
  `src/Drederick/Autopilot/`. Ship CameleonCMS 2.x first (matching
  the demonstrated chain on Facts) as a reference implementation.
  Then WordPress 5.x/6.x, Joomla 4.x/5.x, Drupal 9.x/10.x.
  Persist `chain.run.{start,step,finish}` audit events with chain
  id, step index, step result. Each step re-checks scope (per
  `@invariant-id:scope-in-every-tool`).
- **Code path:** new `src/Drederick/Autopilot/Chains/` with
  `IExploitChain.cs`, `CameleonCmsChain.cs`, `WordPressChain.cs`,
  …; wire into `MicrosoftAgentRunner` and `AdaptiveRunner` as a
  preferred-action when CMS fingerprint lands. Owner zone:
  `autopilot`.
- **Resolution:** open until GAP-036 lands; ship CameleonCMS chain
  as the first reference template once it does.

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
| Critical | 12    | 3    | 0           | 6        | 2 workaround | 1     | 0       |
| High     | 18    | 12   | 0           | 7        |            | 1       | 0       |
| Medium   | 9     | 6    | 1 blocked   | 1        |            | 1       | 0       |
| Low      | 2     | 2    | 0           | 0        |            | 0       | 0       |
| **Total**| **41**| **23**| **1**      | **14**   | **2 workaround** | **3** | **0**   |

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
- **2026-05-02 (later):** facts-2026-05-02-R3 + facts-2026-05-02-R4 tape study. GAP-032 + GAP-033 production-tape confirmed: `a9e305a` vhost fix landed clean (`http_probe` usage `0 → 35 → 48` across `R2 → R3 → R4`); `8751e4a` cve-lead router invokes `FetchOnDemandAsync` per CVE as designed. **GAP-033 effective only when PoC sources have artifacts** — R3+R4 returned 640/640 unfetchable per fight because `PocAggregator` only ships on-disk probe sources. New: GAP-034 (medium — `http.error` events lack reason taxonomy; manual tail-grep needed to distinguish closed-port exploration from vhost regression), GAP-035 (high, meta — escalates `gap-031b-2` git-clone PoC sources to top priority because the cve-lead router is now starved for artifacts). R3: 28 LLM calls / 1,624 events / 6 min. R4: 42 LLM calls / 1,785 events / 6 min — densest planner ever recorded. Operator caught a flag manually after R4 off-harness; Drederick's recon scaffold credited (31 CVEs, vhost reachable, 5 creds, full 25-tool LLM bag). Autopilot record on Facts now 0-4.
- **2026-05-02 (later):** **First W of the harness arc.** facts-2026-05-02-R5-copilot tape study — Copilot cornerman ran an 11-step exploitation chain on Facts after 4 autonomous losses; both flags captured (user `e205d77c…d077d`, root `df6ad544…41c36`). Tag-team: Drederick laid the recon scaffold (R4's 31 CVEs, vhost reachable via GAP-032 fix, scope policy on the operator workstation), Copilot threw the chain (CameleonCMS register → CVE-2025-2304 mass-assign → CVE-2026-1776 traversal → SQLite `cama_metas` exfil → MinIO bucket raid via 54321/tcp → ed25519 SSH key passphrase brute → user shell → sudo `facter --custom-dir` → root). Steps 2-11 ran off-harness in operator bash; no `out-r5/` directory or `audit.jsonl` for this fight. Six new gaps land: **GAP-036** (high — CMS fingerprint), **GAP-037** (high — MinIO/S3 prober), **GAP-038** (high — SQLite credential pillage post-ex), **GAP-039** (high — SSH key passphrase brute), **GAP-040** (critical — `sudo -l` + GTFOBins lookup + exploit), **GAP-041** (high — CMS chain templates, depends on GAP-036). **Numbering note:** the operator's R5-copilot yaml entry uses `GAP-034` for the CMS-fingerprint gap; that number was already taken by `http.error` taxonomy from R3+R4. The operator's yaml is canonical for the operator's numbering; the registry uses GAP-036+ to avoid collision. **GAP-035 status update:** ✅ resolved as escalation — `gap-031b-2-git-poc-sources` is in flight (concurrent agent zone with `MetasploitGitSource`, `NucleiTemplatesGitSource`, `PocInGitHubSource`, `GitPocSourceShared` staged in working tree). Records: chain length 11 (prev. record: 1); Drederick autonomous on Facts 0-4; with cornerman 1-0; overall card per writeup `1-8-1` auto / **`2-8-1` with assist**. Pingpong-2026-05-02-R1 logged in parallel as in-flight (no `autopilot.finish` yet, 176 events, provider `azure_openai`, 14 LLM / 11 `http_probe` / 5 `execute_cred_spray` / 2 `msf-rc` / 3 `budget.deny`); next entry will tell the story. Pingpong is the test bed for whether `llm-exec-shell-tool`, `gap-031b-2`, `gap-032b`, and `gap-034-http-error-taxonomy` carry over to a fresh box.
