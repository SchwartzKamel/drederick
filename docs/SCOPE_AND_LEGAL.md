---
title: Scope, authorized use, and exploitation posture
audience: [humans, agents]
primary: both
stability: stable
last_audited: 2026-04
related:
  - ../README.md
  - ../AGENTS.md
  - ARCHITECTURE.md
  - MODULES.md
  - POST_EXPLOITATION.md
  - EMPIRE.md
  - C2_INTEGRATION.md
  - LLM_SETUP.md
---

# Scope, authorized use, and exploitation posture

> **TL;DR.** Drederick is a **full-auto offensive security tool**: it
> discovers, fingerprints, **and exploits** services on targets the operator
> has declared authorized. The scope file is the authorization gate — it is
> default-deny, wildcards are refused, prefix caps apply, and every tool
> re-checks scope internally. Within scope, Drederick is free to run
> exploits, execute cached PoCs, chain credential attacks, and deliver
> payloads. **Outside scope, it does nothing.** These are hard guarantees.

<a id="invariants"></a>
## Invariants (agent-stable ids)

> **Source of truth.** [AGENTS.md](../AGENTS.md#invariants) mirrors this list.

Each invariant carries a stable `@invariant-id:` anchor. These are hard
guarantees — do not weaken, remove, or route around them. The invariants
protect the **authorization boundary** (scope); they no longer restrict
what Drederick may do *inside* that boundary.

| id | Invariant | Depth |
| -- | --------- | ----- |
| `@invariant-id:scope-in-every-tool`    | `_scope.Require(target)` is the first statement of every method that touches the network — including exploit, credential, and payload tools. | [Every tool re-checks](#what-drederick-does) |
| `@invariant-id:scope-default-deny`     | `Scope` is a default-deny allow-list. No empty scope, no implicit targets, no wildcard fallback. | [The only permitted use](#the-only-permitted-use-of-drederick) |
| `@invariant-id:scope-wildcard-refused` | `0.0.0.0/0` / `::/0` refused even with `--allow-broad`. | [Lab vs strict](#lab-default-vs-no-lab) |
| `@invariant-id:scope-prefix-cap`       | Lab `/8` v4 `/32` v6; strict `/16` v4 `/48` v6. `--allow-broad` lifts caps but not the wildcard refusal. | [Lab vs strict](#lab-default-vs-no-lab) |
| `@invariant-id:scope-is-authorization` | Scope is the **sole** authorization signal. Exploitation, credential attacks, payload staging, and PoC execution are permitted only against scope-resolved targets. | [Authorization model](#authorization-model) |
| `@invariant-id:llm-cannot-escape-scope` | The LLM runner cannot escape the allow-list — every tool re-checks, regardless of prompt, jailbreak, or tool-call forgery. | [Authorization model](#authorization-model) |
| `@invariant-id:subprocess-args-validated` | Any LLM-chosen or caller-chosen subprocess argument is validated before exec — target hosts/IPs in argv must resolve through `_scope.Require`. Argument injection (shell metachar, path traversal into scope-bypass) is rejected. | [Authorization model](#authorization-model) |
| `@invariant-id:audit-everything`       | Every exploitation step (PoC spawn, credential submission, payload delivery, shell interaction) is written to `audit.jsonl` with target, tool, argv digest, and timestamp. The audit log is append-only and operator-readable. | [Accountability](#accountability-and-audit) |
| `@invariant-id:no-exfiltration`        | Loot (credentials, hashes, tickets, captured secrets) stays local to `out/` and `audit.jsonl`. No telemetry, no cloud sync, no phone-home from the harness itself. | [Accountability](#accountability-and-audit) |
| `@invariant-id:scope-file-read-only`   | Scope authoring is a human act. Code never writes to the scope file — not from the CLI, not from `DrederickHost`, not from the Web UI, not from any runner. | [Authorization model](#authorization-model) |
| `@invariant-id:doctor-workstation-only` | Doctor modifies the operator workstation only; never re-execs as root; never contacts a target. Installing exploitation frameworks (Metasploit, impacket, nuclei) is workstation setup, not recon. | [What Drederick does](#what-drederick-does) |
| `@invariant-id:thread-safety`          | `AuditLog` and `KnowledgeBase` are thread-safe; everything else is stateless after construction. No shared mutable state outside those two. | [What Drederick does](#what-drederick-does) |
| `@invariant-id:no-scope-kill-switch`   | No flag, env var, debug build, CLI prompt, or LLM instruction disables the scope check. `--yolo`, `--no-scope`, `DREDERICK_DISABLE_SCOPE` etc. do not and must never exist. | [Authorization model](#authorization-model) |

The machine-readable mirror of this table is in
[`../AGENTS.md#invariants`](../AGENTS.md#invariants).

<a id="the-only-permitted-use-of-drederick"></a>
## The only permitted use of Drederick

**Targets that the operator is explicitly authorized to attack.** That
covers Hack The Box (HTB), TryHackMe, PortSwigger Web Security Academy,
OffSec exam/practice labs, Vulnhub VMs, vulhub Docker containers, CTF
competition ranges, internal red-team engagements with written ROE, bug
bounty programs with in-scope assets, and infrastructure the operator
owns.

Drederick is **not** appropriate for assessing third-party production
systems without written authorization, even if the operator suspects they
are misconfigured or "probably don't mind." Unauthorized exploitation is
a serious crime in most jurisdictions (CFAA in the US, Computer Misuse
Act in the UK, §202a/c StGB in Germany, analogous statutes elsewhere).

By entering a target into the scope file, the operator asserts that they
are authorized to attack it. The scope file is the record of that
assertion. If the operator is wrong about that authorization, the tool
will not save them — but the audit log will show exactly what was
authorized and when.

<a id="authorization-model"></a>
## Authorization model

Drederick's authorization model is deliberately simple:

1. **The scope file is authorization.** It is a user-authored, default-deny
   allow-list. Drederick never writes to it from code.
2. **Every network-touching method re-checks scope.** `_scope.Require(target)`
   is the first statement of every public tool method, including
   exploit, credential, and payload tools. This is not defense-in-depth
   theater — it is the load-bearing check.
3. **The LLM cannot escape scope.** `MicrosoftAgentRunner` exposes tools as
   `AIFunction`s. If the model invents a target, fabricates a tool call, or
   tries to pass a hostname that resolves outside scope, `ScopeException`
   is thrown and the attempt is logged.
4. **Argument validators stop scope-bypass via argv.** Tools that accept
   multi-host or multi-port arguments (nmap, impacket, msfconsole invocations)
   validate every host/IP in argv against `_scope.Require` before exec. See
   `NmapTool.RejectUnsafePortSpec` and `ExploitRunner.AssertTargetsInScope`.
5. **No kill switch exists.** There is no flag, no env var, no debug build,
   no prompt phrasing, and no LLM instruction that disables scope. Do not
   add one. Reviewers should reject any PR that proposes one.

Inside that boundary, Drederick is a full-auto offensive tool. The
authorization check is not "soft" just because the action is aggressive —
it is the same check for an nmap service scan and for a Metasploit exploit
with a meterpreter payload.

<a id="what-drederick-does"></a>
## What Drederick does

<a id="recon-and-enumeration"></a>
### Recon and enumeration (scope-gated)

- Discovery: nmap service/version scans, HTTP/TLS/DNS probes.
- Fingerprinting: version strings, security-header gaps, cert metadata.
- Enumeration: SMB, FTP, SSH, SNMP, LDAP, RPC, Kerberos, DNS, HTTP content
  discovery, TLS cipher enumeration, etc. All NSE categories are available
  within scope — **including** `exploit`, `intrusive`, `brute`, `vuln`,
  `dos`, and `malware`. Lab mode enables them by default; strict mode
  (`--no-lab`) requires explicit opt-in per category.
- CVE annotation: local NVD 2.0 matching against fingerprinted services.
- PoC aggregation: Exploit-DB, GitHub (PoC-in-GitHub, trickest/cve, raw
  fetch), Metasploit module source, nuclei templates, PacketStorm,
  Sploitus, GHSA, vendor advisories. Cached verbatim to
  `out/poc_cache/<source>/<id>/` with SHA-256 provenance.

<a id="exploitation"></a>
### Exploitation (scope-gated, default-on)

- **PoC execution.** Cached PoCs are runnable. The operator (or the LLM
  planner) selects a PoC, `ExploitRunner` verifies all targets in argv
  are in-scope, marks the artifact executable if required, and spawns it
  in an isolated working directory with the audit log recording argv
  digest, target, and exit status.
- **Metasploit integration.** Drederick may drive `msfconsole`
  non-interactively with `-r` resource scripts or `-x` one-liners.
  RHOSTS/LHOST values are scope-validated before the resource script is
  assembled. Meterpreter sessions count as a payload delivery action and
  are audited.
- **Credential attacks.** Password spray, targeted brute force, AS-REP
  roast, kerberoast, password spraying against SMB/WinRM/LDAP/SSH, and
  hash cracking of captured material. Wordlist paths, usernames, and
  lockout budgets are operator-supplied; Drederick enforces per-run rate
  limits and records every attempt.
- **Payload delivery.** Staging webshells, dropping beacons, uploading
  implants via authenticated admin interfaces. Payloads are either
  operator-supplied or generated via `msfvenom` with operator-chosen
  parameters.
- **Post-exploitation.** Under an established session (SSH, WinRM,
  meterpreter), Drederick may enumerate users, privileges, SUID binaries,
  kernel version, loot configured credentials, and attempt privilege
  escalation via cached local-priv-esc PoCs. Every action is audited and
  scope is re-checked if a new host appears (pivoting).
- **Lateral movement.** Pass-the-hash, pass-the-ticket, pivot via
  meterpreter port-forward — permitted against in-scope targets only.
  When a pivot would reach a host not in scope, the attempt is refused
  at `_scope.Require` and logged.

### Workstation support

- `drederick doctor` detects and (on consent) installs `nmap`,
  `searchsploit`, `metasploit-framework`, `impacket`, `nuclei`,
  `hashcat`, `john`, `hydra`, `netexec`, `evil-winrm`, `responder`,
  `python2`/`python3`, `go`, `ruby`, `git`, `jq`, `datasette`. This
  modifies the **operator's workstation**; it never touches a target.

<a id="what-drederick-does-not-do"></a>
### What Drederick does not do, ever

- **Operate outside scope.** No exploit, no recon, no probe, no DNS
  resolve to an address outside the scope allow-list.
- **Accept a wildcard scope.** `0.0.0.0/0` / `::/0` are refused even
  with `--allow-broad`.
- **Disable its own scope check.** No flag, env var, debug build, or
  prompt turns it off.
- **Modify the scope file from code.** Scope authoring is a human act.
- **Re-exec as root.** Doctor prints the command and asks; it does not
  silently elevate.
- **Exfiltrate looted material to third parties.** Credentials, hashes,
  secrets, and loot captured during a run stay local to `out/` and the
  audit log. No telemetry, no cloud sync, no "phone home."

These are hard guarantees.

<a id="accountability-and-audit"></a>
## Accountability and audit

Every exploitation step writes to `audit.jsonl`:

- Tool name, target (validated in-scope), timestamp (UTC, ISO 8601).
- Argv digest (SHA-256 of the exact argv submitted to the subprocess).
- PoC fetch events: source URL, SHA-256, bytes, content-type.
- PoC spawn events: artifact path, target, exit code, stdout/stderr size.
- Credential attempts: target, protocol, username, success/fail, lockout
  state. (Passwords themselves are **not** logged in plaintext; a SHA-256
  of the attempted secret is recorded so the operator can correlate
  without leaking wordlists.)
- Session events: open, pivot, close.

The audit log is append-only and is the canonical record of what the
operator authorized and what Drederick did. Preserve it after every run
for review.

<a id="aggregate-and-execute"></a>
## Aggregate *and* execute

Earlier versions of Drederick drew a hard line at "aggregate, never
execute." That line is gone. Drederick now both aggregates CVE/PoC
corpora **and** executes them against in-scope targets. The relevant
discipline is no longer "don't execute"; it is:

- **Don't leave scope.** The scope check is load-bearing.
- **Audit everything.** The operator must be able to reconstruct every
  action after the fact.
- **Don't surprise the operator.** Destructive actions (DoS scripts,
  `exploit/*` modules flagged as unstable, payload delivery) are gated
  behind explicit opt-in per run (e.g. `--allow-destructive`,
  `--allow-dos`) and default off even inside scope. Stability flags from
  Metasploit / NSE are surfaced, not suppressed.
- **Rate-limit credential attacks by default.** Lockout-aware throttling
  is on by default; the operator can raise it with `--spray-rate` but
  cannot fully remove it without `--acknowledge-lockout-risk`.

If you find a way to make Drederick act against a target **outside** its
scope file, make an outbound request to a target during enrichment or
doctor, or write to the scope file from code — treat it as a
security-critical bug. See "Reporting a security bug" below.

<a id="lab-default-vs-no-lab"></a>
## `--lab` (default) vs `--no-lab`

Lab mode is on by default. It is tuned for CTF/lab ergonomics: broader
NSE surface, destructive opt-ins available, richer cheatsheets. Strict
mode is tuned for engagements with formal ROE where defaults must be
conservative and every aggressive category is opt-in.

| Behavior                                | `--lab` (default)                                      | `--no-lab`                                               |
| --------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------- |
| Max IPv4 scope prefix (no override)     | `/8`                                                   | `/16`                                                    |
| Max IPv6 scope prefix (no override)     | `/32`                                                  | `/48`                                                    |
| NSE script categories                   | `safe,default,discovery,version,auth,exploit,intrusive,vuln` | `safe,default,discovery,version` (others require `--nse-categories=…`) |
| `vuln` / `exploit` NSE                  | on                                                     | opt-in                                                   |
| `dos` / `malware` NSE                   | opt-in (`--allow-dos`)                                 | opt-in (`--allow-dos`)                                   |
| PoC execution                           | on                                                     | opt-in (`--allow-exec-pocs`)                             |
| Credential attacks                      | on (lockout-aware)                                     | opt-in (`--allow-cred-attacks`)                          |
| Payload delivery                        | on                                                     | opt-in (`--allow-payloads`)                              |
| Per-host `manual_commands.txt`          | emitted                                                | emitted                                                  |
| Per-host `notes.md` + `scans/`          | emitted                                                | emitted                                                  |
| Wildcard scope (`0.0.0.0/0`)            | **refused**                                            | **refused**                                              |
| Out-of-scope target                     | **refused**                                            | **refused**                                              |
| Scope kill switch                       | **does not exist**                                     | **does not exist**                                       |

`--allow-broad` is an orthogonal override that lifts the prefix cap
entirely (but still refuses `/0`). Use it only when the authorized range
is genuinely that large.

<a id="accidental-out-of-scope-run"></a>
## Accidental out-of-scope run

If Drederick ever acts against a target it shouldn't have (scope file
typo, wrong engagement's scope loaded, pivot into an unexpected subnet):

1. Stop the process (`Ctrl+C` works; open sessions are closed cleanly
   on SIGINT and their closure is audited).
2. Preserve `out/`, `memory/findings.json`, and `audit.jsonl` for
   incident review — every scope decision, tool call, argv digest,
   credential attempt, PoC spawn, and session event is there.
3. Notify the owner of the unintended target and (if applicable) the
   engagement lead.
4. Fix the scope file before the next run.

The scope file is intentionally a tiny, human-readable allow-list
precisely so this kind of mistake is easy to audit after the fact. The
audit log is designed to be readable by someone who was not in the room
when the run happened.

<a id="reporting-a-security-bug"></a>
## Reporting a security bug

If you find a way to make Drederick touch a target outside its scope
file, bypass `_scope.Require` via argv/shell/LLM prompt, write to the
scope file from code, disable audit logging, or exfiltrate loot to a
third party — treat it as a security-critical bug and open an issue (or
a private report if the repo enables one).

The authorization boundary and the audit log are the only features that
matter more than correctness. Everything else — including which exploits
are on by default, how aggressive credential attacks are, and what
payload frameworks are integrated — is a product decision. The
authorization boundary is not.
