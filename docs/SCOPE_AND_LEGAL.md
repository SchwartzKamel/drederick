# Scope, lab mode, and authorized use

## The only permitted use of Drederick

**Lab and CTF targets that you are explicitly authorized to assess.** That
covers Hack The Box, TryHackMe, PortSwigger Web Security Academy, OffSec
exam/practice labs, Vulnhub VMs, vulhub Docker containers, CTF competition
ranges, and infrastructure you own or have written authorization to test.

Drederick is **not** appropriate for assessing third-party production systems,
even if you suspect they are misconfigured. Unauthorized testing is illegal in
most jurisdictions.

By pointing Drederick at any target you assert that you are authorized to test
that target. If you are wrong about that, the tool will not save you.

## What Drederick does and does not do

### Does

- Discovery: nmap service/version scans, HTTP/TLS/DNS probes.
- Fingerprinting: version strings, security-header gaps, cert metadata.
- Additional enumeration (scope-gated, read-only): SMB, FTP, SSH, SNMP,
  LDAP, RPC, Kerberos-SPN, DNS AXFR, HTTP content discovery, TLS cipher
  enumeration.
- **Aggregates** CVE and PoC references for fingerprinted services from
  public metadata sources (NVD, Exploit-DB / searchsploit, GHSA,
  Metasploit module names, nuclei template IDs).
- **Caches** public PoC source locally under `out/poc_cache/<source>/<id>/`
  with SHA-256 provenance, for the operator to read and decide what to
  attempt outside the tool.
- Generates a **manual-commands cheatsheet** of further enumeration
  commands the operator *may* choose to run themselves.
- `drederick doctor` modifies the **operator's workstation** at their
  consent (installing `nmap`, `searchsploit`, `datasette`, etc).

### Does not, ever

- Run exploits, PoCs, or exploit-category NSE scripts.
- Execute, chmod, or spawn any fetched PoC source.
- Make the outbound request that a PoC would have made (no "test it for
  me" mode).
- Perform credential brute force, password spray, or dictionary attacks.
- Deliver payloads, shells, or implants.
- Integrate with `msfconsole`'s exploit flow, `hydra`, `medusa`, or
  `crackmapexec`'s attack modes.
- Disable its own scope check. There is no flag, no environment variable,
  and no debug build that turns it off.
- Modify, scan, or make any outbound request to a **target** from doctor.
  Doctor is workstation-setup only.

These are **hard guarantees**, not polite defaults.

## The aggregate-vs-execute line

Drederick is deliberately aggressive about enumeration surface — 14
scope-gated scanners, LLM-driven planning, CVE annotation, PoC source
caching. All of that stays on the "aggregate + present" side of a single
bright line:

> **Drederick aggregates and presents. Drederick does not execute.**

Concretely:

- **PoC aggregation.** Default-on (`--no-fetch-poc` opts out). We record
  pointers in `poc_refs` (source, external_id, url) and cache the verbatim
  PoC source in `out/poc_cache/<source>/<id>/` with SHA-256 provenance.
  We never run the cached PoC, never mark it executable, never import it
  as a module, never strip or neutralise phone-home (the practitioner sees
  exactly what's public).
- **CVE annotation.** We download NVD 2.0 JSON feeds to
  `~/.drederick/nvd/` and match fingerprinted services against them
  locally. We do not contact targets while annotating. `DREDERICK_SKIP_CVE=1`
  disables enrichment entirely.
- **Enrichment outbound traffic.** The only outbound requests Drederick
  makes outside the scanners themselves are to **public metadata sources**
  (NVD, GHSA, Exploit-DB archive mirrors). It never makes outbound requests
  to targets as part of enrichment, and never forwards any target data to
  third parties.
- **Doctor.** Modifies the operator's workstation only, at their consent,
  with the package manager they already have. Never re-execs as root,
  never contacts a target, never installs payloads or attack frameworks
  (Exploit-DB archive = reference material, not an attack tool).

If you find a way to make Drederick cross this line, treat it as a
security-critical bug. See "Reporting a security bug" below.

## `--lab` (default) vs `--no-lab`

Lab mode is on by default. It makes two narrow concessions for CTF/lab
ergonomics:

| Behavior                            | `--lab` (default)              | `--no-lab`                       |
| ----------------------------------- | ------------------------------ | -------------------------------- |
| Max IPv4 scope prefix (no override) | `/8`                           | `/16`                            |
| Max IPv6 scope prefix (no override) | `/32`                          | `/48`                            |
| NSE script categories               | `safe,default,discovery,version` | `safe,default`                 |
| Per-host `manual_commands.txt`      | emitted                        | not emitted                      |
| Per-host `notes.md` + `scans/`      | emitted                        | emitted                          |
| Exploit / brute / vuln scripts      | **never**                      | **never**                        |
| Credential attacks / payloads       | **never**                      | **never**                        |
| PoC *execution*                     | **never**                      | **never**                        |
| Wildcard scope (`0.0.0.0/0`)        | **refused**                    | **refused**                      |

The `discovery` and `version` NSE categories are *enumeration* categories — they
probe more actively than `safe,default` alone, but nmap's own maintainers do
not classify them as intrusive or exploit-adjacent. Drederick still excludes
`exploit`, `intrusive`, `brute`, `vuln`, `dos`, and `malware` in both modes.

`--allow-broad` is an orthogonal override that lifts the prefix cap entirely
(but still refuses `/0`). Use it only when your authorized lab range is
genuinely that large.

## Accidental out-of-scope run

If Drederick ever runs against a target it shouldn't have:

1. Stop the process (`Ctrl+C` works).
2. Preserve `out/` and `memory/findings.json` for incident review — the
   `audit.jsonl` has every scope decision, tool call, and argument.
3. Notify the owner of the unintended target.
4. Fix the scope file before the next run.

The scope file is intentionally a tiny, human-readable allow-list precisely so
this kind of mistake is easy to audit after the fact.

## Reporting a security bug

If you find a way to make Drederick touch a target outside its scope file,
make it run anything in an excluded NSE category, execute a cached PoC, or
make an outbound request *to a target* during enrichment or doctor, treat it
as a security-critical bug and open an issue (or a private report if the
repo enables one). Scope enforcement and the aggregate-vs-execute line are
the only features that matter more than correctness.
