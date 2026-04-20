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
- Generates a **manual-commands cheatsheet** of further enumeration commands
  the operator *may* choose to run themselves.

### Does not, ever

- Run exploits, PoCs, or exploit-category NSE scripts.
- Perform credential brute force, password spray, or dictionary attacks.
- Deliver payloads, shells, or implants.
- Integrate with Metasploit, `msfconsole`, `hydra`, `medusa`, or
  `crackmapexec`'s attack modes.
- Fetch PoC code from the internet at runtime.
- Disable its own scope check. There is no flag, no environment variable, and
  no debug build that turns it off.

These are **hard guarantees**, not polite defaults.

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

If you find a way to make Drederick touch a target outside its scope file, or a
way to make it run anything in an excluded NSE category, treat it as a
security-critical bug and open an issue (or a private report if the repo
enables one). Scope enforcement is the only feature that matters more than
correctness.
