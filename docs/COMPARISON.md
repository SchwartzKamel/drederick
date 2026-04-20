# Comparison: Drederick vs AutoRecon / nmapAutomator / Reconnoitre

A frank look at what Drederick does, what it doesn't, and when you'd reach for
one of the other tools instead.

| Capability                                  | Drederick            | AutoRecon          | nmapAutomator  | Reconnoitre    |
| ------------------------------------------- | -------------------- | ------------------ | -------------- | -------------- |
| Runtime                                     | .NET 10 / C#         | Python (asyncio)   | Bash           | Python         |
| Scope allow-list (refuses out-of-scope)     | **yes, in every tool** | configurable    | no             | no             |
| Hard-excludes `exploit`/`brute`/`vuln` NSE  | **yes**              | no (defaults safe) | no             | no             |
| Credential brute force                      | **no**               | no (by default)    | no             | no             |
| Full-range TCP + UDP tiering                | partial (nmap only)  | yes                | yes            | yes            |
| Per-service scanner fan-out                 | partial (HTTP/TLS/DNS today; more **planned**) | yes | limited   | yes        |
| Per-host working dir + notes                | **yes**              | yes                | yes            | yes            |
| Manual-commands cheatsheet                  | **yes (lab mode)**   | yes                | partial        | yes            |
| Adaptive / agentic planning                 | **yes (LLM optional)** | no               | no             | no             |
| Cross-run knowledge base                    | **yes**              | no                 | no             | no             |
| Point-and-click UI                          | **planned (React)**  | no                 | no             | no             |
| Distribution                                | single `dotnet publish` binary (planned self-contained) | `pip install` | shell script | `pip install` |

## When to pick what

- **Pick AutoRecon** if you want the most battle-tested CTF enumeration tool
  with the largest set of per-service scanners today and you're comfortable
  running it from a Python environment.
- **Pick nmapAutomator** for a lightweight shell script that wraps nmap tiers
  without a lot of ceremony.
- **Pick Reconnoitre** for a long-standing OSCP-style enumeration workflow.
- **Pick Drederick** when you need:
  - Strict default-deny scope enforcement baked into every tool, not a CLI
    flag.
  - Hard, non-bypassable exclusion of exploit/brute/vuln scripting.
  - An LLM-assisted adaptive planner that cannot escape the allow-list.
  - A cross-run knowledge base that treats repeated passes as deltas.
  - A point-and-click UX (once the React UI lands).

## What Drederick intentionally does not do

- Run exploits or PoCs.
- Brute-force credentials.
- Deliver payloads.
- Fetch exploit code from the internet.
- Auto-run `searchsploit` / `msfconsole` / `hydra` / `medusa` / `crackmapexec`
  attack modes.
- Offer an "I promise I'm authorized" flag that disables the scope check.

See [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) for the full policy.
