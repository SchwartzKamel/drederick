# Copilot instructions for drederick

Drederick is an **aggressive, scope-enforced reconnaissance harness** for
authorized lab/CTF targets. Mission: **win CTFs fast** by maximizing
enumeration coverage, parallelism, and adaptive planning *inside* the scope
allow-list. It is built in C# on **.NET 10** and the **Microsoft Agent
Framework**. Before making non-trivial changes, read `docs/ARCHITECTURE.md`,
`docs/DEVELOPING.md`, and `docs/SCOPE_AND_LEGAL.md`.

**Design stance: sharpen the fangs, don't file them down.** Prefer wider NSE
coverage over narrower, more concurrent scans over sequential, deeper
cheatsheets over thinner, and more adaptive LLM planning over fixed loops —
bounded only by the hard invariants below. Scope is the user's declaration of
authorized targets; they accept responsibility for what they put in it. Our
job is to exhaustively enumerate *everything inside that scope* as fast as
possible.

## Build, test, format

```bash
dotnet build
dotnet test
dotnet format
```

Run a single test:

```bash
dotnet test --filter "FullyQualifiedName~ScopeTests"
dotnet test --filter "FullyQualifiedName~NmapToolTests.ParsesServiceVersion"
```

Tests are xUnit under `tests/Drederick.Tests/`. Unit tests do **not** require
`nmap`; end-to-end runs do. The solution file is `Drederick.slnx`; shared
build props (`net10.0`, nullable on, implicit usings on, invariant
globalization) live in `Directory.Build.props`.

## Architecture in one paragraph

`CLI → Scope (default-deny allow-list) → ReconToolbox (Nmap/Http/Tls/Dns tools,
each recording to AuditLog JSONL and metered by ToolBudget) → Runner
(AdaptiveRunner deterministic, or MicrosoftAgentRunner LLM-driven) → Reporting
(JSON + Markdown + per-host workdir + `manual_commands.txt` in lab mode) +
Memory/KnowledgeBase (`memory/findings.json`, loaded on next run)`. Sources
live under `src/Drederick/{Agent,Audit,Cli,Memory,Recon,Reporting,Scope}/`.

## Non-negotiable invariants

Scope is the user's responsibility; *what we do inside scope* has these
hard-coded limits (they are the project's legal posture — do not weaken):

- **Scope is enforced inside every tool**, not at the CLI boundary. The first
  line of any method that touches the network must be `_scope.Require(target)`,
  which throws `ScopeException` on out-of-scope input. The LLM runner cannot
  escape it. No flag/env/prompt disables this.
- **Forbidden nmap NSE categories stay hard-coded excluded**: `exploit`,
  `intrusive`, `brute`, `vuln`, `dos`, `malware`. Lab uses
  `safe,default,discovery,version`; strict (`--no-lab`) uses `safe,default`.
- **Wildcards (`0.0.0.0/0`, `::/0`) always refused**, even with
  `--allow-broad`. Caps: lab `/8` v4 `/32` v6; strict `/16` v4 `/48` v6.
- **No exploitation, credential attacks, brute force, or payload delivery
  inside the tool's own execution.** Drederick may *collect and present*
  exploit/PoC information (CVE mappings, Exploit-DB entries, cached PoC
  source, Metasploit/nuclei references) into `manual_commands.txt` and
  `out/findings.db` for the practitioner to review — but it does not execute
  PoC code, does not auto-weaponize, and does not make outbound calls from
  fetched PoCs. The line is: **aggregate + present, never run.**
- Validate any LLM-chosen subprocess arguments — see
  `NmapTool.RejectUnsafePortSpec`.

Everything not on that list is fair game. Bias toward maximum enumeration.

## Where to be aggressive

When adding or tuning code, prefer the option that surfaces more data faster:

- **Parallelism first.** The roadmap's bounded `Channel<ScanJob>` worker pool
  with `--host-concurrency` / `--service-concurrency` is high-priority — any
  new scanner should assume it will run concurrently per-host and
  per-service. No shared mutable state outside `KnowledgeBase` / `AuditLog`,
  both of which must stay thread-safe.
- **Wider enumeration surface.** Roadmap scanners to implement aggressively:
  SMB (shares, sessions, OS), FTP (anon + banner), SSH (algos, host keys),
  SNMP (public community walk), LDAP (anonymous bind, naming contexts), RPC
  (endpoint mapper), Kerberos (**SPN listing only** — no AS-REP roast, no
  kerberoast), HTTP content-discovery (wordlist-driven, read-only), TLS
  cipher enumeration, DNS AXFR. Each re-checks scope inside the tool.
- **Deeper nmap within allowed NSE.** `safe,default,discovery,version` is a
  lot of surface — use it fully (service/version intensity, OS detection,
  script args where useful). Never reach for an excluded category to "just
  get one script."
- **Sharper LLM planning.** `MicrosoftAgentRunner` should plan the next probe
  from `KnowledgeBase` deltas, not re-scan known surface. Every new tool gets
  a precise `[Description(...)]` so the model picks it correctly. Keep
  `ToolBudget` tight enough that the agent is forced to prioritize.
- **Richer `manual_commands.txt`.** Lab-mode cheatsheet should give the
  operator everything they need to pivot fast: service-specific enum commands,
  common wordlist paths, credential-testing commands *the operator runs
  themselves*. Still: no exploit/brute/payload entries written by us.
- **Cross-run convergence.** `memory/findings.json` is the weapon that makes
  repeat runs fast — every scanner should write structured findings (not just
  raw text) so the next run diffs cleanly (new services, expired certs, drift).
- **Environment doctor / auto-provisioner (planned).** Ship a `drederick
  doctor` subcommand (and an implicit preflight before `run`) that detects
  required and recommended tooling on the host and offers to install what's
  missing. Target toolchain, roughly: `nmap`, `searchsploit` (Exploit-DB
  archive), `python3` + `python2` (many older PoCs need 2.7), `go` (many
  modern PoCs / `nuclei` / `httpx`), `ruby` (Metasploit-era PoCs), `git`,
  `curl`, `jq`, and Datasette (`pipx install datasette` or `uv tool install
  datasette`). Design points for future sessions:

  - **Detect first, install on consent.** Default behavior of the implicit
    preflight is *report + summarize* what's missing; actual install requires
    `--doctor-fix` or running `drederick doctor --install` explicitly. One
    confirmation per run is fine; silent `sudo` is not.
  - **Package-manager aware.** Detect `apt`/`dnf`/`pacman`/`zypper`/`brew`
    (macOS) and pick the right install recipe. Fall back to language-native
    installers (`pipx`, `uv tool install`, `go install`, `gem install
    --user-install`) when the system package is stale or missing.
  - **Never assume root.** If a step needs `sudo`, print the exact command
    and ask; don't re-exec ourselves with elevated privileges.
  - **Record to audit.** Every detection result and install action goes to
    `audit.jsonl` as `doctor.detect` / `doctor.install` events, and to a
    `tooling` table in `out/findings.db` (name, version, source, path) so
    Datasette shows what the harness has available.
  - **Offline-friendly.** In airgapped/CTF-VPN setups, doctor should still
    *report* accurately and point at a bundled `scripts/bootstrap.sh` for
    Debian/Ubuntu/Kali (the most common CTF base) rather than erroring out.
  - **Stays inside the invariant.** The doctor modifies the *operator's
    workstation* at their request; it never modifies, scans, or reaches out
    to any target. Installing `searchsploit` is environment setup, not
    recon.
- **CVE + PoC aggregation into SQLite (planned, high-priority).** For every
  fingerprinted service/version, annotate with CVEs (local NVD feed per the
  roadmap) and pull PoC references from public sources (Exploit-DB /
  `searchsploit`, GitHub security advisories, Metasploit module names,
  nuclei template IDs). Land everything in `out/findings.db` (SQLite) with a
  schema designed to be browsed via **Datasette** — tables roughly:
  `hosts`, `services`, `findings`, `cves`, `poc_refs` (url, source, cve_id,
  local_path), and `poc_sources` (cached PoC source from public archives).

  **PoC source caching is default-on** (`--fetch-poc` opt-out via
  `--no-fetch-poc`). The project's stance: a practitioner reviewing a CTF
  box offline needs the actual exploit source in hand, not just a link.
  Cache to `out/poc_cache/<source>/<id>` with provenance (source URL, fetch
  timestamp, SHA-256) recorded in `poc_sources`. Still scope-bound in
  spirit: only fetch PoCs for CVEs matching services found in the user's
  scope. Strip/neutralize any phone-home in fetched PoCs is **not** our job —
  we store verbatim so the practitioner sees exactly what's public.

  Invariant still holds: **Drederick collects and presents PoC
  references/source; Drederick does not execute them.** No auto-run, no
  auto-weaponize, no outbound connection *initiated from* a fetched PoC by
  Drederick itself.

## Conventions for new scanners

Follow `docs/DEVELOPING.md` §"Adding a new `IReconTool`":

1. New class under `src/Drederick/Recon/<Name>Tool.cs`, constructor-inject
   `Scope.Scope` and `AuditLog`.
2. `_scope.Require(target)` on entry; `audit.Record("<tool>.start"/".finish", …)`
   around the call.
3. Return a typed result on `HostFinding`; never leak raw stdout/stderr except
   as a bounded error field.
4. Shell-outs take the binary path via constructor so tests can stub with
   `/bin/true`.
5. Wire into `ReconToolbox`, add `[Description(...)]` on the public tool
   method (this is the LLM-visible surface), and update `ToolBudget`.
6. Tests required: a `ScopeException` test for out-of-scope input, parser
   tests against recorded fixtures, and a negative test proving no forbidden
   NSE category / subprocess flag is enabled.

## Test conventions

- Prefer in-memory / recorded fixtures (nmap XML, HTTP bodies).
- On-disk fixtures go under `Path.GetTempPath()` + a GUID and are cleaned up
  in `finally`.
- Every scanner **must** have a test asserting it refuses out-of-scope targets.

## Style

`.editorconfig` governs formatting: 4-space indent for C#, 2-space for
`csproj/props/json/yaml/md`, LF line endings, final newline, trim trailing
whitespace. Run `dotnet format` before committing.
