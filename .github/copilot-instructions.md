# Copilot instructions for drederick

> **Scope of this file.** Copilot-specific guidance. For the general-LLM
> (vendor-neutral) version — same invariants, extension points, and safety
> triggers, but surfaced as machine-readable tables for any agent — read
> [`../AGENTS.md`](../AGENTS.md). This file remains the canonical source for
> GitHub Copilot sessions; `AGENTS.md` is the mirror for other tools.

Drederick is a **full-auto offensive security harness** for authorized
lab / CTF / red-team targets. Mission: **compromise in-scope targets
fast** by maximizing enumeration coverage, exploitation automation,
parallelism, and adaptive planning *inside* the scope allow-list. Built
in C# on **.NET 10** and the **Microsoft Agent Framework**. Before making
non-trivial changes, read `docs/ARCHITECTURE.md`, `docs/DEVELOPING.md`,
and `docs/SCOPE_AND_LEGAL.md`. For the post-exploitation subsystem
(session dispatch, `PostExLinux`/`PostExWindows`, pivot discovery, flag
extraction, multi-stage chain), see `docs/POST_EXPLOITATION.md`.
Before touching LLM/model routing, prompts, tool descriptions, hybrid
fallback, Jeopardy swarm behavior, or benchmark reporting, read
`docs/MODEL_BEHAVIOR.md` and `.github/fight-history/INDEX.md`.

**Design stance: sharpen the fangs, then use them.** Prefer wider NSE
coverage over narrower, more concurrent scans over sequential, deeper
exploit corpora over thinner, and more adaptive LLM planning over fixed
loops — bounded only by the hard invariants below. Scope is the
operator's declaration of authorized targets; they accept responsibility
for what they put in it. Our job is to exhaustively enumerate **and
exploit** everything inside that scope as fast and as reliably as
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
`nmap`, `msfconsole`, or other offensive tooling; end-to-end runs do. The
solution file is `Drederick.slnx`; shared build props (`net10.0`, nullable
on, implicit usings on, invariant globalization) live in
`Directory.Build.props`.

## Architecture in one paragraph

`CLI → Scope (default-deny allow-list) → ReconToolbox + ExploitToolbox
(Nmap/Http/Tls/Dns/SMB/… plus ExploitRunner/MsfDriver/CredRunner/PayloadStager,
each recording to AuditLog JSONL and metered by ToolBudget) → Runner
(AdaptiveRunner deterministic, or MicrosoftAgentRunner LLM-driven) →
Reporting (JSON + Markdown + SQLite + per-host workdir + loot/ + sessions/)
+ Memory/KnowledgeBase (`memory/findings.json`, loaded on next run)`.
Sources live under `src/Drederick/{Agent,Audit,Autopilot,Bundling,Cli,
Doctor,Enrichment,Exploit,Host,Jeopardy,Memory,Ops,Recon,Reporting,Scope}/`.
The Avalonia operator console
(`src/Drederick.UI/`) is a point-and-click front-end that calls the same
scope-enforced tools via `DrederickHost` — see
[`docs/UI.md`](../docs/UI.md). The Jeopardy CTF mode (`ctf-solve` swarm,
`ctf-msg` operator hints, Docker sandbox, cross-solver bus, budget /
loop-detection rails) lives under `src/Drederick/Jeopardy/` — see
[`docs/JEOPARDY.md`](../docs/JEOPARDY.md).

## Non-negotiable invariants

Scope is the operator's responsibility. *Inside scope* Drederick is a
full-auto offensive tool — it may execute exploits, run credential
attacks, and deliver payloads. *Outside scope* it does nothing. These
are the hard-coded limits (they are the project's legal posture — do
not weaken):

- **Scope is enforced inside every tool**, not at the CLI boundary. The
  first line of any method that touches the network — recon, exploit,
  credential, or payload — must be `_scope.Require(target)`, which
  throws `ScopeException` on out-of-scope input. The LLM runner cannot
  escape it. No flag/env/prompt/jailbreak disables this.
- **Wildcards (`0.0.0.0/0`, `::/0`) always refused**, even with
  `--allow-broad`. Caps: lab `/8` v4 `/32` v6; strict `/16` v4 `/48` v6.
- **Subprocess argv is validated.** Any host/IP/URL in argv that could
  cause the subprocess to reach a target is resolved through
  `_scope.Require` before exec. This applies equally to nmap,
  `msfconsole -r`, `hydra`, `netexec`, `evil-winrm`, and any PoC
  spawned from `out/poc_cache/`. See `NmapTool.RejectUnsafePortSpec`
  and `ExploitRunner.AssertTargetsInScope`.
- **Audit everything.** Every PoC fetch, PoC spawn, credential attempt,
  payload delivery, and session open/close writes to `audit.jsonl` with
  target, tool, argv digest (SHA-256), and timestamp. Plaintext
  passwords are never logged; a SHA-256 of the attempted secret is
  recorded instead so the operator can correlate without leaking
  wordlists.
- **No kill switch.** There is no flag, env var, debug build, or prompt
  phrasing that disables the scope check or the audit log. Reviewers
  should reject any PR that proposes one.
- **No outbound exfiltration of loot.** Credentials, hashes, tickets,
  and captured secrets stay local to `out/` and `audit.jsonl`. No
  telemetry, no cloud sync, no "phone home" from the harness itself.
- **Scope file is read-only from code.** Scope authoring is a human
  act; code never writes to the scope file.
- **Destructive actions are opt-in per run.** `dos`/`malware` NSE,
  Metasploit modules flagged unstable, payload delivery in strict mode,
  and credential attacks without lockout-aware throttling require
  explicit `--allow-destructive` / `--allow-dos` / `--allow-payloads` /
  `--acknowledge-lockout-risk` flags. Default off even inside scope.

Everything not on that list is fair game inside scope. Bias toward
maximum capability.

## Where to be aggressive

When adding or tuning code, prefer the option that produces more
impact faster:

- **Parallelism first.** The bounded `Channel<ScanJob>` worker pool
  with `--host-concurrency` / `--service-concurrency` is the backbone
  for both recon and exploitation. Any new scanner or exploit module
  should assume it will run concurrently per-host and per-service. No
  shared mutable state outside `KnowledgeBase` / `AuditLog`, both of
  which must stay thread-safe.
- **Wider enumeration surface.** Roadmap scanners to implement
  aggressively: SMB (shares, sessions, OS), FTP (anon + banner), SSH
  (algos, host keys, user enum), SNMP (community brute + walk), LDAP
  (anon bind, naming contexts, user/group enum), RPC (endpoint mapper
  + null session), Kerberos (SPN listing, AS-REP roast, kerberoast
  where in scope), HTTP content-discovery (wordlist-driven), TLS
  cipher enumeration, DNS AXFR. Each re-checks scope inside the tool.
- **Full NSE surface inside scope.** `safe,default,discovery,version,
  auth,exploit,intrusive,vuln` are all available in lab mode. `dos`
  and `malware` are opt-in per run. In strict mode the defaults are
  conservative (`safe,default,discovery,version`) and categories are
  added via `--nse-categories=…`.
- **Automated exploitation.** `ExploitRunner` selects a cached PoC or
  Metasploit module based on fingerprinted services + CVE matches,
  validates target-in-scope, sets argv, spawns in an isolated working
  dir, and captures stdout/stderr/exit code. The LLM planner may
  choose the module; the scope check is still load-bearing.
- **Credential attack chain.** `CredRunner` supports password spray,
  targeted brute, AS-REP roast, kerberoast, PtH, and pivot-reuse of
  captured material. Lockout-aware throttling is default-on.
- **Payload delivery.** `PayloadStager` generates or accepts payloads
  (msfvenom-backed or operator-supplied), stages via authenticated
  admin interfaces, and records the drop in `audit.jsonl`.
- **Session handling.** Meterpreter / SSH / WinRM sessions are tracked
  in `out/sessions/`; post-ex actions (enum, loot, privesc) run under
  the session and re-check scope on any host they touch (pivoting).
- **Sharper LLM planning.** `MicrosoftAgentRunner` should plan the
  next probe **or** exploit step from `KnowledgeBase` deltas, not
  re-scan known surface. Every new tool gets a precise
  `[Description(...)]` so the model picks it correctly. Keep
  `ToolBudget` tight enough that the agent is forced to prioritize
  high-signal actions.
- **Richer `manual_commands.txt`.** Lab-mode cheatsheet gives the
  operator everything they need to pivot fast: service-specific enum
  commands, exploit one-liners keyed to matched CVEs, credential-
  testing commands, wordlist paths. These are suggestions for the
  operator to run manually; Drederick itself may also run them via
  `ExploitRunner` when the LLM or `AdaptiveRunner` selects them.
- **Cross-run convergence.** `memory/findings.json` is the weapon
  that makes repeat runs fast — every scanner and exploit module
  should write structured findings (services, CVEs, credentials
  captured, sessions opened) so the next run diffs cleanly. The
  fingerprint stack now ships a parallel learning layer:
  `LearnedFingerprintStore` + `FingerprintLearner`
  (`src/Drederick/Enrichment/FingerprintStack/`) auto-grow from each
  fight and persist at `out/memory/learned-fingerprints.json`.
  Between bouts the champ studies the tape; the corpus widens
  automatically.
- **Unified port-truth across recon signals.** Port presence is the
  union of nmap, the native TCP scanner, HTTP probes, TLS probes, and
  any other tool that confirms a live port — never nmap alone. The
  autopilot planner reads through
  `ExploitationPlanner.HarvestPortsFromAllSignals` so a port confirmed
  by a non-nmap signal still drives exploit selection. New scanners
  must publish their port observations into the same shared shape.
- **Fast host discovery for /N scopes.** `HostDiscoveryTool`
  (`src/Drederick/Recon/HostDiscoveryTool.cs`) does a native TCP-knock
  sweep before per-host fan-out, so the worker pool starts on
  confirmed-live hosts instead of burning cycles on dead address
  space. Use it as the prelude when the scope is broader than a
  handful of IPs.
- **Adaptive planning by archetype.** `ArchetypeClassifier` +
  `TargetArchetype` (`src/Drederick/Learning/`) classify each target
  (web, AD, file-share, …) so the runner biases enumeration depth and
  exploit selection per fight. New tools that benefit from
  archetype-aware dispatch should consume the classifier rather than
  hard-coding service-name heuristics.
- **No "recon-only" outcomes.** `MicrosoftAgentRunner.BuildSystemPrompt`
  and `BuildUserMessage` enforce a forcing function: the planner is
  expected to commit to an exploitation step whenever one is reachable
  inside scope. Do not soften that prompt; if the LLM has enough
  signal to act, it must act.
- **TLS validation callback — single source.** When wiring
  `SslStream`, set `RemoteCertificateValidationCallback` exactly once
  (the constructor or the property — not both). Double-set silently
  overrides the first callback and was the root cause of GAP-027.
  Examples in code or docs must follow the single-source pattern.
- **Environment doctor / auto-provisioner.** Ship `drederick doctor`
  (and an implicit preflight before `run`) that detects required and
  recommended tooling on the host and offers to install what's
  missing. Target toolchain: `nmap`, `searchsploit`, `metasploit-
  framework`, `impacket`, `nuclei`, `hashcat`, `john`, `hydra`,
  `netexec`, `evil-winrm`, `responder`, `python2`/`python3`, `go`,
  `ruby`, `git`, `curl`, `jq`, and Datasette (`pipx install
  datasette`). Design points:

  - **Detect first, install on consent.** Default behavior is report +
    summarize what's missing; actual install requires `--doctor-fix`
    or `drederick doctor --install` explicitly. One confirmation per
    run is fine; silent `sudo` is not.
  - **Package-manager aware.** Detect `apt`/`dnf`/`pacman`/`zypper`/
    `brew` and pick the right recipe. Fall back to `pipx`, `uv tool
    install`, `go install`, `gem install --user-install` when the
    system package is stale or missing.
  - **Never assume root.** If a step needs `sudo`, print the exact
    command and ask; don't re-exec ourselves with elevated privileges.
  - **Record to audit.** Every detection result and install action
    goes to `audit.jsonl` as `doctor.detect` / `doctor.install` and
    to a `tooling` table in `out/findings.db`.
  - **Offline-friendly.** In airgapped / CTF-VPN setups, doctor
    reports accurately and points at `scripts/bootstrap.sh` for
    Debian/Ubuntu/Kali rather than erroring out.
  - **Workstation only.** Doctor modifies the operator's workstation
    at their request; it never modifies, scans, or exploits any
    target. Installing Metasploit is environment setup, not recon
    and not exploitation.

- **CVE + PoC aggregation into SQLite (high-priority, maximalist).**
  For every fingerprinted service/version, annotate with CVEs (local
  NVD feed) and pull PoC references **and source** from every public
  source we can reach. Goal: a self-contained offline exploit corpus
  the practitioner and the LLM planner can read, diff, adapt, **and
  run** against in-scope targets. Land everything in
  `out/findings.db` (SQLite) with a Datasette-browsable schema —
  tables: `hosts`, `services`, `findings`, `cves`, `poc_refs` (url,
  source, cve_id, local_path), `poc_sources` (cached source, language,
  SHA-256, byte size, fetch timestamp, provenance URL), `exploit_runs`
  (target, artifact, argv_digest, exit_code, timestamp), `sessions`
  (target, protocol, opened_at, closed_at), `loot` (target, kind,
  value_digest, timestamp).

  Target sources for `IPocSource` implementations — each one is its
  own pluggable source, and we want **all of them** eventually,
  ranked by signal density:

  - **Exploit-DB** via local `searchsploit` (authoritative, offline).
  - **GitHub** — search for `CVE-YYYY-NNNNN` across public repos
    (`nomi-sec/PoC-in-GitHub`, `trickest/cve`,
    `ARPSyndicate/kenzer-templates`, ad-hoc query). Clone / raw-fetch
    referenced files, not just URLs.
  - **GitHub Security Advisories (GHSA)** — advisory text + referenced
    PoC commits/gists.
  - **Metasploit Framework** — module source at
    `rapid7/metasploit-framework` (`modules/exploits/**`,
    `modules/auxiliary/**`, `modules/post/**`). Cache the `.rb` and
    drive it via `msfconsole -r` when selected.
  - **Nuclei templates** — `projectdiscovery/nuclei-templates` (CVE
    folder). Cache the `.yaml` and drive it via `nuclei -t` when
    selected.
  - **PacketStorm Security** — advisory + PoC archive.
  - **Sploitus** aggregator.
  - **0day.today / inj3ct0r mirrors** where reachable.
  - **CXSecurity / WLB2** advisory archive.
  - **vulncode-db / Snyk advisories / OSV.dev** — structured metadata
    + any linked PoC.
  - **Vendor advisories** linked from NVD references — download and
    cache HTML/PDF for offline review.
  - **Researcher writeups** reachable via NVD reference URLs
    (HackerOne disclosed, Project Zero tracker, blog posts) — cache
    rendered text/HTML.
  - **Gists** referenced from any of the above.
  - **PyPI / npm / RubyGems / crates.io** — when a CVE maps to a
    poisoned package, cache advisory metadata and (where feasible)
    the fix diff so the vulnerable code path is visible.

  **Matching policy — prefer false positives over false negatives.**
  Match PoCs to findings liberally:

  - CPE-exact match (primary).
  - Product + version range match (`>= 1.2.0, < 1.2.7`).
  - Product-only match (low-confidence flag in `poc_refs.match_confidence`).
  - Banner/keyword match.
  - Related-CVE match (one-hop transitive).

  It is better to cache and be ready to run a PoC that turns out not
  to apply than to miss the one that does. Mark confidence in
  `match_confidence` and in the UI; do not suppress.

  **PoC source caching is default-on and aggressive** (`--no-fetch-poc`
  to disable; `--poc-sources=…` to subset). Cache every fetched
  artifact to `out/poc_cache/<source>/<external_id>/` with provenance
  (source URL, fetch timestamp, SHA-256, HTTP status, content-type)
  recorded in `poc_sources`. Store **verbatim** — never rewrite, never
  strip phone-home code, never sanitize. For repository-shaped sources
  (Metasploit, nuclei-templates, PoC-in-GitHub), shallow sparse
  checkout (`git clone --depth=1 --filter=blob:none`, then
  `sparse-checkout set`) is preferred.

  **PoC execution.** `ExploitRunner` may mark a cached artifact
  executable and spawn it against scope-validated targets. Defaults:
  lab mode executes on LLM/AdaptiveRunner selection; strict mode
  requires `--allow-exec-pocs`. Arguments are assembled from
  `KnowledgeBase` (target host, service port, captured credentials if
  any) and every target in argv is re-validated through
  `_scope.Require` immediately before spawn.

  **Size and rate discipline.** Default per-artifact cap 5 MB, per-run
  total cap 2 GB, tunable via `--poc-max-bytes-per-artifact` /
  `--poc-max-bytes-total`. Respect upstream rate limits; back off on
  429. Use authenticated GitHub API calls when `GITHUB_TOKEN` is set.
  Log every fetch to `audit.jsonl` as `poc.fetch` events with URL +
  SHA-256; every spawn as `poc.spawn` with argv digest + target +
  exit code.

## Conventions for new tools (recon or exploit)

Follow `docs/DEVELOPING.md` §"Adding a new `IReconTool`" /
"Adding a new `IExploitTool`":

1. New class under `src/Drederick/Recon/<Name>Tool.cs` or
   `src/Drederick/Exploit/<Name>Tool.cs`, constructor-inject
   `Scope.Scope` and `AuditLog`.
2. `_scope.Require(target)` on entry — for **every** host in argv,
   including pivots and redirect targets. `audit.Record("<tool>.start"
   / ".finish", …)` around the call; include argv digest.
3. Return a typed result on `HostFinding` / `ExploitResult`; never
   leak raw stdout/stderr except as a bounded field (truncate to
   64 KB + record full size + SHA-256).
4. Shell-outs take the binary path via constructor so tests can stub
   with `/bin/true`. Subprocess spawn uses a working directory under
   `out/<host>/<tool>/` so artifacts are isolated per target.
5. Wire into `ReconToolbox` / `ExploitToolbox`, add `[Description(...)]`
   on the public tool method (LLM-visible surface), and update
   `ToolBudget`.
6. Destructive / high-blast-radius tools check their per-run opt-in
   flag (`--allow-destructive`, `--allow-exec-pocs`,
   `--allow-cred-attacks`, `--allow-payloads`) and throw a descriptive
   error if absent.
7. Tests required:
   - `ScopeException` test for out-of-scope input (covers the primary
     target and any extra hosts in argv).
   - Parser / result-shape tests against recorded fixtures.
   - Argv-validation test proving shell-metachar / path-traversal /
     scope-bypass argv is rejected.
   - For exploit tools: a test that `ExploitRunner` refuses to spawn
     when any argv host fails `_scope.Require`.

## Test conventions

- Prefer in-memory / recorded fixtures (nmap XML, HTTP bodies,
  `msfconsole` output transcripts, `searchsploit` JSON).
- On-disk fixtures go under `Path.GetTempPath()` + a GUID and are
  cleaned up in `finally`.
- Every tool **must** have a test asserting it refuses out-of-scope
  targets. Exploit tools additionally must have a test that refuses
  when argv contains a mixed in-scope + out-of-scope target set.
- Tests must not actually spawn exploits against real services.
  Use subprocess stubs (`/bin/true`, `/bin/false`, fixture-replaying
  fake binaries under `tests/fixtures/bin/`).

## Style

`.editorconfig` governs formatting: 4-space indent for C#, 2-space for
`csproj/props/json/yaml/md`, LF line endings, final newline, trim
trailing whitespace. Run `dotnet format` before committing.

## Fuzzing

Ten `IFuzzTool` implementations live under `src/Drederick/Recon/Fuzz/`,
registered through `FuzzToolbox`. Each tool calls `_scope.Require(...)`
as its first network statement and writes start/finish/error events
to `audit.jsonl` with argv digests. `protocol-fuzz` is the only fuzzer
that additionally checks `RunPermissions.AllowDestructive`.

`AdaptiveRunner.ScheduleFuzzAsync(targets, recon, fuzz, ct)` is the
auto-scheduling entry point — `DrederickHost` calls it after the
recon pass when `RunOptions.EnableFuzz=true`. It dispatches
`header-fuzz`, `web-param-fuzz`, `api-endpoint-fuzz`, and (when the
service banner mentions GraphQL) `graphql-fuzz` against discovered
HTTP services.

Reference: [`docs/FUZZING.md`](../docs/FUZZING.md).

## Empire C2 Integration

Drederick integrates with [BC-SECURITY/Empire](https://github.com/BC-SECURITY/Empire/)
for post-exploitation agent delivery and multi-module orchestration. The subsystem
consists of:

- **`EmpireAgentStager`** (`src/Drederick/Exploit/Empire/`): Platform-aware payload
  generation (PowerShell, Python, Bash). Implements `IPayloadTool`.
- **`EmpireModuleExecutor`**: Privilege escalation + lateral movement module dispatch.
  Implements `IExploitTool`.
- **`EmpireModuleLibrary`**: Module fingerprint matcher (SeImpersonate → Potato, UAC
  bypass, sudo privesc, etc.).
- **`SessionAgentMapper`**: Thread-safe registry mapping agent_id → (target, platform,
  opened_at). Uses `ReaderWriterLockSlim` for concurrent enumeration.
- **`EmpireApiClient`**: HTTP client wrapper for Empire v3 API endpoints.

Every public method validates targets via `_scope.Require(target)` as its first
statement. Lateral movement re-checks scope on pivot targets.

Audit trail records every stager generation and module execution (success/error,
duration_ms, output_digest). No plaintext secrets are logged; SHA-256 digests only.

Reference: [`docs/EMPIRE.md`](../docs/EMPIRE.md) (operational guide),
[`docs/C2_INTEGRATION.md`](../docs/C2_INTEGRATION.md) (architecture/extension).

## v0.4.0 subsystems (LLM fight notebook, Windows MSRC, scaffolding, ZeroLogon, KB substitutions, Malleable C2)

The v0.4.0 cycle landed several subsystems Copilot sessions should know
about before editing related code paths:

- **LLM fight notebook** — `src/Drederick/Learning/FightNotebook.cs`,
  `FightNote.cs`, `FightCorpus.cs`, `FightLogSchema.cs`. The planner can
  call `LlmNotebookTool` (`src/Drederick/Agent/LlmNotebookTool.cs`,
  `take_note`) mid-round to record observations; entries land in
  `out/fight-notes.jsonl` (per-run) and `~/.drederick/fight-notebook.jsonl`
  (aggregate). The `drederick notebook {list,tail,show}` subcommand
  (`src/Drederick/Learning/Cli/`) is the operator browse surface. JSONL
  is append-only; do not rewrite past entries.
- **Windows MSRC corpus + `windows-vulns` subcommand** —
  `src/Drederick/Cli/WindowsVulnsCommand.cs` plus the embedded MSRC
  corpus under `src/Drederick/Exploit/Windows/`. `drederick windows-vulns
  list` enumerates known Windows vulns; `analyze --post-ex-json <path>`
  ingests a post-ex JSON snapshot (kernel build, hotfixes, running
  services) and surfaces matching CVEs with privesc paths.
- **Native ZeroLogon (CVE-2020-1472)** — `src/Drederick/Exploit/ZeroLogonTool.cs`
  is a pure-C# Netlogon RPC implementation; no external deps. Like every
  other exploit tool it re-checks scope on entry, requires
  `--allow-exec-pocs`, and audits start/finish events.
- **In-fight scaffolding loader (Tier 0+1+2)** —
  `src/Drederick/Scaffolding/` (`AttackGraph`, `AttackGraphLoader`,
  `BriefingDocument`, `BriefingLoader`, `ScaffoldingContext`,
  `ScaffoldingDiscovery`). Bootstraps the planner with prior-fight tapes,
  attack-graph hints, and pre-loaded briefings before the first probe so
  the LLM is not starting from a cold prompt.
- **`KbSubstitutionResolver`** — `src/Drederick/Exploit/Web/KbSubstitutionResolver.cs`.
  Resolves `{{kb.fingerprint.*}}` / `{{kb.cred.*}}` placeholders inside
  `CmsChainExecutor` steps from the live `KnowledgeBase`, so a chain
  template can reference earlier-fight findings without hard-coding them.
- **Malleable C2 profiles** — `src/Drederick/Exploit/Empire/MalleableProfileLibrary.cs`
  + bundled `.profile` corpus under `src/Drederick/Exploit/Empire/profiles/`,
  ported from BC-SECURITY/Malleable-C2-Profiles. `EmpireAgentStager`
  selects a profile per stage to obfuscate beacon traffic. New profiles
  go alongside the existing corpus; do not modify upstream profiles in
  place.

## Fight history and learning loop

Drederick is tested against real HTB machines. Every engagement — win or
loss — is catalogued so Copilot can learn from past fights and prioritize
development work that turns losses into wins.

### Key files

| File | Purpose |
|------|---------|
| `.github/fight-history/INDEX.md` | Master index of all fights with outcomes |
| `.github/fight-history/<fight-id>.md` | Per-fight structured brief |
| `.github/fight-gaps.md` | Aggregated gap tracker with stable IDs (GAP-NNN) |
| `.github/FIGHT_FEEDBACK.md` | Process: fight → triage → develop → rematch → close |
| `~/HTB/fight-log.yaml` | Structured YAML catalog of all engagements |
| `~/HTB/SCOREBOARD.md` | Win/loss record and improvement tracking |
| `~/HTB/REMATCH_PROTOCOL.md` | When and how to rematch |

### Before working on features

1. Read `fight-gaps.md` — know the open gaps and their severity
2. Skim `fight-history/INDEX.md` — understand the win/loss record
3. If your change addresses a gap, reference its GAP-ID in the commit message
4. Prioritize Critical gaps that affect multiple fights over nice-to-haves

### After an HTB engagement

1. Add a fight entry to `~/HTB/fight-log.yaml`
2. Create a fight brief in `.github/fight-history/<fight-id>.md`
3. Update `.github/fight-history/INDEX.md`
4. Triage new gaps into `.github/fight-gaps.md` with IDs and severity
5. Update `~/HTB/SCOREBOARD.md` with the new record
6. If it was a loss, add the box to the rematch queue in SCOREBOARD.md

### Rematch protocol

When gaps are fixed, schedule a rematch:
1. Check `~/HTB/REMATCH_PROTOCOL.md` for the process
2. Run drederick with the same flags as the original fight
3. Add a new fight-log entry with `rematch_of` linking to the original
4. Update gap statuses based on rematch results
5. A loss is only a loss if we learn nothing from it

### Model behavior for offensive security

Use `docs/MODEL_BEHAVIOR.md` as the durable guide and
`.github/fight-history/lame-model-benchmark-2026-04-30.md` as the latest
Lame benchmark tape. Preserve these contracts:

- Copilot SDK checks `/models`, audits model decisions, and defaults to
  `claude-haiku-4.5`.
- `CopilotModelCompliance` proves availability/policy/tool-call support,
  not offsec willingness or quality.
- Non-compliant Copilot model refusals propagate even under hybrid.
- Hybrid falls back only on operational/provider failures.
- `PermissionHandler.ApproveAll` is not the boundary; tool scope checks,
  argv validation, budgets, and audit are.
