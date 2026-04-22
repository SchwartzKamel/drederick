<!--
---
title: AGENTS.md — LLM entry point for drederick
audience: [agents]
primary: agents
stability: stable
last_audited: 2026-04
related:
  - .github/copilot-instructions.md
  - docs/README.md
  - docs/ARCHITECTURE.md
  - docs/SCOPE_AND_LEGAL.md
  - docs/DEVELOPING.md
  - docs/MODULES.md
  - docs/DB_SCHEMA.md
  - docs/POST_EXPLOITATION.md
  - docs/JEOPARDY.md
  - docs/COMPARISON.md
  - docs/CREDENTIALS.md
---
-->

# AGENTS.md

> **Scope of this file.** General-LLM entry point for the `drederick`
> repository. Copilot sessions should use
> [`.github/copilot-instructions.md`](.github/copilot-instructions.md) as the
> canonical source; this file is the vendor-neutral mirror for other agents
> (Cursor, Claude, Gemini, open-weights tools, etc.).

<a id="purpose"></a>
## Purpose

Drederick is a scope-enforced, adaptive **full-auto offensive security
harness** for **authorized targets only**. Within scope it discovers,
fingerprints, annotates services with CVE/PoC metadata, **executes
matching exploits, runs credential attacks, delivers payloads, and
handles post-exploitation**. Outside scope it does nothing. The scope
file is the authorization gate; it is default-deny and every
network-touching tool re-checks it internally.

<a id="invariants"></a>
## Invariants

> **Mirror.** Source of truth: [docs/SCOPE_AND_LEGAL.md#invariants](docs/SCOPE_AND_LEGAL.md#invariants). If these diverge, SCOPE_AND_LEGAL.md wins.

Each invariant carries a stable `@invariant-id:` anchor. These are hard
guarantees — do not weaken, remove, or route around them. They protect
the **authorization boundary** (scope) and the **audit trail**; they do
not restrict what Drederick may do *inside* that boundary. See
[`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) for the verbatim policy.

| id                              | Invariant |
| ------------------------------- | --------- |
| `@invariant-id:scope-in-every-tool` | Every method that touches the network — recon, exploit, credential, or payload — calls `_scope.Require(target)` **as its first statement**. No ambient scope, no CLI-boundary check. |
| `@invariant-id:scope-default-deny`  | `Scope` is a default-deny allow-list. No empty scope, no implicit targets, no wildcard fallback. |
| `@invariant-id:scope-wildcard-refused` | `0.0.0.0/0` and `::/0` are always refused — even with `--allow-broad`. |
| `@invariant-id:scope-prefix-cap` | Lab mode caps: `/8` v4, `/32` v6. Strict mode (`--no-lab`): `/16` v4, `/48` v6. `--allow-broad` lifts caps but not the wildcard refusal. |
| `@invariant-id:scope-is-authorization` | Scope is the **sole** authorization signal. Exploitation, credential attacks, PoC execution, and payload delivery are permitted only against scope-resolved targets — and are otherwise unrestricted within that boundary. |
| `@invariant-id:llm-cannot-escape-scope` | `MicrosoftAgentRunner` exposes tools as `AIFunction`s; every tool re-checks scope internally. The model cannot escape the allow-list regardless of prompt, jailbreak, or forged tool call. |
| `@invariant-id:subprocess-args-validated` | Any LLM-chosen or caller-chosen subprocess argument is validated before exec. Every host/IP/URL in argv is resolved through `_scope.Require`. Shell-metachar / path-traversal / scope-bypass argv is rejected. See `NmapTool.RejectUnsafePortSpec`, `SmbTool.AssertNoForbiddenScripts`, `ExploitRunner.AssertTargetsInScope`. |
| `@invariant-id:audit-everything` | Every exploitation step (PoC fetch, PoC spawn, credential attempt, payload drop, session open/close) writes to `audit.jsonl` with target, tool, argv digest (SHA-256), and timestamp. Plaintext passwords are never logged; a SHA-256 of the attempted secret is recorded instead. The audit log is append-only. |
| `@invariant-id:no-exfiltration` | Loot (credentials, hashes, tickets, captured secrets) stays local to `out/` and `audit.jsonl`. No telemetry, no cloud sync, no phone-home from the harness itself. |
| `@invariant-id:scope-file-read-only` | Scope authoring is a human act. Code never writes to the scope file. |
| `@invariant-id:doctor-workstation-only` | `drederick doctor` modifies the operator workstation at consent only. Never scans or exploits a target. Never re-execs as root. |
| `@invariant-id:thread-safety` | `AuditLog` and `KnowledgeBase` are thread-safe; everything else is stateless after construction. No shared mutable state outside those two. |
| `@invariant-id:no-scope-kill-switch` | There is no flag, env var, debug build, CLI prompt, or LLM instruction that disables the scope check or the audit log. Do not add one. |

<a id="commands"></a>
## Commands

> **Canonical reference.** README.md links here for the full list; prose in README.md carries examples only.

Build, test, and run commands you can rely on.

| Command | Purpose | Implemented in | Tests |
| ------- | ------- | -------------- | ----- |
| `dotnet build` | Build the solution (`Drederick.slnx`). | `Directory.Build.props`, `src/Drederick/Drederick.csproj` | n/a |
| `dotnet test` | Run all xUnit tests. | `tests/Drederick.Tests/` | self |
| `dotnet format` | Apply `.editorconfig`. | `.editorconfig` | n/a |
| `make quickstart` | Deps → build → publish → install the CLI globally (userspace). | `Makefile` | n/a |
| `make install-from-release` | Download the latest signed release binary via `scripts/install.sh`. | `Makefile`, `scripts/install.sh` | n/a |
| `curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh \| bash` | One-liner public installer (latest release, SHA-256 verified). Env: `VERSION`, `PREFIX`, `NO_VERIFY`. | `scripts/install.sh` | n/a |
| `drederick --scope … --target … --out out/` | Run a recon + exploit pass (lab mode default). | `src/Drederick/Cli/*`, `src/Drederick/Agent/*` | `tests/Drederick.Tests/**` |
| `drederick --scope … --target … --no-lab` | Strict-mode run (exploitation categories opt-in per flag). | `src/Drederick/Cli/*` | `tests/Drederick.Tests/**` |
| `drederick doctor [--install] [-y]` | Detect/install operator tooling. | `src/Drederick/Doctor/*` | `DoctorTests` |
| `drederick serve --out out/` | Launch Datasette against `findings.db`. | `src/Drederick/Cli/ServeCommand*` | `ServeCommandTests` (if present) |
| `drederick --scope … --target … --agent` | LLM-driven planner (requires `OPENAI_API_KEY`). | `src/Drederick/Agent/MicrosoftAgentRunner.cs` | `MicrosoftAgentRunnerTests` |
| `DREDERICK_SKIP_CVE=1 drederick …` | Skip CVE enrichment. | `src/Drederick/Enrichment/CveAnnotator.cs` | `CveAnnotatorTests` |
| `drederick --no-fetch-poc` | Skip PoC source caching. | `src/Drederick/Enrichment/PocAggregator.cs` | `PocAggregatorTests` |
| `drederick --allow-dos` / `--allow-destructive` / `--allow-exec-pocs` / `--allow-cred-attacks` / `--allow-payloads` / `--acknowledge-lockout-risk` | Per-run opt-ins for high-blast-radius categories (required in strict mode; defaults on in lab mode except `--allow-dos`). | `src/Drederick/Cli/*` | `OptInFlagTests` |
| `dotnet run --project src/Drederick.UI` | Launch the Avalonia point-and-click operator console. | `src/Drederick.UI/**`, `src/Drederick/Host/**` | `tests/Drederick.UI.Tests/**` |
| `drederick ctf-solve --scope … --ctfd <url> [--models <csv>]` | Jeopardy CTF swarm: race multiple LLMs across every challenge, auto-submit flags. | `src/Drederick/Jeopardy/**`, `src/Drederick/Cli/CommandLineOptions.cs` | `tests/Drederick.Tests/Jeopardy/**` |
| `drederick ctf-msg --kind <hint\|focus\|skip\|stop\|shutdown> [--challenge …] [--text …]` | Inject mid-run operator hint / control signal into a live `ctf-solve` session. | `src/Drederick/Jeopardy/Cli/**`, `src/Drederick/Jeopardy/Bus/**` | `tests/Drederick.Tests/Jeopardy/**` |
| `drederick --autopilot` | End-to-end recon → exploit → loot → session chain driven by `AutopilotRunner`. | `src/Drederick/Autopilot/**` | `AutopilotRunnerTests` |
| `drederick --agent=hybrid` | LLM-first runner with deterministic fallback on any operational failure (no key, network, auth, rate-limit, transient SDK error). `ScopeException` always propagates. | `src/Drederick/Agent/HybridAgentRunner.cs` | `HybridAgentRunnerTests` |
| `drederick ctf-solve … --llm-provider={copilot,azure,llamacpp}` | Pick the Jeopardy solver swarm backend at runtime. Copilot default; `--azure-endpoint` / `--azure-deployment` / `--llamacpp-url` / `--llamacpp-model` supply per-provider config. | `src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs` | `LlmProviderFactoryTests` |
| `drederick doctor --category=jeopardy [--llm-provider=…]` | Provider-aware Jeopardy preflight: Docker, sandbox image, `jeopardy.llm.token`, `jeopardy.llm.reachable`. | `src/Drederick/Doctor/JeopardyDoctorChecks.cs` | `JeopardyDoctorChecksTests` |
| `drederick web [--web-bind <host>] [--web-port <int>] [--web-token <value>]` | Launch the browser operator pane (ASP.NET Core + SignalR + React SPA). Loopback + no-auth by default; non-loopback binds require a bearer token (auto-generated to `out/web-token.txt` if not supplied). | `src/Drederick.Web/**`, `web/**` | `tests/Drederick.Tests/Web/**`, `web/e2e/**` |

Continuous integration is wired in [`.github/workflows/ci.yml`](.github/workflows/ci.yml);
release artifacts via [`.github/workflows/release.yml`](.github/workflows/release.yml).

<a id="file-concept-map"></a>
## File → concept map

Authoritative mapping of source locations to concepts. When making
surgical edits, identify the owning concept first.

| Path | What lives there | Owner scope (agent) |
| ---- | ---------------- | ------------------- |
| `src/Drederick/Scope/` | `Scope`, `ScopeLoader`, `ScopeException`, prefix caps. | scope-policy |
| `src/Drederick/Recon/` | `IReconTool` scanners + `ReconToolbox`. | recon-tools |
| `src/Drederick/Recon/HostFinding.cs` | Typed recon result shapes. | recon-results |
| `src/Drederick/Exploit/` | `IExploitTool` / `ExploitRunner` / `MsfDriver` / `CredRunner` / `PayloadStager` + `ExploitToolbox`. | exploit-tools |
| `src/Drederick/Exploit/ExploitResult.cs` | Typed exploit / cred / payload / session result shapes. | exploit-results |
| `src/Drederick/Agent/AdaptiveRunner.cs` | Deterministic rule-based planner (recon + exploit). | orchestration |
| `src/Drederick/Agent/MicrosoftAgentRunner.cs` | LLM-driven planner (Microsoft Agent Framework). | orchestration-llm |
| `src/Drederick/Agent/HostWorkerPool.cs` | Bounded `Channel<ScanJob>` pool. | concurrency |
| `src/Drederick/Audit/AuditLog.cs` | Append-only JSONL audit log (thread-safe). | audit |
| `src/Drederick/Cli/` | Command-line options, subcommands, help text. | cli |
| `src/Drederick/Cli/Program.cs` | DI wiring + subcommand dispatch. Edit with unique anchors (see [Agent coordination](#agent-coordination)). | cli-wiring |
| `src/Drederick/Doctor/` | Operator-workstation preflight + installer. | doctor |
| `src/Drederick/Enrichment/NvdCache.cs` | NVD 2.0 feed download/cache. | enrichment-nvd |
| `src/Drederick/Enrichment/CpeMatcher.cs` | `(vendor,product,version) → cve` matching. | enrichment-match |
| `src/Drederick/Enrichment/CveAnnotator.cs` | Applies CVE findings to `HostFinding`. | enrichment-cve |
| `src/Drederick/Enrichment/PocAggregator.cs` | Iterates `IPocSource`s, caches PoC artifacts. | enrichment-poc |
| `src/Drederick/Enrichment/SearchsploitSource.cs` | Exploit-DB source via local `searchsploit`. | enrichment-poc |
| `src/Drederick/Memory/KnowledgeBase.cs` | Cross-run state (`memory/findings.json`). | memory |
| `src/Drederick/Reporting/JsonReport.cs` | `out/report.json`. | reporting |
| `src/Drederick/Reporting/MarkdownReport.cs` | `out/report.md`. | reporting |
| `src/Drederick/Reporting/ManualCommandsCheatsheet.cs` | `out/<host>/manual_commands.txt`. | reporting |
| `src/Drederick/Reporting/SqliteReport.cs` | **Authoritative schema DDL** for `findings.db` (includes `exploit_runs`, `sessions`, `loot`). | reporting-db |
| `src/Drederick/Host/` | `DrederickHost` façade + `ScanEvent` / `RunOptions` shared by CLI and UI. | ui-shell |
| `src/Drederick.UI/` | Avalonia point-and-click operator console. | ui-shell |
| `tests/Drederick.UI.Tests/` | ViewModel + invariant tests for the UI shell. | ui-shell |
| `datasette/metadata.json` | Datasette labels, facets, canned queries. | datasette |
| `tests/Drederick.Tests/` | xUnit tests. | tests |
| `tests/fixtures/` | Recorded scanner/exploit fixtures (nmap XML, HTTP bodies, msfconsole transcripts, searchsploit JSON). | fixtures |
| `tests/fixtures/bin/` | Fake subprocess binaries for exploit-tool testing (replay stdout/exit). | fixtures |
| `docs/` | Human+agent docs (see [`docs/README.md`](docs/README.md)). | docs |
| `Makefile` | `quickstart`, `bootstrap`, `publish`, `install` targets. | build |
| `.github/workflows/ci.yml` | CI build + test. | ci |
| `.github/workflows/release.yml` | Release artifact pipeline. | release |
| `src/Drederick/Jeopardy/Ctfd/` | `CtfdClient` — CTFd v3 API client (list challenges, submit flag, track solves). | jeopardy-ctfd |
| `src/Drederick/Jeopardy/Llm/` | Multi-backend LLM wiring (Copilot SDK, Azure OpenAI, llama.cpp). | jeopardy-llm |
| `src/Drederick/Jeopardy/Sandbox/` | `Dockerfile.jeopardy-sandbox`, sandbox launcher, `--network none` policy. | jeopardy-sandbox |
| `src/Drederick/Jeopardy/Solver/` | Per-category solver loops (web / crypto / pwn / rev / forensics / misc / osint). | jeopardy-solver |
| `src/Drederick/Jeopardy/Swarm/` | `SolverSwarm` — races multiple models per challenge; first-to-solve wins. | jeopardy-swarm |
| `src/Drederick/Jeopardy/Coordinator/` | `FlagSubmitCoordinator`, solve dedup, challenge-state machine. | jeopardy-coordinator |
| `src/Drederick/Jeopardy/Bus/` | `SolverMessageBus` — cross-solver hint bus + operator `ctf-msg` injection. | jeopardy-bus |
| `src/Drederick/Jeopardy/Budget/` | `CostTracker`, `BudgetExceededException`, per-challenge token caps. | jeopardy-budget |
| `src/Drederick/Jeopardy/Detection/` | `LoopDetector` — exact-repeat / AB-oscillation / no-progress detection. | jeopardy-detection |
| `src/Drederick/Jeopardy/Prompts/` | Category-specific Tatum-voiced prompt templates. | jeopardy-prompts |
| `src/Drederick/Jeopardy/Cli/` | `ctf-solve` / `ctf-msg` subcommand handlers. | jeopardy-cli |
| `src/Drederick/Jeopardy/Submit/` | Flag-submission pipeline with plaintext redaction. | jeopardy-submit |
| `src/Drederick/Jeopardy/Ops/` | Jeopardy operational helpers (run state, reporting). | jeopardy-ops |
| `src/Drederick/Autopilot/` | `AutopilotRunner`, `ExploitationPlanner`, `CredentialStore`, `FlagExtractor`, `AutopilotReporter`. | autopilot |
| `src/Drederick/Ops/` | Operational helpers: `HtbRanges`, `VpnDetector`. | ops |
| `src/Drederick/Bundling/` | `DatasetteBootstrap`, `BootstrapOptions` (bundled Datasette bring-up). | bundling |
| `src/Drederick/Agent/HybridAgentRunner.cs` | LLM-first recon runner with automatic fallback to the deterministic runner on operational failure; `ScopeException` / `OperationCanceledException` always propagate. Wired via `--agent=hybrid`. | orchestration-hybrid |
| `src/Drederick/Agent/LlmExploitTools.cs` | LLM-visible `AIFunction` wrappers around the exploit toolbox for `MicrosoftAgentRunner`. Every wrapper re-checks scope + `RunPermissions` before dispatch. | orchestration-llm |
| `src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs` | Provider switch for `ctf-solve` and `drederick doctor --category=jeopardy`. Parses `--llm-provider={copilot,azure,llamacpp}` and builds the matching `ICopilotLlmClient`. | jeopardy-llm |
| `src/Drederick.Web/` | ASP.NET Core minimal API + SignalR hub (`EventsHub`) serving the React SPA from `wwwroot/`. Bearer-token middleware on non-loopback binds. Owned by `ui-shell`. | ui-shell |
| `web/` | Vite + React + TypeScript SPA for the Web UI. 8 operator pages, Playwright E2E under `web/e2e/`. | ui-shell |

<a id="extension-points"></a>
## Extension points

### Adding a recon scanner — see [`docs/DEVELOPING.md#adding-scanner`](docs/DEVELOPING.md#adding-scanner)

Checklist (enforced by tests):

1. New class `src/Drederick/Recon/<Name>Tool.cs` implementing `IReconTool`.
2. Constructor-inject `Scope.Scope`, `AuditLog`, and any subprocess factory.
3. First statement of every public method: `_scope.Require(target)`.
4. Bracket with `audit.Record("<name>.start" / ".finish", …)`; include
   argv digest.
5. Add typed result to `HostFinding.cs`.
6. Validate subprocess argv (regex whitelist / denylist; every host in
   argv re-checked via `_scope.Require`).
7. Wire into `ReconToolbox`; expose via `[Description(...)]` on toolbox
   method + params.
8. Update `ToolBudget` if default `(3 per tool per target, 200 global)`
   is wrong.
9. Register in `Program.cs` (see [Agent coordination](#agent-coordination)
   for merge-safe edits).
10. Extend `AdaptiveRunner` for auto-dispatch if applicable.
11. Tests: `ScopeException` negative, parser against fixture, argv-
    injection negative.

### Adding an exploit / credential / payload tool — see [`docs/DEVELOPING.md#adding-exploit`](docs/DEVELOPING.md#adding-exploit)

Checklist (enforced by tests):

1. New class `src/Drederick/Exploit/<Name>Tool.cs` implementing
   `IExploitTool` (or `ICredTool` / `IPayloadTool`).
2. Constructor-inject `Scope.Scope`, `AuditLog`, and the appropriate
   subprocess factory.
3. First statement of every public method: `_scope.Require(target)`.
   For multi-host argv (pivots, LHOST/RHOSTS, session callbacks),
   call `ExploitRunner.AssertTargetsInScope(hosts)` before exec.
4. Check the per-category opt-in flag (`--allow-exec-pocs`,
   `--allow-cred-attacks`, `--allow-payloads`, `--allow-destructive`,
   `--allow-dos`) and throw a descriptive error if absent in the
   current run configuration.
5. Bracket with `audit.Record("<name>.start" / ".finish", …)`; include
   argv digest, target, PoC SHA-256 if applicable.
6. Add typed result to `ExploitResult.cs` (or the analogous shape).
7. Isolate subprocess working dir to `out/<host>/<tool>/`; truncate
   captured stdout/stderr at 64 KB and record full size + SHA-256.
8. Do not log plaintext credentials. Record SHA-256 of attempted
   secrets and success/fail state only.
9. Wire into `ExploitToolbox`; expose via `[Description(...)]`.
10. Tests:
    - Out-of-scope target rejected (primary and any extra argv hosts).
    - Opt-in flag absent → tool refuses cleanly.
    - Argv injection / shell-metachar rejected.
    - `ExploitRunner` refuses spawn when mixed in-/out-of-scope argv
      is supplied.
    - No plaintext secret appears in recorded audit events (use a
      canary string).

### Adding an enrichment source — see [`docs/DEVELOPING.md#adding-enrichment`](docs/DEVELOPING.md#adding-enrichment)

- PoC source: implement `IPocSource`, cache to
  `out/poc_cache/<source>/<external_id>/`, record SHA-256, byte size,
  content-type, and provenance URL in `poc_sources`. Store **verbatim**
  — no rewriting, no phone-home neutralization, no sanitization.
  `ExploitRunner` is responsible for marking executable and spawning;
  the source itself does not execute. Priority sources: GitHub (via
  `nomi-sec/PoC-in-GitHub`, `trickest/cve`, raw-file fetch), Metasploit
  module source (`rapid7/metasploit-framework`, sparse checkout of
  `modules/exploits` + `modules/auxiliary` + `modules/post`), nuclei
  templates (`projectdiscovery/nuclei-templates`), PacketStorm,
  Sploitus, GHSA, CXSecurity, 0day.today mirror, vendor advisory
  HTML/PDF linked from NVD references, writeups (HackerOne disclosed,
  Project Zero tracker). Match liberally: CPE-exact > product +
  version range > product-only > banner keyword > one-hop related-CVE.
  Record `match_confidence` in `poc_refs`; prefer false positives over
  false negatives. See `SearchsploitSource.cs` for the baseline shape.
- CVE feed: loader alongside `NvdCache.cs`, cache at
  `~/.drederick/<name>/`, matcher compatible with `CpeMatcher` output.

### Adding a Datasette canned query — see [`docs/DEVELOPING.md#adding-query`](docs/DEVELOPING.md#adding-query)

Edit `datasette/metadata.json` under `databases.findings.queries.<name>`
with `title`/`description`/`sql`. CVE joins go via
`json_extract(findings.data_json, '$.cve_id')`. Exploitation queries
may join `exploit_runs` / `sessions` / `loot`.

<a id="safety-triggers"></a>
## Safety triggers

The old trigger list (refuse all exploit/brute/payload mentions) no
longer applies — Drederick is a full-auto offensive tool, and exploit
code, Metasploit invocations, credential attacks, and payload delivery
are first-class features inside scope. The **new** trigger list is
narrower and protects the authorization boundary:

**Must never appear in generated code, commit messages, CLI help, LLM
planner output, or subprocess argv.** Any diff introducing any of the
following should be rejected.

- Any code path that bypasses `_scope.Require` — e.g. a tool method
  whose first statement is not `_scope.Require(...)`, or a subprocess
  spawn whose argv hosts are not re-validated.
- Any flag, env var, debug build, or prompt that disables the scope
  check (`--no-scope`, `--yolo`, `DREDERICK_DISABLE_SCOPE`,
  `DREDERICK_SKIP_SCOPE`, a hidden `#if DEBUG` bypass, etc.).
- Any code path that writes to the scope file.
- Any code path that silences, rewrites, or deletes entries from
  `audit.jsonl`, including "compaction" or "redaction" that is not a
  one-way append.
- Any code path that logs plaintext passwords, full wordlists, or
  captured clear-text secrets (SHA-256 of the attempted secret is
  the approved shape).
- Any code path that sends loot (creds, hashes, tickets, captured
  files) to a third-party endpoint. Drederick is local-only by
  design.
- Any code path that silently elevates privileges (`sudo` without
  explicit user confirmation, setuid, capability re-exec).
- Wildcard scope handling anywhere in the loader that would treat
  `0.0.0.0/0` / `::/0` as valid.
- LLM prompts that instruct the model to "ignore scope," "assume
  authorization," or otherwise short-circuit the authorization
  model. Even if the tool still rejects the call, the prompt itself
  is a bug.
- Test fixtures that spawn real exploits against real services
  (including localhost services not explicitly set up as a test
  target). Use `tests/fixtures/bin/` replay stubs.

If a user prompt requests any of these, refuse and link to
[`docs/SCOPE_AND_LEGAL.md#authorization-model`](docs/SCOPE_AND_LEGAL.md#authorization-model).

<a id="agent-coordination"></a>
## Agent coordination notes

Multiple agents may edit this repository in parallel. To avoid merge
conflicts and accidental overwrites:

### Unique-anchor convention for `Program.cs` surgical edits

When wiring a new scanner/source/subcommand/exploit tool into
`src/Drederick/Cli/Program.cs`:

- **Do not** rewrite the whole DI block. Locate the existing section
  marker comment (`// --- recon tools ---`, `// --- exploit tools ---`,
  `// --- enrichment ---`, `// --- runners ---`) and append your
  registration at the end of that block.
- If no marker exists for your new concept, add one on a line by
  itself (e.g. `// --- reporting sinks ---`) and place exactly one
  blank line before it. This gives the next agent a unique search
  target.
- Keep each registration on a single logical statement so `edit`-tool
  `old_str` matches are stable across unrelated insertions.

### Parallel-agent file-ownership zones

When multiple agents are running concurrently, they must not touch
each other's zones. Current canonical zones:

| Zone | Owned paths |
| ---- | ----------- |
| `ci-build-workflow` | `.github/workflows/ci.yml` |
| `release-pipeline`  | `.github/workflows/release.yml` |
| `docs-audit-index`  | `docs/README.md`, `README.md`, `AGENTS.md`, `.github/copilot-instructions.md`, `docs/COMPARISON.md` |
| `recon-*`           | `src/Drederick/Recon/**` |
| `exploit-*`         | `src/Drederick/Exploit/**` |
| `enrichment-*`      | `src/Drederick/Enrichment/**` |
| `scope-policy`      | `src/Drederick/Scope/**` |
| `ui-shell`          | `src/Drederick.UI/**`, `tests/Drederick.UI.Tests/**`, `src/Drederick/Host/**` |
| `autopilot`         | `src/Drederick/Autopilot/**` |
| `ops`               | `src/Drederick/Ops/**` |
| `bundling`          | `src/Drederick/Bundling/**` |
| `jeopardy-*`        | `src/Drederick/Jeopardy/**` (sub-zones per subdirectory: `jeopardy-ctfd`, `jeopardy-llm`, `jeopardy-sandbox`, `jeopardy-solver`, `jeopardy-swarm`, `jeopardy-coordinator`, `jeopardy-bus`, `jeopardy-budget`, `jeopardy-detection`, `jeopardy-prompts`, `jeopardy-cli`, `jeopardy-submit`, `jeopardy-ops`) |
| `docs-audit-index`    | (see above — narrowed zone) |

| `docs-audit-reference`| `docs/SCOPE_AND_LEGAL.md`, `docs/DEVELOPING.md`, `docs/MODULES.md`, `docs/DB_SCHEMA.md`, `docs/ARCHITECTURE.md` |
| `docs-audit-*`        | per-doc zones under `docs/**` (one owner per file during concurrent audits) |

Before editing, check this table and the working agent list. If two
scopes overlap, coordinate via issue comments — do not racewrite.

### How to avoid merge conflicts

- **Never reflow unrelated prose** when adding a sentence. Prepend or
  append; don't reformat a paragraph you aren't changing.
- **Add, don't replace** in tables. Append new rows at the end unless
  alphabetical order is documented.
- **Frontmatter is idempotent**: if a file already has a `---` block,
  edit keys in place; don't re-emit the whole block.
- **Anchors are append-only**: once an anchor id (`{#foo}` or
  `<a id="foo">`) is published, it is part of the public surface. Do
  not rename.

<a id="canonical-sources"></a>
## Canonical sources (read these before acting)

1. [`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) — hard guarantees.
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers + threading.
3. [`docs/MODULES.md`](docs/MODULES.md) — per-tool contracts (recon + exploit).
4. [`docs/DEVELOPING.md`](docs/DEVELOPING.md) — how to extend.
5. [`docs/DB_SCHEMA.md`](docs/DB_SCHEMA.md) — machine-readable schema.
6. [`docs/DATASETTE.md`](docs/DATASETTE.md) — current UI + triage workflow.
7. [`.github/copilot-instructions.md`](.github/copilot-instructions.md) —
   Copilot-specific version of this file (for Copilot sessions).
8. [`docs/POST_EXPLOITATION.md`](docs/POST_EXPLOITATION.md) — after the
   bell: session dispatch, Linux/Windows enumeration, pivot discovery,
   flag extraction.
