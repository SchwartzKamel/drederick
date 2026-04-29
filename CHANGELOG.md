---
title: Changelog
audience: [humans]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - README.md
  - CONTRIBUTING.md
  - .github/workflows/release.yml
---

# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries accumulate under `[Unreleased]` until a tag is pushed. Tagged releases
publish via [`.github/workflows/release.yml`](.github/workflows/release.yml);
release notes are auto-generated from commits since the prior tag and appended
below this changelog via the release PR.

## [Unreleased]

### Added

- **Empire C2 integration** (`src/Drederick/Exploit/Empire/`) — BC-SECURITY/Empire
  post-exploitation framework integration for agent delivery and multi-module
  orchestration. New components:
  - `EmpireAgentStager` (implements `IPayloadTool`): generates platform-specific
    payloads (PowerShell, Python, Bash) for scope-validated targets.
  - `EmpireModuleExecutor` (implements `IExploitTool`): executes privilege
    escalation and lateral movement modules with scope re-validation on pivots.
  - `EmpireApiClient`: HTTP wrapper for Empire v3 API endpoints.
  - `SessionAgentMapper`: thread-safe registry mapping agent IDs to targets.
  - `IPayloadTool` interface abstraction for payload generation tools.
- `docs/EMPIRE.md` — operational guide for Empire integration: agent types,
  platform-specific workflows, module matrix, patterns, troubleshooting.
- `docs/C2_INTEGRATION.md` — architecture and extension guide for C2 subsystems:
  contracts, thread-safety, audit invariants, extension points for new frameworks.

### Changed

### Fixed

### Security

### Removed

## [0.3.1] — 2026-04-23

> _Drederick Tatum: "Believe me, my god, if I could turn back the clock on
> my mother's stair-pushing, I would certainly reconsider it."_
>
> Same-night polish on the v0.3.0 ring card. The LLM cornerman gets a
> spare when the main one is out, a provider factory so the CLI can pick
> its own trainer, and a lockdown test suite that leaves zero daylight on
> the scope invariant for AI-exposed tools.

### Added

- `HybridAgentRunner` — LLM-first agent wrapper with deterministic fallback
  (`src/Drederick/Agent/HybridAgentRunner.cs`). Non-scope exceptions trigger
  fallback with `hybrid.llm_fallback` audit event; `ScopeException` always
  propagates — the LLM-absent-or-broken path does not widen the blast radius.
  New CLI flag: `--agent=hybrid|llm|adaptive`.
- `LlmProviderFactory` — single entry point for constructing `CopilotLlmClient`,
  `AzureOpenAiLlmClient`, or `LlamaCppLlmClient` from CLI flags or environment
  (`src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs`). New CLI flags on
  `ctf-solve` (and `doctor`):
  - `--llm-provider=copilot|azure|llamacpp` (default: `copilot`)
  - `--azure-endpoint=<url>`, `--azure-api-version=<v>`,
    `--azure-deployment=modelId=deploymentName` (repeatable)
  - `--llamacpp-url=<url>`, `--llamacpp-model=modelId=modelName` (repeatable)
- `JeopardyDoctorChecks` is now provider-aware. `jeopardy.llm.token` verifies
  the configured provider's credentials (Copilot token, Azure endpoint +
  key / Entra, llama.cpp URL) instead of assuming Copilot. `jeopardy.llm.reachable`
  probes the configured endpoint.
- **LLM scope lockdown test suite.** Every `AIFunction` exposed to the
  `MicrosoftAgentRunner` now has a dedicated test asserting it refuses
  out-of-scope targets before any side effect. Covered via
  `tests/Drederick.Tests/Agent/LlmExploitToolsTests.cs` (+6 cases) and
  `tests/Drederick.Tests/Jeopardy/Llm/LlmFallbackIntegrationTests.cs` (new file).
  Audit evidence: `@invariant-id:llm-cannot-escape-scope` has teeth.

### Changed

- `MicrosoftAgentRunner` constructor now throws `ArgumentNullException` on
  null `chatClient` / `modelId` / `audit` instead of deferring to an NRE
  inside `agent.RunAsync`. Misuse is a clean, auditable failure mode.

### Fixed

- CI: `Doctor_NeverInstalls_FromWeb` converted to `async Task` to satisfy
  `xUnit1031` on .NET SDK 10.0.203 (`dotnet format --verify-no-changes`).
  v0.3.0 shipped with red CI on the last three commits because of this;
  subsequent commits on `main` are all green.
- Docs had several stale "planned" / "future" / "being wired" statements
  for work that actually shipped in v0.3.0 (Web UI Phases 2–4, Azure
  OpenAI, llama.cpp, provider switching). Full audit pass synced eleven
  files against the current code reality and added coverage for the new
  `HybridAgentRunner` and `LlmProviderFactory` across README, ARCHITECTURE,
  LLM_SETUP, JEOPARDY, TROUBLESHOOTING, COMPARISON, and AGENTS.
- `docs/SCOPE_AND_LEGAL.md` invariants table was missing the
  `no-exfiltration` and `scope-file-read-only` rows that were already
  present in the `AGENTS.md` mirror. Synced.

### Security / invariants

- No P0 scope-escape bug surfaced during the LLM lockdown audit — every
  `AIFunction` in `LlmExploitTools` already routed through `_scope.Require`
  before any side effect. The new tests make that a permanent contract.
- LLM provider secrets (Copilot token, Azure key, llama.cpp URL config)
  continue to be redacted via the shared `TokenRedactor`. The new factory
  does not expand the set of places secrets can be logged; the factory
  itself prints only presence / absence, never values.

## [0.3.0] — 2026-04-22

> _Drederick Tatum: "I'm heavyweight champ, Drederick Tatum."_
>
> Biggest release since v0.1.0. Full-auto offensive subsystem lands, the
> Jeopardy CTF solver swarm goes live, a dedicated browser UI ships, and
> the LLM cornerman wires up Copilot + Azure OpenAI + llama.cpp. Scope
> invariants are untouched — the ring is bigger, the rules still apply.

### Added — full-auto offensive subsystem

- `ExploitRunner`, `MsfRcRunner`, `NucleiRunner`, `MultiStageExploitRunner`,
  `PasswordSprayTool`, `SessionManager`, `SessionPivotProber`, `PostExLinux`,
  `PostExWindows` — each enforces `_scope.Require` on every target in argv
  (including pivots, LHOST/RHOSTS, session callbacks) and audits every spawn
  with argv SHA-256.
- `MsfRcRunner` Phase 2: unlocked payload-bearing modules (`PAYLOAD`, `CMD`,
  `LHOST`, `SRVHOST`, `EXITFUNC`, `post/*`) when `--allow-payloads` is opted
  in. `AutoRunScript`, `InitialAutoRunScript`, `PROXIES` remain always-forbidden.
- `NmapTool` aggressive NSE selection tied to opt-in flags: `--allow-exec-pocs`
  adds `intrusive,vuln,exploit`; `--allow-cred-attacks` (or lab mode) adds
  `auth`; `--allow-dos` adds `dos,malware`.
- `Autopilot` — post-recon exploitation loop (`AutopilotRunner`,
  `ExploitationPlanner`, `CredentialStore`, `FlagExtractor`, `AutopilotReporter`).
  Tatum-branded operator-facing messages.
- `LlmExploitTools` — LLM-driven `MicrosoftAgentRunner` exposes exploit tools
  as `AIFunction`s; scope re-check happens inside each tool, not at the
  agent boundary.

### Added — Jeopardy CTF solver

- `ChallengeSolver` + `SolverSwarm` with race semantics across multiple models
  per challenge.
- `CopilotLlmClient` (GitHub Copilot SDK multi-model), `AzureOpenAiLlmClient`
  (Entra + API key), `LlamaCppLlmClient` (OpenAI-compatible HTTP).
- `CtfdClient` (CTFd v3 REST), `CtfCoordinator` + `PollerService` for
  continuous challenge polling.
- `CostTracker` with budget enforcement, `LoopDetector`, `FlagSubmitCoordinator`
  with dedup, `OperatorInbox` for mid-run hint injection.
- `SandboxManager` — Docker-isolated CTF toolchain (`sandbox/Dockerfile`),
  `SandboxDoctorCheck` preflight.
- `PromptLibrary` — Tatum-voiced category-specific prompts.
- CLI subcommands: `ctf-solve`, `ctf-msg`.
- `JeopardyDoctorChecks` — `jeopardy.llm.token`, `jeopardy.llm.reachable`,
  sandbox preflight.

### Added — browser UI (`src/Drederick.Web`, `web/`)

- `DrederickHost` façade shared between CLI and the web app — scope-enforced
  tool calls from a single source of truth.
- REST endpoints: Health, Runs, Findings, Audit, Scope, Doctor, Jeopardy
  (34 total). All loot returns SHA-256 only; `MaybeNoDb<T>` wrapper for
  findings endpoints when `findings.db` is absent.
- SignalR hub (`EventsHub`) with bearer-token auth and per-group channels
  (runs/jeopardy/audit).
- React 19 + TanStack Router/Query SPA — 8 operator pages (Runs, Offensive,
  Findings, Jeopardy, Scope, Doctor, Audit, Notes).
- Tatum microcopy library (`web/src/lib/tatumisms.ts`) — "Start a bout",
  "Throw in the towel", "Wild. Not sanctioned by any governing body", etc.
- `RedactedValue` component — plaintext prop forbidden at type level.
- Playwright E2E suite: 23 passing invariants covering scope-file mtime
  stability, loot-never-plaintext, wildcard refusal, 8-route smoke,
  exploit-run redaction, no-database shape. Backend-boot fixtures mirror
  the authoritative `SqliteReport.cs` schema.

### Added — docs

- `docs/LLM_SETUP.md` — Copilot / Azure / llama.cpp cornerman wiring,
  Microsoft-first ordering, env var reference, `drederick doctor` LLM
  checks, troubleshooting rows. Tatum-voiced.
- `docs/WEB_UI.md` — operator guide for the browser UI + Playwright E2E
  running instructions.
- `docs/JEOPARDY.md` — solver workflow, model selection, budget guidance.
- `docs/POST_EXPLOITATION.md` — session + pivot + loot lifecycle.
- `docs/COMPARISON.md` — full rewrite for full-auto + Jeopardy reality.
- Full-suite audit pass across `docs/*.md` + `AGENTS.md` +
  `.github/copilot-instructions.md` for consistent full-auto framing.

### Changed

- **Lab/CTF mode now defaults `--allow-exec-pocs`, `--allow-cred-attacks`,
  `--allow-payloads`, and `--allow-destructive` to ON.** `--allow-dos` stays
  OFF by default. `--no-lab` flips every category back OFF. Credential
  attacks still require `--acknowledge-lockout-risk` explicitly.
- `ExploitToolbox.ToolBudget.Default` raised from `(2, 50)` to `(5, 200)`
  to let the planner iterate through module / payload / credential variants
  on a single target.

### Fixed

- CI: `Doctor_NeverInstalls_FromWeb` converted to async to satisfy xUnit1031
  on .NET SDK 10.0.203 (`dotnet format --verify-no-changes`).

### Security / invariants

- Every new tool (recon, exploit, credential, payload, Jeopardy) calls
  `_scope.Require(target)` as its first statement. E2E tests assert
  scope-file mtime is unchanged after a run, loot is never displayed in
  plaintext, and wildcard scope entries are refused.
- No new flag, env var, or prompt can disable the scope check or the
  audit log — invariant `@invariant-id:no-scope-kill-switch` holds.
- LLM provider secrets (Copilot token, Azure key, llama.cpp URL) are
  redacted from audit + UI surfaces; `TokenRedactor` shared across all
  three clients.
