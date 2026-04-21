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

Drederick is a scope-enforced, adaptive reconnaissance harness for
**authorized lab/CTF targets only**: it discovers, fingerprints, annotates
services with CVE/PoC metadata, and **never executes exploits, PoCs, brute
force, credential attacks, or payload delivery**.

<a id="invariants"></a>
## Invariants

Each invariant carries a stable `@invariant-id:` anchor. These are hard
guarantees — do not weaken, remove, or route around them. See
[`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) for the verbatim policy.

| id                              | Invariant |
| ------------------------------- | --------- |
| `@invariant-id:scope-in-every-tool` | Every method that touches the network calls `_scope.Require(target)` **as its first statement**. No ambient scope, no CLI-boundary check. |
| `@invariant-id:scope-default-deny`  | `Scope` is a default-deny allow-list. No empty scope, no implicit targets. |
| `@invariant-id:scope-wildcard-refused` | `0.0.0.0/0` and `::/0` are always refused — even with `--allow-broad`. |
| `@invariant-id:scope-prefix-cap` | Lab mode caps: `/8` v4, `/32` v6. Strict mode (`--no-lab`): `/16` v4, `/48` v6. `--allow-broad` lifts caps but not the wildcard refusal. |
| `@invariant-id:nse-forbidden-categories` | `exploit`, `intrusive`, `brute`, `vuln`, `dos`, `malware` are **hard-coded excluded** in both lab and strict modes. |
| `@invariant-id:aggregate-not-execute` | Drederick aggregates + presents CVE/PoC metadata. It never executes PoCs, never `chmod +x`, never spawns fetched code, never makes the outbound call a PoC would have made. |
| `@invariant-id:no-credential-attacks` | No brute force, password spray, dictionary attack, AS-REP roast, kerberoast, hydra-style loop, or credential-guessing. SPN listing is anonymous-bind read only. |
| `@invariant-id:no-payload-delivery` | No shells, implants, webshells, persistence, or payload staging — ever. |
| `@invariant-id:llm-cannot-escape-scope` | `MicrosoftAgentRunner` exposes tools as `AIFunction`s; every tool re-checks scope internally. The model cannot escape the allow-list regardless of prompt. |
| `@invariant-id:subprocess-args-validated` | Any LLM-chosen or caller-chosen subprocess argument is validated before exec. See `NmapTool.RejectUnsafePortSpec` and `SmbTool.AssertNoForbiddenScripts`. |
| `@invariant-id:doctor-workstation-only` | `drederick doctor` modifies the operator workstation at consent only. Never scans a target. Never re-execs as root. |
| `@invariant-id:thread-safety` | `AuditLog` and `KnowledgeBase` are thread-safe; everything else is stateless after construction. No shared mutable state outside those two. |
| `@invariant-id:no-scope-kill-switch` | There is no flag, env var, debug build, or prompt that disables the scope check. |

<a id="commands"></a>
## Commands

Build, test, and run commands you can rely on.

| Command | Purpose | Implemented in | Tests |
| ------- | ------- | -------------- | ----- |
| `dotnet build` | Build the solution (`Drederick.slnx`). | `Directory.Build.props`, `src/Drederick/Drederick.csproj` | n/a |
| `dotnet test` | Run all xUnit tests. | `tests/Drederick.Tests/` | self |
| `dotnet format` | Apply `.editorconfig`. | `.editorconfig` | n/a |
| `make quickstart` | Deps → build → publish → install the CLI globally (userspace). | `Makefile` | n/a |
| `make install-from-release` | Download the latest signed release binary via `scripts/install.sh`. | `Makefile`, `scripts/install.sh` | n/a |
| `curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh \| bash` | One-liner public installer (latest release, SHA-256 verified). Env: `VERSION`, `PREFIX`, `NO_VERIFY`. | `scripts/install.sh` | n/a |
| `drederick --scope … --target … --out out/` | Run a recon pass. | `src/Drederick/Cli/*`, `src/Drederick/Agent/*` | `tests/Drederick.Tests/**` |
| `drederick doctor [--install] [-y]` | Detect/install operator tooling. | `src/Drederick/Doctor/*` | `DoctorTests` |
| `drederick serve --out out/` | Launch Datasette against `findings.db`. | `src/Drederick/Cli/ServeCommand*` | `ServeCommandTests` (if present) |
| `drederick --scope … --target … --agent` | LLM-driven planner (requires `OPENAI_API_KEY`). | `src/Drederick/Agent/MicrosoftAgentRunner.cs` | `MicrosoftAgentRunnerTests` |
| `DREDERICK_SKIP_CVE=1 drederick …` | Skip CVE enrichment. | `src/Drederick/Enrichment/CveAnnotator.cs` | `CveAnnotatorTests` |
| `drederick --no-fetch-poc` | Skip PoC source caching. | `src/Drederick/Enrichment/PocAggregator.cs` | `PocAggregatorTests` |

Continuous integration is wired in [`.github/workflows/ci.yml`](.github/workflows/ci.yml);
release artifacts via [`.github/workflows/release.yml`](.github/workflows/release.yml).

<a id="file-concept-map"></a>
## File → concept map

Authoritative mapping of source locations to concepts. When making surgical
edits, identify the owning concept first.

| Path | What lives there | Owner scope (agent) |
| ---- | ---------------- | ------------------- |
| `src/Drederick/Scope/` | `Scope`, `ScopeLoader`, `ScopeException`, prefix caps. | scope-policy |
| `src/Drederick/Recon/` | 14 `IReconTool` scanners + `ReconToolbox`. | recon-tools |
| `src/Drederick/Recon/HostFinding.cs` | All typed result shapes per scanner. | recon-results |
| `src/Drederick/Agent/AdaptiveRunner.cs` | Deterministic rule-based planner. | orchestration |
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
| `src/Drederick/Reporting/ManualCommandsCheatsheet.cs` | `out/<host>/manual_commands.txt` (lab mode). | reporting |
| `src/Drederick/Reporting/SqliteReport.cs` | **Authoritative schema DDL** for `findings.db`. | reporting-db |
| `datasette/metadata.json` | Datasette labels, facets, canned queries. | datasette |
| `tests/Drederick.Tests/` | xUnit tests. | tests |
| `tests/fixtures/` | Recorded scanner fixtures (nmap XML, HTTP bodies, …). | fixtures |
| `docs/` | Human+agent docs (see [`docs/README.md`](docs/README.md)). | docs |
| `Makefile` | `quickstart`, `bootstrap`, `publish`, `install` targets. | build |
| `.github/workflows/ci.yml` | CI build + test. | ci |
| `.github/workflows/release.yml` | Release artifact pipeline. | release |

<a id="extension-points"></a>
## Extension points

### Adding a scanner — see [`docs/DEVELOPING.md#adding-scanner`](docs/DEVELOPING.md#adding-scanner)

Checklist (enforced by tests):

1. New class `src/Drederick/Recon/<Name>Tool.cs` implementing `IReconTool`.
2. Constructor-inject `Scope.Scope`, `AuditLog`, and any subprocess factory.
3. First statement of every public method: `_scope.Require(target)`.
4. Bracket with `audit.Record("<name>.start" / ".finish", …)`.
5. Add typed result to `HostFinding.cs`.
6. Validate subprocess argv (regex whitelist / denylist — see `NmapTool.RejectUnsafePortSpec`).
7. Wire into `ReconToolbox`; expose via `[Description(...)]` on toolbox method + params.
8. Update `ToolBudget` if default `(3 per tool per target, 200 global)` is wrong.
9. Register in `Program.cs` (see [Agent coordination](#agent-coordination) for merge-safe edits).
10. Extend `AdaptiveRunner` for auto-dispatch if applicable.
11. Tests: `ScopeException` negative, parser against fixture, forbidden-flag negative.

### Adding an enrichment source — see [`docs/DEVELOPING.md#adding-enrichment`](docs/DEVELOPING.md#adding-enrichment)

- PoC source: implement `IPocSource`, cache to `out/poc_cache/<source>/<external_id>/`,
  record SHA-256 in `poc_sources`. **Never execute.** See `SearchsploitSource.cs`.
- CVE feed: loader alongside `NvdCache.cs`, cache at `~/.drederick/<name>/`,
  matcher compatible with `CpeMatcher` output.

### Adding a Datasette canned query — see [`docs/DEVELOPING.md#adding-query`](docs/DEVELOPING.md#adding-query)

Edit `datasette/metadata.json` under `databases.findings.queries.<name>` with
`title`/`description`/`sql`. CVE joins go via
`json_extract(findings.data_json, '$.cve_id')`.

<a id="safety-triggers"></a>
## Safety triggers

**Must never appear in generated code, commit messages, manual-commands
cheatsheets, LLM planner output, or PoC wrappers.** Any diff introducing any
of the following should be rejected.

- `msfconsole -x exploit/…` or any Metasploit *exploit* module invocation
  (module **names** in `poc_refs` for reference are fine; *running* them is
  not).
- `hydra`, `medusa`, `ncrack`, `patator` with any credential list
  (`-L`, `-P`, `rockyou.txt`, etc.) — credential brute force.
- `crackmapexec`/`netexec` with `-u`/`-p`/`--spray` — credential attack.
- `evil-winrm -u <u> -p <p>` with baked creds, or any pre-populated
  credential pair.
- `impacket-GetNPUsers` / `impacket-GetUserSPNs` with `-request` (AS-REP /
  kerberoast) — explicitly forbidden; SPN **listing only** is fine.
- `responder`, `mitm6`, `bettercap` — LLMNR/NBT-NS poisoning, MITM.
- `chmod +x` on anything under `out/poc_cache/`.
- `exec`, `Process.Start`, `system()`, or subprocess spawn against files
  under `out/poc_cache/`.
- nmap with `--script` containing `exploit`, `intrusive`, `brute`, `vuln`,
  `dos`, `malware`.
- nmap with `-sU --script vuln` or any `vulners`/`vulscan` script.
- `searchsploit -m … && python …` style one-liner that fetches **and runs**
  a PoC.
- Outbound HTTP from cached PoC source (e.g., "just test the payload").
- Writing to scope file from code (scope is user-authored only).

If a user prompt requests any of these, refuse and link to
[`docs/SCOPE_AND_LEGAL.md#aggregate-vs-execute`](docs/SCOPE_AND_LEGAL.md#aggregate-vs-execute).

<a id="agent-coordination"></a>
## Agent coordination notes

Multiple agents may edit this repository in parallel. To avoid merge
conflicts and accidental overwrites:

### Unique-anchor convention for `Program.cs` surgical edits

When wiring a new scanner/source/subcommand into `src/Drederick/Cli/Program.cs`:

- **Do not** rewrite the whole DI block. Locate the existing section marker
  comment (`// --- recon tools ---`, `// --- enrichment ---`, `// --- runners ---`)
  and append your registration at the end of that block.
- If no marker exists for your new concept, add one on a line by itself
  (e.g. `// --- reporting sinks ---`) and place exactly one blank line
  before it. This gives the next agent a unique search target.
- Keep each registration on a single logical statement so `edit`-tool
  `old_str` matches are stable across unrelated insertions.

### Parallel-agent file-ownership zones

When multiple agents are running concurrently, they must not touch each
other's zones. Current canonical zones:

| Zone | Owned paths |
| ---- | ----------- |
| `ci-build-workflow` | `.github/workflows/ci.yml` |
| `release-pipeline`  | `.github/workflows/release.yml` |
| `docs-audit-index`  | `docs/**`, `AGENTS.md`, `README.md` (non-code edits), `docs/DB_SCHEMA.md`, `.github/copilot-instructions.md` (top-of-file pointer only) |
| `recon-*`           | `src/Drederick/Recon/**` |
| `enrichment-*`      | `src/Drederick/Enrichment/**` |
| `scope-policy`      | `src/Drederick/Scope/**` |

Before editing, check this table and the working agent list. If two scopes
overlap, coordinate via issue comments — do not racewrite.

### How to avoid merge conflicts

- **Never reflow unrelated prose** when adding a sentence. Prepend or append;
  don't reformat a paragraph you aren't changing.
- **Add, don't replace** in tables. Append new rows at the end unless
  alphabetical order is documented.
- **Frontmatter is idempotent**: if a file already has a `---` block, edit
  keys in place; don't re-emit the whole block.
- **Anchors are append-only**: once an anchor id (`{#foo}` or `<a id="foo">`)
  is published, it is part of the public surface. Do not rename.

<a id="canonical-sources"></a>
## Canonical sources (read these before acting)

1. [`docs/SCOPE_AND_LEGAL.md`](docs/SCOPE_AND_LEGAL.md) — hard guarantees.
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers + threading.
3. [`docs/MODULES.md`](docs/MODULES.md) — per-scanner contracts.
4. [`docs/DEVELOPING.md`](docs/DEVELOPING.md) — how to extend.
5. [`docs/DB_SCHEMA.md`](docs/DB_SCHEMA.md) — machine-readable schema.
6. [`docs/DATASETTE.md`](docs/DATASETTE.md) — current UI + triage workflow.
7. [`.github/copilot-instructions.md`](.github/copilot-instructions.md) —
   Copilot-specific version of this file (for Copilot sessions).
