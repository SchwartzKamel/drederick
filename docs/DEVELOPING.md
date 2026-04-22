---
title: Developing
audience: [humans]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - ARCHITECTURE.md
  - MODULES.md
  - SCOPE_AND_LEGAL.md
  - ../AGENTS.md
---

# Developing

> **Contributor quickstart:** `make quickstart` installs deps, builds,
> publishes, and installs the CLI globally (userspace `~/.local/bin`). Then
> `dotnet test` to verify. See [`../Makefile`](../Makefile) for the targets.
>
> **TL;DR map:** adding a scanner → [`#adding-scanner`](#adding-scanner);
> enrichment source → [`#adding-enrichment`](#adding-enrichment); Datasette
> canned query → [`#adding-query`](#adding-query). Agent-facing contract is
> [`../AGENTS.md#extension-points`](../AGENTS.md#extension-points).

## Prerequisites

- **.NET 10 SDK** (check with `dotnet --list-sdks`).
- `nmap` on `PATH` for end-to-end runs. Unit tests do not need it.
- Optional for full-feature work: `searchsploit`, `datasette`, `curl`, `jq`.
  `drederick doctor --install` will fetch these on Debian/Ubuntu/Kali/Fedora/
  Arch/openSUSE/macOS with consent.

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

All tests are xUnit under `tests/Drederick.Tests/`. The solution file is
`Drederick.slnx`; shared build props (`net10.0`, nullable on, implicit usings
on, invariant globalization) live in `Directory.Build.props`.

## Adding a new `IReconTool` {#adding-scanner}

`IReconTool` is a metadata-only interface (`Name`, `Description`). Call
signatures stay typed per-scanner because recon surfaces are intentionally
heterogeneous — forcing a uniform `ScanAsync(target, ct)` would throw away
useful per-tool parameters. `ReconToolbox` dispatches by concrete type
(`OfType<T>().SingleOrDefault()`).

1. **Create** `src/Drederick/Recon/<Name>Tool.cs`.
2. **Implement** `IReconTool`:
   ```csharp
   public sealed class MyTool : IReconTool
   {
       public string Name => "my-tool";
       public string Description =>
           "One-paragraph, LLM-readable description of what this tool does. " +
           "End with a safety assertion: read-only, no credentials, scope-bound.";
       // … typed ProbeAsync below …
   }
   ```
3. **Constructor** — inject `Scope.Scope` and `AuditLog`; take the binary
   path or network factory via optional parameters so tests can stub with
   `/bin/true` or an in-memory stream:
   ```csharp
   public MyTool(
       Scope.Scope scope,
       AuditLog audit,
       IProcessRunner? runner = null,
       string? binPath = null)
   {
       _scope = scope;
       _audit = audit;
       _runner = runner ?? new DefaultProcessRunner();
       _binPath = binPath ?? "my-bin";
   }
   ```
4. **Typed scan method** — `_scope.Require(target)` must be the **first
   statement**. Bracket work with `audit.Record("<Name>.start" / ".finish", …)`:
   ```csharp
   public async Task<MyResult> ProbeAsync(string target, int port, CancellationToken ct = default)
   {
       _scope.Require(target);
       _audit.Record("my-tool.start", new Dictionary<string, object?> {
           ["target"] = target, ["port"] = port,
       });
       var result = new MyResult { Port = port };
       try { /* … */ }
       finally {
           _audit.Record("my-tool.finish", new Dictionary<string, object?> {
               ["target"] = target, ["port"] = port, ["error"] = result.Error,
           });
       }
       return result;
   }
   ```
5. **Add a typed result** to `HostFinding.cs` and a matching list/field on
   `HostFinding`. Never leak raw stdout/stderr except as a bounded `error`
   field.
6. **Validate LLM-chosen subprocess args** before handing them to a process
   runner. See `NmapTool.RejectUnsafePortSpec` (regex whitelist of digits,
   commas, dashes) and `SmbTool.AssertNoForbiddenScripts` (denylist of script
   name fragments: `brute`, `vuln`, `enum-users`, `enum-shares`).
7. **Wire into `ReconToolbox`** — add a nullable backing field, pick it out
   via `materialized.OfType<MyTool>().SingleOrDefault()`, and add a public
   async method with a `[Description(...)]` on the method and each
   parameter. The `[Description]` text *is* the LLM-visible surface.
8. **Update `ToolBudget`** if your tool's call shape means the default
   `(PerTargetPerTool: 3, MaxTotalCalls: 200)` is wrong.
9. **Register** in `Program.cs` service wiring alongside the other scanners.
10. **Auto-dispatch** (optional) — if the tool should auto-fire on a specific
    nmap service name, extend `AdaptiveRunner`'s per-port plan loop with a
    service-name check and a `DispatchAction(name, port)`.
11. **Tests** (all required):
    - A `ScopeException` test: `Assert.Throws<ScopeException>` on
      out-of-scope input.
    - Parser / response tests against recorded fixtures under
      `tests/fixtures/`.
    - A negative test asserting no forbidden NSE category or CLI flag is
      enabled on the built argv (pattern: `SmbToolTests.AssertNoForbiddenScripts_*`).

<a id="adding-post-ex"></a>
## Adding a post-ex command

Post-exploitation commands are the structured enumeration step that
runs *after* a session has been opened. The contract is similar to
[`#adding-scanner`](#adding-scanner) and the `IExploitTool` shape used
elsewhere in `src/Drederick/Exploit/`, with two post-ex-specific
twists: (1) the command is dispatched through an established session,
so `target` is the session's target (not ambient), and (2) captured
stdout is SHA-256'd and truncated at
`PostExCommandRun.MaxCaptureBytes` — plaintext content never rides
along in the audit record or the report. Narrative, worked example,
and data flow are in
[`POST_EXPLOITATION.md#extending-post-ex`](POST_EXPLOITATION.md#extending-post-ex).

1. **Pick the platform.** Linux commands go on
   [`PostExLinux`](../src/Drederick/Exploit/PostExLinux.cs); Windows
   commands go on
   [`PostExWindows`](../src/Drederick/Exploit/PostExWindows.cs). Cross-
   platform operations (e.g. `FlagExtractor`-adjacent sweeps) live on
   `SessionManager` or a new helper; do not fork a third `PostEx*`
   class for them.
2. **Add a typed result** to
   [`PostExResult.cs`](../src/Drederick/Exploit/PostExResult.cs). The
   result carries a `PostExCommandRun Run` (or `Capture` for Windows —
   follow the existing casing) envelope plus parsed fields. Never add
   a raw-string field for captured content; use SHA-256 + byte length.
3. **Public async method** on the platform class with the signature
   `Task<TResult> <Cmd>Async(string target, string? session, CancellationToken ct)`
   for Linux (session is optional at the class level because the probe
   may be local-first); `Task<TResult> <Cmd>Async(string target, string session, CancellationToken ct)`
   for Windows (session is required — Windows enumeration does not
   have a local fallback). **First statement must be
   `_scope.Require(target)`.** No exceptions, no shortcuts.
4. **Argv construction** — assemble a constrained `/bin/sh -c "…"`
   (Linux) or `cmd.exe /c` / `powershell -NoProfile -NonInteractive
   -Command` (Windows) string. The command body is a **fixed literal**
   — no interpolation of LLM-supplied or operator-supplied text. If
   you need a parameter, add it to the method signature and whitelist
   its shape (digits only, identifier only, path-under-root only)
   before interpolating.
5. **Audit** — wrap execution with
   `audit.Record("postex.<platform>.<cmd>.start" / ".finish", …)`
   events. Include `target`, `session_id`, `argv_digest` (SHA-256 of
   the argv), `exit_code`, and — on finish — `stdout_sha256` +
   `stdout_bytes`. Never copy `stdout_truncated` into the audit event.
6. **RunPermissions.** Post-ex enumeration itself does not require an
   additional opt-in beyond the `--allow-exec-pocs` that got you the
   session — enumeration on a box you already own is low-blast-radius.
   If a new command is state-mutating (writes a file on the target,
   reboots, kills a process), it must additionally call
   `_permissions.Require(ExploitCategory.Destructive, Name)`.
7. **Compose into `RunAllAsync`** — add the new command's call into
   `PostExLinux.RunAllAsync` / `PostExWindows.RunAllAsync` and a
   nullable field on `PostExLinuxResult` / `PostExWindowsResult` so
   the default sweep picks it up.
8. **LLM surface** (optional but preferred) — add a wrapper in
   [`LlmExploitTools`](../src/Drederick/Agent/LlmExploitTools.cs) with
   a `[Description]` attribute and the standard error envelope
   (`{error: "permission_denied"|"scope_refused"|"budget_exceeded"|…}`).
   The wrapper re-checks scope, consults `RunPermissions`, consumes a
   budget slot, and audits `llm.tool.<name>.start` / `.finish`.
9. **Register** in `Program.cs` if a new dependency is introduced
   (usually not needed — `PostExLinux` / `PostExWindows` are already
   wired). Follow the unique-anchor convention from
   [`../AGENTS.md#agent-coordination`](../AGENTS.md#agent-coordination).
10. **Tests (all required):**
    - `ScopeException` on out-of-scope target (`Assert.Throws<ScopeException>`).
    - Parser test against a recorded stdout fixture under
      `tests/fixtures/`. Use the fake subprocess binaries in
      `tests/fixtures/bin/` to replay canned output.
    - Argv-stability test: the built argv for identical inputs is
      byte-for-byte identical across runs (so `argv_digest` is a
      stable identifier in the audit log).
    - An audit-content test: no plaintext secret or raw file content
      appears in the audit record — only SHA-256 + byte length. Use
      a canary string (`DREDERICK_TEST_CANARY_…`) in the fixture
      stdout and assert it is absent from the serialised audit event.
    - For LLM wrappers: a `permission_denied` envelope test when the
      corresponding `RunPermissions` flag is off, and a
      `budget_exceeded` envelope test when the budget is exhausted.

Cross-reference: [`POST_EXPLOITATION.md#extending-post-ex`](POST_EXPLOITATION.md#extending-post-ex)
for narrative guidance on new session protocols, pivot probes, and
flag patterns. Invariants: [`../AGENTS.md#invariants`](../AGENTS.md#invariants).

## Adding a new enrichment source {#adding-enrichment}

Enrichment sources annotate findings with third-party intel (CVEs, PoCs,
threat reports). All live under `src/Drederick/Enrichment/`.

### A PoC source

1. Implement `IPocSource` (see `SearchsploitSource.cs` for the canonical
   example). The source resolves PoC pointers for a given CVE id, returns
   `(source, external_id, url, local_path?)` tuples, and optionally caches
   raw PoC source under `out/poc_cache/<source>/<external_id>/` with a
   SHA-256 recorded in the `poc_sources` row.
2. **Invariant**: aggregate + present, never execute. Never `chmod +x`, never
   spawn fetched PoC code, never make the outbound request that a PoC would
   have made. Cache verbatim; the practitioner reads it.
3. Respect `--no-fetch-poc` at the orchestration layer (don't branch inside
   the source — `PocAggregator` decides whether to call you).
4. Network dependencies go through `IHttpFetcher` so tests can inject a
   fake.
5. Tests: a scope-agnostic unit test per response shape, a cache-hit test
   (no network), and a SHA-256 stability test.

### A CVE feed

1. Add a loader alongside `NvdCache.cs`. Cache under `~/.drederick/<name>/`.
2. Keep the offline-fallback contract: if network fails and a cache exists,
   load stale; if neither, skip enrichment rather than fail the run.
3. Provide a matcher compatible with `CpeMatcher`'s `(vendor, product,
   version) → IEnumerable<CveHit>` shape, or write a sibling matcher that
   consumes the feed's native schema.
4. Wire into `CveAnnotator.AnnotateAsync` behind a feature flag /
   environment variable mirroring `DREDERICK_SKIP_CVE`.

## Adding a Datasette canned query {#adding-query}

Canned queries are declared in `datasette/metadata.json` under
`databases.findings.queries.<name>`. Each entry needs `title`, `description`,
and `sql`. Example:

```json
"hosts_by_cve_count": {
  "title": "Hosts by CVE count",
  "description": "Top 10 hosts by total annotated CVEs, desc.",
  "sql": "SELECT h.address, COUNT(c.id) AS cve_count FROM hosts h JOIN services s ON s.host_id = h.id JOIN findings f ON f.service_id = s.id AND f.kind = 'cve' JOIN cves c ON c.cve_id = json_extract(f.data_json, '$.cve_id') GROUP BY h.address ORDER BY cve_count DESC LIMIT 10"
}
```

- CVE joins go through `json_extract(findings.data_json, '$.cve_id')` because
  `findings` is the denormalized home of probe payloads — see
  `CveAnnotator` for the key contract.
- Mention the query in [`DATASETTE.md`](./DATASETTE.md) so it is findable.
- No schema migration is needed; Datasette re-reads metadata on restart.

## Running doctor locally {#doctor-local}

```bash
# Read-only: print what's installed and what's missing.
./src/Drederick/bin/Debug/net10.0/drederick doctor

# With consent, install what's missing via the detected package manager.
# apt/dnf/pacman/zypper/brew → fallback to pipx / uv / go install / gem.
./src/Drederick/bin/Debug/net10.0/drederick doctor --install         # [y/N] per step
./src/Drederick/bin/Debug/net10.0/drederick doctor --install -y      # non-interactive
```

Detection is always safe to run. Install steps print the exact `sudo`
command and ask `[y/N]` — doctor never re-execs itself with elevated
privileges. Every detection and install is recorded to `audit.jsonl` and
to the `tooling` table in `findings.db`.

## Running the worker pool locally

The bounded `HostWorkerPool` is the same code path in tests and production.
To stress it against a local scope:

```bash
# Small scope, high concurrency — useful to shake out races.
./src/Drederick/bin/Debug/net10.0/drederick \
    --scope scope.yaml --expand \
    --host-concurrency 16 --service-concurrency 32 \
    --out out/
```

Caps: `--host-concurrency` ≤ 32, `--service-concurrency` ≤ 64. The legacy
`-j / --parallel` knob is accepted and maps to `--host-concurrency` if the
latter is not explicitly set.

## How scope re-checks work

Scope enforcement lives **inside every tool**, not at the CLI boundary.
Whichever runner is driving — deterministic or LLM — a target outside the
scope file causes the tool to throw `ScopeException`, which is logged and
skipped. There is no flag, no prompt, and no environment variable that
disables this check. If you are adding a code path that reaches the network,
it must start with `_scope.Require(target)`.

## Testing conventions {#testing}

- Prefer in-memory fixtures: recorded XML for nmap, recorded response
  streams for FTP/SSH/SMTP, recorded HTTP bodies.
- On-disk fixtures go under `Path.GetTempPath()` + a GUID; clean up in
  `finally`. See `tests/fixtures/` for naming conventions.
- For any scanner that shells out, inject the binary path via the
  constructor so tests can use `/bin/true` or a stub `IProcessRunner`.
- For any scanner that opens a socket, inject the connect factory so tests
  pass an in-memory `Stream` (see `FtpTool`).
- Every new scanner **must** have a test asserting it refuses out-of-scope
  targets. Every new scanner that invokes a subprocess **must** have a
  negative test on the built argv proving no forbidden NSE/CLI flag is
  enabled.

## Running the web UI in dev (planned)

Once `src/Drederick.Web` and `web/` land:

```bash
# Terminal 1
cd src/Drederick.Web
dotnet watch

# Terminal 2
cd web
npm install
npm run dev
```

The host will bind to `127.0.0.1` only and print a one-time auth token.

Until then, `drederick serve` against Datasette is the current UI — see
[`DATASETTE.md`](./DATASETTE.md).

## Project layout {#project-layout}

```text
src/Drederick/          # Core engine (CLI today)
  Agent/                # AdaptiveRunner, MicrosoftAgentRunner, HostWorkerPool
  Audit/                # JSONL audit log (thread-safe)
  Cli/                  # CommandLineOptions
  Doctor/               # Operator-workstation preflight + installer
  Enrichment/           # NVD cache, CPE match, CVE annotate, PoC sources
  Memory/               # KnowledgeBase (cross-run state)
  Recon/                # 14 IReconTool scanners + ReconToolbox
  Reporting/            # JSON, Markdown, cheatsheet, SqliteReport
  Scope/                # Scope, ScopeLoader, ScopeException
datasette/              # metadata.json for Datasette UI
tests/Drederick.Tests/  # xUnit tests
tests/fixtures/         # Recorded scanner outputs
docs/                   # This directory
```

## What to read before editing

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — layers and data flow.
- [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) — the hard guarantees.
  Changes that weaken any of them need discussion first.
- [`MODULES.md`](./MODULES.md) — existing scanner contracts.
- [`../.github/copilot-instructions.md`](../.github/copilot-instructions.md) —
  the aggressive-enum stance and the aggregate-vs-execute line.
