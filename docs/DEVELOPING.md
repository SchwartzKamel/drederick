---
title: Developing
audience: [humans]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - ARCHITECTURE.md
  - MODULES.md
  - POST_EXPLOITATION.md
  - EMPIRE.md
  - C2_INTEGRATION.md
  - SCOPE_AND_LEGAL.md
  - DB_SCHEMA.md
  - ../AGENTS.md
---

# Developing

> **Contributor quickstart:** `make quickstart` installs deps, builds,
> publishes, and installs the CLI globally (userspace `~/.local/bin`). Then
> `dotnet test` to verify. See [`../Makefile`](../Makefile) for the targets.
>
> **TL;DR map:** adding a recon scanner →
> [`#adding-scanner`](#adding-scanner); adding an exploit / credential /
> payload tool → [`#adding-exploit`](#adding-exploit); enrichment source →
> [`#adding-enrichment`](#adding-enrichment); post-ex command →
> [`#adding-post-ex`](#adding-post-ex); Datasette canned query →
> [`#adding-query`](#adding-query). Agent-facing condensed contract is
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

<a id="adding-exploit"></a>
## Adding an exploit / credential / payload tool

Offensive tools live under `src/Drederick/Exploit/` and implement
[`IExploitTool`](../src/Drederick/Exploit/IExploitTool.cs),
[`ICredTool`](../src/Drederick/Exploit/ICredTool.cs), or
[`IPayloadTool`](../src/Drederick/Exploit/IPayloadTool.cs). Payload
tools (like `EmpireAgentStager`) generate raw bytecode or scripts for
delivery; exploit and cred tools execute actions. Unlike recon (which is
read-only and scope-gated only), these tools are gated by **two**
boundaries: `Scope.Scope` (authorization — what targets you may touch at
all) and
[`RunPermissions`](../src/Drederick/Exploit/RunPermissions.cs) (what
category of blast radius is opted into this run, mapped to CLI flags
`--allow-exec-pocs` / `--allow-cred-attacks` / `--allow-payloads` /
`--allow-destructive` / `--allow-dos`). Both checks live on the tool
itself, not the toolbox — the UI, the LLM runner, `DrederickHost`, and
direct test construction all go through the same enforcement.

Spawning subprocesses, hashing captured output, and persisting
`ExploitRunRecord` rows are done through
[`ExploitRunner`](../src/Drederick/Exploit/ExploitRunner.cs) — do not
shell out from the tool directly, because `ExploitRunner` owns the
argv-digest, working-dir isolation, stdout/stderr truncation, and
SHA-256 pipeline that `exploit_runs` depends on.

1. **Create** `src/Drederick/Exploit/<Name>Tool.cs` (or `<Name>Runner.cs`
   if it drives an external orchestrator like msfconsole/nuclei).
   Implement `IExploitTool`:
   ```csharp
   public sealed class MyExploitTool : IExploitTool
   {
       public string Name => "my-exploit";
       public string Description =>
           "One-paragraph, LLM-readable description of what this tool does, " +
           "which service/CVE class it targets, and which opt-in category gates it.";
       public ExploitCategory Category => ExploitCategory.ExecPocs;
       // … typed RunAsync below …
   }
   ```
2. **Constructor** — inject `Scope.Scope`, `AuditLog`, `RunPermissions`,
   and an `ExploitRunner`. Accept optional factory / binary-path
   parameters so tests can substitute fakes:
   ```csharp
   public MyExploitTool(
       Scope.Scope scope,
       AuditLog audit,
       RunPermissions permissions,
       ExploitRunner runner,
       string? binPath = null)
   {
       _scope = scope;
       _audit = audit;
       _permissions = permissions;
       _runner = runner;
       _binPath = binPath ?? "my-bin";
   }
   ```
3. **Entry method** — run the gates in this exact order, and record a
   refusal audit event *before* throwing so
   `@invariant-id:audit-everything` holds even on denied attempts:
   ```csharp
   public async Task<MyExploitResult> RunAsync(string target, …, CancellationToken ct)
   {
       try { _scope.Require(target); }
       catch (ScopeException) {
           _audit.Record("my-exploit.scope_refused", new() { ["target"] = target });
           throw;
       }
       try { _permissions.Require(Category, Name); }
       catch (PermissionRefusedException) {
           _audit.Record("my-exploit.permission_refused",
               new() { ["target"] = target, ["category"] = Category.ToString() });
           throw;
       }
       // …build argv, then:
       _runner.AssertTargetsInScope(allHostsInArgv);   // pivots, LHOST, RHOSTS, callbacks
       var wd = _runner.NewWorkingDir(target, Name);
       _audit.Record("my-exploit.start", new() {
           ["target"] = target, ["invocation_id"] = wd.InvocationId,
       });
       var rec = _runner.Spawn(Name, target, _binPath, argString, wd, Category, timeoutSeconds: 300);
       _audit.Record("my-exploit.finish", new() {
           ["target"] = target, ["invocation_id"] = rec.InvocationId,
           ["argv_digest"] = rec.ArgvDigest, ["exit_code"] = rec.ExitCode,
       });
       return new MyExploitResult { Run = rec, /* parsed fields */ };
   }
   ```
4. **Typed result** — add a class to
   [`ExploitResult.cs`](../src/Drederick/Exploit/ExploitResult.cs) with
   an `ExploitRunRecord Run` field plus any parsed data. Do not add a
   raw-stdout field; stdout/stderr live on `Run` as truncated bodies +
   byte count + SHA-256. The `Run` field maps 1-for-1 to a row in the
   `exploit_runs` table (see
   [`DB_SCHEMA.md#table-exploit-runs`](DB_SCHEMA.md#table-exploit-runs)).
5. **Argv validation — every time.** Every host / IP / URL / payload
   callback in argv must pass `_runner.AssertTargetsInScope(...)` before
   `Spawn`. Shell-metachars, path traversal, and scope-bypass tokens
   must be rejected at argv-build time, not left for the subprocess to
   notice. See
   [`NmapTool.RejectUnsafePortSpec`](../src/Drederick/Recon/NmapTool.cs)
   and `ExploitRunner.AssertTargetsInScope` for the patterns.
6. **Never log plaintext secrets.** Credentials, wordlist entries,
   ticket bodies, and payload blobs never appear in audit records or
   in SQLite. Record SHA-256 + a boolean result instead — see
   `PasswordSprayResult.PasswordSha256`. `loot` rows use `value_sha256`
   exclusively; plaintext stays in `out/<host>/loot/`.
7. **Session + loot persistence.** If the tool opens an interactive
   session, build a `SessionRecord` and call
   `SqliteReport.UpsertSession` at open time (with `closed_at = null`)
   and again at close time. If it captures a secret, build a
   `LootRecord` with `value_sha256` only and call
   `SqliteReport.UpsertLoot`. The `SessionManager` handles long-lived
   sessions; prefer it over ad-hoc process tracking.
8. **Wire into `ExploitToolbox`** — add a nullable backing field and a
   public async method with a `[Description(...)]` on the method and
   each parameter. The `[Description]` text *is* the LLM-visible
   surface exposed by `MicrosoftAgentRunner`.
9. **Register** in `Program.cs` service wiring alongside the other
   exploit tools. Follow the unique-anchor convention from
   [`../AGENTS.md#agent-coordination`](../AGENTS.md#agent-coordination):
   locate `// --- exploit tools ---` and append at the end of that
   block; don't rewrite the block.
10. **Tests** (all required — see
    [`tests/Drederick.Tests`](../tests/Drederick.Tests/) for patterns):
    - **Scope refusal:** `Assert.Throws<ScopeException>` for out-of-scope
      `target`.
    - **Mixed-argv scope refusal:** when argv contains a mix of in-scope
      and out-of-scope hosts (pivot leg, `RHOSTS` list, callback), the
      tool refuses with `ScopeException` before spawning.
    - **Permission refusal:** with `RunPermissions.None`, the tool
      throws `PermissionRefusedException` and emits a
      `*.permission_refused` audit event.
    - **Audit refusal ordering:** both `*.scope_refused` and
      `*.permission_refused` events are recorded **before** the
      exception is raised.
    - **Argv-injection refusal:** shell-metachar / path-traversal /
      scope-bypass argv is rejected at build time.
    - **Parser:** recorded fixture under
      [`tests/fixtures/`](../tests/fixtures/) (and a fake subprocess
      binary under [`tests/fixtures/bin/`](../tests/fixtures/bin/) for
      replay — never spawn a real exploit against a real service in
      tests).
    - **No plaintext secrets leaked:** use a canary string
      (`DREDERICK_TEST_CANARY_…`) in fixture stdout; assert it never
      appears in serialised audit events or in written SQLite rows.
    - **Argv-digest stability:** identical inputs → identical
      `ArgvDigest` across runs (so `exploit_runs.argv_digest` is a
      stable correlation key).

### Credential attack tools

Credential tools set `Category = ExploitCategory.CredAttacks` and
additionally consult `RunPermissions.AcknowledgeLockoutRisk` before
running a spray or targeted brute — an operator who mechanically
flipped `--allow-cred-attacks` still has to positively attest
`--acknowledge-lockout-risk`. Lockout-aware throttling is default on;
the tool's argv-builder should derive per-target rate limits from the
knowledge base (prior failure count, observed lockout policy) rather
than a fixed sleep. See
[`PasswordSprayTool`](../src/Drederick/Exploit/PasswordSprayTool.cs) for
the canonical shape.

### Payload-staging tools

Payload tools set `Category = ExploitCategory.Payloads`. They should
generate or accept a payload artefact, record its SHA-256 in
`ExploitRunRecord.ArtifactSha256`, stage it through an authenticated
interface (never an unauthenticated write), and record the drop in the
audit log with the target path on the remote. The delivered payload's
bytes are not sent anywhere else — `@invariant-id:no-exfiltration`
applies end-to-end.

<a id="adding-post-ex"></a>
## Adding a post-ex command
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
   `(source, external_id, url, local_path?)` tuples, and caches raw PoC
   source under `out/poc_cache/<source>/<external_id>/` with a SHA-256
   recorded in the `poc_sources` row. Execution is not the source's job
   — `ExploitRunner` is responsible for marking executable and spawning
   cached artefacts when an `ExecPocs`-category tool is dispatched.
2. **Source invariant: aggregate verbatim.** Cache byte-for-byte — never
   `chmod +x` inside the source, never rewrite / neutralise /
   sanitise the fetched content, never make the outbound request that a
   PoC would have made. The source stops at "bytes on disk with a
   SHA-256 row." Spawning is gated separately by `RunPermissions`
   (`--allow-exec-pocs`) at the `ExploitRunner` layer.
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
disables this check. If you are adding a code path that reaches the
network, it must start with `_scope.Require(target)`.

Scope is the **authorization** boundary — what targets you may touch.
**Blast radius** is gated separately by
[`RunPermissions`](../src/Drederick/Exploit/RunPermissions.cs), which
maps CLI flags `--allow-exec-pocs` / `--allow-cred-attacks` /
`--allow-payloads` / `--allow-destructive` / `--allow-dos` to per-
category opt-ins. Inside scope, recon is unconditional; exploit,
credential, payload, and DoS tools additionally require the matching
opt-in. Lab mode enables most categories by default; strict mode
(`--no-lab`) is default-deny and requires each flag explicitly. See
[`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) for the hard invariants
that protect both boundaries.

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

## Running the web UI in dev

The browser operator pane shipped in v0.3.0 — full surfaces + Playwright
E2E; see [`WEB_UI.md`](./WEB_UI.md). For iterative development run the
ASP.NET host and the Vite dev server side-by-side:

```bash
# Terminal 1 — backend (hot reload)
cd src/Drederick.Web
dotnet watch

# Terminal 2 — frontend (Vite dev, proxied to the backend)
cd web
npm install
npm run dev
```

Backend binds to `http://127.0.0.1:7070`; Vite dev server runs on
`http://127.0.0.1:5173` and proxies `/api` and `/hubs` to the backend.
`drederick web` on a published build prints (or reuses) a bearer token;
in `dotnet watch` dev mode the token is read from `out/web-token.txt`
when present and regenerated otherwise. E2E smoke lives in `web/e2e/`
and is runnable via `npm run test:e2e` from `web/`.

`drederick serve` against Datasette remains available alongside the
browser pane for ad-hoc SQL — see [`DATASETTE.md`](./DATASETTE.md).

## Project layout {#project-layout}

```text
src/Drederick/          # Core engine (CLI + Web backend)
  Agent/                # AdaptiveRunner, MicrosoftAgentRunner, HybridAgentRunner,
                        #   HostWorkerPool
  Audit/                # JSONL audit log (thread-safe)
  Autopilot/            # Post-recon exploitation planner
  Cli/                  # CommandLineOptions, subcommands (doctor/serve/init/note/analyze/web/ctf-*)
  Doctor/               # Operator-workstation preflight + installer
  Enrichment/           # NVD cache, CPE match, CVE annotate, PoC sources
  Exploit/              # IExploitTool + ExploitRunner, MsfRcRunner, NucleiRunner,
                        #   PasswordSprayTool, PayloadStager, SessionManager, PostEx*
  Host/                 # DrederickHost facade shared by CLI, UI, and Web
  Jeopardy/             # CTFd Jeopardy solver swarm (Budget, Bus, Cli, Coordinator,
                        #   Ctfd, Detection, Llm, Ops, Prompts, Sandbox, Solver, Submit, Swarm)
  Memory/               # KnowledgeBase (cross-run state)
  Recon/                # IReconTool scanners + ReconToolbox
  Reporting/            # JSON, Markdown, cheatsheet, SqliteReport, NotesSchema
  Scope/                # Scope, ScopeLoader, ScopeException
src/Drederick.UI/       # Avalonia point-and-click operator console
src/Drederick.Web/      # ASP.NET Core host + SignalR hub (drederick web)
web/                    # React + TypeScript + Vite SPA, built into wwwroot/
datasette/              # metadata.json for Datasette UI
tests/Drederick.Tests/  # xUnit tests for the engine
tests/Drederick.UI.Tests/ # xUnit tests for the UI shell
tests/fixtures/         # Recorded scanner/exploit outputs
tests/fixtures/bin/     # Fake subprocess binaries for exploit-tool testing
docs/                   # This directory
```

## What to read before editing

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — layers and data flow.
- [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) — the hard guarantees.
  Changes that weaken any of them need discussion first.
- [`DB_SCHEMA.md`](./DB_SCHEMA.md) — findings.db schema (including
  `exploit_runs`, `sessions`, `loot`).
- [`MODULES.md`](./MODULES.md) — existing scanner + exploit contracts.
- [`../.github/copilot-instructions.md`](../.github/copilot-instructions.md) —
  the aggressive-enum + full-auto-exploit stance and the scope /
  permissions boundary.
