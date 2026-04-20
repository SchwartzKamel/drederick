# Developing

## Prerequisites

- **.NET 10 SDK** (check with `dotnet --list-sdks`).
- `nmap` on `PATH` for end-to-end runs. Unit tests do not need it.

## Build, test, format

```bash
dotnet build
dotnet test
dotnet format
```

All tests are xUnit and live under `tests/Drederick.Tests/`.

## Adding a new `IReconTool`

> The `IReconTool` abstraction is planned but not yet implemented. Today each
> scanner is its own class under `src/Drederick/Recon/`. The pattern described
> below matches the current scanners and will carry over to `IReconTool`.

1. Create a class under `src/Drederick/Recon/<Name>Tool.cs`.
2. Inject `Scope.Scope scope` and `AuditLog audit` via the constructor.
3. **First line of every public method that touches the network:**
   `_scope.Require(target);`
4. Record `audit.Record("<tool>.start", …)` before the call and
   `audit.Record("<tool>.finish", …)` after.
5. Return a typed result class under `HostFinding.cs`; do not leak raw
   stdout/stderr except as a bounded error field.
6. Validate any LLM-chosen arguments before passing them to a subprocess. See
   `NmapTool.RejectUnsafePortSpec` for the pattern.
7. Wire the new tool into `ReconToolbox`, add an `[Description(...)]` on the
   public tool method so the LLM surface stays documented, and update the
   `ToolBudget` accounting.
8. Add tests:
   - A scope-check test (`Assert.Throws<ScopeException>` on out-of-scope
     input).
   - Parser tests against recorded fixtures under `tests/fixtures/`.
   - A negative test that the tool does not enable any forbidden NSE category
     or subprocess flag.

## How scope re-checks work

Scope enforcement lives **inside every tool**, not at the CLI boundary.
Whichever runner is driving — deterministic or LLM — a target outside the
scope file causes the tool to throw `ScopeException`, which is logged and
skipped. There is no flag, no prompt, and no environment variable that
disables this check. If you are adding a code path that reaches the network,
it must start with `_scope.Require(target)`.

## Testing conventions

- Prefer in-memory fixtures (recorded XML for nmap, recorded bodies for HTTP).
- Use `Path.GetTempPath()` + a GUID for any on-disk test fixtures; clean up in
  a `finally`.
- For any scanner that shells out, inject the binary path via constructor so
  tests can use `/bin/true` or a stub.
- Every new scanner **must** have a test asserting it refuses out-of-scope
  targets.

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

## Project layout

```
src/Drederick/          # Core engine (CLI today)
  Agent/                # AdaptiveRunner + MicrosoftAgentRunner
  Audit/                # JSONL audit log
  Cli/                  # CommandLineOptions
  Memory/               # KnowledgeBase (cross-run state)
  Recon/                # Scanners
  Reporting/            # JSON, Markdown, manual-commands cheatsheet
  Scope/                # Scope, ScopeLoader, ScopeException
tests/Drederick.Tests/  # xUnit tests
docs/                   # This directory
```

## What to read before editing

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — layers and data flow.
- [`SCOPE_AND_LEGAL.md`](./SCOPE_AND_LEGAL.md) — the hard guarantees. Changes
  that weaken any of these need to be discussed first.
- [`MODULES.md`](./MODULES.md) — existing scanner contracts and planned ones.
