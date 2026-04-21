<!--
---
title: UI — Drederick operator console (Avalonia)
audience: [humans, agents]
primary: humans
stability: experimental
last_audited: 2026-04
related:
  - ../AGENTS.md
  - ../README.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
  - DATASETTE.md
  - UI_GUIDE.md
---
-->

# UI — Drederick operator console

> **Status: experimental.** The Avalonia operator console is a live scan
> launcher, not a triage surface. Post-run triage still goes through
> [Datasette](DATASETTE.md); do not reimplement it here.

Drederick ships two operator-facing UIs that complement each other:

| Surface | Purpose | Lives in |
| ------- | ------- | -------- |
| **`Drederick.UI` (this doc)** | Live operator console: compose scope, pick targets, launch runs, watch progress. | `src/Drederick.UI/` |
| **Datasette (`drederick serve`)** | Post-run triage: SQL-queryable browsing of `out/findings.db`. | `datasette/metadata.json`, CLI `serve` subcommand |

<a id="quickstart"></a>
## Quickstart

```bash
# From the repo root (no packaging step required):
dotnet run --project src/Drederick.UI
```

Authorised targets only. Everything the CLI refuses, the UI refuses — the
scope check lives inside each recon tool, not at the UI boundary
(see [Invariants](#invariants)).

<a id="workflow"></a>
## Point-and-click workflow

1. **Scope tab**
   - Either **Browse…** to pick an existing scope file, **or** paste/edit
     CIDR entries directly in the inline editor — no file on disk required.
   - Toggle **Lab/CTF mode** and **Allow broad scope** with checkboxes.
   - Click **Re-parse** to validate; the parsed entry list fills in on the
     right. Any `ScopeException` (including the hard-coded wildcard
     refusal) renders as a red error banner.
   - Click **Save inline…** to persist the GUI-authored scope to a file for
     re-use.
2. **Run tab**
   - Type a target IP into **Add target** and click **Add**. The VM checks
     both that it's a valid IP and that it falls inside the loaded scope;
     out-of-scope or malformed targets are refused inline.
   - Click **Remove** on any target row to drop it.
   - Flip **Lab/CTF mode**, **Use agent runner** (needs `OPENAI_API_KEY`),
     or **Allow-broad**. Allow-broad surfaces a confirmation banner that
     must be explicitly clicked through before **Start scan** will enable.
   - Second row of checkboxes: **Annotate CVEs**, **Aggregate PoC refs**,
     **Cache PoC source**, **VPN preflight**, **Require VPN (abort if
     down)**. All default on (parity with CLI); toggling is per-run.
   - Set **Output dir** and **Memory** text boxes (defaults: `out`,
     `memory/findings.json`).
   - **Start scan** is disabled until the scope has validated *and* at
     least one target is in the list. Click it to run. **Cancel** aborts
     the in-flight run.
3. **Progress tab**
   - Live feed of `ScanEvent`s: timestamp, kind, target, tool, message.
     Phase-2 adds `VpnPreflight`, `CveAnnotated`, `PocAggregated` kinds so
     the operator can watch enrichment happen.
   - Status strip at the bottom shows `hosts:` / `tool calls:` counters and
     the latest error, if any.
4. **Doctor tab** *(phase 2)*
   - **Detect** scans PATH for all 24 tools in `DoctorRunner.Tools`
     (nmap, searchsploit, python3/2, go, ruby, git, datasette, netexec,
     impacket, hashcat, john, gobuster, ffuf, sqlmap, nuclei, kerbrute,
     seclists, evil-winrm, …) and displays Found/Version/Path per row.
   - Package-manager name (apt/dnf/pacman/zypper/brew) is displayed.
   - **Install missing** is gated behind an explicit consent checkbox.
     `@invariant-id:doctor-workstation-only`: drederick never re-execs as
     root; individual install recipes may prompt for sudo themselves, and
     the UI pipes the install transcript to `audit.jsonl`.
5. **Findings tab** *(phase 2)*
   - Read-only summary of `out/findings.db`: host / service / CVE / PoC-ref
     counts, plus a per-host row with open-port-count and service sample.
   - **Open in Datasette** launches our own `drederick serve` subcommand.
     This is the harness itself (not a scanner binary), and Datasette is
     read-only — triage stays with Datasette, per the plan's "don't
     reimplement triage" posture.

<a id="architecture"></a>
## Architecture

```
  +---------------------+
  |  Drederick.UI       |     (Avalonia 11.3, net10)
  |  Views/ViewModels   |
  +----------+----------+
             |  IProgress<ScanEvent>, CancellationToken
             v
  +---------------------+
  |  DrederickHost      |     (src/Drederick/Host/, same assembly as CLI)
  |  RunAsync(Scope,…)  |
  +----------+----------+
             |   ReconToolbox + AdaptiveRunner | MicrosoftAgentRunner
             v
  +---------------------+
  |  Scope-enforced     |     (@invariant-id:scope-in-every-tool)
  |  IReconTool scanners|
  +---------------------+
```

### `DrederickHost` façade

`src/Drederick/Host/DrederickHost.cs` exposes two overloads:

- `RunAsync(RunOptions, IProgress<ScanEvent>?, CancellationToken)` —
  loads the scope from `RunOptions.ScopePath`. Used when the operator
  points the UI at an existing scope file.
- `RunAsync(Scope, RunOptions, IProgress<ScanEvent>?, CancellationToken)` —
  accepts an already-parsed `Scope`. This is the path the UI takes when the
  operator composes a scope entirely inside the inline editor — no temp
  file, no round-trip through disk. The `Scope` must have been produced by
  `ScopeLoader` (default-deny and wildcard refusal live there).

### `ScanEvent` stream

`ScanEvent` (also under `Host/`) is an append-only record surfaced to the UI
*in addition to* the append-only JSONL `AuditLog`. Kinds include
`SessionStart`, `ScopeLoaded`, `RunnerStart`, `HostFinished`,
`ReportWritten`, `SessionEnd`, and `Error`. The UI is free to drop or
batch; the audit log is always authoritative.

<a id="invariants"></a>
## Invariants preserved at the UI boundary

This is the non-negotiable bit. Every invariant the CLI honours, the UI
honours by construction:

| Invariant | UI expression |
| --------- | ------------- |
| `@invariant-id:scope-in-every-tool` | UI never spawns scanner binaries; every call goes through `DrederickHost` → `ReconToolbox` → scope-enforced `IReconTool`s. |
| `@invariant-id:scope-default-deny`  | Start button disabled unless a scope is validated (no file = no scope = no run). |
| `@invariant-id:scope-wildcard-refused` | Inline CIDR editor shows the raw `ScopeException` text when the operator pastes `0.0.0.0/0` or `::/0`; the refusal is not dismissable from the UI. |
| `@invariant-id:scope-prefix-cap`   | `Allow-broad` must be clicked *and* confirmed via a separate banner before Start will enable. |
| `@invariant-id:aggregate-not-execute` | The UI has no "Run PoC", no `chmod +x`, no "Open terminal in poc_cache". A CI-enforced source scan (`UiAssemblyInvariantsTests`) fails if any scanner binary name (`nmap`, `hydra`, `msfconsole`, `crackmapexec`, `responder`, …) or `chmod +x` / `poc_cache` pattern appears in `src/Drederick.UI/`. The one narrowly-allowed subprocess launch is the harness's own `drederick serve` CLI (Datasette over the read-only `findings.db`), invoked by the Findings tab's **Open in Datasette** button. |
| `@invariant-id:no-credential-attacks` | Zero credential fields. Targets are the only input. |
| `@invariant-id:llm-cannot-escape-scope` | When the "Use agent runner" checkbox is on, the agent routes through the same scope-enforced `AIFunction`s as the CLI. |

<a id="first-iteration-scope"></a>
## Deferred to follow-ups

Explicitly not landing in this iteration, to keep the PR small:

- **Analyze** (`drederick analyze`) and **Init** (`drederick init`) wizards
  from the UI — low immediate UX win, heavy dialog logic.
- **UI packaging** (AppImage/MSI/DMG). `dotnet run --project src/Drederick.UI`
  is the supported entry point today; single-release consolidation (one
  artifact producing CLI + GUI) is a separate packaging effort.

Already landed in phase 2: **DoctorView**, **FindingsView** (with
"Open in Datasette"), and enrichment parity (CVE annotation, PoC
aggregation, VPN preflight) inside `DrederickHost.RunAsync`.

<a id="testing"></a>
## Testing

```bash
# Engine + CLI tests.
dotnet test tests/Drederick.Tests/Drederick.Tests.csproj

# UI ViewModel tests (pure CommunityToolkit.Mvvm, no Avalonia window).
dotnet test tests/Drederick.UI.Tests/Drederick.UI.Tests.csproj
```

The UI test project covers:

- `ScopeViewModelTests` — empty / wildcard-refused / valid-list / save-to-file.
- `RunViewModelTests` — Start-disabled invariants, Add/Remove, out-of-scope
  and non-IP refusals, Allow-broad confirmation gate.
- `DoctorViewModelTests` — install-consent-gating (install disabled before
  detect, without consent, or when nothing is missing; enabled only when
  all three are true).
- `FindingsViewModelTests` — `Reload` against missing / real `findings.db`.
- `UiAssemblyInvariantsTests` — source-tree scan refusing forbidden scanner
  binary names (`nmap`, `hydra`, `msfconsole`, `crackmapexec`, `responder`,
  `impacket-GetUserSPNs`, …) and `chmod +x` / `poc_cache` patterns.

<a id="dependencies"></a>
## Dependency posture

The UI is **net10 native**: `Microsoft.Extensions.*` at **10.0.0**, not
bonsai's pinned 8.0.0. Avalonia 11.3.11 (net10-compatible),
`CommunityToolkit.Mvvm` 8.4.0. `Tmds.DBus.Protocol` is pinned to 0.21.3 to
close the transitive `GHSA-xrw6-gwf8-vvr9`.

Full versions live in
[`src/Drederick.UI/Drederick.UI.csproj`](../src/Drederick.UI/Drederick.UI.csproj).
