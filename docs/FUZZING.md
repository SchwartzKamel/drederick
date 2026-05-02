---
title: Fuzzing Subsystem
audience: [humans, agents]
primary: humans
stability: experimental
last_audited: 2026-05
related: [SCOPE_AND_LEGAL.md, ARCHITECTURE.md, MODULES.md, POST_EXPLOITATION.md, DEVELOPING.md]
---

# Fuzzing Subsystem

The fuzzing subsystem (`src/Drederick/Recon/Fuzz/`) is a scope-bounded,
audit-logged offensive layer that complements passive recon. Each fuzz
tool is an `IFuzzTool` registered in `FuzzToolbox`, re-checks scope
internally (`@invariant-id:scope-in-every-tool`), and writes start /
finish / error events to `audit.jsonl` with argv digests.

> **Invariant boundary.** Fuzzing is *not* exempt from any rule in
> [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md). Every fuzz tool's first
> network statement is `_scope.Require(target)`. The LLM planner cannot
> bypass it. Out-of-scope fuzzing is impossible by construction.

## When fuzzing runs

1. **AdaptiveRunner (deterministic).** `RunOptions.EnableFuzz=true` plus
   the `AdaptiveRunner` triggers `AdaptiveRunner.ScheduleFuzzAsync` after
   the recon pass completes. HTTP-driven tools (header, web-param, api,
   graphql) are dispatched against discovered HTTP services. JWT,
   subdomain, protocol, file-format, and LLM payload fuzzers require
   operator-supplied input and are not auto-scheduled.
2. **MicrosoftAgentRunner / LLM.** Fuzz tools are visible to the LLM
   planner via `FuzzToolbox.Tools`; each `IFuzzTool.Description` is the
   LLM-readable tool surface. Scope and budget enforcement happens in
   the tool itself, not in the agent runner.
3. **Manual.** `FuzzToolbox.GetByName("…")` returns the registered tool
   for direct invocation from a custom script.

## The 10 fuzz tools

| # | Name | Category | Backing tool(s) | Operator-supplied input |
| - | ---- | -------- | --------------- | ----------------------- |
| 1 | `web-param-fuzz` | `WebApi` | `arjun`, `x8` | base URL |
| 2 | `vhost-fuzz` | `WebApi` | `ffuf` | base URL + apex domain |
| 3 | `subdomain-fuzz` | `Dns` | `gobuster`, `dnsx` | apex domain |
| 4 | `api-endpoint-fuzz` | `WebApi` | `kr` (kiterunner) | base URL + `.kite` file |
| 5 | `graphql-fuzz` | `WebApi` | `graphql-cop` + native introspection | endpoint URL |
| 6 | `jwt-fuzz` | `Auth` | `jwt_tool` | token (URL mode also takes URL) |
| 7 | `header-fuzz` | `WebApi` | native HTTP probes | base URL |
| 8 | `protocol-fuzz` | `Network` (destructive) | `boofuzz` | target host + protocol script |
| 9 | `file-format-fuzz` | `Mutation` | `radamsa` | seed file + optional upload form |
| 10 | `llm-payload-fuzz` | `WebApi` | LLM mutator | anchor URL + LLM provider |

### `web-param-fuzz`

Discovers hidden HTTP parameters via `arjun` (Python heuristic miner)
and optionally `x8` (Rust binary, faster on large parameter spaces).
Auto-scheduled against any HTTP service `AdaptiveRunner` finds.

### `vhost-fuzz`

Iterates a wordlist of `Host:` header values via `ffuf` to enumerate
virtual hosts behind the same IP. Requires an operator-supplied apex
domain — not auto-scheduled.

### `subdomain-fuzz`

Wordlist-driven subdomain enumeration via `gobuster dns` (TCP) and
optionally `dnsx` (UDP burst). Apex domain must be in scope (resolved
to its first A record before the scope check).

### `api-endpoint-fuzz`

`kr scan` against an HTTP target with a `.kite` route wordlist.
The default `routes-large.kite` ships in the full container at
`/opt/kiterunner/routes.kite`. Argv whitelist rejects path traversal
in the kite path.

### `graphql-fuzz`

Native introspection probe (mutations, queries, types, schema digest)
plus optional `graphql-cop` for COP detection (alias overloading,
batching, CSRF, field suggestion).

### `jwt-fuzz`

Two modes:

- **URL mode** (`ProbeAsync(token, targetUrl)`): scope-checks `targetUrl`
  host, sends crafted tokens, observes responses. Detects alg=none,
  weak HMAC, RS256→HS256 confusion, KID injection, JKU/X5U injection.
- **Offline mode** (`AnalyzeAsync(token)`): structural analysis only,
  no network, no scope check (no egress).

The audit log records the SHA-256 of the token, never the plaintext.

### `header-fuzz`

In-process HTTP probes (no subprocess). Detects host-header injection,
HTTP request smuggling (CL.TE / TE.CL / TE.TE), header CRLF injection,
and cache poisoning (X-Forwarded-Proto / X-Original-URL divergence
combined with a cache header in the response). Auto-scheduled against
every HTTP service.

### `protocol-fuzz` (destructive — opt-in)

Drives `boofuzz` against a target service. **Requires BOTH
`RunPermissions.AllowDestructive` AND `RunPermissions.AllowDos`**
(CLI: `--allow-destructive --allow-dos`). The tool refuses to spawn a
subprocess if either gate is missing. Recommended only inside lab /
CTF networks where target downtime is acceptable.

### `file-format-fuzz`

`radamsa`-mutated payloads. Two surfaces:

- **Local mutation only** — generate corrupted files for offline
  analysis (no network).
- **`MutateAndUploadAsync`** — upload mutated payloads to a target's
  upload form; scope-checked URL, multipart POST, response captured.

### `llm-payload-fuzz`

LLM-guided payload generation gated by an *anchor finding* — typically
a WAF-like 403 from another fuzz tool. The model proposes mutations,
the tool sends them, and the loop continues for up to `MaxRounds` (8 by
default). `LlmPayloadFuzzTool` re-checks scope on every request and
records every prompt + response pair to the audit log.

## Budgets and rails

`FuzzToolbox.DefaultBudget` is `(PerTargetPerTool: 2, MaxTotalCalls: 100)`
— tighter than `ReconToolbox` because fuzzers are intentionally
high-volume. Override via the `budget` ctor parameter. When the cap is
hit, `RecordCall` throws `InvalidOperationException` and the runner
moves on rather than retrying.

## Scope and authorization

Every fuzz tool's first network statement is `_scope.Require(target)`.
For URL-based tools, `target` is `uri.Host` after parsing the operator-
supplied URL. For domain-based tools (`subdomain-fuzz`), the apex is
resolved to its first A record and *that IP* is scope-checked. There
is no path that bypasses this check — refer to
[`SCOPE_AND_LEGAL.md#invariants`](SCOPE_AND_LEGAL.md#invariants).

## Doctor coverage

`drederick doctor` reports availability of: `arjun`, `x8`, `kr`,
`graphql-cop`, `jwt_tool`, `radamsa`, `boofuzz` (Python module).
The full Containerfile (`Containerfile.full`) installs all seven plus
their wordlist deps.

## Authoring a new fuzz tool

See [`DEVELOPING.md`](DEVELOPING.md) — the recipe is identical to
`IReconTool`/`IExploitTool`, except the type is `IFuzzTool` and
registration goes through `FuzzToolbox` (not `ReconToolbox`).
Mandatory: scope check on entry, audit start/finish, argv digest in
the start record, opt-in flag for destructive categories.
