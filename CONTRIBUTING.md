---
title: Contributing to drederick
audience: [humans]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - README.md
  - AGENTS.md
  - .github/copilot-instructions.md
  - docs/SCOPE_AND_LEGAL.md
  - docs/DEVELOPING.md
  - CODE_OF_CONDUCT.md
  - SECURITY.md
---

# Contributing

Thanks for your interest in drederick. This is a scope-enforced reconnaissance
harness for authorized engagements; contributions are welcome as long as the
hard invariants stay intact.

## Before you start

Please read these first — they are the source of truth for what drederick is
allowed to do:

- [docs/SCOPE_AND_LEGAL.md](docs/SCOPE_AND_LEGAL.md) — scope rules, forbidden
  NSE categories, the aggregate-vs-execute line, and the stable `@invariant-id:*`
  table your change must preserve.
- [AGENTS.md](AGENTS.md) — repo-level contributor contract (vendor-neutral).
- [.github/copilot-instructions.md](.github/copilot-instructions.md) — the
  canonical instructions used by Copilot sessions; mirror of AGENTS.md.

If your change would weaken any invariant, stop and open a discussion issue
first — those are not negotiable in a PR.

## Dev quickstart

```sh
make quickstart     # restore, build, and smoke-check the CLI
make test           # dotnet test across the solution
make format         # dotnet format (apply)
```

See [docs/DEVELOPING.md](docs/DEVELOPING.md) for the full loop, environment
variables, and module layout.

## Pull request checklist

Before requesting review, confirm:

- [ ] **Invariants preserved.** Cross-check your diff against the
      `@invariant-id:*` table in
      [docs/SCOPE_AND_LEGAL.md](docs/SCOPE_AND_LEGAL.md#invariants) and
      [AGENTS.md](AGENTS.md). If an invariant anchor is touched, explain why.
- [ ] `dotnet test` is green locally.
- [ ] `dotnet format --verify-no-changes` is clean.
- [ ] Scanner changes come with updates to the matching `*ToolTests.cs`
      (e.g., edits to `NmapTool.cs` update `NmapToolTests.cs`).
- [ ] Docs updated for any user-visible CLI flag, env var, or output change.
- [ ] CHANGELOG.md has an entry under `[Unreleased]` if your change is
      user-visible.

## Issue workflow

Open issues via the forms in
[.github/ISSUE_TEMPLATE/](.github/ISSUE_TEMPLATE/):

- **Bug report** — something broke or produced the wrong result.
- **Feature request** — new behavior, flag, or UX change.
- **Scanner request** — add or extend support for a service / port.

Security reports do **not** go in public issues. See
[SECURITY.md](SECURITY.md) for the private channel.

## Commit style

- Concise subject in the imperative mood ("Add X", "Fix Y"), ~72 chars.
- Body explains *why*, not *what* the diff already shows.
- Reference invariants by their stable id where relevant
  (e.g., `@invariant-id:scope-wildcard-refused`).
- When a change is agent-assisted (Copilot, Claude, etc.), include a
  `Co-authored-by:` trailer for the agent. Keep a human co-author too.

Example:

```
Tighten NSE category filter for smb scanner

The previous check relied on a single startswith pass which let
"vuln-ms17" through. Normalize and split on commas first.

Preserves @invariant-id:nse-forbidden-categories.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

## Code of Conduct

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
