---
title: Security policy
audience: [humans]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - README.md
  - AGENTS.md
  - docs/SCOPE_AND_LEGAL.md
  - CONTRIBUTING.md
---

# Security policy

Drederick is a scope-enforced reconnaissance harness used on authorized
engagements. A vulnerability in the tool itself (especially one that weakens
the scope guarantees) is treated as high severity.

## Reporting a vulnerability

**Do not open a public issue or PR for security bugs.**

Use GitHub's private vulnerability reporting:

- [Open a Security Advisory](https://github.com/SchwartzKamel/drederick/security/advisories/new)

If you cannot use that channel, open a minimal public issue asking a
maintainer to contact you privately — do not include details, PoC, or
affected versions in the public issue.

## In scope for disclosure

In priority order:

1. **Scope-enforcement bugs** — any path that lets a network call reach a
   target not in the scope file. Path-traversal in scope parsing, scope
   bypass, wildcard leakage (`0.0.0.0/0` / `::/0`), prefix-cap bypass,
   or a missing `_scope.Require` call on a network-touching method.
2. **Forbidden-NSE-category leakage** — any code path that lets
   `exploit`, `intrusive`, `brute`, `vuln`, `dos`, or `malware` NSE
   scripts run.
3. **PoC execution / arbitrary code execution regressions** — drederick
   aggregates and presents PoC metadata; it must never execute, chmod,
   or spawn fetched code.
4. **Cache poisoning** — PoC source bytes, CVE data, or NSE scripts
   bypassing the SHA-256 integrity check.
5. **Credential-file disclosure** — secrets written to `out/`, `memory/`,
   or anywhere else on disk in cleartext.
6. **Doctor re-exec as root** — `drederick doctor` escalating outside the
   explicit consent flow, or touching anything other than the operator
   workstation.

## Out of scope

Vulnerabilities in **target systems** discovered while running drederick
are expected. Report those to the target owner per your engagement rules;
they are not drederick bugs.

## Response SLA

Best-effort acknowledgement within **7 days**. We will keep the advisory
thread updated with a rough fix timeline once reproduced.

## Supported versions

| Version                  | Supported |
|--------------------------|-----------|
| `main`                   | Yes       |
| Most recent tagged release | Yes     |
| Older tags               | No        |

## Credit

Unless you request anonymity, we will credit you in the release notes for
the fixing tag and in the advisory.

## Please include in your report

To help us reproduce quickly, include:

- The **invariant id** you believe is being bypassed
  (`@invariant-id:*` — see [AGENTS.md](AGENTS.md) and
  [docs/SCOPE_AND_LEGAL.md](docs/SCOPE_AND_LEGAL.md)).
- Minimal scope file + CLI command that triggers the issue (redact
  targets if the engagement is under NDA).
- Expected vs. observed behavior.
- Affected commit SHA or tag.
- OS, kernel, and `dotnet --version`.
