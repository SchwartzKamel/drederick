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

Drederick is a scope-enforced, full-auto offensive security harness used
on authorized engagements. A vulnerability in the tool itself —
especially one that weakens the **authorization boundary** (scope) or
the **audit trail** — is treated as high severity.

## Reporting a vulnerability

**Do not open a public issue or PR for security bugs.**

Use GitHub's private vulnerability reporting:

- [Open a Security Advisory](https://github.com/SchwartzKamel/drederick/security/advisories/new)

If you cannot use that channel, open a minimal public issue asking a
maintainer to contact you privately — do not include details, PoC, or
affected versions in the public issue.

## In scope for disclosure

In priority order:

1. **Scope-enforcement bugs** — any path that lets a network call
   (recon, exploit, credential, payload, or pivot) reach a target not
   in the scope file. Path-traversal in scope parsing, scope bypass,
   wildcard leakage (`0.0.0.0/0` / `::/0`), prefix-cap bypass, missing
   `_scope.Require` call on a network-touching method, or
   `ExploitRunner.AssertTargetsInScope` not being called before a
   multi-host subprocess spawn.
2. **Scope kill switches** — any flag, env var, debug build, CLI
   prompt, or LLM instruction that disables the scope check, even
   partially. No kill switch must exist.
3. **Audit-log tampering** — any code path that silences, rewrites,
   deletes, or truncates entries in `audit.jsonl` (one-way append is
   the only supported shape), or that logs plaintext credentials
   where only a SHA-256 digest is approved.
4. **Subprocess argv injection** — shell-metachar / path-traversal /
   URL-host-spoofing that lets argv reach an out-of-scope target
   without triggering `_scope.Require`.
5. **Scope-file write from code** — any code path that modifies the
   user-authored scope file.
6. **Loot exfiltration** — any outbound sink that sends captured
   credentials, hashes, tickets, or secrets to a third-party
   endpoint. Drederick is local-only by design.
7. **Cache poisoning** — PoC source bytes, CVE data, or NSE scripts
   bypassing the SHA-256 integrity check (matters more now that
   cached PoCs are executed, not just presented).
8. **Credential-file disclosure in cleartext** — captured secrets
   written to `out/`, `memory/`, or anywhere else in plaintext
   instead of as SHA-256 digests.
9. **Doctor re-exec as root** — `drederick doctor` escalating outside
   the explicit consent flow, or touching anything other than the
   operator workstation.

## Out of scope

Vulnerabilities in **target systems** discovered while running
drederick are expected — the tool exists to find and exploit them.
Report those to the target owner per your engagement rules; they are
not drederick bugs.

Bugs in third-party exploits, Metasploit modules, nuclei templates,
or cached PoCs are out of scope for drederick's tracker. Report them
upstream.

## Response SLA

Best-effort acknowledgement within **7 days**. We will keep the
advisory thread updated with a rough fix timeline once reproduced.

## Supported versions

| Version                  | Supported |
|--------------------------|-----------|
| `main`                   | Yes       |
| Most recent tagged release | Yes     |
| Older tags               | No        |

## Credit

Unless you request anonymity, we will credit you in the release notes
for the fixing tag and in the advisory.

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
