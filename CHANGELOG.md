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

- `MsfRcRunner` Phase 2: unlocked payload-bearing modules (`PAYLOAD`, `CMD`,
  `LHOST`, `SRVHOST`, `EXITFUNC`, post-exploitation `post/*` modules) when
  `--allow-payloads` is opted in. Every callback address is still re-validated
  through `_scope.Require` before spawn. Always-forbidden RC primitives
  (`AutoRunScript`, `InitialAutoRunScript`, `PROXIES`) remain refused
  regardless of opt-ins.
- `NmapTool` aggressive NSE selection: when `--allow-exec-pocs` is on, the
  script categories now include `intrusive,vuln,exploit`. With
  `--allow-cred-attacks` (or lab mode) adds `auth`. With `--allow-dos` adds
  `dos,malware`. Strict mode with no opt-ins remains `safe,default`.

### Changed

- Lab/CTF mode now defaults `--allow-exec-pocs`, `--allow-cred-attacks`,
  `--allow-payloads`, and `--allow-destructive` to ON. `--allow-dos` remains
  OFF by default even in lab mode. `--no-lab` flips every category back OFF.
  Credential attacks still require `--acknowledge-lockout-risk` explicitly.
- `ExploitToolbox.ToolBudget.Default` raised from `(2, 50)` to `(5, 200)` to
  match the aggressive recon posture and let the planner iterate through
  module / payload / credential variants on a single target.

### Fixed

### Security

### Removed
