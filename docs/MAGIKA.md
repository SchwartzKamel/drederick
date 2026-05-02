<!--
---
title: Magika integration
audience: [operators, agents]
primary: operators
stability: beta
last_audited: 2026-05
related:
  - MODULES.md
  - JEOPARDY.md
  - GETTING_STARTED.md
---
-->

# Magika integration

## What is magika, and why does drederick care?

[Magika](https://github.com/google/magika) is Google's ML-based file-type
detector. It is **fast** (sub-10ms per file) and **more accurate than
`file`** on disguised, polyglot, or ML-adversarial inputs — the exact
kind of artifact CTF reversing and malware triage tend to throw at us.

Drederick uses magika in two places:

1. **Binary analysis pre-pass.** `BinaryAnalyzer` now calls magika as its
   first step, before `file`/`readelf`/`nm`/`objdump`/`strings`. The
   verdict is attached to `BinaryAnalysisReport.Magika` (JSON field
   `magika`). If magika disagrees with `file` about whether the artifact
   is actually an executable (e.g. magika says `zip` for a `.so` that
   ships ELF magic bytes), we emit a high-confidence warning finding.
2. **CTF reversing hint (planned — see TODO below).** Once wired into
   `ChallengeSolver`, magika's verdict will steer the sandbox toolchain
   selection for Jeopardy challenges — is this a PE32, an ELF, a
   polyglot, a stego JPEG, a serialized pickle, a firmware dump?

Drederick **works fine without magika**. The integration is strictly
additive: when magika is unavailable, the magika field is null and
downstream analysis proceeds as before.

> **Companion: native magic-byte signatures.** When magika is missing
> *and* `file(1)` is restricted, Drederick falls back to
> [`MagicSignatures`](../src/Drederick/Recon/Binary/MagicSignatures.cs)
> — a small in-process table of magic-byte → format mappings (ELF, PE,
> Mach-O, ZIP, gzip, JPEG, PNG, PDF, etc.). It is not a replacement for
> magika's ML-based classification; it is a "we always have *something*"
> floor so the binary-analysis pre-pass can still tag the artifact.

## Install

Primary (Python, pipx-isolated):

```sh
pipx install magika
```

Alternate (Rust binary, fastest startup):

```sh
cargo install magika
```

No supported distro currently ships magika as a system package; there
is **no** `apt install magika` recipe at this time (2026-04). If one
lands later, the install recipe in
[`src/Drederick/Doctor/InstallRecipe.cs`](../src/Drederick/Doctor/InstallRecipe.cs)
will be updated.

The doctor runner picks up magika automatically:

```sh
drederick doctor                    # lists magika alongside other tools
drederick doctor --category=recon   # runs recon-category checks (just magika today)
```

## Doctor check id

- **Id:** `recon.magika.available`
- **Category:** `recon`
- **Status:** `Pass` when `magika --version` exits 0, `Warn` otherwise
  (never `Fail` — magika is optional).
- **Fix command:** `pipx install magika` (fallback: `cargo install magika`).
- Implementation:
  [`src/Drederick/Doctor/MagikaToolCheck.cs`](../src/Drederick/Doctor/MagikaToolCheck.cs).

## Graceful fallback

If magika is not installed:

- `MagikaDetector.DetectAsync` returns `null`.
- `BinaryAnalyzer` continues with `file`/`readelf`/etc.
- The JSON report serializes `"magika": null`.
- The first missed invocation records one `magika.detect.unavailable`
  audit event (we never spam the log — subsequent misses are silent).

If magika is installed but emits unexpected JSON (e.g. an upstream
format change), the same graceful path applies: null verdict, one
`magika.detect.unavailable` event, analysis proceeds.

## Path validation (load-bearing)

`MagikaDetector.DetectAsync` validates the input path before spawning:

- Path must be **absolute**.
- Path must resolve under the current working directory (i.e. the
  artifact must be inside drederick's workspace).
- Literal `..` segments are rejected even when they would resolve
  inside cwd — we never want `..` on magika's argv.

Invalid paths throw `ArgumentException`; `BinaryAnalyzer` catches this
and falls through to the non-magika path so an out-of-workspace
artifact still gets analyzed (it just doesn't get a magika verdict).

## Audit events

- `magika.detect.start` — file path + SHA-256 of the path string. File
  **contents** are never recorded.
- `magika.detect.finish` — status (`ok` / `unavailable` / `exit-N` /
  `unparseable`), label, group, confidence.
- `magika.detect.unavailable` — emitted at most once per
  `MagikaDetector` instance, with a reason string.

## Output shape

`MagikaVerdict` (JSON property names shown):

```jsonc
{
  "label": "elf",                                    // primary content-type label
  "description": "ELF executable",                   // human-readable
  "group": "executable",                             // bucket: executable / archive / code / text / image / …
  "mime_type": "application/x-executable",
  "extension": "elf",
  "confidence": 0.987,                               // model score in [0,1]
  "is_text": false,
  "raw_json": "{…}"                                  // verbatim first line magika emitted
}
```

## TODO — CTF solver prompt enrichment

The `ChallengeSolver` / `PromptLibrary.cs` path to feed magika's verdict
into the category hint sent to the LLM ("this challenge is a
{magika_verdict}; toolchain is …") has **not** been wired yet. Gating
it on `magika != null` is trivial; the holdback is zone risk from
parallel agents touching the Jeopardy subsystem at the same time as
this PR.

Tracking this as a follow-up — when picked up, the minimal change is:

1. In the pre-solve fan-out that prepares the mounted-artifact prompt,
   construct a `MagikaDetector` (via the same `AuditLog` already in
   scope) and call `DetectAsync(<artifact_path>)` inside the sandbox
   workspace.
2. When the verdict is non-null, inject a category line like
   `artifact classification: {label} ({description}, group={group}, confidence={confidence:F2})`
   at the top of the category-hint block.
3. When null, omit the line — no fallback text (absence is a signal).

## Tests

- Unit + integration coverage in
  [`tests/Drederick.Tests/Recon/Binary/MagikaDetectorTests.cs`](../tests/Drederick.Tests/Recon/Binary/MagikaDetectorTests.cs).
- All tests use a stub `IMagikaProcessRunner` — they never shell out to
  a real magika binary (CI runners may not have it installed).
- Run with: `dotnet test --filter "FullyQualifiedName~Magika"`.
