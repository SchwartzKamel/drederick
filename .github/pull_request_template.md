<!-- Thanks for the PR. Keep this template; fill each section. -->

## Summary

<!-- One or two sentences: what does this change and why. -->

## Invariants preserved

Cross-check against the `@invariant-id:*` table in
[docs/SCOPE_AND_LEGAL.md](../blob/main/docs/SCOPE_AND_LEGAL.md) and
[AGENTS.md](../blob/main/AGENTS.md).

- [ ] `scope-in-every-tool` — every network-touching method still calls `_scope.Require` first.
- [ ] `scope-default-deny` / `scope-wildcard-refused` / `scope-prefix-cap` — scope parsing untouched or tightened.
- [ ] `nse-forbidden-categories` — no new path runs `exploit`/`intrusive`/`brute`/`vuln`/`dos`/`malware`.
- [ ] `aggregate-not-execute` — no new code executes fetched PoCs or payloads.
- [ ] `no-credential-attacks` / `no-payload-delivery` — no brute-force, spray, shells, implants.
- [ ] `doctor-workstation-only` — doctor still never scans targets and never re-execs as root.
- [ ] `no-scope-kill-switch` — no new flag/env var bypasses scope.

If a box cannot be checked, explain below.

## Testing

<!-- What you ran: `dotnet test`, `dotnet format --verify-no-changes`,
     scanner-specific tests, manual CLI exercises. -->

## Docs touched

<!-- List any README / AGENTS.md / docs/* / CHANGELOG.md edits, or say "none". -->

## Linked issues

<!-- e.g., Closes #123 -->

## Checklist

- [ ] I have read [SCOPE_AND_LEGAL.md](../blob/main/docs/SCOPE_AND_LEGAL.md).
- [ ] `dotnet test` is green.
- [ ] `dotnet format --verify-no-changes` is clean.
- [ ] Scanner changes updated the matching `*ToolTests.cs`.
- [ ] User-visible changes have a CHANGELOG entry under `[Unreleased]`.
