<!-- Thanks for the PR. Keep this template; fill each section. -->

## Summary

<!-- One or two sentences: what does this change and why. -->

## Invariants preserved

Cross-check against the `@invariant-id:*` table in
[docs/SCOPE_AND_LEGAL.md](../blob/main/docs/SCOPE_AND_LEGAL.md) and
[AGENTS.md](../blob/main/AGENTS.md).

- [ ] `scope-in-every-tool` — every network-touching method (recon, exploit, cred, payload) still calls `_scope.Require` first.
- [ ] `scope-default-deny` / `scope-wildcard-refused` / `scope-prefix-cap` — scope parsing untouched or tightened.
- [ ] `scope-is-authorization` — exploitation / cred / payload tools act only against scope-resolved targets; multi-host argv re-validated via `ExploitRunner.AssertTargetsInScope`.
- [ ] `subprocess-args-validated` — every host/IP/URL in argv is re-checked; no shell-metachar / path-traversal bypass.
- [ ] `audit-everything` — new PoC spawns, cred attempts, payload drops, session events write to `audit.jsonl` with argv digest; no plaintext passwords logged.
- [ ] `no-exfiltration` — no new outbound sink for loot / creds / captured secrets.
- [ ] `scope-file-read-only` — no code path writes to the scope file.
- [ ] `doctor-workstation-only` — doctor still never scans or exploits targets and never re-execs as root.
- [ ] `no-scope-kill-switch` — no new flag/env var/prompt bypasses scope or silences the audit log.

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
