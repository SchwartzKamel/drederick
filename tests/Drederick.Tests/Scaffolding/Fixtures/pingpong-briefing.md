---
box: pingpong
round: r2
briefing_version: 1
last_updated: 2026-04-01
---

# pingpong — briefing

## Topology

Single Windows DC + member host, c.roberts is a domain user with a
PFX certificate retrieved from a phishing dropbox.

## Assumed-Breach Material

| path                       | kind | identity   | use_for                    |
|----------------------------|------|------------|----------------------------|
| `loot/c.roberts.pfx`       | pfx  | c.roberts  | PKINIT to obtain TGT       |
| `loot/svc-mail.kirbi`      | tgt  | svc-mail   | s4u2self abuse             |

## Known / Suspected Attack Paths

1. PKINIT with c.roberts.pfx → TGT → DCSync
2. Kerberoast via the PKINIT-derived TGT
3. Fall back to AS-REP roast if PKINIT tooling unavailable

## Cornerman Directives

### Do

- Consume `c.roberts.pfx` in the first 5 actions
- Prefer pkinit over password spray when both are viable

### Don't

- password_spray against the whole user list
- brute the helpdesk SMB share

## Out-of-Scope Reminders

10.10.0.0/24 only. Anything else is out-of-scope; never engage.
