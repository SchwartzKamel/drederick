# Briefing — Example Box

Operator briefing for the lab target. Format is the cornerman /
HTB convention; the Memory BriefingLoader parses the H2 sections
below and seeds the knowledge base.

## Targets

- 10.10.10.5  # primary web host
- 10.10.10.6 (dc)
- 10.10.10.99 - secondary file share
- 192.168.99.42  # OUT OF SCOPE — should be skipped by the loader

## Users

- alice
- bob (helpdesk)
- svc_sql

## Credentials

- alice:p@ssw0rd
- bob NTLM:31d6cfe0d16ae931b73c59d7e0c089c0
- svc_sql AES256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

## Constraints

- no DoS
- no Tor exit
- lockout threshold = 5 attempts per 30 minutes

## Notes

Foothold likely via the web app on :80. The DC is reachable
from the web host via SMB. Helpdesk account `bob` has been
observed using the same password on multiple internal
services — credential reuse is in scope.
