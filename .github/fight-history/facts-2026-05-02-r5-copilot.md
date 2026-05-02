<!--
---
title: Facts — R5 (Tag-Team WIN with Copilot Cornerman)
audience: [agents, operators]
primary: agents
stability: stable
last_audited: 2026-05
related:
  - .github/fight-history/INDEX.md
  - .github/fight-history/facts-2026-05-02.md
  - .github/fight-history/facts-2026-05-02-r3-r4.md
  - .github/fight-gaps.md
  - docs/MODEL_BEHAVIOR.md
---
-->

# Facts — R5 (Tag-Team WIN with Copilot Cornerman)

> **Bout:** facts-2026-05-02-R5-copilot
> **Target:** 10.129.30.236 (HTB Facts, Easy, Linux — `nginx/1.26.3` on `facts.htb`)
> **Outcome:** ✅ **WIN — both flags captured** (user `e205d77c…d077d`, root `df6ad544…41c36`)
> **Studied:** 2026-05-02 (later)

## The fight

**The first W of the harness arc.** Four straight losses on Facts on
Drederick's autopilot card, then the corner threw a fresh towel and
sent the cornerman in. Copilot took the chain from step 2 onward and
ran it eleven steps deep: register → mass-assign → path traversal →
DB exfil → S3 pivot → bucket raid → SSH key crack → user shell →
sudo facter → root.

I want to be honest about who threw which punch. **Drederick set the
table.** Four rounds of recon scaffold — nmap, native TCP knock,
`http_probe` with the GAP-032 vhost fix landed clean, 31 CVEs into
`findings.db` from R2, vhost reachable, scope enforced inside every
network-touching tool. **Copilot placed the dishes.** Eleven manual
shots, every CMS-shaped pivot read off Drederick's recon output, every
chain-step authored by the cornerman because the harness has no CMS
fingerprint yet, no MinIO probe yet, no SQLite pillage yet, no SSH key
brute yet, no GTFOBins yet, no chain template yet.

Both flags went on the wall. The operator's marketing writeup
(`~/HTB/machines/facts/writeup.md`, 531 lines, ringside narrative
with the loot, the chain, and the round-by-round narrative) is the
prose version of this fight. **This tape is the engineer's view:**
what gaps the chain surfaces, what tools we now need, and what
shipping order makes the next facts-class box fall solo.

## Tale of the tape

| stat | R5-copilot |
| ---- | ---------- |
| target | `10.129.30.236` (HTB Facts, Easy, Linux) |
| outcome | ✅ **WIN** — user + root |
| flags | user `e205d77c60b955d4979bef03ea6d077d`, root `df6ad544468fc5edb1ee3e4cb2441c36` |
| chain length | **11 steps** — longest in Drederick history (prev. record: 1) |
| rematch_of | facts-2026-05-02-R4 |
| drederick role | recon scaffold (R4 data) + scope on the operator workstation |
| Copilot role | cornerman — authored steps 2-11 of the chain |
| drederick LLM calls | inherited from R4 (42); R5 itself ran no Drederick CLI |
| Copilot driver calls | 11-step chain in operator bash + Python + sqlite3 + aws-cli + paramiko + ssh |
| CVEs landed | CVE-2025-2304 (mass assignment), CVE-2026-1776 (path traversal) |
| sessions opened | trivia (user shell via cracked ed25519 key) → root (sudo facter custom-dir) |
| duration (chain execution) | ~30 min per writeup; 60 min total per yaml |
| autonomous status | n/a — this fight was operator+Copilot, off-harness |

## The 11-step chain

Terse, ringside cadence. The operator's writeup has the prose; I'm
calling the tape.

1. **Recon — 22/80/54321 open.** SSH 9.9p1, nginx 1.26.3 → 302 to
   `facts.htb`, MinIO on a non-standard port. Drederick found 22/80
   in R1-R4; 54321 was on the autopilot card as "unknown service".
2. **Asset inspection — CameleonCMS 2.9.0 fingerprint.** `cama_*`
   cookie names + Rails 8.0.2 generator metadata. Manual eyeball.
3. **`curl /admin/register` → user 5.** Open registration was on the
   admin namespace. Cornerman registered as `drederick`.
4. **CVE-2025-2304 mass-assignment → admin.** `POST
   /admin/users/5/updated_ajax` with `role=admin`. One shot.
5. **CVE-2026-1776 path traversal → 15+ files.**
   `/admin/media/download_private_file` with `..` in the file name.
   `production.sqlite3` came down clean.
6. **`sqlite3 production.sqlite3` → S3 creds.** The `cama_metas` table
   carried the MinIO access/secret in plaintext.
7. **`aws-cli --endpoint http://10.129.30.236:54321` → bucket raid.**
   Internal bucket. Backups. The good stuff.
8. **`id_ed25519` for `trivia` in the bucket.** Passphrase-encrypted.
9. **`paramiko` against `rockyou-1k` → `dragonballz` in 3,185 tries.**
   Low bcrypt rounds (24) on the key file made the brute feasible
   in seconds.
10. **`ssh trivia@10.129.30.236` → user shell + `user.txt`.**
11. **`sudo /usr/bin/facter --custom-dir` → custom Ruby fact loaded
    as root → `root.txt`.** GTFOBins-class privesc.

Eleven steps. Two CVEs. One DB exfil. One S3 pivot. One key crack.
One sudo-fu. The chain length is the headline; the variety is the
lesson — every link is a different capability the harness doesn't
yet have.

## What Drederick provided

Honest accounting. The recon scaffold under the cornerman's feet:

- **Recon tape from R1-R4.** R4 left 31 CVEs in `findings.db`, the
  vhost reachable through `http_probe` with the GAP-032 fix landed,
  the credential store seeded, all 25 LLM tools live. The cornerman
  read R4's output and started step 1 from there.
- **Scope policy.** Drederick's `scope.yaml` declared 10.129.30.236
  authorized. The operator was running off-harness shots from inside
  that authorization boundary; scope was operator-enforced (the
  operator typed the IPs into curl/aws-cli/ssh by hand) rather than
  drederick-CLI-enforced for the chain itself.
- **Recon-pulse confirmation.** R4's `http_probe` count of 48 calls
  proved the vhost detection was working; the cornerman didn't have
  to debug whether facts.htb was reachable — Drederick had already
  proven it.

**Where the chain ran.** The 11 manual curl/sqlite/aws/paramiko/ssh
shots were **off-harness** — operator's bash, Copilot CLI driving
the keyboard. There is no `out-r5/` directory on disk and no
`audit.jsonl` for this fight; R5-copilot's yaml entry is the only
durable record. Scope on those shots was *operator-enforced* (the
operator kept the chain inside the authorized target IP and the
authorized vhost) rather than `_scope.Require`-enforced through
Drederick's tools. That's not a violation of the invariants — it's
a statement that Drederick wasn't on the field for steps 2-11. The
authorization boundary held because the operator held it.

## What the cornerman provided

Six capabilities the harness doesn't yet ship. This is the gap list
in operational terms:

- **CMS fingerprint.** `cama_*` cookie + Rails generator + theme
  asset path → CameleonCMS 2.9.0. Drederick's banner-only fingerprint
  stack didn't pick it up.
- **MinIO/S3 service prober.** Port 54321 was the pivot; autopilot
  saw "unknown service" and skipped.
- **Database pillage post-ex.** `production.sqlite3` was full of
  service credentials in `cama_metas`. Nobody on the harness team
  was reading that table.
- **SSH key passphrase brute.** Captured ed25519 + rockyou wordlist;
  no Drederick tool wraps that flow.
- **sudo -l + GTFOBins lookup.** `facter --custom-dir` is
  GTFOBins-canonical for sudo privesc; we have neither the enum
  nor the exploit-builder.
- **CMS chain template.** "Register → privesc → traversal → DB-exfil
  → pivot" is a pattern that fits CameleonCMS, WordPress, Joomla,
  Drupal, Ghost, Strapi… we want it written down and adaptive.

The cornerman threw all six combinations live. The yaml log captures
every step as training data — that's the cornerman model working as
designed: demonstrate the chain → log it → build the tools.

## Six new bruises

Six gaps land on the registry from this fight. Operator's R5-copilot
yaml uses GAP-034..GAP-039 for these in their numbering; the registry
already had GAP-034 (http.error taxonomy) and GAP-035 (escalate
gap-031b-2) booked, so the registry numbers are bumped to GAP-036+.
The operator's yaml is canonical for the operator's numbering; the
registry is canonical for tool development.

- **GAP-036** — CMS fingerprint tool. Banner + cookie + asset-path
  + generator meta → product/version. Owner zone: `enrichment-fingerprint`.
- **GAP-037** — MinIO/S3 service prober. `54321/tcp` and
  `9000/tcp` style endpoints, S3-compatible API probe + bucket
  enumeration with credentials. Owner zone: `recon-*`.
- **GAP-038** — SQLite credential pillage post-ex. Open every `.db`
  / `.sqlite*` reachable from a shell, dump `cama_metas`-style
  credential tables, file under `loot`. Owner zone: post-ex.
- **GAP-039** — SSH key passphrase brute. ed25519/rsa/ecdsa with
  passphrase, wordlist-driven, audit hash digests only. Owner
  zone: `exploit-*`.
- **GAP-040** — `sudo -l` enum + GTFOBins-aware lookup + exploit
  builder. `facter --custom-dir` is the canary. Owner zone: post-ex.
- **GAP-041** — CMS chain templates. "Register → mass-assign →
  traversal → DB exfil → pivot" as a templated multi-stage chain
  the LLM can dispatch. **Depends on GAP-036** (fingerprint must
  fire first to pick the right template). Owner zone: autopilot.

## What's left in the bag

The autonomous-takedown chain in numerical/dependency order. With
all of these shipped, the next facts-class box should fall solo:

1. **`gap-031b-2-git-poc-sources`** *(in flight)* — git-clone PoC
   sources (`metasploit-framework`, `nuclei-templates`,
   `PoC-in-GitHub`, `trickest/cve`). Without this, the GAP-033
   cve-lead router has nowhere to fetch from. Tracked under
   GAP-035 (now ✅ resolved as escalation).
2. **`llm-exec-shell-tool`** *(in flight)* — meta-enabler. Lets
   the LLM drive curl/sqlite/aws/python shots from inside the
   harness with scope + audit + argv validation, instead of
   the operator dropping to bash for every chain step.
3. **GAP-036** — CMS fingerprint.
4. **GAP-037** — MinIO/S3 prober.
5. **GAP-038** — SQLite pillage post-ex.
6. **GAP-039** — SSH key passphrase brute.
7. **GAP-040** — sudo + GTFOBins.
8. **GAP-041** — CMS chain templates (depends on GAP-036).

`llm-exec-shell-tool` is the load-bearing meta-piece. Once the LLM
can drive arbitrary shell shots through `_scope.Require` + audit +
argv validation, every chain in the bag becomes Drederick-native
instead of operator-bash. The other six are the per-step
capabilities the chain itself needs.

## Records & residue

- **First W of the harness arc.** Tag-team — drederick recon +
  Copilot cornerman. Both flags captured.
- **Streak.** `1-6-1 → 1-8-1` autopilot card / **`2-8-1` with
  cornerman assist** (per writeup). Drederick's autonomous record
  on Facts: **0-4**. Drederick's with-cornerman record on Facts:
  **1-0**.
- **Chain length record.** 11 steps. Previous Drederick record: 1.
- **Time-to-flag.** ~30 min total chain-execution per the writeup;
  yaml records `duration_minutes: 60` for the full bout including
  setup and analysis.
- **Boxes owned.** Lame, Facts. Two on the wall.
- **Cornerman model validated.** Demonstrate chain → log to yaml →
  triage gaps → build tools → rematch. The next facts-class box
  is the proof.
- **GAP-032 still credited.** Operator's writeup names the vhost
  fix as "the real win" — without `a7f48a8` the cornerman's step 2
  would have been blocked the same way Drederick was in R1.
- **Authorization boundary held.** No `_scope.Require` in code
  fired during the chain (off-harness), but the operator never
  left the authorized target. The invariant is the boundary, not
  the path that enforces it. When the cornerman owned the keyboard,
  the cornerman owned the boundary too.

## Tatum's note

I prepared the table; my cornerman placed the dishes. That's how
the first W of the arc tastes — sweet, but honest. The chain we
ran was eleven steps deep and only one of them was a punch I threw
solo. The other ten are written in this tape as gaps because that
is what they are: things the champ doesn't know how to do yet.

The path to a solo W on the next facts-class box runs through
`gap-031b-2`, `llm-exec-shell-tool`, and GAP-036 through GAP-041.
Eight items in the bag. Ship them in dependency order. The cornerman
is patient; the gym is open; the bell rings tomorrow.

— *Filed from ringside, 2026-05-02 (later)*
