---
title: Scanner modules
audience: [humans, agents]
primary: both
stability: stable
last_audited: 2026-04
related:
  - ARCHITECTURE.md
  - POST_EXPLOITATION.md
  - EMPIRE.md
  - C2_INTEGRATION.md
  - JEOPARDY.md
  - DEVELOPING.md
  - SCOPE_AND_LEGAL.md
  - ../AGENTS.md
---

# Modules

> **TL;DR.** 14 `IReconTool` scanners under `src/Drederick/Recon/`. Each
> checks `_scope.Require(target)` as its first statement, brackets work with
> `audit.Record("<name>.start"/".finish", …)`, returns a typed result on
> `HostFinding`, and validates any subprocess argv. Per-scanner anchors
> below: [`{#scanner-nmap}`](#scanner-nmap), [`{#scanner-http}`](#scanner-http),
> [`{#scanner-tls}`](#scanner-tls), [`{#scanner-dns}`](#scanner-dns),
> [`{#scanner-smb}`](#scanner-smb), [`{#scanner-ftp}`](#scanner-ftp),
> [`{#scanner-ssh}`](#scanner-ssh), [`{#scanner-snmp}`](#scanner-snmp),
> [`{#scanner-ldap}`](#scanner-ldap), [`{#scanner-rpc}`](#scanner-rpc),
> [`{#scanner-kerberos}`](#scanner-kerberos),
> [`{#scanner-dns-axfr}`](#scanner-dns-axfr),
> [`{#scanner-http-content-discovery}`](#scanner-http-content-discovery),
> [`{#scanner-tls-cipher-enum}`](#scanner-tls-cipher-enum).
>
> **Scope is the authorization boundary for every recon tool**; opt-in
> category flags (`--allow-exec-pocs`, `--allow-cred-attacks`,
> `--allow-payloads`, `--allow-destructive`, `--allow-dos`) gate the
> exploit-side toolbox documented in [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md)
> and [`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md). See
> [`../AGENTS.md#invariants`](../AGENTS.md#invariants) for the invariant
> table.
>
> A parallel Jeopardy CTF subsystem lives under
> [`src/Drederick/Jeopardy/`](../src/Drederick/Jeopardy/); see
> [`JEOPARDY.md`](JEOPARDY.md).

Every scanner lives under `src/Drederick/Recon/` and implements
`IReconTool`. Each scanner re-checks scope at its entry point via
`Scope.Require(target)`. If a target is not in scope, the scanner throws
`ScopeException` before any network activity. Every scanner brackets its
work with `audit.Record("<name>.start" / ".finish", …)` so every probe is
traceable in `audit.jsonl`.

Per-scanner result shapes live in `Drederick.Recon.HostFinding`; CLI flags
are defined in `Drederick.Cli.CommandLineOptions`.

## 1. `NmapTool` {#scanner-nmap}

- **Purpose:** service/version scan and first-pass NSE enumeration.
- **Subprocess:** `nmap -Pn -sV -sC -T4 --min-rate 1000 -oX - <target>`.
- **NSE categories:** opt-in-expanding. Strict mode baseline
  `safe,default`; lab mode adds `discovery,version`;
  `--allow-cred-attacks` (or lab mode) adds `auth`; `--allow-exec-pocs`
  adds `intrusive,vuln,exploit`; `--allow-dos` adds `dos,malware`. See
  `NseCategoriesStrict` / `NseCategoriesLab` in `NmapTool` for the
  authoritative list.
- **Prohibitions:** argv injection (port spec is regex-validated by
  `RejectUnsafePortSpec`). No user-supplied `--script` values — the
  category set is picked by the CLI flags above.
- **Ports:** `--top-ports 1000` by default; accepts a whitelisted port
  spec (`1-65535`, `80,443`, …).
- **Result:** `HostFinding.Nmap` → `NmapResult { ReturnCode, Stderr,
  OpenPorts[] }` with per-port `service`/`product`/`version`/`scripts[]`.
- **CLI flags:** `--lab` / `--no-lab` controls NSE category set.
- **Dispatch trigger:** always runs in phase 1 alongside DNS.

## 2. `HttpProbeTool` {#scanner-http}

- **Purpose:** status, title, server, content-type, and missing
  security-header inventory for a single HTTP(S) endpoint.
- **Subprocess:** none — `HttpClient`, no request body, no auth.
- **Prohibitions:** no body/auth/header injection; follows redirects only
  within scope; no content discovery (see `HttpContentDiscoveryTool`).
- **Result:** `HostFinding.Http[]` → `HttpResult { Url, Status, FinalUrl,
  Server, Title, ContentType, MissingSecurityHeaders[], Error }`.
- **CLI flags:** none beyond scope.
- **Dispatch trigger:** auto-dispatched when nmap reports
  `service ~= http` or the port is one of `80, 8080, 8000, 8008, 8888,
  3000, 5000`; HTTPS variant when `service ~= https|ssl|tls`.

## 3. `TlsProbeTool` {#scanner-tls}

- **Purpose:** peer certificate subject/SAN/issuer/validity and negotiated
  TLS version.
- **Subprocess:** none — .NET `SslStream`.
- **Prohibitions:** does **not** validate the cert against a trust store —
  we record what's presented, not what's trusted.
- **Result:** `HostFinding.Tls[]` → `TlsResult { Port, TlsVersion, Subject,
  Issuer, SubjectAltNames[], NotBefore, NotAfter, DaysUntilExpiry, Error }`.
- **CLI flags:** none beyond scope.
- **Dispatch trigger:** HTTPS / TLS-bearing service detected by nmap.

## 4. `DnsProbeTool` {#scanner-dns}

- **Purpose:** forward + reverse DNS lookup via the host resolver.
- **Subprocess:** none — `System.Net.Dns`.
- **Prohibitions:** no zone transfer (see `DnsZoneTransferTool`), no
  recursion control, no axfr/ixfr, no DNS over HTTPS.
- **Result:** `HostFinding.Dns` → `DnsResult { Target, Forward, Reverse,
  ForwardError, ReverseError }`.
- **Dispatch trigger:** always runs in phase 1 alongside nmap.

## 5. `SmbTool` {#scanner-smb}

- **Purpose:** SMB OS/identity/dialect/signing inventory; optional
  anonymous shares + users via `enum4linux-ng`.
- **Subprocesses:** `nmap -Pn -p 139,445 --script
  smb-os-discovery,smb-protocols,smb2-security-mode -oX -`, and when
  available `enum4linux-ng -A -R <target>`.
- **Prohibitions:** denylisted script fragments `brute`, `vuln`,
  `enum-users`, `enum-shares` (credentialed variants); no credentials
  ever, no mounts, no writes. `AssertNoForbiddenScripts` asserts the
  built argv.
- **Result:** `HostFinding.Smb[]` → `SmbResult { Port, Os, ComputerName,
  Domain, Protocols[], SigningRequired, Shares[], Users[], Error }`.
- **CLI flags:** none beyond scope.
- **Dispatch trigger:** nmap service `microsoft-ds` or `netbios-ssn`.

## 6. `FtpTool` {#scanner-ftp}

- **Purpose:** banner + anonymous login + bounded root listing.
- **Subprocess:** none — raw TCP via an injectable connect factory.
- **Prohibitions:** never writes (no `STOR/DELE/MKD/RMD`), never brute-forces
  (only the single `anonymous` credential), never recurses. Hard caps:
  `MaxListingLines = 200`, `MaxListingBytes = 64 KiB`, 10 s total timeout.
- **Result:** `HostFinding.Ftp[]` → `FtpResult { Port, Banner,
  AnonymousAllowed, RootListing[], Error }`.
- **Dispatch trigger:** nmap service `ftp`.

## 7. `SshTool` {#scanner-ssh}

- **Purpose:** banner + KEX/host-key/cipher/MAC algorithm lists via
  `ssh2-enum-algos`.
- **Subprocess:** `nmap` with the `ssh2-enum-algos` NSE script
  (safe category).
- **Prohibitions:** no auth attempts, no key exchange beyond banner
  exchange, no `ssh-brute`, no `ssh-auth-methods` with credentials.
- **Result:** `HostFinding.Ssh[]` → `SshResult { Port, Banner,
  KexAlgorithms[], HostKeyAlgorithms[], EncryptionAlgorithms[],
  MacAlgorithms[], … }`.
- **Dispatch trigger:** nmap service `ssh`.

## 8. `SnmpTool` {#scanner-snmp}

- **Purpose:** SNMPv2c system-OID walk (`1.3.6.1.2.1.1`) with default
  communities `public` / `private`.
- **Subprocess:** `snmpwalk` — capped output size.
- **Prohibitions:** no community brute-force, no writes, no walks outside
  the system subtree.
- **Result:** `HostFinding.Snmp[]` → SNMP system OID entries.
- **Dispatch trigger:** nmap service `snmp`, or `service ~= snmp` on UDP.

## 9. `LdapTool` {#scanner-ldap}

- **Purpose:** anonymous bind + RootDSE attributes (`namingContexts`,
  `supportedControl`, `supportedLDAPVersion`, `supportedSASLMechanisms`).
- **Subprocess:** none — direct LDAP client.
- **Prohibitions:** no credentialed enumeration, no brute force, no
  directory writes.
- **Result:** `HostFinding.Ldap[]` → `LdapResult { Port, AnonymousBind,
  NamingContexts[], SupportedControls[], Error }`.
- **Dispatch trigger:** nmap service `ldap` or `ldaps`.

## 10. `RpcTool` {#scanner-rpc}

- **Purpose:** list RPC programs registered with the portmapper.
- **Subprocess:** `rpcinfo -p` plus `nmap --script rpc-grind`.
- **Prohibitions:** never mounts NFS, never dumps YP/NIS, never runs
  SunRPC exploits.
- **Result:** `HostFinding.Rpc[]` → `RpcResult { Port, Programs[] }`, where
  each `RpcProgram` carries `{ Program, Version, Protocol, Port, Name }`.
- **Dispatch trigger:** nmap service `sunrpc` or `rpcbind`.

## 11. `KerberosTool` {#scanner-kerberos}

- **Purpose:** Kerberos realm + **SPN listing only**, sourced via LDAP
  anonymous bind.
- **Subprocess:** none — LDAP client.
- **Prohibitions:** **no** AS-REP roasting, **no** kerberoasting, **no**
  TGT/TGS requests, **no** user enumeration by timing, **no** password
  spray.
- **Result:** `HostFinding.Kerberos[]` → `KerberosResult { Port, Realm,
  Spns[], Error }`.
- **Dispatch trigger:** paired with `ldap` dispatch when nmap reports
  `ldap` / `ldaps` on a Domain Controller.

## 12. `DnsZoneTransferTool` {#scanner-dns-axfr}

- **Purpose:** DNS AXFR against an in-scope nameserver IP for a given
  domain label.
- **Subprocess:** `dig axfr <domain> @<nameserver>`.
- **Prohibitions:** nameserver **must** be an IP literal in scope; domain
  is a label only (no wildcards, no injected query flags). AXFR is a
  legitimate enumeration query, not an exploit.
- **Result:** `HostFinding.DnsZoneTransfer[]` → `DnsZoneTransferResult
  { Domain, NameServer, Success, Records[], Error }`.
- **CLI flags:** none beyond scope; triggered explicitly by the LLM runner
  or by the deterministic runner when DNS service metadata suggests a
  candidate domain.

## 13. `HttpContentDiscoveryTool` {#scanner-http-content-discovery}

- **Purpose:** path-only content discovery against an HTTP(S) base URL.
  GETs a bounded, sanitized wordlist and records statuses in
  `{200, 201, 204, 301, 302, 307, 401, 403}` (404 intentionally dropped).
- **Subprocess:** none — `HttpClient`, rate-limited (default 10 rps).
- **Prohibitions:** **NO** query-parameter fuzzing, **NO** POST bodies,
  **NO** header injection, **NO** auth probing. Wordlist size hard-capped
  at `MaxWordlistEntries = 2000`; paths validated by `IsSafePath`.
- **Result:** `HostFinding.HttpContentDiscovery[]` →
  `HttpContentDiscoveryResult { BaseUrl, Entries[], Error }` where each
  entry is `{ Path, Status, Size }`.
- **CLI flags:** gated on `--content-discovery` for deterministic
  auto-dispatch. The LLM runner can still invoke the tool directly
  regardless of the flag (budget-metered).
- **Dispatch trigger:** any HTTP/HTTPS service when `--content-discovery`
  is set.

## 14. `TlsCipherEnumTool` {#scanner-tls-cipher-enum}

- **Purpose:** TLS version + cipher-suite enumeration per port.
- **Subprocess:** `nmap --script ssl-enum-ciphers` (safe category).
- **Prohibitions:** no downgrade attacks, no client-cert probing, no
  STARTTLS hijack.
- **Result:** `HostFinding.TlsCipherEnum[]` →
  `TlsCipherEnumResult { Port, Versions: { <tls-version>:
  { Ciphers[], Grade } }, Error }`.
- **Dispatch trigger:** HTTPS / TLS-bearing service detected by nmap
  (auto-paired with `tls` probe).

## 15. `MagikaDetector` (binary pre-pass) {#binary-magika}

- **Purpose:** Fast ML-based file-type classification; used as a
  pre-pass inside `BinaryAnalyzer` (see
  [`MAGIKA.md`](MAGIKA.md)) and planned as a category-hint feed for the
  CTF `ChallengeSolver`.
- **Subprocess:** `magika --jsonl <file>` (optional tool — warns, never
  fails, when missing). Install: `pipx install magika` (primary) or
  `cargo install magika` (fallback).
- **Scope / path validation:** path must be absolute and resolve under
  the current working directory; literal `..` segments are rejected
  before spawn. Out-of-workspace paths fall through to the non-magika
  path (analysis still runs).
- **Audit:** `magika.detect.start` / `.finish` events record the file
  path and a SHA-256 digest of the path string. File contents are
  never logged. `magika.detect.unavailable` fires at most once per
  detector instance.
- **Result:** `BinaryAnalysisReport.Magika → MagikaVerdict { Label,
  Description, Group, MimeType, Extension, Confidence, IsText,
  RawJson }`. When magika disagrees with `file` on whether the
  artifact is an executable (e.g. magika says `zip` for a file `file`
  reports as ELF), a warning finding is emitted.
- **Doctor check:** `recon.magika.available`
  ([`MagikaToolCheck`](../src/Drederick/Doctor/MagikaToolCheck.cs)).
  Wired via `drederick doctor --category=recon`.

## Reporting {#reporting}

### `JsonReport`

Emits `out/report.json` containing the full `HostFinding` list.

### `MarkdownReport`

Emits `out/report.md`: per-host summary, open TCP services table, HTTP/TLS
details, errors.

### `ManualCommandsCheatsheet`

Creates `out/<host>/scans/`, `out/<host>/loot/`, `out/<host>/notes.md`. In
lab mode, also emits `out/<host>/manual_commands.txt` — service-specific
enumeration commands the operator *may* run themselves. The cheatsheet
file is advisory and does not drive Drederick's execution path;
exploits, credential attacks, and payload delivery run through the
[`ExploitToolbox`](ARCHITECTURE.md#layer-exploit) and
[post-ex layer](POST_EXPLOITATION.md), not by parsing this text.

The cheatsheet recognizes: `http`/`https`, `ssh`, `ftp`, `smtp`, `dns`,
`smb` (`microsoft-ds`, `netbios-ssn`), `ldap`, `snmp`, `rpcbind`,
`kerberos`, `mysql`, `postgresql`, `redis`, `mongodb`. Unknown services get
a generic `nmap --script safe,default,discovery,version` suggestion.

### `SqliteReport`

Writes `out/findings.db` — ten tables (`hosts`, `services`, `findings`,
`cves`, `poc_refs`, `poc_sources`, `tooling`, `exploit_runs`, `sessions`,
`loot`). Authoritative DDL in `SqliteReport.EnsureSchema`; doc mirror in
[`DB_SCHEMA.md`](./DB_SCHEMA.md). Browsed via Datasette
([`DATASETTE.md`](./DATASETTE.md)).

## Enrichment (not `IReconTool` — runs after recon completes) {#enrichment}

### `CveAnnotator`

Matches every fingerprinted `(product, version)` from `NmapTool`
against a local NVD 2.0 cache (`~/.drederick/nvd/`) and writes
`kind = "cve"` findings plus `cves` rows. Offline fallback uses stale
cache. Opt-out via `DREDERICK_SKIP_CVE=1`.

### `PocAggregator` + `IPocSource` implementations

For every annotated CVE, walks the registered PoC sources —
`SearchsploitSource` (Exploit-DB), `GhsaSource` (GitHub Security
Advisories), `MetasploitSource` (module index), `NucleiSource` (template
index) — records a `poc_refs` row per pointer and caches the source
under `out/poc_cache/<source>/<external_id>/` with SHA-256 provenance in
`poc_sources`. Artifacts are stored **verbatim**. Default-on; opt out
with `--no-fetch-poc`. Execution of cached PoCs is handled by
[`ExploitRunner`](ARCHITECTURE.md#layer-exploit) under
`--allow-exec-pocs`, not by `PocAggregator` itself.

## Offensive toolbox (exploit + post-ex) {#offensive-toolbox}

Exploit, credential, payload, and post-ex tools under
`src/Drederick/Exploit/` are documented in
[`POST_EXPLOITATION.md`](POST_EXPLOITATION.md) and the
[`Drederick.Exploit` architecture section](ARCHITECTURE.md#layer-exploit).
Each one follows the same pattern as a recon tool (`_scope.Require` as
first statement, audit bracketing, typed result) plus a
[`RunPermissions`](../src/Drederick/Exploit/RunPermissions.cs) category
gate. Summary:

| Tool | Category flag(s) |
| ---- | ---------------- |
| `ExploitRunner` (cached PoC spawn) | `--allow-exec-pocs` |
| `MsfRcRunner` (msfconsole `-r`) | `--allow-exec-pocs` (+ `--allow-payloads` when delivering) |
| `NucleiRunner` | `--allow-exec-pocs` |
| `PasswordSprayTool` | `--allow-cred-attacks` + `--acknowledge-lockout-risk` |
| `MultiStageExploitRunner` | `--allow-exec-pocs` + `--allow-payloads` |
| `EmpireAgentStager` (agent payload generation) | `--allow-payloads` |
| `EmpireModuleExecutor` (privesc/lateral movement) | `--allow-payloads` (+ `--allow-cred-attacks` for credential reuse) |
| `PostExLinux` / `PostExWindows` | (via session opened by exploit tools) |
| `SessionPivotProber` | (post-ex; pivot CIDRs re-checked per-IP) |

## Jeopardy CTF subsystem {#jeopardy-subsystem}

`src/Drederick/Jeopardy/` is a separate pipeline for challenge-based CTFs
(CTFd polling, LLM-driven solving, sandboxed tool execution, flag
submission). It is orthogonal to the offensive recon/exploit toolbox but
shares `Scope`, `AuditLog`, and `KnowledgeBase`. See
[`JEOPARDY.md`](JEOPARDY.md).
