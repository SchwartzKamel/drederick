---
title: Scanner modules
audience: [humans, agents]
primary: both
stability: stable
last_audited: 2026-05
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

> **TL;DR.** ~24 `IReconTool` scanners under `src/Drederick/Recon/` (the 14
> classic recon tools below + 8 NSE-port natives under `Recon/Native/`)
> plus `FingerprintStackTool` under `Enrichment/FingerprintStack/`. Each
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

- **Purpose:** SNMPv2c/v1 system-OID walk across three subtrees
  (`1.3.6.1.2.1.1` system, `1.3.6.1.2.1.25` host-resources,
  `1.3.6.1.4.1` enterprise) with seven communities tried (`public`,
  `private`, `community`, `manager`, `admin`, `cisco`, `snmpd`).
- **Subprocess:** none — `Lextm.SharpSnmpLib` (`ISnmpWalker` abstraction).
- **Replaces:** `snmpwalk` subprocess dependency. Zero external tools required.
- **External dependency:** none (native via `Lextm.SharpSnmpLib` NuGet).
- **Scope check:** `_scope.Require(target)` as first statement.
- **Prohibitions:** no writes, no SET operations, no community brute-force
  beyond the built-in 7-entry set.
- **Result:** `HostFinding.Snmp[]` → SNMP system OID entries.
- **Dispatch trigger:** nmap or `NativeScannerTool` service hint `snmp`,
  or UDP port 161.

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
- **Subprocess:** none — `DnsClient.NET` `LookupClient.QueryServerAsync`
  with `QueryType.AXFR`.
- **Replaces:** `dig axfr <domain> @<nameserver>` subprocess dependency.
- **External dependency:** none (native via `DnsClient` NuGet).
- **Scope check:** `_scope.Require(target)` as first statement (nameserver IP).
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

## 16. `NativeScannerTool` {#scanner-native}

- **Class:** `NativeScannerTool` (`src/Drederick/Recon/NativeScannerTool.cs`)
- **Purpose:** Async TCP port scanner and service banner grabber. 57-port
  default set covering well-known services; `SemaphoreSlim`-bounded
  concurrency; TLS probe (SNI, certificate, negotiated version); Redis
  inline-command probe on port 6379. Zero external dependencies.
- **Subprocess:** none — `System.Net.Sockets.TcpClient` +
  `System.Net.Security.SslStream`.
- **Scope check:** `_scope.Require(target)` as first statement.
- **External dependency:** none (native).
- **Replaces:** primary use of `nmap` for basic port enumeration when nmap
  is not installed. `NmapTool` remains the optional enrichment layer for
  NSE scripts and deep version detection.
- **Prohibitions:** read-only banner grab; no auth probing; no write
  operations.
- **Result:** `HostFinding.NativeScan[]` → `NativeScanResult { Port, Open,
  Banner, ServiceHint, Tls { Version, Subject, Error } }`.
- **Dispatch trigger:** phase 1 alongside `NmapTool`; if nmap is absent,
  sole TCP port scanner.

## 17. `NativeDnsTool` {#scanner-native-dns}

- **Class:** `NativeDnsTool` (`src/Drederick/Recon/NativeDnsTool.cs`)
- **Purpose:** Full DNS record resolution (A/AAAA/MX/NS/TXT/SOA/PTR) using
  `DnsClient.NET`. No `dig` dependency. Covers all common record types
  needed for target enumeration and virtual-host discovery.
- **Subprocess:** none — `DnsClient.LookupClient`.
- **Scope check:** `_scope.Require(target)` as first statement.
- **External dependency:** none (native via `DnsClient` NuGet).
- **Replaces:** `dig` for basic DNS record queries. Complements
  `DnsProbeTool` (which uses `System.Net.Dns` for forward/reverse).
- **Prohibitions:** no recursive resolution beyond the configured system
  resolver; no zone transfer (see `DnsZoneTransferTool`).
- **Result:** `HostFinding.NativeDns[]` → `NativeDnsResult { RecordType,
  Name, Values[], Ttl, Error }`.
- **Dispatch trigger:** phase 1; runs alongside `DnsProbeTool`.

## 18. `ElfParser` / `PeParser` / `BinaryAnalyzer` {#scanner-binary}

- **Classes:** `ElfParser`, `PeParser`, `BinaryAnalyzer`
  (`src/Drederick/Recon/Binary/`)
- **Purpose:** Native ELF/PE binary analysis: magic detection, architecture,
  section enumeration, symbol extraction, imported libraries, entry-point,
  strings, embedded artifacts. Zero external tool dependencies. 46 parser
  tests + all 16 original tests pass.
- **Subprocess:** none — pure byte parsing over `Span<byte>` / `BinaryReader`.
- **Scope check:** `_scope.Require(target)` on path-resolved analysis start.
- **External dependency:** none (native).
- **Replaces:** `file`, `readelf`, `nm`, `strings`, `objdump` for structural
  binary analysis. `MagikaDetector` remains available for ML-based file-type
  hints (optional).
- **Prohibitions:** read-only; does not execute, disassemble beyond headers,
  or modify the analyzed artifact. Paths must resolve under the working
  directory (no workspace escape via `..`).
- **Result:** `BinaryAnalysisReport { Format, Architecture, Sections[],
  Symbols[], Strings[], Imports[], EntryPoint, Magika }`.
- **Dispatch trigger:** invoked by `ChallengeSolver` on CTF challenge
  binaries; available to the LLM runner via `ReconToolbox`.

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

Writes `out/findings.db` — eleven tables (`hosts`, `services`, `findings`,
`cves`, `poc_refs`, `poc_sources`, `tooling`, `exploit_runs`, `sessions`,
`loot`, plus `notes` whose DDL ships from `NotesSchema.GetCreateTableDdl()`).
Authoritative DDL in `SqliteReport.EnsureSchema`; doc mirror in
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
| `NativeHttpSprayTool` (pure-.NET HTTP spray: Basic/Digest/Tomcat/Jenkins/Grafana/WordPress/phpMyAdmin/OWA/WinRM) | `--allow-cred-attacks` + `--acknowledge-lockout-risk` |
| `PasswordSprayTool` | `--allow-cred-attacks` + `--acknowledge-lockout-risk` |
| `MultiStageExploitRunner` | `--allow-exec-pocs` + `--allow-payloads` |
| `ZeroLogonTool` (CVE-2020-1472, native C# Netlogon bypass + secretsdump) | `--allow-exec-pocs` + `--allow-cred-attacks` |
| `KerberoastTool` / `AsRepRoastTool` (`Drederick.Exploit.Ad`, AD ticket roasting) | `--allow-cred-attacks` |
| `HttpFormBruteTool` / `CmsChainExecutor` (declarative CMS chain w/ `KbSubstitutionResolver`) | `--allow-exec-pocs` (+ `--allow-cred-attacks` for brute steps) |
| `LlmExecShellTool` (LLM-driven post-ex shell over an open session) | (via active session; per-step scope check) |
| `EmpireAgentStager` (agent payload generation) | `--allow-payloads` |
| `EmpireModuleExecutor` (privesc/lateral movement) | `--allow-payloads` (+ `--allow-cred-attacks` for credential reuse) |
| `MalleableProfileLibrary` (Empire C2 profile selector — APT/Crimeware/Normal) | (config-time; no network) |
| `MacroPayloadGenerator` (VBA / HTA / LNK / ISO macro lures) | `--allow-phishing` |
| `PhishingDelivery` (SMB drop / WebDAV PUT / one-shot HTTP stager) | `--allow-phishing` (SMTP relay additionally requires `--allow-smtp-relay`; Phase 2) |
| `PostExLinux` / `PostExWindows` | (via session opened by exploit tools) |
| `SessionPivotProber` | (post-ex; pivot CIDRs re-checked per-IP) |

## Jeopardy CTF subsystem {#jeopardy-subsystem}

`src/Drederick/Jeopardy/` is a separate pipeline for challenge-based CTFs
(CTFd polling, LLM-driven solving, sandboxed tool execution, flag
submission). It is orthogonal to the offensive recon/exploit toolbox but
shares `Scope`, `AuditLog`, and `KnowledgeBase`. See
[`JEOPARDY.md`](JEOPARDY.md).

## Operational utilities {#ops-utilities}

### `PathResolver` (`src/Drederick/Ops/PathResolver.cs`)

- **Purpose:** `PathResolver.Which(name)` — replaces all `which` subprocess
  calls for tool-presence checks. Walks `PATH` environment variable entries
  to find the first matching executable; no subprocess spawn.
- **External dependency:** none (native).
- **Replaces:** `which` subprocess calls in `BinaryAnalyzer`, `MagikaDetector`,
  and any scanner that checks for optional external tools before shelling out.
- **Usage:**
  ```csharp
  string? nmapPath = PathResolver.Which("nmap");
  if (nmapPath is not null)
      // enrich with nmap NSE; else use NativeScannerTool result only
  ```

## NSE-ported native scanners (`src/Drederick/Recon/Native/`) {#scanner-native-nse-ports}

Pattern-3 ports of widely-used NSE scripts to native C# (see
[`PLUGIN_STRATEGY.md#pattern-3-ported-community-logic`](PLUGIN_STRATEGY.md#pattern-3-ported-community-logic)).
Every tool is an `IReconTool`, calls `_scope.Require(target)` as its first
statement, brackets work with `audit.Record(...)`, and never shells out.
HTTP-bearing tools share `NativeHttpClientFactory` (no auto-redirect, lax
TLS validation for fingerprinting only).

| Class | NSE script | Result on `HostFinding` | Notes |
| ----- | ---------- | ----------------------- | ----- |
| `HttpTitleTool` | `http-title` | `HttpTitle[]` | GET `/` and extract `<title>` (256 KiB body cap). |
| `HttpHeadersTool` | `http-headers` | `HttpHeaders[]` | HEAD/GET, captures full response header set. |
| `HttpRobotsTool` | `http-robots` | `HttpRobots[]` | GET `/robots.txt`, parses `User-agent`/`Disallow`. |
| `HttpMethodsTool` | `http-methods` | `HttpMethods[]` | OPTIONS probe; flags risky verbs (`PUT`/`DELETE`/`TRACE`). |
| `SslCertTool` | `ssl-cert` | `SslCert[]` | Certificate chain dump (subject/SAN/issuer/validity). Complements `TlsProbeTool`. |
| `SshHostkeyTool` | `ssh-hostkey` | `SshHostkey[]` | Per-key-type fingerprint enumeration (SHA-256 / MD5). |
| `FtpAnonTool` | `ftp-anon` | `FtpAnon[]` | Anonymous login + bounded `LIST` (200 lines / 64 KiB). PASV target re-validated through scope before opening data channel. |
| `LdapRootDseTool` | `ldap-rootdse` | `LdapRootDse[]` | Anonymous bind + RootDSE attribute dump. |

`NativeHttpClientFactory` (`Recon/Native/NativeHttpClientFactory.cs`) is the
shared `HttpClient` factory — `AllowAutoRedirect = false`, `ConnectTimeout =
8s`, custom `User-Agent: Drederick/1.0 (+recon)`, default 15s overall
timeout.

## `HostDiscoveryTool` {#scanner-host-discovery}

- **Class:** `HostDiscoveryTool` (`src/Drederick/Recon/HostDiscoveryTool.cs`)
- **Purpose:** Fast first-pass TCP-knock sweep across a `/N` scope. Probes
  a small curated set of "known-noisy" ports (`80, 443, 22, 445, 3389, 5985`
  by default) per target in parallel; the first successful connect marks a
  host alive and seeds downstream port scanners with the responding ports.
  Designed for HTB Pro Labs / OSCP-style ranges where deep-scanning every
  /16 IP is wasteful.
- **Subprocess:** none — `TcpClient` with `SemaphoreSlim`-bounded
  concurrency.
- **Scope check:** `_scope.Require(target)` re-checked **per target** before
  any socket is opened.
- **External dependency:** none (native).
- **Result:** `HostDiscoveryResult { Address, Alive, RespondingPorts[],
  Latency }`.
- **Dispatch trigger:** explicit (called by orchestration when the scope
  contains a `/N` block); not auto-invoked per-host like phase-1 scanners.

## Unified port-harvest contract {#unified-port-harvest}

`ExploitationPlanner.HarvestPortsFromAllSignals(HostFinding)` is the single
source of truth that downstream offensive logic uses to enumerate the open
ports of a target. It folds **every** positive recon signal into a single
`Dictionary<int, NmapPort>` keyed by port. The contract:

1. **Real `NmapTool` output wins on collision.** `host.Nmap.OpenPorts` is
   seeded first; later signals never overwrite a port already present.
2. **`NativeScanResult` ports fill gaps.** When nmap is absent or missed a
   port, `host.NativeScan.OpenPorts` is folded in.
3. **Native protocol probes are positive evidence the port is open** even
   when neither nmap nor `NativeScannerTool` reported it. The harvester
   walks every signal sibling and seeds with a service hint.

| Signal source on `HostFinding` | Seeded service hint |
| ------------------------------ | ------------------- |
| `Nmap.OpenPorts` (authoritative) | as reported |
| `NativeScan.OpenPorts` | as reported |
| `Http`, `HttpTitle`, `HttpHeaders`, `HttpRobots`, `HttpMethods`, `HttpContentDiscovery` | `http` |
| `Tls`, `TlsCipherEnum`, `SslCert` | `https` |
| `Ftp`, `FtpAnon` | `ftp` |
| `Ssh`, `SshHostkey` | `ssh` |
| `Snmp` | `snmp` |
| `Smb` | `microsoft-ds` |
| `Ldap`, `LdapRootDse` | `ldap` |
| `Rpc` | `msrpc` |
| `Kerberos` | `kerberos` |

URL-bearing signals (`Http*`) extract the port via `PortFromUrl` (defaults
to 80/443 by scheme when no explicit port is present). The harvester is
pure — no scope calls, no I/O — so it is safe to invoke from the
deterministic runner, the LLM runner, `ChainReasoner`, and
`ArchetypeClassifier` alike. Reference:
`src/Drederick/Autopilot/ExploitationPlanner.cs` lines 448-513.

## ChainReasoner — multi-step exploitation chain planner {#chain-reasoner}

- **Path:** `src/Drederick/Autopilot/ChainReasoner/`
  (`ChainReasoner.cs`, `ChainTemplate.cs`, `ChainFacts.cs`, `ChainCommand.cs`,
  `AttackChain.cs`).
- **Role:** deterministic chain proposer. Reads predicates from
  `ChainFacts` (synthesized from `KnowledgeBase` + `HostFinding` +
  `CredentialStore`), instantiates every `ChainTemplate` whose `Requires`
  list is satisfied, computes `score = likelihood × impact − cost`, and
  returns the top-N ranked `AttackChain[]` with explainability fields.
- **LLM augmentation:** optional `IChainAugmenter`. Default
  `NoOpChainAugmenter` is used when `--agent` is not set; an LLM-backed
  augmenter may add candidates derived from the same `ChainFacts`. Failures
  are recorded as `chain.augmenter.error` audit events and the reasoner
  falls back to deterministic output.
- **Scope posture:** `ChainReasoner` itself does **not** call
  `Scope.Require` and does not touch the network — it manipulates pure
  data. Tools that later execute the steps re-check scope as their first
  statement (`@invariant-id:scope-in-every-tool`).
- **Example chain:** `anon-smb-read → grep-creds-in-share → smb-exec →
  loot-sam → ad-privesc`. Each `ChainCommand` is keyed to a concrete
  `IExploitTool` invocation downstream.

## Cross-protocol credential replay (`xprotocol-replay`) {#exploit-replay}

- **Path:** `src/Drederick/Exploit/Replay/` (14 files: 6 core + 8 protocol
  adapters under `Protocols/`).
- **Role:** Pattern-4 original Drederick tooling — take one captured
  credential triplet (`CredentialTriplet { Username, Domain, SecretKind,
  SecretSha256, … }`) and replay it in parallel across every in-scope host
  on every supported protocol. Where NetExec replays SMB only, this covers
  the full surface.
- **Adapters (`Protocols/`):** `SmbReplayAdapter`, `WinRmReplayAdapter`,
  `MssqlReplayAdapter`, `LdapReplayAdapter`, `SshReplayAdapter`,
  `HttpReplayAdapter`, `RdpReplayAdapter`, plus the
  `NetexecReplayAdapterBase` shared base for adapters that wrap an external
  netexec invocation. Each adapter implements `IReplayProtocolAdapter` and
  must:
  1. Call `_scope.Require(target)` as the first statement of `ReplayAsync`.
  2. Re-check `RunPermissions.AllowCredAttacks` **and**
     `RunPermissions.AcknowledgeLockoutRisk`; on miss, emit
     `ReplayOutcome.Skipped` with `error_reason = permission_refused` /
     `lockout_risk_refused` (do not throw — let the matrix complete
     partially).
  3. Skip with `credential_kind_unsupported` when the triplet's `SecretKind`
     is unsupported by this protocol (e.g. SSH + NTLM hash).
  4. Validate every argv field for shell metacharacters; skip with
     `argv_refused` on miss.
  5. Never log plaintext or NTLM material — audit events carry
     `SecretSha256` only.
- **Coordination:** `CrossProtocolReplay` owns the host × protocol matrix,
  bounds parallelism via `SemaphoreSlim`, and consumes an
  `IReplayLockoutScheduler` for global AD-policy-aware throttling.
- **Result:** `CrossProtocolReplayReport { Successes[], Skipped[],
  Failures[] }`. Replay is a **pure tool** — it does not write to
  `KnowledgeBase` / `CredentialStore` / `findings.db` directly; the runner
  that owns the credential is responsible for feeding successes back into
  those stores (avoids a dependency cycle through `Drederick.Autopilot`).
- **Gates:** `--allow-cred-attacks` + `--acknowledge-lockout-risk`.

## Additional recon scanners {#additional-recon-scanners}

Beyond the 14 classic recon tools above, several more `IReconTool`
scanners ship under `src/Drederick/Recon/` and `src/Drederick/Recon/Native/`,
plus `FingerprintStackTool` under `src/Drederick/Enrichment/FingerprintStack/`.
All follow the standard pattern (`_scope.Require` first, audit
bracketing, typed `HostFinding` result, argv validation).

- **`HostDiscoveryTool`** — ARP / ICMP / TCP-ping sweep across an in-scope
  CIDR. Documented in detail at [`#scanner-host-discovery`](#scanner-host-discovery).
- **`S3MinioProbeTool`** — anonymous S3 / MinIO bucket discovery + listing
  against in-scope HTTP services.
- **`CmsFingerprintTool`** — version + plugin/theme detection for
  WordPress / Drupal / Joomla. Feeds `CmsChainExecutor` selection.
- **`SmbNullSessionTool`** — SMB null-session enumeration (shares, users,
  groups, RID cycling) against scope-validated SMB hosts.
- **`CertVulnerabilityEnumTool`** — AD CS template enumeration looking for
  ESC1–ESC8 misconfigurations.
- **`DcSyncDetectionTool`** — detects accounts with `Replicating Directory
  Changes` / `…All` rights (DCSync prerequisites).
- **`DelegationEnumTool`** — unconstrained / constrained / RBCD delegation
  enumeration on AD accounts.
- **`NseProxy`** (`src/Drederick/Recon/NseProxy.cs`) — runs a curated NSE
  category against an already-open port set, surfacing structured findings
  back through `HostFinding` for the planner.
- **NSE-ported natives** under `src/Drederick/Recon/Native/` — see
  [`#scanner-native-nse-ports`](#scanner-native-nse-ports) for the eight
  pure-.NET ports (no `nmap` dependency).
- **`FingerprintStackTool`** (`Drederick.Enrichment.FingerprintStack`) —
  banner + favicon + header + body multi-signal fingerprinter; consumes the
  `LearnedFingerprintStore` so each engagement sharpens the corpus.

## CMS chain step `KbSubstitutionResolver` {#kb-substitution-resolver}

`src/Drederick/Exploit/Web/KbSubstitutionResolver.cs` resolves
`${kb.<path>:<default>}` placeholders inside `cms-chain-templates.yaml`
chain steps against `KnowledgeBase` at run-time:

- **Inputs:** the raw step argument template, the active `KnowledgeBase`,
  the live `Scope.Scope`, and the run's `AuditLog`.
- **Lookup:** `${kb.host.cms.admin_path:/wp-admin/}` walks the JSON path
  in `KnowledgeBase` for the active host. Missing keys fall back to the
  inline default; missing keys without a default are recorded as
  `chain.kb_substitution.unresolved` and short-circuit the step.
- **Audit events:** every successful resolution emits
  `chain.kb_substitution.resolved` with the path + a SHA-256 of the
  resolved value (no plaintext); failures emit
  `chain.kb_substitution.unresolved`.
- **Scope:** the resolver itself is pure (no network); downstream chain
  steps re-check scope per `@invariant-id:scope-in-every-tool`.

## `FightNotebook` + learning surface {#fight-notebook}

`src/Drederick/Learning/` is the cross-engagement memory layer:

- **`FightNotebook`** (`FightNotebook.cs`) — append-only JSONL at
  `memory/fight-notebook.jsonl`. The LLM planner gets a `take_note`
  `AIFunction`; the operator gets a `notebook` CLI subcommand. Every note
  is tagged (kind + fight + tactic) and replayed into the planner's
  context on subsequent runs.
- **`FightCorpus`** (`FightCorpus.cs`) — read-only loader for the
  operator-curated `~/HTB/fight-log.yaml` catalog; surfaces prior
  wins/losses + open `GAP-NNN` items.
- **`ArchetypeClassifier`** + **`TargetArchetype`** — classifies each
  target into a working archetype (web / AD / file-share / …) so the
  runner picks enumeration depth and exploit selection per fight.
- **`LearnedFingerprintStore`** + **`FingerprintLearner`**
  (`src/Drederick/Enrichment/FingerprintStack/`) — auto-grows the
  fingerprint corpus from each engagement and persists at
  `out/memory/learned-fingerprints.json`.

See [`LEARNING_LOOP.md`](LEARNING_LOOP.md) for the operator-facing
workflow and [`ARCHITECTURE.md#layer-learning`](ARCHITECTURE.md#layer-learning)
for layer wiring.

## Scaffolding loader {#scaffolding-loader}

`src/Drederick/Scaffolding/` is the in-fight scaffolding loader per
`machines/SCAFFOLDING/LOADER_SPEC.md`. It is **read-only context** — it
never executes tools or touches the network.

- **`BriefingDocument`** + **`BriefingLoader`** — parses per-machine
  `briefing.md` (target metadata, declared trophies, scope hints) into a
  typed shape consumed by every runner.
- **`AttackGraph`** + **`AttackGraphLoader`** — parses
  `attack-graph.yaml` (nodes = capabilities; edges = required
  preconditions). Unknown vocabulary is preserved, not rejected, so
  playbooks can evolve without breaking the loader.
- **`ScaffoldingDiscovery`** — walks the briefing root, locates briefing
  + attack-graph + cornerman files, and produces a bundled
  **`ScaffoldingContext`** that `AdaptiveRunner`,
  `MicrosoftAgentRunner`, and `AutopilotRunner` all read at run-start.

Downstream tools still enforce scope per
`@invariant-id:scope-in-every-tool`; nothing in the scaffolding layer is
a security boundary.
