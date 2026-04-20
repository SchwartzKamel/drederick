# Modules

Every scanner lives under `src/Drederick/Recon/` and implements
`IReconTool`. Each scanner re-checks scope at its entry point via
`Scope.Require(target)`. If a target is not in scope, the scanner throws
`ScopeException` before any network activity. Every scanner brackets its
work with `audit.Record("<name>.start" / ".finish", …)` so every probe is
traceable in `audit.jsonl`.

Per-scanner result shapes live in `Drederick.Recon.HostFinding`; CLI flags
are defined in `Drederick.Cli.CommandLineOptions`.

## 1. `NmapTool`

- **Purpose:** service/version scan and first-pass NSE enumeration.
- **Subprocess:** `nmap -Pn -sV -sC -T4 --min-rate 1000 -oX - <target>`.
- **NSE categories:** lab `safe,default,discovery,version`; strict
  `safe,default`. **Never enables** `exploit`, `intrusive`, `brute`, `vuln`,
  `dos`, `malware` — hard-coded excluded in both modes.
- **Prohibitions:** exploit/brute/vuln/dos/malware NSE; user-supplied
  `--script` injection (port spec is regex-validated by
  `RejectUnsafePortSpec`).
- **Ports:** `--top-ports 1000` by default; accepts a whitelisted port
  spec (`1-65535`, `80,443`, …).
- **Result:** `HostFinding.Nmap` → `NmapResult { ReturnCode, Stderr,
  OpenPorts[] }` with per-port `service`/`product`/`version`/`scripts[]`.
- **CLI flags:** `--lab` / `--no-lab` controls NSE category set.
- **Dispatch trigger:** always runs in phase 1 alongside DNS.

## 2. `HttpProbeTool`

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

## 3. `TlsProbeTool`

- **Purpose:** peer certificate subject/SAN/issuer/validity and negotiated
  TLS version.
- **Subprocess:** none — .NET `SslStream`.
- **Prohibitions:** does **not** validate the cert against a trust store —
  we record what's presented, not what's trusted.
- **Result:** `HostFinding.Tls[]` → `TlsResult { Port, TlsVersion, Subject,
  Issuer, SubjectAltNames[], NotBefore, NotAfter, DaysUntilExpiry, Error }`.
- **CLI flags:** none beyond scope.
- **Dispatch trigger:** HTTPS / TLS-bearing service detected by nmap.

## 4. `DnsProbeTool`

- **Purpose:** forward + reverse DNS lookup via the host resolver.
- **Subprocess:** none — `System.Net.Dns`.
- **Prohibitions:** no zone transfer (see `DnsZoneTransferTool`), no
  recursion control, no axfr/ixfr, no DNS over HTTPS.
- **Result:** `HostFinding.Dns` → `DnsResult { Target, Forward, Reverse,
  ForwardError, ReverseError }`.
- **Dispatch trigger:** always runs in phase 1 alongside nmap.

## 5. `SmbTool`

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

## 6. `FtpTool`

- **Purpose:** banner + anonymous login + bounded root listing.
- **Subprocess:** none — raw TCP via an injectable connect factory.
- **Prohibitions:** never writes (no `STOR/DELE/MKD/RMD`), never brute-forces
  (only the single `anonymous` credential), never recurses. Hard caps:
  `MaxListingLines = 200`, `MaxListingBytes = 64 KiB`, 10 s total timeout.
- **Result:** `HostFinding.Ftp[]` → `FtpResult { Port, Banner,
  AnonymousAllowed, RootListing[], Error }`.
- **Dispatch trigger:** nmap service `ftp`.

## 7. `SshTool`

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

## 8. `SnmpTool`

- **Purpose:** SNMPv2c system-OID walk (`1.3.6.1.2.1.1`) with default
  communities `public` / `private`.
- **Subprocess:** `snmpwalk` — capped output size.
- **Prohibitions:** no community brute-force, no writes, no walks outside
  the system subtree.
- **Result:** `HostFinding.Snmp[]` → SNMP system OID entries.
- **Dispatch trigger:** nmap service `snmp`, or `service ~= snmp` on UDP.

## 9. `LdapTool`

- **Purpose:** anonymous bind + RootDSE attributes (`namingContexts`,
  `supportedControl`, `supportedLDAPVersion`, `supportedSASLMechanisms`).
- **Subprocess:** none — direct LDAP client.
- **Prohibitions:** no credentialed enumeration, no brute force, no
  directory writes.
- **Result:** `HostFinding.Ldap[]` → `LdapResult { Port, AnonymousBind,
  NamingContexts[], SupportedControls[], Error }`.
- **Dispatch trigger:** nmap service `ldap` or `ldaps`.

## 10. `RpcTool`

- **Purpose:** list RPC programs registered with the portmapper.
- **Subprocess:** `rpcinfo -p` plus `nmap --script rpc-grind`.
- **Prohibitions:** never mounts NFS, never dumps YP/NIS, never runs
  SunRPC exploits.
- **Result:** `HostFinding.Rpc[]` → `RpcResult { Port, Programs[] }`, where
  each `RpcProgram` carries `{ Program, Version, Protocol, Port, Name }`.
- **Dispatch trigger:** nmap service `sunrpc` or `rpcbind`.

## 11. `KerberosTool`

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

## 12. `DnsZoneTransferTool`

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

## 13. `HttpContentDiscoveryTool`

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

## 14. `TlsCipherEnumTool`

- **Purpose:** TLS version + cipher-suite enumeration per port.
- **Subprocess:** `nmap --script ssl-enum-ciphers` (safe category).
- **Prohibitions:** no downgrade attacks, no client-cert probing, no
  STARTTLS hijack.
- **Result:** `HostFinding.TlsCipherEnum[]` →
  `TlsCipherEnumResult { Port, Versions: { <tls-version>:
  { Ciphers[], Grade } }, Error }`.
- **Dispatch trigger:** HTTPS / TLS-bearing service detected by nmap
  (auto-paired with `tls` probe).

## Reporting

### `JsonReport`

Emits `out/report.json` containing the full `HostFinding` list.

### `MarkdownReport`

Emits `out/report.md`: per-host summary, open TCP services table, HTTP/TLS
details, errors.

### `ManualCommandsCheatsheet`

Creates `out/<host>/scans/`, `out/<host>/loot/`, `out/<host>/notes.md`. In
lab mode, also emits `out/<host>/manual_commands.txt` — enumeration commands
the operator *may* run themselves. Deliberately omits exploit, brute-force,
password-spray, and payload-delivery commands.

The cheatsheet recognizes: `http`/`https`, `ssh`, `ftp`, `smtp`, `dns`,
`smb` (`microsoft-ds`, `netbios-ssn`), `ldap`, `snmp`, `rpcbind`,
`kerberos`, `mysql`, `postgresql`, `redis`, `mongodb`. Unknown services get
a generic `nmap --script safe,default,discovery,version` suggestion.

### `SqliteReport`

Writes `out/findings.db` — seven tables (`hosts`, `services`, `findings`,
`cves`, `poc_refs`, `poc_sources`, `tooling`). Authoritative DDL in
`SqliteReport.EnsureSchema`. Browsed via Datasette
([`DATASETTE.md`](./DATASETTE.md)).

## Enrichment (not `IReconTool` — runs after recon completes)

### `CveAnnotator`

Matches every fingerprinted `(product, version)` from `NmapTool`
against a local NVD 2.0 cache (`~/.drederick/nvd/`) and writes
`kind = "cve"` findings plus `cves` rows. Offline fallback uses stale
cache. Opt-out via `DREDERICK_SKIP_CVE=1`.

### `PocAggregator` + `IPocSource` implementations

For every annotated CVE, walks the registered PoC sources —
`SearchsploitSource` (Exploit-DB), plus (in progress) GHSA, Metasploit
module names, nuclei template IDs — records a `poc_refs` row per pointer
and caches the source under `out/poc_cache/<source>/<external_id>/` with
SHA-256 provenance in `poc_sources`. Default-on; opt out with
`--no-fetch-poc`. **Drederick never executes cached PoC code and never
initiates outbound requests from it.**

## Planned enrichment sources

- **GHSA source** — GitHub Security Advisory mappings for the CVE set
  (pointers only, no code fetch).
- **Metasploit module source** — offline grep of the MSF modules tree
  detected by `drederick doctor` — record module names only.
- **Nuclei template source** — offline index of installed nuclei templates
  — record template IDs only.
