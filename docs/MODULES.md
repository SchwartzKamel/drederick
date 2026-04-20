# Modules

Every scanner lives under `src/Drederick/Recon/` and re-checks scope at its
entry point via `Scope.Require(target)`. If a target is not in scope, the
scanner throws `ScopeException` before any network activity.

## NmapTool

Wrapper around the `nmap` binary.

- **Flags:** `-Pn -sV -sC -T4 --min-rate 1000`
- **NSE categories:**
  - Lab mode (default): `safe,default,discovery,version`
  - Strict mode: `safe,default`
- **Never enables:** `exploit`, `intrusive`, `brute`, `vuln`, `dos`, `malware`.
- **Ports:** `--top-ports 1000` by default; accepts a port spec (e.g.
  `1-65535`, `80,443`) that is validated before being passed to nmap — only
  digits, commas, and dashes, no leading/trailing separators, no adjacent
  separators.
- **Output:** parses `-oX -` XML from stdout into `NmapResult`
  (`returncode`, `open_ports`, per-port `service`/`product`/`version` and
  script output).
- **Failure modes:** `nmap` not on `PATH` (returncode `-1`, error in
  `stderr`); XML parse failure (partial result with `stderr: xml-parse:...`);
  non-zero exit (`stderr` trimmed to the last 2 KB).

## HttpProbeTool

- Fetches an HTTP(S) response, records status, final URL, `Server`, `<title>`,
  `Content-Type`, and which of the common security headers are missing.
- Safe: no request bodies, no authentication.
- Failure modes: connection refused, TLS handshake failure — recorded as
  `error` on the `HttpResult`.

## TlsProbeTool

- Completes a TLS handshake and records the peer certificate subject, SAN,
  issuer, validity window, days-until-expiry, and negotiated TLS version.
- No attempt to validate the certificate against a trust store — we are
  recording what is presented, not trusting it.

## DnsProbeTool

- Forward and reverse DNS lookup using the host resolver.
- Records resolution errors separately for forward and reverse.

## Reporting

### `JsonReport`

Emits `out/report.json` containing the full `HostFinding` list.

### `MarkdownReport`

Emits `out/report.md`: per-host summary, open TCP services table, HTTP/TLS
details, errors.

### `ManualCommandsCheatsheet`

Creates `out/<host>/scans/`, `out/<host>/loot/`, `out/<host>/notes.md`. In lab
mode, also emits `out/<host>/manual_commands.txt` — enumeration commands the
operator *may* run themselves. Deliberately omits exploit, brute-force,
password-spray, and payload-delivery commands.

The cheatsheet recognizes: `http`/`https`, `ssh`, `ftp`, `smtp`, `dns`, `smb`
(`microsoft-ds`, `netbios-ssn`), `ldap`, `snmp`, `rpcbind`, `kerberos`,
`mysql`, `postgresql`, `redis`, `mongodb`. Unknown services get a generic
`nmap --script safe,default,discovery,version` suggestion.

## Planned modules

- **SmbTool** — `smb-os-discovery`, `smb-protocols`, `smb2-security-mode`,
  `enum4linux-ng` in read-only listing mode.
- **FtpTool** — banner + anonymous-listing check (read-only).
- **SshTool** — banner + `ssh2-enum-algos`.
- **SnmpTool** — `snmpwalk` with `public` community, read-only.
- **LdapTool** — anonymous base-DN query.
- **RpcTool** — `rpcinfo -p` + `nmap rpc-grind`.
- **KerberosTool** — SPN listing only. **No** AS-REP roasting, **no**
  user-enum-by-timing.
- **DnsZoneTransferTool** — AXFR attempt (legitimate enumeration).
- **HttpContentDiscoveryTool** — wordlist-driven, off by default, enabled with
  `--lab --content-discovery` and a bundled small wordlist only.
- **TlsCipherEnumTool** — `nmap --script ssl-enum-ciphers`.

Each will ship with recorded fixtures under `tests/fixtures/` and scope-check
tests.
