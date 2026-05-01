---
title: Self-sufficiency — native-first architecture
audience: [operators, contributors]
primary: operators
stability: stable
last_audited: 2026-05
related:
  - ARCHITECTURE.md
  - MODULES.md
  - DEVELOPING.md
  - ../AGENTS.md
---

# Self-sufficiency

> "The heavyweight doesn't outsource the jab." Drederick's native-first
> philosophy means the core enumeration loop works out of the box — no `nmap`,
> no `snmpwalk`, no `dig`, no `file`, no `readelf` required for basic recon.
> External tools remain available as an optional enrichment layer when you want
> deeper NSE coverage or Metasploit exploitation.

<a id="philosophy"></a>
## Why self-sufficiency matters

Every external binary is a failure mode: not installed, wrong version, wrong
path, wrong permissions. In airgapped labs, CTF VPNs, and CI pipelines these
failures are silent — the tool simply doesn't run, enumeration coverage
degrades, and you don't know what you missed.

The native-first pass solves this. Drederick's core loop — port scan, banner
grab, DNS resolution, SNMP walk, DNS zone transfer, binary analysis, HTTP
credential spray — now runs on pure .NET with no system-level prerequisites
beyond the runtime. External tools are installed alongside and provide
*additional depth*, not *basic coverage*.

<a id="native-vs-external"></a>
## What's native vs what stays external

| Capability | Native implementation | External (optional enrichment) | Why kept external |
| ---------- | --------------------- | ------------------------------ | ----------------- |
| TCP port scan + banner | `NativeScannerTool` (57-port default, `TcpClient`, `SslStream`) | `NmapTool` | NSE scripts, deep version detection, service fingerprinting beyond banner |
| DNS resolution (A/AAAA/MX/NS/TXT/SOA/PTR) | `NativeDnsTool` (`DnsClient.NET`) | — | Fully replaced |
| DNS zone transfer (AXFR) | `DnsZoneTransferTool` (`DnsClient.NET` `QueryType.AXFR`) | — | Fully replaced; no longer needs `dig` |
| SNMP walk | `SnmpTool` (`Lextm.SharpSnmpLib`, 7 communities, 3 OID subtrees) | — | Fully replaced; no longer needs `snmpwalk` |
| Binary analysis (ELF/PE) | `ElfParser` / `PeParser` / `BinaryAnalyzer` (pure byte parsing) | `MagikaDetector` (ML file-type hints, optional) | Deep disassembly, decompilation (out of scope) |
| HTTP credential spray | `NativeHttpSprayTool` (Basic, Digest, Tomcat, Jenkins, Grafana, WordPress, phpMyAdmin, OWA, WinRM, auto-detect) | `netexec` (SMB/RDP protocols) | SMB/RDP spray still needs external tooling |
| Tool-presence checks | `PathResolver.Which()` (PATH scan, no subprocess) | — | Fully replaced; no longer needs `which` |
| Exploit execution | — | `msfconsole`, `nuclei`, `searchsploit` | Complex Ruby/YAML engines; irreplaceable in .NET |
| Hash cracking | — | `hashcat`, `john` | GPU acceleration; irreplaceable in .NET |
| NSE script engine | — | `nmap` | 600+ Lua scripts, timing engine |

<a id="architecture-diagram"></a>
## Architecture: native-first scanner pipeline

```
Phase 1 — Port discovery (always runs)
───────────────────────────────────────
NativeScannerTool ──→ 57-port TCP connect + banner grab + TLS probe
       │                  (SemaphoreSlim concurrency, no deps)
       │
       └──→ NmapTool (optional) ──→ NSE scripts, deep version detection
                                     (installed? enriches; absent? skipped)

Phase 1 — DNS (always runs)
────────────────────────────
NativeDnsTool ──→ A/AAAA/MX/NS/TXT/SOA/PTR  (DnsClient.NET, no dig)
DnsZoneTransferTool ──→ AXFR                  (DnsClient.NET, no dig)

Phase 2 — Per-service dispatch
───────────────────────────────
SnmpTool ──→ SNMPv2c/v1 walk    (SharpSnmpLib, no snmpwalk)
BinaryAnalyzer ──→ ELF/PE parse  (native byte parsing, no readelf/nm)
NativeHttpSprayTool ──→ HTTP spray (pure .NET, no netexec HTTP layer)
... (SmbTool, LdapTool, SshTool, etc. — mix of native + subprocess)

Enrichment layer (runs after recon)
─────────────────────────────────────
CveAnnotator ──→ NVD 2.0 feed (pure HTTP + JSON, no deps)
PocAggregator ──→ searchsploit / GitHub / Metasploit / Nuclei
                  (external tools optional; pointers recorded regardless)
```

<a id="zero-dep-mode"></a>
## Running Drederick with zero external tools

Basic recon mode requires only the .NET 10 runtime:

```bash
# No nmap, no dig, no snmpwalk required.
drederick --scope scope.yaml --target 10.10.10.5 --out out/
```

What you get:
- TCP port scan of 57 well-known ports (`NativeScannerTool`)
- TLS certificate grab on TLS-bearing ports
- Redis probe on port 6379
- DNS A/AAAA/MX/NS/TXT/SOA/PTR resolution (`NativeDnsTool`)
- SNMP system-OID walk on port 161 (`SnmpTool`)
- HTTP probe, TLS probe, SMB probe (native clients — no subprocess)
- Binary analysis on captured artifacts (`ElfParser`/`PeParser`)
- CVE annotation from the NVD feed (pure HTTP)
- PoC pointer collection from searchsploit's local archive (no network)

What you don't get without external tools:
- NSE script results (requires `nmap`)
- Deep service version fingerprinting (requires `nmap -sV`)
- PoC execution (requires `msfconsole`, `nuclei`, etc.)
- Hash cracking (requires `hashcat`/`john`)

<a id="with-external-tools"></a>
## What you get with external tools installed

Run `drederick doctor` to detect what's installed, or `drederick doctor
--install` to install the full toolchain. Each external tool adds a specific
enrichment layer on top of the native baseline:

| Tool | Added capability |
| ---- | --------------- |
| `nmap` | NSE scripts (`safe,default,discovery,version,auth,vuln,exploit` in lab mode), deep version detection, `--top-ports 1000` scan |
| `searchsploit` | Offline Exploit-DB PoC pointer collection (no network required after `updatedb`) |
| `msfconsole` | Metasploit RC script execution against matched CVEs (`MsfRcRunner`) |
| `nuclei` | Template-driven vulnerability scanning against discovered HTTP services (`NucleiRunner`) |
| `hashcat` / `john` | Offline hash cracking after credential capture |
| `evil-winrm` | WinRM post-exploitation sessions |
| `impacket` | Kerberos attacks, SMB relay, PtH |
| `magika` | ML-based file-type hints as pre-pass for `BinaryAnalyzer` |

<a id="nuget-packages"></a>
## NuGet packages added

These packages ship inside the published binary — no separate install:

| Package | Version | Purpose |
| ------- | ------- | ------- |
| `DnsClient` | ≥ 1.8 | DNS resolution and AXFR for `NativeDnsTool` and `DnsZoneTransferTool`. Replaces `dig`. |
| `Lextm.SharpSnmpLib` | ≥ 12.x | SNMP v1/v2c/v3 GET/WALK for `SnmpTool`. Replaces `snmpwalk`. |

All other native capabilities (`NativeScannerTool`, `ElfParser`/`PeParser`,
`NativeHttpSprayTool`, `PathResolver`) use the BCL exclusively
(`System.Net.Sockets`, `System.Net.Security`, `System.Net.Http`,
`System.IO`, `System.Text.RegularExpressions`) — no additional NuGet
packages.

<a id="extending"></a>
## Contributing a new native tool

Before reaching for a subprocess, ask: can the tool's core function be
implemented in pure .NET with reasonable effort? If yes, prefer native over
subprocess. If the external tool is truly irreplaceable (msfconsole, nuclei,
hashcat), keep the subprocess but make the external tool *optional* using
`PathResolver.Which("tool-name")` for presence checks.

Reference implementations:
- **Port scanner:** `NativeScannerTool` (`src/Drederick/Recon/NativeScannerTool.cs`)
- **DNS resolver:** `NativeDnsTool` (`src/Drederick/Recon/NativeDnsTool.cs`)
- **Binary analyzer:** `BinaryAnalyzer` + `ElfParser` + `PeParser` (`src/Drederick/Recon/Binary/`)
- **HTTP spray:** `NativeHttpSprayTool` (`src/Drederick/Exploit/NativeHttpSprayTool.cs`)
- **Tool presence:** `PathResolver.Which()` (`src/Drederick/Ops/PathResolver.cs`)

See [`DEVELOPING.md#adding-scanner`](DEVELOPING.md#adding-scanner) for the
full checklist including scope check, audit bracketing, and test requirements.
