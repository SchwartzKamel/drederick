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

<a id="performance-gains"></a>
## Performance gains

The native-first internalization pass (commit ~`15ecfb4`) replaced 5+
subprocess shellouts with 2,204 lines of in-process C#. The numbers
below are analytical estimates — the `scan-bench` task in the Tier-2
roadmap will produce measured BenchmarkDotNet figures and replace this
table.

### Per-call speedup (estimates pending `scan-bench`)

| Replacement | Per-call before | Per-call after | Speedup | Why |
|---|---|---|---|---|
| `which` → `PathResolver` | ~10–20 ms (process spawn) | ~0.1–1 ms (file checks) | 10–100× | No fork/exec, no pipe |
| `dig` → `DnsClient` | ~30–50 ms | ~2–10 ms | 5–25× | In-process UDP, no text parse |
| `snmpwalk` → `SharpSNMP` | ~50–150 ms (spawn + walk) | ~10–40 ms | 3–10× | Eliminates spawn; same wire protocol |
| `file/readelf/nm/strings/objdump` → `ElfParser/PeParser` | ~150–250 ms (5 spawns) | ~5–20 ms | 10–50× | Single mmap+parse vs 5 subprocesses |
| `netexec` (HTTP) → `NativeHttpSprayTool` | ~200–500 ms (Python startup + per-attempt) | ~10–50 ms | 10–50× | HttpClient connection pool, persistent TLS |
| nmap (basic scan) → `NativeScannerTool` | ~1–2 s for `-F` | ~2–4 s for 57 ports @ 500 conc | 1–3× cold-start | Skips nmap discovery phases; loses NSE corpus |

> **Note**: These are analytical estimates. The `scan-bench` task in the
> Tier-2 roadmap will produce measured numbers via BenchmarkDotNet to
> replace this table.

### Compounding wins

- **Concurrency**: Subprocess-based tools were fork-bound (~`RLIMIT_NPROC`,
  ~10–50 MB Python interpreter RSS each). Native tools are `Task`s on a
  shared heap. The `HostWorkerPool` `Channel<ScanJob>` can run 500–1000
  in-flight scans without thrashing.
- **CTF/HTB recon phase**: A typical "lame target" sweep cuts from ~5–7 s
  to ~1–2 s of overhead — roughly 3–5× faster recon overhead per host.
  On a /24 sweep that's ~15 minutes shaved.
- **Post-exploitation binary triage**: Enumerating `/usr/bin` (≈3,000
  binaries) drops from 30–60 minutes of fork overhead to ~30–60 seconds
  of pure I/O + parse — 30–60× faster.
- **Tests**: Subprocess-based tests waited for `/bin/true` stubs
  (~50–200 ms each). Native tests run in-memory (~1–10 ms) — 5–10×
  faster suite on affected tools.
- **Cross-platform**: Drederick now works on Windows without WSL for the
  native paths.

### Risks & gotchas (honest accounting)

| Risk | Severity | Mitigation |
|---|---|---|
| **NSE corpus gap** — `NativeScannerTool` has no NSE; banner-grab fingerprints chatty protocols only | Medium | nmap kept as enrichment layer when present (`nse-proxy` task formalizes this) |
| **Crash blast radius** — bug in `ElfParser` crashes Drederick; bug in `readelf` only kills that subprocess | Medium | Wrap parsers in try/catch with structured error in result; never let parse exceptions propagate to `AutopilotRunner` |
| **TLS quirks on weird targets** — `SslStream` is stricter than nmap re: SNI, SSLv3, weak ciphers | Low | `NativeHttpSprayTool` already disables cert validation; for scanning, fallback to `--no-verify` mode |
| **GC pauses at scale** — 1000 in-flight scans share the heap | Low | Server GC + `<ConcurrentGCEnabled>true</ConcurrentGCEnabled>` (likely already set) |
| **Connect-scan footprint** — TCP connect leaves traces; nmap SYN scan is stealthier | Low for lab/CTF | `scan-syn-raw` task adds raw-socket SYN scan with `CAP_NET_RAW` |
| **Cold-port timeout amplification** — closed ports still cost full timeout (default 2s) | Medium | RST-on-connect closes immediately; only filtered/dropped ports cost the full 2s |

<a id="roadmap"></a>
## Roadmap: Tier 2 / Tier 3 / Tier 4 / Tier 5

Drederick gets stronger over time through five complementary patterns:

1. **Graceful enrichment** — use external tools when present, native is
   the floor.
2. **Embedded community data** — bundle MIBs, libmagic, fingerprint
   corpora, YARA rules as in-process resources.
3. **Ported community logic** — translate top NSE / NetExec scripts to
   native C#, citing the originals.
4. **Original Drederick tooling** — capabilities we design that no
   existing tool does cleanly.
5. **Self-improving feedback loop** — review every fight, learn what
   worked, tune priorities, grow fingerprints, scaffold new tools. The
   training arc — the champ studies the tape between bouts.

See [PLUGIN_STRATEGY.md](PLUGIN_STRATEGY.md) for patterns 1–4 and
[LEARNING_LOOP.md](LEARNING_LOOP.md) for pattern 5.

### Tier 2 — Performance hardening

- `scan-syn-raw` — Raw-socket SYN scan with CAP_NET_RAW; falls back to
  connect-scan.
- `http-pool-persistent` — Per-target HttpClient cache in
  NativeHttpSprayTool (connection reuse).
- `elf-cache-host` — KnowledgeBase-backed ELF parse cache keyed on
  (host, path, sha256, mtime).
- `scan-bench` — BenchmarkDotNet harness that replaces the estimated
  speedup table with measurements.

### Tier 3 — Community plugin reuse (Patterns 1+2+3)

- `nse-proxy` — Formalize NSE enrichment when nmap is present.
- `nse-port-top` — Port the top 20–30 NSE scripts to native C#
  IReconTool implementations.
- `mib-bundle` — Bundle ~50 vendor MIBs as embedded resources for
  SnmpTool.
- `magic-bundle` — Expand BinaryAnalyzer magic-byte signatures (ZIP,
  PDF, JAR, ISO, RPM, DEB, etc.).
- `yara-integration` — dnYara for binary classification with curated
  offsec rule set.

### Tier 4 — Drederick-original tooling (Pattern 4)

- `xprotocol-replay` — Cross-protocol credential replay
  (SMB/WinRM/MSSQL/LDAP/SSH/HTTP/RDP in parallel).
- `fingerprint-stack` — Multi-signal host fingerprinter → ranked CPE →
  CVE matches.
- `lockout-scheduler` — Global AD-lockout-aware spray scheduler shared
  across all spray tools.
- `chain-reasoner` — Multi-stage attack chain proposer with
  explainability.

### Tier 5 — Self-improving training arc (Pattern 5)

- `fight-telemetry` — Per-attempt structured telemetry →
  `out/telemetry.db`.
- `fight-corpus-loader` — Read `~/HTB/fight-log.yaml` (schema v1) as
  long-term curated corpus.
- `fight-corpus-writer` — Draft post-fight corpus entries
  (operator-reviewed, never auto-committed).
- `fight-archetype` — Target archetype classifier (htb-linux-easy,
  htb-windows-ad, ctf-jeopardy-*).
- `fight-review` — `drederick review` subcommand for between-fight
  analysis.
- `planner-self-tune` — ExploitationPlanner priorities learn from
  telemetry + corpus.
- `fingerprint-grow` — fingerprint-stack auto-extends from observed
  fights.
- `archetype-playbook` — Pre-tuned playbooks per archetype loaded via
  `drederick warmup`.
- `tool-forge` — `drederick forge --from <fight>` generates IReconTool
  / IExploitTool scaffolds.

Track these in the project's todo store; cross-reference with
`.github/fight-gaps.md` GAP-016 (resolved), GAP-017, GAP-018, GAP-019
(planned).

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
