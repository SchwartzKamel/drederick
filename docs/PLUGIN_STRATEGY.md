<!--
---
title: PLUGIN_STRATEGY.md — How Drederick reuses community plugins while staying self-sufficient
audience: [contributors, agents]
primary: contributors
stability: stable
last_audited: 2026-05
related:
  - docs/SELF_SUFFICIENCY.md
  - docs/LEARNING_LOOP.md
  - docs/MODULES.md
  - docs/ARCHITECTURE.md
---
-->

# Plugin strategy — capability sources

> Drederick stands alone, but the heavyweight champ still studies film. This doc
> describes the four patterns by which Drederick incorporates community
> capability without taking on dependency risk. The fifth pattern (self-improving
> feedback loop) is documented separately in [LEARNING_LOOP.md](LEARNING_LOOP.md).

## TL;DR

| Pattern | How | When | Example |
|---|---|---|---|
| 1. Graceful enrichment | Use external when present, native is floor | External tool adds depth we cannot reasonably re-implement | NSE proxy via nmap when installed |
| 2. Embedded community data | Bundle community knowledge as in-process resources | The data is the value (rules, signatures, MIBs); engine is replaceable | ~50 vendor MIBs as DLL resources |
| 3. Ported community logic | Translate to native C# IReconTool, cite original | High-frequency scripts; clear contract | Top 20–30 NSE scripts as native C# |
| 4. Original Drederick tooling | We design and own | No existing tool does it cleanly | Cross-protocol credential replay engine |

<a id="pattern-1-graceful-enrichment"></a>
## Pattern 1: Graceful enrichment

Native is always the floor. When the external tool is present, use it as an enrichment layer that adds depth.

**Contract**: every native tool exposes its result; if an external companion is detected, an enrichment phase merges deeper data into the same result type.

**Examples**:
- `NativeScannerTool` → `nse-proxy` task: when `PathResolver.IsAvailable("nmap")` is true, run `nmap -sV --script <category> -p <port>` against discovered services and merge XML results back into `HostFinding`.
- `NativeDnsTool` → already works without `dig`; if external resolver wanted, that's a future enrichment.
- `BinaryAnalyzer` → can layer external `radare2` analysis when present without taking a hard dependency.

**Why it works**:
- Operators with the tool installed get the depth.
- Operators without it still get the baseline.
- No CI / install-script gymnastics required.

**Code shape**:
```csharp
var native = await _scanner.ScanAsync(target, ports, ct);
if (PathResolver.IsAvailable("nmap"))
{
    await _nseProxy.EnrichAsync(native, categories: "safe,default,version", ct);
}
return native;
```

<a id="pattern-2-embedded-community-data"></a>
## Pattern 2: Embedded community data

The community has built enormous data corpora — MIBs, libmagic signatures, JA3/JA4 fingerprint maps, YARA rules. The data is the value; the engine that consumes it is often trivial.

**Contract**: bundle a curated subset as embedded resources in the Drederick DLL; load system equivalents at runtime if present (additive, not replace).

**Examples**:
- `mib-bundle` task: bundle ~50 vendor MIBs (Cisco, Juniper, Net-SNMP, IF-MIB, HOST-RESOURCES-MIB) as embedded resources. SnmpTool resolves numeric OIDs (e.g. `1.3.6.1.2.1.1.5.0`) to symbolic names (`sysName.0`).
- `magic-bundle` task: curated libmagic-equivalent table (ZIP, PDF, JAR, ISO, RPM, DEB, OLE2, image formats) inside `BinaryAnalyzer`.
- `yara-integration` task: bundle a curated YARA rule set focused on offsec (packers, suspicious imports, common malware family signatures).
- Banner→CPE map and JA3/JA4 fingerprint corpus for `fingerprint-stack`.

**Why it works**:
- Always works (even airgapped).
- Operators on systems with full `/usr/share/snmp/mibs/` get more (additive load).
- Drederick's airgapped CTF/lab story is intact.

**Code shape**:
```csharp
private static readonly Lazy<MibIndex> _bundled = new(() => MibIndex.LoadEmbedded());
private static MibIndex Load()
{
    var bundled = _bundled.Value;
    if (Directory.Exists("/usr/share/snmp/mibs"))
        bundled.Augment(MibIndex.LoadDirectory("/usr/share/snmp/mibs"));
    return bundled;
}
```

<a id="pattern-3-ported-community-logic"></a>
## Pattern 3: Ported community logic

For the top community scripts whose logic is small enough to translate (most NSE scripts are <200 lines), port them to native C# `IReconTool` implementations. Cite the original in the file header.

**Contract**: each ported script becomes an `IReconTool` with the standard scope/audit invariants. The file header credits the original NSE / CME author and links to the original source.

**Examples** (top 20–30 NSE scripts to port — `nse-port-top` task):
- `http-title`, `http-headers`, `http-robots`, `http-methods` →
  `Recon/Native/HttpTitleTool`, `HttpHeadersTool`, `HttpRobotsTool`,
  `HttpMethodsTool` ✅ shipped
- `ssl-cert` → `Recon/Native/SslCertTool` ✅ shipped
- `ssh-hostkey` → `Recon/Native/SshHostkeyTool` ✅ shipped
- `ftp-anon` → `Recon/Native/FtpAnonTool` ✅ shipped
- `ldap-rootdse` → `Recon/Native/LdapRootDseTool` ✅ shipped
- `http-enum` → `NativeHttpReconTool` family (planned)
- `ssl-enum-ciphers` → already covered by `TlsCipherEnumTool` (Pattern-1
  proxy via nmap); planned native port pending Tier 3
- `smb-os-discovery`, `smb-enum-shares` → `NativeSmbReconTool` (extends
  existing `SmbTool`) (planned)
- `mysql-info`, `ms-sql-info` → `NativeDatabaseReconTool` family (planned)
- `rpcinfo` → `NativeRpcInfoTool` (extends existing `RpcTool`) (planned)
- `banner` → already covered by `NativeScannerTool` banner-grab phase

**File-header convention**:
```csharp
// Ported from NSE script `http-title` (https://nmap.org/nsedoc/scripts/http-title.html)
// Original: Diman Todorov, Apache 2.0
// Drederick port: native C#, scope-checked, audit-recorded
namespace Drederick.Recon.Native;
public sealed class HttpTitleTool : IReconTool { ... }
```

**Why it works**:
- Native means no Lua dependency, no nmap install required for the script's value.
- Logic is auditable line-by-line; we own the code path.
- Tests are straightforward .NET fixtures.

**When to port vs proxy**:
- Port if: the script is <500 lines, depends only on stdnse / nmap.new_socket, has clear inputs/outputs.
- Proxy via Pattern 1 (`nse-proxy`) if: the script depends on nmap's version-detection corpus, NSE library helpers, or has Lua-specific patterns that don't translate well.

<a id="pattern-4-original-drederick-tooling"></a>
## Pattern 4: Original Drederick tooling

The heavyweight signature: capabilities we design that no existing tool does cleanly.

**Contract**: full `IReconTool` / `IExploitTool` / `IPayloadTool` with native logic, scope/audit invariants, and tests. No external dependency. No prior art to cite.

**Examples** (Tier 4 roadmap):

- **`xprotocol-replay`** ✅ shipped — `src/Drederick/Exploit/Replay/`. Take
  credentials/hashes/tickets captured from one protocol and replay them in
  parallel across every other protocol on every in-scope host (SMB → WinRM
  → MSSQL → LDAP → SSH → HTTP → RDP). CrackMapExec/NetExec does this for
  SMB; we cover the full surface, scope-checked, deduplicated,
  lockout-aware. See [`MODULES.md#exploit-replay`](MODULES.md#exploit-replay).
- **`fingerprint-stack`** ✅ shipped — `src/Drederick/Enrichment/FingerprintStack/`.
  Multi-signal host fingerprinter combining port + banner + TLS cert
  subject/SAN + HTTP headers + favicon SHA-256 + JA3/JA4 → ranked CPE →
  CVE matches with confidence. Goes beyond product-token matching in
  `ExploitationPlanner`. **Cross-run learning** is owned by the companion
  `LearnedFingerprintStore`
  (`Enrichment/FingerprintStack/LearnedFingerprintStore.cs`) — every fight
  promotes observed `(signal_kind, signal_value) → (vendor, product,
  version, port)` tuples into `memory/learned-fingerprints.json` (versioned
  envelope). Re-observation increments `Hits` and merges contributing
  fight ids; the store is loaded on the next run so the FingerprintStack
  auto-extends from past fights without redistributing vendor MIB content
  or proprietary banner corpora — only the (signal → product) tuples we
  observed ourselves.
- **`lockout-scheduler`** — Global lockout-aware spray scheduler shared
  across all spray tools. Tracks 401/403/locked signals per (domain,
  account, protocol) globally; backoff per-account; honors
  `--acknowledge-lockout-risk`. Replaces per-tool throttling with
  centralized AD-policy-aware throttling. Consumed by `CrossProtocolReplay`
  via `IReplayLockoutScheduler`.
- **`chain-reasoner`** ✅ shipped — `src/Drederick/Autopilot/ChainReasoner/`.
  Multi-stage attack-chain proposer. Reads `ChainFacts` (current findings +
  captured creds + open sessions), instantiates every `ChainTemplate` whose
  `Requires` predicates are satisfied, scores by `likelihood × impact −
  cost`, and returns ranked `AttackChain[]` with explainability ("anon SMB
  read → grep creds in share → SMB exec → loot SAM → AD privesc"). LLM
  augmentation is optional via `IChainAugmenter`; the reasoner itself does
  not call `Scope.Require` because it manipulates pure data — every tool
  the chain dispatches to re-checks scope on entry. See
  [`MODULES.md#chain-reasoner`](MODULES.md#chain-reasoner).

**Why it works**:
- The toolchain matures past being a wrapper over Kali.
- Each original capability is a moat: a new operator picking Drederick gets value they can't get from `apt install kali-tools-everything`.
- We learn from every fight (Pattern 5 in [LEARNING_LOOP.md](LEARNING_LOOP.md)) and feed observations back into these tools.

<a id="decision-tree"></a>
## When facing a new external tool — decision tree

```
Can we re-implement the engine cleanly in <500 lines of C#?
├── YES → Pattern 3 (port logic)
└── NO
    │
    Is the value primarily structured DATA (rules, signatures, MIBs)?
    ├── YES → Pattern 2 (embed data, write small native engine)
    └── NO
        │
        Is the tool's depth (NSE corpus, exploit framework) >> our re-impl effort?
        ├── YES → Pattern 1 (graceful enrichment when present)
        └── NO  → Pattern 4 (build something better, originally)
```

<a id="anti-patterns"></a>
## Anti-patterns to reject

- **Hard dependency**: making Drederick require external tool X to run — defeats self-sufficiency.
- **Silent fallback**: degrading capability without telling the operator. Always log "external X not present, using native baseline" at info level.
- **Half-port**: porting only part of a script and pretending it's complete. Either port fully (Pattern 3) or proxy (Pattern 1).
- **Embedding outdated data**: bundle community data with provenance + version + last-fetched timestamp. Refresh via tooling, not manual edits.
- **Reinventing for ego**: don't re-implement nmap. Pattern 1 gracefully enriches with it.

<a id="see-also"></a>
## See also

- [SELF_SUFFICIENCY.md](SELF_SUFFICIENCY.md) — native-vs-external table, perf gains, roadmap
- [LEARNING_LOOP.md](LEARNING_LOOP.md) — pattern 5: how Drederick learns from each fight
- [DEVELOPING.md](DEVELOPING.md) — how to add a new IReconTool / IExploitTool
- [MODULES.md](MODULES.md) — current tool inventory
