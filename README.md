# drederick

> **Drederick E. Tatum** — Heavyweight HTB/CTF champion.

Drederick is a scope-enforced, adaptive reconnaissance harness for **authorized**
lab environments (Hack The Box, TryHackMe, CTF ranges, or infrastructure you
are explicitly authorized to assess). It performs discovery and fingerprinting
only — **no exploitation, no credential attacks, no brute force, no payload
delivery**.

Built in C# on **.NET 10** with the **Microsoft Agent Framework**.

## Authorization notice

Drederick runs exclusively against targets you list in a scope file. There is
no default scope, no implicit allow-list, and the tool refuses wildcard or
over-broad entries. By pointing it at any target you assert that you are
authorized to test that target. Unauthorized testing of third-party systems is
illegal in most jurisdictions; don't do it.

## What it does

- **Scoped nmap** — TCP service/version scan with the `safe` + `default` NSE
  categories only. Exploit, brute, and vuln scripts are excluded.
- **HTTP probe** — status, title, `Server`, and which of the common security
  headers are missing.
- **TLS probe** — peer certificate subject/SAN/issuer/expiry and negotiated
  TLS version.
- **DNS probe** — forward + reverse.
- **Adaptive orchestration** — an agent plans the next probe from prior
  findings (deterministic runner out of the box, or the Microsoft Agent
  Framework runner when an OpenAI-compatible key is supplied).
- **Cross-run memory** — every run updates `memory/findings.json`; the next
  run starts with the prior map in hand, so repeated passes converge on
  deltas (expired certs, new services, drift) rather than re-discovering
  the whole surface.

## Build & test

```bash
dotnet build
dotnet test
```

`nmap` should be installed on the host that runs the recon. The unit tests do
not require it.

## Usage

```bash
# Minimal: explicit targets, deterministic runner
./src/Drederick/bin/Debug/net10.0/drederick \
    --scope scope.yaml \
    --target 10.10.10.5 \
    --target 10.10.10.6 \
    --out out/

# Enumerate everything in a small scope
drederick --scope scope.yaml --expand --out out/

# Use the Microsoft Agent Framework runner (needs OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
export DREDERICK_MODEL=gpt-4o-mini     # optional; default is gpt-4o-mini
drederick --scope scope.yaml --target 10.10.10.5 --agent --out out/
```

### Scope file

One CIDR, IP, or comment per line. `#` starts a comment.

```
# A single HTB box
10.10.10.5

# A CTF /24 I own
192.168.56.0/24

# An IPv6 lab range
fd00:dead:beef::/64
```

Entries broader than `/16` (v4) or `/48` (v6) require `--allow-broad`. The
wildcard entries `0.0.0.0/0` and `::/0` are always refused.

### Output

```
out/
├── report.json     # machine-readable consolidated findings
├── report.md       # per-host markdown summary
└── audit.jsonl     # one JSON object per scope decision / tool call
memory/
└── findings.json   # cross-run knowledge base (loaded on next run)
```

## Architecture

```
CLI ──► Scope (default-deny allow-list)
         │
         ▼
    ReconToolbox  ◄── AuditLog (JSONL)
         │
   ┌─────┴──────┐
   │            │
 nmap        http / tls / dns
   │            │
   └────┬───────┘
        ▼
  AdaptiveRunner  or  MicrosoftAgentRunner
        │                     │
        │           (LLM chooses tool calls;
        │            scope re-checked inside
        │            every tool — the model
        │            cannot escape the allow-list)
        ▼
  KnowledgeBase + JSON/Markdown reports
```

Scope enforcement lives **inside every tool**, not at the CLI boundary.
Whichever runner is driving — deterministic or LLM — a target outside the
scope file causes the tool to throw a `ScopeException`, which is logged and
skipped. There is no flag, no prompt, and no environment variable that
disables this check.
