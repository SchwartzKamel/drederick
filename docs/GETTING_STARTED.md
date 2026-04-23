---
title: Getting Started with Drederick
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-04
related: [CREDENTIALS.md, SCOPE_AND_LEGAL.md, TROUBLESHOOTING.md, JEOPARDY.md, LLM_SETUP.md, COMPARISON.md, POST_EXPLOITATION.md, ../README.md, DATASETTE.md]
---

# Getting Started with Drederick

Welcome. Drederick is a scope-enforced, full-auto offensive harness —
and, with `ctf-solve`, a parallel Jeopardy CTF solver. Inside the scope
file it will enumerate, exploit, credential-attack, deliver payloads,
and race LLM-driven solvers at a scoreboard. Outside scope it does
nothing. This guide gets you from zero to a first scoped run.

> New here and wondering how this compares to AutoRecon, nmapAutomator,
> or ctf-agent? See [COMPARISON.md](COMPARISON.md).

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash
```

This downloads the latest release for Linux (x64 or arm64), verifies the SHA256 checksum, creates `~/.local/bin/` if missing, and installs the binary there. The installer also warns if `~/.local/bin` is not on your `PATH` and tells you what to add to your shell rc.

> Drederick is Linux-first (Kali/Parrot operator workstations). macOS and Windows binaries are not published.

### Manual Download

Visit the [releases page](https://github.com/SchwartzKamel/drederick/releases) and download the binary for your platform:
- `drederick-*-linux-x64.tar.gz` — Linux x86-64
- `drederick-*-linux-arm64.tar.gz` — Linux ARM64

Verify the checksum:
```bash
curl -fsSL https://github.com/SchwartzKamel/drederick/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Extract and add to your PATH:
```bash
tar -xzf drederick-*.tar.gz
mkdir -p ~/.local/bin
install -m 755 drederick ~/.local/bin/   # or /usr/local/bin for system-wide (needs sudo)
# Ensure ~/.local/bin is on PATH — add to ~/.bashrc or ~/.zshrc if missing:
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac
drederick --help
```

## Prerequisites & Tooling

Drederick depends on system tools for network scanning and exploitation database lookups.

### Check Your Setup

Run:
```bash
drederick doctor
```

This verifies: nmap, searchsploit, python3/2, go, ruby, git, curl, jq, datasette.

### Install Missing Tools

If any tools are missing:
```bash
drederick doctor --install
```

Drederick will use your system package manager (apt, brew, yum, etc.) to install them. It **never** re-executes as root—you'll be prompted for each tool.

### One-shot setup wizard

If you'd rather walk through tooling, credentials, and scope-file creation in a single guided pass, use the interactive wizard:

```bash
drederick init          # verifies tools, offers credential + scope setup
drederick init --yes    # non-interactive; accepts defaults
```

`--skip-creds` and `--skip-scope` opt out of individual steps. See `drederick --help` for the full subcommand list (`doctor`, `init`, `serve`, `analyze`, `note`, `web`, `ctf-solve`, `ctf-msg`).

### Why Each Tool?

- **nmap** — Network scanning and service enumeration
- **searchsploit** — Exploit database lookups (local mirror)
- **python3/2** — Bundled Datasette UI (Python-based)
- **go/ruby/git/curl/jq** — Optional (used by some advanced features)

## First-Time Configuration

### 1. Create a Scope File

Create a file `~/scope.txt` with targets:
```
# Example scope
10.0.0.0/24
192.168.1.0/24
```

**Format**: One CIDR or IP per line. `#` is a comment. Blank lines are ignored.

### 2. Optional: Set Environment Variables

For Hack The Box or other integrations:
```bash
export DREDERICK_HTB_TOKEN="your_token_here"  # HTB API token
export HTTP_PROXY="http://proxy:8080"         # Proxy settings (if needed)
```

See [docs/CREDENTIALS.md](CREDENTIALS.md) for full details.

### 3. Verify the Binary

```bash
drederick --help
```

You should see the help text with all available subcommands.

## Your First Run

Drederick has three operating modes. Which one you want depends on the
engagement:

| Goal | Command |
| ---- | ------- |
| Recon + annotate (safe defaults inside scope) | `drederick --scope ~/scope.txt --target 10.0.0.1 --out ~/results` |
| Offensive pass (recon + exploit inside scope) | same command — **lab mode is default**, exploit categories except DoS are on. Strict mode (`--no-lab`) requires explicit `--allow-*` flags. |
| Jeopardy CTF solver swarm | `drederick ctf-solve --scope scope.yaml --ctfd https://ctf.example.com --ctfd-token "$CTFD_TOKEN" --report-dir out/ctf-report/` — see [JEOPARDY.md](JEOPARDY.md). |

### Basic recon + offensive pass

```bash
drederick --scope ~/scope.txt --target 10.0.0.1 --out ~/results
```

**Flags explained:**
- `--scope ~/scope.txt` — Scope file (required; default-deny allow-list)
- `--target 10.0.0.1` — Single target (repeatable)
- `--out ~/results` — Output directory (default: `./out/`)

In lab mode (default) this runs recon **and** exploitation inside scope
— cached PoCs (proof-of-concept exploits matched to annotated CVEs),
credential attacks (with lockout-aware throttling), and payload staging
are all on. DoS / malware categories require explicit `--allow-dos`.
In strict mode (`--no-lab`) every offensive category is off until you
pass the matching `--allow-*` flag. See
[SCOPE_AND_LEGAL.md](SCOPE_AND_LEGAL.md) for the per-category opt-in
contract.

### Scan Multiple Targets

```bash
drederick --scope ~/scope.txt --target 10.0.0.1 --target 10.0.0.2 --out ~/results
```

### Scan Entire Scope

```bash
drederick --scope ~/scope.txt --expand --out ~/results
```

The `--expand` flag will enumerate all hosts in your scope file and scan them.

### Lab/CTF Mode (Recommended for HTB)

Lab mode is the **default**. The only extra flag worth adding on HTB is
`--require-vpn`:

```bash
drederick --scope ~/scope.txt --target 10.10.10.X --require-vpn --out ~/results
```

- Lab mode: scope cap `/8` (v4), Nmap Scripting Engine (NSE) categories
  broadened, cheatsheet generated, exploitation categories except DoS
  enabled by default.
- `--require-vpn` — Abort if you're not on a `tun*`/`tap*` interface
  resolving to HTB's published ranges.
- Pass `--no-lab` for strict mode (scope cap `/16`, every offensive
  category off until explicitly allowed).

### Jeopardy CTF (new)

For CTFd-backed Jeopardy events, run the solver swarm. It races LLM
fighters per challenge and submits the first accepted flag:

```bash
drederick ctf-solve \
  --scope scope.yaml \
  --ctfd https://ctf.example.com \
  --ctfd-token "$CTFD_TOKEN" \
  --out out/
```

Full recipe, model roster, budgets, and operator hints in
[JEOPARDY.md](JEOPARDY.md). LLM provider setup (Copilot, Azure OpenAI,
llama.cpp) in [LLM_SETUP.md](LLM_SETUP.md).

## Output & Results

Drederick writes findings to a SQLite database at `~/results/findings.db`.

### View Results in Datasette

```bash
drederick serve --out ~/results
```

This launches a web dashboard at `http://127.0.0.1:8001` where you can:
- Browse findings by host/service
- Filter by severity (Info, Warning, Critical)
- Export to JSON/CSV
- Search findings

### Export Results

Query the database directly with sqlite3 for CSV export:
```bash
sqlite3 ~/results/findings.db ".mode csv" "SELECT * FROM findings;" > results.csv
```

Or open `~/results/report.json` for machine-readable consolidated output.

See [docs/DB_SCHEMA.md](DB_SCHEMA.md) for database structure.

## Next Steps

### Full Documentation

- [README](../README.md) — Feature overview
- [SCOPE & LEGAL](SCOPE_AND_LEGAL.md) — Scope enforcement, legal guardrails
- [JEOPARDY](JEOPARDY.md) — Jeopardy CTF solver swarm (`ctf-solve`)
- [LLM_SETUP](LLM_SETUP.md) — Copilot, Azure OpenAI, llama.cpp
- [POST_EXPLOITATION](POST_EXPLOITATION.md) — Session handling and loot
- [COMPARISON](COMPARISON.md) — vs AutoRecon, nmapAutomator, ctf-agent
- [CREDENTIALS](CREDENTIALS.md) — Store API keys, tokens, proxies
- [DATASETTE UI](DATASETTE.md) — Dashboard features
- [TROUBLESHOOTING](TROUBLESHOOTING.md) — Common issues & solutions
- [ARCHITECTURE](ARCHITECTURE.md) — How drederick works internally

### Operator Cheatsheet

Need quick command references for your HTB machine?

After scanning, use:
```bash
drederick serve --out ~/results
```

Then visit the dashboard to see the auto-generated cheatsheet with manual commands for each service found.

## Tips for Lab/CTF Work

### Using with Hack The Box

1. Connect to HTB VPN
2. Set scope to the machine IP: `echo "10.10.10.X" > scope.txt`
3. Run with lab mode:
   ```bash
   drederick --scope scope.txt --target 10.10.10.X --require-vpn --out results
   ```

### Scope Best Practices

- **Lab mode** (default): scope cap `/8` (v4), `/32` (v6); offensive
  categories on except DoS.
- **Strict** (`--no-lab`): scope cap `/16` (v4), `/48` (v6); every
  offensive category off until the matching `--allow-*` flag.
- Always specify a scope file—never run without one. Empty scope and
  `0.0.0.0/0` / `::/0` are refused.

### Performance Tuning

If scans are too slow or too fast:
```bash
drederick --scope ~/scope.txt --target 10.0.0.1 \
  --host-concurrency 8 \           # Hosts to scan in parallel (default: 4)
  --service-concurrency 16 \       # Services per host (default: 8)
  --out ~/results
```

Higher = faster but more network load. Adjust based on your network and lab.

### Staying Organized

Create separate directories for each lab/CTF:
```bash
mkdir -p ~/htb/machines/{lame,pwnbox,remote}
echo "10.10.10.3" > ~/htb/machines/lame/scope.txt
drederick --scope ~/htb/machines/lame/scope.txt --out ~/htb/machines/lame/results
```

## Troubleshooting

If something goes wrong, see [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) for:
- Common errors and fixes
- Doctor warnings
- Timeout issues
- Datasette not starting

---

**Questions?** Open an issue on [GitHub](https://github.com/SchwartzKamel/drederick/issues).

**Ready to test?** Head to [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) for real-world examples or run `drederick doctor` to verify your setup.
