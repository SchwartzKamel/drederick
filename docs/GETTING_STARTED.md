---
title: Getting Started with Drederick
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-04
related: [CREDENTIALS.md, SCOPE_AND_LEGAL.md, TROUBLESHOOTING.md, ../README.md, DATASETTE.md]
---

# Getting Started with Drederick

Welcome! This guide will help you get up and running with Drederick in minutes.

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash
```

This downloads the latest release for your platform (Linux, macOS, or Windows), verifies the SHA256 checksum, and installs it to `~/.local/bin`.

### Manual Download

Visit the [releases page](https://github.com/SchwartzKamel/drederick/releases) and download the binary for your platform:
- `drederick-*-linux-x64.tar.gz` — Linux x86-64
- `drederick-*-linux-arm64.tar.gz` — Linux ARM64
- `drederick-*-osx-x64.tar.gz` — macOS Intel
- `drederick-*-osx-arm64.tar.gz` — macOS Apple Silicon
- `drederick-*-win-x64.zip` — Windows x86-64

Verify the checksum:
```bash
sha256sum -c SHA256SUMS
```

Extract and add to your PATH:
```bash
tar -xzf drederick-*.tar.gz
mv drederick ~/.local/bin/  # or /usr/local/bin for system-wide
export PATH="$PATH:$HOME/.local/bin"  # Add to ~/.bashrc if needed
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

## Your First Scan

### Basic Scan

```bash
drederick --scope ~/scope.txt --target 10.0.0.1 --out ~/results
```

**Flags explained:**
- `--scope ~/scope.txt` — Scope file (required for safety)
- `--target 10.0.0.1` — Single target to scan
- `--out ~/results` — Output directory (default: `./out/`)

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

```bash
drederick --scope ~/scope.txt --target 10.10.10.x --lab --require-vpn --out ~/results
```

**Flags:**
- `--lab` — Enable lab mode (relaxes scope checks, enables extra NSE scripts, shows cheatsheet)
- `--require-vpn` — Abort if you're not on the VPN (prevents accidental out-of-scope scans)

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

View findings as JSON:
```bash
drederick serve --out ~/results --json
```

Or query the database directly with sqlite3:
```bash
sqlite3 ~/results/findings.db ".mode csv" "SELECT * FROM findings;" > results.csv
```

See [docs/DB_SCHEMA.md](DB_SCHEMA.md) for database structure.

## Next Steps

### Full Documentation

- [README](../README.md) — Feature overview
- [SCOPE & LEGAL](SCOPE_AND_LEGAL.md) — Scope enforcement, legal guardrails
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
   drederick --scope scope.txt --target 10.10.10.X --lab --require-vpn --out results
   ```

### Scope Best Practices

- **Lab mode** (`--lab`): scope cap is `/8` (very broad)
- **Production** (`--no-lab`): scope cap is `/16` (stricter)
- Always specify a scope file—never scan without one
- Default: lab mode (safe for CTF/authorized testing)

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
drederick --scope ~/htb/machines/lame/scope.txt --lab --out ~/htb/machines/lame/results
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
