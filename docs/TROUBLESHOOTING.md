---
title: Troubleshooting runbook
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-04
related:
  - README.md
  - MODULES.md
  - SCOPE_AND_LEGAL.md
  - DATASETTE.md
---

# Troubleshooting runbook

Runbook for operators who hit issues. Each section has a stable anchor so links
from the CLI's error messages, other docs, and issues stay valid.

## TL;DR — symptom → section

| Symptom | Section |
| ------- | ------- |
| `drederick: command not found` | [install-path](#install-path) |
| nmap hangs or times out | [nmap-timeout](#nmap-timeout) |
| `drederick doctor` misses tools | [doctor-detection](#doctor-detection) |
| CVE annotation slow/failing | [cve-offline](#cve-offline) |
| `out/findings.db is locked` | [sqlite-locked](#sqlite-locked) |
| `drederick serve` won't start | [datasette-bootstrap](#datasette-bootstrap) |
| VPN warning but VPN is up | [vpn-detection](#vpn-detection) |
| `.htb` hostname doesn't resolve | [htb-hostname](#htb-hostname) |
| Scope rejected | [scope-parse](#scope-parse) |
| LLM runner errors / timeouts | [llm-runner](#llm-runner) |
| PoC cache empty despite CVEs | [poc-cache](#poc-cache) |
| Scanner crashed mid-run | [scanner-fail](#scanner-fail) |

---

## install-path

The installer (`scripts/install.sh`) drops the `drederick` binary into
`$HOME/.local/bin` by default. If that directory isn't on your shell's `PATH`,
the next shell you open will report `drederick: command not found` even though
the file exists.

1. Verify the binary is actually there:

    ```bash
    ls -l "$HOME/.local/bin/drederick"
    ```

2. Add `~/.local/bin` to `PATH` — pick the rc file your login shell actually
   reads (`~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`, etc.):

    ```bash
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
    ```

3. Refresh the current shell's command-hash cache and confirm:

    ```bash
    hash -r
    which drederick
    drederick --version
    ```

4. For a system-wide install, rerun `install.sh` with `PREFIX=/usr/local/bin`
   (needs `sudo`); that location is usually on `PATH` already.

---

## nmap-timeout

`drederick`'s nmap wrapper runs `-Pn -sV -sC -T4 --min-rate 1000` and defaults
to `--top-ports 1000` (see `src/Drederick/Recon/NmapTool.cs`). It does not
impose its own per-scan timeout — a hang almost always means nmap itself is
waiting on the network (firewall dropping SYNs, VPN down, or a full-port scan
against a slow host).

1. Confirm the target is reachable at all:

    ```bash
    ping -c 2 <target>
    ```

2. If you're scanning an HTB target, verify the VPN is up (see
   [vpn-detection](#vpn-detection)). A scan over the wrong interface will
   silently stall.

3. If you passed an explicit port range like `1-65535`, expect multi-minute
   runtimes. Try the default top-1000 first, then widen ports only for hosts
   that look interesting.

4. Cancel with `Ctrl-C`; findings from scanners that completed before the
   cancel persist in `out/findings.db`. Tail `out/audit.jsonl` for
   `nmap.start` / `nmap.finish` events to see where time is spent:

    ```bash
    tail -f out/audit.jsonl | jq 'select(.event|startswith("nmap"))'
    ```

---

## doctor-detection

`drederick doctor` detects tools by looking up binaries on `PATH` and, for
some tools, a list of alternate names — e.g. `netexec` also accepts `nxc`
and `crackmapexec` (see `Doctor.Specs` in `src/Drederick/Doctor/Doctor.cs`).
For each binary it runs a configured version probe (`--version`, `-V`,
`version`, `-h`, or `--help` depending on the tool); when a tool reports
`[miss]` but you know it's installed, one of those two lookups has failed.

1. Check what name `drederick` is looking for. The canonical names and
   aliases are in `Doctor.Tools` / `Doctor.Specs`. For example: if you
   installed `crackmapexec` but doctor reports `netexec` missing, you're
   fine — the alias chain should pick it up; if it doesn't, the binary
   isn't on `PATH`.

2. Verify the binary resolves on the same `PATH` drederick sees:

    ```bash
    which netexec nxc crackmapexec
    echo "$PATH"
    ```

3. If the binary exists but the version probe fails (e.g. upstream changed
   its flag), check what command drederick tried:

    ```bash
    jq 'select(.event=="doctor.detect" and .found==false)' out/audit.jsonl
    ```

    Then run the version probe by hand. If the upstream flag genuinely
    moved, file an issue so we can update the spec.

4. `seclists` is a directory, not a binary. Doctor looks in
   `/usr/share/seclists`, `/usr/share/SecLists`, `~/seclists`, and
   `~/SecLists` (see `Doctor.SeclistsCandidateDirs()`). Symlink or
   install into one of those paths.

5. There is no `--skip-check <tool>` flag. If a tool is genuinely absent
   and you don't need it, ignore the `[miss]` line — only `nmap` is
   marked required.

---

## cve-offline

CVE annotation loads NVD JSON 2.0 feeds from `~/.drederick/nvd/` (see
`NvdCache.DefaultCacheDir()` in `src/Drederick/Enrichment/NvdCache.cs`).
The cache is refreshed at most every 24 hours; if the refresh fails
(offline, NVD rate-limited, etc.) any pre-existing `*.json.gz` files are
still used, and the annotator runs silently against whatever it has.

1. Check what's actually cached:

    ```bash
    ls -la ~/.drederick/nvd/
    ```

    You should see `nvdcve-2.0-<year>.json.gz` files for the last five
    years plus `nvdcve-2.0-modified.json.gz`.

2. Force a refresh by removing the cache and rerunning any command that
   triggers enrichment:

    ```bash
    rm -rf ~/.drederick/nvd/
    drederick <your-args>
    ```

    If the refresh fails with an empty cache you'll get an explicit
    `NvdCache: no feed files … and refresh failed` error.

3. Opt out of CVE annotation entirely for this run:

    ```bash
    DREDERICK_SKIP_CVE=1 drederick <your-args>
    ```

4. Offline install: download the NVD 2.0 `.json.gz` feeds on a
   connected host and drop them directly into `~/.drederick/nvd/`. The
   cache loader parses any `*.json.gz` it finds there.

---

## sqlite-locked

`out/findings.db` is an on-disk SQLite database opened by
`Microsoft.Data.Sqlite` (see `src/Drederick/Reporting/SqliteReport.cs`). In
WAL-ish configurations SQLite leaves `-wal` / `-shm` sidecar files next to
the DB; a crashed or force-killed prior run can leave those in a state that
makes the next `drederick` invocation hang or fail with `database is locked`.

1. Make sure no other process still holds the DB open:

    ```bash
    lsof out/findings.db 2>/dev/null
    ```

2. Remove the sidecar files (the main `findings.db` keeps your prior
   results):

    ```bash
    rm -f out/findings.db-wal out/findings.db-shm
    ```

3. If the lock persists, archive `out/` and let drederick recreate it:

    ```bash
    mv out out.broken.$(date +%s)
    ```

4. If the DB is locked on every run from a clean state, `out/` may be
   on a filesystem that doesn't support POSIX locks (some network
   mounts). Move it to a local disk.

---

## datasette-bootstrap

`drederick serve` needs a `datasette` binary. It resolves one via, in order
(see `src/Drederick/Bundling/DatasetteBootstrap.cs`):

1. `--datasette-path` if you passed it
2. `datasette` on `PATH`
3. `~/.drederick/venv/datasette/bin/datasette` (or the cached pointer file
   `~/.drederick/bin/datasette.path`)
4. Auto-install via `uv tool`, `pipx`, or `python3 -m venv` (in that
   preference order), which requires `python3 >= 3.9`.

Remediation depends on where it's failing:

1. Check the audit log to see which step blew up:

    ```bash
    jq 'select(.event|startswith("bundling.datasette"))' out/audit.jsonl
    ```

2. If auto-install was disabled and nothing is installed, either drop
   `--no-auto-install` or install datasette manually:

    ```bash
    pipx install datasette
    # or
    uv tool install datasette
    ```

3. If `python3 --version` is wrong or <3.9, install a newer python3
   (`drederick doctor --install` will pull it in on supported package
   managers) and rerun.

4. If a prior install left a broken venv, force a rebuild by removing
   the managed install and the cached pointer:

    ```bash
    rm -rf ~/.drederick/venv/datasette ~/.drederick/bin/datasette.path
    drederick serve
    ```

5. If you already have datasette in a weird location, bypass resolution
   entirely:

    ```bash
    drederick serve --datasette-path /opt/datasette/bin/datasette
    ```

---

## vpn-detection

The preflight considers the VPN "up" only if an interface whose name starts
with `tun` or `tap` is in `OperationalStatus.Up` **and** carries a
non-link-local IPv4 address (see `src/Drederick/Ops/VpnDetector.cs`). If
your VPN client uses a different interface name — WireGuard's `wg0`, PPP's
`ppp0`, some OpenVPN setups with custom `dev` names — the heuristic
misses it and you'll get a warning against HTB CIDRs even though traffic
is tunneled.

1. Confirm what your VPN interface is actually called:

    ```bash
    ip -o -4 addr show | awk '{print $2, $4}'
    ```

2. If the interface isn't a `tun*`/`tap*`, rename it (OpenVPN: `dev tun0`
   in the config) or skip the preflight:

    ```bash
    drederick --skip-vpn-check <args>
    ```

3. File an issue with your interface name so we can expand the recognised
   list. Keep the allow-list intentionally narrow (see `HtbRanges` notes)
   rather than matching any private-range interface.

4. If the VPN really is down, the warning is correct. Reconnect and
   verify with:

    ```bash
    curl --interface tun0 https://ifconfig.me
    ```

---

## htb-hostname

`.htb` hostnames are resolved via `/etc/hosts` **first** (HTB boxes ship
an `/etc/hosts` entry; public DNS will NXDOMAIN). Non-`.htb` hostnames
fall through to a normal DNS lookup (see `HtbRanges.TryResolve` in
`src/Drederick/Ops/HtbRanges.cs`).

1. Add the box to `/etc/hosts` (requires `sudo`):

    ```bash
    echo "10.10.11.42 sauna.htb" | sudo tee -a /etc/hosts
    ```

2. Verify resolution:

    ```bash
    getent hosts sauna.htb
    ```

3. Or pass the hostname explicitly on the CLI so drederick resolves and
   tracks it for the run:

    ```bash
    drederick --htb-host sauna.htb <other args>
    ```

4. If you keep hosts entries in a non-standard file, pass it via the
   `HostsFilePath` integration option — CLI users just edit `/etc/hosts`.

---

## scope-parse

Scope files are one CIDR / IP / `#comment` per line (see
`src/Drederick/Scope/ScopeLoader.cs`). Empty scopes, `0.0.0.0/0` wildcards,
and prefixes broader than the lab/strict caps (IPv4 `/8` in lab, `/16` in
strict) are refused by design. A minimal valid file:

```text
# HTB box
10.10.11.42/32
# small lab range
192.168.56.0/24
```

Common mistakes:

1. **Bare IP treated as a CIDR.** `10.10.10.5` is accepted and is
   equivalent to `10.10.10.5/32` — but `10.10.10.5/` (trailing slash with
   no prefix) fails with `Invalid prefix`. Either drop the slash or write
   the full `/32`.

2. **Wildcards.** `0.0.0.0/0` and `::/0` are always refused. Narrow the
   scope.

3. **Too-broad prefix.** In lab mode (default) anything broader than
   `/8` IPv4 or `/32` IPv6 is refused; in strict (`--strict`) the caps
   are `/16` and `/48`. Pass `--allow-broad` to override deliberately.

4. **Whitespace / CRLF.** Lines are trimmed before parsing, so trailing
   spaces are fine, but a stray character before the address is not.
   Save scope files as UTF-8 without BOM.

6. **Empty file / all-comments.** Rejected with `Scope is empty`.

---

## llm-runner

`--agent` uses the Microsoft Agent Framework runner backed by OpenAI (see
`src/Drederick/Agent/MicrosoftAgentRunner.cs`). It needs `OPENAI_API_KEY`
in the environment and will use `DREDERICK_MODEL` if set (default
`gpt-4o-mini`). Errors from the OpenAI client are recorded as
`runner.agent_error` in the audit log and then rethrown.

1. Check the env vars are actually exported in the shell you're running
   `drederick` from:

    ```bash
    env | grep -E 'OPENAI_API_KEY|DREDERICK_MODEL'
    ```

2. If `--agent` was requested but `OPENAI_API_KEY` is missing, drederick
   logs `--agent requested but OPENAI_API_KEY is not set. Falling back to
   AdaptiveRunner.` and continues — this is expected, not a failure.

3. Rate limits / timeouts / provider 5xx surface as
   `runner.agent_error`. Inspect:

    ```bash
    jq 'select(.event=="runner.agent_error")' out/audit.jsonl
    ```

4. Fall back to the deterministic adaptive runner (no LLM, no network
   calls to OpenAI) by dropping the flag:

    ```bash
    drederick <args>  # no --agent
    ```

5. If the LLM succeeded but called no tools, the scope enforcement may
   have rejected every target — check for `scope` errors in
   `out/audit.jsonl` before blaming the model.

---

## poc-cache

By default `drederick` fetches and caches PoC references into
`out/poc_cache/<source>/<id>/`, keyed by source name with a SHA-256
recorded in the `poc_sources` table (see
`src/Drederick/Enrichment/PocAggregator.cs`). Two things commonly produce
an empty cache even when CVEs were annotated:

1. `--no-fetch-poc` was passed. In that mode PoC references are recorded
   as rows in `poc_refs` (URLs, module names, template paths) but nothing
   is downloaded. Re-run without the flag to populate the cache.

2. The source is silently no-opping because its CLI isn't installed.
   `SearchsploitSource` explicitly returns an empty list if `searchsploit`
   is not on `PATH` (see `SearchsploitSource.QueryAsync`). Install via
   `drederick doctor --install` or `apt install exploitdb`.

Diagnose:

1. Check the aggregate event for each CVE:

    ```bash
    jq 'select(.event=="poc.aggregate")' out/audit.jsonl
    ```

2. Look for the error path:

    ```bash
    jq 'select(.event=="poc.aggregate.error")' out/audit.jsonl
    ```

3. Query the DB for what did get recorded:

    ```bash
    sqlite3 out/findings.db 'SELECT source, COUNT(*) FROM poc_refs GROUP BY source;'
    sqlite3 out/findings.db 'SELECT source, COUNT(*) FROM poc_sources GROUP BY source;'
    ```

4. If only `poc_refs` has rows but `poc_sources` is empty, caching was
   disabled (flag or missing tool). If both are empty, annotation itself
   didn't run — see [cve-offline](#cve-offline).

---

## scanner-fail

Individual scanner failures do not abort the run. Each scanner logs a
`<name>.error` event to `out/audit.jsonl` (e.g. `nmap.error`,
`http.error`, `tls.error`, `http-content-discovery.error`) and returns
whatever it collected; other scanners and targets continue.

1. List every scanner error for the run:

    ```bash
    jq 'select(.event|endswith(".error"))' out/audit.jsonl
    ```

2. Group by scanner to see which tool was unstable:

    ```bash
    jq -r 'select(.event|endswith(".error")) | .event' out/audit.jsonl \
      | sort | uniq -c | sort -rn
    ```

3. What's already in `findings.db` is safe to use — the `findings` table
   carries everything that was collected before the failure. Re-run just
   the failed targets rather than the whole scope.

4. If a scanner consistently fails on the same target, try running it
   in isolation outside drederick to see the raw error (e.g. invoke
   `nmap` with the same argv printed in the `nmap.start` audit event).

5. If a scanner crashes the host process (not just the scanner), that's
   a bug — capture `out/audit.jsonl` and the stack trace and file it
   against the bug template below.

---

## Still stuck?

- File a bug using the [`bug_report.yml`](../.github/ISSUE_TEMPLATE/bug_report.yml)
  issue template. Attach the relevant slice of `out/audit.jsonl`, your
  `drederick --version`, and the exact command line.
- For anything scope-enforcement-adjacent (scope bypass, a scanner
  touching something outside the authorized list, authorization
  concerns), follow [`SECURITY.md`](../SECURITY.md) instead of opening
  a public issue.
