---
title: Troubleshooting runbook
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-05
related:
  - README.md
  - MODULES.md
  - SCOPE_AND_LEGAL.md
  - DATASETTE.md
  - JEOPARDY.md
  - LLM_SETUP.md
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
| nmap reports 0 ports but native HTTP/TLS probes succeeded | [port-truth-divergence](#port-truth-divergence) |
| `--agent` LLM stopped after recon (no exploit attempts) | [llm-recon-only](#llm-recon-only) |
| `--agent` runner errors / timeouts | [llm-runner](#llm-runner) |
| Copilot model unavailable / not tool-call compliant | [llm-runner](#llm-runner) (item 2) |
| `--agent=hybrid` unexpectedly fell back to deterministic | [llm-runner](#llm-runner) (item 8) |
| `Copilot CLI not found at .../runtimes/<rid>/native/copilot` | [llm-runner](#llm-runner) (item 9) |
| PoC cache empty despite CVEs | [poc-cache](#poc-cache) |
| Scanner crashed mid-run | [scanner-fail](#scanner-fail) |
| Jeopardy: Docker sandbox unreachable | [jeopardy-docker](#jeopardy-docker) |
| Jeopardy: CTFd 401 / 403 | [jeopardy-ctfd-auth](#jeopardy-ctfd-auth) |
| Jeopardy: no LLM provider picked up | [jeopardy-llm](#jeopardy-llm) |
| Jeopardy: scope rejects CTFd host | [jeopardy-scope](#jeopardy-scope) |

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
   `/8` IPv4 or `/32` IPv6 is refused; in strict (`--no-lab`) the caps
   are `/16` and `/48`. Pass `--allow-broad` to override deliberately.

4. **Whitespace / CRLF.** Lines are trimmed before parsing, so trailing
   spaces are fine, but a stray character before the address is not.
   Save scope files as UTF-8 without BOM.

5. **Empty file / all-comments.** Rejected with `Scope is empty`.

6. **YAML form with `exclude:`.** Drederick also accepts a YAML
   scope file with `include:` and optional `exclude:` lists; the
   exclude list is a deny-overlay that wins over include (see
   [SCOPE_AND_LEGAL.md#deny-overlay](SCOPE_AND_LEGAL.md#deny-overlay)).
   A target rejected by `exclude:` reports the deny rule that fired
   in the `ScopeException` message — useful when a previously-allowed
   host suddenly stops responding to scans.

---

<a id="port-truth-divergence"></a>
## port-truth-divergence

**Symptom:** nmap reports `0 open ports` for a target, but native HTTP
or TLS probes against the same host succeeded (`http.finish` /
`tls.finish` events in `out/audit.jsonl`).

**Cause:** nmap's defaults (`-T4 --min-rate 1000` plus a 300-second
host timeout, see `src/Drederick/Recon/NmapTool.cs`) are tuned for
fast lab scanning. A slow Windows host — common on HTB / OffSec /
TryHackMe — drops or delays SYN responses badly enough that the
host-timeout fires before any port is reported. The rate limit then
prevents nmap from retrying. JobTwo r4 lost an HTB box this way:
nmap returned `[]`, the runner stopped, and the operator never saw
the 80/443/5985/10001/10002 services that native probes had already
proven open.

**Fix — already applied:** `ExploitationPlanner.HarvestPortsFromAllSignals`
unifies port evidence across every recon signal (nmap, NativeScan,
HTTP/TLS/SMB/FTP/SSH/SNMP/LDAP/RPC/Kerberos probes) before the
exploit planner runs. A port observed by *any* signal is treated as
open even if nmap missed it. See
`src/Drederick/Autopilot/ExploitationPlanner.cs` (`HarvestPortsFromAllSignals`).

**Operator workaround if nmap data is desired anyway:**

1. Re-run nmap against the slow target with a longer host timeout
   and lower rate, bypassing drederick's wrapper for that one
   target:

    ```bash
    nmap -Pn -sV -sC --host-timeout 1200s --min-rate 100 -p- <target>
    ```

2. Inspect what each scanner observed, port-by-port:

    ```bash
    jq 'select(.event|test("\\.(start|finish)$")) | {event,target:.target,port:.port,url:.url}' \
      out/audit.jsonl
    ```

3. Drederick's reports (`out/report.json`, `out/findings.db`) already
   reflect the unified set; the divergence only matters if you are
   comparing native nmap output with drederick's view.

---

<a id="llm-recon-only"></a>
## llm-recon-only

**Symptom:** `--agent` (or `--agent=hybrid` when the LLM leg succeeded)
finished a fight with only `nmap.*` / `http.*` events in
`out/audit.jsonl` — no `*.cred_spray.*`, `*.exploit.*`,
`postex.*`, or session-open events. The operator wanted exploitation
to be attempted.

**Cause:** previously the system prompt let the model stop after
recon. Closed by GAP-025: the prompt now contains a forcing function.
After enumeration the model **must** do at least one of (1) call
`exploit_plan` and act on every action whose required permission
flag is enabled, (2) call `execute_cred_spray` against every
auth-bearing service it observed, (3) run post-ex on any opened
session, or (4) explicitly state in the summary that every offensive
category is forbidden by the current permission flags and name the
missing flag(s). Recon-only is now a documented **loss** unless
gated by missing permissions. See
`src/Drederick/Agent/MicrosoftAgentRunner.cs` (`BuildSystemPrompt`).

**Diagnose:**

1. Confirm what categories the run actually allowed:

    ```bash
    jq 'select(.event=="run.start") | {flags:.flags}' out/audit.jsonl
    ```

    Look for `allow_exec_pocs`, `allow_cred_attacks`,
    `allow_payloads`, `acknowledge_lockout_risk`. If they are all
    `false`, the model has nothing to spend — its summary should say
    so explicitly.

2. Re-read the model's final assistant message
   (`out/report.md` or `out/audit.jsonl` `runner.agent.final`
   events). If the model *did* call out a missing flag, the
   forcing function worked — fix the flag and re-run.

**Fix — enable the missing permissions:**

- Lab mode (default) already enables exploit categories except DoS;
  if you are in `--no-lab`, opt in per category:

    ```bash
    drederick --scope ~/scope.txt --target 10.10.10.42 --no-lab \
      --allow-exec-pocs --allow-cred-attacks --acknowledge-lockout-risk \
      --allow-payloads --agent --out ~/results
    ```

- DoS / malware NSE remain opt-in even in lab — add `--allow-dos`
  if you specifically want them.

**If the model still stops after recon with permissions enabled:**
file an issue against the prompt — that is now a regression.

---

## llm-runner

`--agent` supports `--llm-provider=copilot|azure|openai`. Copilot uses
the official `GitHub.Copilot.SDK` runner
(`src/Drederick/Agent/CopilotSdkAgentRunner.cs`); Azure and raw OpenAI use
`src/Drederick/Agent/MicrosoftAgentRunner.cs` with structured tool-call
adapters. Errors are recorded as `runner.agent_error` in the audit log and
then rethrown.

1. Check the env vars are actually exported in the shell you're running
   `drederick` from:

    ```bash
    env | grep -E 'COPILOT_TOKEN|GH_TOKEN|GITHUB_TOKEN|AZURE_OPENAI|OPENAI_API_KEY|DREDERICK_MODEL'
    ```

2. For Copilot model selection, the SDK runner checks
   `https://api.githubcopilot.com/models` (no `/v1`) and only runs models
   that are available to your token and tool/function-call compliant.
   Preferred default is `claude-sonnet-4.6`; override with
   `DREDERICK_MODEL` only when the replacement is also compliant:

    ```bash
    export DREDERICK_MODEL=claude-sonnet-4.6
    ```

   If an explicit model is missing or non-compliant, both pure `--agent`
   and `--agent=hybrid` fail clearly. Drederick does not hide a selected
   non-tool Copilot model behind deterministic fallback.

3. If the selected provider cannot be created because auth/config is
   missing, `--agent` falls back deterministically with a provider-specific
   setup hint, and `--agent=hybrid` records the fallback path. For Copilot,
   run `gh auth login --web` or export `COPILOT_TOKEN`, `GH_TOKEN`, or
   `GITHUB_TOKEN`.

4. Azure/OpenAI deployments are operator-managed. The configured model or
   deployment must support structured tool calls; otherwise pure
   `--agent` fails clearly and hybrid falls back.

5. Rate limits / timeouts / provider 5xx surface as
   `runner.agent_error`. Inspect:

    ```bash
    jq 'select(.event=="runner.agent_error")' out/audit.jsonl
    ```

6. Fall back to the deterministic adaptive runner (no LLM, no network
   calls to an LLM provider) by dropping the flag:

    ```bash
    drederick <args>  # no --agent
    ```

7. If the LLM succeeded but called no tools, the scope enforcement may
   have rejected every target — check for `scope` errors in
   `out/audit.jsonl` before blaming the model.

8. **Hybrid mode (`--agent=hybrid`) unexpectedly ran the deterministic
   runner.** `HybridAgentRunner` falls back to `AdaptiveRunner` on any
   operational failure of the LLM planner — missing key, network
   error, auth, rate limit, timeout, transient SDK exception. This is
   intentional. Copilot model-compliance refusals are different: selected
   non-tool models propagate so the operator fixes `DREDERICK_MODEL`.
   Look for the fallback audit event:

    ```bash
    jq 'select(.event=="hybrid.llm_fallback")' out/audit.jsonl
    ```

   The record contains the exception **type** and a SHA-256 of the
   message. The full message is deliberately not logged because
   SDK/LLM errors can echo back prompt fragments, URLs, or token IDs.
   If you want the LLM planner to be load-bearing (abort the run when
   it can't run), use `--agent` / `--agent=llm`, not
   `--agent=hybrid`. `ScopeException`, `OperationCanceledException`, and
   Copilot model-compliance failures always propagate from hybrid mode —
   they are never swallowed by the fallback.

9. **Copilot CLI not found at `<install>/runtimes/<rid>/native/copilot`.**
   The `GitHub.Copilot.SDK` ships its native CLI as a sidecar that
   must live next to the installed `drederick` binary. If the sidecar
   is missing, `runner.agent_error` records:

    ```text
    Copilot CLI not found at '<prefix>/runtimes/linux-x64/native/copilot'.
    ```

   Verify and fix:

    ```bash
    ls "$(dirname "$(command -v drederick)")/runtimes/linux-x64/native/copilot"
    # If missing:
    cd /path/to/drederick && make install
    # Or reinstall the released tarball:
    curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash
    ```

   `make install`, `scripts/install.sh`, and the release tarball all
   ship the `runtimes/<rid>/native/copilot` sidecar with the executable
   bit preserved. Older builds installed only the single binary —
   reinstall after upgrading.

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

## jeopardy-docker

`drederick ctf-solve` requires Docker for the solver sandbox (see
`src/Drederick/Doctor/JeopardyDoctorChecks.cs` — `DockerInstalledCheck`,
`DockerDaemonCheck`). The preflight will not auto-install Docker —
blast radius is too high.

1. Run the category preflight:

    ```bash
    drederick doctor --category=jeopardy
    ```

2. Install Docker via your distro's recipe — the doctor prints the
   command:

    ```bash
    # Debian/Ubuntu/Kali:
    sudo apt install docker.io
    # Fedora/RHEL:
    sudo dnf install docker
    # macOS:
    brew install --cask docker
    ```

3. If Docker is installed but `DockerDaemonCheck` fails with
   `Docker daemon not reachable`:

    ```bash
    sudo systemctl start docker
    sudo usermod -aG docker "$USER"   # then re-login
    docker info                        # confirm
    ```

4. Build the Jeopardy sandbox image once per host (the coordinator
   won't pull it from a registry):

    ```bash
    docker build \
      -t drederick/jeopardy-sandbox \
      -f sandbox/Dockerfile.jeopardy-sandbox sandbox/
    ```

5. If `/var/lib/docker` is on a filesystem that can't host overlayfs
   (some NFS / 9P mounts), move Docker's data root to a local disk
   before running.

---

## jeopardy-ctfd-auth

Authentication against CTFd uses the API token you pass via
`--ctfd-token` or `$CTFD_TOKEN`. Failures surface as HTTP `401` /
`403` from `CtfdClient` on the first poll.

1. Confirm the token by hand against the CTFd host in scope:

    ```bash
    curl -fsSL \
      -H "Authorization: Token ${CTFD_TOKEN}" \
      "${CTFD_URL}/api/v1/challenges" | jq '.data | length'
    ```

2. `401 Unauthorized` — the token is wrong, revoked, or belongs to a
   user that hasn't accepted the event rules. Re-mint via the CTFd UI
   (profile → **Settings** → **Access Tokens**).

3. `403 Forbidden` — token is valid but the user lacks permission
   (team not registered, event not started, admin-only scoreboard).
   Check the rules tab in the CTFd UI.

4. The CTFd token is **never logged in plaintext**; its SHA-256 is
   recorded in `audit.jsonl`. To correlate after the fact:

    ```bash
    jq 'select(.event=="ctfd.auth")' out/ctf-report/audit.jsonl
    ```

---

## jeopardy-llm

`drederick ctf-solve` selects its LLM backend via
[`LlmProviderFactory`](../src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs).
Pick the backend with `--llm-provider {copilot|azure|llamacpp}`
(default `copilot`). Copilot / Azure OpenAI / llama.cpp are all wired;
per-provider flag reference lives in
[`LLM_SETUP.md`](LLM_SETUP.md#ctf-solve-cli-recipes).

1. `no Copilot token found (set COPILOT_TOKEN, GH_TOKEN, or GITHUB_TOKEN)`:

    ```bash
    # Preferred:
    gh auth login --web
    # Or, for automation:
    export COPILOT_TOKEN="ghu_..."
    export GH_TOKEN="$(gh auth token)"
    # PAT fallback (routes to the GitHub Models endpoint):
    export GITHUB_TOKEN="ghp_..."
    ```

   Precedence is `COPILOT_TOKEN > GH_TOKEN > GITHUB_TOKEN > gh auth token`.
   If no token is available and the terminal is interactive, Drederick starts
   `gh auth login --web --skip-ssh-key` and retries. A `GITHUB_TOKEN` that
   looks like a PAT causes the client to use
   `https://models.inference.ai.azure.com/v1` instead of the Copilot
   endpoint — see [LLM_SETUP.md#precedence](LLM_SETUP.md#precedence).

2. Azure OpenAI env set but requests aren't going there — pass
   `--llm-provider=azure` explicitly. The Jeopardy runner defaults to
   Copilot; it does not auto-switch based on `AZURE_OPENAI_*` env
   alone. Minimum config:

    ```bash
    export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
    export AZURE_OPENAI_API_KEY="…"
    export AZURE_OPENAI_DEPLOYMENT_MAP="gpt-5.4=gpt5-prod"
    drederick ctf-solve --llm-provider=azure --models=gpt-5.4 …
    ```

3. `LLAMACPP_URL` connection refused — your `llama-server` isn't
   running or isn't bound on the expected port. Confirm:

    ```bash
    curl -fsSL "$LLAMACPP_URL/v1/models"
    llama-server -m model.gguf --port 8080 -c 8192 --jinja
    ```

4. `AZURE_OPENAI_DEPLOYMENT_MAP` unset and calls fail with
   `DeploymentNotFound` — logical model ids in `--models` must map to
   real deployment names in your Azure resource:

    ```bash
    export AZURE_OPENAI_DEPLOYMENT_MAP="gpt-5.4=gpt5-prod,gpt-4o=gpt4o-prod"
    ```

5. Azure `401` — api-key wrong or Entra bearer expired. Refresh:

    ```bash
    export AZURE_OPENAI_BEARER_TOKEN="$(az account get-access-token \
      --resource https://cognitiveservices.azure.com \
      --query accessToken -o tsv)"
    ```

---

## jeopardy-scope

The CTFd host and every per-challenge infra host must live in the
scope file. `CtfdClient` / `SandboxManager` re-check scope at the tool
boundary; the LLM cannot bypass it.

1. `CTFd host '…' is not in scope` — add the CTFd host (IP or
   hostname) to `scope.yaml` and retry. Hostnames are resolved and
   scope-checked against the resolved IP.

2. If per-challenge boxes appear mid-event (`ssh.chal.example.com`,
   `web-svc.chal.example.com:31337`), append them to the scope file.
   The solver will keep moving on other challenges while you edit — the
   next challenge dispatch re-reads the relevant hosts at its own
   boundary.

3. Wildcards are still refused. A reasonable CTFd scope:

    ```text
    # CTFd platform
    ctf.example.com
    # per-challenge infra listed by organizers
    chal.example.com
    ```

4. Diagnose at run time:

    ```bash
    jq 'select(.event|startswith("scope"))' out/ctf-report/audit.jsonl
    ```

---

## Still stuck?

- File a bug using the [`bug_report.yml`](../.github/ISSUE_TEMPLATE/bug_report.yml)
  issue template. Attach the relevant slice of `out/audit.jsonl`, your
  `drederick --version`, and the exact command line.
- For anything scope-enforcement-adjacent (scope bypass, a scanner
  touching something outside the authorized list, authorization
  concerns), follow [`SECURITY.md`](../SECURITY.md) instead of opening
  a public issue.
