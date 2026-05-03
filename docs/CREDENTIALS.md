---
title: Credential Storage & Management
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-05
related: [SCOPE_AND_LEGAL.md, POST_EXPLOITATION.md, LLM_SETUP.md, DEVELOPING.md, ../SECURITY.md, ../README.md]
---

# Credential Storage & Management

This guide explains where and how to securely store credentials for Drederick.

## Overview

Drederick uses credentials for:
- **Hack The Box (HTB)** — API tokens for HTB-specific features
- **SearchSploit** — Optional API key for private exploits
- **Proxies** — HTTP/HTTPS proxy authentication
- **Custom tools** — Custom integrations (if applicable)

### Why Security Matters

Leaked credentials can compromise your lab or CTF account. **Never commit credentials to git.** Always use environment variables or secure config files with restricted permissions.

## Environment Variables

### Drederick-Specific

```bash
# Hack The Box API token
export DREDERICK_HTB_TOKEN="your_htb_token_here"

# LLM model override (for agent runner)
export DREDERICK_MODEL="gpt-4"

# Enable integration tests (development only)
export DREDERICK_INTEGRATION=1
```

### System Tools

```bash
# Proxy settings (used by curl, wget, etc.)
export HTTP_PROXY="http://proxy.internal:8080"
export HTTPS_PROXY="https://proxy.internal:8443"
export NO_PROXY="localhost,127.0.0.1"

# OpenAI API key (if using agent runner with LLM)
export OPENAI_API_KEY="sk-..."
```

### How to Set Environment Variables

**Bash/Zsh (temporary):**
```bash
export DREDERICK_HTB_TOKEN="token_here"
drederick --scope scope.txt
```

**Bash/Zsh (permanent):**
Add to `~/.bashrc` or `~/.zshrc`:
```bash
export DREDERICK_HTB_TOKEN="token_here"
```

Then reload:
```bash
source ~/.bashrc  # or ~/.zshrc
```

**.env file (for project-specific setup):**
```bash
# Create .env file (don't commit to git!)
cat > ~/.drederick/.env <<EOF
DREDERICK_HTB_TOKEN=token_here
HTTP_PROXY=http://proxy:8080
EOF

# Source it before running drederick
source ~/.drederick/.env
drederick --scope scope.txt
```

## Configuration Files

### Location

Drederick looks for configuration in `~/.drederick/config.json`.

### Example Structure

```json
{
  "htb": {
    "api_token": "your_token_here"
  },
  "searchsploit": {
    "api_key": "optional"
  },
  "proxy": {
    "http": "http://proxy.internal:8080",
    "https": "https://proxy.internal:8443"
  }
}
```

### File Permissions

**Critical**: Restrict permissions to owner only:
```bash
chmod 600 ~/.drederick/config.json
```

This ensures only your user can read the file (no group/world access).

### Creating the Config File

Use `drederick init` for guided setup:
```bash
drederick init
```

Or manually:
```bash
mkdir -p ~/.drederick
cat > ~/.drederick/config.json <<'EOF'
{
  "htb": {
    "api_token": "your_token_here"
  }
}
EOF
chmod 600 ~/.drederick/config.json
```

## Credential Scoping

### Use .gitignore

Never commit credentials to git:
```bash
# .gitignore
.drederick/
.env
*.env
scope.txt  # if it contains sensitive IPs
config.json
*.swp
```

### Separate Credentials Per Lab/CTF

Create separate config files for each engagement:
```bash
# HTB Pwnbox
~/.drederick/htb-pwnbox.json

# HTB Endgame
~/.drederick/htb-endgame.json

# Internal lab
~/.drederick/internal-lab.json
```

Use when running:
```bash
DREDERICK_CONFIG="~/.drederick/htb-pwnbox.json" drederick --scope scope.txt
```

### Rotate Tokens After Competitions

After each HTB/CTF competition:
1. Revoke the old token in your account settings
2. Generate a new token
3. Update your config file
4. Delete the old token from any cached locations

### Use a Secrets Manager (Production)

For production environments, use a secrets manager:
- **1Password** — `op read op://vault/drederick/htb_token`
- **LastPass** — `lpass show --password "Drederick HTB Token"`
- **HashiCorp Vault** — `vault kv get secret/drederick`

Example:
```bash
export DREDERICK_HTB_TOKEN=$(op read op://vault/drederick/htb_token)
drederick --scope scope.txt
```

## Best Practices

### Never Hardcode Credentials

❌ **Bad:**
```bash
drederick scan --htb-token "abc123" --scope scope.txt  # DON'T DO THIS
```

✅ **Good:**
```bash
export DREDERICK_HTB_TOKEN="abc123"
drederick --scope scope.txt
```

### Use Short-Lived Tokens

For HTB and CTF work:
- Generate a temporary token for the competition
- Revoke it immediately after
- Use a different token for each engagement if possible

### Rotate Credentials Regularly

- **Monthly** — For persistent lab access
- **After each competition** — For CTF/HTB
- **Immediately** — If credentials are suspected compromised

### Audit Log Review

Check what Drederick is doing:
```bash
cat ~/.drederick/audit.jsonl
```

Look for unexpected tool invocations or unusual activity.

### Proxy Usage

If using a corporate proxy:
```bash
export HTTP_PROXY="http://proxy.corp.com:8080"
export HTTPS_PROXY="https://proxy.corp.com:8443"
```

Test with curl:
```bash
curl -I https://github.com  # Should work through proxy
```

### SSH Keys

If you have SSH keys protected by passphrases:
```bash
# Start ssh-agent
eval $(ssh-agent -s)

# Add your key (you'll be prompted for passphrase once)
ssh-add ~/.ssh/id_rsa

# Now SSH commands won't prompt for the passphrase
```

Never store SSH passphrases in plain text config files.

## Troubleshooting Credential Issues

### "Authorization Failed" Error

Check:
1. Token expiry: `echo $DREDERICK_HTB_TOKEN` — is it set?
2. Token format: Should start with specific prefix (check HTB docs)
3. Permissions: `ls -la ~/.drederick/config.json` — is it readable by you?

### "Connection Refused" with Proxy

Check:
1. Proxy URL: `echo $HTTP_PROXY`
2. Proxy reachability: `curl -I https://github.com -x $HTTP_PROXY`
3. Proxy auth: If proxy needs auth, include in URL: `http://user:pass@proxy:8080`

### Credentials Not Picked Up

Check priority:
1. Environment variables (highest priority)
2. Config file at `~/.drederick/config.json`
3. CLI arguments (lowest priority)

Test which is being used:
```bash
drederick --help 2>&1 | grep -i credential  # Show credential sources
```

## Security Reminders

### Scope is the authorization boundary

Drederick is a **full-auto offensive security harness** inside scope. It
discovers, fingerprints, **and** executes cached PoCs, drives Metasploit,
runs credential attacks, delivers payloads, and handles post-ex — all
gated on per-category opt-in flags (`--allow-exec-pocs`,
`--allow-cred-attacks` + `--acknowledge-lockout-risk`, `--allow-payloads`,
`--allow-destructive`, `--allow-dos`). **Outside scope it does nothing.**
Every network-touching tool re-checks the scope allow-list as its first
statement — there is no flag, env var, debug build, or prompt phrasing
that disables that check. See
[SCOPE_AND_LEGAL.md](SCOPE_AND_LEGAL.md#invariants).

### Operator credentials vs captured credentials

Two distinct categories live in this document's orbit:

- **Operator credentials** — the tokens documented above (HTB API
  tokens, `OPENAI_API_KEY`, proxy credentials). These authenticate
  *you* to external services. Store them in environment variables or
  `~/.drederick/config.json` with `chmod 600`.
- **Captured credentials** — material Drederick obtains during a run
  (cracked hashes, captured tickets, successful spray results). These
  flow through
  [`CredentialStore`](../src/Drederick/Autopilot/CredentialStore.cs)
  (in-process index for the `AutopilotRunner`) and the credential-attack
  tools in [`src/Drederick/Exploit/`](../src/Drederick/Exploit/) (e.g.
  [`PasswordSprayTool`](../src/Drederick/Exploit/PasswordSprayTool.cs),
  [`NativeHttpSprayTool`](../src/Drederick/Exploit/NativeHttpSprayTool.cs)),
  and land in `out/` (see `loot` / `exploit_runs` / `sessions` tables
  in `findings.db`). They are never exfiltrated to a third party.
  Plaintext passwords attempted during credential attacks are **never**
  logged — `audit.jsonl` records a SHA-256 of the attempted secret so
  the operator can correlate without leaking wordlists. This is the
  [`@invariant-id:audit-everything`](../AGENTS.md#invariants) contract
  and there is no flag, env var, or prompt that disables it.

### Always Respect Scope Boundaries

Scope enforcement is **mandatory**. Before scanning:
1. Verify your scope file contains only authorized targets
2. Use `--require-vpn` for lab/CTF work (HTB protection)
3. Use `--no-lab` for stricter scope enforcement in production — every
   exploitation category becomes opt-in per flag

### Revoke Credentials on Exit

After a competition or engagement:
1. Revoke all API tokens in your account settings
2. Delete local config files
3. Unset environment variables: `unset DREDERICK_HTB_TOKEN`

---

**Questions?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on [GitHub](https://github.com/SchwartzKamel/drederick/issues).

---

### Credential-attack tool inventory

The full credential-attack surface lives across `src/Drederick/Exploit/`
and `src/Drederick/Exploit/PostEx/`. Every entry below validates scope
on entry, gates on `--allow-cred-attacks` (and `--acknowledge-lockout-risk`
for spray flows), records argv digest + secret SHA-256 to `audit.jsonl`,
and never logs plaintext credentials.

| Tool | File | Purpose | Extra gates |
| ---- | ---- | ------- | ----------- |
| `PasswordSprayTool` | [`Exploit/PasswordSprayTool.cs`](../src/Drederick/Exploit/PasswordSprayTool.cs) | Multi-protocol password spray (SMB, LDAP, WinRM, etc.) with realm-aware username derivation. Lockout-aware throttling default-on. | `--acknowledge-lockout-risk` |
| `NativeHttpSprayTool` | [`Exploit/NativeHttpSprayTool.cs`](../src/Drederick/Exploit/NativeHttpSprayTool.cs) | In-process HTTP basic/NTLM spray (no subprocess). | `--acknowledge-lockout-risk` |
| `HttpFormBruteTool` | [`Exploit/Web/HttpFormBruteTool.cs`](../src/Drederick/Exploit/Web/HttpFormBruteTool.cs) | Targeted HTTP login-form brute (CSRF token prefetch, cookie chain). | `--acknowledge-lockout-risk` |
| `AsRepRoastTool` | [`Exploit/Ad/AsRepRoastTool.cs`](../src/Drederick/Exploit/Ad/AsRepRoastTool.cs) | AS-REP roasting against accounts with pre-auth disabled — yields hashes for offline crack. Native Kerberos transport via `KdcTransport`. | none beyond `--allow-cred-attacks` (no online lockout risk) |
| `KerberoastTool` | [`Exploit/Ad/KerberoastTool.cs`](../src/Drederick/Exploit/Ad/KerberoastTool.cs) | Kerberoast SPN tickets via `KerberosNetKerberoastEngine` for offline crack. | requires authenticated Kerberos session |
| `SshKeyBruteTool` | [`Exploit/PostEx/SshKeyBruteTool.cs`](../src/Drederick/Exploit/PostEx/SshKeyBruteTool.cs) | SSH key/password brute against scope-resolved hosts. | `--acknowledge-lockout-risk` |
| `SshKeyPassphraseBruteTool` | [`Exploit/PostEx/SshKeyPassphraseBruteTool.cs`](../src/Drederick/Exploit/PostEx/SshKeyPassphraseBruteTool.cs) | Offline brute of an encrypted SSH private key passphrase. No network → no lockout, but still gated on `--allow-cred-attacks` for audit consistency. | none beyond `--allow-cred-attacks` |
| `WinRmAuthTool` | [`Exploit/PostEx/Windows/WinRmAuthTool.cs`](../src/Drederick/Exploit/PostEx/Windows/WinRmAuthTool.cs) | GAP-046 credential spray over evil-winrm with **adaptive timeout backoff** (per-host RTT-aware) and lockout-aware throttling. | `--acknowledge-lockout-risk` |
| `NtdsSamDumpTool` | [`Exploit/PostEx/Windows/NtdsSamDumpTool.cs`](../src/Drederick/Exploit/PostEx/Windows/NtdsSamDumpTool.cs) | GAP-047 SAM/LSA/NTDS dump via `impacket-secretsdump`. Three modes (Remote, RemoteDcSync, LocalHives). Captured hashes are deposited into `CredentialStore`. | `RemoteDcSync` mode additionally requires `--allow-destructive` |
| `ZeroLogonTool` | [`Exploit/ZeroLogonTool.cs`](../src/Drederick/Exploit/ZeroLogonTool.cs) | Native C# CVE-2020-1472 — sets DC machine account password to empty, then optionally chains into `secretsdump` for full domain compromise. | requires both `--allow-cred-attacks` AND `--allow-destructive` |

**Lockout discipline.** Spray flows (`PasswordSprayTool`,
`NativeHttpSprayTool`, `HttpFormBruteTool`, `WinRmAuthTool`) consult
[`LockoutScheduler`](../src/Drederick/Exploit/Spray/LockoutScheduler.cs)
to space attempts across the configured realm-policy window.
`--acknowledge-lockout-risk` is the operator's positive attestation
that they understand the consequences if the policy estimate is wrong;
without it, every spray refuses cleanly at the tool layer (not the
toolbox — see [`POST_EXPLOITATION.md#safety-model`](POST_EXPLOITATION.md#safety-model)).
