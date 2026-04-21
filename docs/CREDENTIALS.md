---
title: Credential Storage & Management
audience: [humans, agents]
primary: humans
stability: stable
last_audited: 2026-04
related: [SCOPE_AND_LEGAL.md, DEVELOPING.md, ../SECURITY.md, ../README.md]
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

### Drederick Never Executes PoCs

Drederick **aggregates** public PoC artefacts from Exploit-DB but **never executes** them. This is safe for untrusted networks and protected labs.

### Credentials Are Used for Discovery Only

Credentials are **only used for reconnaissance** (nmap, DNS, LDAP). They're never used for exploitation or payload delivery. Drederick is scope-enforced and operator-controlled.

### Always Respect Scope Boundaries

Scope enforcement is **mandatory**. Before scanning:
1. Verify your scope file contains only authorized targets
2. Use `--require-vpn` for lab/CTF work (HTB protection)
3. Use `--no-lab` for stricter scope enforcement in production

### Revoke Credentials on Exit

After a competition or engagement:
1. Revoke all API tokens in your account settings
2. Delete local config files
3. Unset environment variables: `unset DREDERICK_HTB_TOKEN`

---

**Questions?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on [GitHub](https://github.com/SchwartzKamel/drederick/issues).
