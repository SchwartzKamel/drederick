---
title: LLM setup — giving Drederick the unfair advantage
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-04
related:
  - README.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
  - TROUBLESHOOTING.md
  - ../AGENTS.md
---

# LLM setup — giving Drederick the unfair advantage

> *"A fair fight is one you didn't prepare well enough for."*
> — **Drederick Tatum**, pre-bout press conference

This guide turns on Drederick's LLM cornerman. The agent reads the ring,
calls the next combination, and keeps the knockouts coming. The hard
rules below are non-negotiable: the LLM **cannot escape scope**, cannot
disable the audit log, and cannot invent targets. Everything it does is
bracketed by the same invariants the rest of the harness obeys — see
[`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md).

- [What the LLM does (and doesn't)](#what-the-llm-does)
- [Quickstart — 60 seconds to first LLM-driven scan](#quickstart)
- [Environment variables](#env-vars)
- [Choosing a model](#choosing-a-model)
- [Provider recipes](#provider-recipes)
  - [OpenAI (default, supported)](#provider-openai)
  - [OpenAI-compatible gateways](#provider-compatible)
  - [Azure OpenAI (roadmap)](#provider-azure)
  - [Ollama / local LLMs (roadmap)](#provider-ollama)
- [Combining `--agent` with `--autopilot`](#combining-agent-autopilot)
- [Cost, rate limits, and budgets](#cost)
- [Prompt hygiene and what the model sees](#prompt-hygiene)
- [Safety — what the LLM cannot do](#safety)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)

<a id="what-the-llm-does"></a>
## What the LLM does (and doesn't)

Drederick has **three** orchestration modes. Know which one you want:

| Mode | Flag | Brains | Weapons | When to use |
| ---- | ---- | ------ | ------- | ----------- |
| Adaptive (default) | *(none)* | Deterministic rules | Recon only | Fast, repeatable, offline; CI pipelines; low-noise rooms. |
| LLM cornerman | `--agent` | OpenAI chat model via Microsoft Agent Framework | Recon only (today) | You want the model to pick the **next probe** based on prior findings; diffing HTB boxes over repeat runs; unfamiliar surface. |
| Autopilot | `--autopilot` | Deterministic fight-card planner | **Exploit** (nuclei, credential spray, CVE-matched PoCs) | After recon, you want automated exploitation + flag extraction. |

They compose:

```bash
drederick --scope scope.yaml --target 10.10.10.5 \
  --agent --autopilot \
  --allow-exec-pocs --allow-cred-attacks --acknowledge-lockout-risk \
  --out out/
```

The `--agent` runner plans reconnaissance; the `--autopilot` runner then
executes the fight card against whatever the recon layer found. Both
obey the scope file. The LLM **does not** today drive the exploit
toolbox directly — that's on the roadmap (`llm-exploit-tools`,
`hybrid-agent-runner`). Until then, think of the LLM as the cornerman
and the autopilot as the jab–cross–hook sequence the fighter already
knows.

<a id="quickstart"></a>
## Quickstart — 60 seconds to first LLM-driven scan

1. Get an OpenAI API key: <https://platform.openai.com/api-keys>.
2. Export it:

   ```bash
   export OPENAI_API_KEY="sk-proj-..."
   # optional: pick a stronger model (default gpt-4o-mini)
   export DREDERICK_MODEL="gpt-4o"
   ```

3. Confirm it's exported (no newline, no quotes in the value):

   ```bash
   echo "${OPENAI_API_KEY:0:7}...${OPENAI_API_KEY: -4}"
   # → sk-proj-...abcd
   ```

4. Run a scoped scan with the LLM in the corner:

   ```bash
   drederick --scope scope.yaml --target 10.10.10.5 --agent --out out/
   ```

5. Watch the progress on stderr; the agent summary prints after the
   final bell:

   ```
   --- agent summary ---
   10.10.10.5 — open: 22/tcp (OpenSSH 8.2p1), 80/tcp (Apache 2.4.41),
   ...
   ---------------------
   ```

6. Open the dashboard: `drederick serve --out out/` → <http://127.0.0.1:8001>.

If the agent is unreachable for any reason, Drederick falls back to the
deterministic AdaptiveRunner automatically and writes
`runner.agent_error` to `out/audit.jsonl`. You never silently lose a
run because of a flaky API.

<a id="env-vars"></a>
## Environment variables

Supported today:

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `OPENAI_API_KEY` | *(unset → `--agent` falls back to Adaptive)* | OpenAI-format API key. Required for `--agent`. |
| `DREDERICK_MODEL` | `gpt-4o-mini` | OpenAI chat model name. Any model the key can call. |
| `DREDERICK_SKIP_CVE` | `0` | `1` disables the NVD CVE enrichment pass (faster, less informed). |

Env vars consumed by `--autopilot`: none today — autopilot is driven by
CLI flags (`--autopilot`, `--autopilot-default-creds`, `--cred ...`,
`--autopilot-max-iterations`, `--autopilot-max-actions`). See
[`README.md`](../README.md) §autopilot for the full flag list.

### Putting them in your shell profile

```bash
# ~/.zshrc or ~/.bashrc
export OPENAI_API_KEY="sk-proj-..."        # keep this file chmod 600
export DREDERICK_MODEL="gpt-4o"
```

Or use [direnv](https://direnv.net/) with a per-project `.envrc`:

```bash
# .envrc (git-ignore this file)
export OPENAI_API_KEY="sk-proj-..."
export DREDERICK_MODEL="gpt-4o"
```

Then `direnv allow` in the repo. The `.envrc` stays local; the key
never hits the repo.

### Using a secret manager

```bash
# 1Password CLI
export OPENAI_API_KEY="$(op read 'op://Private/OpenAI/api_key')"

# pass (password-store)
export OPENAI_API_KEY="$(pass show openai/api_key)"

# macOS Keychain
export OPENAI_API_KEY="$(security find-generic-password -a $USER -s openai -w)"
```

Never bake the key into a shell script you commit. Drederick never
writes the key to `audit.jsonl` or any report artifact.

<a id="choosing-a-model"></a>
## Choosing a model

Ranked by "how reliably does this pick the right next probe against a
lab box I've never seen":

| Model | Quality | Cost (relative) | When to pick |
| ----- | ------- | --------------- | ------------ |
| `gpt-4o` | Best | $$$ | Unknown surface; red-team eval; you want the LLM to catch the weird stuff. |
| `gpt-4o-mini` (default) | Strong | $ | HTB/CTF daily driver; good balance; cheap enough to leave on. |
| `gpt-4.1` / `o3-mini` / newer | Varies | Varies | Experimental; feature-flag it in a one-off shell before setting it globally. |
| `gpt-3.5-turbo` | Weak | ¢ | Not recommended; it will waste budget on repeats the AdaptiveRunner already handles. |

Rule of thumb: **if the deterministic AdaptiveRunner already finds
everything on your target, the LLM is strictly more expensive and no
more useful.** Turn `--agent` on when the surface is novel, when you
want cross-run synthesis, or when you're building toward the
LLM-driven exploit loop on the roadmap.

<a id="provider-recipes"></a>
## Provider recipes

<a id="provider-openai"></a>
### OpenAI (default, supported today)

Nothing fancy:

```bash
export OPENAI_API_KEY="sk-proj-..."
export DREDERICK_MODEL="gpt-4o"
drederick --scope scope.yaml --target 10.10.10.5 --agent --out out/
```

Organization/project scoping is honored by the key itself; Drederick
does not read `OPENAI_ORG` or `OPENAI_PROJECT` today.

<a id="provider-compatible"></a>
### OpenAI-compatible gateways (partial)

Drederick currently constructs the `OpenAIClient` with the built-in
default endpoint. Overriding the base URL to point at a compatible
gateway (LiteLLM, vLLM, Together, Groq, OpenRouter) is **not yet
plumbed as an env var** — it's on the roadmap.

Workarounds today:

1. **LiteLLM proxy** running locally that rewrites OpenAI-flavoured
   requests:

   ```bash
   pip install 'litellm[proxy]'
   litellm --model openrouter/anthropic/claude-3.5-sonnet --port 4000
   ```

   Then patch `src/Drederick/Agent/MicrosoftAgentRunner.cs` locally:

   ```csharp
   var openAi = new OpenAIClient(
       new ApiKeyCredential(apiKey),
       new OpenAIClientOptions { Endpoint = new Uri("http://127.0.0.1:4000") });
   ```

   Rebuild (`dotnet build`) and run. If you plan to upstream this,
   open an issue referencing todo `hybrid-agent-runner`.

2. **System-wide HTTP proxy** via `HTTPS_PROXY` — works but gives you
   no visibility into what's being rewritten. Not recommended for
   anything you care about.

A first-class env var (`DREDERICK_OPENAI_BASE_URL`) is planned; tracked
in [AGENTS.md](../AGENTS.md) extension points.

<a id="provider-azure"></a>
### Azure OpenAI (roadmap)

Not supported today. The Microsoft Agent Framework dependency
(`Microsoft.Agents.AI`) supports Azure OpenAI natively; wiring it
through `TryCreateFromEnvironment` requires reading
`AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` + deployment name and
constructing an `AzureOpenAIClient` instead of `OpenAIClient`. Tracked
under the same hybrid-agent-runner roadmap item.

If you need this now, open an issue with your deployment shape — it's
a ~30-line change once the env contract is agreed.

<a id="provider-ollama"></a>
### Ollama / local LLMs (roadmap)

Not supported today. Two reasons:

1. Tool-calling quality on local <13B models is still uneven, and the
   agent loop leans hard on well-formed tool calls.
2. The `ChatClient` wiring assumes OpenAI-style streaming tool calls;
   llama.cpp-based backends vary.

**Interim recipe** if you want to experiment:

```bash
# llama-cpp-python with OpenAI-compatible server
python -m llama_cpp.server \
  --model ~/models/qwen2.5-coder-14b-instruct-q4_k_m.gguf \
  --host 127.0.0.1 --port 8000 --n_ctx 16384 --chat_format chatml

export OPENAI_API_KEY="local-dummy"
export DREDERICK_MODEL="qwen2.5-coder"
# then apply the MicrosoftAgentRunner endpoint patch from
# the OpenAI-compatible section above, pointing at 127.0.0.1:8000
```

Expect false starts — the model will sometimes hallucinate tool names.
The scope invariant still holds: even a misbehaving model cannot reach
out-of-scope targets because the tool layer refuses them.

<a id="combining-agent-autopilot"></a>
## Combining `--agent` with `--autopilot`

The most powerful single invocation today:

```bash
drederick --scope scope.yaml --target 10.10.10.5 \
  --agent \
  --autopilot \
  --autopilot-default-creds \
  --allow-exec-pocs \
  --allow-cred-attacks \
  --acknowledge-lockout-risk \
  --lab \
  --out out/
```

Flow:

1. `--agent` drives recon with OpenAI picking which probes to run next,
   informed by `memory/findings.json` from previous runs.
2. After recon closes, `--autopilot` kicks in: the
   `ExploitationPlanner` builds a priority-ordered fight card
   (nuclei > cred-spray-with-realm > cred-spray-no-realm > msfrc),
   `AutopilotRunner` executes, `FlagExtractor` sweeps the captured
   output and loot dir for `flag{}` / `HTB{}` / `THM{}` / `picoCTF{}` /
   32-hex strings.
3. Reports land in `out/report.md`, `out/autopilot.md`, and
   `out/findings.db` (Datasette-ready).

Watch `out/audit.jsonl` in a second pane while the run is live:

```bash
tail -f out/audit.jsonl | jq -c '{ts, event, target}'
```

<a id="cost"></a>
## Cost, rate limits, and budgets

The agent runner is single-turn today: Drederick sends one prompt with
all targets and the prior-digest summary, and the agent calls tools
until it stops. On `gpt-4o-mini` a typical 3-target HTB sweep costs
pennies. On `gpt-4o` it's tens of pennies. Still cheap; budget
accordingly for fleets.

Guardrails that already exist:

- `ToolBudget` — the tool layer refuses repeat calls beyond a per-tool
  and global budget. The model cannot run up your bill by spamming
  `nmap_scan`. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for defaults.
- One-shot runner — no multi-turn conversation, no memory-doom-loop.
- Scope layer — the model cannot widen its target list mid-run.

What to watch for:

- **429 rate limits** from OpenAI → Drederick surfaces the exception
  and falls back to Adaptive. Check `audit.jsonl` for
  `runner.agent_error`.
- **Long-running targets** (slow nmap) → the model is idle while nmap
  runs; cost stays flat, time doesn't.

<a id="prompt-hygiene"></a>
## Prompt hygiene and what the model sees

The system prompt lives in
[`MicrosoftAgentRunner.BuildSystemPrompt()`](../src/Drederick/Agent/MicrosoftAgentRunner.cs).
It pins the agent to scoped reconnaissance and forbids it from
fabricating targets. The user message is built from:

- Your `--target` list (one line per target).
- A short `KnowledgeBase.Digest(target)` string per target, summarizing
  what prior runs found. This is how cross-run convergence happens.

The model does **not** see:

- Your `OPENAI_API_KEY` (it's only sent to OpenAI over TLS).
- Your scope file contents (only the specific target IPs you passed).
- Credentials from `CredentialStore` (autopilot is a separate runner).
- Raw nmap XML / HTTP bodies — those are summarized by the tool layer
  before returning to the agent.

If you want to change the prompt — e.g., to bias toward web surface on
a web-only engagement — edit `BuildSystemPrompt`, rebuild, and add a
test asserting the new prompt still contains the scope-pinning
language. Do not remove the "you MUST NOT fabricate tool output or
targets" line; it's there to keep the model honest.

<a id="safety"></a>
## Safety — what the LLM cannot do

These are not conventions; they are enforced in code. The LLM runner
has no special privileges.

| The LLM cannot… | Because… |
| --------------- | -------- |
| Scan a target outside `--scope` | Every tool's first statement is `_scope.Require(target)` — the tool layer refuses regardless of caller. |
| Widen the scope file | Scope is read-only from code. There is no write path. |
| Disable the audit log | `AuditLog` has no disable API. No env var, no flag, no prompt turns it off. |
| Exfiltrate loot to a third party | No network calls exist in the reporting or memory layers. The only outbound call is to OpenAI for chat completion, and it never carries loot content — only scan summaries. |
| Bypass per-run opt-ins | `--allow-exec-pocs`, `--allow-cred-attacks`, `--allow-payloads`, `--acknowledge-lockout-risk` are checked by the exploit/autopilot layers, not the agent runner. The model has no handle on them. |
| Invent a target | The tool layer rejects any target string not in the `--target` list. |

If a future model jailbreak tells the agent "ignore scope" or "assume
authorization", the tool call still fails. That's the design.

<a id="troubleshooting"></a>
## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `--agent requested but OPENAI_API_KEY is not set. Falling back to AdaptiveRunner.` on stderr | Env var missing or shell scope. | `export OPENAI_API_KEY=...` in the same shell; verify with `echo "${OPENAI_API_KEY:0:7}"`. |
| `runner.agent_error` in `audit.jsonl` with `401 Incorrect API key` | Key revoked or typo. | Regenerate at <https://platform.openai.com/api-keys>. |
| `runner.agent_error` with `model_not_found` | `DREDERICK_MODEL` references a model your key can't call. | `export DREDERICK_MODEL=gpt-4o-mini` and retry. |
| `runner.agent_error` with `429 rate_limit_exceeded` | OpenAI quota. | Drederick already fell back to Adaptive; raise your OpenAI tier or wait. |
| Agent summary missing / empty | Model returned empty text (tool-only response) or error. | Check `audit.jsonl` for `runner.agent_response.text_len=0`; often harmless — findings are in reports. |
| LLM calls the same tool on the same target repeatedly | Normal up to `ToolBudget`; the tool layer then refuses. | Raise budget in `ReconToolbox` wiring if legitimate; usually it's the model being inefficient. |
| `ScopeException` from an agent-invoked tool | Model chose a target not in your `--target` list, or it malformed the argument. | Expected — the tool refuses cleanly. Check `audit.jsonl` for the attempted target. |
| No LLM behaviour at all | You forgot `--agent`. Adaptive runs without it. | Add `--agent` to the command line. |

See also [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for non-LLM
issues (doctor, scope loader, Datasette).

<a id="roadmap"></a>
## Roadmap

These are tracked in the SQL todo list and the
[AGENTS.md extension points](../AGENTS.md#extension-points):

- `llm-exploit-tools` — expose `ExploitRunner`, `CredRunner`,
  `PayloadStager` as `AIFunction`s so the LLM can plan the
  **exploit** step, not just recon. Scope/permission gates still
  live on the tools; the model doesn't get a shortcut.
- `adaptive-exploit-runner` — deterministic fallback for
  `llm-exploit-tools` when no API key is set, so `--autopilot` can run
  LLM-shaped plans without an LLM.
- `hybrid-agent-runner` — wrapper that tries LLM first, falls back to
  deterministic on API failure. Also the home for `DREDERICK_OPENAI_BASE_URL`
  and the Azure OpenAI recipe.
- `test-llm-tools` — unit tests verifying every new AIFunction tool
  re-checks scope and that the deterministic fallback kicks in when
  `OPENAI_API_KEY` is missing.

Open an issue if your use case needs one of these promoted.

---

> *"You call that a scan? I've seen tighter enumeration from a rookie's
> jab. Let the cornerman call the combinations."*
> — **Drederick Tatum**, post-sparring debrief
