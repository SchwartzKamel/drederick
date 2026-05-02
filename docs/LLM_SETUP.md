---
title: LLM setup — giving Drederick the unfair advantage
audience: [humans]
primary: humans
stability: evolving
last_audited: 2026-05
related:
  - README.md
  - JEOPARDY.md
  - COMPARISON.md
  - POST_EXPLOITATION.md
  - ARCHITECTURE.md
  - SCOPE_AND_LEGAL.md
  - TROUBLESHOOTING.md
  - ../AGENTS.md
---

# LLM setup — giving Drederick the unfair advantage

> *"The best fighters don't pick one weapon — they pick the right weapon
> for the round. Copilot SDK gives you five families on one token. Azure
> gives you enterprise discipline. llama.cpp gives you a cornerman who
> doesn't leave the gym."*
> — **Drederick Tatum**, pre-bout press conference

Drederick's LLM stack is **provider-plural**. Pick the backend that
matches your posture; the rest of the harness is identical. The hard
rules below are non-negotiable: the LLM **cannot escape scope**, cannot
disable the audit log, and cannot invent targets. See
[`SCOPE_AND_LEGAL.md`](SCOPE_AND_LEGAL.md) for the full authorization
model.

- [Provider matrix](#providers)
- [Which mode uses which provider](#modes)
- [Copilot SDK](#provider-copilot)
- [Azure OpenAI](#provider-azure)
- [llama.cpp](#provider-llamacpp)
- [`--agent` (recon) — multi-provider](#provider-agent-recon)
- [`--agent=hybrid` (recon) — LLM first, deterministic fallback](#provider-agent-hybrid)
- [Web UI provider selection](#web-ui-provider)
- [Token precedence and auto-selection](#precedence)
- [`drederick doctor` — LLM checks](#doctor)
- [Cost, rate limits, budgets](#cost)
- [Prompt hygiene and what the model sees](#prompt-hygiene)
- [Safety — what the LLM cannot do](#safety)
- [Troubleshooting](#troubleshooting)

<a id="providers"></a>
## Provider matrix

Ranked by operator preference for this Microsoft-heavy shop. **Azure and
Copilot are first-class** for both `ctf-solve` and `--agent` recon; llama.cpp is the
escape hatch for Jeopardy only; raw OpenAI is deprioritized.

| Rank | Provider | Use case | Auth | Config env | Models | Pros | Cons |
| ---- | -------- | -------- | ---- | ---------- | ------ | ---- | ---- |
| 1 | **Copilot SDK / Copilot API** | `--agent` recon through the official `GitHub.Copilot.SDK`; Jeopardy solver swarm through the Copilot chat API. | OAuth (Copilot/GitHub PAT) | `COPILOT_TOKEN` → `GH_TOKEN` → `GITHUB_TOKEN` → authenticated `gh` CLI; `DREDERICK_MODEL` for `--agent` override; `COPILOT_INTEGRATION_ID` (default `drederick-cli`); `COPILOT_ENDPOINT` (default `https://api.githubcopilot.com`, Jeopardy/raw API only) | `--agent` uses Copilot `/models` metadata and only runs available tool/function-call compliant models; preferred default is `claude-sonnet-4.6`. Jeopardy can use any Copilot-exposed chat model in `--models`. | One token, five model families, Tatum approves. Built-in model rotation for the swarm. | Needs an active Copilot entitlement. Rate limits follow your subscription. |
| 1 | **Azure OpenAI** | Enterprise-governed deployments; auditable, per-tenant keys; Entra ID flows. | api-key **or** Entra ID bearer | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY` **or** `AZURE_OPENAI_BEARER_TOKEN`, `AZURE_OPENAI_API_VERSION` (default `2024-10-21`), `AZURE_OPENAI_DEPLOYMENT_MAP` | Whatever tool-calling deployments you manage in the resource — GPT-4o, GPT-4.1, o-series, etc. | Tenant-scoped, audit-friendly, data-residency controls, integrates with `az login`. | You own the deployments and must pick models that support tool calling. `modelId → deploymentName` mapping has to be correct. |
| 3 | **llama.cpp** | Offline / airgapped operations; lab hardware with GPUs; "no phone-home" policy. | none or static bearer | `LLAMACPP_URL` (default `http://127.0.0.1:8080`), `LLAMACPP_BEARER_TOKEN` (optional) | Any GGUF you can load. | Local, free, private. Works on the plane. | Tool-calling quality is model-dependent; most local models lack function calling and the client strips tools from those requests. |
| 4 | OpenAI (raw) | Legacy fallback for `--agent` recon runner. | `OPENAI_API_KEY` | `OPENAI_API_KEY`, `DREDERICK_MODEL` (default `gpt-4o-mini`) | OpenAI models with tool-calling support. | Simple. | Deprioritized — use Copilot or Azure via `--llm-provider`. |

Sources of truth:
[`CopilotLlmClient.cs`](../src/Drederick/Jeopardy/Llm/CopilotLlmClient.cs),
[`AzureOpenAiLlmClient.cs`](../src/Drederick/Jeopardy/Llm/AzureOpenAiLlmClient.cs),
[`LlamaCppLlmClient.cs`](../src/Drederick/Jeopardy/Llm/LlamaCppLlmClient.cs),
[`MicrosoftAgentRunner.cs`](../src/Drederick/Agent/MicrosoftAgentRunner.cs),
[`CopilotSdkAgentRunner.cs`](../src/Drederick/Agent/CopilotSdkAgentRunner.cs),
[`AzureOpenAiChatClient.cs`](../src/Drederick/Agent/AzureOpenAiChatClient.cs).

<a id="modes"></a>
## Which mode uses which provider

Drederick's LLM entrypoints all support **Copilot, Azure OpenAI, and
OpenAI** via `--llm-provider`. llama.cpp is supported for `ctf-solve`
but not for `--agent` (most local models lack function-calling).

| Mode | Flag / subcommand | Providers | How to pick |
| ---- | ----------------- | --------- | ----------- |
| Jeopardy solver swarm (CLI) | `drederick ctf-solve` | **Copilot / Azure / llama.cpp** — operator-selectable per run via `LlmProviderFactory`. | Pass `--llm-provider=copilot\|azure\|llamacpp` (default `copilot`) and export the matching env vars (or pass the CLI flags listed below). |
| Jeopardy solver swarm (Web UI) | `Drederick.Web` session-start form | **Copilot / Azure / llama.cpp** — operator-selectable per session. | Pick `copilot`, `azure`, or `llamacpp` in the form; export the matching env vars on the host running `Drederick.Web` ([details](#web-ui-provider)). |
| Recon cornerman | `drederick ... --agent` | **Copilot / Azure / OpenAI**. Copilot uses the official `GitHub.Copilot.SDK`; Azure/OpenAI use Microsoft Agent Framework with structured tool calls. | Pass `--llm-provider=copilot\|azure\|openai` (default `copilot`) and export the matching env vars. |
| Recon cornerman — hybrid | `drederick ... --agent=hybrid` | **Copilot / Azure / OpenAI** with automatic fallback to `AdaptiveRunner` on operational failure. | Same as `--agent`; if auth / network / rate-limit fails, the deterministic runner takes over. Scope rejections and Copilot model-compliance refusals still propagate. |
| Autopilot exploitation | `--autopilot` | Deterministic — **no LLM**. | No env vars needed. Driven by CLI flags. |

> If provider auth is missing, `--agent` can fall back to deterministic
> execution with a clear setup hint. If an explicit Copilot model is
> unavailable or not tool/function-call compliant, the run fails clearly
> even under `--agent=hybrid`; Drederick will not hide a non-compliant model
> behind deterministic fallback. `ctf-solve` aborts at preflight with
> provider-specific hints rather than solving blind.

<a id="ctf-solve-cli-recipes"></a>
### `ctf-solve` CLI recipes

All three providers are wired through
[`LlmProviderFactory`](../src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs).
Default is Copilot — omit `--llm-provider` to use it.

```bash
# Copilot (default)
drederick ctf-solve --ctfd https://ctf.example/ --token $CTF_TOKEN

# Azure OpenAI (api-key auth)
export AZURE_OPENAI_API_KEY=...
drederick ctf-solve --ctfd https://ctf.example/ --token $CTF_TOKEN \
  --llm-provider=azure \
  --azure-endpoint=https://foo.openai.azure.com \
  --azure-deployment=gpt-5.4=gpt5-prod \
  --azure-deployment=claude-sonnet-4.6=sonnet-prod

# Azure OpenAI (Entra bearer token pre-fetched via az cli)
export AZURE_OPENAI_BEARER_TOKEN=$(az account get-access-token \
  --resource https://cognitiveservices.azure.com --query accessToken -o tsv)
drederick ctf-solve ... --llm-provider=azure --azure-endpoint=https://foo.openai.azure.com

# llama.cpp (local llama-server)
drederick ctf-solve --ctfd https://ctf.example/ --token $CTF_TOKEN \
  --llm-provider=llamacpp \
  --llamacpp-url=http://127.0.0.1:8080 \
  --llamacpp-model=qwen2.5-coder \
  --llamacpp-model=llama3.1-70b=local-llama
```

The `doctor --category=jeopardy` subcommand accepts the same provider
flags and runs provider-aware reachability checks (Azure `/openai/models`
probe, llama.cpp `/v1/models` probe with a 2s timeout).

<a id="agent-cli-recipes"></a>
### `--agent` recon CLI recipes

The `--agent` recon runner now uses the same `--llm-provider` flag.
Default is Copilot — omit `--llm-provider` to use it.

```bash
# Copilot (default) — reuses `gh auth login`; if not logged in,
# Drederick starts `gh auth login --web --skip-ssh-key` for you.
drederick --scope scope.yaml --target 10.10.10.5 --out out/ --agent

# Azure OpenAI
export AZURE_OPENAI_API_KEY=...
drederick --scope scope.yaml --target 10.10.10.5 --out out/ \
  --agent \
  --llm-provider=azure \
  --azure-endpoint=https://foo.openai.azure.com \
  --azure-deployment=gpt-4o=my-gpt4-deployment

# Raw OpenAI (legacy)
export OPENAI_API_KEY=sk-...
drederick --scope scope.yaml --target 10.10.10.5 --out out/ \
  --agent --llm-provider=openai

# Hybrid with Copilot — LLM first, deterministic fallback
drederick --scope scope.yaml --target 10.10.10.5 --out out/ --agent=hybrid
```

> **Note:** llama.cpp is not supported for `--agent` because most local
> models lack reliable function-calling — the factory returns `null` and
> the runner falls back to `AdaptiveRunner`.

<a id="provider-copilot"></a>
## Copilot SDK / API (preferred Copilot path)

One token, five model families. This is the default for `--agent` and
`drederick ctf-solve`, and the standard corner for this shop.

### Quickstart

```bash
gh auth login --web                       # preferred local setup
# or, for automation:
export COPILOT_TOKEN="ghu_..."
export GH_TOKEN="$(gh auth token)"
export GITHUB_TOKEN="ghp_..."             # PAT fallback (uses GitHub Models endpoint)

drederick ctf-solve \
  --scope scope.yaml \
  --ctfd https://ctf.example.com \
  --ctfd-token "$CTFD_TOKEN" \
  --models gpt-5.4,claude-opus-4.7,gemini-3.1-pro \
  --report-dir out/ctf-report/
```

### Env vars

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `COPILOT_TOKEN` | *(none)* | Highest-precedence Copilot OAuth token. |
| `GH_TOKEN` | *(none)* | Second choice — what `gh auth token` emits. |
| `GITHUB_TOKEN` | *(none)* | Last choice. If it looks like a classic/fine-grained PAT and no Copilot token is present, the client **falls back to the GitHub Models endpoint** (`https://models.inference.ai.azure.com/v1`) instead of Copilot's endpoint. |
| authenticated `gh` CLI | *(none)* | Used after env vars. Run `gh auth login --web`; Drederick will also launch that flow on demand in an interactive terminal. |
| `DREDERICK_MODEL` | `claude-sonnet-4.6` for `--agent` | Optional Copilot SDK runner override. The selected model must appear in `GET https://api.githubcopilot.com/models` and advertise tool/function-call support. |
| `COPILOT_INTEGRATION_ID` | `drederick-cli` | Required `Copilot-Integration-Id` header. |
| `COPILOT_ENDPOINT` | `https://api.githubcopilot.com` | Base URL override for the Jeopardy/raw Copilot API client (rarely needed). |

### Picking models

For `--agent --llm-provider=copilot`, the SDK runner discovers Copilot
model metadata from `https://api.githubcopilot.com/models` (no `/v1`)
and only runs a selected model when it is both available to the token
and compliant with Drederick's tool/function-call loop. The preferred
default is `claude-sonnet-4.6`; override it only when needed:

```bash
export DREDERICK_MODEL=claude-sonnet-4.6
```

If an explicit `DREDERICK_MODEL` is unavailable or non-compliant, both
pure `--agent` and `--agent=hybrid` fail clearly. Drederick treats a
non-tool Copilot model as operator-visible configuration, not an outage
to hide behind deterministic fallback.

### Native CLI sidecar (required next to the binary)

`GitHub.Copilot.SDK` ships a native Copilot CLI as a sidecar. The SDK
expects to find it at `<install-dir>/runtimes/<rid>/native/copilot`
(e.g. `~/.local/bin/runtimes/linux-x64/native/copilot`). If the
sidecar is missing, the SDK throws before the first model call and
`audit.jsonl` records `runner.agent_error: Copilot CLI not found at
'.../runtimes/<rid>/native/copilot'`.

`make install`, `scripts/install.sh`, and the GitHub Releases tarball
all ship the sidecar tree alongside the binary with the executable bit
preserved. If you packaged a build before this fix, reinstall:

```bash
cd /path/to/drederick && make install
# or
curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash

ls "$(dirname "$(command -v drederick)")/runtimes/linux-x64/native/copilot"
```

For `ctf-solve`, the default swarm roster is
`claude-opus-4.7, gpt-5.4, gemini-3.1-pro`. Override with `--models`:

```bash
--models gpt-5.4,claude-opus-4.7,claude-sonnet-4.6,gemini-3.1-pro,grok-code-fast-1
```

Rotate the roster per category. Model names follow the Copilot catalog;
see [`CopilotPrices.cs`](../src/Drederick/Jeopardy/Llm/CopilotPrices.cs)
for what's currently priced in.

<a id="provider-azure"></a>
## Azure OpenAI (preferred for enterprise)

Own your deployments, own your audit trail. Azure is first-class in
this shop; use it when tenant isolation, data residency, or Entra ID
are part of the policy.

> **Resource creation.** Reference the Azure docs — we don't
> reproduce the portal UX here:
> <https://learn.microsoft.com/azure/ai-services/openai/how-to/create-resource>.
> Create the resource, pick a region, then **deploy each model you want
> to call** under a deployment name of your choosing. Drederick talks
> to deployments, not model IDs directly.

### Quickstart — api-key auth

```bash
export AZURE_OPENAI_ENDPOINT="https://my-resource.openai.azure.com"
export AZURE_OPENAI_API_KEY="<from Azure portal → Keys and Endpoint>"
export AZURE_OPENAI_API_VERSION="2024-10-21"   # optional, this is the default
# Map the logical model ids you pass in --models to your deployment names:
export AZURE_OPENAI_DEPLOYMENT_MAP="gpt-5.4=gpt5-prod,gpt-4o=gpt4o-prod"
```

### Quickstart — Entra ID (bearer token)

For keyless auth, pre-fetch an access token scoped to Cognitive
Services and export it. Drederick does **not** shell out to `az`;
the operator owns the refresh cycle.

```bash
export AZURE_OPENAI_ENDPOINT="https://my-resource.openai.azure.com"
export AZURE_OPENAI_BEARER_TOKEN="$(az account get-access-token \
  --resource https://cognitiveservices.azure.com \
  --query accessToken -o tsv)"
export AZURE_OPENAI_DEPLOYMENT_MAP="gpt-5.4=gpt5-prod"
```

Tokens typically expire after ~1 hour. Refresh in a wrapper script if
your runs are longer.

### Env vars

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `AZURE_OPENAI_ENDPOINT` | yes | Resource URL, e.g. `https://my-resource.openai.azure.com`. |
| `AZURE_OPENAI_API_KEY` | one of key/bearer | Portal api-key auth (preferred when set). |
| `AZURE_OPENAI_BEARER_TOKEN` | one of key/bearer | Pre-fetched Entra ID access token. |
| `AZURE_OPENAI_API_VERSION` | no | Default `2024-10-21`. |
| `AZURE_OPENAI_DEPLOYMENT_MAP` | effectively yes | `modelId=deploymentName,modelId2=deploymentName2`. Without it, calls route to the literal model id, which almost never matches a deployment name. |

Source: [`AzureOpenAiLlmClient.cs`](../src/Drederick/Jeopardy/Llm/AzureOpenAiLlmClient.cs).

For `--agent --llm-provider=azure`, the operator-managed deployment must
support structured tool/function calls. Drederick can validate its own
tool schema, but Azure model/deployment compliance is your resource
configuration; a non-tool-calling deployment should fail clearly (or
fall back only under `--agent=hybrid`).

### Example

```bash
drederick ctf-solve \
  --scope scope.yaml \
  --ctfd https://ctf.example.com \
  --ctfd-token "$CTFD_TOKEN" \
  --models gpt-5.4 \
  --report-dir out/ctf-report/
# With AZURE_OPENAI_* exported, the Azure client takes priority once
# the Azure-backed swarm wiring lands (tracked in JEOPARDY.md).
```

<a id="provider-llamacpp"></a>
## llama.cpp (escape hatch / offline)

The cornerman who doesn't leave the gym. Use this when the laptop is
off the wire, the event rules forbid third-party APIs, or you're on a
plane with a GGUF and a grudge.

### Running `llama-server`

```bash
# Build or install llama.cpp from https://github.com/ggml-org/llama.cpp,
# then serve a GGUF over OpenAI-compatible HTTP:
llama-server \
  -m ~/models/qwen2.5-coder-14b-instruct-q4_k_m.gguf \
  --port 8080 \
  -c 8192 \
  --jinja              # enable Jinja chat templates → native tool calls
```

- `--jinja` turns on the model's chat template for tool-calling. Without
  it, most tool-capable models will still generate syntactically valid
  JSON but won't hit the server's function-call path.
- `-c 8192` sets the KV cache window. Bigger = more history, more VRAM.
- Pick a model that *advertises* tool calling (Qwen2.5-Coder, Llama-3.x
  instruct, Hermes-3, etc.). **Most local models lack function
  calling**; for those, Drederick's llama.cpp client detects the
  limitation and **strips the `tools` field from requests** so the
  model can still respond, but you'll lose the tool-driven loop.

### Env vars

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `LLAMACPP_URL` | `http://127.0.0.1:8080` | Base URL of your `llama-server` (or compatible). |
| `LLAMACPP_BEARER_TOKEN` | *(none)* | Optional static bearer if you front the server with a reverse proxy that requires auth. |
| `LLAMACPP_MODELS` | *(none)* | Optional comma-separated model IDs to advertise without hitting `/v1/models`. If absent, the client discovers the loaded model at first use. Handy when the server is cold-started or you want to pin a name. |

Source: [`LlamaCppLlmClient.cs`](../src/Drederick/Jeopardy/Llm/LlamaCppLlmClient.cs).

### VRAM / memory guidance

Rough rule of thumb for GGUF Q4_K_M quant on CUDA:

| Model size | VRAM you want | CPU-only fallback |
| ---------- | ------------- | ----------------- |
| 7–8B | 6–8 GB | ~8 GB RAM, slow |
| 13–14B | 10–12 GB | ~16 GB RAM, slower |
| 30–34B | 20–24 GB | painful |
| 70B | 40+ GB or multi-GPU | don't |

Context windows (`-c`) are additive on top of the weights — add
0.5–1 GB per 4k tokens depending on the model. If you OOM, shrink `-c`
before shrinking the quant.

<a id="provider-agent-recon"></a>
## `--agent` (recon) — multi-provider

The recon-side LLM runner now supports **Copilot SDK, Azure OpenAI, and raw
OpenAI** via the `--llm-provider` flag. Copilot uses the official
[`GitHub.Copilot.SDK`](../src/Drederick/Agent/CopilotSdkAgentRunner.cs)
session runtime with Drederick's own scoped tools registered as
`AIFunction`s. Azure and raw OpenAI use
[`MicrosoftAgentRunner.cs`](../src/Drederick/Agent/MicrosoftAgentRunner.cs)
with provider-specific `IChatClient` adapters.

Model compliance is load-bearing here: Copilot chooses only
`/models` entries that are available and tool/function-call compliant
(preferred default `claude-sonnet-4.6`, override with `DREDERICK_MODEL`).
Azure/OpenAI deployments are operator-managed and must support tool
calling.

### Quickstart

```bash
# Copilot (default — no --llm-provider needed)
gh auth login --web
drederick --scope scope.yaml --target 10.10.10.5 --agent --out out/

# Azure OpenAI
export AZURE_OPENAI_API_KEY="..."
drederick --scope scope.yaml --target 10.10.10.5 --agent \
  --llm-provider=azure --azure-endpoint=https://foo.openai.azure.com --out out/

# Raw OpenAI (legacy)
export OPENAI_API_KEY="sk-proj-..."
drederick --scope scope.yaml --target 10.10.10.5 --agent \
  --llm-provider=openai --out out/
```

<a id="provider-agent-hybrid"></a>
## `--agent=hybrid` (recon) — LLM first, deterministic fallback

`HybridAgentRunner` ([source](../src/Drederick/Agent/HybridAgentRunner.cs))
wraps the selected LLM runner (Copilot SDK for Copilot,
`MicrosoftAgentRunner` for Azure/OpenAI) over `AdaptiveRunner`. It tries
the LLM planner first and falls back to the deterministic runner on
operational failures such as missing auth, network error, rate limit,
timeout, or transient SDK exception. Copilot model-compliance refusals
are not swallowed; they propagate so the operator fixes
`DREDERICK_MODEL` instead of unknowingly running without a compliant LLM.
This is the natural pairing for Jeopardy-style workloads where you want
the model when it's available but you do not want the run to abort on
transient provider outages. Supports the same `--llm-provider` flag as
`--agent`.

```bash
# LLM when auth is present, deterministic runner when it isn't.
drederick --scope scope.yaml --target 10.10.10.5 --agent=hybrid --out out/
```

Invariants the hybrid wrapper preserves:

- `ScopeException` is never swallowed. A scope rejection is an
  authorization signal — it propagates, the operator sees it, and the
  deterministic runner is **not** retried against the rejected target.
- `OperationCanceledException` propagates unchanged — Ctrl-C stays
  responsive and the deterministic runner is not re-invoked after a
  user-requested cancel.
- Copilot model-compliance refusals propagate unchanged — selected
  non-tool models are configuration errors, not transient outages.
- Every fallback emits a `hybrid.llm_fallback` audit event with the
  exception **type** and a **SHA-256 digest** of the message. The full
  message is deliberately never logged because LLM/SDK errors can echo
  back prompt fragments, URLs, or token IDs.

Related CLI variants:

| Flag | Runner selected |
| ---- | --------------- |
| *(none)* | `AdaptiveRunner` — deterministic, no LLM. |
| `--agent` / `--agent=llm` | Selected LLM runner — `CopilotSdkAgentRunner` for Copilot, `MicrosoftAgentRunner` for Azure/OpenAI; aborts the run if provider/model compliance or the SDK call fails. |
| `--agent=hybrid` | `HybridAgentRunner` — LLM first, `AdaptiveRunner` fallback on operational failure. |
| `--agent=adaptive` | Force `AdaptiveRunner`, even if `UseAgent` is set elsewhere. |

<a id="web-ui-provider"></a>
## Web UI provider selection

When you start a Jeopardy session from `Drederick.Web`, the session form
carries an `llm_provider` field with three values — `copilot`, `azure`,
or `llamacpp` (aliases `llama-cpp` / `llama.cpp` accepted). This is the
per-session backend switch. The CLI uses the same provider choice through
`--llm-provider`.

The web host reads env vars from its own process environment — whatever
shell launched `dotnet run --project src/Drederick.Web` or the published
binary. Export the matching set **before** starting the server:

```bash
# Copilot — default choice
gh auth login --web

# Azure OpenAI
export AZURE_OPENAI_ENDPOINT="https://my-resource.openai.azure.com"
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_DEPLOYMENT_MAP="gpt-5.4=gpt5-prod"

# llama.cpp
export LLAMACPP_URL="http://127.0.0.1:8080"

# now launch the web pane
dotnet run --project src/Drederick.Web
```

Selection logic lives in
[`JeopardySessionManager.cs`](../src/Drederick.Web/Jeopardy/JeopardySessionManager.cs) —
the chosen provider's `TryCreateFromEnvironment` is called at session
start. If it returns `null`, the session fails with:

```
no LLM client could be created from environment (run `gh auth login --web` or set COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN
for copilot, or the provider-specific env vars for azure / llamacpp).
```

> **Tatum note:** one shop, three corners. Pick the corner *before* the
> bell — once the session starts, the swarm is committed to that
> provider for its lifetime.

<a id="precedence"></a>
## Token precedence and auto-selection

Inside the Jeopardy stack, each provider client is constructed from
env via `TryCreateFromEnvironment`. The first one that satisfies its
required vars is the one that wins. `ctf-solve` now picks the backend
via [`LlmProviderFactory`](../src/Drederick/Jeopardy/Llm/LlmProviderFactory.cs)
keyed off `--llm-provider` (default Copilot); Azure and llama.cpp
clients live alongside
([`AzureOpenAiLlmClient.cs`](../src/Drederick/Jeopardy/Llm/AzureOpenAiLlmClient.cs),
[`LlamaCppLlmClient.cs`](../src/Drederick/Jeopardy/Llm/LlamaCppLlmClient.cs)).

Inside `CopilotLlmClient.TryCreateFromEnvironment`:

1. `COPILOT_TOKEN` → use it against `COPILOT_ENDPOINT`.
2. else `GH_TOKEN` → same.
3. else `GITHUB_TOKEN` → if it *looks like* a PAT (`ghp_…` / `github_pat_…`),
   fall back to the **GitHub Models** endpoint
   (`https://models.inference.ai.azure.com/v1`) instead of the Copilot
   endpoint. This lets a developer with only a PAT still reach the
   model catalog.
4. else `gh auth token` → reuse the locally authenticated GitHub CLI
   session; no shell export required.
5. none + interactive terminal → start `gh auth login --web --skip-ssh-key`
   and then retry `gh auth token`.
6. none + non-interactive terminal → return `null`, preflight fails with a
   clear "no Copilot token found" message.

Tokens are **never logged in plaintext**. The audit log records a
`SHA-256` digest (see [`TokenRedactor.cs`](../src/Drederick/Jeopardy/Llm/TokenRedactor.cs)).

<a id="doctor"></a>
## `drederick doctor` — LLM checks

`drederick doctor` is the single-command preflight. For LLM wiring it
runs two checks under the `jeopardy` category:

| Check id | What it verifies |
| -------- | ---------------- |
| `jeopardy.llm.token` | Provider-aware: Copilot looks for `COPILOT_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN` / authenticated `gh` CLI; Azure verifies endpoint + one of api-key / bearer / Entra + a deployment; llama.cpp verifies the base URL parses. |
| `jeopardy.llm.reachable` | Copilot: `GET https://api.githubcopilot.com/models` (gated by scope unless `--allow-copilot-host`). Azure: `GET $endpoint/openai/models?api-version=…`. llama.cpp: `GET $url/v1/models` with a 2 s timeout (loopback allowed without scope). |

Sample output when Copilot is wired correctly:

```text
$ drederick doctor
[jeopardy.llm.token]     PASS  LLM token present via $COPILOT_TOKEN
[jeopardy.llm.reachable] PASS  GET https://api.githubcopilot.com/models → 200
...
```

And when it's not:

```text
[jeopardy.llm.token]     FAIL  no COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN in environment and no authenticated gh CLI session
                               fix: gh auth login --web   # or export COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN
[jeopardy.llm.reachable] WARN  skipped — no LLM token set (see jeopardy.llm.token)
```

> **Provider selection:** pass `--llm-provider=azure` or
> `--llm-provider=llamacpp` to `drederick doctor` (alongside
> `--category=jeopardy`) to run the checks against those backends. The
> doctor uses the same flags and env vars as `ctf-solve`, so a green
> `jeopardy.llm.*` means "the selected provider is ready."

Source: [`JeopardyDoctorChecks.cs`](../src/Drederick/Doctor/JeopardyDoctorChecks.cs).

<a id="cost"></a>
## Cost, rate limits, budgets

Guardrails that already exist regardless of provider:

- `CostTracker` — per-run USD cap (`--run-budget-usd`) and per-challenge
  cap (`--challenge-budget-usd`). See [JEOPARDY.md](JEOPARDY.md#budget).
- `ToolBudget` — per-tool and global call caps on the recon side. See
  [`ARCHITECTURE.md`](ARCHITECTURE.md).
- One-shot `--agent` runner on recon — no multi-turn doom loop.
- Scope layer — the model cannot widen its target list mid-run.

What to watch for:

- **429 rate limits** surface as `runner.agent_error` (recon) or per-solver
  errors (jeopardy). In recon the runner falls back to Adaptive; in
  jeopardy the losing solver is torn down and the swarm continues.
- **Azure throughput units** — if you hit TPM/RPM on a deployment, raise
  the quota or spread across deployments by editing the deployment map.
- **Copilot entitlement caps** — your Copilot plan's limit is yours;
  Drederick does not negotiate them.

<a id="prompt-hygiene"></a>
## Prompt hygiene and what the model sees

- **Scope file contents** → not sent. Only the specific target IPs /
  hostnames you pass on the CLI.
- **API keys / tokens** → never sent. They travel only to their own
  provider endpoint over TLS.
- **Credential plaintext** → never sent. Autopilot and solvers pass
  SHA-256 digests, not passwords.
- **Raw tool output** → summarized / truncated by the tool layer before
  being returned to the model. Nmap XML, HTTP bodies, etc. are bounded
  to ≤64 KB with full-size + SHA-256 recorded alongside.

Recon system prompt: [`MicrosoftAgentRunner.BuildSystemPrompt()`](../src/Drederick/Agent/MicrosoftAgentRunner.cs).
User message assembly (per-target prior digests from `KnowledgeBase`):
[`MicrosoftAgentRunner.BuildUserMessage()`](../src/Drederick/Agent/MicrosoftAgentRunner.cs).
Jeopardy per-category fragments: [`PromptLibrary.cs`](../src/Drederick/Jeopardy/Prompts/PromptLibrary.cs).

> **Forcing function (GAP-025).** `BuildSystemPrompt` now flags
> recon-only outcomes as **losses**. The system prompt explicitly
> demands that, before producing a final summary, the agent must
> either (1) call `exploit_plan` and act on every action whose
> required permission flag is set, (2) call `execute_cred_spray`
> for at least one auth-bearing service it observed, (3) drive
> `run_post_ex_*` + `extract_flags_from_dir` on any session it
> opened, or (4) explicitly name the missing permission flag in
> the summary — the only acceptable "recon-only" exit. Native
> HTTP/TLS probe hits are now treated as proof a port is open
> even when nmap returns `[]` (the JobTwo r4 lesson; see
> [`POST_EXPLOITATION.md`](POST_EXPLOITATION.md)). Operators
> overriding the prompt should preserve this contract.

<a id="safety"></a>
## Safety — what the LLM cannot do

Enforced in code. The runner has no special privileges.

| The LLM cannot… | Because… |
| --------------- | -------- |
| Scan or exploit a target outside `--scope` | Every tool's first statement is `_scope.Require(target)` — the tool layer refuses regardless of caller. |
| Widen the scope file | Scope is read-only from code. There is no write path. |
| Disable the audit log | `AuditLog` has no disable API. No env var, no flag, no prompt turns it off. |
| Exfiltrate loot | The only outbound calls are to the configured LLM provider (chat completion) and, for Jeopardy, the CTFd host. No reporting or memory layer makes network calls. |
| Bypass per-run opt-ins | `--allow-exec-pocs`, `--allow-cred-attacks`, `--allow-payloads`, `--acknowledge-lockout-risk` are checked by the exploit/autopilot layers, not the agent runner. The model has no handle on them. |
| Invent a target | The tool layer rejects any target string not resolved through scope. |

If a future model jailbreak tells the agent "ignore scope" or "assume
authorization", the tool call still fails. That's the design.

<a id="troubleshooting"></a>
## Troubleshooting

> *"Dear God, why are we fighting? …Because the token expired. Refresh
> it, step back into the ring, and let's go again."*
> — **Drederick Tatum**, between rounds

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `no Copilot token found (set COPILOT_TOKEN, GH_TOKEN, or GITHUB_TOKEN)` | No env token and no authenticated `gh` CLI session. | Run `gh auth login --web` or export one; `COPILOT_TOKEN` wins precedence. |
| `no LLM client could be created from environment …` from the Web UI | Selected `azure` or `llamacpp` in the session form but the matching env vars aren't set in the web-host process. | Stop `Drederick.Web`, export the provider's env vars ([Web UI section](#web-ui-provider)), relaunch. Env vars are read at session start, not at request time. |
| `401` from Copilot | Token expired / revoked / wrong scope. | `gh auth refresh` or regenerate; re-export. |
| `Azure OpenAI auth failed (401)` | `AZURE_OPENAI_API_KEY` wrong, or Entra bearer expired, or endpoint tenant mismatch. | Re-fetch the token (`az account get-access-token …`) or rotate the api-key; confirm the endpoint matches the subscription. |
| Azure `DeploymentNotFound` | `AZURE_OPENAI_DEPLOYMENT_MAP` missing an entry for one of `--models`. | Add `modelId=deploymentName` to the map. Logical model ids in `--models` must resolve to a real deployment. |
| `LLAMACPP_URL` connection refused | `llama-server` not running, or wrong port. | `curl "$LLAMACPP_URL/v1/models"` to confirm; restart server with `--port 8080 --jinja`. |
| llama.cpp runs but is painfully slow | Too-large quant, tiny `-c`, no GPU offload. | Drop to Q4_K_M, set `--n-gpu-layers -1` if you have VRAM, or lower `--solver-concurrency` on the swarm so one model isn't racing itself. |
| llama.cpp model refuses tool calls / ignores `tools` field | Model doesn't support function calling; the client auto-strips tools for those. | Use a tool-calling model (Qwen2.5-Coder, Llama-3.x instruct, Hermes-3), or accept freeform reasoning without tool loops. |
| `--agent requested but LLM provider 'copilot' is not configured. Falling back to AdaptiveRunner.` on stderr | No usable token from env or authenticated `gh` CLI. | Run `gh auth login --web`, or export `COPILOT_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN`. |
| `runner.agent_error` with `429 rate_limit_exceeded` | Provider quota. | Drederick already fell back to Adaptive; raise the quota or wait. |
| LLM calls the same tool on the same target repeatedly | Normal up to `ToolBudget`; the tool layer then refuses. | Raise budget in `ReconToolbox` wiring if legitimate; usually it's the model being inefficient. |
| `ScopeException` from an agent-invoked tool | Model chose a target not resolvable in the scope. | Expected — the tool refuses cleanly. Check `audit.jsonl` for the attempted target. |

See also [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for non-LLM issues
and [`JEOPARDY.md#troubleshooting`](JEOPARDY.md#troubleshooting) for
solver-specific symptoms.

---

> *"You call that a scan? I've seen tighter enumeration from a rookie's
> jab. Let the cornerman call the combinations — and pick the fighter
> that fits the round. I'm heavyweight champ, Drederick Tatum."*
> — **Drederick Tatum**, post-sparring debrief
