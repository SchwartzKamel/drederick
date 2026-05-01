---
title: Model behavior fight notes
audience: [humans, agents]
primary: agents
stability: stable
last_audited: 2026-04
related:
  - README.md
  - LLM_SETUP.md
  - JEOPARDY.md
  - POST_EXPLOITATION.md
  - SCOPE_AND_LEGAL.md
  - ../AGENTS.md
  - ../.github/copilot-instructions.md
  - ../.github/fight-history/INDEX.md
  - ../.github/fight-history/lame-model-benchmark-2026-04-30.md
---

# Model behavior fight notes

> These are Drederick's ringside notes for model behavior on authorized
> offensive-security work. Treat models like fighters: measure what they
> actually do in the ring, route them by price-to-performance, and never
> confuse a cooperative answer with the security boundary.

This guide is for coding agents changing LLM/provider code and for
operators collecting fight data. It intentionally uses sanitized,
aggregate evidence only. Do not add HTB flags, plaintext credentials,
private tokens, SSH keys, or target secrets to this document or any
fight-history note.

- [Purpose and ringside card](#purpose)
- [What model compliance proves](#compliance)
- [Fight lesson: Lame](#lame-lesson)
- [Model routing card](#routing-card)
- [Multi-model playbook](#multi-model-playbook)
- [Coding-agent checklist](#coding-agent-checklist)
- [Data collection fields](#data-collection)
- [Safe reporting rules](#safe-reporting)

<a id="purpose"></a>
## Purpose and ringside card

Drederick is a scope-enforced full-auto offensive harness for authorized
targets. LLMs are cornermen: they choose probes, synthesize arguments,
compare fingerprints, and explain the next punch. They are not the
security boundary.

The boundary is still:

| Guardrail | Required behavior |
| --------- | ----------------- |
| Scope | Every network-touching tool re-checks `_scope.Require(target)` on entry. |
| Subprocess argv | Every host/IP/URL that can cause network reachability is validated before exec. |
| Audit | Exploit, credential, payload, session, and PoC actions append audit records with digests. |
| Secrets | Plaintext passwords, flags, tokens, SSH keys, and loot values are not logged. |
| Exfiltration | Loot stays local under `out/` and `audit.jsonl`; no harness telemetry or cloud sync. |

Model strategy should maximize impact inside scope while preserving those
invariants. Use cheap deterministic punches for known fingerprints and
spend premium model budget only where reasoning or argument synthesis
changes the fight.

<a id="compliance"></a>
## What model compliance proves

Compliance checks are admission control, not a prediction that a model
will be willing or competent on offensive tasks.

| Surface | Durable behavior |
| ------- | ---------------- |
| Core `--agent` providers | Copilot SDK, Azure OpenAI, and legacy OpenAI are the supported provider surface. llama.cpp is not used for core `--agent` because tool/function calling is unreliable for local models. |
| Copilot SDK model selection | The Copilot SDK runner checks `/models`, audits model decisions, and defaults to `claude-haiku-4.5`. `DREDERICK_MODEL` can request another model, but it must pass availability and tool/function-call compliance. |
| `CopilotModelCompliance` | Measures availability, policy metadata, and tool-call support. It does not prove offsec willingness, exploit-planning quality, or price-to-performance. |
| Non-compliant Copilot model | A Copilot model-compliance refusal propagates. `--agent=hybrid` must not hide it behind deterministic fallback. |
| Hybrid fallback | Hybrid falls back only on operational/provider failures: missing key, network failure, auth failure, rate limit, or transient SDK/provider errors. `ScopeException`, cancellation, and Copilot model-compliance failures propagate. |
| Permission approval | `PermissionHandler.ApproveAll` approves framework tool-call prompts. It is not a security boundary. Tool-level scope checks, argv validation, permission flags, budgets, and audit are the boundary. |
| LLM exploit tools | Exploit planning, credential spray, post-ex, pivot scan, flag extraction, and multi-stage chain tools re-check scope, enforce permissions/budgets, audit digests, and hash secrets. |
| Jeopardy swarm | `ctf-solve` races configured models, bounds parallelism, cancels losing solvers, watches budgets, and reports per-solver outcomes. |
| llama.cpp | Jeopardy can use llama.cpp. Tool schemas are stripped unless model config says `SupportsTools=true`; factory defaults to false. |

Read refusals as fight data. Do not weaken compliance checks, suppress
refusals, auto-route around a specifically requested non-compliant model,
or describe hybrid as a catch-all escape hatch.

<a id="lame-lesson"></a>
## Fight lesson: Lame

The Lame fight history is the cautionary tape. The sanitized record
showed Drederick fingerprinting four services, including exact versions
for vsftpd 2.3.4 and Samba 3.0.20-Debian, and persisting four services,
50 findings, and 23 CVEs. That was enough data to throw a known-path
haymaker.

Instead, autopilot circled: 26 password-spray actions, zero Metasploit
runs, zero nuclei runs, zero PoC refs/sources, zero sessions, and zero
loot. Audit summaries showed repeated nmap exit 134 crashes before a
successful pass, plus `runner.adapt` repeating "no ports on first pass;
widening" without changing tactics. `llm.exploit_tools.ready` fired, but
no LLM exploit plan followed. Apparent knockouts were false positives
from 32-character scan metadata, not shell-derived flags.

| Lesson | Coding implication |
| ------ | ------------------ |
| Version-exact RCE beats default spraying. | Add deterministic mappings for known fingerprints before spending LLM budget. The obvious Lame mappings are Samba usermap, vsftpd backdoor, and distcc exec. |
| Cheap planners should hit known paths first. | Route exact service/version matches through deterministic exploit planners and memory before premium models. |
| LLMs are for uncertainty and synthesis. | Call models when mapping confidence is low, arguments are ambiguous, credentials must be composed, or multiple exploit chains need ranking. |
| Tool descriptions affect model punches. | LLM-visible descriptions must say when a tool creates an msfrc, fetches PoCs, opens sessions, collects loot, stages payloads, or hashes secrets. |
| Crash adaptation must adapt. | Repeated scanner crashes or "no ports" loops must switch tactics, not repeat the same widening message. |
| Memory should remember misses. | Store missed exploit mappings and false-positive knockout patterns so rematches converge. |
| Expensive reasoning is not always useful. | For Lame-class known fingerprints, premium planning was unnecessary until deterministic mappings failed. |

The lesson is not "avoid LLMs." The lesson is "make the first punch
deterministic when the fingerprint is famous, then spend model tokens
where they buy a new angle."

<a id="jobtwo-lesson"></a>
## Fight lesson: JobTwo

JobTwo (hard Windows, Veeam Backup chain) is the rematch that forced
the CVE-driven planner. Drederick's recon was fine — 15 services, 95
NSE script results, hMailServer/SMB/WinRM/RDP/Veeam ports surfaced,
SSL cert revealed `job2.vl` — but autopilot threw 39 password sprays
and zero CVE actions. The known attack chain hinges on Veeam
CVE-2024-29849, which the operator had on `findings.db` already; the
planner just didn't look there.

Two things failed at once:

1. **Copilot SDK couldn't start.** The installed binary lacked the
   native `runtimes/<rid>/native/copilot` sidecar, so the SDK threw
   before the first model call. Audit logged `runner.agent_error` +
   `hybrid.llm_fallback`, but the operator-facing report didn't
   surface the fallback. Hybrid is supposed to fall back on
   operational failure — the bug was packaging + reporting, not
   policy.
2. **Deterministic planner was spray-only.** `ExploitationPlanner`
   only matched cached nuclei templates against `port.Product` token.
   It ignored NSE script CVE IDs, the `findings.kind='cve'` rows
   already enriched into `findings.db`, and the `poc_refs` table that
   `PocAggregator` had populated with Metasploit module names per CVE.

| Lesson | Coding implication |
| ------ | ------------------ |
| LLM packaging is a fight gate. | Treat the Copilot CLI sidecar as a first-class artefact. Verify `runtimes/<rid>/native/copilot` exists next to the installed binary in CI/install/release. |
| Fallback must be loud. | When hybrid falls back, the operator-facing report should say so prominently — not just `audit.jsonl`. |
| CVE evidence must drive actions, not annotate reports. | Read NSE script CVE IDs, `findings.kind='cve'`, and `poc_refs` straight into the planner. Emit `nuclei`/`msfrc` actions above sprays. |
| MSF must be reachable from autopilot. | Wire `MsfRcRunner` into `AutopilotRunner` with a constrained `msfrc` action shape (module + whitelisted options, host-bearing values re-validated). |
| Action IDs must dedupe across iterations. | Content-address actions on (tool, target, port, identifying tokens) so re-plans don't churn the same haymaker. |

JobTwo's fix shipped a 500-priority `nuclei` band and a 490-priority
`msfrc` band, both above the 300/200 spray bands. Next rematch should
land at least the Veeam CVE-2024-29849 path before any spray fires.

<a id="routing-card"></a>
## Model routing card

Use this card when changing provider selection, autopilot planning, or
operator guidance. Model names are examples from current Copilot/Azure
surfaces and fight history; always re-measure on fresh runs.

| Scenario | First route | Escalate when | Record |
| -------- | ----------- | ------------- | ------ |
| Exact known fingerprint with a stable exploit path | Deterministic mapping plus `ExploitRunner`/`MsfRcRunner`/`NucleiRunner` as applicable. | Tool args are ambiguous, exploit preconditions conflict, or the first run fails for a non-operational reason. | Mapping id, confidence, tool invoked, exit code, session/loot counts. |
| Low-cost argument synthesis | Copilot default `claude-haiku-4.5` or another cheap tool-compliant model. | The model loops, refuses, misses tools, or cannot rank chains. | Latency, tokens, cost, tool calls, refusal/loop reason. |
| Complex multi-stage chain | Strong reasoning model or operator-managed Azure deployment with tool calling. | Cost exceeds budget or deterministic evidence narrows to a known module. | Chain length, first-session time, valid-action rate, budget consumed. |
| Parallel fleet or benchmark | Cheap model mix with bounded concurrency; Jeopardy-style race where supported. | A class of targets remains unsolved after deterministic and cheap routes. | Per-model win/loss/refusal, canceled losers, aggregate and per-solver cost. |
| Offline Jeopardy solving | llama.cpp only when the configured model can solve without tools or declares `SupportsTools=true`. | Tool use is required and `SupportsTools=false`. | Model config, stripped-tool status, success/failure. |
| Explicit non-compliant Copilot model | Stop and report the model-compliance refusal. | The operator explicitly chooses a different compliant model or fixes entitlement/config. | Requested model, compliance result, refusal reason. |

Price-to-performance should be calculated from useful offensive progress,
not answer fluency. Useful metrics include seconds to first valid exploit
action, cost per valid tool call, cost per session opened, cost per
scope-valid finding, refusal rate, loop rate, and false-positive knockout
rate.

<a id="multi-model-playbook"></a>
## Multi-model playbook

1. **Enter the ring scoped.** Confirm the target is in the human-authored
   scope file. Do not let prompts, provider defaults, or benchmark logic
   create new targets.
2. **Fingerprint first.** Build the service/version card from recon,
   memory, CVEs, and PoC refs before asking a model to improvise.
3. **Throw deterministic haymakers.** Exact mappings and high-confidence
   PoCs should run before premium LLM planning.
4. **Use cheap models for glue.** Let the default Copilot model or a
   low-cost Azure deployment synthesize safe arguments, summarize
   evidence, and rank close choices.
5. **Escalate only on uncertainty.** Bring premium reasoning models in
   for multi-stage chains, conflicting evidence, exploit adaptation, or
   post-ex pivot planning.
6. **Race where cancellation is cheap.** Jeopardy swarm can launch
   multiple solvers, cancel losers, and report outcomes. Do not copy its
   per-solver cost fields blindly when they are derived from aggregate
   challenge cost.
7. **Write down the round.** Store sanitized model, provider, cost,
   latency, tool-call, refusal, and outcome data in fight history.
8. **Rematch with memory.** Missed mappings and false-positive knockout
   patterns belong in memory and gap trackers so the next run changes
   tactics.

<a id="coding-agent-checklist"></a>
## Coding-agent checklist

Before changing model/provider code, prompts, LLM-visible tool
descriptions, hybrid fallback, Jeopardy swarm behavior, or cost reports:

| Check | Requirement |
| ----- | ----------- |
| Read the tape | Read this guide, `LLM_SETUP.md`, `../.github/fight-history/INDEX.md`, and the latest model benchmark before editing. |
| Preserve provider facts | Core `--agent` is Copilot SDK / Azure / OpenAI. llama.cpp remains Jeopardy-only unless reliable tool calling is implemented and tested. |
| Preserve Copilot compliance | Keep `/models` checks, the `claude-haiku-4.5` default, compliance audit records, and hard propagation of non-compliant Copilot model refusals. |
| Preserve hybrid semantics | Fallback only for operational/provider failures; propagate scope failures, cancellation, and Copilot model-compliance refusals. |
| Preserve boundaries | Do not move security trust to model prompts or permission approval. Every tool still owns scope, permissions, argv validation, budgets, and audit. |
| Fix prompt drift | Do not frame the agent as only producing a remediation-focused summary. It may summarize, but the authorized mission includes exploit planning, sessions, loot accounting, and post-ex actions inside scope. |
| Sharpen tool descriptions | State whether each tool fetches PoCs, creates msfrc files, spawns nuclei, opens sessions, collects loot, stages payloads, hashes secrets, or consumes destructive/credential/payload permissions. |
| Keep secrets out | Reports and benchmarks may store counts, digests, hashes of attempted secrets, and redacted paths. Never store flags, plaintext credentials, private tokens, SSH keys, or target secrets. |
| Test behavior | Add or keep tests for compliance refusal propagation, operational fallback, llama.cpp tool stripping, cost accounting, and no plaintext secret logging. |

<a id="data-collection"></a>
## Data collection fields

Future fights should collect enough data to route models by evidence,
not vibes. These fields can live in fight-history markdown, JSON
artifacts, SQLite, or a benchmark table. Keep values sanitized.

| Field | Type | Notes |
| ----- | ---- | ----- |
| `fight_id` | string | Stable id; no flags or secret-derived names. |
| `target_label` | string | Public lab machine name or redacted engagement label. |
| `scope_mode` | enum | `lab`, `strict`, or engagement-specific redacted label. |
| `provider` | enum | `copilot`, `azure`, `openai`, `llamacpp`, `deterministic`. |
| `model` | string | Requested model/deployment alias; record if defaulted. |
| `runner_mode` | enum | `adaptive`, `agent`, `hybrid`, `autopilot`, `ctf-solve`. |
| `model_compliance_status` | enum | `not_checked`, `passed`, `failed`, `unavailable`, `no_tool_support`. |
| `fallback_kind` | enum | `none`, `operational`, `provider`, `deterministic`, `not_allowed`. |
| `supports_tools` | boolean | Especially important for Copilot `/models` and llama.cpp configs. |
| `latency_ms` | integer | End-to-end or per-turn; name the measurement window. |
| `input_tokens` / `output_tokens` | integer | If provider reports them. |
| `cost_usd` | decimal | Use zero/null if unknown; distinguish estimate from billable. |
| `cost_scope` | enum | `per_solver`, `per_challenge_aggregate`, `per_run`, `estimate`. |
| `tool_calls_total` | integer | Count LLM-requested tool calls. |
| `valid_tool_calls` | integer | Calls that passed scope/argv/permission validation. |
| `exploit_actions` | integer | Metasploit, PoC, nuclei, payload, credential, or post-ex actions. |
| `sessions_opened` | integer | Count only; do not store session secrets. |
| `loot_items` | integer | Count/digest only; no plaintext loot. |
| `false_positive_knockouts` | integer | Count flag/session claims disproved by audit or shell evidence. |
| `outcome` | enum | `win`, `loss`, `partial`, `refusal`, `timeout`, `operational_failure`. |
| `failure_reason` | string | Sanitized reason: refusal, loop, crash, missing mapping, auth failure, etc. |
| `deterministic_mappings_used` | list | Stable mapping ids or names, not exploit secrets. |
| `missed_mappings` | list | Sanitized mapping names to add to memory/gap trackers. |
| `audit_event_counts` | object | Aggregates by event name; no raw secret-bearing payloads. |
| `notes` | string | Sanitized operator/coding-agent lesson. |

Recommended derived metrics:

| Metric | Formula |
| ------ | ------- |
| `cost_per_valid_tool_call` | `cost_usd / max(valid_tool_calls, 1)` |
| `cost_per_session` | `cost_usd / max(sessions_opened, 1)` |
| `valid_action_rate` | `valid_tool_calls / max(tool_calls_total, 1)` |
| `refusal_rate` | `refusals / max(model_attempts, 1)` |
| `time_to_first_exploit_ms` | First exploit audit timestamp minus run start timestamp. |

<a id="safe-reporting"></a>
## Safe reporting rules

- Use aggregate counts, sanitized service versions, CVE ids, tool names,
  exit codes, durations, and SHA-256 digests.
- Do not quote `user.txt`, `root.txt`, `*_flag.txt`, `u.txt`, `r.txt`,
  shell output containing flags, captured credentials, private tokens,
  SSH keys, or target-specific secrets.
- Do not paste raw audit events if they include secret-adjacent fields.
  Summarize counts by event type instead.
- Do not call a model "safe" because it refused or "unsafe" because it
  complied. Record the exact behavior and whether Drederick's scope,
  permission, argv, and audit guards held.
- If a report includes remediation, keep it as a final operator summary;
  do not let remediation wording replace the offensive planning mission
  for authorized in-scope work.
