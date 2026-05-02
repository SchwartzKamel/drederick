# Fight Brief: JobTwo Rematch — 2026-05-01

## Summary

| Field              | Value                                      |
|--------------------|--------------------------------------------|
| **Box**            | JobTwo (Hard, Windows Server 2022)          |
| **Target**         | 10.129.238.35                               |
| **Mode**           | `--agent=hybrid --llm-provider=copilot`     |
| **Model**          | claude-sonnet-4.6 (via direct Copilot HTTP) |
| **Result**         | ⏸️ DRAW (tools fired, nmap timeout)         |
| **Duration**       | ~44 min (stalled on nmap exploit scripts)   |

## What Happened

### Bugs Fixed (3 critical)

1. **Copilot SDK 0.3.0 SendAndWaitAsync hang (GAP-021)** — Bypassed entirely.
   Replaced CopilotSdkAgentRunner with direct HTTP to `api.githubcopilot.com/chat/completions`
   via AzureOpenAiChatClient in copilotMode. Auth via `gh auth token`.

2. **Copilot API multi-choice response parsing (GAP-020)** — THE breakthrough.
   ParseResponse only read `choices[0]` (text content). Copilot API returns
   tool calls in separate choices (1, 2, 3...). Fixed to iterate ALL choices
   and merge into single ChatMessage.

3. **Missing e_sqlite3 native library** — Reporting crashed with
   DllNotFoundException. Copied from NuGet cache to `~/.local/bin/`.

### What Worked

- **LLM engagement**: Sonnet 4.6 responded in 7.5s with 699 tokens, correctly
  identified all 15 prior-scanned ports, and requested 8+ parallel tool calls
  (nmap_scan, http_probe ×2, tls_probe ×2, dns_probe, smb_probe, etc.)
- **Tool execution**: nmap_scan fired with full script suite including vuln/exploit
- **Copilot direct HTTP path**: Auth OK, model selection OK, tool schema serialization OK

### What Failed

- **Nmap exploit scripts timeout (GAP-022)**: LLM chose `--script exploit` which
  runs 30-60+ min on Windows. Blocked all other tool calls for 44+ minutes.
- **Sequential tool execution (GAP-023)**: FunctionInvokingChatClient runs tools
  one-at-a-time. LLM's parallel probe strategy was serialized into sequential.

## Key Code Changes

| File | Change |
|------|--------|
| `src/Drederick/Agent/MicrosoftAgentRunner.cs` | Copilot provider → direct HTTP via AzureOpenAiChatClient(copilotMode) |
| `src/Drederick/Agent/AzureOpenAiChatClient.cs` | Added copilotMode flag (URL, model-in-body, Integration-Id header) |
| `src/Drederick/Agent/AzureOpenAiChatClient.cs` | ParseResponse: iterate ALL choices, merge tool calls |

## Gaps Exposed

- **GAP-020** (critical, resolved): Multi-choice response parsing
- **GAP-021** (critical, resolved): SDK SendAndWaitAsync hang bypass
- **GAP-022** (high, open): Nmap exploit category timeout
- **GAP-023** (medium, open): Sequential tool execution bottleneck

## Lessons for Training Arc

1. **Never trust choices[0] alone** — Copilot API uses multi-choice for tool calls
2. **Cap nmap script categories** — block `exploit`, limit `intrusive` to 5-10min
3. **Enable concurrent tool invocation** — network-bound probes are embarrassingly parallel
4. **The SDK is a dead end** — direct HTTP is simpler, debuggable, and actually works
5. **Sonnet 4.6 is a great fight planner** — correct tool selection, parallel strategy, 7.5s response
