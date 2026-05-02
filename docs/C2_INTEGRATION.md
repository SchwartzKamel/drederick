---
title: C2 Integration Architecture
audience: [contributors, agents]
primary: contributors
stability: stable
last_audited: 2026-05
related:
  - docs/EMPIRE.md
  - docs/ARCHITECTURE.md
  - docs/SCOPE_AND_LEGAL.md
---

# C2 Integration Architecture

> **Scope.** This document describes the design, thread safety, and audit
> invariants of Drederick's C2 integration subsystem (Empire). It is for
> contributors extending the C2 layer or integrating new frameworks.

<a id="subsystem-overview"></a>
## Subsystem Overview

The C2 subsystem is decoupled from the main recon/exploit loop and sits at
the boundary between post-exploitation and full agent orchestration. It
consists of four cooperating components:

```
┌─────────────────────────────────────────────────┐
│ Autopilot / ExploitRunner / SessionManager       │
│ (calls C2 tools when agent delivery is needed)  │
└──────────────────────────┬──────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────┐
│ EmpireAgentStager (IPayloadTool)                        │
│  - Scope validation: _scope.Require(target)             │
│  - Platform detection: Windows|Linux|macOS              │
│  - Payload generation: raw stager code                  │
│  - Audit: empire.stager.generate + success/error        │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────┐
│ EmpireApiClient (HTTP wrapper)                          │
│  - POST /stager, /listeners, /agents, /modules          │
│  - JSON-RPC style request/response                      │
│  - Error handling: HTTP 4xx/5xx → descriptive error     │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────┐
│ BC-SECURITY/Empire Server (external process)            │
│  - Listener loop awaits agent callback                  │
│  - Module dispatch: C2 protocol (staging → execution)   │
│  - Agent session tracking: database.db                  │
└─────────────────────────────────────────────────────────┘
                           │
                           ↓
┌──────────────────────────────────────────────────────────┐
│ Target Agent (PowerShell, Python, Bash)                 │
│  - Executes stager: IEX, exec, bash -c                  │
│  - Callback loop: check-in → command → response         │
│  - Module execution: in-memory injection / fork         │
└──────────────────────────────────────────────────────────┘
```

## Component Contracts

### EmpireAgentStager

```csharp
public class EmpireAgentStager : IPayloadTool
{
    /// <summary>
    /// Generate a platform-specific agent stager for delivery to target.
    /// Returns raw code (PowerShell, Python, Bash) that can be executed
    /// directly on the target via RCE.
    ///
    /// Invariants:
    /// - First statement: _scope.Require(target)
    /// - Scope failure raises ScopeException; generation proceeds on pass
    /// - Output is idempotent: same target + platform → same stager code
    /// - Audit event records target, platform, stager_sha256, success/error
    /// </summary>
    public async Task<EmpireStagerResult> GenerateAsync(
        string target, EmpireAgentPlatform platform, CancellationToken ct);
}
```

**Returns:**
```csharp
public sealed class EmpireStagerResult
{
    public bool Success { get; set; }
    public string Target { get; set; }
    public EmpireAgentPlatform Platform { get; set; }
    public string? StagerCode { get; set; }  // Raw PowerShell, Python, etc.
    public string? StagerSha256 { get; set; }
    public string? ListenerUrl { get; set; }
    public string? Error { get; set; }
}
```

### EmpireModuleExecutor

```csharp
public class EmpireModuleExecutor : IExploitTool
{
    /// <summary>
    /// Execute privilege escalation modules against post-ex findings.
    /// Queries EmpireModuleLibrary for recommended modules, validates targets
    /// in scope, and invokes via EmpireApiClient.
    ///
    /// Invariants:
    /// - First statement: _scope.Require(target)
    /// - Scope failure raises ScopeException
    /// - Audit events for each module attempt (success/error/duration)
    /// </summary>
    public async Task<ExploitResult> ExecutePrivescAsync(
        string target, HostFinding findings, CancellationToken ct);

    /// <summary>
    /// Execute lateral movement modules (WMI, PSRemoting, SSH, etc.).
    /// Target must be in scope; pivot hosts are re-validated via scope.
    ///
    /// Invariants:
    /// - Scope re-check: _scope.Require(target); _scope.Require(pivotTarget)
    /// - Lateral move audit includes both source and destination
    /// </summary>
    public async Task<ExploitResult> ExecuteLateralAsync(
        string target, IReadOnlyList<string> pivotTargets, HostFinding findings, CancellationToken ct);
}
```

### SessionAgentMapper

```csharp
public class SessionAgentMapper
{
    /// <summary>
    /// Thread-safe registry mapping agent_id → (target, listener, platform, opened_at).
    /// Used to track active Empire agents across module execution phases.
    ///
    /// Thread safety: ReaderWriterLockSlim guards _agents dictionary.
    /// - Reads (GetAgentsByHost, ListActiveAgents) enter read lock
    /// - Writes (TrackAgent, CloseAgent) enter write lock
    /// </summary>
    
    /// <summary>Register an agent in the mapper after successful callback.</summary>
    public void TrackAgent(string agentId, string target, string listener, 
        EmpireAgentPlatform platform);

    /// <summary>Get all agents active on a specific target.</summary>
    public IReadOnlyList<AgentRecord> GetAgentsByHost(string target);

    /// <summary>Mark an agent inactive (clean up on logout).</summary>
    public void CloseAgent(string agentId);

    /// <summary>List all active agents.</summary>
    public IReadOnlyList<AgentRecord> ListActiveAgents();
}

public sealed record AgentRecord(
    string AgentId,
    string Target,
    string Listener,
    EmpireAgentPlatform Platform,
    DateTimeOffset OpenedAt,
    DateTimeOffset? ClosedAt);
```

<a id="scope-enforcement"></a>
## Scope Enforcement

Every public method in the C2 subsystem validates targets against the scope
allow-list as the first statement:

```csharp
public async Task<EmpireStagerResult> GenerateAsync(
    string target, EmpireAgentPlatform platform, CancellationToken ct)
{
    // @invariant-id:scope-in-every-tool — FIRST statement
    _scope.Require(target);  // throws ScopeException if out-of-scope

    // ... rest of method (post-echo, payload generation, etc.)
    _audit.Record("empire.stager.generate", new Dictionary<string, object?> { ... });
}
```

For lateral movement (multi-target operations), scope is validated for both source
and pivot targets:

```csharp
public async Task<ExploitResult> ExecuteLateralAsync(
    string target, IReadOnlyList<string> pivotTargets, HostFinding findings, ...)
{
    _scope.Require(target);  // source
    foreach (var pivot in pivotTargets)
    {
        _scope.Require(pivot);  // each destination
    }
    // ... execution
}
```

**Out-of-scope behavior:** If a target fails scope validation:
- `ScopeException` is thrown immediately
- The operation is aborted (no partial execution)
- An audit event is recorded with the failed target + reason
- The calling tool (Autopilot, SessionManager, operator) handles the exception

<a id="audit-invariants"></a>
## Audit Invariants

Every C2 action is recorded to `audit.jsonl` with the following structure:

### Stager Generation

```json
{
  "timestamp": "2026-04-15T10:30:45Z",
  "event": "empire.stager.generate",
  "target": "192.168.1.100",
  "platform": "windows",
  "stager_sha256": "abc123def456...",
  "success": true,
  "error": null,
  "duration_ms": 342
}
```

### Module Execution

```json
{
  "timestamp": "2026-04-15T10:31:10Z",
  "event": "empire.module.execute",
  "target": "192.168.1.100",
  "agent_id": "3KWJXK8L",
  "module_name": "windows/escalate/seimpersonate_potato",
  "success": true,
  "output_sha256": "xyz789...",
  "duration_ms": 5200,
  "error": null
}
```

### Scope Violation

```json
{
  "timestamp": "2026-04-15T10:32:00Z",
  "event": "empire.stager.generate",
  "target": "203.0.113.50",
  "scope_error": "target 203.0.113.50 not in scope",
  "success": false,
  "duration_ms": 2
}
```

**Invariants:**
- **No plaintext output:** If module execution yields credentials or secrets,
  only a SHA-256 digest is recorded. Plaintext is written to loot files only.
- **Append-only:** Audit events are never deleted, replaced, or redacted after
  creation. Redaction is a forward-only operation (future events are withheld).
- **Idempotent targets:** Same action on same target within the same run
  produces only one audit event (deduplication is not applied; each invocation
  is a new event).

<a id="thread-safety"></a>
## Thread Safety

### SessionAgentMapper: ReaderWriterLockSlim Pattern

```csharp
private readonly ReaderWriterLockSlim _lock = new();
private readonly Dictionary<string, AgentRecord> _agents = new();

// Read operations: parallel-safe
public IReadOnlyList<AgentRecord> GetAgentsByHost(string target)
{
    _lock.EnterReadLock();
    try
    {
        return _agents.Values.Where(a => a.Target == target).ToList();
    }
    finally { _lock.ExitReadLock(); }
}

// Write operations: exclusive
public void TrackAgent(string agentId, string target, ...)
{
    _lock.EnterWriteLock();
    try
    {
        _agents[agentId] = new AgentRecord(agentId, target, ...);
    }
    finally { _lock.ExitWriteLock(); }
}
```

**Rationale:** Read lock allows concurrent enumeration (e.g., multiple
post-ex threads querying agents per host), while write lock ensures atomic
agent registration/closure.

### AuditLog: ConcurrentQueue Pattern

The `AuditLog` is thread-safe internally (uses `ConcurrentBag` + lock-free
queue). C2 tools call `_audit.Record()` without explicit locking:

```csharp
// Multiple threads can call this concurrently (safe)
_audit.Record("empire.stager.generate", new Dictionary<string, object?> { ... });
_audit.Record("empire.module.execute", new Dictionary<string, object?> { ... });
```

### Scope: Read-Only After Construction

The `Scope` object is immutable after parsing. All methods are thread-safe
(no locks needed):

```csharp
// Multiple threads can call Require() concurrently
_scope.Require(target1);  // Thread A
_scope.Require(target2);  // Thread B
```

<a id="error-handling"></a>
## Error Handling

### Categorized Errors

| Error Type | Thrown | Handling | Audit |
| ---------- | ------ | -------- | ----- |
| **ScopeException** | Always | Propagate immediately | Recorded as scope_error |
| **OperationCanceledException** | On CT | Propagate immediately | Recorded as cancelled |
| **Http errors** (4xx/5xx) | EmpireApiClient | Return error in result | Recorded as http_error + status |
| **Timeout** | Task.WaitAsync | Return result.Error = "timeout" | Recorded as duration_ms |
| **Invalid platform** | GenerateAsync | ArgumentException → result.Error | Recorded as error |

### Error Result Pattern

Instead of throwing on recoverable errors, C2 tools return results with
an `Error` field set:

```csharp
public sealed class ExploitResult
{
    public bool Success { get; set; }
    public string Target { get; set; }
    public string? Error { get; set; }  // null if Success == true
    // ... module-specific fields
}
```

This allows the calling orchestrator (Autopilot, SessionManager) to decide
whether to abort, retry, or skip the action.

### Scope & Permission Failures

Scope failures (`ScopeException`) always propagate and are non-recoverable:

```csharp
try
{
    var result = await stager.GenerateAsync(target, platform, ct);
}
catch (ScopeException ex)
{
    // Log and abort (Autopilot skips action)
    _audit.Record("scope_error", new Dictionary<string, object?> { ... });
    return false;
}
```

Permission failures (`PermissionRefusedException`) also propagate:

```csharp
if (!_permissions.AllowPayloads)
{
    throw new PermissionRefusedException("--allow-payloads required for agent delivery");
}
```

<a id="integration-with-runners"></a>
## Integration with Runners

### AutopilotRunner Integration

```csharp
// Phase 1: Recon
var findings = await nuclei.ScanAsync(...);

// Phase 2: Exploitation
var exploits = await spray.BruteAsync(...);

// Phase 3: (Future) Empire agent delivery
// var agent = await stager.GenerateAsync(target, platform, ct);
// sessionAgentMapper.TrackAgent(agentId, target, listener, platform);

// Phase 4: (Future) Privesc modules
// var privesc = await executor.ExecutePrivescAsync(target, findings, ct);
```

### SessionManager Integration

The `SessionManager` tracks active post-ex shells (SSH, WinRM, Meterpreter).
Empire agents are tracked separately in `SessionAgentMapper` because:
1. Empire agents have longer lifecycle (continuous callback loop)
2. Module execution spans multiple agents per host
3. Audit trail must distinguish shell sessions from C2 agents

### ExploitRunner Integration

`ExploitRunner` coordinates multi-stage exploitation. Empire stager can be
used as the "payload" stage in a multi-stage chain:

```
Nuclei RCE → [Meterpreter payload]  or  [Empire stager]
```

The choice is deferred to the orchestrator (LLM planner or deterministic
prioritization).

<a id="data-flow"></a>
## Data Flow: Scope → Audit Trail

```
Input: target="192.168.1.100", platform=Windows
  ↓
[EmpireAgentStager.GenerateAsync()]
  ↓
  1. _scope.Require(target)           ← ScopeException if out-of-scope
  ↓
  2. Validate platform enum           ← ArgumentException if invalid
  ↓
  3. Generate stager code (PowerShell one-liner)
  ↓
  4. SHA-256 hash the stager          ← Idempotent
  ↓
  5. _audit.Record("empire.stager.generate", {
       target, platform, stager_sha256, success: true, duration_ms: 342
     })
  ↓
Output: EmpireStagerResult { Success: true, StagerCode, StagerSha256, ... }
  ↓
[Calling tool handles result]
  ↓
  - On success: Deliver StagerCode to target
  - On error: Log and retry/skip per orchestrator policy
```

<a id="extension-points"></a>
## Extension Points for New C2 Frameworks

To integrate a new C2 framework (Sliver, Metasploit, Havoc, etc.):

1. **Create `I<Framework>AgentStager : IPayloadTool`**
   - Implement `GenerateAsync(target, platform, ct)`
   - Call `_scope.Require(target)` as first statement
   - Return typed `<Framework>StagerResult`
   - Audit: `_audit.Record("<framework>.stager.generate", ...)`

2. **Create `I<Framework>ModuleExecutor : IExploitTool`**
   - Implement `ExecuteAsync(target, findings, ct)`
   - Call `_scope.Require(target)` as first statement (+ pivots)
   - Match findings to available modules
   - Audit: `_audit.Record("<framework>.module.execute", ...)`

3. **Register in DI container (Program.cs)**
   ```csharp
   // --- sliver c2 ---
   var sliverStager = new SliverAgentStager(scope, audit);
   var sliverExecutor = new SliverModuleExecutor(scope, audit, sliverModuleLibrary);
   exploitToolbox.Tools.Add(sliverExecutor);
   // --- end sliver c2 ---
   ```

4. **Add tests**
   - Scope validation negative test
   - Platform support test
   - Module matching test
   - Audit verification test

