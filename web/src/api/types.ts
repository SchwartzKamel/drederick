/**
 * Hand-rolled TypeScript mirrors of the backend DTOs. Backend JSON uses
 * snake_case via [JsonPropertyName] — we mirror that exactly here so
 * callers can pass responses straight through without translation.
 *
 * Source files (keep in sync):
 *   - src/Drederick.Web/Runs/RunDtos.cs
 *   - src/Drederick.Web/Jeopardy/JeopardyDtos.cs
 *   - src/Drederick.Web/Endpoints/FindingsEndpoints.cs
 *   - src/Drederick.Web/Data/FindingsQueries.cs
 *   - src/Drederick.Web/Endpoints/DoctorEndpoints.cs
 *   - src/Drederick.Web/Endpoints/ScopeEndpoints.cs
 *   - src/Drederick.Web/Endpoints/AuditEndpoints.cs
 *   - src/Drederick.Web/Hubs/ScanEventBridge.cs
 *
 * ISO-8601 timestamps are `string` (the backend emits `DateTimeOffset`
 * via System.Text.Json — always ISO-8601). Guids are `string`.
 */

// ---------------------------------------------------------------------------
// Common paging envelope — used by every /api/findings/* list endpoint.
// See FindingsEndpoints.Page<T>(items, total, limit, offset).
// ---------------------------------------------------------------------------

export type PagedResponse<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

/**
 * Every /api/findings/* endpoint returns this stand-in when findings.db
 * is absent. HTTP status is still 200. Clients should branch on `status`.
 */
export type NoDatabaseResponse = {
  status: "no_database";
  database_path: string;
};

export type MaybeNoDb<T> = T | NoDatabaseResponse;

export function isNoDatabase<T>(r: MaybeNoDb<T>): r is NoDatabaseResponse {
  return (
    typeof r === "object" &&
    r !== null &&
    (r as NoDatabaseResponse).status === "no_database"
  );
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

export type HostFindingRow = {
  id: number;
  address: string;
  hostname: string | null;
  first_seen: string;
  last_seen: string;
  services_count: number;
};

export type HostDetail = HostFindingRow & {
  findings_count: number;
  cves_count: number;
};

export type ServiceRow = {
  id: number;
  host_id: number;
  port: number;
  protocol: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
};

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type CveRow = {
  cve_id: string;
  cvss: number | null;
  summary: string | null;
  published: string | null;
  severity: Severity;
};

export type ServiceDetail = ServiceRow & {
  cves: CveRow[];
};

export type PocRefRow = {
  id: number;
  cve_id: string;
  source: string;
  url: string | null;
  external_id: string | null;
  local_path: string | null;
  fetched_at: string | null;
  sha256: string | null;
  match_confidence: string | null;
};

export type CveDetail = CveRow & {
  poc_refs: PocRefRow[];
};

export type ExploitRunRow = {
  id: number;
  invocation_id: string | null;
  target: string;
  tool: string;
  category: string;
  artifact: string | null;
  artifact_sha256: string | null;
  argv_digest: string | null;
  exit_code: number | null;
  started_at: string;
  finished_at: string | null;
  stdout_bytes: number | null;
  stdout_sha256: string | null;
  stderr_bytes: number | null;
  stderr_sha256: string | null;
  work_dir: string | null;
  error: string | null;
};

export type SessionState = "open" | "closed";

export type SessionRow = {
  id: number;
  session_id: string;
  target: string;
  protocol: string;
  via_tool: string | null;
  opened_at: string;
  closed_at: string | null;
  state: SessionState;
};

export type LootRow = {
  id: number;
  target: string;
  kind: string;
  value_sha256: string;
  source_tool: string | null;
  captured_at: string;
};

export type GenericFindingRow = {
  id: number;
  host_id: number | null;
  service_id: number | null;
  kind: string;
  data_json: string;
  created_at: string;
};

export type FindingsSummary = {
  hosts: number;
  services: number;
  findings: number;
  poc_refs: number;
  cves: number;
  cves_by_severity: Record<Severity, number>;
  exploit_runs: number;
  exploit_runs_by_category: Record<string, number>;
  sessions_open: number;
  sessions_closed: number;
  loot: number;
  loot_by_kind: Record<string, number>;
};

// ---------------------------------------------------------------------------
// runs
// ---------------------------------------------------------------------------

export type StartRunRequest = {
  scope_path: string;
  targets: string[];
  out_dir?: string | null;
  mode?: "lab" | "strict" | null;
  categories?: string[] | null;
};

export type StartRunResponse = {
  run_id: string;
  started_at: string;
  status: string;
};

export type RunStatus = "running" | "finished" | "failed" | "cancelled" | string;

export type RunRecord = {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  status: RunStatus;
  target_count: number;
  finding_count: number;
  error?: string | null;
};

export type ScanEventDto = {
  kind: string;
  timestamp: string;
  target: string | null;
  tool: string | null;
  message: string | null;
  tool_calls_total: number | null;
};

export type EventsBatch = {
  run_id: string;
  since: string | null;
  events: ScanEventDto[];
  truncated: boolean;
};

export type RunsError = {
  error: string;
  message: string;
  rejected_targets?: string[] | null;
};

// ---------------------------------------------------------------------------
// jeopardy
// ---------------------------------------------------------------------------

export type JeopardyStartRequest = {
  ctfd_url: string;
  ctfd_token: string;
  scope_path: string;
  models: string[];
  run_budget_usd?: number | null;
  challenge_budget_usd?: number | null;
  llm_provider?: string | null;
  categories?: string[] | null;
  challenge_ids?: number[] | null;
  out_dir?: string | null;
  wall_clock_minutes?: number | null;
  max_concurrent?: number | null;
};

export type JeopardyStartResponse = {
  session_id: string;
  started_at: string;
};

export type JeopardyError = {
  error: string;
  message: string;
};

export type JeopardySessionSummary = {
  session_id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  ctfd_url_sha256: string;
  models: string[];
  challenges_discovered: number;
  challenges_solved: number;
  total_usd_cost: number;
};

export type JeopardyFlagRecord = {
  challenge_id: number;
  flag_sha256: string;
  correct: boolean;
  solved_by_model: string | null;
  solved_at: string;
};

export type JeopardyActiveSolver = {
  model: string;
  started_at: string;
  turns_taken: number;
};

export type JeopardyChallengeState = {
  id: number;
  name: string;
  category: string;
  value: number;
  state: string;
  active_solvers: JeopardyActiveSolver[];
  flag_sha256: string | null;
  solved_by_model: string | null;
  solved_at: string | null;
};

export type JeopardySessionDetail = JeopardySessionSummary & {
  out_dir: string;
  flags_submitted: JeopardyFlagRecord[];
  swarm: JeopardyChallengeState[];
  error: string | null;
};

export type JeopardyHintRequest = {
  challenge_id?: number | string | null;
  kind: string;
  body: string;
  solver_id?: string | null;
};

export type JeopardyHintResponse = {
  delivered_at: string;
  body_sha256: string;
  kind: string;
  challenge_id: string | null;
};

export type JeopardyHintHistory = {
  at: string;
  kind: string;
  challenge_id: string | null;
  solver_id: string | null;
  body_sha256: string;
};

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

export type DoctorStatus = "ok" | "warn" | "fail" | "missing";

export type DoctorCheck = {
  id: string;
  name: string;
  category: string | null;
  status: DoctorStatus;
  detail: string | null;
  recommendation: string | null;
};

export type DoctorSummary = {
  Ok: number;
  Warn: number;
  Fail: number;
  Missing: number;
};

export type DoctorChecksPayload = {
  Checks: DoctorCheck[];
  Summary: DoctorSummary;
};

// ---------------------------------------------------------------------------
// scope
// ---------------------------------------------------------------------------

export type ScopeEntry = {
  cidr_or_ip: string;
  family: "v4" | "v6";
  prefix_length: number;
};

export type ScopeViewResponse = {
  path: string;
  entries: ScopeEntry[];
  warnings: string[];
  mode: string;
};

export type ScopeValidateRequest = {
  path: string;
  proposed_targets: string[];
};

export type ScopeValidateRejection = {
  target: string;
  reason: string;
};

export type ScopeValidateResponse = {
  accepted: string[];
  rejected: ScopeValidateRejection[];
};

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

export type AuditRedactedEntry = {
  ts: string | null;
  event: string;
  redacted: true;
  reason: string;
};

export type AuditRawEntry = {
  ts?: string;
  event?: string;
  [key: string]: unknown;
};

export type AuditEntry = AuditRedactedEntry | AuditRawEntry;

export function isRedactedAudit(e: AuditEntry): e is AuditRedactedEntry {
  return (e as AuditRedactedEntry).redacted === true;
}

export type AuditTailResponse = {
  entries: AuditEntry[];
  count: number;
  redacted: number;
};

export type AuditCategoriesResponse = {
  prefixes: string[];
  events: string[];
};

// ---------------------------------------------------------------------------
// SignalR / ScanEventBridge
// ---------------------------------------------------------------------------

export type SignalRGroup = "recon" | "jeopardy" | "audit";

/**
 * Wire shape sent by ScanEventBridge on the SignalR "scanEvent" method.
 * Details are redacted server-side before send (sensitive keys become
 * `sha256:<hex>` values).
 */
export type ScanEventPayload = {
  Kind: string;
  Timestamp: string;
  Target: string | null;
  Tool: string | null;
  Message: string | null;
  ToolCallsTotal: number | null;
  Details: Record<string, unknown> | null;
};
