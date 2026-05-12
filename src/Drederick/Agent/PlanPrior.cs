using System.Text.Json.Serialization;

namespace Drederick.Agent;

// --- htb-structured-plan-prior --- (GAP-054)
/// <summary>
/// Structured snapshot of the run state that the planner consumes before
/// choosing the next action. Replaces the opaque prose <c>prior</c> field
/// previously embedded in the <c>runner.plan</c> audit event.
///
/// Invariants:
/// <list type="bullet">
///   <item><description>No plaintext credentials are embedded — captured
///   credential state is exposed as a count only.</description></item>
///   <item><description>All collections are non-null and may be empty.</description></item>
///   <item><description><see cref="Summary"/> is an optional
///   human-readable form for log triage; structured fields are
///   authoritative.</description></item>
/// </list>
/// </summary>
public sealed record PlanPrior(
    [property: JsonPropertyName("targets")] IReadOnlyList<string> Targets,
    [property: JsonPropertyName("open_services")] IReadOnlyList<PlanPriorService> OpenServices,
    [property: JsonPropertyName("captured_creds")] PlanPriorCredentials CapturedCreds,
    [property: JsonPropertyName("active_sessions")] PlanPriorSessions ActiveSessions,
    [property: JsonPropertyName("previously_attempted")] IReadOnlyList<PlanPriorAttempt> PreviouslyAttempted,
    [property: JsonPropertyName("budget")] PlanPriorBudget Budget,
    [property: JsonPropertyName("summary")] string? Summary = null);

/// <summary>One open service on one host as known prior to planning.</summary>
public sealed record PlanPriorService(
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("protocol")] string Protocol,
    [property: JsonPropertyName("product")] string? Product,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("cves")] IReadOnlyList<string> Cves);

/// <summary>Aggregated credential state. Count only — no plaintext.</summary>
public sealed record PlanPriorCredentials(
    [property: JsonPropertyName("count")] int Count);

/// <summary>Aggregated session state. Count only.</summary>
public sealed record PlanPriorSessions(
    [property: JsonPropertyName("count")] int Count);

/// <summary>One past tool attempt deduped by (tool, target).</summary>
public sealed record PlanPriorAttempt(
    [property: JsonPropertyName("tool")] string Tool,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("result_kind")] string ResultKind);

/// <summary>Snapshot of the global tool budget at plan time.</summary>
public sealed record PlanPriorBudget(
    [property: JsonPropertyName("used")] int Used,
    [property: JsonPropertyName("remaining")] int Remaining);
// --- end htb-structured-plan-prior ---
