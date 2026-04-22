using System.Text.Json.Serialization;
using Drederick.Host;

namespace Drederick.Web.Runs;

/// <summary>
/// Request body for <c>POST /api/runs</c>. Mirrors the subset of
/// <see cref="RunOptions"/> the Web UI currently exposes. Category strings
/// gate high-blast-radius tool categories — the server validates each
/// against <see cref="ServerCategoryGrants"/> before accepting the run.
/// </summary>
public sealed record StartRunRequest(
    [property: JsonPropertyName("scope_path")] string ScopePath,
    [property: JsonPropertyName("targets")] IReadOnlyList<string> Targets,
    [property: JsonPropertyName("out_dir")] string? OutDir = null,
    [property: JsonPropertyName("mode")] string? Mode = null,
    [property: JsonPropertyName("categories")] IReadOnlyList<string>? Categories = null);

/// <summary>Response body for <c>POST /api/runs</c> (HTTP 202).</summary>
public sealed record StartRunResponse(
    [property: JsonPropertyName("run_id")] Guid RunId,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("status")] string Status);

/// <summary>Serializable view of a tracked run.</summary>
public sealed record RunRecordDto(
    [property: JsonPropertyName("run_id")] Guid RunId,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("finished_at")] DateTimeOffset? FinishedAt,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("target_count")] int TargetCount,
    [property: JsonPropertyName("finding_count")] int FindingCount,
    [property: JsonPropertyName("error")] string? Error = null);

/// <summary>Serializable view of a single <see cref="ScanEvent"/>.</summary>
public sealed record ScanEventDto(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("target")] string? Target,
    [property: JsonPropertyName("tool")] string? Tool,
    [property: JsonPropertyName("message")] string? Message,
    [property: JsonPropertyName("tool_calls_total")] int? ToolCallsTotal);

/// <summary>Response body for <c>GET /api/runs/{id}/events</c>.</summary>
public sealed record EventsBatchDto(
    [property: JsonPropertyName("run_id")] Guid RunId,
    [property: JsonPropertyName("since")] DateTimeOffset? Since,
    [property: JsonPropertyName("events")] IReadOnlyList<ScanEventDto> Events,
    [property: JsonPropertyName("truncated")] bool Truncated);

/// <summary>Problem-details-ish error body shared by runs endpoints.</summary>
public sealed record RunsErrorDto(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("rejected_targets")] IReadOnlyList<string>? RejectedTargets = null);
