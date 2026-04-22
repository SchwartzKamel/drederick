using System.Text.Json.Serialization;

namespace Drederick.Web.Jeopardy;

/// <summary>
/// Request / response DTOs for the <c>/api/jeopardy/*</c> endpoints. These
/// deliberately mirror the <c>drederick ctf-solve</c> CLI flags so an operator
/// can drive the Jeopardy division from either path without translation.
///
/// <para>
/// Invariants surfaced here:
/// <list type="bullet">
///   <item><description>No DTO exposes plaintext CTFd tokens or plaintext
///     flags. Flags are echoed as <c>flag_sha256</c>; tokens stay in the
///     request body only, hashed on audit.</description></item>
///   <item><description>The Azure / llama.cpp provider branches are
///     experimental until the <c>llm-factory-cli</c> todo lands; callers
///     default to <c>copilot</c>.</description></item>
/// </list>
/// </para>
/// </summary>

public sealed class JeopardyStartRequest
{
    [JsonPropertyName("ctfd_url")]
    public string CtfdUrl { get; set; } = string.Empty;

    [JsonPropertyName("ctfd_token")]
    public string CtfdToken { get; set; } = string.Empty;

    [JsonPropertyName("scope_path")]
    public string ScopePath { get; set; } = string.Empty;

    [JsonPropertyName("models")]
    public List<string> Models { get; set; } = new();

    [JsonPropertyName("run_budget_usd")]
    public decimal? RunBudgetUsd { get; set; }

    [JsonPropertyName("challenge_budget_usd")]
    public decimal? ChallengeBudgetUsd { get; set; }

    [JsonPropertyName("llm_provider")]
    public string? LlmProvider { get; set; }

    [JsonPropertyName("categories")]
    public List<string>? Categories { get; set; }

    [JsonPropertyName("challenge_ids")]
    public List<int>? ChallengeIds { get; set; }

    [JsonPropertyName("out_dir")]
    public string? OutDir { get; set; }

    [JsonPropertyName("wall_clock_minutes")]
    public int? WallClockMinutes { get; set; }

    [JsonPropertyName("max_concurrent")]
    public int? MaxConcurrent { get; set; }
}

public sealed record JeopardyStartResponse(
    [property: JsonPropertyName("session_id")] Guid SessionId,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt);

public sealed record JeopardyErrorDto(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("message")] string Message);

public sealed record JeopardySessionSummary(
    [property: JsonPropertyName("session_id")] Guid SessionId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("finished_at")] DateTimeOffset? FinishedAt,
    [property: JsonPropertyName("ctfd_url_sha256")] string CtfdUrlSha256,
    [property: JsonPropertyName("models")] IReadOnlyList<string> Models,
    [property: JsonPropertyName("challenges_discovered")] int ChallengesDiscovered,
    [property: JsonPropertyName("challenges_solved")] int ChallengesSolved,
    [property: JsonPropertyName("total_usd_cost")] decimal TotalUsdCost);

public sealed record JeopardySessionDetail(
    [property: JsonPropertyName("session_id")] Guid SessionId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("finished_at")] DateTimeOffset? FinishedAt,
    [property: JsonPropertyName("ctfd_url_sha256")] string CtfdUrlSha256,
    [property: JsonPropertyName("models")] IReadOnlyList<string> Models,
    [property: JsonPropertyName("out_dir")] string OutDir,
    [property: JsonPropertyName("challenges_discovered")] int ChallengesDiscovered,
    [property: JsonPropertyName("challenges_solved")] int ChallengesSolved,
    [property: JsonPropertyName("total_usd_cost")] decimal TotalUsdCost,
    [property: JsonPropertyName("flags_submitted")] IReadOnlyList<JeopardyFlagRecordDto> FlagsSubmitted,
    [property: JsonPropertyName("swarm")] IReadOnlyList<JeopardyChallengeStateDto> Swarm,
    [property: JsonPropertyName("error")] string? Error);

public sealed record JeopardyFlagRecordDto(
    [property: JsonPropertyName("challenge_id")] int ChallengeId,
    [property: JsonPropertyName("flag_sha256")] string FlagSha256,
    [property: JsonPropertyName("correct")] bool Correct,
    [property: JsonPropertyName("solved_by_model")] string? SolvedByModel,
    [property: JsonPropertyName("solved_at")] DateTimeOffset SolvedAt);

public sealed record JeopardyActiveSolverDto(
    [property: JsonPropertyName("model")] string Model,
    [property: JsonPropertyName("started_at")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("turns_taken")] int TurnsTaken);

public sealed record JeopardyChallengeStateDto(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("value")] int Value,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("active_solvers")] IReadOnlyList<JeopardyActiveSolverDto> ActiveSolvers,
    [property: JsonPropertyName("flag_sha256")] string? FlagSha256,
    [property: JsonPropertyName("solved_by_model")] string? SolvedByModel,
    [property: JsonPropertyName("solved_at")] DateTimeOffset? SolvedAt);

public sealed class JeopardyHintRequest
{
    /// <summary>
    /// Optional. May be an int (challenge id) or a string. When omitted the
    /// hint is broadcast to every active challenge.
    /// </summary>
    [JsonPropertyName("challenge_id")]
    public object? ChallengeId { get; set; }

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "hint";

    [JsonPropertyName("body")]
    public string Body { get; set; } = string.Empty;

    [JsonPropertyName("solver_id")]
    public string? SolverId { get; set; }
}

public sealed record JeopardyHintResponse(
    [property: JsonPropertyName("delivered_at")] DateTimeOffset DeliveredAt,
    [property: JsonPropertyName("body_sha256")] string BodySha256,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("challenge_id")] string? ChallengeId);

public sealed record JeopardyHintHistoryDto(
    [property: JsonPropertyName("at")] DateTimeOffset At,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("challenge_id")] string? ChallengeId,
    [property: JsonPropertyName("solver_id")] string? SolverId,
    [property: JsonPropertyName("body_sha256")] string BodySha256);
