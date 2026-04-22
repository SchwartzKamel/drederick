using Drederick.Audit;
using Drederick.Web.Jeopardy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// HTTP surface for the Jeopardy CTF solver. All routes live under
/// <c>/api/jeopardy/</c>. Endpoint handlers defer every piece of real work
/// to <see cref="JeopardySessionManager"/> — the endpoint file itself is
/// deliberately thin so the invariants (no plaintext flag / token in
/// responses, scope-gated CTFd host, audit-first) stay in one place.
/// </summary>
internal static class JeopardyEndpoints
{
    public static IEndpointRouteBuilder MapJeopardyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/jeopardy").WithTags("jeopardy");

        group.MapPost("/sessions", StartSession).WithName("StartJeopardySession");
        group.MapGet("/sessions", ListSessions).WithName("ListJeopardySessions");
        group.MapGet("/sessions/{sessionId:guid}", GetSession).WithName("GetJeopardySession");
        group.MapDelete("/sessions/{sessionId:guid}", CancelSession).WithName("CancelJeopardySession");
        group.MapGet("/sessions/{sessionId:guid}/challenges", ListChallenges).WithName("ListJeopardyChallenges");
        group.MapGet("/sessions/{sessionId:guid}/challenges/{challengeId:int}", GetChallenge).WithName("GetJeopardyChallenge");
        group.MapPost("/sessions/{sessionId:guid}/hints", PostHint).WithName("PostJeopardyHint");
        group.MapGet("/sessions/{sessionId:guid}/hints", ListHints).WithName("ListJeopardyHints");
        group.MapGet("/sessions/{sessionId:guid}/swarm", GetSwarm).WithName("GetJeopardySwarm");

        return app;
    }

    // --- POST /api/jeopardy/sessions ---
    //
    // Launches a CtfCoordinator. Returns 202 with a session id so the
    // caller can poll /sessions/{id} for status.
    //
    // The Azure / llama.cpp provider branches are experimental until the
    // llm-factory-cli todo lands. Default ("copilot") mirrors CtfSolveRunner.
    private static async Task<IResult> StartSession(
        JeopardyStartRequest request,
        JeopardySessionManager mgr,
        AuditLog audit,
        HttpContext ctx)
    {
        var (session, error, message) = await mgr.StartAsync(request, ctx.RequestAborted);
        if (error is not null)
        {
            var status = error switch
            {
                "invalid_request" or "scope_load_failed" or "scope_path_rejected" or "out_of_scope"
                    => StatusCodes.Status400BadRequest,
                "setup_failed" => StatusCodes.Status500InternalServerError,
                _ => StatusCodes.Status400BadRequest,
            };
            return Results.Json(new JeopardyErrorDto(error, message ?? error), statusCode: status);
        }
        if (session is null)
        {
            return Results.Problem("unknown failure", statusCode: 500);
        }
        return Results.Accepted(
            $"/api/jeopardy/sessions/{session.SessionId:D}",
            new JeopardyStartResponse(session.SessionId, session.StartedAt));
    }

    private static IResult ListSessions(JeopardySessionManager mgr)
    {
        var sessions = mgr.List()
            .OrderByDescending(s => s.StartedAt)
            .Select(Summarize)
            .ToArray();
        return Results.Ok(sessions);
    }

    private static IResult GetSession(Guid sessionId, JeopardySessionManager mgr, AuditLog audit)
    {
        var session = mgr.Get(sessionId);
        if (session is null) return NotFound(sessionId);
        audit.Record("web.jeopardy.query", new Dictionary<string, object?>
        {
            ["session_id"] = sessionId.ToString(),
            ["kind"] = "detail",
        });
        return Results.Ok(Detail(session));
    }

    private static async Task<IResult> CancelSession(Guid sessionId, JeopardySessionManager mgr)
    {
        var ok = await mgr.CancelAsync(sessionId);
        if (!ok) return NotFound(sessionId);
        return Results.NoContent();
    }

    private static IResult ListChallenges(Guid sessionId, JeopardySessionManager mgr, AuditLog audit)
    {
        var session = mgr.Get(sessionId);
        if (session is null) return NotFound(sessionId);
        audit.Record("web.jeopardy.query", new Dictionary<string, object?>
        {
            ["session_id"] = sessionId.ToString(),
            ["kind"] = "challenges",
        });
        return Results.Ok(session.BuildSwarm());
    }

    private static IResult GetChallenge(Guid sessionId, int challengeId, JeopardySessionManager mgr)
    {
        var session = mgr.Get(sessionId);
        if (session is null) return NotFound(sessionId);
        var c = session.BuildChallenge(challengeId);
        if (c is null)
        {
            return Results.Json(
                new JeopardyErrorDto("not_found", $"challenge {challengeId} not in session {sessionId:D}"),
                statusCode: StatusCodes.Status404NotFound);
        }
        return Results.Ok(c);
    }

    private static async Task<IResult> PostHint(
        Guid sessionId,
        JeopardyHintRequest req,
        JeopardySessionManager mgr,
        HttpContext ctx)
    {
        var (resp, error, message) = await mgr.SendHintAsync(sessionId, req, ctx.RequestAborted);
        if (error is not null)
        {
            var status = error switch
            {
                "not_found" => StatusCodes.Status404NotFound,
                "invalid_request" => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status500InternalServerError,
            };
            return Results.Json(new JeopardyErrorDto(error, message ?? error), statusCode: status);
        }
        return Results.Ok(resp);
    }

    private static IResult ListHints(Guid sessionId, JeopardySessionManager mgr)
    {
        var session = mgr.Get(sessionId);
        if (session is null) return NotFound(sessionId);
        return Results.Ok(session.Hints());
    }

    private static IResult GetSwarm(Guid sessionId, JeopardySessionManager mgr, AuditLog audit)
    {
        var session = mgr.Get(sessionId);
        if (session is null) return NotFound(sessionId);
        audit.Record("web.jeopardy.query", new Dictionary<string, object?>
        {
            ["session_id"] = sessionId.ToString(),
            ["kind"] = "swarm",
        });
        return Results.Ok(session.BuildSwarm());
    }

    // ---- helpers ----

    private static IResult NotFound(Guid sessionId) =>
        Results.Json(
            new JeopardyErrorDto("not_found", $"session {sessionId:D} not found"),
            statusCode: StatusCodes.Status404NotFound);

    private static JeopardySessionSummary Summarize(JeopardySession s) => new(
        SessionId: s.SessionId,
        Status: s.Status,
        StartedAt: s.StartedAt,
        FinishedAt: s.FinishedAt,
        CtfdUrlSha256: s.CtfdUrlSha256,
        Models: s.Models,
        ChallengesDiscovered: s.ChallengesDiscovered,
        ChallengesSolved: s.ChallengesSolved,
        TotalUsdCost: s.TotalUsdCost);

    private static JeopardySessionDetail Detail(JeopardySession s) => new(
        SessionId: s.SessionId,
        Status: s.Status,
        StartedAt: s.StartedAt,
        FinishedAt: s.FinishedAt,
        CtfdUrlSha256: s.CtfdUrlSha256,
        Models: s.Models,
        OutDir: s.OutDir,
        ChallengesDiscovered: s.ChallengesDiscovered,
        ChallengesSolved: s.ChallengesSolved,
        TotalUsdCost: s.TotalUsdCost,
        FlagsSubmitted: s.Flags(),
        Swarm: s.BuildSwarm(),
        Error: s.Error);
}
