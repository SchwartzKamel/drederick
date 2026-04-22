using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Host;
using Drederick.Scope;
using Drederick.Web.Runs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Drederick.Web.Endpoints;

/// <summary>
/// <c>/api/runs</c> endpoint group. Starts/stops recon runs via
/// <see cref="DrederickHost"/> (through <see cref="IRunExecutor"/>), tracks
/// them in <see cref="RunManager"/>, and enforces the scope / category
/// invariants at the request boundary as defence-in-depth. Tools downstream
/// still re-check scope themselves (<c>@invariant-id:scope-in-every-tool</c>).
/// </summary>
public static class RunsEndpoints
{
    public static IEndpointRouteBuilder MapRunsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/runs").WithTags("runs");

        group.MapPost("/", StartRun).WithName("StartRun");
        group.MapGet("/", ListRuns).WithName("ListRuns");
        group.MapGet("/{runId:guid}", GetRun).WithName("GetRun");
        group.MapDelete("/{runId:guid}", CancelRun).WithName("CancelRun");
        group.MapGet("/{runId:guid}/events", GetEvents).WithName("GetRunEvents");

        return app;
    }

    // ---- POST /api/runs ----

    private static async Task<IResult> StartRun(
        HttpContext ctx,
        StartRunRequest request,
        RunManager runs,
        ScopePathPolicy scopePolicy,
        ServerCategoryGrants grants,
        WebAppSettings settings,
        AuditLog audit)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.ScopePath))
            return Results.BadRequest(new RunsErrorDto(
                "invalid_request", "scope_path is required."));
        if (request.Targets is null || request.Targets.Count == 0)
            return Results.BadRequest(new RunsErrorDto(
                "invalid_request", "targets must be a non-empty array."));

        // --- scope_path traversal guard (defence-in-depth) ---
        var resolvedPath = scopePolicy.Resolve(request.ScopePath);
        if (resolvedPath is null || !File.Exists(resolvedPath))
        {
            // Never echo the submitted path back in the audit / response — it
            // may be a canary. Record only the SHA-256.
            audit.Record("web.runs.start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_scope_path",
                ["scope_path_sha256"] = Sha256(request.ScopePath),
                ["auth_mode"] = AuthMode(ctx, settings),
            });
            return Results.BadRequest(new RunsErrorDto(
                "scope_path_rejected",
                "scope_path is outside the allowed root or does not exist."));
        }

        // --- category grant check ---
        var categories = (request.Categories ?? new List<string> { "recon" })
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c.Trim())
            .ToList();
        if (categories.Count == 0) categories.Add("recon");
        var ungranted = categories.Where(c => !grants.IsGranted(c)).ToList();
        if (ungranted.Count > 0)
        {
            audit.Record("web.runs.start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_categories",
                ["scope_path_sha256"] = Sha256(resolvedPath),
                ["categories_requested"] = categories,
                ["categories_ungranted"] = ungranted,
                ["auth_mode"] = AuthMode(ctx, settings),
            });
            return Results.Json(
                new RunsErrorDto(
                    "category_not_granted",
                    $"Server was not started with: {string.Join(",", ungranted)}. " +
                    "Restart the web server with the matching opt-in flags."),
                statusCode: StatusCodes.Status403Forbidden);
        }

        // --- scope load + per-target validation ---
        Drederick.Scope.Scope scope;
        var labMode = !"strict".Equals(request.Mode, StringComparison.OrdinalIgnoreCase);
        try
        {
            scope = ScopeLoader.LoadFile(resolvedPath, allowBroad: false, labMode: labMode);
        }
        catch (ScopeException ex)
        {
            audit.Record("web.runs.start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_scope_load",
                ["scope_path_sha256"] = Sha256(resolvedPath),
                ["auth_mode"] = AuthMode(ctx, settings),
            });
            return Results.BadRequest(new RunsErrorDto(
                "scope_load_failed", ex.Message));
        }

        var rejected = request.Targets.Where(t => !scope.Contains(t)).ToList();
        if (rejected.Count > 0)
        {
            audit.Record("web.runs.start", new Dictionary<string, object?>
            {
                ["outcome"] = "rejected_out_of_scope",
                ["scope_path_sha256"] = Sha256(resolvedPath),
                ["target_count"] = request.Targets.Count,
                ["rejected_count"] = rejected.Count,
                ["auth_mode"] = AuthMode(ctx, settings),
            });
            return Results.BadRequest(new RunsErrorDto(
                "scope",
                $"{rejected.Count} target(s) are not in scope.",
                RejectedTargets: rejected));
        }

        // --- build RunOptions ---
        var outDir = string.IsNullOrWhiteSpace(request.OutDir)
            ? Path.Combine(settings.OutputDir, "runs", Guid.NewGuid().ToString("N"))
            : request.OutDir!;
        var options = new RunOptions(
            ScopePath: resolvedPath,
            Targets: request.Targets.ToList(),
            OutputDir: outDir,
            LabMode: labMode);

        var runId = runs.StartRun(scope, options);

        audit.Record("web.runs.start", new Dictionary<string, object?>
        {
            ["outcome"] = "accepted",
            ["run_id"] = runId.ToString(),
            ["target_count"] = request.Targets.Count,
            ["scope_path_sha256"] = Sha256(resolvedPath),
            ["categories_requested"] = categories,
            ["auth_mode"] = AuthMode(ctx, settings),
        });

        var response = new StartRunResponse(runId, DateTimeOffset.UtcNow, "running");
        return Results.Json(response, statusCode: StatusCodes.Status202Accepted);
    }

    // ---- GET /api/runs ----

    private static IResult ListRuns(
        HttpContext ctx,
        RunManager runs,
        WebAppSettings settings,
        AuditLog audit)
    {
        audit.Record("web.runs.query", new Dictionary<string, object?>
        {
            ["kind"] = "list",
            ["auth_mode"] = AuthMode(ctx, settings),
        });
        return Results.Ok(runs.List());
    }

    // ---- GET /api/runs/{id} ----

    private static IResult GetRun(
        Guid runId,
        HttpContext ctx,
        RunManager runs,
        WebAppSettings settings,
        AuditLog audit)
    {
        var rec = runs.Get(runId);
        audit.Record("web.runs.query", new Dictionary<string, object?>
        {
            ["kind"] = "get",
            ["run_id"] = runId.ToString(),
            ["found"] = rec is not null,
            ["auth_mode"] = AuthMode(ctx, settings),
        });
        return rec is null
            ? Results.NotFound(new RunsErrorDto("not_found", $"run {runId} not found"))
            : Results.Ok(rec);
    }

    // ---- DELETE /api/runs/{id} ----

    private static IResult CancelRun(
        Guid runId,
        HttpContext ctx,
        RunManager runs,
        WebAppSettings settings,
        AuditLog audit)
    {
        var outcome = runs.Cancel(runId);
        audit.Record("web.runs.cancel", new Dictionary<string, object?>
        {
            ["run_id"] = runId.ToString(),
            ["outcome"] = outcome switch
            {
                null => "not_found",
                true => "cancelled",
                false => "already_finished",
            },
            ["auth_mode"] = AuthMode(ctx, settings),
        });
        return outcome switch
        {
            null => Results.NotFound(new RunsErrorDto("not_found", $"run {runId} not found")),
            false => Results.NotFound(new RunsErrorDto("already_finished", "run already finished")),
            true => Results.NoContent(),
        };
    }

    // ---- GET /api/runs/{id}/events?since=<iso> ----

    private static IResult GetEvents(
        Guid runId,
        HttpContext ctx,
        RunManager runs,
        WebAppSettings settings,
        AuditLog audit)
    {
        DateTimeOffset? since = null;
        if (ctx.Request.Query.TryGetValue("since", out var raw) && !string.IsNullOrWhiteSpace(raw))
        {
            if (!DateTimeOffset.TryParse(raw, out var parsed))
                return Results.BadRequest(new RunsErrorDto(
                    "invalid_since", "since must be an ISO-8601 timestamp."));
            since = parsed;
        }
        var batch = runs.Events(runId, since, maxBatch: 500);
        audit.Record("web.runs.query", new Dictionary<string, object?>
        {
            ["kind"] = "events",
            ["run_id"] = runId.ToString(),
            ["found"] = batch is not null,
            ["since"] = since?.ToString("o"),
            ["auth_mode"] = AuthMode(ctx, settings),
        });
        return batch is null
            ? Results.NotFound(new RunsErrorDto("not_found", $"run {runId} not found"))
            : Results.Ok(batch);
    }

    // ---- helpers ----

    private static string Sha256(string s)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexStringLower(hash);
    }

    private static string AuthMode(HttpContext ctx, WebAppSettings settings)
    {
        var hasHeader = !string.IsNullOrEmpty(ctx.Request.Headers.Authorization.ToString());
        if (!settings.RequireBearer && !hasHeader) return "loopback_bypass";
        if (hasHeader) return "bearer";
        return "rejected";
    }
}
