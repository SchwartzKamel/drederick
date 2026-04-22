using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// Minimal <c>/api/health</c> endpoint. Scaffold-only: returns a fixed-shape
/// JSON payload (<c>{ "status": "ok", "version": ..., "started_at": ... }</c>).
/// Phase-2 agents will add the real endpoints (runs, scope, findings, etc.)
/// next to this one, keyed by the <c>/api/</c> prefix.
/// </summary>
public static class HealthEndpoints
{
    public static IEndpointRouteBuilder MapHealthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/health", () => Results.Ok(new
        {
            status = "ok",
            version = typeof(HealthEndpoints).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            started_at = DateTimeOffset.UtcNow.ToString("o"),
        }))
        .WithName("GetHealth")
        .WithTags("health");

        return app;
    }
}
