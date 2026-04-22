using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Web.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// Read-only REST surface over <c>findings.db</c>. Every route is a
/// <c>GET</c>; writes never happen from these handlers. When the DB file
/// is absent (fresh install, no runs yet), every endpoint returns
/// <c>{ "status": "no_database" }</c> with HTTP 200 — empty-state is not
/// an error condition.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — each call
///     records a <c>web.findings.query</c> event with endpoint name and
///     a SHA-256 digest of the raw query string (not plaintext params —
///     filter values such as host names / loot kinds may be sensitive).
///     </description></item>
///   <item><description><c>@invariant-id:no-exfiltration</c> — the loot
///     endpoint never projects a plaintext <c>value</c> column (schema
///     has none), only <c>value_sha256</c> + tool-controlled metadata.
///     The exploit-runs endpoint never projects stdout/stderr content,
///     only bytes + sha256 + work_dir.</description></item>
/// </list>
/// </para>
/// </summary>
public static class FindingsEndpoints
{
    public static IEndpointRouteBuilder MapFindingsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/findings").WithTags("findings");

        group.MapGet("/", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                long? host_id, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "findings.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListFindings(host_id, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListFindings")
            .WithOpenApi(op => { op.Summary = "List generic findings rows (optionally filtered by host)."; return op; });

        group.MapGet("/hosts", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                string? q_param, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "hosts.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListHosts(q_param, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListHosts")
            .WithOpenApi(op => { op.Summary = "List hosts with per-host services_count; supports ?q= substring search."; return op; });

        group.MapGet("/hosts/{hostId:long}", (HttpContext ctx, FindingsQueries q, AuditLog audit, long hostId) =>
            Guarded(ctx, audit, q, "hosts.get", () =>
            {
                var host = q.GetHost(hostId);
                return host is null ? Results.NotFound() : Results.Ok(host);
            }))
            .WithName("GetHost")
            .WithOpenApi(op => { op.Summary = "Get a single host with aggregate counts."; return op; });

        group.MapGet("/services", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                long? host_id, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "services.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListServices(host_id, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListServices")
            .WithOpenApi(op => { op.Summary = "List services (optionally filtered by host_id)."; return op; });

        group.MapGet("/services/{serviceId:long}", (HttpContext ctx, FindingsQueries q, AuditLog audit, long serviceId) =>
            Guarded(ctx, audit, q, "services.get", () =>
            {
                var s = q.GetService(serviceId);
                return s is null ? Results.NotFound() : Results.Ok(s);
            }))
            .WithName("GetService")
            .WithOpenApi(op => { op.Summary = "Get a single service including linked CVEs."; return op; });

        group.MapGet("/cves", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                long? host_id, long? service_id, string? severity, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "cves.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListCves(host_id, service_id, severity, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListCves")
            .WithOpenApi(op => { op.Summary = "List CVEs, optionally filtered by host_id, service_id, or severity (critical|high|medium|low)."; return op; });

        group.MapGet("/cves/{cveId}", (HttpContext ctx, FindingsQueries q, AuditLog audit, string cveId) =>
            Guarded(ctx, audit, q, "cves.get", () =>
            {
                var c = q.GetCve(cveId);
                return c is null ? Results.NotFound() : Results.Ok(c);
            }))
            .WithName("GetCve")
            .WithOpenApi(op => { op.Summary = "Get a single CVE including linked PoC refs."; return op; });

        group.MapGet("/poc-refs", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                string? cve_id, string? source, string? match_confidence, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "poc_refs.list", () =>
            {
                // match_confidence is accepted for forward compatibility
                // but is not yet persisted in the schema; silently treated
                // as "no filter". See FindingsQueries.ListPocRefs notes.
                _ = match_confidence;
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListPocRefs(cve_id, source, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListPocRefs")
            .WithOpenApi(op => { op.Summary = "List PoC references; filters: cve_id, source, match_confidence."; return op; });

        group.MapGet("/exploit-runs", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                string? target, string? tool, string? category, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "exploit_runs.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListExploitRuns(target, tool, category, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListExploitRuns")
            .WithOpenApi(op => { op.Summary = "List exploit runs (stdout/stderr content NOT returned — only bytes + sha256 + work_dir)."; return op; });

        group.MapGet("/sessions", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                string? target, string? protocol, string? state, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "sessions.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListSessions(target, protocol, state, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListSessions")
            .WithOpenApi(op => { op.Summary = "List sessions (state=open|closed derived from closed_at)."; return op; });

        group.MapGet("/loot", (HttpContext ctx, FindingsQueries q, AuditLog audit,
                string? target, string? kind, int? limit, int? offset) =>
            Guarded(ctx, audit, q, "loot.list", () =>
            {
                var lim = FindingsQueries.ClampLimit(limit);
                var off = FindingsQueries.ClampOffset(offset);
                var (items, total) = q.ListLoot(target, kind, lim, off);
                return Results.Ok(Page(items, total, lim, off));
            }))
            .WithName("ListLoot")
            .WithOpenApi(op => { op.Summary = "List loot rows (value_sha256 only — plaintext never returned)."; return op; });

        group.MapGet("/summary", (HttpContext ctx, FindingsQueries q, AuditLog audit) =>
            Guarded(ctx, audit, q, "summary", () => Results.Ok(q.Summary())))
            .WithName("GetFindingsSummary")
            .WithOpenApi(op => { op.Summary = "Top-level dashboard counts across all findings tables."; return op; });

        return app;
    }

    private static IResult Guarded(
        HttpContext ctx, AuditLog audit, FindingsQueries q,
        string endpointName, Func<IResult> exec)
    {
        // Hash the full query string for audit — filter values may include
        // host names, CVE IDs, or other triage-sensitive data; we want
        // correlation without leaking the plaintext.
        var qs = ctx.Request.QueryString.Value ?? "";
        var digest = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(endpointName + "?" + qs)));

        audit.Record("web.findings.query", new Dictionary<string, object?>
        {
            ["endpoint"] = endpointName,
            ["path"] = ctx.Request.Path.Value,
            ["query_params_sha256"] = digest,
        });

        if (!q.DatabaseExists())
        {
            return Results.Ok(new { status = "no_database", database_path = q.DatabasePath });
        }

        return exec();
    }

    private static object Page<T>(IReadOnlyList<T> items, int total, int limit, int offset) =>
        new { items, total, limit, offset };
}
