using Drederick.Audit;
using Drederick.Doctor;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// Read-only operator-workstation preflight endpoints.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:doctor-workstation-only</c> — these
///     endpoints are <b>detect-only</b>. There is deliberately no install /
///     apt-get / pipx surface reachable from the Web UI. Install remains a
///     TTY-consented CLI flow (<c>drederick doctor --install</c>).
///     </description></item>
///   <item><description><c>@invariant-id:audit-everything</c> — every
///     invocation records a <c>web.doctor.checks</c> event.</description></item>
/// </list>
/// </para>
/// </summary>
public static class DoctorEndpoints
{
    /// <summary>
    /// Pluggable check registry so tests can inject a canned list without
    /// requiring docker / impacket / etc. to be installed. Default
    /// implementation is empty until wiring code registers concrete
    /// <see cref="IDoctorCheck"/> instances in DI.
    /// </summary>
    public interface IWebDoctorCheckRegistry
    {
        IReadOnlyList<IDoctorCheck> Checks { get; }
    }

    public sealed class EmptyRegistry : IWebDoctorCheckRegistry
    {
        public IReadOnlyList<IDoctorCheck> Checks { get; } = Array.Empty<IDoctorCheck>();
    }

    public sealed class StaticRegistry : IWebDoctorCheckRegistry
    {
        public IReadOnlyList<IDoctorCheck> Checks { get; }
        public StaticRegistry(IReadOnlyList<IDoctorCheck> checks) { Checks = checks; }
    }

    public static IEndpointRouteBuilder MapDoctorEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/doctor/checks", async (
            IWebDoctorCheckRegistry registry,
            AuditLog audit,
            CancellationToken ct) =>
        {
            var results = await RunAllAsync(registry.Checks, ct).ConfigureAwait(false);
            var payload = BuildPayload(registry.Checks, results);
            audit.Record("web.doctor.checks", new Dictionary<string, object?>
            {
                ["check_count"] = registry.Checks.Count,
                ["ok"] = payload.Summary.Ok,
                ["warn"] = payload.Summary.Warn,
                ["fail"] = payload.Summary.Fail,
                ["missing"] = payload.Summary.Missing,
            });
            return Results.Ok(payload);
        })
        .WithName("GetDoctorChecks")
        .WithTags("doctor")
        .WithSummary("Detect-only workstation preflight. Never installs.");

        app.MapGet("/api/doctor/checks/{checkId}", async (
            string checkId,
            IWebDoctorCheckRegistry registry,
            AuditLog audit,
            CancellationToken ct) =>
        {
            var check = registry.Checks.FirstOrDefault(
                c => string.Equals(c.Id, checkId, StringComparison.Ordinal));
            if (check is null)
            {
                return Results.NotFound(new { error = $"check '{checkId}' not found" });
            }
            var result = await SafeRunAsync(check, ct).ConfigureAwait(false);
            audit.Record("web.doctor.checks", new Dictionary<string, object?>
            {
                ["check_id"] = checkId,
                ["status"] = MapStatus(result),
            });
            return Results.Ok(Project(check, result));
        })
        .WithName("GetDoctorCheck")
        .WithTags("doctor")
        .WithSummary("Detect-only single check. Never installs.");

        return app;
    }

    private static async Task<IReadOnlyList<DoctorCheckResult>> RunAllAsync(
        IReadOnlyList<IDoctorCheck> checks,
        CancellationToken ct)
    {
        var results = new List<DoctorCheckResult>(checks.Count);
        foreach (var c in checks)
        {
            results.Add(await SafeRunAsync(c, ct).ConfigureAwait(false));
        }
        return results;
    }

    private static async Task<DoctorCheckResult> SafeRunAsync(
        IDoctorCheck check,
        CancellationToken ct)
    {
        try
        {
            // install=false, assumeYes=false — the Web surface NEVER installs.
            using var stdin = new StringReader(string.Empty);
            using var stdout = new StringWriter();
            return await check.RunAsync(install: false, assumeYes: false,
                stdin, stdout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new DoctorCheckResult(
                check.Id, DoctorCheckStatus.Fail,
                $"check threw: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public sealed record Summary(int Ok, int Warn, int Fail, int Missing);
    public sealed record ChecksPayload(object[] Checks, Summary Summary);

    private static ChecksPayload BuildPayload(
        IReadOnlyList<IDoctorCheck> checks,
        IReadOnlyList<DoctorCheckResult> results)
    {
        var rows = new List<object>(checks.Count);
        int ok = 0, warn = 0, fail = 0, missing = 0;
        for (int i = 0; i < checks.Count; i++)
        {
            var c = checks[i];
            var r = results[i];
            rows.Add(Project(c, r));
            switch (MapStatus(r))
            {
                case "ok": ok++; break;
                case "warn": warn++; break;
                case "fail": fail++; break;
                case "missing": missing++; break;
            }
        }
        return new ChecksPayload(rows.ToArray(), new Summary(ok, warn, fail, missing));
    }

    private static object Project(IDoctorCheck c, DoctorCheckResult r) => new
    {
        id = c.Id,
        name = c.Id,
        category = c.Category,
        status = MapStatus(r),
        detail = r.Detail,
        recommendation = r.FixCommand,
    };

    /// <summary>
    /// Map the underlying <see cref="DoctorCheckStatus"/> plus detail text
    /// to the REST status vocabulary <c>ok|warn|fail|missing</c>. A fail
    /// whose detail says "not found" surfaces as <c>missing</c> so UIs can
    /// distinguish "not installed" from "installed but broken".
    /// </summary>
    private static string MapStatus(DoctorCheckResult r)
    {
        return r.Status switch
        {
            DoctorCheckStatus.Pass => "ok",
            DoctorCheckStatus.Warn => "warn",
            DoctorCheckStatus.Fail => r.Detail is not null
                && (r.Detail.Contains("not found", StringComparison.OrdinalIgnoreCase)
                    || r.Detail.Contains("missing", StringComparison.OrdinalIgnoreCase))
                ? "missing"
                : "fail",
            _ => "fail",
        };
    }
}
