using System.IO;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using Drederick.Audit;
using Drederick.Scope;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// Read-only scope endpoints.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:scope-file-read-only</c> —
///     <b>code never writes to the scope file.</b> These endpoints load
///     and validate; they never mutate. Do not add a PUT/POST/DELETE that
///     edits the scope file.</description></item>
///   <item><description><c>@invariant-id:scope-default-deny</c> — the
///     validator delegates to <see cref="Scope.Require"/>, inheriting all
///     default-deny / prefix-cap / wildcard-refusal semantics.
///     </description></item>
///   <item><description><c>@invariant-id:audit-everything</c> — every
///     scope view and validate operation records <c>web.scope.view</c>
///     or <c>web.scope.validate</c>.</description></item>
/// </list>
/// </para>
/// </summary>
public static class ScopeEndpoints
{
    public sealed record ValidateRequest(
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("proposed_targets")] string[] ProposedTargets);

    public static IEndpointRouteBuilder MapScopeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/scope", (HttpContext ctx, AuditLog audit, string? path) =>
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return Results.BadRequest(new { error = "query parameter 'path' is required" });
            }
            if (!TryResolveSafePath(path, out var resolved, out var reason))
            {
                audit.Record("web.scope.view", new Dictionary<string, object?>
                {
                    ["path"] = path,
                    ["result"] = "rejected",
                    ["reason"] = reason,
                });
                return Results.BadRequest(new { error = reason });
            }

            try
            {
                // Load lab-mode defaults — strict-cap warnings are surfaced
                // below rather than throwing.
                var warnings = new List<string>();
                Scope.Scope? scope = null;
                string mode = "lab";
                try
                {
                    scope = ScopeLoader.LoadFile(resolved, allowBroad: false, labMode: true);
                }
                catch (ScopeException labEx)
                {
                    warnings.Add($"lab-mode load refused: {labEx.Message}");
                    // Try with allowBroad so we can still show the operator
                    // what's in the file (view-only; no enforcement bypass).
                    scope = ScopeLoader.LoadFile(resolved, allowBroad: true, labMode: true);
                    warnings.Add("displayed with allow_broad=true for visibility; " +
                                 "an actual run with this file would be refused.");
                }

                var entries = scope.Entries.Select(e => new
                {
                    cidr_or_ip = e.ToString(),
                    family = e.Family == AddressFamily.InterNetwork ? "v4" : "v6",
                    prefix_length = e.PrefixLength,
                }).ToArray();

                audit.Record("web.scope.view", new Dictionary<string, object?>
                {
                    ["path"] = resolved,
                    ["entry_count"] = entries.Length,
                    ["warnings"] = warnings.Count,
                });

                return Results.Ok(new
                {
                    path = resolved,
                    entries,
                    warnings,
                    mode,
                });
            }
            catch (ScopeException ex)
            {
                audit.Record("web.scope.view", new Dictionary<string, object?>
                {
                    ["path"] = resolved,
                    ["result"] = "load_failed",
                    ["reason"] = ex.Message,
                });
                return Results.BadRequest(new { error = ex.Message });
            }
            catch (FileNotFoundException)
            {
                return Results.NotFound(new { error = "scope file not found" });
            }
        })
        .WithName("GetScope")
        .WithTags("scope")
        .WithSummary("READ-ONLY scope file viewer. Never writes the scope file.");

        app.MapPost("/api/scope/validate", async (HttpContext ctx, AuditLog audit) =>
        {
            ValidateRequest? req;
            try
            {
                req = await ctx.Request.ReadFromJsonAsync<ValidateRequest>();
            }
            catch
            {
                return Results.BadRequest(new { error = "invalid JSON body" });
            }
            if (req is null || string.IsNullOrWhiteSpace(req.Path) || req.ProposedTargets is null)
            {
                return Results.BadRequest(new { error = "body must be { path, proposed_targets: [] }" });
            }
            if (!TryResolveSafePath(req.Path, out var resolved, out var reason))
            {
                audit.Record("web.scope.validate", new Dictionary<string, object?>
                {
                    ["path"] = req.Path,
                    ["result"] = "rejected_path",
                    ["reason"] = reason,
                });
                return Results.BadRequest(new { error = reason });
            }

            Scope.Scope scope;
            try
            {
                scope = ScopeLoader.LoadFile(resolved, allowBroad: false, labMode: true);
            }
            catch (ScopeException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
            catch (FileNotFoundException)
            {
                return Results.NotFound(new { error = "scope file not found" });
            }

            var accepted = new List<string>();
            var rejected = new List<object>();
            foreach (var t in req.ProposedTargets)
            {
                if (string.IsNullOrWhiteSpace(t))
                {
                    rejected.Add(new { target = t, reason = "empty target" });
                    continue;
                }
                try
                {
                    scope.Require(t);
                    accepted.Add(t);
                }
                catch (ScopeException ex)
                {
                    rejected.Add(new { target = t, reason = ex.Message });
                }
            }

            audit.Record("web.scope.validate", new Dictionary<string, object?>
            {
                ["path"] = resolved,
                ["proposed"] = req.ProposedTargets.Length,
                ["accepted"] = accepted.Count,
                ["rejected"] = rejected.Count,
            });

            return Results.Ok(new { accepted, rejected });
        })
        .WithName("PostScopeValidate")
        .WithTags("scope")
        .WithSummary("READ-ONLY scope validator — checks proposed targets against scope file without mutating it.");

        return app;
    }

    /// <summary>
    /// Resolve a user-supplied path to an absolute path under the current
    /// working directory. Rejects traversal (<c>..</c>) that escapes cwd.
    /// </summary>
    internal static bool TryResolveSafePath(string input, out string resolved, out string reason)
    {
        resolved = string.Empty;
        reason = string.Empty;
        try
        {
            var cwd = Path.GetFullPath(Directory.GetCurrentDirectory());
            var full = Path.GetFullPath(input, cwd);
            // Must be within cwd.
            var cwdNorm = cwd.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            if (!full.StartsWith(cwdNorm, StringComparison.Ordinal) && full != cwd)
            {
                reason = "path must be within the current working directory";
                return false;
            }
            resolved = full;
            return true;
        }
        catch (Exception ex)
        {
            reason = $"invalid path: {ex.Message}";
            return false;
        }
    }
}
