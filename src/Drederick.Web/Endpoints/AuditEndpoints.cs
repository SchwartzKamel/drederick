using System.Text.Json;
using Drederick.Audit;
using Drederick.Web.Auditing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// Read-only endpoints exposing <c>audit.jsonl</c> via filtered tail.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — these
///     endpoints themselves emit <c>web.audit.query</c> events.</description></item>
///   <item><description><c>@invariant-id:no-exfiltration</c> — the audit
///     file is read only. No endpoint in this group writes to, truncates,
///     or deletes <c>audit.jsonl</c>.</description></item>
///   <item><description><c>@invariant-id:no-plaintext-secrets</c> — entries
///     are canary-scanned before being returned. A canary hit means a
///     producer upstream skipped the SHA-256 step; the offending line is
///     dropped and a warning is logged.</description></item>
/// </list>
/// </para>
/// </summary>
public static class AuditEndpoints
{
    private const int DefaultLimit = 100;
    private const int MaxLimit = 1000;

    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/audit/tail", (
            HttpContext ctx,
            AuditTailer tailer,
            AuditLog audit,
            string? since,
            int? limit,
            string? category) =>
        {
            var clampedLimit = Math.Clamp(limit ?? DefaultLimit, 1, MaxLimit);
            DateTimeOffset? sinceParsed = null;
            if (!string.IsNullOrEmpty(since))
            {
                if (!DateTimeOffset.TryParse(since, out var parsed))
                {
                    return Results.BadRequest(new { error = "since must be an ISO-8601 timestamp" });
                }
                sinceParsed = parsed;
            }

            var query = new AuditTailer.TailQuery(sinceParsed, clampedLimit, category);
            var entries = tailer.Read(query);

            var redactedCount = 0;
            var safe = new List<object>(entries.Count);
            foreach (var e in entries)
            {
                if (e.RedactionWarning)
                {
                    redactedCount++;
                    // Never pass plaintext through. Emit a minimal stand-in
                    // so the UI can show "N entries redacted" without
                    // leaking what was in them.
                    safe.Add(new
                    {
                        ts = e.Timestamp?.ToString("o"),
                        @event = e.EventType,
                        redacted = true,
                        reason = "plaintext canary detected — see server logs",
                    });
                    continue;
                }
                safe.Add(JsonSerializer.Deserialize<JsonElement>(e.Raw.GetRawText()));
            }

            audit.Record("web.audit.query", new Dictionary<string, object?>
            {
                ["since"] = sinceParsed?.ToString("o"),
                ["limit"] = clampedLimit,
                ["category"] = category,
                ["returned"] = safe.Count,
                ["redacted"] = redactedCount,
            });

            if (redactedCount > 0)
            {
                // Leave a breadcrumb in the audit file itself so operators
                // notice the upstream bug.
                audit.Record("web.audit.redaction_warning", new Dictionary<string, object?>
                {
                    ["count"] = redactedCount,
                });
            }

            return Results.Ok(new
            {
                entries = safe,
                count = safe.Count,
                redacted = redactedCount,
            });
        })
        .WithName("GetAuditTail")
        .WithTags("audit")
        .WithSummary("Read-only tail of audit.jsonl. Never writes.");

        app.MapGet("/api/audit/categories", (AuditTailer tailer, AuditLog audit) =>
        {
            var (prefixes, events) = tailer.Categories();
            audit.Record("web.audit.query", new Dictionary<string, object?>
            {
                ["kind"] = "categories",
                ["prefix_count"] = prefixes.Count,
                ["event_count"] = events.Count,
            });
            return Results.Ok(new { prefixes, events });
        })
        .WithName("GetAuditCategories")
        .WithTags("audit")
        .WithSummary("Distinct event-type prefixes and event names for UI filters.");

        return app;
    }
}
