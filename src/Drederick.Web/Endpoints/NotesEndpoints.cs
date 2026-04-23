using System.Text.Json.Serialization;
using Drederick.Audit;
using Drederick.Reporting;
using Drederick.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Drederick.Web.Endpoints;

/// <summary>
/// REST surface over the <c>notes</c> table in <c>findings.db</c>.
/// Notes are operator prose (observations, flags, credentials the
/// operator jotted by hand) — they are <em>not</em> tool-captured loot,
/// so the audit posture differs from <see cref="FindingsEndpoints"/>:
/// each mutation records a <c>notes.create</c> / <c>notes.delete</c>
/// event carrying only <c>{id, host, tag, length}</c>. The note body is
/// deliberately never hashed or written to the audit stream — hashing
/// operator prose defeats the purpose of having a notebook.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — every
///     mutation (POST / DELETE) writes an audit event with the note id,
///     scope host, tag, and body length. GETs are covered by the
///     ambient <c>web.request</c> middleware event and do not emit a
///     second notes-specific event.</description></item>
///   <item><description><c>@invariant-id:no-plaintext-secrets</c> —
///     note bodies never appear in audit.jsonl in any form (plaintext
///     or digest). Only id / host / tag / length are recorded.</description></item>
///   <item><description>When <c>findings.db</c> is absent, GET endpoints
///     return <c>{status: "no_database"}</c> with HTTP 200 to match the
///     findings-endpoint contract. POST bypasses the check — creating a
///     note is the moment the notebook comes into existence, and
///     <see cref="NotesRepository"/> will bootstrap the schema
///     idempotently.</description></item>
/// </list>
/// </para>
/// </summary>
public static class NotesEndpoints
{
    public static IEndpointRouteBuilder MapNotesEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/notes").WithTags("notes");

        group.MapGet("/", (WebAppSettings settings, string? host, string? tag) =>
        {
            var dbPath = DatabasePath(settings);
            if (!File.Exists(dbPath))
            {
                return Results.Ok(new { status = "no_database", database_path = dbPath });
            }
            var repo = new NotesRepository(dbPath);
            var rows = repo.GetNotes(hostId: host, category: null, includeArchived: false);
            IEnumerable<NoteData> filtered = rows;
            if (!string.IsNullOrEmpty(tag))
            {
                filtered = filtered.Where(n =>
                    !string.IsNullOrEmpty(n.Tags)
                    && n.Tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase)));
            }
            var notes = filtered.Select(NoteDto.From).ToList();
            return Results.Ok(new { notes });
        })
        .WithName("ListNotes")
        .WithOpenApi(op => { op.Summary = "List notes. Optional ?host=<host> and ?tag=<tag> filters."; return op; });

        group.MapGet("/{id:long}", (WebAppSettings settings, long id) =>
        {
            var dbPath = DatabasePath(settings);
            if (!File.Exists(dbPath))
            {
                return Results.Ok(new { status = "no_database", database_path = dbPath });
            }
            var repo = new NotesRepository(dbPath);
            var note = repo.GetNote(id);
            return note is null ? Results.NotFound() : Results.Ok(NoteDto.From(note));
        })
        .WithName("GetNote")
        .WithOpenApi(op => { op.Summary = "Fetch a single note by id. 404 if missing."; return op; });

        group.MapPost("/", (WebAppSettings settings, AuditLog audit, CreateNoteRequest req) =>
        {
            if (req is null || string.IsNullOrWhiteSpace(req.Body))
            {
                return Results.BadRequest(new { error = "body is required" });
            }
            var dbPath = DatabasePath(settings);
            var repo = new NotesRepository(dbPath);
            var title = !string.IsNullOrWhiteSpace(req.Title)
                ? req.Title!.Trim()
                : DeriveTitle(req.Body);
            var id = repo.CreateNote(
                title: title,
                content: req.Body,
                tags: req.Tag,
                category: "note",
                hostId: req.Host,
                source: "ui");

            audit.Record("notes.create", new Dictionary<string, object?>
            {
                ["id"] = id,
                ["host"] = req.Host,
                ["tag"] = req.Tag,
                ["length"] = req.Body.Length,
            });

            var created = repo.GetNote(id);
            return created is null
                ? Results.StatusCode(StatusCodes.Status500InternalServerError)
                : Results.Created($"/api/notes/{id}", NoteDto.From(created));
        })
        .WithName("CreateNote")
        .WithOpenApi(op => { op.Summary = "Create a note. Body: {host?, tag?, body, title?}."; return op; });

        group.MapDelete("/{id:long}", (WebAppSettings settings, AuditLog audit, long id) =>
        {
            var dbPath = DatabasePath(settings);
            if (!File.Exists(dbPath))
            {
                return Results.NotFound();
            }
            var repo = new NotesRepository(dbPath);
            var existing = repo.GetNote(id);
            if (existing is null)
            {
                return Results.NotFound();
            }
            repo.DeleteNote(id);
            audit.Record("notes.delete", new Dictionary<string, object?>
            {
                ["id"] = id,
                ["host"] = existing.HostId,
                ["tag"] = existing.Tags,
                ["length"] = existing.Content?.Length ?? 0,
            });
            return Results.NoContent();
        })
        .WithName("DeleteNote")
        .WithOpenApi(op => { op.Summary = "Delete a note by id. 204 on success, 404 if missing."; return op; });

        return app;
    }

    private static string DatabasePath(WebAppSettings settings) =>
        Path.Combine(settings.OutputDir, "findings.db");

    private static string DeriveTitle(string body)
    {
        var firstLine = body.Split('\n', 2)[0].Trim();
        if (string.IsNullOrEmpty(firstLine)) firstLine = "note";
        return firstLine.Length > 80 ? firstLine[..80] : firstLine;
    }

    public sealed class CreateNoteRequest
    {
        [JsonPropertyName("host")] public string? Host { get; set; }
        [JsonPropertyName("tag")] public string? Tag { get; set; }
        [JsonPropertyName("body")] public string Body { get; set; } = "";
        [JsonPropertyName("title")] public string? Title { get; set; }
    }

    public sealed class NoteDto
    {
        [JsonPropertyName("id")] public long Id { get; set; }
        [JsonPropertyName("host")] public string? Host { get; set; }
        [JsonPropertyName("tag")] public string? Tag { get; set; }
        [JsonPropertyName("title")] public string Title { get; set; } = "";
        [JsonPropertyName("body")] public string? Body { get; set; }
        [JsonPropertyName("created_at")] public string CreatedAt { get; set; } = "";
        [JsonPropertyName("updated_at")] public string UpdatedAt { get; set; } = "";

        public static NoteDto From(NoteData n) => new()
        {
            Id = n.Id,
            Host = n.HostId,
            Tag = n.Tags,
            Title = n.Title,
            Body = n.Content,
            CreatedAt = n.CreatedAt,
            UpdatedAt = n.UpdatedAt,
        };
    }
}
