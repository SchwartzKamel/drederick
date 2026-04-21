using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Drederick.Reporting;

/// <summary>
/// Data access layer for notes stored in findings.db.
/// Supports CRUD operations, file attachments, and search.
/// </summary>
public sealed class NotesRepository
{
    private readonly string _dbPath;

    public NotesRepository(string databasePath)
    {
        if (string.IsNullOrEmpty(databasePath))
        {
            throw new ArgumentException("databasePath is required", nameof(databasePath));
        }
        _dbPath = databasePath;
        EnsureSchema();
    }

    /// <summary>
    /// Ensures the notes table exists. Safe to call repeatedly (idempotent).
    /// Creates the database file if missing so note operations work standalone
    /// before any scan has produced findings.db.
    /// </summary>
    private void EnsureSchema()
    {
        var dir = Path.GetDirectoryName(_dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = NotesSchema.GetCreateTableDdl();
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Creates a new note. Returns the note ID.
    /// </summary>
    public long CreateNote(
        string title,
        string? content = null,
        string? flagFormat = null,
        string? tags = null,
        string? category = "note",
        string? hostId = null,
        long? serviceId = null,
        byte[]? fileData = null,
        string? fileName = null,
        string? fileMimeType = null,
        string? source = "cli")
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            throw new ArgumentException("title cannot be empty", nameof(title));
        }

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO notes (
                title, content, created_at, updated_at, created_by,
                is_flag, flag_format, tags, category, host_id, service_id,
                file_data, file_name, file_mime_type, file_size, source, is_archived
            ) VALUES (
                @title, @content, @created_at, @updated_at, 'operator',
                @is_flag, @flag_format, @tags, @category, @host_id, @service_id,
                @file_data, @file_name, @file_mime_type, @file_size, @source, 0
            )
        ";

        cmd.Parameters.AddWithValue("@title", title);
        cmd.Parameters.AddWithValue("@content", content ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@created_at", DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("@updated_at", DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("@is_flag", !string.IsNullOrEmpty(flagFormat));
        cmd.Parameters.AddWithValue("@flag_format", flagFormat ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@tags", tags ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@category", category ?? "note");
        cmd.Parameters.AddWithValue("@host_id", hostId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@service_id", serviceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@file_data", fileData ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@file_name", fileName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@file_mime_type", fileMimeType ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@file_size", fileData?.Length ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@source", source ?? "cli");

        cmd.ExecuteNonQuery();

        using var idCmd = conn.CreateCommand();
        idCmd.CommandText = "SELECT last_insert_rowid()";
        var result = idCmd.ExecuteScalar();
        return result is long id ? id : throw new InvalidOperationException("Failed to retrieve note ID");
    }

    /// <summary>
    /// Gets a note by ID. Returns null if not found.
    /// </summary>
    public NoteData? GetNote(long noteId)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT
                id, title, content, created_at, updated_at, created_by,
                is_flag, flag_format, tags, category, host_id, service_id,
                file_data, file_name, file_mime_type, file_size, source, is_archived
            FROM notes
            WHERE id = @id
        ";
        cmd.Parameters.AddWithValue("@id", noteId);

        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadNoteFromReader(reader) : null;
    }

    /// <summary>
    /// Gets all notes, optionally filtered by host or category.
    /// </summary>
    public List<NoteData> GetNotes(string? hostId = null, string? category = null, bool includeArchived = false)
    {
        var notes = new List<NoteData>();

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        var query = "SELECT id, title, content, created_at, updated_at, created_by, is_flag, flag_format, tags, category, host_id, service_id, file_data, file_name, file_mime_type, file_size, source, is_archived FROM notes WHERE 1=1";

        if (!includeArchived)
        {
            query += " AND is_archived = 0";
        }
        if (!string.IsNullOrEmpty(hostId))
        {
            query += " AND host_id = @host_id";
            cmd.Parameters.AddWithValue("@host_id", hostId);
        }
        if (!string.IsNullOrEmpty(category))
        {
            query += " AND category = @category";
            cmd.Parameters.AddWithValue("@category", category);
        }

        query += " ORDER BY created_at DESC";
        cmd.CommandText = query;

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            notes.Add(ReadNoteFromReader(reader));
        }

        return notes;
    }

    /// <summary>
    /// Gets all notes marked as flags.
    /// </summary>
    public List<NoteData> GetFlags(bool includeArchived = false)
    {
        var flags = new List<NoteData>();

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        var query = "SELECT id, title, content, created_at, updated_at, created_by, is_flag, flag_format, tags, category, host_id, service_id, file_data, file_name, file_mime_type, file_size, source, is_archived FROM notes WHERE is_flag = 1";

        if (!includeArchived)
        {
            query += " AND is_archived = 0";
        }

        query += " ORDER BY created_at DESC";
        cmd.CommandText = query;

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            flags.Add(ReadNoteFromReader(reader));
        }

        return flags;
    }

    /// <summary>
    /// Searches notes by title/content/tags.
    /// </summary>
    public List<NoteData> SearchNotes(string searchTerm, bool includeArchived = false)
    {
        var results = new List<NoteData>();

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT
                id, title, content, created_at, updated_at, created_by,
                is_flag, flag_format, tags, category, host_id, service_id,
                file_data, file_name, file_mime_type, file_size, source, is_archived
            FROM notes
            WHERE (title LIKE @search OR content LIKE @search OR tags LIKE @search)
        ";

        if (!includeArchived)
        {
            cmd.CommandText += " AND is_archived = 0";
        }

        cmd.CommandText += " ORDER BY created_at DESC";

        var likePattern = $"%{searchTerm}%";
        cmd.Parameters.AddWithValue("@search", likePattern);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadNoteFromReader(reader));
        }

        return results;
    }

    /// <summary>
    /// Updates an existing note.
    /// </summary>
    public void UpdateNote(
        long noteId,
        string? title = null,
        string? content = null,
        string? tags = null,
        string? category = null,
        string? flagFormat = null,
        bool? isArchived = null)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        var updates = new List<string>();
        var parameters = new Dictionary<string, object>();

        if (!string.IsNullOrEmpty(title))
        {
            updates.Add("title = @title");
            parameters["@title"] = title;
        }
        if (content != null)
        {
            updates.Add("content = @content");
            parameters["@content"] = content;
        }
        if (tags != null)
        {
            updates.Add("tags = @tags");
            parameters["@tags"] = tags;
        }
        if (!string.IsNullOrEmpty(category))
        {
            updates.Add("category = @category");
            parameters["@category"] = category;
        }
        if (!string.IsNullOrEmpty(flagFormat))
        {
            updates.Add("flag_format = @flag_format");
            updates.Add("is_flag = 1");
            parameters["@flag_format"] = flagFormat;
        }
        if (isArchived.HasValue)
        {
            updates.Add("is_archived = @is_archived");
            parameters["@is_archived"] = isArchived.Value ? 1 : 0;
        }

        if (updates.Count == 0)
        {
            return;
        }

        updates.Add("updated_at = @updated_at");
        parameters["@updated_at"] = DateTime.UtcNow.ToString("o");

        cmd.CommandText = $"UPDATE notes SET {string.Join(", ", updates)} WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", noteId);

        foreach (var (key, value) in parameters)
        {
            cmd.Parameters.AddWithValue(key, value);
        }

        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Archives a note (soft delete).
    /// </summary>
    public void ArchiveNote(long noteId)
    {
        UpdateNote(noteId, isArchived: true);
    }

    /// <summary>
    /// Permanently deletes a note (hard delete).
    /// </summary>
    public void DeleteNote(long noteId)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM notes WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", noteId);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Gets the file attachment for a note, if any.
    /// </summary>
    public (byte[] data, string fileName, string mimeType)? GetNoteAttachment(long noteId)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT file_data, file_name, file_mime_type FROM notes WHERE id = @id AND file_data IS NOT NULL";
        cmd.Parameters.AddWithValue("@id", noteId);

        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            var data = (byte[])reader["file_data"];
            var fileName = (string)reader["file_name"];
            var mimeType = (string)reader["file_mime_type"];
            return (data, fileName, mimeType);
        }

        return null;
    }

    /// <summary>
    /// Updates the file attachment for a note.
    /// </summary>
    public void UpdateNoteAttachment(long noteId, byte[] fileData, string fileName, string mimeType)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE notes
            SET file_data = @file_data, file_name = @file_name, file_mime_type = @file_mime_type, file_size = @file_size, updated_at = @updated_at
            WHERE id = @id
        ";
        cmd.Parameters.AddWithValue("@id", noteId);
        cmd.Parameters.AddWithValue("@file_data", fileData);
        cmd.Parameters.AddWithValue("@file_name", fileName);
        cmd.Parameters.AddWithValue("@file_mime_type", mimeType);
        cmd.Parameters.AddWithValue("@file_size", fileData.Length);
        cmd.Parameters.AddWithValue("@updated_at", DateTime.UtcNow.ToString("o"));

        cmd.ExecuteNonQuery();
    }

    private static NoteData ReadNoteFromReader(SqliteDataReader reader)
    {
        return new NoteData
        {
            Id = (long)reader["id"],
            Title = (string)reader["title"],
            Content = reader["content"] is DBNull ? null : (string)reader["content"],
            CreatedAt = (string)reader["created_at"],
            UpdatedAt = (string)reader["updated_at"],
            CreatedBy = (string)reader["created_by"],
            IsFlag = reader["is_flag"] is long isFlag && isFlag == 1,
            FlagFormat = reader["flag_format"] is DBNull ? null : (string)reader["flag_format"],
            Tags = reader["tags"] is DBNull ? null : (string)reader["tags"],
            Category = (string)reader["category"],
            HostId = reader["host_id"] is DBNull ? null : (string)reader["host_id"],
            ServiceId = reader["service_id"] is DBNull ? null : (long)reader["service_id"],
            FileName = reader["file_name"] is DBNull ? null : (string)reader["file_name"],
            FileMimeType = reader["file_mime_type"] is DBNull ? null : (string)reader["file_mime_type"],
            FileSize = reader["file_size"] is DBNull ? null : (long)reader["file_size"],
            Source = (string)reader["source"],
            IsArchived = reader["is_archived"] is long archived && archived == 1,
        };
    }
}

/// <summary>
/// Represents a note in findings.db.
/// </summary>
public class NoteData
{
    public long Id { get; set; }
    public string Title { get; set; } = "";
    public string? Content { get; set; }
    public string CreatedAt { get; set; } = "";
    public string UpdatedAt { get; set; } = "";
    public string CreatedBy { get; set; } = "operator";
    public bool IsFlag { get; set; }
    public string? FlagFormat { get; set; }
    public string? Tags { get; set; }
    public string Category { get; set; } = "note";
    public string? HostId { get; set; }
    public long? ServiceId { get; set; }
    public string? FileName { get; set; }
    public string? FileMimeType { get; set; }
    public long? FileSize { get; set; }
    public string Source { get; set; } = "cli";
    public bool IsArchived { get; set; }
}
