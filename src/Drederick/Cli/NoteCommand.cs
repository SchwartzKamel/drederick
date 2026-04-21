using Drederick.Reporting;
using System.Text.Json;

namespace Drederick.Cli;

/// <summary>
/// Handles the 'drederick note' subcommands for managing CTF notes.
/// Subcommands: add, list, view, archive, delete
/// </summary>
public sealed class NoteCommand
{
    private readonly NotesRepository _repo;
    private readonly TextWriter _out;
    private readonly TextWriter _err;

    public NoteCommand(string databasePath, TextWriter? outWriter = null, TextWriter? errWriter = null)
    {
        if (string.IsNullOrEmpty(databasePath))
        {
            throw new ArgumentException("databasePath is required", nameof(databasePath));
        }

        _repo = new NotesRepository(databasePath);
        _out = outWriter ?? Console.Out;
        _err = errWriter ?? Console.Error;
    }

    /// <summary>
    /// Executes a note subcommand. Returns exit code: 0 on success, 1 on error, 2 on validation failure.
    /// </summary>
    public int Execute(CommandLineOptions opts)
    {
        try
        {
            return opts.NoteSubcommand switch
            {
                "add" => ExecuteAdd(opts),
                "list" => ExecuteList(opts),
                "view" => ExecuteView(opts),
                "archive" => ExecuteArchive(opts),
                "delete" => ExecuteDelete(opts),
                "flags" => ExecuteFlags(opts),
                "search" => ExecuteSearch(opts),
                _ => ExecuteHelp()
            };
        }
        catch (Exception ex)
        {
            _err.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private int ExecuteAdd(CommandLineOptions opts)
    {
        if (string.IsNullOrEmpty(opts.NoteTitle))
        {
            _err.WriteLine("note add: --title is required");
            return 2;
        }

        byte[]? fileData = null;
        string? fileName = null;
        string? fileMimeType = null;

        if (!string.IsNullOrEmpty(opts.NoteFile))
        {
            if (!File.Exists(opts.NoteFile))
            {
                _err.WriteLine($"note add: file not found: {opts.NoteFile}");
                return 2;
            }

            fileData = File.ReadAllBytes(opts.NoteFile);
            fileName = Path.GetFileName(opts.NoteFile);
            fileMimeType = GuessContentType(opts.NoteFile);
        }

        var id = _repo.CreateNote(
            title: opts.NoteTitle,
            content: opts.NoteContent,
            flagFormat: opts.NoteFlag,
            tags: opts.NoteTags,
            category: opts.NoteCategory ?? "note",
            hostId: opts.NoteHost,
            fileData: fileData,
            fileName: fileName,
            fileMimeType: fileMimeType,
            source: "cli"
        );

        if (opts.NoteJson)
        {
            var note = _repo.GetNote(id);
            _out.WriteLine(JsonSerializer.Serialize(note, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            _out.WriteLine($"✓ Created note #{id}: {opts.NoteTitle}");
            if (!string.IsNullOrEmpty(opts.NoteTags))
                _out.WriteLine($"  Tags: {opts.NoteTags}");
            if (opts.NoteFlag != null)
                _out.WriteLine($"  Flag: {opts.NoteFlag}");
            if (fileData != null)
                _out.WriteLine($"  Attachment: {fileName} ({fileData.Length} bytes)");
        }

        return 0;
    }

    private int ExecuteList(CommandLineOptions opts)
    {
        var notes = _repo.GetNotes(
            hostId: opts.NoteHost,
            category: opts.NoteCategory,
            includeArchived: opts.NoteIncludeArchived
        );

        if (opts.NoteJson)
        {
            _out.WriteLine(JsonSerializer.Serialize(notes, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            if (notes.Count == 0)
            {
                _out.WriteLine("No notes found");
                return 0;
            }

            foreach (var note in notes)
            {
                _out.WriteLine($"[#{note.Id}] {note.Title}");
                if (!string.IsNullOrEmpty(note.Tags))
                    _out.WriteLine($"     Tags: {note.Tags}");
                if (note.IsFlag)
                    _out.WriteLine($"     📍 FLAG ({note.FlagFormat})");
                if (note.FileName != null)
                    _out.WriteLine($"     📎 {note.FileName} ({note.FileSize} bytes)");
                _out.WriteLine($"     Category: {note.Category} | Created: {note.CreatedAt}");
                _out.WriteLine();
            }
        }

        return 0;
    }

    private int ExecuteView(CommandLineOptions opts)
    {
        if (!long.TryParse(opts.NoteId, out var noteId))
        {
            _err.WriteLine("note view: invalid note ID");
            return 2;
        }

        var note = _repo.GetNote(noteId);
        if (note == null)
        {
            _err.WriteLine($"note view: note #{noteId} not found");
            return 2;
        }

        if (opts.NoteJson)
        {
            _out.WriteLine(JsonSerializer.Serialize(note, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            _out.WriteLine($"Note #{note.Id}: {note.Title}");
            _out.WriteLine($"Category: {note.Category}");
            _out.WriteLine($"Created: {note.CreatedAt} by {note.CreatedBy}");
            _out.WriteLine($"Updated: {note.UpdatedAt}");

            if (!string.IsNullOrEmpty(note.Tags))
                _out.WriteLine($"Tags: {note.Tags}");
            if (!string.IsNullOrEmpty(note.HostId))
                _out.WriteLine($"Host: {note.HostId}");
            if (note.IsFlag)
                _out.WriteLine($"Flag Format: {note.FlagFormat}");

            _out.WriteLine();
            if (!string.IsNullOrEmpty(note.Content))
            {
                _out.WriteLine("Content:");
                _out.WriteLine(note.Content);
            }

            if (note.FileName != null)
            {
                _out.WriteLine();
                _out.WriteLine($"Attachment: {note.FileName}");
                _out.WriteLine($"  MIME Type: {note.FileMimeType}");
                _out.WriteLine($"  Size: {note.FileSize} bytes");
            }
        }

        return 0;
    }

    private int ExecuteArchive(CommandLineOptions opts)
    {
        if (!long.TryParse(opts.NoteId, out var noteId))
        {
            _err.WriteLine("note archive: invalid note ID");
            return 2;
        }

        var note = _repo.GetNote(noteId);
        if (note == null)
        {
            _err.WriteLine($"note archive: note #{noteId} not found");
            return 2;
        }

        _repo.ArchiveNote(noteId);
        _out.WriteLine($"✓ Archived note #{noteId}");

        return 0;
    }

    private int ExecuteDelete(CommandLineOptions opts)
    {
        if (!long.TryParse(opts.NoteId, out var noteId))
        {
            _err.WriteLine("note delete: invalid note ID");
            return 2;
        }

        var note = _repo.GetNote(noteId);
        if (note == null)
        {
            _err.WriteLine($"note delete: note #{noteId} not found");
            return 2;
        }

        _repo.DeleteNote(noteId);
        _out.WriteLine($"✓ Deleted note #{noteId}");

        return 0;
    }

    private int ExecuteFlags(CommandLineOptions opts)
    {
        var flags = _repo.GetFlags(includeArchived: opts.NoteIncludeArchived);

        if (opts.NoteJson)
        {
            _out.WriteLine(JsonSerializer.Serialize(flags, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            if (flags.Count == 0)
            {
                _out.WriteLine("No flags captured yet");
                return 0;
            }

            _out.WriteLine($"📍 {flags.Count} flags captured:");
            _out.WriteLine();

            foreach (var flag in flags)
            {
                _out.WriteLine($"[#{flag.Id}] {flag.Title}");
                _out.WriteLine($"     Format: {flag.FlagFormat}");
                if (!string.IsNullOrEmpty(flag.HostId))
                    _out.WriteLine($"     From: {flag.HostId}");
                if (!string.IsNullOrEmpty(flag.Tags))
                    _out.WriteLine($"     Tags: {flag.Tags}");
                _out.WriteLine($"     Captured: {flag.CreatedAt}");
                _out.WriteLine();
            }
        }

        return 0;
    }

    private int ExecuteSearch(CommandLineOptions opts)
    {
        if (string.IsNullOrEmpty(opts.NoteSearch))
        {
            _err.WriteLine("note search: search term required");
            return 2;
        }

        var results = _repo.SearchNotes(opts.NoteSearch, includeArchived: opts.NoteIncludeArchived);

        if (opts.NoteJson)
        {
            _out.WriteLine(JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            if (results.Count == 0)
            {
                _out.WriteLine($"No notes found matching: {opts.NoteSearch}");
                return 0;
            }

            _out.WriteLine($"Found {results.Count} notes matching '{opts.NoteSearch}':");
            _out.WriteLine();

            foreach (var note in results)
            {
                _out.WriteLine($"[#{note.Id}] {note.Title}");
                if (!string.IsNullOrEmpty(note.Content) && note.Content.Length > 100)
                    _out.WriteLine($"     {note.Content.Substring(0, 100)}...");
                else if (!string.IsNullOrEmpty(note.Content))
                    _out.WriteLine($"     {note.Content}");
                _out.WriteLine();
            }
        }

        return 0;
    }

    private int ExecuteHelp()
    {
        _out.WriteLine("drederick note - Manage CTF notes and flags");
        _out.WriteLine();
        _out.WriteLine("Subcommands:");
        _out.WriteLine("  add [options]        Create a new note");
        _out.WriteLine("  list [options]       List all notes");
        _out.WriteLine("  view <id>            View a note in detail");
        _out.WriteLine("  archive <id>         Archive a note");
        _out.WriteLine("  delete <id>          Delete a note permanently");
        _out.WriteLine("  flags [options]      List all captured flags");
        _out.WriteLine("  search <term>        Search notes by content");
        _out.WriteLine();
        _out.WriteLine("Options for 'add':");
        _out.WriteLine("  --title <text>      Note title (required)");
        _out.WriteLine("  --content <text>    Note content");
        _out.WriteLine("  --flag <format>     Mark as flag (e.g. HTB, CTF)");
        _out.WriteLine("  --tags <csv>        Comma-separated tags");
        _out.WriteLine("  --category <type>   Category: flag, credential, exploit, screenshot, command, note");
        _out.WriteLine("  --host <ip>         Associated host IP");
        _out.WriteLine("  --file <path>       Attach a file");
        _out.WriteLine("  --json               Output as JSON");
        _out.WriteLine();
        _out.WriteLine("Options for 'list', 'flags':");
        _out.WriteLine("  --host <ip>         Filter by host");
        _out.WriteLine("  --category <type>   Filter by category");
        _out.WriteLine("  --archived          Include archived notes");
        _out.WriteLine("  --json               Output as JSON");
        _out.WriteLine();
        _out.WriteLine("Examples:");
        _out.WriteLine("  drederick note add --title \"My Flag\" --flag HTB --content \"HTB{flag123}\"");
        _out.WriteLine("  drederick note list --host 10.0.0.1");
        _out.WriteLine("  drederick note flags");
        _out.WriteLine("  drederick note search \"password\"");

        return 0;
    }

    private static string GuessContentType(string filePath)
    {
        return Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".txt" => "text/plain",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            ".json" => "application/json",
            _ => "application/octet-stream"
        };
    }
}
