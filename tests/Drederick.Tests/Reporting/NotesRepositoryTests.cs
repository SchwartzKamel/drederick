using Drederick.Reporting;
using Xunit;
using Microsoft.Data.Sqlite;

namespace Drederick.Tests.Reporting;

public class NotesRepositoryTests : IDisposable
{
    private readonly string _testDir;
    private readonly NotesRepository _repo;

    public NotesRepositoryTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"drederick-notes-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_testDir);

        var dbPath = Path.Combine(_testDir, "findings.db");
        InitializeDatabase(dbPath);
        _repo = new NotesRepository(dbPath);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, recursive: true);
            }
        }
        catch { }
    }

    private static void InitializeDatabase(string dbPath)
    {
        using (var conn = new SqliteConnection($"Data Source={dbPath}"))
        {
            conn.Open();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = NotesSchema.GetCreateTableDdl();
                cmd.ExecuteNonQuery();
            }
        }
    }

    [Fact]
    public void CreateNote_WithMinimalInfo_ReturnsValidId()
    {
        var id = _repo.CreateNote("Test Note");
        Assert.True(id > 0);
    }

    [Fact]
    public void CreateNote_WithEmptyTitle_Throws()
    {
        Assert.Throws<ArgumentException>(() => _repo.CreateNote(""));
    }

    [Fact]
    public void GetNote_WithInvalidId_ReturnsNull()
    {
        var note = _repo.GetNote(9999);
        Assert.Null(note);
    }

    [Fact]
    public void CreateNote_WithAllFields_StoresCorrectly()
    {
        var id = _repo.CreateNote(
            title: "My Flag",
            content: "HTB{flag123}",
            flagFormat: "HTB",
            tags: "web,easy",
            category: "flag",
            hostId: "192.168.1.1"
        );

        var note = _repo.GetNote(id);

        Assert.NotNull(note);
        Assert.Equal("My Flag", note.Title);
        Assert.Equal("HTB{flag123}", note.Content);
        Assert.True(note.IsFlag);
        Assert.Equal("HTB", note.FlagFormat);
        Assert.Equal("web,easy", note.Tags);
        Assert.Equal("flag", note.Category);
        Assert.Equal("192.168.1.1", note.HostId);
    }

    [Fact]
    public void GetNotes_ReturnsAllNotes()
    {
        _repo.CreateNote("Note 1");
        _repo.CreateNote("Note 2");
        _repo.CreateNote("Note 3");

        var notes = _repo.GetNotes();

        Assert.Equal(3, notes.Count);
    }

    [Fact]
    public void GetNotes_FilteredByCategory_ReturnsMatching()
    {
        _repo.CreateNote("Flag 1", category: "flag");
        _repo.CreateNote("Cred 1", category: "credential");
        _repo.CreateNote("Flag 2", category: "flag");

        var flags = _repo.GetNotes(category: "flag");

        Assert.Equal(2, flags.Count);
        Assert.All(flags, n => Assert.Equal("flag", n.Category));
    }

    [Fact]
    public void GetNotes_FilteredByHost_ReturnsMatching()
    {
        _repo.CreateNote("Note 1", hostId: "10.0.0.1");
        _repo.CreateNote("Note 2", hostId: "10.0.0.2");
        _repo.CreateNote("Note 3", hostId: "10.0.0.1");

        var hostNotes = _repo.GetNotes(hostId: "10.0.0.1");

        Assert.Equal(2, hostNotes.Count);
        Assert.All(hostNotes, n => Assert.Equal("10.0.0.1", n.HostId));
    }

    [Fact]
    public void GetFlags_ReturnsOnlyFlags()
    {
        _repo.CreateNote("Note", category: "note");
        _repo.CreateNote("Flag 1", flagFormat: "HTB", category: "flag");
        _repo.CreateNote("Flag 2", flagFormat: "HTB", category: "flag");

        var flags = _repo.GetFlags();

        Assert.Equal(2, flags.Count);
        Assert.All(flags, f => Assert.True(f.IsFlag));
    }

    [Fact]
    public void SearchNotes_FindsMatchInTitle()
    {
        _repo.CreateNote("Important findings");
        _repo.CreateNote("Random note");
        _repo.CreateNote("More findings");

        var results = _repo.SearchNotes("findings");

        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void UpdateNote_ModifiesFields()
    {
        var id = _repo.CreateNote("Original Title", content: "Original content");
        _repo.UpdateNote(id, title: "Updated Title", content: "Updated content");

        var note = _repo.GetNote(id);

        Assert.Equal("Updated Title", note!.Title);
        Assert.Equal("Updated content", note.Content);
    }

    [Fact]
    public void ArchiveNote_SetsIsArchived()
    {
        var id = _repo.CreateNote("Note");
        _repo.ArchiveNote(id);

        var note = _repo.GetNote(id);

        Assert.True(note!.IsArchived);
    }

    [Fact]
    public void DeleteNote_RemovesFromDatabase()
    {
        var id = _repo.CreateNote("To Delete");
        Assert.NotNull(_repo.GetNote(id));

        _repo.DeleteNote(id);

        var note = _repo.GetNote(id);
        Assert.Null(note);
    }

    [Fact]
    public void CreateNote_WithFileAttachment_StoresCorrectly()
    {
        var fileData = new byte[] { 0x89, 0x50, 0x4E, 0x47 };
        var id = _repo.CreateNote(
            title: "Screenshot",
            fileData: fileData,
            fileName: "capture.png",
            fileMimeType: "image/png"
        );

        var note = _repo.GetNote(id);

        Assert.NotNull(note);
        Assert.Equal("capture.png", note.FileName);
        Assert.Equal("image/png", note.FileMimeType);
        Assert.Equal(4, note.FileSize);
    }

    [Fact]
    public void GetNoteAttachment_ReturnsFileData()
    {
        var fileData = new byte[] { 1, 2, 3, 4, 5 };
        var id = _repo.CreateNote(
            "Screenshot",
            fileData: fileData,
            fileName: "test.png",
            fileMimeType: "image/png"
        );

        var attachment = _repo.GetNoteAttachment(id);

        Assert.NotNull(attachment);
        Assert.Equal(fileData, attachment.Value.data);
        Assert.Equal("test.png", attachment.Value.fileName);
        Assert.Equal("image/png", attachment.Value.mimeType);
    }

    [Fact]
    public void CreateNote_TimestampsAreSet()
    {
        var id = _repo.CreateNote("Timestamped");
        var note = _repo.GetNote(id);

        Assert.NotNull(note);
        Assert.NotEmpty(note.CreatedAt);
        Assert.NotEmpty(note.UpdatedAt);
    }
}
