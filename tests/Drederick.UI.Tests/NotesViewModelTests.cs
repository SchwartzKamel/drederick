using Drederick.Reporting;
using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Tests for <see cref="NotesViewModel"/>. Exercises CRUD operations,
/// search, and filtering against a test instance of <c>findings.db</c>.
/// </summary>
public class NotesViewModelTests
{
    [Fact]
    public async Task LoadNotesAsync_with_no_database_sets_error_status()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);
            var vm = new NotesViewModel { OutputDir = tmp };
            await vm.LoadNotesCommand.ExecuteAsync(null);

            Assert.Empty(vm.NotesList);
            Assert.Contains("No database", vm.Status);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task CreateNote_adds_note_to_database_and_refreshes_list()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            // Initialize findings.db via SqliteReport
            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var vm = new NotesViewModel { OutputDir = tmp };
            vm.Title = "Test Note";
            vm.Content = "This is a test note";
            vm.Category = "flag";
            vm.Tags = "test,important";

            await vm.CreateNoteCommand.ExecuteAsync(null);

            Assert.NotEmpty(vm.NotesList);
            Assert.Single(vm.NotesList);
            Assert.Equal("Test Note", vm.NotesList[0].Title);
            Assert.Equal("flag", vm.NotesList[0].Category);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task CreateFlaggedNote_sets_flag_properties()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var vm = new NotesViewModel { OutputDir = tmp };
            vm.Title = "Critical Issue";
            vm.Content = "Requires immediate action";
            vm.IsFlag = true;
            vm.FlagFormat = "CRITICAL";

            await vm.CreateNoteCommand.ExecuteAsync(null);

            Assert.NotEmpty(vm.NotesList);
            var note = vm.NotesList[0];
            Assert.True(note.IsFlag);
            Assert.Equal("CRITICAL", note.FlagFormat);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task SearchNotesAsync_filters_by_title_and_content()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            // Create multiple notes
            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            repo.CreateNote("First Note", "About SSH", tags: "network");
            repo.CreateNote("Second Note", "About HTTP", tags: "web");

            var vm = new NotesViewModel { OutputDir = tmp };
            vm.SearchTerm = "SSH";

            await vm.SearchNotesCommand.ExecuteAsync(null);

            Assert.Single(vm.NotesList);
            Assert.Equal("First Note", vm.NotesList[0].Title);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task GetFlagsAsync_returns_only_flagged_notes()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            repo.CreateNote("Regular Note", "Not flagged");
            repo.CreateNote("Flagged Note", "This is flagged", flagFormat: "TODO");

            var vm = new NotesViewModel { OutputDir = tmp };

            await vm.GetFlagsCommand.ExecuteAsync(null);

            Assert.Single(vm.NotesList);
            Assert.True(vm.NotesList[0].IsFlag);
            Assert.Equal("TODO", vm.NotesList[0].FlagFormat);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task UpdateNoteAsync_modifies_selected_note_and_refreshes()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            repo.CreateNote("Original Title", "Original content");

            var vm = new NotesViewModel { OutputDir = tmp };
            await vm.LoadNotesCommand.ExecuteAsync(null);

            var note = vm.NotesList[0];
            vm.SelectedNote = note;

            vm.Title = "Updated Title";
            vm.Content = "Updated content";

            await vm.UpdateNoteCommand.ExecuteAsync(null);

            await vm.LoadNotesCommand.ExecuteAsync(null);
            Assert.Single(vm.NotesList);
            Assert.Equal("Updated Title", vm.NotesList[0].Title);
            Assert.Equal("Updated content", vm.NotesList[0].Content);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task DeleteNoteAsync_removes_note_from_database()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            repo.CreateNote("To Delete", "Will be removed");

            var vm = new NotesViewModel { OutputDir = tmp };
            await vm.LoadNotesCommand.ExecuteAsync(null);

            vm.SelectedNote = vm.NotesList[0];
            await vm.DeleteNoteCommand.ExecuteAsync(null);

            await vm.LoadNotesCommand.ExecuteAsync(null);
            Assert.Empty(vm.NotesList);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task ArchiveNoteAsync_soft_deletes_note()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            repo.CreateNote("To Archive", "Will be archived");

            var vm = new NotesViewModel { OutputDir = tmp };
            await vm.LoadNotesCommand.ExecuteAsync(null);

            vm.SelectedNote = vm.NotesList[0];
            await vm.ArchiveNoteCommand.ExecuteAsync(null);

            await vm.LoadNotesCommand.ExecuteAsync(null);
            Assert.Empty(vm.NotesList);

            // But the record still exists when includeArchived=true
            var archived = repo.GetNotes(includeArchived: true);
            Assert.Single(archived);
            Assert.True(archived[0].IsArchived);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void SelectedNoteChanged_populates_form_fields()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-notes-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            report.WriteReport(new[] { hf });

            var repo = new NotesRepository(Path.Combine(tmp, "findings.db"));
            var noteId = repo.CreateNote("Test Note", "Test Content", tags: "urgent,important", category: "flag");
            var note = repo.GetNote(noteId);

            var vm = new NotesViewModel { OutputDir = tmp };
            vm.SelectedNote = note;

            Assert.Equal("Test Note", vm.Title);
            Assert.Equal("Test Content", vm.Content);
            Assert.Equal("urgent,important", vm.Tags);
            Assert.Equal("flag", vm.Category);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }
}
