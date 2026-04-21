using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Reporting;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Notes tab. Provides CRUD operations for notes stored in findings.db,
/// including search, filtering by flags, and attachment metadata display.
/// </summary>
public sealed partial class NotesViewModel : ObservableObject
{
    private NotesRepository? _repository;

    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _status = "No notes loaded.";

    [ObservableProperty]
    private string _searchTerm = string.Empty;

    [ObservableProperty]
    private string? _hostFilter;

    [ObservableProperty]
    private bool _showFlagsOnly;

    [ObservableProperty]
    private NoteData? _selectedNote;

    // Form fields for creating/editing
    [ObservableProperty]
    private string _title = string.Empty;

    [ObservableProperty]
    private string _content = string.Empty;

    [ObservableProperty]
    private string _tags = string.Empty;

    [ObservableProperty]
    private string _category = "note";

    // Allowed categories (must match NotesSchema CHECK constraint)
    public static readonly string[] AllowedCategories = { "note", "flag", "credential", "exploit", "screenshot", "command" };

    [ObservableProperty]
    private string _flagFormat = string.Empty;

    [ObservableProperty]
    private bool _isFlag;

    public ObservableCollection<NoteData> NotesList { get; } = new();

    partial void OnSelectedNoteChanged(NoteData? oldValue, NoteData? newValue)
    {
        if (newValue is not null)
        {
            Title = newValue.Title;
            Content = newValue.Content ?? string.Empty;
            Tags = newValue.Tags ?? string.Empty;
            Category = newValue.Category;
            FlagFormat = newValue.FlagFormat ?? string.Empty;
            IsFlag = newValue.IsFlag;
        }
        else
        {
            ClearForm();
        }
    }

    [RelayCommand]
    public async Task LoadNotesAsync()
    {
        if (!ValidateRepository()) return;

        IsLoading = true;
        try
        {
            var notes = await Task.Run(() => _repository!.GetNotes());
            NotesList.Clear();
            foreach (var note in notes)
            {
                NotesList.Add(note);
            }
            Status = $"{notes.Count} note(s) loaded.";
        }
        catch (Exception ex)
        {
            Status = $"Failed to load notes: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task SearchNotesAsync()
    {
        if (!ValidateRepository() || string.IsNullOrWhiteSpace(SearchTerm)) return;

        IsLoading = true;
        try
        {
            var searchTerm = SearchTerm;
            var results = await Task.Run(() => _repository!.SearchNotes(searchTerm));
            NotesList.Clear();
            foreach (var note in results)
            {
                NotesList.Add(note);
            }
            Status = $"Search found {results.Count} note(s).";
        }
        catch (Exception ex)
        {
            Status = $"Search failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task GetFlagsAsync()
    {
        if (!ValidateRepository()) return;

        IsLoading = true;
        try
        {
            var flags = await Task.Run(() => _repository!.GetFlags());
            NotesList.Clear();
            foreach (var flag in flags)
            {
                NotesList.Add(flag);
            }
            Status = $"{flags.Count} flagged note(s).";
        }
        catch (Exception ex)
        {
            Status = $"Failed to load flags: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanCreateNote))]
    public async Task CreateNoteAsync()
    {
        if (!ValidateRepository() || string.IsNullOrWhiteSpace(Title))
            return;

        IsLoading = true;
        try
        {
            var title = Title;
            var content = Content;
            var tags = Tags;
            var category = Category;
            var flagFormat = IsFlag ? FlagFormat : null;

            await Task.Run(() =>
            {
                _repository!.CreateNote(
                    title: title,
                    content: string.IsNullOrWhiteSpace(content) ? null : content,
                    flagFormat: flagFormat,
                    tags: string.IsNullOrWhiteSpace(tags) ? null : tags,
                    category: category,
                    source: "ui"
                );
            });

            Status = "Note created successfully.";
            ClearForm();
            SelectedNote = null;
            await LoadNotesAsync();
        }
        catch (Exception ex)
        {
            Status = $"Failed to create note: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanUpdateNote))]
    public async Task UpdateNoteAsync()
    {
        if (!ValidateRepository() || SelectedNote is null)
            return;

        IsLoading = true;
        try
        {
            var noteId = SelectedNote.Id;
            var title = Title;
            var content = Content;
            var tags = Tags;
            var category = Category;
            var flagFormat = IsFlag ? FlagFormat : null;

            await Task.Run(() =>
            {
                _repository!.UpdateNote(
                    noteId: noteId,
                    title: title,
                    content: string.IsNullOrWhiteSpace(content) ? null : content,
                    tags: string.IsNullOrWhiteSpace(tags) ? null : tags,
                    category: category,
                    flagFormat: flagFormat
                );
            });

            Status = "Note updated successfully.";
            SelectedNote = null;
            await LoadNotesAsync();
        }
        catch (Exception ex)
        {
            Status = $"Failed to update note: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanDeleteNote))]
    public async Task DeleteNoteAsync()
    {
        if (!ValidateRepository() || SelectedNote is null)
            return;

        IsLoading = true;
        try
        {
            var noteId = SelectedNote.Id;
            await Task.Run(() => _repository!.DeleteNote(noteId));

            Status = "Note deleted successfully.";
            SelectedNote = null;
            await LoadNotesAsync();
        }
        catch (Exception ex)
        {
            Status = $"Failed to delete note: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanArchiveNote))]
    public async Task ArchiveNoteAsync()
    {
        if (!ValidateRepository() || SelectedNote is null)
            return;

        IsLoading = true;
        try
        {
            var noteId = SelectedNote.Id;
            await Task.Run(() => _repository!.ArchiveNote(noteId));

            Status = "Note archived successfully.";
            SelectedNote = null;
            await LoadNotesAsync();
        }
        catch (Exception ex)
        {
            Status = $"Failed to archive note: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private bool CanCreateNote() => !IsLoading && !string.IsNullOrWhiteSpace(Title);
    private bool CanUpdateNote() => !IsLoading && SelectedNote is not null && !string.IsNullOrWhiteSpace(Title);
    private bool CanDeleteNote() => !IsLoading && SelectedNote is not null;
    private bool CanArchiveNote() => !IsLoading && SelectedNote is not null;

    private void ClearForm()
    {
        Title = string.Empty;
        Content = string.Empty;
        Tags = string.Empty;
        Category = "note";
        FlagFormat = string.Empty;
        IsFlag = false;
    }

    private bool ValidateRepository()
    {
        // Lazy-init repository when output dir changes
        if (_repository is null || NeedsRepositoryRefresh())
        {
            var dbPath = Path.Combine(OutputDir, "findings.db");
            if (!File.Exists(dbPath))
            {
                Status = $"No database at {dbPath}. Run a scan first.";
                return false;
            }

            _repository = new NotesRepository(dbPath);
        }

        return true;
    }

    private bool NeedsRepositoryRefresh()
    {
        if (_repository is null) return true;
        var dbPath = Path.Combine(OutputDir, "findings.db");
        return !File.Exists(dbPath);
    }
}
