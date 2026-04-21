using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Host;
using Drederick.Scope;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Scope tab. The operator points at a scope file with the
/// "Browse…" button, or pastes CIDR entries into the inline text box. We
/// re-validate via <see cref="ScopeLoader"/> and surface every
/// <see cref="ScopeException"/> — including the hard-coded wildcard refusal —
/// as an operator-visible error banner.
///
/// This VM owns no subprocess invocation. Scope validation is pure parsing.
/// </summary>
public sealed partial class ScopeViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    [NotifyPropertyChangedFor(nameof(EntriesSummary))]
    private string? _scopePath;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    [NotifyPropertyChangedFor(nameof(EntriesSummary))]
    private string _inlineText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    [NotifyPropertyChangedFor(nameof(EntriesSummary))]
    private bool _labMode = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    [NotifyPropertyChangedFor(nameof(EntriesSummary))]
    private bool _allowBroad;

    [ObservableProperty]
    private string? _errorMessage;

    public bool HasError => !string.IsNullOrEmpty(ErrorMessage);

    public bool IsValid => LoadedScope is not null && !HasError;

    public Drederick.Scope.Scope? LoadedScope { get; private set; }

    public ObservableCollection<string> Entries { get; } = new();

    public string EntriesSummary => LoadedScope is null
        ? "No scope loaded."
        : $"{LoadedScope.Entries.Count} entr{(LoadedScope.Entries.Count == 1 ? "y" : "ies")} • source: {LoadedScope.Source}";

    /// <summary>
    /// Reparse on every field change so the UI can reactively show errors.
    /// Called by the view after a file is picked or the inline text edited.
    /// </summary>
    [RelayCommand]
    public void Reparse()
    {
        ErrorMessage = null;
        LoadedScope = null;
        Entries.Clear();

        try
        {
            Drederick.Scope.Scope parsed;
            if (!string.IsNullOrWhiteSpace(ScopePath))
            {
                parsed = ScopeLoader.LoadFile(ScopePath, allowBroad: AllowBroad, labMode: LabMode);
            }
            else if (!string.IsNullOrWhiteSpace(InlineText))
            {
                parsed = ScopeLoader.Parse(InlineText, source: "<inline>", allowBroad: AllowBroad, labMode: LabMode);
            }
            else
            {
                // Empty is a "no scope yet" state, not an error.
                return;
            }

            LoadedScope = parsed;
            foreach (var e in parsed.Entries) Entries.Add(e.ToString());
        }
        catch (ScopeException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to load scope: {ex.Message}";
        }
    }

    /// <summary>
    /// Persist the current inline CIDR text to <paramref name="path"/>. Lets
    /// operators who composed a scope inside the GUI save it for re-use on
    /// subsequent runs. We write the text verbatim (including comments) and
    /// re-point <see cref="ScopePath"/> at the newly-written file so
    /// subsequent re-parses go through the file path.
    /// </summary>
    public void SaveInlineToFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, InlineText ?? string.Empty);
        ScopePath = path;
    }
}
