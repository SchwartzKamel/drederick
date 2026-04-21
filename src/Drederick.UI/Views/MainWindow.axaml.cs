using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Drederick.UI.ViewModels;

namespace Drederick.UI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private MainWindowViewModel? Vm => DataContext as MainWindowViewModel;

    // ---- Scope tab -----------------------------------------------------
    private async void OnBrowseScope(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select scope file",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Scope files") { Patterns = new[] { "*.yaml", "*.yml", "*.txt", "*.scope" } },
                FilePickerFileTypes.All,
            },
        });
        if (files.Count > 0)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrEmpty(path))
            {
                Vm.Scope.ScopePath = path;
                Vm.Scope.ReparseCommand.Execute(null);
            }
        }
    }

    private async void OnSaveScope(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save scope file",
            SuggestedFileName = "scope.yaml",
            DefaultExtension = "yaml",
            FileTypeChoices = new[]
            {
                new FilePickerFileType("Scope files") { Patterns = new[] { "*.yaml", "*.yml", "*.txt", "*.scope" } },
            },
        });
        if (file is not null)
        {
            var path = file.TryGetLocalPath();
            if (!string.IsNullOrEmpty(path))
            {
                Vm.Scope.SaveInlineToFile(path);
                Vm.Scope.ReparseCommand.Execute(null);
            }
        }
    }

    // ---- Run tab -------------------------------------------------------
    private void OnRemoveTarget(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (sender is Button b && b.Tag is string target)
        {
            Vm.Run.RemoveTargetCommand.Execute(target);
        }
    }

    private void OnConfirmAllowBroad(object? sender, RoutedEventArgs e) => Vm?.Run.ConfirmAllowBroad();
    private void OnCancelAllowBroad(object? sender, RoutedEventArgs e) => Vm?.Run.CancelAllowBroad();
}
