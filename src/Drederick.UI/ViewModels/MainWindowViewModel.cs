using CommunityToolkit.Mvvm.ComponentModel;

namespace Drederick.UI.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    public ScopeViewModel Scope { get; }
    public ProgressViewModel Progress { get; }
    public RunViewModel Run { get; }

    [ObservableProperty]
    private string _title = "Drederick — operator console";

    public MainWindowViewModel()
    {
        Scope = new ScopeViewModel();
        Progress = new ProgressViewModel();
        Run = new RunViewModel(Scope, Progress);
    }
}
