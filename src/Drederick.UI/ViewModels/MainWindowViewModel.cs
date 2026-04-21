using CommunityToolkit.Mvvm.ComponentModel;

namespace Drederick.UI.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    public ScopeViewModel Scope { get; }
    public ProgressViewModel Progress { get; }
    public RunViewModel Run { get; }
    public DoctorViewModel Doctor { get; }
    public FindingsViewModel Findings { get; }

    [ObservableProperty]
    private string _title = "Drederick — operator console";

    public MainWindowViewModel()
    {
        Scope = new ScopeViewModel();
        Progress = new ProgressViewModel();
        Run = new RunViewModel(Scope, Progress);
        Doctor = new DoctorViewModel();
        Findings = new FindingsViewModel();

        // Keep the out-dir in sync so Doctor + Findings always target the
        // same directory the active Run writes to.
        Run.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(RunViewModel.OutputDir))
            {
                Doctor.OutputDir = Run.OutputDir;
                Findings.OutputDir = Run.OutputDir;
            }
        };
    }
}
