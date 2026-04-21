using CommunityToolkit.Mvvm.ComponentModel;

namespace Drederick.UI.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    public ScopeViewModel Scope { get; }
    public ProgressViewModel Progress { get; }
    public RunViewModel Run { get; }
    public DoctorViewModel Doctor { get; }
    public FindingsViewModel Findings { get; }
    public AnalyzeViewModel Analyze { get; }
    public InitViewModel Init { get; }
    public NotesViewModel Notes { get; }

    [ObservableProperty]
    private string _title = "Drederick — operator console";

    public MainWindowViewModel()
    {
        Scope = new ScopeViewModel();
        Progress = new ProgressViewModel();
        Run = new RunViewModel(Scope, Progress);
        Doctor = new DoctorViewModel();
        Findings = new FindingsViewModel();
        Analyze = new AnalyzeViewModel();
        Init = new InitViewModel();
        Notes = new NotesViewModel();

        // Keep out-dir in sync so Doctor / Findings / Analyze / Init / Notes all
        // target the same directory the active Run writes to.
        Run.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(RunViewModel.OutputDir))
            {
                Doctor.OutputDir = Run.OutputDir;
                Findings.OutputDir = Run.OutputDir;
                Analyze.OutputDir = Run.OutputDir;
                Init.OutputDir = Run.OutputDir;
                Notes.OutputDir = Run.OutputDir;
            }
        };
    }
}
