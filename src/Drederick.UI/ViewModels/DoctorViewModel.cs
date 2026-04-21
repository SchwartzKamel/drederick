using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Doctor tab. Wraps <see cref="DoctorRunner"/> for detect/install
/// workflows, driven entirely from GUI buttons. Preserves
/// <c>@invariant-id:doctor-workstation-only</c> (UI never re-execs as root,
/// confirmation is explicit) and logs every action to
/// <see cref="AuditLog"/> as a <c>ui.doctor.*</c> event.
/// </summary>
public sealed partial class DoctorViewModel : ObservableObject
{
    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private string _statusLine = "Doctor has not run.";

    [ObservableProperty]
    private string _packageManager = "(unknown)";

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _hasRunDetect;

    /// <summary>Operator must explicitly tick this before Install is enabled.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InstallMissingCommand))]
    private bool _installConfirmed;

    public ObservableCollection<ToolRow> Tools { get; } = new();

    public int MissingCount => Tools.Count(t => !t.Found);

    [RelayCommand]
    public async Task DetectAsync()
    {
        IsBusy = true;
        StatusLine = "Detecting operator tooling…";
        try
        {
            await Task.Run(() =>
            {
                Directory.CreateDirectory(OutputDir);
                var auditPath = Path.Combine(OutputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                audit.Record("ui.doctor.detect", new Dictionary<string, object?>
                {
                    ["initiator"] = "ui",
                });
                var runner = new DoctorRunner(audit);
                var detected = runner.Detect();
                var pm = PackageManagerDetection.Detect(new PathToolLocator());

                // SQLite tooling sink best-effort: only if a findings.db
                // already exists (parity with CLI's doctor subcommand).
                var dbPath = Path.Combine(OutputDir, "findings.db");
                if (File.Exists(dbPath)) SqliteToolingSink.TryUpsert(dbPath, detected);

                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    Tools.Clear();
                    foreach (var t in detected) Tools.Add(new ToolRow(t));
                    PackageManager = PackageManagerDetection.DisplayName(pm);
                    HasRunDetect = true;
                    OnPropertyChanged(nameof(MissingCount));
                    var missing = detected.Count(x => !x.Found);
                    StatusLine = missing == 0
                        ? $"All tooling present (pm={PackageManager})."
                        : $"{missing} tool(s) missing (pm={PackageManager}).";
                    InstallMissingCommand.NotifyCanExecuteChanged();
                });
            }).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            StatusLine = $"Detect failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanInstall() => HasRunDetect && !IsBusy && InstallConfirmed && MissingCount > 0;

    [RelayCommand(CanExecute = nameof(CanInstall))]
    public async Task InstallMissingAsync()
    {
        IsBusy = true;
        StatusLine = "Running installer…";
        try
        {
            await Task.Run(() =>
            {
                Directory.CreateDirectory(OutputDir);
                var auditPath = Path.Combine(OutputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                audit.Record("ui.doctor.install", new Dictionary<string, object?>
                {
                    ["initiator"] = "ui",
                    ["confirmed"] = true,
                });
                var locator = new PathToolLocator();
                var pm = PackageManagerDetection.Detect(locator);
                var runner = new DoctorRunner(audit);
                var detected = runner.Detect();
                // Pipe install transcript to an in-memory writer; AssumeYes=true
                // because the GUI's own confirmation checkbox has already
                // stood in for the [y/N] prompt (@invariant-id:doctor-workstation-only).
                using var sw = new StringWriter();
                var outcomes = runner.Install(detected, pm, assumeYes: true, TextReader.Null, sw);

                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    // Refresh detect so the checklist reflects the new state.
                    DetectCommand.Execute(null);
                    StatusLine = outcomes.Count == 0
                        ? "No installable candidates."
                        : $"Install finished ({outcomes.Count} step(s)). See audit.jsonl for details.";
                });
            }).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            StatusLine = $"Install failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            // Force a fresh consent click for any subsequent install.
            InstallConfirmed = false;
        }
    }
}

/// <summary>Presentation-layer row for a detected tool.</summary>
public sealed class ToolRow
{
    public ToolRow(ToolInfo t)
    {
        Name = t.Name;
        Found = t.Found;
        Version = t.Version ?? string.Empty;
        Path = t.Path ?? string.Empty;
        Status = t.Found ? "ok" : "missing";
    }

    public string Name { get; }
    public bool Found { get; }
    public string Status { get; }
    public string Version { get; }
    public string Path { get; }
}
