using System.Collections.ObjectModel;
using System.Net;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Host;
using Drederick.Scope;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Run tab: target list with Add / Remove buttons, profile
/// (Lab / Strict), runner (Adaptive / Agent), allow-broad toggle (with a
/// confirmation-required flag the view must honour), and Start / Cancel.
///
/// Start is disabled unless the bound <see cref="ScopeViewModel"/> has
/// validated a scope and at least one target is present — this is the
/// operator-visible expression of <c>@invariant-id:scope-default-deny</c>.
/// </summary>
public sealed partial class RunViewModel : ObservableObject
{
    private readonly ScopeViewModel _scope;
    private readonly ProgressViewModel _progress;
    private readonly DrederickHost _host = new();
    private CancellationTokenSource? _cts;

    public RunViewModel(ScopeViewModel scope, ProgressViewModel progress)
    {
        _scope = scope;
        _progress = progress;
        _scope.PropertyChanged += (_, __) =>
        {
            StartCommand.NotifyCanExecuteChanged();
            OnPropertyChanged(nameof(CanStart));
        };
    }

    public ObservableCollection<string> Targets { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanStart))]
    [NotifyCanExecuteChangedFor(nameof(StartCommand))]
    private string _pendingTarget = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanStart))]
    [NotifyCanExecuteChangedFor(nameof(StartCommand))]
    private bool _labMode = true;

    [ObservableProperty]
    private bool _useAgent;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AllowBroadConfirmationRequired))]
    private bool _allowBroad;

    /// <summary>
    /// True when the user has checked Allow-Broad but has not yet confirmed
    /// via the modal dialog. The view must present a confirmation dialog
    /// and call <see cref="ConfirmAllowBroad"/> or <see cref="CancelAllowBroad"/>.
    /// Wildcard refusal is still hard-coded in ScopeLoader regardless.
    /// </summary>
    public bool AllowBroadConfirmationRequired => AllowBroad && !_allowBroadConfirmed;

    private bool _allowBroadConfirmed;

    public void ConfirmAllowBroad() { _allowBroadConfirmed = true; OnPropertyChanged(nameof(AllowBroadConfirmationRequired)); }

    public void CancelAllowBroad() { _allowBroadConfirmed = false; AllowBroad = false; OnPropertyChanged(nameof(AllowBroadConfirmationRequired)); }

    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private string _memoryPath = "memory/findings.json";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanStart))]
    [NotifyCanExecuteChangedFor(nameof(StartCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool _isRunning;

    [ObservableProperty]
    private string? _errorMessage;

    public bool CanStart =>
        !IsRunning &&
        _scope.IsValid &&
        Targets.Count > 0;

    [RelayCommand]
    public void AddTarget()
    {
        var t = PendingTarget.Trim();
        if (string.IsNullOrEmpty(t)) return;
        if (!IPAddress.TryParse(t, out _))
        {
            ErrorMessage = $"'{t}' is not a valid IP address.";
            return;
        }
        if (_scope.LoadedScope is { } scope && !scope.Contains(t))
        {
            ErrorMessage = $"'{t}' is not inside the loaded scope.";
            return;
        }
        if (!Targets.Contains(t)) Targets.Add(t);
        PendingTarget = string.Empty;
        ErrorMessage = null;
        OnPropertyChanged(nameof(CanStart));
        StartCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    public void RemoveTarget(string? target)
    {
        if (string.IsNullOrEmpty(target)) return;
        Targets.Remove(target);
        OnPropertyChanged(nameof(CanStart));
        StartCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    public async Task StartAsync()
    {
        if (_scope.LoadedScope is null) return;
        if (AllowBroad && !_allowBroadConfirmed)
        {
            ErrorMessage = "Allow-broad requires explicit confirmation.";
            return;
        }

        IsRunning = true;
        ErrorMessage = null;
        _progress.Clear();

        var opts = new RunOptions(
            ScopePath: _scope.ScopePath,
            Targets: Targets.ToList(),
            OutputDir: OutputDir,
            MemoryPath: MemoryPath,
            LabMode: LabMode,
            AllowBroad: AllowBroad,
            UseAgent: UseAgent);

        var progress = new Progress<ScanEvent>(_progress.Append);
        _cts = new CancellationTokenSource();
        try
        {
            // Pass the already-parsed Scope so operators can compose a scope
            // entirely inside the GUI without writing a file to disk.
            await _host.RunAsync(_scope.LoadedScope, opts, progress, _cts.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = "Cancelled.";
        }
        catch (ScopeException ex)
        {
            ErrorMessage = $"scope: {ex.Message}";
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
            _cts = null;
            OnPropertyChanged(nameof(CanStart));
            StartCommand.NotifyCanExecuteChanged();
            CancelCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(IsRunning))]
    public void Cancel() => _cts?.Cancel();
}
