using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Host;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Progress feed backing the Progress panel. Append-only observable list of
/// <see cref="ScanEvent"/>s; bound to a virtualised list in the view. Capped
/// to avoid unbounded growth for long-running scans.
/// </summary>
public sealed partial class ProgressViewModel : ObservableObject
{
    private const int MaxEvents = 2000;

    [ObservableProperty]
    private int _hostCount;

    [ObservableProperty]
    private int _toolCalls;

    [ObservableProperty]
    private string _status = "Idle.";

    public ObservableCollection<ScanEventRow> Events { get; } = new();

    [RelayCommand]
    public void Clear()
    {
        Events.Clear();
        HostCount = 0;
        ToolCalls = 0;
        Status = "Idle.";
    }

    public void Append(ScanEvent e)
    {
        Events.Add(new ScanEventRow(e));
        if (Events.Count > MaxEvents) Events.RemoveAt(0);

        if (e.ToolCallsTotal is int tc) ToolCalls = tc;
        if (e.Kind == ScanEventKind.HostFinished) HostCount++;
        Status = e.Kind switch
        {
            ScanEventKind.SessionStart => "Running…",
            ScanEventKind.RunnerFinish => "Runner finished; writing reports.",
            ScanEventKind.SessionEnd => "Done.",
            ScanEventKind.Error => $"Error: {e.Message}",
            _ => Status,
        };
    }
}

/// <summary>Presentation-layer row; lets the view bind without pulling in the engine assembly.</summary>
public sealed class ScanEventRow
{
    public ScanEventRow(ScanEvent e)
    {
        Timestamp = e.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");
        Kind = e.Kind.ToString();
        Target = e.Target ?? string.Empty;
        Tool = e.Tool ?? string.Empty;
        Message = e.Message ?? string.Empty;
    }

    public string Timestamp { get; }
    public string Kind { get; }
    public string Target { get; }
    public string Tool { get; }
    public string Message { get; }
}
