using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Pure-VM tests for <see cref="AnalyzeViewModel"/>. These verify the
/// can-execute gating logic without running a real <c>BinaryAnalyzer</c>
/// (which requires on-disk tools like <c>readelf</c> / <c>objdump</c>).
/// End-to-end analysis is exercised in the engine's <c>BinaryAnalyzerTests</c>.
/// </summary>
public class AnalyzeViewModelTests
{
    [Fact]
    public void Analyze_is_disabled_with_no_path()
    {
        var vm = new AnalyzeViewModel();
        Assert.False(vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
    public void Analyze_is_disabled_with_whitespace_path()
    {
        var vm = new AnalyzeViewModel { BinaryPath = "   " };
        Assert.False(vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
    public void Analyze_is_enabled_with_non_empty_path()
    {
        var vm = new AnalyzeViewModel { BinaryPath = "/usr/bin/ls" };
        Assert.True(vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
    public void Analyze_is_disabled_while_busy()
    {
        var vm = new AnalyzeViewModel { BinaryPath = "/usr/bin/ls" };
        // Simulate the busy flag being set (as AnalyzeAsync does).
        typeof(AnalyzeViewModel)
            .GetProperty(nameof(AnalyzeViewModel.IsBusy))!
            .SetValue(vm, true);
        Assert.False(vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
    public void Findings_starts_empty()
    {
        var vm = new AnalyzeViewModel();
        Assert.Empty(vm.Findings);
    }

    [Fact]
    public void Default_output_dir_is_out()
    {
        var vm = new AnalyzeViewModel();
        Assert.Equal("out", vm.OutputDir);
    }

    [Fact]
    public void Setting_binary_path_enables_command()
    {
        var vm = new AnalyzeViewModel();
        bool canExecuteChanged = false;
        vm.AnalyzeCommand.CanExecuteChanged += (_, _) => canExecuteChanged = true;
        vm.BinaryPath = "/bin/bash";
        Assert.True(canExecuteChanged);
        Assert.True(vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
    public async Task Analyze_file_not_found_sets_status()
    {
        // Run with a guaranteed non-existent path; AnalyzeAsync must not throw
        // out of the command — it should surface the error in StatusLine.
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-analyze-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);
            var vm = new AnalyzeViewModel
            {
                BinaryPath = Path.Combine(tmp, "no_such_binary"),
                OutputDir = tmp,
            };
            await vm.AnalyzeCommand.ExecuteAsync(null);
            // After completion the VM must not be busy and must surface an error.
            Assert.False(vm.IsBusy);
            Assert.Contains("not found", vm.StatusLine, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }
}
