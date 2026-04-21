using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Pure-VM tests for <see cref="DoctorViewModel"/>. These exercise the
/// consent-gating logic around <c>InstallMissingCommand</c> without
/// spawning real installers — doctor runs against the actual workstation
/// are integration territory (handled by the engine's <c>DoctorTests</c>).
/// </summary>
public class DoctorViewModelTests
{
    [Fact]
    public void Install_is_disabled_before_detect()
    {
        var vm = new DoctorViewModel();
        Assert.False(vm.InstallMissingCommand.CanExecute(null));
    }

    [Fact]
    public void Install_is_disabled_without_consent_even_after_detect()
    {
        var vm = new DoctorViewModel();
        // Simulate a completed detect by flipping the property the command
        // depends on. This is the same state a real DetectAsync leaves.
        vm.GetType().GetProperty(nameof(DoctorViewModel.HasRunDetect))!
            .SetValue(vm, true);
        vm.Tools.Add(new ToolRow(new Drederick.Doctor.ToolInfo(
            Name: "nmap", Found: false, Version: null, Path: null,
            DetectedAt: DateTimeOffset.UtcNow)));
        Assert.False(vm.InstallMissingCommand.CanExecute(null));
    }

    [Fact]
    public void Install_becomes_enabled_after_detect_plus_consent_plus_missing()
    {
        var vm = new DoctorViewModel();
        vm.GetType().GetProperty(nameof(DoctorViewModel.HasRunDetect))!
            .SetValue(vm, true);
        vm.Tools.Add(new ToolRow(new Drederick.Doctor.ToolInfo(
            Name: "nmap", Found: false, Version: null, Path: null,
            DetectedAt: DateTimeOffset.UtcNow)));
        vm.InstallConfirmed = true;
        Assert.True(vm.InstallMissingCommand.CanExecute(null));
    }

    [Fact]
    public void Install_stays_disabled_if_nothing_is_missing()
    {
        var vm = new DoctorViewModel();
        vm.GetType().GetProperty(nameof(DoctorViewModel.HasRunDetect))!
            .SetValue(vm, true);
        vm.Tools.Add(new ToolRow(new Drederick.Doctor.ToolInfo(
            Name: "nmap", Found: true, Version: "7.94", Path: "/usr/bin/nmap",
            DetectedAt: DateTimeOffset.UtcNow)));
        vm.InstallConfirmed = true;
        Assert.False(vm.InstallMissingCommand.CanExecute(null));
    }
}
