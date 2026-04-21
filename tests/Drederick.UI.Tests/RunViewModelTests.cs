using Drederick.Scope;
using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// VM-level tests for <see cref="RunViewModel"/>. Covers the
/// default-deny invariant surface: Start is disabled without a valid scope
/// and/or without at least one target, and targets outside the loaded scope
/// are rejected at the Add-button boundary.
/// </summary>
public class RunViewModelTests
{
    private static (ScopeViewModel scope, RunViewModel run) BuildVms(string inlineScope)
    {
        var scope = new ScopeViewModel { InlineText = inlineScope };
        scope.Reparse();
        var run = new RunViewModel(scope, new ProgressViewModel());
        return (scope, run);
    }

    [Fact]
    public void Start_is_disabled_when_scope_is_empty()
    {
        var (_, run) = BuildVms("");
        Assert.False(run.CanStart);
        Assert.False(run.StartCommand.CanExecute(null));
    }

    [Fact]
    public void Start_is_disabled_when_scope_valid_but_no_targets()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        Assert.Empty(run.Targets);
        Assert.False(run.CanStart);
    }

    [Fact]
    public void Adding_in_scope_target_enables_start()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        run.PendingTarget = "10.10.10.42";
        run.AddTargetCommand.Execute(null);
        Assert.Contains("10.10.10.42", run.Targets);
        Assert.True(run.CanStart);
        Assert.True(run.StartCommand.CanExecute(null));
    }

    [Fact]
    public void Adding_out_of_scope_target_is_refused_with_visible_error()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        run.PendingTarget = "192.168.1.1";
        run.AddTargetCommand.Execute(null);
        Assert.Empty(run.Targets);
        Assert.NotNull(run.ErrorMessage);
        Assert.Contains("not inside the loaded scope", run.ErrorMessage);
        Assert.False(run.CanStart);
    }

    [Fact]
    public void Adding_non_ip_target_is_refused()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        run.PendingTarget = "example.com";
        run.AddTargetCommand.Execute(null);
        Assert.Empty(run.Targets);
        Assert.NotNull(run.ErrorMessage);
        Assert.Contains("not a valid IP", run.ErrorMessage);
    }

    [Fact]
    public void Remove_target_drops_it_and_disables_start_if_empty()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        run.PendingTarget = "10.10.10.42";
        run.AddTargetCommand.Execute(null);
        Assert.True(run.CanStart);

        run.RemoveTargetCommand.Execute("10.10.10.42");
        Assert.Empty(run.Targets);
        Assert.False(run.CanStart);
    }

    [Fact]
    public void AllowBroad_requires_explicit_confirmation_flag_before_start()
    {
        var (_, run) = BuildVms("10.10.10.0/24\n");
        run.PendingTarget = "10.10.10.42";
        run.AddTargetCommand.Execute(null);
        run.AllowBroad = true;

        Assert.True(run.AllowBroadConfirmationRequired);

        run.ConfirmAllowBroad();
        Assert.False(run.AllowBroadConfirmationRequired);
    }
}
