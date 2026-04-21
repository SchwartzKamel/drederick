using Drederick.Scope;
using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Pure-VM tests for <see cref="ScopeViewModel"/>. The viewmodel does not
/// touch Avalonia types directly so we can exercise it without
/// <see cref="Avalonia.Headless.AvaloniaTestApplicationAttribute"/>.
/// </summary>
public class ScopeViewModelTests
{
    [Fact]
    public void Empty_input_is_not_an_error_but_is_not_valid_either()
    {
        var vm = new ScopeViewModel();
        vm.Reparse();
        Assert.False(vm.IsValid);
        Assert.False(vm.HasError);
        Assert.Null(vm.LoadedScope);
    }

    [Fact]
    public void Wildcard_inline_is_refused_with_scope_exception_message()
    {
        var vm = new ScopeViewModel
        {
            InlineText = "0.0.0.0/0\n",
        };
        vm.Reparse();
        Assert.False(vm.IsValid);
        Assert.True(vm.HasError);
        Assert.Contains("0.0.0.0/0", vm.ErrorMessage);
        Assert.Null(vm.LoadedScope);
    }

    [Fact]
    public void Valid_cidr_list_loads_and_populates_entries()
    {
        var vm = new ScopeViewModel
        {
            InlineText = "10.10.10.0/24\n10.10.11.42/32\n",
        };
        vm.Reparse();
        Assert.True(vm.IsValid);
        Assert.False(vm.HasError);
        Assert.NotNull(vm.LoadedScope);
        Assert.Equal(2, vm.LoadedScope!.Entries.Count);
        Assert.Equal(2, vm.Entries.Count);
    }

    [Fact]
    public void SaveInlineToFile_writes_and_updates_path()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-scope-" + Guid.NewGuid().ToString("N") + ".yaml");
        try
        {
            var vm = new ScopeViewModel { InlineText = "10.0.0.0/24\n" };
            vm.SaveInlineToFile(tmp);
            Assert.True(File.Exists(tmp));
            Assert.Equal(tmp, vm.ScopePath);
            Assert.Contains("10.0.0.0/24", File.ReadAllText(tmp));
        }
        finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }
}
