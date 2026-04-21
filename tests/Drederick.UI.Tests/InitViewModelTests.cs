using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Pure-VM tests for <see cref="InitViewModel"/>. Verifies credential save,
/// sample-scope creation, and quick-start content without invoking real
/// installs or network calls.
/// </summary>
public class InitViewModelTests
{
    [Fact]
    public void QuickStart_contains_key_commands()
    {
        Assert.Contains("drederick doctor", InitViewModel.QuickStart, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("drederick serve",  InitViewModel.QuickStart, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("scope.txt",        InitViewModel.QuickStart, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DetectedTools_starts_empty()
    {
        var vm = new InitViewModel();
        Assert.Empty(vm.DetectedTools);
    }

    [Fact]
    public async Task SaveCredentials_writes_config_file()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-init-test-" + Guid.NewGuid().ToString("N"));
        var origHome = Environment.GetEnvironmentVariable("HOME");
        try
        {
            Directory.CreateDirectory(tmp);
            // Override HOME so the config lands inside our temp dir.
            Environment.SetEnvironmentVariable("HOME", tmp);

            var vm = new InitViewModel
            {
                OutputDir = tmp,
                HtbToken  = "test-token-xyz",
                HttpProxy = "http://127.0.0.1:8080",
            };
            await vm.SaveCredentialsCommand.ExecuteAsync(null);

            var configPath = Path.Combine(tmp, ".drederick", "config.json");
            Assert.True(File.Exists(configPath), $"Expected config at {configPath}");
            var content = File.ReadAllText(configPath);
            Assert.Contains("htb_api_token", content);
            Assert.Contains("http_proxy",    content);
            // Token value should be present (it is stored — but NEVER in audit.jsonl).
            Assert.Contains("test-token-xyz", content);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOME", origHome);
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task CreateSampleScope_creates_file()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-init-scope-" + Guid.NewGuid().ToString("N"));
        var origHome = Environment.GetEnvironmentVariable("HOME");
        try
        {
            Directory.CreateDirectory(tmp);
            Environment.SetEnvironmentVariable("HOME", tmp);

            var vm = new InitViewModel { OutputDir = tmp };
            await vm.CreateSampleScopeCommand.ExecuteAsync(null);

            var scopePath = Path.Combine(tmp, "scope.txt");
            Assert.True(File.Exists(scopePath), $"Expected scope.txt at {scopePath}");
            var content = File.ReadAllText(scopePath);
            Assert.Contains("10.0.0.0/24", content);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOME", origHome);
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public async Task CreateSampleScope_skips_if_exists()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-init-skip-" + Guid.NewGuid().ToString("N"));
        var origHome = Environment.GetEnvironmentVariable("HOME");
        try
        {
            Directory.CreateDirectory(tmp);
            Environment.SetEnvironmentVariable("HOME", tmp);
            // Pre-create the scope file with sentinel content.
            var scopePath = Path.Combine(tmp, "scope.txt");
            File.WriteAllText(scopePath, "# sentinel");

            var vm = new InitViewModel { OutputDir = tmp };
            await vm.CreateSampleScopeCommand.ExecuteAsync(null);

            // File should be unchanged.
            Assert.Equal("# sentinel", File.ReadAllText(scopePath));
            Assert.Contains("already exists", vm.ScopeStatus, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOME", origHome);
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void GetConfigPath_includes_drederick_dir()
    {
        var path = InitViewModel.GetConfigPath();
        Assert.Contains(".drederick", path, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("config.json", path, StringComparison.OrdinalIgnoreCase);
    }
}
