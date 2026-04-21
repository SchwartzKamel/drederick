using Drederick.UI.ViewModels;
using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Pure-VM tests for <see cref="FindingsViewModel"/>. Exercises
/// <c>Reload</c>'s behaviour on a missing / empty database — the integration
/// path against a populated <c>findings.db</c> is covered by the engine's
/// <c>SqliteReport</c> tests.
/// </summary>
public class FindingsViewModelTests
{
    [Fact]
    public void Reload_with_no_database_clears_state_and_surfaces_message()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-findings-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);
            var vm = new FindingsViewModel { OutputDir = tmp };
            vm.Reload();
            Assert.Equal(0, vm.HostCount);
            Assert.Empty(vm.Rows);
            Assert.False(vm.CanOpenDatasette);
            Assert.Contains("No database", vm.Status);
            Assert.False(vm.OpenDatasetteCommand.CanExecute(null));
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void Reload_against_real_findings_db_populates_counts()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "drederick-ui-findings-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            // Build a real findings.db via the engine's SqliteReport so we
            // test against the same schema the GUI will actually read.
            var report = new Drederick.Reporting.SqliteReport(tmp);
            var hf = new Drederick.Recon.HostFinding { Target = "10.10.10.42" };
            hf.Nmap = new Drederick.Recon.NmapResult
            {
                OpenPorts =
                {
                    new Drederick.Recon.NmapPort
                    {
                        Port = 22, Protocol = "tcp", Service = "ssh",
                        Product = "OpenSSH", Version = "9.6p1",
                    },
                },
            };
            report.WriteReport(new[] { hf });

            var vm = new FindingsViewModel { OutputDir = tmp };
            vm.Reload();

            Assert.Equal(1, vm.HostCount);
            Assert.True(vm.ServiceCount >= 1);
            Assert.NotEmpty(vm.Rows);
            Assert.True(vm.CanOpenDatasette);
            Assert.True(vm.OpenDatasetteCommand.CanExecute(null));
        }
        finally
        {
            if (Directory.Exists(tmp)) Directory.Delete(tmp, recursive: true);
        }
    }
}
