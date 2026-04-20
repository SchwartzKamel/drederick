using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// Environment-gated live smoke test. Skipped (as a silent pass) unless
/// <c>DREDERICK_INTEGRATION=1</c> is set. When enabled, invokes the real
/// <c>drederick</c> binary via <c>dotnet run</c> against <c>127.0.0.1</c>
/// and asserts the same output contract as <see cref="PipelineSmokeTests"/>,
/// but exercising real nmap output.
///
/// If <c>nmap</c> is not on PATH this test also silently passes — the
/// integration env is expected to provision it.
/// </summary>
public class LiveSmokeTests : IDisposable
{
    private readonly string _workDir;
    private const string EnvVar = "DREDERICK_INTEGRATION";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    public LiveSmokeTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-live-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string? LocateRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            if (File.Exists(Path.Combine(dir, "Drederick.slnx"))) return dir;
            dir = Path.GetDirectoryName(dir);
        }
        return null;
    }

    private static bool NmapOnPath()
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        var exe = OperatingSystem.IsWindows() ? "nmap.exe" : "nmap";
        foreach (var p in pathVar.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            try
            {
                if (File.Exists(Path.Combine(p, exe))) return true;
            }
            catch { /* ignore unreadable PATH entry */ }
        }
        return false;
    }

    [Fact]
    public async Task Live_end_to_end_smoke_against_loopback()
    {
        // Gate 1: opt-in env var.
        if (Environment.GetEnvironmentVariable(EnvVar) != "1")
        {
            return; // silent skip
        }
        // Gate 2: nmap must be on PATH — don't fail when missing.
        if (!NmapOnPath())
        {
            return; // silent skip
        }

        var repoRoot = LocateRepoRoot() ?? throw new InvalidOperationException("repo root not found");
        var outDir = Path.Combine(_workDir, "out");
        Directory.CreateDirectory(outDir);
        var scopePath = Path.Combine(_workDir, "scope.txt");
        File.WriteAllText(scopePath, "127.0.0.1/32\n");

        var csproj = Path.Combine(repoRoot, "src", "Drederick", "Drederick.csproj");
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = repoRoot,
        };
        foreach (var a in new[]
        {
            "run", "--project", csproj, "--no-build", "--",
            "--scope", scopePath,
            "--target", "127.0.0.1",
            "--out", outDir,
            "--no-fetch-poc",
        })
        {
            psi.ArgumentList.Add(a);
        }
        // Isolate NVD / knowledge state so the live run does not touch the
        // developer's real cache.
        psi.Environment["HOME"] = _workDir;
        // Keep the run offline-tolerant and fast.
        psi.Environment["DREDERICK_SKIP_CVE"] = "1";

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("failed to start dotnet run");
        using var cts = new CancellationTokenSource(Timeout);
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
        var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);
        var exitTask = proc.WaitForExitAsync(cts.Token);
        try
        {
            await exitTask;
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new Xunit.Sdk.XunitException($"drederick live run exceeded {Timeout.TotalSeconds:F0}s timeout");
        }
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        Assert.True(proc.ExitCode == 0,
            $"drederick exit={proc.ExitCode}\nstdout:\n{stdout}\nstderr:\n{stderr}");

        // Output contract — same shape as the fixture-based smoke test.
        Assert.True(File.Exists(Path.Combine(outDir, "report.json")));
        Assert.True(File.Exists(Path.Combine(outDir, "report.md")));
        Assert.True(File.Exists(Path.Combine(outDir, "audit.jsonl")));
        Assert.True(File.Exists(Path.Combine(outDir, "findings.db")));
        // manual_commands.txt is written under out/<host>/ in lab mode.
        Assert.True(File.Exists(Path.Combine(outDir, "127.0.0.1", "manual_commands.txt")));

        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(outDir, "report.json")));
        var hosts = doc.RootElement.GetProperty("hosts");
        Assert.Equal(JsonValueKind.Array, hosts.ValueKind);
        Assert.Single(hosts.EnumerateArray());
        Assert.Equal("127.0.0.1", hosts.EnumerateArray().First().GetProperty("target").GetString());

        using var conn = new SqliteConnection(
            $"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT COUNT(*) FROM hosts WHERE address='127.0.0.1';";
            Assert.Equal(1L, Convert.ToInt64(cmd.ExecuteScalar()));
        }
    }
}
