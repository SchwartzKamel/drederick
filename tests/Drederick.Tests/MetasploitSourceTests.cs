using System.ComponentModel;
using Drederick.Enrichment;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class MetasploitSourceTests : IDisposable
{
    private readonly string _workDir;

    public MetasploitSourceTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-msf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string LoadFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    private PocQueryContext Ctx() => new(Path.Combine(_workDir, "cache"), false, new SqliteReport(_workDir));

    [Fact]
    public async Task Absent_msfconsole_returns_empty_and_does_not_throw()
    {
        var runner = new RecordingProcessRunner();
        runner.OnRunThrow((f, _) => f == "msfconsole", new Win32Exception(2, "not found"));

        var src = new MetasploitSource(runner);
        var refs = await src.QueryAsync("CVE-2011-2523", Ctx(), CancellationToken.None);
        Assert.Empty(refs);
    }

    [Fact]
    public async Task Parses_matching_module_rows()
    {
        var runner = new RecordingProcessRunner();
        var stdout = LoadFixture("metasploit-search-sample.txt");
        runner.OnRun((f, a) => f == "msfconsole" && a.Contains("search cve"), 0, stdout: stdout);

        var src = new MetasploitSource(runner);
        var refs = await src.QueryAsync("CVE-2011-2523", Ctx(), CancellationToken.None);

        Assert.Equal(2, refs.Count);
        Assert.Contains(refs, r => r.ExternalId == "exploit/unix/ftp/vsftpd_234_backdoor");
        Assert.Contains(refs, r => r.ExternalId == "auxiliary/scanner/ftp/ftp_version");
        Assert.All(refs, r => Assert.Equal("metasploit", r.Source));
        // No caching, no URL — stays inside the Metasploit tree.
        Assert.All(refs, r => Assert.Null(r.Url));
        Assert.All(refs, r => Assert.Null(r.LocalPath));
    }

    [Fact]
    public async Task Empty_stdout_returns_empty()
    {
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, _) => f == "msfconsole", 0, stdout: "");
        var src = new MetasploitSource(runner);
        Assert.Empty(await src.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None));
    }
}
