using Drederick.Enrichment;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class NucleiSourceTests : IDisposable
{
    private readonly string _workDir;

    public NucleiSourceTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-nuclei-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private PocQueryContext Ctx() => new(Path.Combine(_workDir, "cache"), false, new SqliteReport(_workDir));

    [Fact]
    public async Task No_templates_dir_returns_empty()
    {
        var runner = new RecordingProcessRunner();
        var src = new NucleiSource(runner, templatesDirProbe: () => null);
        var refs = await src.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None);
        Assert.Empty(refs);
        // We must not even attempt to run grep when the dir is absent.
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Records_template_paths_and_ids_when_grep_hits()
    {
        var templates = Path.Combine(_workDir, "nuclei-templates");
        Directory.CreateDirectory(templates);
        var runner = new RecordingProcessRunner();
        var stdout = string.Join('\n', new[]
        {
            Path.Combine(templates, "cves", "2011", "CVE-2011-2523.yaml"),
            Path.Combine(templates, "http", "vsftpd-backdoor.yaml"),
        });
        runner.OnRun((f, a) => f == "grep" && a.Contains("CVE-2011-2523"), 0, stdout: stdout);

        var src = new NucleiSource(runner, templatesDirProbe: () => templates);
        var refs = await src.QueryAsync("CVE-2011-2523", Ctx(), CancellationToken.None);

        Assert.Equal(2, refs.Count);
        Assert.Contains(refs, r => r.ExternalId == "CVE-2011-2523");
        Assert.Contains(refs, r => r.ExternalId == "vsftpd-backdoor");
        Assert.All(refs, r => Assert.Equal("nuclei", r.Source));
        Assert.All(refs, r => Assert.NotNull(r.LocalPath));
    }

    [Fact]
    public async Task Grep_no_match_exits_1_and_returns_empty()
    {
        var templates = Path.Combine(_workDir, "nuclei-templates");
        Directory.CreateDirectory(templates);
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, _) => f == "grep", 1, stdout: "");

        var src = new NucleiSource(runner, templatesDirProbe: () => templates);
        Assert.Empty(await src.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None));
    }
}
