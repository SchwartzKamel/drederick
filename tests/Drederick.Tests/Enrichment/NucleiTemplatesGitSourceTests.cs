using Drederick.Enrichment;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

public class NucleiTemplatesGitSourceTests : IDisposable
{
    private readonly string _workDir;
    private readonly Drederick.Audit.AuditLog _audit;
    private readonly Drederick.Reporting.SqliteReport _report;

    public NucleiTemplatesGitSourceTests()
    {
        (_workDir, _audit, _report) = TestEnv.Make("nucgit");
    }

    public void Dispose()
    {
        _audit.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private PocQueryContext Ctx(bool fetch = true) => TestEnv.Ctx(_workDir, _audit, _report, fetch);

    [Fact]
    public async Task NoFetchPoc_returns_empty_without_clone()
    {
        var git = new FakeGitClient();
        var src = new NucleiTemplatesGitSource(git);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(fetch: false), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Empty(git.Clones);
    }

    [Fact]
    public async Task Direct_path_match_under_http_cves_year()
    {
        var git = new FakeGitClient();
        git.Layout["http/cves/2023/cve-2023-12345.yaml"] =
            System.Text.Encoding.UTF8.GetBytes("id: CVE-2023-12345\ninfo:\n  name: test\n");
        var src = new NucleiTemplatesGitSource(git);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(refs);
        Assert.Equal("nuclei-git", refs[0].Source);
        Assert.NotNull(refs[0].LocalPath);
        Assert.Equal("cve-2023-12345.yaml", refs[0].ExternalId);
    }

    [Fact]
    public async Task Sparse_paths_include_http_and_dns_cves()
    {
        var git = new FakeGitClient();
        git.Layout["dns/cves/2023/cve-2023-99999.yaml"] = System.Text.Encoding.UTF8.GetBytes("id: x");
        var src = new NucleiTemplatesGitSource(git);

        await src.QueryAsync("CVE-2023-99999", Ctx(), CancellationToken.None);

        var clone = Assert.Single(git.Clones);
        Assert.Contains("http/cves", clone.SparsePaths);
        Assert.Contains("dns/cves", clone.SparsePaths);
    }

    [Fact]
    public async Task Cache_hit_short_circuits_on_second_call()
    {
        var git = new FakeGitClient();
        git.Layout["http/cves/2023/cve-2023-11111.yaml"] = System.Text.Encoding.UTF8.GetBytes("a");
        git.Layout["http/cves/2023/cve-2023-22222.yaml"] = System.Text.Encoding.UTF8.GetBytes("b");
        var src = new NucleiTemplatesGitSource(git);

        await src.QueryAsync("CVE-2023-11111", Ctx(), CancellationToken.None);
        await src.QueryAsync("CVE-2023-22222", Ctx(), CancellationToken.None);

        Assert.Single(git.Clones);
    }

    [Fact]
    public async Task Cve_not_found_emits_miss()
    {
        var git = new FakeGitClient();
        git.Layout["http/cves/2023/cve-2023-11111.yaml"] = System.Text.Encoding.UTF8.GetBytes("x");
        var src = new NucleiTemplatesGitSource(git);

        var refs = await src.QueryAsync("CVE-2099-99999", Ctx(), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("\"poc.fetch.miss\""));
    }

    [Fact]
    public async Task Size_cap_skips_oversized()
    {
        var git = new FakeGitClient();
        git.Layout["http/cves/2023/cve-2023-12345.yaml"] = new byte[8 * 1024];
        var src = new NucleiTemplatesGitSource(git, maxArtifactBytes: 1024);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(refs);
        Assert.Null(refs[0].LocalPath);
    }

    [Fact]
    public async Task Provenance_recorded_in_poc_sources()
    {
        var git = new FakeGitClient();
        git.Layout["http/cves/2023/cve-2023-12345.yaml"] = System.Text.Encoding.UTF8.GetBytes("x");
        var src = new NucleiTemplatesGitSource(git);

        await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        using var conn = new SqliteConnection($"Data Source={_report.DatabasePath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM poc_sources WHERE source='nuclei-git';";
        Assert.Equal(1L, (long)cmd.ExecuteScalar()!);
    }
}
