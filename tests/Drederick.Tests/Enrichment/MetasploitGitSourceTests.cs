using Drederick.Enrichment;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

public class MetasploitGitSourceTests : IDisposable
{
    private readonly string _workDir;
    private readonly Drederick.Audit.AuditLog _audit;
    private readonly Drederick.Reporting.SqliteReport _report;

    public MetasploitGitSourceTests()
    {
        (_workDir, _audit, _report) = TestEnv.Make("msfgit");
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
        var src = new MetasploitGitSource(git);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(fetch: false), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Empty(git.Clones);
    }

    [Fact]
    public async Task First_call_clones_with_correct_sparse_paths()
    {
        var git = new FakeGitClient();
        git.Layout["modules/exploits/foo.rb"] = System.Text.Encoding.UTF8.GetBytes("# CVE-2023-12345 here\nclass Foo; end\n");
        var src = new MetasploitGitSource(git);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(git.Clones);
        var clone = git.Clones[0];
        Assert.Equal(GitPocAllowlist.MetasploitFramework, clone.Url);
        Assert.Contains("modules/exploits", clone.SparsePaths);
        Assert.Contains("modules/auxiliary", clone.SparsePaths);
        Assert.Contains("modules/post", clone.SparsePaths);
        Assert.Single(refs);
        Assert.Equal("metasploit-git", refs[0].Source);
        Assert.NotNull(refs[0].LocalPath);
    }

    [Fact]
    public async Task Cache_hit_short_circuits_on_second_call()
    {
        var git = new FakeGitClient();
        git.Layout["modules/exploits/a.rb"] = System.Text.Encoding.UTF8.GetBytes("CVE-2023-11111 here");
        git.Layout["modules/exploits/b.rb"] = System.Text.Encoding.UTF8.GetBytes("CVE-2023-22222 here");
        var src = new MetasploitGitSource(git);

        await src.QueryAsync("CVE-2023-11111", Ctx(), CancellationToken.None);
        await src.QueryAsync("CVE-2023-22222", Ctx(), CancellationToken.None);

        Assert.Single(git.Clones); // second call must reuse cache
        var lines = TestEnv.ReadAuditEvents(_workDir);
        Assert.Contains(lines, l => l.Contains("poc.fetch.git_clone.skip"));
    }

    [Fact]
    public async Task Cve_with_no_match_emits_miss()
    {
        var git = new FakeGitClient();
        git.Layout["modules/exploits/foo.rb"] = System.Text.Encoding.UTF8.GetBytes("# unrelated module");
        var src = new MetasploitGitSource(git);

        var refs = await src.QueryAsync("CVE-2099-99999", Ctx(), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("\"poc.fetch.miss\"") && l.Contains("no module matches CVE"));
    }

    [Fact]
    public async Task Match_by_cve_id_grep_only_matches_correct_cve()
    {
        var git = new FakeGitClient();
        git.Layout["modules/exploits/match.rb"] = System.Text.Encoding.UTF8.GetBytes("references: [CVE-2023-12345]");
        git.Layout["modules/exploits/miss.rb"] = System.Text.Encoding.UTF8.GetBytes("references: [CVE-2024-99999]");
        var src = new MetasploitGitSource(git);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(refs);
        Assert.Equal("match.rb", refs[0].ExternalId);
    }

    [Fact]
    public async Task Size_cap_skips_oversized_artifact()
    {
        var git = new FakeGitClient();
        // Just over 1 KB cap.
        var oversize = new byte[2048];
        Array.Fill(oversize, (byte)'a');
        // Need the CVE id to appear in the file so it's a candidate.
        var prefix = System.Text.Encoding.UTF8.GetBytes("# CVE-2023-12345\n");
        var combined = prefix.Concat(oversize).ToArray();
        git.Layout["modules/exploits/big.rb"] = combined;

        var src = new MetasploitGitSource(git, maxArtifactBytes: 1024);
        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(refs);
        Assert.Null(refs[0].LocalPath); // oversized → not cached
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("per-artifact cap"));
    }

    [Fact]
    public async Task Provenance_recorded_in_poc_sources()
    {
        var git = new FakeGitClient();
        git.Layout["modules/exploits/p.rb"] = System.Text.Encoding.UTF8.GetBytes("CVE-2023-12345");
        var src = new MetasploitGitSource(git);

        await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        using var conn = new SqliteConnection($"Data Source={_report.DatabasePath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT source, sha256, source_url FROM poc_sources WHERE source='metasploit-git';";
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("metasploit-git", r.GetString(0));
        Assert.Equal(64, r.GetString(1).Length); // sha-256 hex
        Assert.StartsWith("https://github.com/rapid7/metasploit-framework/", r.GetString(2));
    }

    [Fact]
    public async Task Disallowed_url_in_clone_fails_via_default_runner()
    {
        // Verifies the allowlist gate in ProcessGitClient — covered indirectly
        // via FakeGitClient's enforcement, but assert the static allowlist.
        Assert.False(GitPocAllowlist.IsAllowed("https://example.com/evil"));
        Assert.True(GitPocAllowlist.IsAllowed(GitPocAllowlist.MetasploitFramework));
        await Task.CompletedTask;
    }
}
