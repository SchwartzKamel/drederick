using System.Text;
using Drederick.Enrichment;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

public class PocInGitHubSourceTests : IDisposable
{
    private readonly string _workDir;
    private readonly Drederick.Audit.AuditLog _audit;
    private readonly Drederick.Reporting.SqliteReport _report;
    private readonly string? _origToken;

    public PocInGitHubSourceTests()
    {
        (_workDir, _audit, _report) = TestEnv.Make("pigh");
        _origToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", _origToken);
        _audit.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private PocQueryContext Ctx(bool fetch = true) => TestEnv.Ctx(_workDir, _audit, _report, fetch);

    private static byte[] J(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Manifest(params (string owner, string repo)[] repos)
    {
        var sb = new StringBuilder("[");
        for (int i = 0; i < repos.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append($"{{\"full_name\":\"{repos[i].owner}/{repos[i].repo}\"}}");
        }
        sb.Append(']');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static byte[] Listing(params string[] files)
    {
        var sb = new StringBuilder("[");
        for (int i = 0; i < files.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append($"{{\"type\":\"file\",\"name\":\"{files[i]}\"}}");
        }
        sb.Append(']');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    [Fact]
    public async Task NoFetchPoc_returns_empty_without_clone()
    {
        var git = new FakeGitClient();
        var http = new FakeGitHubHttpClient();
        var src = new PocInGitHubSource(git, http);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(fetch: false), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Empty(git.Clones);
        Assert.Empty(http.RequestedUrls);
    }

    [Fact]
    public async Task Manifest_drives_top_files_fetch_per_repo()
    {
        var git = new FakeGitClient();
        git.Layout["2023/CVE-2023-12345.json"] = Manifest(("alice", "poc1"), ("bob", "poc2"));
        var http = new FakeGitHubHttpClient();
        http.Responses["https://api.github.com/repos/alice/poc1/contents/"] =
            new GitHubFetchResult(200, Listing("a.py", "b.py"), "application/json", null);
        http.Responses["https://api.github.com/repos/bob/poc2/contents/"] =
            new GitHubFetchResult(200, Listing("x.rb"), "application/json", null);
        http.Responses["https://raw.githubusercontent.com/alice/poc1/HEAD/a.py"] =
            new GitHubFetchResult(200, J("# poc a"), "text/plain", null);
        http.Responses["https://raw.githubusercontent.com/alice/poc1/HEAD/b.py"] =
            new GitHubFetchResult(200, J("# poc b"), "text/plain", null);
        http.Responses["https://raw.githubusercontent.com/bob/poc2/HEAD/x.rb"] =
            new GitHubFetchResult(200, J("# poc x"), "text/plain", null);

        var src = new PocInGitHubSource(git, http);
        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Equal(3, refs.Count);
        Assert.All(refs, r => Assert.Equal("poc-in-github", r.Source));
        Assert.All(refs, r => Assert.NotNull(r.LocalPath));
        // verify cache file layout
        var cveCache = Path.Combine(_workDir, "poc_cache", "poc-in-github", "CVE-2023-12345");
        Assert.True(Directory.Exists(Path.Combine(cveCache, "alice__poc1")));
        Assert.True(Directory.Exists(Path.Combine(cveCache, "bob__poc2")));
    }

    [Fact]
    public async Task Manifest_missing_emits_miss()
    {
        var git = new FakeGitClient();
        // empty layout — no manifest file
        var http = new FakeGitHubHttpClient();
        var src = new PocInGitHubSource(git, http);

        var refs = await src.QueryAsync("CVE-2023-99999", Ctx(), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("manifest missing"));
    }

    [Fact]
    public async Task Rate_limit_429_records_event_and_halts_without_throw()
    {
        var git = new FakeGitClient();
        git.Layout["2023/CVE-2023-12345.json"] = Manifest(("a", "p1"), ("b", "p2"));
        var http = new FakeGitHubHttpClient
        {
            DefaultResponse = new GitHubFetchResult(429, null, null, RetryAfterSeconds: 60),
        };

        var src = new PocInGitHubSource(git, http);
        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Empty(refs);
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("\"poc.fetch.rate_limited\""));
        // After the first 429, we must NOT keep hammering the second repo.
        Assert.Single(http.RequestedUrls);
    }

    [Fact]
    public async Task Github_token_sets_bearer_via_default_client()
    {
        // Cover the env-driven Bearer header path through DefaultGitHubHttpClient.
        // We intercept via a custom HttpMessageHandler.
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", "test-token-xyz");
        try
        {
            var capture = new CapturingHandler();
            using var http = new HttpClient(capture);
            var client = new DefaultGitHubHttpClient(http);

            await client.GetAsync("https://api.github.com/repos/foo/bar/contents/", CancellationToken.None);

            Assert.NotNull(capture.LastAuth);
            Assert.Equal("Bearer", capture.LastAuth!.Scheme);
            Assert.Equal("test-token-xyz", capture.LastAuth!.Parameter);
        }
        finally { Environment.SetEnvironmentVariable("GITHUB_TOKEN", null); }
    }

    [Fact]
    public async Task Cache_hit_short_circuits_on_second_call()
    {
        var git = new FakeGitClient();
        git.Layout["2023/CVE-2023-11111.json"] = Manifest(("o", "r"));
        git.Layout["2023/CVE-2023-22222.json"] = Manifest(("o2", "r2"));
        var http = new FakeGitHubHttpClient();
        http.DefaultResponse = new GitHubFetchResult(200, Listing(), "application/json", null);
        var src = new PocInGitHubSource(git, http);

        await src.QueryAsync("CVE-2023-11111", Ctx(), CancellationToken.None);
        await src.QueryAsync("CVE-2023-22222", Ctx(), CancellationToken.None);

        Assert.Single(git.Clones);
    }

    [Fact]
    public async Task Size_cap_skips_oversized_http_artifact()
    {
        var git = new FakeGitClient();
        git.Layout["2023/CVE-2023-12345.json"] = Manifest(("alice", "poc"));
        var http = new FakeGitHubHttpClient();
        http.Responses["https://api.github.com/repos/alice/poc/contents/"] =
            new GitHubFetchResult(200, Listing("big.bin"), "application/json", null);
        http.Responses["https://raw.githubusercontent.com/alice/poc/HEAD/big.bin"] =
            new GitHubFetchResult(200, new byte[8 * 1024], "application/octet-stream", null);

        var src = new PocInGitHubSource(git, http, maxArtifactBytes: 1024);
        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Single(refs);
        Assert.Null(refs[0].LocalPath);
        Assert.Contains(TestEnv.ReadAuditEvents(_workDir), l => l.Contains("per-artifact cap"));
    }

    [Fact]
    public async Task Malicious_owner_name_rejected()
    {
        var git = new FakeGitClient();
        git.Layout["2023/CVE-2023-12345.json"] = J("[{\"full_name\":\"../../etc/passwd\"}]");
        var http = new FakeGitHubHttpClient();
        var src = new PocInGitHubSource(git, http);

        var refs = await src.QueryAsync("CVE-2023-12345", Ctx(), CancellationToken.None);

        Assert.Empty(refs);
        // No HTTP requests should ever be made for an evil owner string.
        Assert.Empty(http.RequestedUrls);
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public System.Net.Http.Headers.AuthenticationHeaderValue? LastAuth { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastAuth = request.Headers.Authorization;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Array.Empty<byte>()),
            });
        }
    }
}
