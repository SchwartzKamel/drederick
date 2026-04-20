using Drederick.Enrichment;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class GhsaSourceTests : IDisposable
{
    private readonly string _workDir;

    public GhsaSourceTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-ghsa-" + Guid.NewGuid().ToString("N"));
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

    private sealed class StubFetcher : IHttpFetcher
    {
        private readonly byte[]? _body;
        private readonly Exception? _throw;
        public List<string> Calls { get; } = new();
        public int ThrowCount { get; set; }
        public StubFetcher(byte[]? body, Exception? ex = null) { _body = body; _throw = ex; }
        public Task<byte[]?> FetchAsync(string url, CancellationToken ct)
        {
            Calls.Add(url);
            if (_throw is not null && Calls.Count <= ThrowCount) throw _throw;
            return Task.FromResult(_body);
        }
    }

    private PocQueryContext Ctx() => new(Path.Combine(_workDir, "cache"), false, new SqliteReport(_workDir));

    [Fact]
    public async Task Parses_advisory_and_references()
    {
        var json = LoadFixture("ghsa-sample.json");
        var fetcher = new StubFetcher(System.Text.Encoding.UTF8.GetBytes(json));
        var src = new GhsaSource(fetcher);

        var refs = await src.QueryAsync("CVE-2011-2523", Ctx(), CancellationToken.None);

        Assert.Single(fetcher.Calls);
        Assert.Contains("cve_id=CVE-2011-2523", fetcher.Calls[0]);

        // 1 advisory ref + 3 reference URLs (one as object) = 4
        Assert.Equal(4, refs.Count);
        Assert.All(refs, r => Assert.Equal("ghsa", r.Source));
        Assert.Contains(refs, r => r.Url == "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz");
        Assert.Contains(refs, r => r.Url == "https://github.com/example/poc-vsftpd");
        Assert.Contains(refs, r => r.Url == "https://nvd.nist.gov/vuln/detail/CVE-2011-2523");
        // external_ids are distinct so poc_refs UNIQUE(cve, source, external_id) holds.
        Assert.Equal(refs.Count, refs.Select(r => r.ExternalId).Distinct().Count());
    }

    [Fact]
    public async Task Empty_body_returns_empty()
    {
        var src = new GhsaSource(new StubFetcher(Array.Empty<byte>()));
        Assert.Empty(await src.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None));

        var src2 = new GhsaSource(new StubFetcher(null));
        Assert.Empty(await src2.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None));
    }

    [Fact]
    public async Task Http_failure_returns_empty_and_does_not_throw()
    {
        // Rate-limit / network failures must not abort the aggregator. The
        // spec calls this "rate-limit respect".
        var fetcher = new StubFetcher(null, new HttpRequestException("403 rate-limited"))
        {
            ThrowCount = 1,
        };
        var src = new GhsaSource(fetcher);
        var refs = await src.QueryAsync("CVE-2024-0001", Ctx(), CancellationToken.None);
        Assert.Empty(refs);
    }

    [Theory]
    [InlineData("https://github.com/example/poc-vsftpd", true)]
    [InlineData("https://github.com/example/exploit-foo", true)]
    [InlineData("https://github.com/rapid7/metasploit-framework", false)]
    [InlineData("https://nvd.nist.gov/vuln/detail/CVE-2011-2523", false)]
    [InlineData("not-a-url", false)]
    public void LooksLikePocRepoPath_classifies(string url, bool expected)
    {
        Assert.Equal(expected, GhsaSource.LooksLikePocRepoPath(url));
    }
}
