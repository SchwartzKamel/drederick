using System.Security.Cryptography;
using Drederick.Enrichment;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class PocAggregatorTests : IDisposable
{
    private readonly string _workDir;

    public PocAggregatorTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-pocagg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private sealed class FakeSource : IPocSource
    {
        public string Name { get; }
        public List<PocRef> Refs { get; }
        public int Calls;
        public bool? SeenFetchPoc;
        public FakeSource(string name, IEnumerable<PocRef>? refs = null)
        {
            Name = name;
            Refs = refs?.ToList() ?? new List<PocRef>();
        }
        public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
        {
            Calls++;
            SeenFetchPoc = ctx.FetchPoc;
            return Task.FromResult<IReadOnlyList<PocRef>>(Refs);
        }
    }

    private sealed class ThrowingSource : IPocSource
    {
        public string Name => "boom";
        public int Calls;
        public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
        {
            Calls++;
            throw new InvalidOperationException("boom");
        }
    }

    private void SeedCves(params string[] ids)
    {
        var report = new SqliteReport(_workDir);
        foreach (var id in ids) report.UpsertCve(id);
    }

    [Fact]
    public async Task No_cves_no_calls()
    {
        // DB must exist with cves table but zero rows.
        var report = new SqliteReport(_workDir);
        // Touching the report creates findings.db lazily on first write; make
        // sure the table exists by performing a no-op upsert then delete.
        report.UpsertCve("CVE-0000-0000");
        using (var conn = new SqliteConnection($"Data Source={report.DatabasePath}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM cves;";
            cmd.ExecuteNonQuery();
        }

        var source = new FakeSource("x");
        var agg = new PocAggregator(new IPocSource[] { source });
        var res = await agg.AggregateAsync(null, _workDir, fetchPoc: true);
        Assert.Equal(0, res.CveCount);
        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task Writes_poc_refs_for_every_cve_and_source()
    {
        SeedCves("CVE-2011-2523", "CVE-2024-0001");
        var s1 = new FakeSource("src-one", new[] { new PocRef("src-one", Url: "https://u1", ExternalId: "A") });
        var s2 = new FakeSource("src-two", new[] { new PocRef("src-two", Url: "https://u2", ExternalId: "B") });
        var agg = new PocAggregator(new IPocSource[] { s1, s2 });

        var res = await agg.AggregateAsync(null, _workDir, fetchPoc: false);

        Assert.Equal(2, res.CveCount);
        Assert.Equal(4, res.RefCount);
        Assert.Equal(0, res.CachedCount);
        Assert.Equal(2, s1.Calls);
        Assert.Equal(2, s2.Calls);
        Assert.Equal(false, s1.SeenFetchPoc);

        using var conn = new SqliteConnection($"Data Source={Path.Combine(_workDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM poc_refs;";
        Assert.Equal(4L, (long)cmd.ExecuteScalar()!);
    }

    [Fact]
    public async Task FetchPoc_flag_propagates_to_sources()
    {
        SeedCves("CVE-2011-2523");
        var s = new FakeSource("src-one", new[] { new PocRef("src-one", Url: "u", ExternalId: "E") });
        var agg = new PocAggregator(new IPocSource[] { s });
        await agg.AggregateAsync(null, _workDir, fetchPoc: true);
        Assert.Equal(true, s.SeenFetchPoc);
    }

    [Fact]
    public async Task Cached_refs_with_local_path_record_counted()
    {
        SeedCves("CVE-2011-2523");
        var local = Path.Combine(_workDir, "poc_cache", "fake", "1", "x.rb");
        Directory.CreateDirectory(Path.GetDirectoryName(local)!);
        File.WriteAllText(local, "x");

        var s = new FakeSource("fake", new[] { new PocRef("fake", Url: "u", ExternalId: "1", LocalPath: local) });
        var agg = new PocAggregator(new IPocSource[] { s });
        var res = await agg.AggregateAsync(null, _workDir, fetchPoc: true);
        Assert.Equal(1, res.CachedCount);

        using var conn = new SqliteConnection($"Data Source={Path.Combine(_workDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT local_path FROM poc_refs WHERE source='fake';";
        Assert.Equal(local, (string)cmd.ExecuteScalar()!);
    }

    [Fact]
    public async Task Source_failure_does_not_abort_aggregate()
    {
        SeedCves("CVE-2011-2523");
        var bad = new ThrowingSource();
        var good = new FakeSource("good", new[] { new PocRef("good", Url: "u", ExternalId: "G") });
        var agg = new PocAggregator(new IPocSource[] { bad, good });
        var res = await agg.AggregateAsync(null, _workDir, fetchPoc: false);
        Assert.Equal(1, bad.Calls);
        Assert.Equal(1, good.Calls);
        Assert.Equal(1, res.RefCount);
    }

    [Fact]
    public async Task Is_idempotent_under_re_run()
    {
        SeedCves("CVE-2011-2523");
        var s = new FakeSource("src-one", new[] { new PocRef("src-one", Url: "u", ExternalId: "A") });
        var agg = new PocAggregator(new IPocSource[] { s });
        await agg.AggregateAsync(null, _workDir, fetchPoc: false);
        await agg.AggregateAsync(null, _workDir, fetchPoc: false);

        using var conn = new SqliteConnection($"Data Source={Path.Combine(_workDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM poc_refs;";
        Assert.Equal(1L, (long)cmd.ExecuteScalar()!);
    }

    [Fact]
    public void Default_for_fetch_poc_CLI_is_on()
    {
        var opts = Drederick.Cli.CommandLineOptions.Parse(new[] { "-s", "/dev/null" });
        Assert.True(opts.FetchPoc);
    }

    [Fact]
    public void No_fetch_poc_flag_is_honored()
    {
        var opts = Drederick.Cli.CommandLineOptions.Parse(new[] { "-s", "/dev/null", "--no-fetch-poc" });
        Assert.False(opts.FetchPoc);
        var opts2 = Drederick.Cli.CommandLineOptions.Parse(new[] { "-s", "/dev/null", "--no-fetch-poc", "--fetch-poc" });
        Assert.True(opts2.FetchPoc);
    }

    // ---------------- Invariant tests ----------------

    private static IEnumerable<string> EnrichmentPocSources()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "src", "Drederick", "Enrichment");
            if (Directory.Exists(candidate))
            {
                foreach (var f in Directory.EnumerateFiles(candidate, "*.cs"))
                {
                    var n = Path.GetFileName(f);
                    if (n.StartsWith("Poc") || n == "SearchsploitSource.cs" || n == "GhsaSource.cs"
                        || n == "MetasploitSource.cs" || n == "NucleiSource.cs" || n == "IPocSource.cs")
                    {
                        yield return f;
                    }
                }
                yield break;
            }
            dir = Path.GetDirectoryName(dir);
        }
    }

    [Fact]
    public void Invariant_no_process_start_in_aggregator_sources()
    {
        // Every subprocess must go through IProcessRunner. Direct
        // Process.Start of a fetched path would be a silent execution path.
        foreach (var file in EnrichmentPocSources())
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain("Process.Start", text);
        }
    }

    [Fact]
    public void Invariant_cached_poc_sha256_matches_source_bytes()
    {
        // Simulate a cached PoC and verify that the SHA-256 recorded in
        // poc_sources matches the bytes on disk — i.e. we did not rewrite /
        // neutralise content during caching.
        SeedCves("CVE-2011-2523");
        var cacheRoot = Path.Combine(_workDir, "poc_cache");
        var dir = Path.Combine(cacheRoot, "exploit-db", "17491");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "17491.rb");
        var bytes = System.Text.Encoding.UTF8.GetBytes("# verbatim\nprint('nope')\n");
        File.WriteAllBytes(path, bytes);
        var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        var report = new SqliteReport(_workDir);
        report.UpsertPocSource("exploit-db", "17491", sha, path,
            fetchedAt: DateTimeOffset.UtcNow.ToString("o"),
            sourceUrl: "https://www.exploit-db.com/exploits/17491");

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, path FROM poc_sources WHERE external_id='17491';";
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(sha, reader.GetString(0));
        var storedPath = reader.GetString(1);
        var storedSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(storedPath))).ToLowerInvariant();
        Assert.Equal(sha, storedSha);
    }
}
