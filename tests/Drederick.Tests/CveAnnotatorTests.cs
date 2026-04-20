using Drederick.Enrichment;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class CveAnnotatorTests : IDisposable
{
    private readonly string _workDir;

    public CveAnnotatorTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-cve-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string FindFixturePath()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", "nvd-mini.json.gz");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException("fixture not found: nvd-mini.json.gz");
    }

    private string NewCacheDir()
    {
        var d = Path.Combine(_workDir, "cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    private string SeedCacheWithFixture()
    {
        var cache = NewCacheDir();
        File.Copy(FindFixturePath(), Path.Combine(cache, "nvdcve-2.0-2011.json.gz"));
        return cache;
    }

    private string NewOutDir()
    {
        var d = Path.Combine(_workDir, "out-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    private static HostFinding Finding(string target, NmapPort port) => new()
    {
        Target = target,
        Started = DateTimeOffset.UtcNow.ToString("o"),
        Finished = DateTimeOffset.UtcNow.ToString("o"),
        Nmap = new NmapResult { ReturnCode = 0, OpenPorts = new() { port } },
    };

    private sealed class ThrowingFetcher : IHttpFetcher
    {
        public int Calls;
        public Task<byte[]?> FetchAsync(string url, CancellationToken ct)
        {
            Calls++;
            throw new HttpRequestException("offline");
        }
    }

    [Fact]
    public async Task NvdCache_loads_fixture()
    {
        var cache = new NvdCache(
            cacheDir: SeedCacheWithFixture(),
            fetcher: new ThrowingFetcher(),
            refreshInterval: TimeSpan.FromDays(365));
        var entries = await cache.LoadAsync();
        Assert.Equal(5, entries.Count);
        var vsftpd = entries.Single(e => e.CveId == "CVE-2011-2523");
        Assert.Equal(9.8, vsftpd.Cvss);
        Assert.StartsWith("vsftpd 2.3.4", vsftpd.Summary);
        Assert.Single(vsftpd.CpeMatches);
    }

    [Fact]
    public async Task CpeMatcher_returns_expected_cve_for_exact_version()
    {
        var cache = new NvdCache(SeedCacheWithFixture(), new ThrowingFetcher(), TimeSpan.FromDays(365));
        var matcher = new CpeMatcher(await cache.LoadAsync());

        var hits = matcher.Match(vendor: null, product: "vsftpd", version: "2.3.4");
        Assert.Contains(hits, h => h.CveId == "CVE-2011-2523");

        var none = matcher.Match(vendor: null, product: "vsftpd", version: "3.0.0");
        Assert.DoesNotContain(none, h => h.CveId == "CVE-2011-2523");
    }

    [Fact]
    public async Task CpeMatcher_handles_version_end_excluding()
    {
        var cache = new NvdCache(SeedCacheWithFixture(), new ThrowingFetcher(), TimeSpan.FromDays(365));
        var matcher = new CpeMatcher(await cache.LoadAsync());

        // CVE-2016-0777 is versionEndExcluding 7.1p2 → 7.0 matches, 7.1p2 does not.
        Assert.Contains(matcher.Match(null, "openssh", "7.0"), h => h.CveId == "CVE-2016-0777");
        Assert.DoesNotContain(matcher.Match(null, "openssh", "7.1p2"), h => h.CveId == "CVE-2016-0777");
        Assert.DoesNotContain(matcher.Match(null, "openssh", "8.0"), h => h.CveId == "CVE-2016-0777");

        // CVE-2020-14145 has a start..end inclusive range covering 8.4.
        Assert.Contains(matcher.Match(null, "openssh", "8.4"), h => h.CveId == "CVE-2020-14145");
        Assert.DoesNotContain(matcher.Match(null, "openssh", "5.6"), h => h.CveId == "CVE-2020-14145");
    }

    [Fact]
    public async Task Annotator_writes_cve_for_vsftpd_host()
    {
        var cache = new NvdCache(SeedCacheWithFixture(), new ThrowingFetcher(), TimeSpan.FromDays(365));
        var outDir = NewOutDir();
        var port = new NmapPort { Port = 21, Protocol = "tcp", Service = "ftp", Product = "vsftpd", Version = "2.3.4" };
        var findings = new List<HostFinding> { Finding("10.0.0.1", port) };
        new SqliteReport(outDir).WriteReport(findings);

        var annotator = new CveAnnotator(cache);
        var result = await annotator.AnnotateAsync(findings, outDir);

        Assert.True(result.CacheLoaded);
        Assert.True(result.CveCount >= 1);
        Assert.True(result.FindingCount >= 1);

        var cves = LoadCveIds(outDir);
        Assert.Contains("CVE-2011-2523", cves);

        var findingRows = LoadCveFindingPayloads(outDir);
        Assert.Contains(findingRows, p => p.Contains("CVE-2011-2523"));
    }

    [Fact]
    public async Task Annotator_is_idempotent()
    {
        var cache = new NvdCache(SeedCacheWithFixture(), new ThrowingFetcher(), TimeSpan.FromDays(365));
        var outDir = NewOutDir();
        var port = new NmapPort { Port = 21, Protocol = "tcp", Service = "ftp", Product = "vsftpd", Version = "2.3.4" };
        var findings = new List<HostFinding> { Finding("10.0.0.1", port) };
        new SqliteReport(outDir).WriteReport(findings);

        var annotator = new CveAnnotator(cache);
        await annotator.AnnotateAsync(findings, outDir);
        var r2 = await annotator.AnnotateAsync(findings, outDir);

        // Second pass may report CveCount > 0 (UpsertCve runs) but no new
        // findings rows should be inserted.
        Assert.Equal(0, r2.FindingCount);
        Assert.Equal(1, CountCveFindings(outDir));
        Assert.Equal(1, CountCveRows(outDir));
    }

    [Fact]
    public async Task Annotator_uses_existing_cache_when_fetcher_fails()
    {
        // Pre-populate cache, then make it "stale" so a refresh is attempted.
        var cache = SeedCacheWithFixture();
        foreach (var f in Directory.EnumerateFiles(cache))
        {
            File.SetLastWriteTimeUtc(f, DateTime.UtcNow - TimeSpan.FromDays(30));
        }
        var fetcher = new ThrowingFetcher();
        var nvd = new NvdCache(cache, fetcher, TimeSpan.FromHours(24));

        var entries = await nvd.LoadAsync();
        Assert.True(fetcher.Calls > 0, "fetcher should have been called since cache was stale");
        Assert.Equal(5, entries.Count); // offline fallback still loaded existing feed
    }

    [Fact]
    public async Task Annotator_returns_empty_when_no_cache_and_offline()
    {
        var nvd = new NvdCache(NewCacheDir(), new ThrowingFetcher(), TimeSpan.FromHours(24));
        var outDir = NewOutDir();
        new SqliteReport(outDir).WriteReport(new List<HostFinding>());

        var result = await new CveAnnotator(nvd).AnnotateAsync(new List<HostFinding>(), outDir);
        Assert.False(result.CacheLoaded);
        Assert.Equal(0, result.CveCount);
    }

    // ---------- helpers that read back findings.db ----------

    private static List<string> LoadCveIds(string outDir)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT cve_id FROM cves ORDER BY cve_id;";
        var result = new List<string>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) result.Add(r.GetString(0));
        return result;
    }

    private static List<string> LoadCveFindingPayloads(string outDir)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT data_json FROM findings WHERE kind='cve';";
        var result = new List<string>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) result.Add(r.GetString(0));
        return result;
    }

    private static int CountCveFindings(string outDir)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM findings WHERE kind='cve';";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static int CountCveRows(string outDir)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM cves;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }
}
