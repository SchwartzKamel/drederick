using System.Net;
using Drederick.Audit;
using Drederick.Enrichment;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-033 — verifies <see cref="CveLeadResolver"/> auto-pursues unmatched
/// CVE leads via <see cref="PocAggregator.FetchOnDemandAsync"/>, audits the
/// outcome as <c>cve.lead.pursued</c>, respects <c>--no-fetch-poc</c> /
/// network-unavailable signals as <c>cve.lead.skipped_offline</c>, dedupes
/// in-run, and backs off on 429 rate-limit responses.
/// </summary>
public class CveLeadResolverTests : IDisposable
{
    private readonly string _workDir;

    public CveLeadResolverTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-cve-lead-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_workDir)) Directory.Delete(_workDir, recursive: true); }
        catch { }
    }

    private string SeedDb(IEnumerable<(string cve, bool cachedPoc)> rows)
    {
        var dbPath = Path.Combine(_workDir, "findings.db");
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS cves (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL UNIQUE,
  cvss REAL, summary TEXT, published TEXT);
CREATE TABLE IF NOT EXISTS poc_refs (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT, external_id TEXT, local_path TEXT, fetched_at TEXT,
  UNIQUE(cve_id, source, external_id));";
            cmd.ExecuteNonQuery();
        }
        foreach (var (cve, cached) in rows)
        {
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO cves(cve_id) VALUES($c);";
                cmd.Parameters.AddWithValue("$c", cve);
                cmd.ExecuteNonQuery();
            }
            if (cached)
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"INSERT INTO poc_refs(cve_id, source, external_id, local_path)
VALUES($c, 'searchsploit', 'EDB-1', '/tmp/x.rb');";
                cmd.Parameters.AddWithValue("$c", cve);
                cmd.ExecuteNonQuery();
            }
        }
        return dbPath;
    }

    private AuditLog OpenAudit(out string path)
    {
        path = Path.Combine(_workDir, "audit.jsonl");
        return new AuditLog(path);
    }

    private static IReadOnlyList<string> ReadEvents(string auditPath, string eventName)
    {
        if (!File.Exists(auditPath)) return Array.Empty<string>();
        return File.ReadAllLines(auditPath)
            .Where(l => l.Contains($"\"event\":\"{eventName}\"", StringComparison.Ordinal))
            .ToArray();
    }

    [Fact]
    public async Task Unmatched_Cve_Triggers_Fetch_And_Records_Pursued()
    {
        SeedDb(new[] { ("CVE-2024-0001", false) });
        var audit = OpenAudit(out var auditPath);

        var calls = new List<string>();
        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
        {
            calls.Add(cve);
            return Task.FromResult(new PocAggregator.FetchOnDemandResult(
                cve, RefCount: 3, ArtifactCount: 1,
                SourcesWithArtifact: new[] { "metasploit-git" }));
        }
        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: true);

        var outcomes = await resolver.ResolveAsync(_workDir, CancellationToken.None);

        Assert.Single(outcomes);
        Assert.True(outcomes[0].Succeeded);
        Assert.Equal("pursued", outcomes[0].Status);
        Assert.Equal(1, outcomes[0].PocsCached);
        Assert.Single(calls);
        Assert.Equal("CVE-2024-0001", calls[0]);

        audit.Dispose();
        var pursued = ReadEvents(auditPath, "cve.lead.pursued");
        Assert.Single(pursued);
        Assert.Contains("CVE-2024-0001", pursued[0]);
    }

    [Fact]
    public async Task Cve_With_Cached_Poc_Is_Not_Fetched()
    {
        SeedDb(new[]
        {
            ("CVE-2024-0001", true),
            ("CVE-2024-0002", false),
        });
        var audit = OpenAudit(out _);

        var calls = new List<string>();
        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
        {
            calls.Add(cve);
            return Task.FromResult(new PocAggregator.FetchOnDemandResult(
                cve, 1, 1, new[] { "searchsploit" }));
        }
        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: true);

        var outcomes = await resolver.ResolveAsync(_workDir, CancellationToken.None);

        Assert.Single(outcomes);
        Assert.Equal("CVE-2024-0002", outcomes[0].CveId);
        Assert.Single(calls);
        Assert.Equal("CVE-2024-0002", calls[0]);
        audit.Dispose();
    }

    [Fact]
    public async Task Offline_Mode_Skips_Cleanly_With_Audit()
    {
        SeedDb(new[] { ("CVE-2024-0010", false) });
        var audit = OpenAudit(out var auditPath);

        int callCount = 0;
        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
        {
            callCount++;
            return Task.FromResult(new PocAggregator.FetchOnDemandResult(cve, 0, 0, Array.Empty<string>()));
        }
        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: false);

        var outcomes = await resolver.ResolveAsync(_workDir, CancellationToken.None);

        Assert.Single(outcomes);
        Assert.Equal("skipped_offline", outcomes[0].Status);
        Assert.False(outcomes[0].Succeeded);
        Assert.Equal(0, callCount);

        audit.Dispose();
        Assert.NotEmpty(ReadEvents(auditPath, "cve.lead.skipped_offline"));
    }

    [Fact]
    public async Task Network_Failure_Falls_Through_To_Offline_Skip()
    {
        SeedDb(new[] { ("CVE-2024-0011", false) });
        var audit = OpenAudit(out var auditPath);

        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
            => throw new HttpRequestException("dns failure");

        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: true);
        var outcomes = await resolver.ResolveAsync(_workDir, CancellationToken.None);

        Assert.Single(outcomes);
        Assert.Equal("skipped_offline", outcomes[0].Status);

        audit.Dispose();
        Assert.NotEmpty(ReadEvents(auditPath, "cve.lead.skipped_offline"));
    }

    [Fact]
    public async Task Repeated_Calls_In_Same_Run_Dedup()
    {
        SeedDb(new[] { ("CVE-2024-0020", false) });
        var audit = OpenAudit(out var auditPath);

        int callCount = 0;
        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
        {
            callCount++;
            return Task.FromResult(new PocAggregator.FetchOnDemandResult(cve, 1, 1, new[] { "ghsa" }));
        }
        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: true);

        var first = await resolver.ResolveAsync(_workDir, CancellationToken.None);
        var second = await resolver.ResolveAsync(_workDir, CancellationToken.None);

        Assert.Single(first);
        Assert.Equal("pursued", first[0].Status);
        Assert.Single(second);
        Assert.Equal("skipped_dedup", second[0].Status);
        Assert.Equal(1, callCount);

        audit.Dispose();
        Assert.NotEmpty(ReadEvents(auditPath, "cve.lead.skipped_dedup"));
    }

    [Fact]
    public async Task Rate_Limit_Triggers_Backoff_And_Records_Event()
    {
        SeedDb(new[] { ("CVE-2024-0030", false) });
        var audit = OpenAudit(out var auditPath);

        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
            => throw new HttpRequestException(
                message: "API rate limit exceeded",
                inner: null,
                statusCode: HttpStatusCode.TooManyRequests);

        var backoff = TimeSpan.FromMilliseconds(25);
        var resolver = new CveLeadResolver(
            new CveLeadResolver.FetchOnDemandDelegate(fetch),
            audit, fetchPoc: true, rateLimitBackoff: backoff);

        var start = DateTimeOffset.UtcNow;
        var outcomes = await resolver.ResolveAsync(_workDir, CancellationToken.None);
        var elapsed = DateTimeOffset.UtcNow - start;

        Assert.Single(outcomes);
        Assert.Equal("rate_limited", outcomes[0].Status);
        Assert.True(elapsed >= backoff, $"expected backoff sleep ≥ {backoff}, observed {elapsed}");

        audit.Dispose();
        var rl = ReadEvents(auditPath, "cve.lead.rate_limited");
        Assert.Single(rl);
        Assert.Contains("backoff_ms", rl[0]);
    }

    [Fact]
    public async Task Explicit_Cve_Overload_Bypasses_Db()
    {
        var audit = OpenAudit(out _);

        int callCount = 0;
        Task<PocAggregator.FetchOnDemandResult> fetch(string cve, string outDir, bool fp, CancellationToken ct)
        {
            callCount++;
            return Task.FromResult(new PocAggregator.FetchOnDemandResult(
                cve, 1, 1, new[] { "poc-in-github" }));
        }
        var resolver = new CveLeadResolver(new CveLeadResolver.FetchOnDemandDelegate(fetch), audit, fetchPoc: true);

        var outcomes = await resolver.ResolveAsync(_workDir, new[] { "cve-2024-0040" }, CancellationToken.None);

        Assert.Single(outcomes);
        Assert.Equal("CVE-2024-0040", outcomes[0].CveId);
        Assert.Equal("pursued", outcomes[0].Status);
        Assert.Equal(1, callCount);
        audit.Dispose();
    }

    [Fact]
    public void LoadUnmatchedCveLeads_Returns_Empty_When_Db_Missing()
    {
        var fresh = Path.Combine(_workDir, "empty-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fresh);
        var ids = CveAnnotator.LoadUnmatchedCveLeads(fresh);
        Assert.Empty(ids);
    }
}
