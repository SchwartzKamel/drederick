using System.Globalization;
using Drederick.Audit;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;

namespace Drederick.Enrichment;

/// <summary>
/// Walks every CVE recorded in <c>findings.db</c> and asks each configured
/// <see cref="IPocSource"/> for public PoC references. References are
/// persisted via <see cref="SqliteReport.UpsertPocRef"/>; when
/// <paramref name="fetchPoc"/> is set, sources that support caching also
/// write the artefact bytes verbatim under
/// <c>&lt;outDir&gt;/poc_cache/&lt;source&gt;/&lt;id&gt;/</c> and register the
/// SHA-256 via <see cref="SqliteReport.UpsertPocSource"/>.
///
/// Invariant: this type aggregates + presents references. It never executes
/// fetched PoCs, and never rewrites/"neutralises" their bytes — the
/// practitioner reviews exactly what the upstream published.
/// </summary>
public sealed class PocAggregator
{
    private readonly IReadOnlyList<IPocSource> _sources;
    private readonly AuditLog? _audit;

    public PocAggregator(IEnumerable<IPocSource>? sources = null, AuditLog? audit = null)
    {
        _sources = (sources ?? DefaultSources()).ToArray();
        _audit = audit;
    }

    public static IEnumerable<IPocSource> DefaultSources() => new IPocSource[]
    {
        new SearchsploitSource(),
        new GhsaSource(),
        new MetasploitSource(),
        new NucleiSource(),
    };

    public sealed record AggregationResult(int CveCount, int RefCount, int CachedCount);

    public async Task<AggregationResult> AggregateAsync(
        IEnumerable<object>? findings,
        string outputDir,
        bool fetchPoc,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));
        _ = findings; // reserved for future per-host filtering

        var report = new SqliteReport(outputDir);
        var cveIds = LoadCveIds(report.DatabasePath);
        if (cveIds.Count == 0) return new AggregationResult(0, 0, 0);

        var cacheRoot = Path.Combine(outputDir, "poc_cache");
        if (fetchPoc) Directory.CreateDirectory(cacheRoot);
        var ctx = new PocQueryContext(cacheRoot, fetchPoc, report, _audit);
        var now = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture);

        int refCount = 0;
        int cached = 0;
        foreach (var cve in cveIds)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var source in _sources)
            {
                IReadOnlyList<PocRef> refs;
                try
                {
                    refs = await source.QueryAsync(cve, ctx, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception)
                {
                    // Per spec: a single source's failure must never abort the
                    // aggregation. Swallow and carry on to the next source.
                    continue;
                }

                foreach (var r in refs)
                {
                    report.UpsertPocRef(
                        cveId: cve,
                        source: r.Source,
                        url: r.Url,
                        externalId: r.ExternalId,
                        localPath: r.LocalPath,
                        fetchedAt: now);
                    refCount++;
                    if (!string.IsNullOrWhiteSpace(r.LocalPath)) cached++;
                }
            }
        }
        return new AggregationResult(cveIds.Count, refCount, cached);
    }

    private static List<string> LoadCveIds(string dbPath)
    {
        var ids = new List<string>();
        if (!File.Exists(dbPath)) return ids;
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        // Some sqlite builds reject querying a missing table — probe first.
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='cves';";
        var exists = cmd.ExecuteScalar();
        if (exists is null || exists is DBNull) return ids;
        cmd.CommandText = "SELECT cve_id FROM cves ORDER BY cve_id;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var v = reader.GetString(0);
            if (!string.IsNullOrWhiteSpace(v)) ids.Add(v);
        }
        return ids;
    }
}
