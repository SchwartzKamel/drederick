using System.Globalization;
using System.Text.RegularExpressions;
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
        // GAP-031b-2 — git-clone sources so on-demand fetch returns artifacts
        // even when the operator's box has no msf-framework / nuclei-templates
        // installed. URLs are hard-coded in GitPocAllowlist.
        new MetasploitGitSource(),
        new NucleiTemplatesGitSource(),
        new PocInGitHubSource(),
    };

    public sealed record AggregationResult(int CveCount, int RefCount, int CachedCount);

    /// <summary>
    /// Outcome of a single-CVE on-demand fetch. <see cref="ArtifactCount"/>
    /// is the number of <c>LocalPath</c>-bearing refs persisted; if it's
    /// zero the lead is genuinely unfetchable from the configured sources
    /// and the caller should mark the CVE as a dead end for the run.
    /// </summary>
    public sealed record FetchOnDemandResult(
        string CveId,
        int RefCount,
        int ArtifactCount,
        IReadOnlyList<string> SourcesWithArtifact);

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

    /// <summary>
    /// GAP-033 — single-CVE on-demand fetch path. Used by
    /// <see cref="Drederick.Autopilot.AutopilotRunner"/> when a band-250
    /// <c>cve-lead</c> action runs and the cache had no artifact for the CVE
    /// at recon-enrichment time. Walks every configured <see cref="IPocSource"/>
    /// for the single id, persists any returned refs to <c>poc_refs</c>, and
    /// (when <paramref name="fetchPoc"/> is true) lets the source cache the
    /// artefact under <c>out/poc_cache/&lt;source&gt;/</c>. Same invariants as
    /// <see cref="AggregateAsync"/>: never executes, never rewrites, source
    /// failures are swallowed so one bad source doesn't black-hole the lead.
    /// </summary>
    public async Task<FetchOnDemandResult> FetchOnDemandAsync(
        string cveId,
        string outputDir,
        bool fetchPoc,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));

        // Defensive whitelist — every source already validates internally,
        // but keep the entrypoint argv-safe in case a future source forwards
        // the id raw to a subprocess.
        if (!CveShape.IsMatch(cveId))
        {
            _audit?.Record("poc.fetch.on_demand.reject", new Dictionary<string, object?>
            {
                ["cve"] = cveId,
                ["reason"] = "cve id failed shape regex",
            });
            return new FetchOnDemandResult(cveId, 0, 0, Array.Empty<string>());
        }
        var normalizedCve = cveId.ToUpperInvariant();

        var report = new SqliteReport(outputDir);
        report.UpsertCve(normalizedCve);

        var cacheRoot = Path.Combine(outputDir, "poc_cache");
        if (fetchPoc) Directory.CreateDirectory(cacheRoot);
        var ctx = new PocQueryContext(cacheRoot, fetchPoc, report, _audit);
        var now = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture);

        int refCount = 0;
        int cached = 0;
        var sourcesWithArtifact = new List<string>();
        foreach (var source in _sources)
        {
            ct.ThrowIfCancellationRequested();
            IReadOnlyList<PocRef> refs;
            try
            {
                refs = await source.QueryAsync(normalizedCve, ctx, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _audit?.Record("poc.fetch.on_demand.source_error", new Dictionary<string, object?>
                {
                    ["cve"] = normalizedCve,
                    ["source"] = source.Name,
                    ["error"] = ex.Message,
                });
                continue;
            }

            bool sourceCached = false;
            foreach (var r in refs)
            {
                report.UpsertPocRef(
                    cveId: normalizedCve,
                    source: r.Source,
                    url: r.Url,
                    externalId: r.ExternalId,
                    localPath: r.LocalPath,
                    fetchedAt: now);
                refCount++;
                if (!string.IsNullOrWhiteSpace(r.LocalPath))
                {
                    cached++;
                    sourceCached = true;
                }
            }
            if (sourceCached) sourcesWithArtifact.Add(source.Name);
        }

        _audit?.Record("poc.fetch.on_demand", new Dictionary<string, object?>
        {
            ["cve"] = normalizedCve,
            ["refs"] = refCount,
            ["cached"] = cached,
            ["sources_with_artifact"] = string.Join(",", sourcesWithArtifact),
            ["fetch_poc"] = fetchPoc,
        });

        return new FetchOnDemandResult(normalizedCve, refCount, cached, sourcesWithArtifact);
    }

    // CVE-id shape — same as the per-source guards. Defends sources that
    // forward the id into subprocess argv (msfconsole search, grep -F).
    private static readonly Regex CveShape = new(@"^CVE-\d{4}-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

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
