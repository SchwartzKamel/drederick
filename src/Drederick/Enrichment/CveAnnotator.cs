using System.Text.Json;
using Drederick.Audit;
using Drederick.Enrichment.FingerprintStack;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;

namespace Drederick.Enrichment;

/// <summary>
/// Orchestrates CVE enrichment of a completed recon run:
/// 1. Ensure the NVD cache is populated (tolerates offline).
/// 2. For every (port, product, version) tuple harvested from any recon
///    signal — nmap, native scan, HTTP <c>Server</c> banner, or the
///    fingerprint stack — ask <see cref="CpeMatcher"/>.
/// 3. Write each match via <see cref="SqliteReport.UpsertCve"/> and record a
///    <c>kind = "cve"</c> finding linking the service to the CVE id.
///
/// Mirrors GAP-028's planner-side <c>HarvestPortsFromAllSignals</c> on the
/// enrichment side so a host with zero nmap ports still gets CVE rows when
/// non-nmap signals identify a matchable product (GAP-031c).
///
/// Dedupes by (host, port, cve_id) across signals — nmap wins on collision.
/// Idempotent: re-running the same recon + feed yields the same rows.
/// </summary>
public sealed class CveAnnotator
{
    private readonly NvdCache _cache;
    private readonly AuditLog? _audit;
    private readonly CuratedCveCorpus? _curated;

    public CveAnnotator(NvdCache? cache = null, AuditLog? audit = null, CuratedCveCorpus? curated = null)
    {
        _cache = cache ?? new NvdCache();
        _audit = audit;
        _curated = curated;
    }

    /// <summary>Result summary, mostly for tests and log output.</summary>
    public sealed record AnnotationResult(int CveCount, int FindingCount, bool CacheLoaded);

    public async Task<AnnotationResult> AnnotateAsync(
        IEnumerable<HostFinding> findings,
        string outputDir,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (string.IsNullOrWhiteSpace(outputDir)) throw new ArgumentException("outputDir required", nameof(outputDir));

        IReadOnlyList<NvdEntry> entries;
        bool cacheLoaded = true;
        try
        {
            entries = await _cache.LoadAsync(ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            entries = Array.Empty<NvdEntry>();
            cacheLoaded = false;
            if (_curated is null || _curated.Count == 0)
            {
                return new AnnotationResult(0, 0, false);
            }
        }

        var matcher = new CpeMatcher(entries);
        var report = new SqliteReport(outputDir);
        var now = DateTimeOffset.UtcNow.ToString("o");

        int cveCount = 0;
        int findingCount = 0;
        int hostCount = 0;
        int candidateCount = 0;

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();

        foreach (var host in findings)
        {
            if (host is null || string.IsNullOrWhiteSpace(host.Target)) continue;
            var hostId = LookupHostId(conn, host.Target);
            if (hostId is null) continue;
            hostCount++;

            // Track (port, cve_id) emitted for this host so a CVE matched
            // from multiple signals (e.g. nmap and HTTP both fingerprint
            // Apache 2.4.49 on 80) only writes one finding row. Higher-
            // priority sources are iterated first → nmap wins on collision.
            var emitted = new HashSet<(int port, string cveId)>();

            foreach (var cand in HarvestProductCandidatesFromAllSignals(host))
            {
                candidateCount++;
                var serviceId = LookupServiceId(conn, hostId.Value, cand.Port, cand.Protocol);

                if (_curated is not null && _curated.Count > 0)
                {
                    var curatedMatches = _curated.Match(cand.Vendor, cand.Product, cand.Version);
                    foreach (var cm in curatedMatches)
                    {
                        if (!emitted.Add((cand.Port, cm.CveId))) continue;

                        report.UpsertCve(cm.CveId, cm.Cvss, cm.Summary, null);
                        cveCount++;

                        foreach (var url in cm.RefUrls)
                        {
                            try { report.UpsertPocRef(cm.CveId, "curated", url: url); } catch { }
                        }

                        var curatedPayload = JsonSerializer.Serialize(new CveFindingPayload(
                            cm.CveId, cm.Cvss, cand.Product, cand.Version, cand.Source, "curated",
                            "curated", cm.Severity, cm.GhsaId));
                        if (InsertCveFinding(conn, hostId.Value, serviceId, curatedPayload, now))
                        {
                            findingCount++;
                        }
                    }
                }

                // --- htb-pterodactyl-fingerprint ---
                // GAP-052: in-code PterodactylCveCorpus backstop. NVD lags
                // upstream Pterodactyl GHSAs and the on-disk curated/
                // directory may not be present in every environment, so
                // any CMS-fingerprint candidate whose (vendor, product)
                // resolves to Pterodactyl is unconditionally enriched
                // with the built-in pack.
                if (Recon.Cms.PterodactylCveCorpus.AppliesTo(cand.Vendor, cand.Product))
                {
                    foreach (var pcm in Recon.Cms.PterodactylCveCorpus.Match(cand.Version))
                    {
                        if (!emitted.Add((cand.Port, pcm.CveId))) continue;

                        report.UpsertCve(pcm.CveId, pcm.Cvss, pcm.Summary, null);
                        cveCount++;

                        foreach (var url in pcm.RefUrls)
                        {
                            try { report.UpsertPocRef(pcm.CveId, "builtin-pterodactyl", url: url); } catch { }
                        }

                        var pterPayload = JsonSerializer.Serialize(new CveFindingPayload(
                            pcm.CveId, pcm.Cvss, cand.Product, cand.Version, cand.Source, "curated",
                            "builtin-pterodactyl", pcm.Severity, pcm.GhsaId));
                        if (InsertCveFinding(conn, hostId.Value, serviceId, pterPayload, now))
                        {
                            findingCount++;
                        }
                    }
                }
                // --- end htb-pterodactyl-fingerprint ---

                if (!cacheLoaded) continue;

                var matches = matcher.Match(vendor: null, product: cand.Product, version: cand.Version);
                foreach (var m in matches)
                {
                    if (!emitted.Add((cand.Port, m.CveId))) continue;

                    report.UpsertCve(m.CveId, m.Cvss, m.Summary, m.Published);
                    cveCount++;

                    var payload = JsonSerializer.Serialize(new CveFindingPayload(
                        m.CveId, m.Cvss, cand.Product, cand.Version, cand.Source, cand.MatchConfidence,
                        "nvd", null, null));
                    if (InsertCveFinding(conn, hostId.Value, serviceId, payload, now))
                    {
                        findingCount++;
                    }
                }
            }
        }

        _audit?.Record("cve.annotate.finish", new Dictionary<string, object?>
        {
            ["hosts"] = hostCount,
            ["candidates"] = candidateCount,
            ["cve_matches"] = cveCount,
            ["findings_written"] = findingCount,
        });

        return new AnnotationResult(cveCount, findingCount, true);
    }

    /// <summary>
    /// Single (port, product, version) candidate harvested from one recon
    /// signal. <see cref="Source"/> identifies the originating tool;
    /// <see cref="MatchConfidence"/> is the confidence band recorded in
    /// the <c>findings.data_json</c> blob (the <c>findings</c> schema has
    /// no dedicated column).
    /// </summary>
    internal sealed record ProductCandidate(
        int Port,
        string Protocol,
        string Product,
        string? Version,
        string Source,
        string MatchConfidence,
        string? Vendor = null);

    /// <summary>
    /// Walks every result array on <see cref="HostFinding"/> that carries
    /// a product/version pair and yields a <see cref="ProductCandidate"/>
    /// for each. Mirrors <c>ExploitationPlanner.HarvestPortsFromAllSignals</c>
    /// (GAP-028) on the enrichment side — without this, hosts with zero
    /// nmap ports would never get CVE rows even when fingerprint / HTTP
    /// signals identified a matchable product (GAP-031c).
    ///
    /// Priority: nmap and native_scan first (richest data, "high"
    /// confidence), then HTTP <c>Server</c> banner ("medium"), then the
    /// fingerprint stack ("learned" — possibly low individually but
    /// product-only matches are still kept; <see cref="CpeMatcher"/> is
    /// already tuned to prefer false positives over false negatives).
    /// </summary>
    internal static IEnumerable<ProductCandidate> HarvestProductCandidatesFromAllSignals(HostFinding host)
    {
        if (host.Nmap is not null)
        {
            foreach (var p in host.Nmap.OpenPorts)
            {
                if (p is null || string.IsNullOrWhiteSpace(p.Product)) continue;
                yield return new ProductCandidate(
                    p.Port, p.Protocol ?? "tcp", p.Product!, p.Version, "nmap", "high");
            }
        }

        if (host.NativeScan is not null)
        {
            foreach (var p in host.NativeScan.OpenPorts)
            {
                if (p is null || string.IsNullOrWhiteSpace(p.Product)) continue;
                yield return new ProductCandidate(
                    p.Port, p.Protocol ?? "tcp", p.Product!, p.Version, "native_scan", "high");
            }
        }

        // HTTP Server header → parse via FingerprintLearner.ParseServerHeader.
        // Banner-derived → "medium".
        foreach (var h in host.Http)
        {
            if (string.IsNullOrWhiteSpace(h.Server)) continue;
            var port = PortFromUrl(h.Url);
            if (port <= 0) continue;
            var (_, product, version) = FingerprintLearner.ParseServerHeader(h.Server!);
            if (string.IsNullOrEmpty(product)) continue;
            yield return new ProductCandidate(
                port, "tcp", product, version, "http_server", "medium");
        }

        // Fingerprint stack — every candidate above the aggregator's report
        // threshold becomes a low-confidence ("learned") match attempt.
        foreach (var fp in host.Fingerprint)
        {
            if (fp is null || fp.Port is null) continue;
            foreach (var c in fp.Candidates)
            {
                if (c is null || string.IsNullOrEmpty(c.Product)) continue;
                yield return new ProductCandidate(
                    fp.Port.Value, "tcp", c.Product, c.Version, "fingerprint", "learned");
            }
        }

        // CMS fingerprints (GAP-052) — yield each CMS match as a candidate so
        // the curated CVE corpus can match by (vendor, product, version)
        // without requiring the NVD CPE machinery to recognise the product.
        foreach (var cms in host.CmsFingerprint)
        {
            if (cms is null) continue;
            foreach (var m in cms.Matches)
            {
                if (m is null || string.IsNullOrWhiteSpace(m.Name)) continue;
                string? vendor = null;
                string product = m.Name;
                if (!string.IsNullOrWhiteSpace(m.Cpe))
                {
                    try
                    {
                        var (v, p2, _) = CuratedCveCorpus.ParseCpe(m.Cpe!);
                        if (!string.IsNullOrWhiteSpace(v)) vendor = v;
                        if (!string.IsNullOrWhiteSpace(p2)) product = p2;
                    }
                    catch { }
                }
                int port = PortFromUrl(cms.BaseUrl);
                if (port <= 0) port = 443;
                yield return new ProductCandidate(
                    port, "tcp", product, m.Version, "cms_fingerprint", "learned", vendor);
            }
        }
    }

    private static int PortFromUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return 0;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return 0;
        return u.Port > 0 ? u.Port : (u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80);
    }

    private sealed record CveFindingPayload(
        string cve_id,
        double? cvss,
        string? product,
        string? version,
        string source,
        string match_confidence,
        string? enrichment_source = null,
        string? severity = null,
        string? ghsa_id = null);

    private static long? LookupHostId(SqliteConnection conn, string address)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM hosts WHERE address = $a LIMIT 1;";
        cmd.Parameters.AddWithValue("$a", address);
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? null : Convert.ToInt64(r);
    }

    private static long? LookupServiceId(SqliteConnection conn, long hostId, int port, string proto)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM services WHERE host_id=$h AND port=$p AND proto=$pr LIMIT 1;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$p", port);
        cmd.Parameters.AddWithValue("$pr", proto);
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? null : Convert.ToInt64(r);
    }

    // --- htb-cve-lead-actions-resolve ---
    /// <summary>
    /// GAP-033 — enumerate CVE ids in <paramref name="outputDir"/>'s
    /// <c>findings.db</c> that have no cached PoC artefact yet
    /// (no <c>poc_refs.local_path</c> row). <see cref="CveLeadResolver"/>
    /// consumes this to drive on-demand
    /// <see cref="PocAggregator.FetchOnDemandAsync"/> calls after
    /// annotation finishes, closing the loop between
    /// <c>cve.annotate</c> and exploit-side PoC consumption.
    /// </summary>
    public static IReadOnlyList<string> LoadUnmatchedCveLeads(string outputDir)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));
        var dbPath = Path.Combine(outputDir, "findings.db");
        var ids = new List<string>();
        if (!File.Exists(dbPath)) return ids;
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using (var probe = conn.CreateCommand())
        {
            probe.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('cves','poc_refs');";
            var n = Convert.ToInt64(probe.ExecuteScalar() ?? 0L);
            if (n < 2) return ids;
        }
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT c.cve_id FROM cves c
WHERE NOT EXISTS (
  SELECT 1 FROM poc_refs p
  WHERE p.cve_id = c.cve_id AND p.local_path IS NOT NULL AND TRIM(p.local_path) != ''
)
ORDER BY c.cve_id;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var v = reader.GetString(0);
            if (!string.IsNullOrWhiteSpace(v)) ids.Add(v);
        }
        return ids;
    }
    // --- end htb-cve-lead-actions-resolve ---

    private static bool InsertCveFinding(SqliteConnection conn, long hostId, long? serviceId,
        string dataJson, string now)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO findings(host_id, service_id, kind, data_json, created_at)
VALUES($h, $s, 'cve', $d, $c)
ON CONFLICT(host_id, COALESCE(service_id, 0), kind, data_json) DO NOTHING;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$s", (object?)serviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$d", dataJson);
        cmd.Parameters.AddWithValue("$c", now);
        return cmd.ExecuteNonQuery() > 0;
    }
}
