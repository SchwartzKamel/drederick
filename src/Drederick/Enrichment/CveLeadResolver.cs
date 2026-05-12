using System.Net;
using Drederick.Audit;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-033 — closes the loop between <see cref="CveAnnotator"/> and the
/// exploit-side PoC corpus. After annotation has finished a host (or a
/// whole run), this resolver scans the recorded CVEs in
/// <c>findings.db</c> for ids that have no cached PoC artefact yet, then
/// invokes <see cref="PocAggregator.FetchOnDemandAsync"/> once per
/// previously-unmatched CVE.
///
/// <para>
/// Hard rules (audit-trail and scope discipline):
/// <list type="bullet">
///   <item>Every fetch is bracketed by audit events:
///         <c>cve.lead.pursued</c> on success/empty,
///         <c>cve.lead.skipped_offline</c> when <c>fetchPoc</c> is off or the
///         network is unavailable, <c>cve.lead.skipped_dedup</c> when the
///         same CVE was already attempted in this run, and
///         <c>cve.lead.rate_limited</c> with backoff metadata on upstream
///         <c>HTTP 429</c>.</item>
///   <item>Idempotent within a run: an in-memory set tracks every CVE the
///         resolver has attempted; repeated calls into <see cref="ResolveAsync"/>
///         never re-fetch.</item>
///   <item>Scope is not directly applicable (enrichment-only, no target
///         host) — but the underlying <see cref="PocAggregator"/> retains
///         its own argv- and source-side guards verbatim.</item>
///   <item>No plaintext upstream tokens or response bodies leak into the
///         audit log; only counts, source names, and (on error) the
///         exception message are recorded.</item>
/// </list>
/// </para>
/// </summary>
public sealed class CveLeadResolver
{
    /// <summary>Pluggable fetch delegate — defaults to the real aggregator
    /// but lets unit tests swap in a stub to exercise rate-limit and error
    /// paths without spinning up real <see cref="IPocSource"/>s.</summary>
    public delegate Task<PocAggregator.FetchOnDemandResult> FetchOnDemandDelegate(
        string cveId, string outputDir, bool fetchPoc, CancellationToken ct);

    private readonly FetchOnDemandDelegate _fetch;
    private readonly AuditLog? _audit;
    private readonly bool _fetchPoc;
    private readonly TimeSpan _rateLimitBackoff;
    private readonly HashSet<string> _attempted = new(StringComparer.OrdinalIgnoreCase);

    public CveLeadResolver(
        PocAggregator aggregator,
        AuditLog? audit = null,
        bool fetchPoc = true,
        TimeSpan? rateLimitBackoff = null)
        : this(
            fetch: (cve, outDir, fp, ct) => (aggregator ?? throw new ArgumentNullException(nameof(aggregator)))
                .FetchOnDemandAsync(cve, outDir, fp, ct),
            audit: audit,
            fetchPoc: fetchPoc,
            rateLimitBackoff: rateLimitBackoff)
    {
    }

    public CveLeadResolver(
        FetchOnDemandDelegate fetch,
        AuditLog? audit = null,
        bool fetchPoc = true,
        TimeSpan? rateLimitBackoff = null)
    {
        _fetch = fetch ?? throw new ArgumentNullException(nameof(fetch));
        _audit = audit;
        _fetchPoc = fetchPoc;
        _rateLimitBackoff = rateLimitBackoff ?? TimeSpan.FromSeconds(2);
    }

    /// <summary>
    /// Number of CVE ids the resolver has already attempted in this run.
    /// Exposed for diagnostics; the dedup itself is internal.
    /// </summary>
    public int AttemptedCount => _attempted.Count;

    /// <summary>
    /// Walks every CVE recorded in <paramref name="outputDir"/>'s
    /// <c>findings.db</c> that lacks a cached PoC artefact (no
    /// <c>poc_refs.local_path</c> row) and pursues it via the configured
    /// <see cref="FetchOnDemandDelegate"/>. Returns one outcome per CVE
    /// considered, including dedup skips for the convenience of callers
    /// that want a complete report.
    /// </summary>
    public async Task<IReadOnlyList<CveLeadOutcome>> ResolveAsync(
        string outputDir,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));

        var unmatched = CveAnnotator.LoadUnmatchedCveLeads(outputDir);
        return await ResolveAsync(outputDir, unmatched, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Overload that takes an explicit set of CVE ids — used by orchestrators
    /// that already know which CVEs were just matched (per-host hook).
    /// </summary>
    public async Task<IReadOnlyList<CveLeadOutcome>> ResolveAsync(
        string outputDir,
        IEnumerable<string> cveIds,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));
        ArgumentNullException.ThrowIfNull(cveIds);

        var outcomes = new List<CveLeadOutcome>();
        foreach (var rawCve in cveIds)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(rawCve)) continue;
            var cve = rawCve.Trim().ToUpperInvariant();

            if (!_attempted.Add(cve))
            {
                _audit?.Record("cve.lead.skipped_dedup", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                });
                outcomes.Add(new CveLeadOutcome(
                    cve, Array.Empty<string>(), 0, Succeeded: false, Status: "skipped_dedup"));
                continue;
            }

            if (!_fetchPoc)
            {
                _audit?.Record("cve.lead.skipped_offline", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                    ["reason"] = "fetch_poc_disabled",
                });
                outcomes.Add(new CveLeadOutcome(
                    cve, Array.Empty<string>(), 0, Succeeded: false, Status: "skipped_offline"));
                continue;
            }

            PocAggregator.FetchOnDemandResult result;
            try
            {
                result = await _fetch(cve, outputDir, _fetchPoc, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (HttpRequestException ex) when (IsRateLimit(ex))
            {
                _audit?.Record("cve.lead.rate_limited", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                    ["backoff_ms"] = (long)_rateLimitBackoff.TotalMilliseconds,
                    ["error"] = ex.Message,
                });
                try { await Task.Delay(_rateLimitBackoff, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                outcomes.Add(new CveLeadOutcome(
                    cve, Array.Empty<string>(), 0, Succeeded: false,
                    Status: "rate_limited", Error: ex.Message));
                continue;
            }
            catch (HttpRequestException ex)
            {
                _audit?.Record("cve.lead.skipped_offline", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                    ["reason"] = "network_unavailable",
                    ["error"] = ex.Message,
                });
                outcomes.Add(new CveLeadOutcome(
                    cve, Array.Empty<string>(), 0, Succeeded: false,
                    Status: "skipped_offline", Error: ex.Message));
                continue;
            }
            catch (Exception ex)
            {
                _audit?.Record("cve.lead.error", new Dictionary<string, object?>
                {
                    ["cve"] = cve,
                    ["error"] = ex.Message,
                });
                outcomes.Add(new CveLeadOutcome(
                    cve, Array.Empty<string>(), 0, Succeeded: false,
                    Status: "error", Error: ex.Message));
                continue;
            }

            _audit?.Record("cve.lead.pursued", new Dictionary<string, object?>
            {
                ["cve"] = cve,
                ["sources"] = string.Join(",", result.SourcesWithArtifact),
                ["results"] = result.RefCount,
                ["fetched_count"] = result.ArtifactCount,
            });
            outcomes.Add(new CveLeadOutcome(
                cve,
                result.SourcesWithArtifact,
                result.ArtifactCount,
                Succeeded: result.ArtifactCount > 0,
                Status: "pursued"));
        }
        return outcomes;
    }

    private static bool IsRateLimit(HttpRequestException ex)
    {
        if (ex.StatusCode == HttpStatusCode.TooManyRequests) return true;
        return ex.Message.Contains("429", StringComparison.Ordinal)
            || ex.Message.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
    }
}
