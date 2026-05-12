namespace Drederick.Enrichment;

/// <summary>
/// GAP-033 — typed outcome of a single <see cref="CveLeadResolver"/> pursuit.
/// Closes the loop between CVE annotation and exploitation by recording
/// what an on-demand <see cref="PocAggregator.FetchOnDemandAsync"/> call
/// produced for one previously-unmatched CVE id.
///
/// <para>
/// <see cref="Succeeded"/> is <c>true</c> when at least one PoC artefact was
/// cached (i.e. <see cref="PocsCached"/> &gt; 0). A pursuit with zero refs is
/// recorded as a genuine dead-end for the run — <see cref="CveLeadResolver"/>
/// dedupes future attempts at the same CVE in-memory.
/// </para>
///
/// <para>
/// <see cref="Status"/> distinguishes the operational shape of the outcome:
///   <c>pursued</c>     — fetch ran end-to-end (success or empty);
///   <c>skipped_offline</c> — <c>--no-fetch-poc</c> set or network unavailable;
///   <c>skipped_dedup</c>   — already attempted in this run;
///   <c>rate_limited</c>    — upstream replied 429 / Too Many Requests;
///   <c>error</c>           — unexpected failure surfaced from the aggregator.
/// </para>
/// </summary>
public sealed record CveLeadOutcome(
    string CveId,
    IReadOnlyList<string> SourcesTried,
    int PocsCached,
    bool Succeeded,
    string Status = "pursued",
    string? Error = null);
