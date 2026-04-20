using Drederick.Reporting;

namespace Drederick.Enrichment;

/// <summary>
/// A reference to a public Proof-of-Concept artefact for a given CVE.
/// Sources return these; the aggregator persists them via
/// <see cref="SqliteReport.UpsertPocRef"/>.
/// Invariant: drederick aggregates and presents — it never executes.
/// </summary>
public sealed record PocRef(
    string Source,
    string? Url = null,
    string? ExternalId = null,
    string? LocalPath = null);

/// <summary>
/// Context passed to a source for a single CVE query. Sources should only
/// cache content under <see cref="CacheRoot"/> and only when
/// <see cref="FetchPoc"/> is true. They record cached artefacts via
/// <see cref="SqliteReport.UpsertPocSource"/>.
/// </summary>
public sealed class PocQueryContext
{
    public PocQueryContext(string cacheRoot, bool fetchPoc, SqliteReport report)
    {
        CacheRoot = cacheRoot ?? throw new ArgumentNullException(nameof(cacheRoot));
        FetchPoc = fetchPoc;
        Report = report ?? throw new ArgumentNullException(nameof(report));
    }

    /// <summary>Absolute path to the poc_cache root (e.g. out/poc_cache).</summary>
    public string CacheRoot { get; }

    /// <summary>Whether the source should fetch/cache content locally.</summary>
    public bool FetchPoc { get; }

    /// <summary>Report used to record cached artefacts (sha256, path).</summary>
    public SqliteReport Report { get; }
}

/// <summary>
/// Contract for a public PoC lookup backend (Exploit-DB, GHSA, Metasploit,
/// Nuclei, …). Implementations must:
///   * never execute fetched content,
///   * never neutralize/rewrite fetched content,
///   * return an empty list rather than throwing when their dependency is
///     missing (e.g. <c>searchsploit</c> not on PATH).
/// </summary>
public interface IPocSource
{
    /// <summary>Short stable name recorded in <c>poc_refs.source</c>.</summary>
    string Name { get; }

    /// <summary>
    /// Query this backend for refs that map to <paramref name="cveId"/>.
    /// Respects <paramref name="ctx"/>.FetchPoc for caching decisions.
    /// </summary>
    Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct);
}
