using System.Text.RegularExpressions;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-031b-2 — sparse-clone PoC source for nuclei templates.
/// Complements <see cref="NucleiSource"/> (FS-only) by fetching from
/// <c>projectdiscovery/nuclei-templates</c> on demand.
///
/// <para><b>Strategy.</b> First call clones with sparse-checkout
/// <c>http/cves</c> + <c>dns/cves</c>. For a given CVE id, look for
/// <c>{cve_lower}.yaml</c> under <c>http/cves/&lt;year&gt;/</c> or
/// <c>dns/cves/&lt;year&gt;/</c> (direct path match preferred over grep).
/// Verbatim copy into <c>poc_cache/nuclei-git/&lt;cve&gt;/&lt;basename&gt;.yaml</c>.</para>
///
/// <para><b>Invariants.</b> URL hard-coded
/// (<see cref="GitPocAllowlist.NucleiTemplates"/>); verbatim caching;
/// size caps via <see cref="GitPocCacheWriter"/>.</para>
/// </summary>
public sealed class NucleiTemplatesGitSource : IPocSource
{
    public const string SourceName = "nuclei-git";
    private const long DefaultMaxArtifactBytes = 5L * 1024 * 1024;
    private const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024;

    private static readonly string[] SparsePaths =
    {
        "http/cves",
        "dns/cves",
    };

    private static readonly Regex CveShape = new(
        @"^CVE-(?<year>\d{4})-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IGitClient _git;
    private readonly GitPocCacheWriter _writer;
    // --- htb-poc-fetch-diagnostics ---
    private readonly PocFetchDiagnostics? _diag;
    private readonly PocOfflineBundle? _offlineBundle;
    // --- end htb-poc-fetch-diagnostics ---

    public NucleiTemplatesGitSource(
        IGitClient? git = null,
        long? maxArtifactBytes = null,
        long? maxTotalBytes = null,
        // --- htb-poc-fetch-diagnostics ---
        PocFetchDiagnostics? diagnostics = null,
        PocOfflineBundle? offlineBundle = null)
        // --- end htb-poc-fetch-diagnostics ---
    {
        _git = git ?? new ProcessGitClient();
        _writer = new GitPocCacheWriter(
            maxArtifactBytes ?? DefaultMaxArtifactBytes,
            maxTotalBytes ?? DefaultMaxTotalBytes);
        // --- htb-poc-fetch-diagnostics ---
        _diag = diagnostics;
        _offlineBundle = offlineBundle;
        // --- end htb-poc-fetch-diagnostics ---
    }

    public string Name => SourceName;

    public async Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        IReadOnlyList<PocRef> empty = Array.Empty<PocRef>();
        var m = CveShape.Match(cveId);
        if (!m.Success) return empty;
        if (!ctx.FetchPoc) return empty;
        var year = m.Groups["year"].Value;
        var lower = cveId.ToLowerInvariant();

        ctx.Audit?.Record("poc.fetch.start", new Dictionary<string, object?>
        {
            ["source"] = Name,
            ["cve_id"] = cveId,
        });

        // --- htb-poc-fetch-diagnostics ---
        if (_offlineBundle is not null)
        {
            var hit = _offlineBundle.TryResolve(Name, cveId, ctx.Audit);
            if (hit is not null)
            {
                var bundleRefs = new List<PocRef>(hit.RelativePaths.Count);
                foreach (var rel in hit.RelativePaths)
                {
                    ct.ThrowIfCancellationRequested();
                    var absSrc = Path.Combine(hit.BundleDir, rel.Replace('/', Path.DirectorySeparatorChar));
                    var basename = Path.GetFileName(rel);
                    var sourceUrl = $"offline-bundle://{Name}/{cveId}/{rel}";
                    var local = _writer.WriteCopy(
                        source: Name,
                        cveId: cveId,
                        sourcePath: absSrc,
                        relativeDestPath: basename,
                        sourceUrl: sourceUrl,
                        contentTypeHint: "text/yaml",
                        ctx: ctx);
                    bundleRefs.Add(new PocRef(Name, Url: sourceUrl, ExternalId: basename, LocalPath: local));
                }
                return bundleRefs;
            }
        }
        // --- end htb-poc-fetch-diagnostics ---

        var repoDir = Path.Combine(ctx.CacheRoot, Name, "_repo");
        var sem = RepoCacheLock.For(repoDir);
        await sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!_git.IsCached(repoDir))
            {
                ctx.Audit?.Record("poc.fetch.git_clone", new Dictionary<string, object?>
                {
                    ["source"] = Name,
                    ["repo_url"] = GitPocAllowlist.NucleiTemplates,
                    ["dest"] = repoDir,
                    ["depth"] = 1,
                });
                var cloneResult = await _git.CloneSparseAsync(
                    GitPocAllowlist.NucleiTemplates,
                    repoDir,
                    SparsePaths,
                    ct).ConfigureAwait(false);
                // --- htb-poc-fetch-diagnostics ---
                if (!cloneResult.Success && _diag is not null)
                {
                    await _diag.WrapAsync(
                        ctx.Audit, Name, cveId,
                        GitPocAllowlist.NucleiTemplates,
                        _ => Task.FromResult(cloneResult),
                        ct).ConfigureAwait(false);
                }
                // --- end htb-poc-fetch-diagnostics ---
                if (!cloneResult.Success)
                {
                    await GitPocDiagnostics.RecordCloneFailureAsync(
                        ctx.Audit, Name, cveId,
                        GitPocAllowlist.NucleiTemplates,
                        _git, cloneResult, ct).ConfigureAwait(false);
                    return empty;
                }
            }
            else
            {
                ctx.Audit?.Record("poc.fetch.git_clone.skip", new Dictionary<string, object?>
                {
                    ["source"] = Name,
                    ["repo_url"] = GitPocAllowlist.NucleiTemplates,
                    ["reason"] = "already cached",
                });
            }
        }
        finally { sem.Release(); }

        var hits = new List<string>(2);
        foreach (var rel in SparsePaths)
        {
            var candidate = Path.Combine(repoDir, rel, year, $"{lower}.yaml");
            if (File.Exists(candidate)) hits.Add(candidate);
        }
        if (hits.Count == 0)
        {
            ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve_id"] = cveId,
                ["reason"] = "no template matches CVE",
            });
            return empty;
        }

        var refs = new List<PocRef>(hits.Count);
        foreach (var path in hits)
        {
            var basename = Path.GetFileName(path);
            var rel = Path.GetRelativePath(repoDir, path).Replace(Path.DirectorySeparatorChar, '/');
            var sourceUrl = $"https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel}";
            var local = _writer.WriteCopy(
                source: Name,
                cveId: cveId,
                sourcePath: path,
                relativeDestPath: basename,
                sourceUrl: sourceUrl,
                contentTypeHint: "text/yaml",
                ctx: ctx);
            refs.Add(new PocRef(Name, Url: sourceUrl, ExternalId: basename, LocalPath: local));
        }
        return refs;
    }
}
