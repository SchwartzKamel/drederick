using System.Text.Json;
using System.Text.RegularExpressions;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-031b-2 — sparse-clone + raw-fetch PoC source for the
/// <c>nomi-sec/PoC-in-GitHub</c> aggregator. The aggregator maintains
/// per-CVE JSON manifests that point at third-party PoC repos. We sparse-
/// checkout the year directory for the CVE, read the manifest, and shallow
/// blob-fetch the top 5 files (default branch) of each referenced repo via
/// <c>raw.githubusercontent.com</c>.
///
/// <para><b>GitHub auth.</b> When <c>GITHUB_TOKEN</c> is set,
/// <see cref="DefaultGitHubHttpClient"/> sends Bearer auth (5000 req/hr). On
/// 429 we audit <c>poc.fetch.rate_limited</c>, halt further fetches for this
/// run, and return whatever we already collected — does not block other
/// sources.</para>
///
/// <para><b>Invariants.</b> Aggregator URL hard-coded
/// (<see cref="GitPocAllowlist.PocInGitHub"/>); raw fetches restricted to
/// <c>raw.githubusercontent.com</c> with shape-validated owner/repo names.
/// Verbatim caching only.</para>
/// </summary>
public sealed class PocInGitHubSource : IPocSource
{
    public const string SourceName = "poc-in-github";
    private const int TopFilesPerRepo = 5;
    private const long DefaultMaxArtifactBytes = 5L * 1024 * 1024;
    private const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024;

    private static readonly Regex CveShape = new(
        @"^CVE-(?<year>\d{4})-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Owner / repo segment shape — protects argv we forward into raw URLs.
    // GitHub permits letters, digits, '-', '_', '.'; nothing else is safe.
    private static readonly Regex SegmentShape = new(
        @"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$",
        RegexOptions.Compiled);

    private readonly IGitClient _git;
    private readonly IGitHubHttpClient _http;
    private readonly GitPocCacheWriter _writer;
    private bool _rateLimitedThisRun;
    // --- htb-poc-fetch-diagnostics ---
    private readonly PocFetchDiagnostics? _diag;
    private readonly PocOfflineBundle? _offlineBundle;
    // --- end htb-poc-fetch-diagnostics ---

    public PocInGitHubSource(
        IGitClient? git = null,
        IGitHubHttpClient? http = null,
        long? maxArtifactBytes = null,
        long? maxTotalBytes = null,
        // --- htb-poc-fetch-diagnostics ---
        PocFetchDiagnostics? diagnostics = null,
        PocOfflineBundle? offlineBundle = null)
        // --- end htb-poc-fetch-diagnostics ---
    {
        _git = git ?? new ProcessGitClient();
        _http = http ?? new DefaultGitHubHttpClient();
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
        var canonicalCve = cveId.ToUpperInvariant();

        ctx.Audit?.Record("poc.fetch.start", new Dictionary<string, object?>
        {
            ["source"] = Name,
            ["cve_id"] = canonicalCve,
        });

        // --- htb-poc-fetch-diagnostics ---
        if (_offlineBundle is not null)
        {
            var hit = _offlineBundle.TryResolve(Name, canonicalCve, ctx.Audit);
            if (hit is not null)
            {
                var bundleRefs = new List<PocRef>(hit.RelativePaths.Count);
                foreach (var rel in hit.RelativePaths)
                {
                    ct.ThrowIfCancellationRequested();
                    var absSrc = Path.Combine(hit.BundleDir, rel.Replace('/', Path.DirectorySeparatorChar));
                    var basename = Path.GetFileName(rel);
                    var sourceUrl = $"offline-bundle://{Name}/{canonicalCve}/{rel}";
                    var local = _writer.WriteCopy(
                        source: Name,
                        cveId: canonicalCve,
                        sourcePath: absSrc,
                        relativeDestPath: basename,
                        sourceUrl: sourceUrl,
                        contentTypeHint: null,
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
                    ["repo_url"] = GitPocAllowlist.PocInGitHub,
                    ["dest"] = repoDir,
                    ["depth"] = 1,
                });
                var cloneResult = await _git.CloneSparseAsync(
                    GitPocAllowlist.PocInGitHub,
                    repoDir,
                    new[] { year },
                    ct).ConfigureAwait(false);
                // --- htb-poc-fetch-diagnostics ---
                if (!cloneResult.Success && _diag is not null)
                {
                    await _diag.WrapAsync(
                        ctx.Audit, Name, canonicalCve,
                        GitPocAllowlist.PocInGitHub,
                        _ => Task.FromResult(cloneResult),
                        ct).ConfigureAwait(false);
                }
                // --- end htb-poc-fetch-diagnostics ---
                if (!cloneResult.Success)
                {
                    await GitPocDiagnostics.RecordCloneFailureAsync(
                        ctx.Audit, Name, canonicalCve,
                        GitPocAllowlist.PocInGitHub,
                        _git, cloneResult, ct).ConfigureAwait(false);
                    return empty;
                }
            }
            else
            {
                ctx.Audit?.Record("poc.fetch.git_clone.skip", new Dictionary<string, object?>
                {
                    ["source"] = Name,
                    ["repo_url"] = GitPocAllowlist.PocInGitHub,
                    ["reason"] = "already cached",
                });
            }
        }
        finally { sem.Release(); }

        var manifest = Path.Combine(repoDir, year, $"{canonicalCve}.json");
        if (!File.Exists(manifest))
        {
            ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve_id"] = canonicalCve,
                ["reason"] = "manifest missing",
            });
            return empty;
        }

        List<RepoRef> repos;
        try { repos = ParseManifest(File.ReadAllBytes(manifest)); }
        catch (JsonException ex)
        {
            ctx.Audit?.Record("poc.fetch.error", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve_id"] = canonicalCve,
                ["error"] = $"manifest parse failed: {ex.Message}",
            });
            return empty;
        }

        var refs = new List<PocRef>();
        foreach (var repo in repos)
        {
            ct.ThrowIfCancellationRequested();
            if (_rateLimitedThisRun) break;
            if (!SegmentShape.IsMatch(repo.Owner) || !SegmentShape.IsMatch(repo.Name)) continue;

            // Pull the repo's top-level file listing via the GitHub
            // contents API; pick the first TopFilesPerRepo file blobs.
            var listingUrl = $"https://api.github.com/repos/{repo.Owner}/{repo.Name}/contents/";
            var listing = await _http.GetAsync(listingUrl, ct).ConfigureAwait(false);
            if (HandleRateLimit(listing, canonicalCve, repo, ctx)) break;
            if (listing.Body is null) continue;

            List<string> files;
            try { files = ParseRepoListing(listing.Body); }
            catch (JsonException) { continue; }

            int taken = 0;
            foreach (var file in files)
            {
                if (taken >= TopFilesPerRepo) break;
                ct.ThrowIfCancellationRequested();
                if (_rateLimitedThisRun) break;
                if (string.IsNullOrEmpty(file) || file.IndexOf('/') >= 0) continue;
                if (!IsSafeFileName(file)) continue;

                var rawUrl = $"https://raw.githubusercontent.com/{repo.Owner}/{repo.Name}/HEAD/{file}";
                var resp = await _http.GetAsync(rawUrl, ct).ConfigureAwait(false);
                if (HandleRateLimit(resp, canonicalCve, repo, ctx)) break;
                if (resp.Body is null) continue;

                var relDest = Path.Combine($"{repo.Owner}__{repo.Name}", file);
                var local = _writer.WriteBytes(
                    source: Name,
                    cveId: canonicalCve,
                    bytes: resp.Body,
                    relativeDestPath: relDest,
                    sourceUrl: rawUrl,
                    contentTypeHint: resp.ContentType,
                    ctx: ctx);
                refs.Add(new PocRef(
                    Name,
                    Url: $"https://github.com/{repo.Owner}/{repo.Name}",
                    ExternalId: $"{repo.Owner}/{repo.Name}/{file}",
                    LocalPath: local));
                taken++;
            }
        }

        if (refs.Count == 0 && !_rateLimitedThisRun)
        {
            ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve_id"] = canonicalCve,
                ["reason"] = "manifest had no fetchable files",
            });
        }
        return refs;
    }

    private bool HandleRateLimit(GitHubFetchResult res, string cveId, RepoRef repo, PocQueryContext ctx)
    {
        if (res.Status != 429) return false;
        _rateLimitedThisRun = true;
        ctx.Audit?.Record("poc.fetch.rate_limited", new Dictionary<string, object?>
        {
            ["source"] = Name,
            ["cve_id"] = cveId,
            ["repo"] = $"{repo.Owner}/{repo.Name}",
            ["retry_after_seconds"] = res.RetryAfterSeconds,
        });
        return true;
    }

    private static bool IsSafeFileName(string name)
    {
        if (name.Length == 0 || name.Length > 200) return false;
        if (name.StartsWith('.')) return false;
        foreach (var c in name)
        {
            if (c == '/' || c == '\\' || c == 0) return false;
        }
        return true;
    }

    internal sealed record RepoRef(string Owner, string Name);

    internal static List<RepoRef> ParseManifest(byte[] bytes)
    {
        var list = new List<RepoRef>();
        using var doc = JsonDocument.Parse(bytes);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
        foreach (var el in doc.RootElement.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;
            string? full = null;
            if (el.TryGetProperty("full_name", out var fn) && fn.ValueKind == JsonValueKind.String)
                full = fn.GetString();
            else if (el.TryGetProperty("html_url", out var hu) && hu.ValueKind == JsonValueKind.String)
                full = ExtractFullNameFromHtmlUrl(hu.GetString());
            if (string.IsNullOrWhiteSpace(full)) continue;
            var slash = full.IndexOf('/');
            if (slash <= 0 || slash == full.Length - 1) continue;
            var owner = full.Substring(0, slash);
            var name = full.Substring(slash + 1);
            // Strip extra path segments that sometimes appear in html_url.
            var extra = name.IndexOf('/');
            if (extra >= 0) name = name.Substring(0, extra);
            list.Add(new RepoRef(owner, name));
        }
        return list;
    }

    private static string? ExtractFullNameFromHtmlUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        const string prefix = "https://github.com/";
        if (!url.StartsWith(prefix, StringComparison.Ordinal)) return null;
        return url.Substring(prefix.Length).TrimEnd('/');
    }

    internal static List<string> ParseRepoListing(byte[] bytes)
    {
        var files = new List<string>();
        using var doc = JsonDocument.Parse(bytes);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return files;
        foreach (var el in doc.RootElement.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;
            if (!el.TryGetProperty("type", out var t) || t.ValueKind != JsonValueKind.String) continue;
            if (t.GetString() != "file") continue;
            if (!el.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) continue;
            var name = n.GetString();
            if (!string.IsNullOrEmpty(name)) files.Add(name);
        }
        return files;
    }
}
