using System.ComponentModel;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-031b-2 — sparse-clone PoC source for Metasploit framework module
/// source. Complements <see cref="MetasploitSource"/> (which only finds an
/// already-installed <c>metasploit-framework</c> tree on disk) by fetching
/// modules from <c>rapid7/metasploit-framework</c> on demand. The clone is
/// shared across every CVE lookup in a run via a per-repo
/// <see cref="SemaphoreSlim"/>; on the second CVE the clone is short-circuited
/// and <c>poc.fetch.git_clone.skip</c> is audited.
///
/// <para><b>Strategy.</b> First call: <c>git clone --depth=1 --filter=blob:none</c>
/// into <c>poc_cache/metasploit-git/_repo/</c>, then
/// <c>git sparse-checkout set modules/exploits modules/auxiliary modules/post</c>.
/// For a given CVE id, recursively scan the sparse tree for <c>.rb</c> files
/// containing the literal CVE id (case-insensitive) and copy each match
/// verbatim into <c>poc_cache/metasploit-git/&lt;cve&gt;/&lt;basename&gt;.rb</c>.</para>
///
/// <para><b>Invariants.</b> URL is hard-coded
/// (<see cref="GitPocAllowlist.MetasploitFramework"/>) — no config knob.
/// Verbatim caching only — never rewrite, never neutralise. Size discipline
/// honored via <see cref="GitPocCacheWriter"/>. Source itself never executes
/// modules; the consumer (<c>ExploitRunner</c>) re-validates scope before
/// any spawn.</para>
/// </summary>
public sealed class MetasploitGitSource : IPocSource
{
    public const string SourceName = "metasploit-git";
    private const long DefaultMaxArtifactBytes = 5L * 1024 * 1024;
    private const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024;

    private static readonly string[] SparsePaths =
    {
        "modules/exploits",
        "modules/auxiliary",
        "modules/post",
    };

    private static readonly Regex CveShape = new(
        @"^CVE-\d{4}-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IGitClient _git;
    private readonly long _maxArtifactBytes;
    private readonly long _maxTotalBytes;
    private readonly GitPocCacheWriter _writer;
    // --- htb-poc-fetch-diagnostics ---
    private readonly PocFetchDiagnostics? _diag;
    private readonly PocOfflineBundle? _offlineBundle;
    // --- end htb-poc-fetch-diagnostics ---

    public MetasploitGitSource(
        IGitClient? git = null,
        long? maxArtifactBytes = null,
        long? maxTotalBytes = null,
        // --- htb-poc-fetch-diagnostics ---
        PocFetchDiagnostics? diagnostics = null,
        PocOfflineBundle? offlineBundle = null)
        // --- end htb-poc-fetch-diagnostics ---
    {
        _git = git ?? new ProcessGitClient();
        _maxArtifactBytes = maxArtifactBytes ?? DefaultMaxArtifactBytes;
        _maxTotalBytes = maxTotalBytes ?? DefaultMaxTotalBytes;
        _writer = new GitPocCacheWriter(_maxArtifactBytes, _maxTotalBytes);
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
        if (!CveShape.IsMatch(cveId)) return empty;
        if (!ctx.FetchPoc) return empty;

        ctx.Audit?.Record("poc.fetch.start", new Dictionary<string, object?>
        {
            ["source"] = Name,
            ["cve_id"] = cveId,
        });

        // --- htb-poc-fetch-diagnostics ---
        // GAP-053: Offline bundle short-circuits the clone entirely.
        // If <bundle>/<source>/<cve>/ has staged content, copy each file
        // through the writer (so SHA-256 / poc.fetch.artifact / SQLite
        // rows still fire) and return without touching the network.
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
                        contentTypeHint: "text/x-ruby",
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
                    ["repo_url"] = GitPocAllowlist.MetasploitFramework,
                    ["dest"] = repoDir,
                    ["depth"] = 1,
                });
                var cloneResult = await _git.CloneSparseAsync(
                    GitPocAllowlist.MetasploitFramework,
                    repoDir,
                    SparsePaths,
                    ct).ConfigureAwait(false);
                // --- htb-poc-fetch-diagnostics ---
                // GAP-053: when wired, emit poc.fetch.error.diagnosed with
                // git-presence / DNS / HTTPS-reachability surface so failures
                // are triagable from audit.jsonl without re-running verbose.
                if (!cloneResult.Success && _diag is not null)
                {
                    await _diag.WrapAsync(
                        ctx.Audit, Name, cveId,
                        GitPocAllowlist.MetasploitFramework,
                        _ => Task.FromResult(cloneResult),
                        ct).ConfigureAwait(false);
                }
                // --- end htb-poc-fetch-diagnostics ---
                if (!cloneResult.Success)
                {
                    await GitPocDiagnostics.RecordCloneFailureAsync(
                        ctx.Audit, Name, cveId,
                        GitPocAllowlist.MetasploitFramework,
                        _git, cloneResult, ct).ConfigureAwait(false);
                    return empty;
                }
            }
            else
            {
                ctx.Audit?.Record("poc.fetch.git_clone.skip", new Dictionary<string, object?>
                {
                    ["source"] = Name,
                    ["repo_url"] = GitPocAllowlist.MetasploitFramework,
                    ["reason"] = "already cached",
                });
            }
        }
        finally { sem.Release(); }

        // Grep the sparse tree in-process. Fast (~5k .rb files); avoids the
        // injection surface of shelling another grep.
        var matches = FindMatchingModules(repoDir, cveId, ct);
        if (matches.Count == 0)
        {
            ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve_id"] = cveId,
                ["reason"] = "no module matches CVE",
            });
            return empty;
        }

        var refs = new List<PocRef>(matches.Count);
        foreach (var path in matches)
        {
            ct.ThrowIfCancellationRequested();
            var basename = Path.GetFileName(path);
            var sourceUrl = $"https://github.com/rapid7/metasploit-framework/blob/master/" +
                Path.GetRelativePath(repoDir, path).Replace(Path.DirectorySeparatorChar, '/');
            var local = _writer.WriteCopy(
                source: Name,
                cveId: cveId,
                sourcePath: path,
                relativeDestPath: basename,
                sourceUrl: sourceUrl,
                contentTypeHint: "text/x-ruby",
                ctx: ctx);
            refs.Add(new PocRef(Name, Url: sourceUrl, ExternalId: basename, LocalPath: local));
        }
        return refs;
    }

    private static List<string> FindMatchingModules(string repoDir, string cveId, CancellationToken ct)
    {
        var hits = new List<string>();
        foreach (var sparseRel in SparsePaths)
        {
            var root = Path.Combine(repoDir, sparseRel);
            if (!Directory.Exists(root)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*.rb", SearchOption.AllDirectories); }
            catch (DirectoryNotFoundException) { continue; }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var f in files)
            {
                ct.ThrowIfCancellationRequested();
                if (FileContainsCveId(f, cveId)) hits.Add(f);
            }
        }
        return hits;
    }

    private static bool FileContainsCveId(string path, string cveId)
    {
        try
        {
            // Read as text — module sources are ASCII Ruby. Cap read size to
            // avoid blowing memory on a hostile/large file in the sparse tree.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length > 4L * 1024 * 1024) return false;
            using var sr = new StreamReader(fs);
            var content = sr.ReadToEnd();
            return content.IndexOf(cveId, StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
