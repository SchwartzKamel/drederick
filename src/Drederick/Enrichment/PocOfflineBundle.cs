using Drederick.Audit;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-053 — pre-staged offline PoC bundle resolver. When the operator
/// runs in an airgapped CTF / VPN environment, a bundle directory
/// (configured via <c>--poc-offline-bundle &lt;dir&gt;</c>) can be
/// pre-populated with per-CVE PoC content. The git-clone PoC sources
/// consult this resolver before attempting any network call; on a hit
/// the bundle content is copied verbatim into the normal
/// <c>poc_cache/&lt;source&gt;/&lt;cve&gt;/</c> tree and a
/// <c>poc.fetch.offline_hit</c> audit event is emitted, allowing the
/// caller to skip the clone entirely.
///
/// <para><b>Layout.</b>
/// <c>&lt;bundleRoot&gt;/&lt;source-name&gt;/&lt;cve-id&gt;/…files…</c>.
/// The CVE id segment is sanitised through
/// <see cref="GitPocCacheWriter.SafeId"/> on lookup; symlinks below the
/// CVE directory are refused.</para>
///
/// <para><b>Invariants.</b> Verbatim copy only — never rewrites, never
/// neutralises. No network, no subprocess. The bundle root is operator-
/// supplied; the resolver itself does no scope check (PoC artefacts are
/// not targets).</para>
/// </summary>
public sealed class PocOfflineBundle
{
    public string BundleRoot { get; }

    public PocOfflineBundle(string bundleRoot)
    {
        if (string.IsNullOrWhiteSpace(bundleRoot))
            throw new ArgumentException("bundle root path required", nameof(bundleRoot));
        BundleRoot = bundleRoot;
    }

    /// <summary>
    /// Returns the bundle directory for <paramref name="sourceName"/> +
    /// <paramref name="cveId"/> if it exists and is non-empty, else null.
    /// Does not copy anything. Pure inspection — safe to call before
    /// deciding whether to attempt a clone.
    /// </summary>
    public string? TryFindContent(string sourceName, string cveId)
    {
        if (string.IsNullOrWhiteSpace(sourceName) || string.IsNullOrWhiteSpace(cveId))
            return null;
        var safeCve = GitPocCacheWriter.SafeId(cveId);
        var dir = Path.Combine(BundleRoot, sourceName, safeCve);
        if (!Directory.Exists(dir)) return null;
        try
        {
            return Directory.EnumerateFileSystemEntries(dir).Any() ? dir : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// If a bundle exists for (<paramref name="sourceName"/>,
    /// <paramref name="cveId"/>), emit <c>poc.fetch.offline_hit</c> and
    /// return a manifest of staged files (forward-slash relative paths
    /// + total byte size, computed from the bundle directory). Returns
    /// null on miss. Does NOT copy bytes itself — the caller (typically
    /// a git PoC source) is expected to feed each file through its
    /// existing <see cref="GitPocCacheWriter"/> so the standard
    /// SHA-256 / SQLite / <c>poc.fetch.artifact</c> trail still fires
    /// per artefact.
    /// </summary>
    public OfflineBundleHit? TryResolve(
        string sourceName,
        string cveId,
        AuditLog? audit)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);

        var srcDir = TryFindContent(sourceName, cveId);
        if (srcDir is null) return null;

        var files = new List<string>();
        long bytes = 0;
        foreach (var src in Directory.EnumerateFiles(srcDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                var info = new FileInfo(src);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                var rel = Path.GetRelativePath(srcDir, src);
                if (rel.Contains("..", StringComparison.Ordinal)) continue;
                files.Add(rel.Replace(Path.DirectorySeparatorChar, '/'));
                bytes += info.Length;
            }
            catch (IOException) { /* skip */ }
            catch (UnauthorizedAccessException) { /* skip */ }
        }

        audit?.Record("poc.fetch.offline_hit", new Dictionary<string, object?>
        {
            ["source"] = sourceName,
            ["cve_id"] = cveId,
            ["bundle_root"] = BundleRoot,
            ["bundle_dir"] = srcDir,
            ["file_count"] = files.Count,
            ["byte_size"] = bytes,
            ["files"] = files,
        });

        return new OfflineBundleHit(srcDir, files, bytes);
    }
}

/// <summary>Result of a successful <see cref="PocOfflineBundle.TryResolve"/>.</summary>
/// <param name="BundleDir">Source directory under the bundle root.</param>
/// <param name="RelativePaths">Forward-slash-normalised relative paths under <paramref name="BundleDir"/>.</param>
/// <param name="ByteSize">Total bytes in the bundle directory.</param>
public sealed record OfflineBundleHit(
    string BundleDir,
    IReadOnlyList<string> RelativePaths,
    long ByteSize);
