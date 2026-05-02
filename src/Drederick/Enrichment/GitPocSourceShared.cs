using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Reporting;

namespace Drederick.Enrichment;

/// <summary>
/// Shared abstractions for the git-clone PoC sources
/// (<see cref="MetasploitGitSource"/>, <see cref="NucleiTemplatesGitSource"/>,
/// <see cref="PocInGitHubSource"/>). Hard-coded URL allowlist + shared
/// per-repo lock + verbatim cache writer. No source consumes config-driven
/// URLs; the only knobs are byte caps and the cache root.
/// </summary>
public interface IGitClient
{
    /// <summary>Returns true if <paramref name="repoDir"/> is a non-empty cached clone.</summary>
    bool IsCached(string repoDir);

    /// <summary>
    /// Sparse, blob-filtered, depth-1 clone. <paramref name="repoUrl"/> MUST
    /// be one of <see cref="GitPocAllowlist.AllowedRepoUrls"/>; implementations
    /// re-check before exec. Returns <c>true</c> on success, <c>false</c> on
    /// any non-zero exit. Errors are swallowed — sources fall back to
    /// returning empty refs.
    /// </summary>
    Task<bool> CloneSparseAsync(
        string repoUrl,
        string destDir,
        IReadOnlyList<string> sparsePaths,
        CancellationToken ct);
}

internal sealed class ProcessGitClient : IGitClient
{
    private readonly IProcessRunner _runner;
    private const int CloneTimeoutSeconds = 600;
    private const int SparseTimeoutSeconds = 120;

    public ProcessGitClient(IProcessRunner? runner = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
    }

    public bool IsCached(string repoDir)
    {
        try
        {
            return Directory.Exists(Path.Combine(repoDir, ".git"));
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    public Task<bool> CloneSparseAsync(
        string repoUrl,
        string destDir,
        IReadOnlyList<string> sparsePaths,
        CancellationToken ct)
    {
        if (!GitPocAllowlist.IsAllowed(repoUrl))
            return Task.FromResult(false);

        try
        {
            var parent = Path.GetDirectoryName(destDir);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

            // Sparse, blob-filtered, depth-1 clone with no checkout — then
            // configure sparse-checkout, then check out. This avoids pulling
            // the full tree into the working copy on a slow link.
            var cloneArgs =
                $"clone --depth=1 --filter=blob:none --sparse --no-checkout " +
                $"{ShellArg(repoUrl)} {ShellArg(destDir)}";
            var (cc, _, _) = _runner.Run("git", cloneArgs, CloneTimeoutSeconds);
            if (cc != 0) return Task.FromResult(false);

            var setArgs =
                $"-C {ShellArg(destDir)} sparse-checkout set " +
                string.Join(' ', sparsePaths.Select(ShellArg));
            var (sc, _, _) = _runner.Run("git", setArgs, SparseTimeoutSeconds);
            if (sc != 0) return Task.FromResult(false);

            var (xc, _, _) = _runner.Run("git", $"-C {ShellArg(destDir)} checkout", CloneTimeoutSeconds);
            return Task.FromResult(xc == 0);
        }
        catch (Win32Exception) { return Task.FromResult(false); }
        catch (InvalidOperationException) { return Task.FromResult(false); }
        catch (TimeoutException) { return Task.FromResult(false); }
    }

    private static string ShellArg(string s) => "'" + s.Replace("'", "'\\''") + "'";
}

/// <summary>
/// Hard-coded allowlist of repo URLs the git-clone PoC sources may pass to
/// <c>git clone</c>. There is no config knob; mutating this list is a code
/// change. Defends against arbitrary-URL exec via subprocess argv.
/// </summary>
public static class GitPocAllowlist
{
    public const string MetasploitFramework = "https://github.com/rapid7/metasploit-framework";
    public const string NucleiTemplates = "https://github.com/projectdiscovery/nuclei-templates";
    public const string PocInGitHub = "https://github.com/nomi-sec/PoC-in-GitHub";

    public static readonly IReadOnlyList<string> AllowedRepoUrls = new[]
    {
        MetasploitFramework,
        NucleiTemplates,
        PocInGitHub,
    };

    public static bool IsAllowed(string? url)
        => !string.IsNullOrWhiteSpace(url) && AllowedRepoUrls.Contains(url, StringComparer.Ordinal);
}

/// <summary>
/// Per-repo-dir async lock so concurrent CVE fetches in the same run share a
/// single clone. Thread-safe by <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
internal static class RepoCacheLock
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks
        = new(StringComparer.Ordinal);

    public static SemaphoreSlim For(string repoDir)
        => _locks.GetOrAdd(repoDir, _ => new SemaphoreSlim(1, 1));
}

/// <summary>
/// HTTP client used by <see cref="PocInGitHubSource"/> for raw.githubusercontent.com
/// fetches. Tests substitute a recording stub. Status 429 is surfaced as a
/// dedicated return so the source can record + back off without throwing.
/// </summary>
public interface IGitHubHttpClient
{
    Task<GitHubFetchResult> GetAsync(string url, CancellationToken ct);
}

public sealed record GitHubFetchResult(
    int Status,
    byte[]? Body,
    string? ContentType,
    int? RetryAfterSeconds);

internal sealed class DefaultGitHubHttpClient : IGitHubHttpClient, IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    public DefaultGitHubHttpClient(HttpClient? http = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        _ownsClient = http is null;
    }

    public async Task<GitHubFetchResult> GetAsync(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            int? retryAfter = null;
            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                if (resp.Headers.RetryAfter?.Delta is { } delta)
                    retryAfter = (int)delta.TotalSeconds;
            }
            byte[]? body = resp.IsSuccessStatusCode
                ? await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false)
                : null;
            var ct2 = resp.Content.Headers.ContentType?.MediaType;
            return new GitHubFetchResult((int)resp.StatusCode, body, ct2, retryAfter);
        }
        catch (HttpRequestException) { return new GitHubFetchResult(0, null, null, null); }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return new GitHubFetchResult(0, null, null, null);
        }
    }

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}

/// <summary>
/// Verbatim cache writer shared by the git PoC sources. Enforces per-artifact
/// and per-run byte caps, sha256s the raw bytes, persists provenance, and
/// audits each fetch. Never rewrites or sanitises content.
/// </summary>
internal sealed class GitPocCacheWriter
{
    private readonly long _maxArtifactBytes;
    private readonly long _maxTotalBytes;
    private long _totalCached;

    public GitPocCacheWriter(long maxArtifactBytes, long maxTotalBytes)
    {
        _maxArtifactBytes = maxArtifactBytes;
        _maxTotalBytes = maxTotalBytes;
    }

    public long TotalCached => Interlocked.Read(ref _totalCached);

    /// <summary>
    /// Copy <paramref name="sourcePath"/> verbatim into
    /// <c>{ctx.CacheRoot}/{source}/{cve}/{relativeDestPath}</c>, persist
    /// provenance + audit, and return the destination path. Returns null on
    /// size cap, missing file, symlink, or I/O failure (audit-recorded).
    /// </summary>
    public string? WriteCopy(
        string source,
        string cveId,
        string sourcePath,
        string relativeDestPath,
        string sourceUrl,
        string? contentTypeHint,
        PocQueryContext ctx)
    {
        try
        {
            var info = new FileInfo(sourcePath);
            if (!info.Exists) return null;
            // Refuse symlinks — git can check out a symlink that escapes the
            // sparse tree; we read its bytes via the abstract path but flag
            // and skip to avoid copying out-of-tree content.
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
                {
                    ["source"] = source,
                    ["cve_id"] = cveId,
                    ["reason"] = "symlink in sparse tree refused",
                });
                return null;
            }
            if (info.Length > _maxArtifactBytes)
            {
                ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
                {
                    ["source"] = source,
                    ["cve_id"] = cveId,
                    ["reason"] = $"artifact exceeds per-artifact cap ({info.Length} > {_maxArtifactBytes})",
                });
                return null;
            }
            var prior = Interlocked.Read(ref _totalCached);
            if (prior + info.Length > _maxTotalBytes)
            {
                ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
                {
                    ["source"] = source,
                    ["cve_id"] = cveId,
                    ["reason"] = $"per-run total cap exceeded ({prior + info.Length} > {_maxTotalBytes})",
                });
                return null;
            }

            var bytes = File.ReadAllBytes(sourcePath);
            return WriteBytes(source, cveId, bytes, relativeDestPath, sourceUrl, contentTypeHint, ctx);
        }
        catch (IOException ex)
        {
            ctx.Audit?.Record("poc.fetch.error", new Dictionary<string, object?>
            {
                ["source"] = source,
                ["cve_id"] = cveId,
                ["error"] = ex.Message,
            });
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.Audit?.Record("poc.fetch.error", new Dictionary<string, object?>
            {
                ["source"] = source,
                ["cve_id"] = cveId,
                ["error"] = ex.Message,
            });
            return null;
        }
    }

    /// <summary>
    /// Write raw bytes (already fetched, e.g. via HTTP) into the cache.
    /// Same caps + audit semantics as <see cref="WriteCopy"/>.
    /// </summary>
    public string? WriteBytes(
        string source,
        string cveId,
        byte[] bytes,
        string relativeDestPath,
        string sourceUrl,
        string? contentTypeHint,
        PocQueryContext ctx)
    {
        try
        {
            if (bytes.LongLength > _maxArtifactBytes)
            {
                ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
                {
                    ["source"] = source,
                    ["cve_id"] = cveId,
                    ["reason"] = $"artifact exceeds per-artifact cap ({bytes.LongLength} > {_maxArtifactBytes})",
                });
                return null;
            }
            long after = Interlocked.Add(ref _totalCached, bytes.LongLength);
            if (after > _maxTotalBytes)
            {
                Interlocked.Add(ref _totalCached, -bytes.LongLength);
                ctx.Audit?.Record("poc.fetch.miss", new Dictionary<string, object?>
                {
                    ["source"] = source,
                    ["cve_id"] = cveId,
                    ["reason"] = $"per-run total cap exceeded ({after} > {_maxTotalBytes})",
                });
                return null;
            }

            var safeCve = SafeId(cveId);
            var dest = Path.Combine(ctx.CacheRoot, source, safeCve, relativeDestPath);
            var dir = Path.GetDirectoryName(dest)!;
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(dest, bytes);

            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var fetchedAt = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture);

            ctx.Report.UpsertPocSource(
                source: source,
                externalId: BuildExternalId(safeCve, relativeDestPath),
                sha256: sha,
                path: dest,
                fetchedAt: fetchedAt,
                sourceUrl: sourceUrl);

            ctx.Audit?.Record("poc.fetch.artifact", new Dictionary<string, object?>
            {
                ["source"] = source,
                ["cve_id"] = cveId,
                ["local_path"] = dest,
                ["sha256"] = sha,
                ["byte_size"] = bytes.LongLength,
                ["url"] = sourceUrl,
                ["content_type"] = contentTypeHint,
            });

            return dest;
        }
        catch (IOException ex)
        {
            ctx.Audit?.Record("poc.fetch.error", new Dictionary<string, object?>
            {
                ["source"] = source,
                ["cve_id"] = cveId,
                ["error"] = ex.Message,
            });
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.Audit?.Record("poc.fetch.error", new Dictionary<string, object?>
            {
                ["source"] = source,
                ["cve_id"] = cveId,
                ["error"] = ex.Message,
            });
            return null;
        }
    }

    private static string BuildExternalId(string safeCve, string rel)
        => $"{safeCve}/{rel.Replace(Path.DirectorySeparatorChar, '/')}";

    public static string SafeId(string id)
    {
        var sb = new System.Text.StringBuilder(id.Length);
        foreach (var c in id)
        {
            sb.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_');
        }
        return sb.Length == 0 ? "_" : sb.ToString();
    }
}
