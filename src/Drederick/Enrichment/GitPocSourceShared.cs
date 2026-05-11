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
/// Outcome of a single <see cref="IGitClient.CloneSparseAsync"/> call. Carries
/// enough diagnostic surface for the consuming PoC source to emit a
/// <c>poc.fetch.diagnostics</c> audit event when the clone fails — the old
/// boolean return swallowed stderr and exit codes, leaving production
/// failures (GAP-053) impossible to triage from <c>audit.jsonl</c>.
/// </summary>
/// <param name="Success">True iff every git step exited 0.</param>
/// <param name="ExitCode">Exit code of the failing step (0 on success).</param>
/// <param name="Stderr">Combined stderr of the failing step (verbatim, untruncated).</param>
/// <param name="Stage">Which step failed: <c>clone</c>, <c>sparse-checkout</c>,
/// <c>checkout</c>, <c>url-not-allowed</c>, <c>timeout</c>, <c>exception</c>,
/// or <c>ok</c> on success.</param>
public sealed record GitCloneResult(
    bool Success,
    int ExitCode,
    string Stderr,
    string Stage);

/// <summary>
/// Outcome of <see cref="IGitClient.ProbeEgressAsync"/> — a synthetic
/// <c>git ls-remote HEAD</c> against a small public canary repo. Used by
/// the PoC sources to disambiguate "git is broken" from "the network is
/// blocking us" inside a single audit event.
/// </summary>
public sealed record GitEgressResult(
    bool Ok,
    int ExitCode,
    string Stderr,
    string Probe);

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
    /// Cached output of <c>git --version</c> (first line, trimmed). Returns
    /// a sentinel string like <c>"git not available: …"</c> when the binary
    /// is missing or unreadable; never throws and never null. Captured once
    /// at construction so failure diagnostics record a stable value even if
    /// the binary disappears mid-run.
    /// </summary>
    string GitVersion { get; }

    /// <summary>
    /// Sparse, blob-filtered, depth-1 clone. <paramref name="repoUrl"/> MUST
    /// be one of <see cref="GitPocAllowlist.AllowedRepoUrls"/>; implementations
    /// re-check before exec. Returns a <see cref="GitCloneResult"/> with the
    /// failing step's exit code and stderr — sources emit it verbatim into a
    /// <c>poc.fetch.diagnostics</c> audit event so production failures are
    /// triagable from <c>audit.jsonl</c> alone.
    /// </summary>
    Task<GitCloneResult> CloneSparseAsync(
        string repoUrl,
        string destDir,
        IReadOnlyList<string> sparsePaths,
        CancellationToken ct);

    /// <summary>
    /// Probes outbound git egress with <c>git ls-remote HEAD</c> against a
    /// small public canary repo. Lets sources distinguish a broken local
    /// git binary from a blocked network when a clone fails. Never throws.
    /// </summary>
    Task<GitEgressResult> ProbeEgressAsync(CancellationToken ct);
}

internal sealed class ProcessGitClient : IGitClient
{
    private readonly IProcessRunner _runner;
    private const int CloneTimeoutSeconds = 600;
    private const int SparseTimeoutSeconds = 120;
    private const int ProbeTimeoutSeconds = 15;

    /// <summary>
    /// Public, read-only canary repo used by <see cref="ProbeEgressAsync"/>.
    /// Tiny (no LFS, single branch) so the probe completes in well under
    /// <see cref="ProbeTimeoutSeconds"/> on a healthy link.
    /// </summary>
    private const string EgressCanaryRepo = "https://github.com/SchwartzKamel/drederick.git";

    private readonly Lazy<string> _gitVersion;

    public ProcessGitClient(IProcessRunner? runner = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
        _gitVersion = new Lazy<string>(CaptureGitVersion, isThreadSafe: true);
    }

    public string GitVersion => _gitVersion.Value;

    private string CaptureGitVersion()
    {
        try
        {
            var (cc, sout, serr) = _runner.Run("git", "--version", 5);
            if (cc == 0)
            {
                var first = (sout ?? string.Empty).Split('\n', 2)[0].Trim();
                return string.IsNullOrEmpty(first) ? "git: (no version output)" : first;
            }
            var stderr = (serr ?? string.Empty).Split('\n', 2)[0].Trim();
            return $"git not available: exit={cc} {stderr}".Trim();
        }
        catch (Win32Exception ex) { return $"git not available: {ex.Message}"; }
        catch (InvalidOperationException ex) { return $"git not available: {ex.Message}"; }
        catch (TimeoutException ex) { return $"git not available: {ex.Message}"; }
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

    public Task<GitCloneResult> CloneSparseAsync(
        string repoUrl,
        string destDir,
        IReadOnlyList<string> sparsePaths,
        CancellationToken ct)
    {
        if (!GitPocAllowlist.IsAllowed(repoUrl))
            return Task.FromResult(new GitCloneResult(false, -1, "url not on allowlist", "url-not-allowed"));

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
            var (cc, _, cerr) = _runner.Run("git", cloneArgs, CloneTimeoutSeconds);
            if (cc != 0) return Task.FromResult(new GitCloneResult(false, cc, cerr ?? string.Empty, "clone"));

            var setArgs =
                $"-C {ShellArg(destDir)} sparse-checkout set " +
                string.Join(' ', sparsePaths.Select(ShellArg));
            var (sc, _, serr) = _runner.Run("git", setArgs, SparseTimeoutSeconds);
            if (sc != 0) return Task.FromResult(new GitCloneResult(false, sc, serr ?? string.Empty, "sparse-checkout"));

            var (xc, _, xerr) = _runner.Run("git", $"-C {ShellArg(destDir)} checkout", CloneTimeoutSeconds);
            return Task.FromResult(xc == 0
                ? new GitCloneResult(true, 0, string.Empty, "ok")
                : new GitCloneResult(false, xc, xerr ?? string.Empty, "checkout"));
        }
        catch (Win32Exception ex) { return Task.FromResult(new GitCloneResult(false, -1, ex.Message, "exception")); }
        catch (InvalidOperationException ex) { return Task.FromResult(new GitCloneResult(false, -1, ex.Message, "exception")); }
        catch (TimeoutException ex) { return Task.FromResult(new GitCloneResult(false, -1, ex.Message, "timeout")); }
    }

    public Task<GitEgressResult> ProbeEgressAsync(CancellationToken ct)
    {
        var probe = $"git ls-remote {EgressCanaryRepo} HEAD";
        try
        {
            var (cc, _, err) = _runner.Run("git", $"ls-remote {ShellArg(EgressCanaryRepo)} HEAD", ProbeTimeoutSeconds);
            return Task.FromResult(new GitEgressResult(cc == 0, cc, err ?? string.Empty, probe));
        }
        catch (Win32Exception ex) { return Task.FromResult(new GitEgressResult(false, -1, ex.Message, probe)); }
        catch (InvalidOperationException ex) { return Task.FromResult(new GitEgressResult(false, -1, ex.Message, probe)); }
        catch (TimeoutException ex) { return Task.FromResult(new GitEgressResult(false, -1, ex.Message, probe)); }
    }

    private static string ShellArg(string s) => "'" + s.Replace("'", "'\\''") + "'";
}

/// <summary>
/// Helpers for emitting a <c>poc.fetch.diagnostics</c> + enriched
/// <c>poc.fetch.error</c> audit pair when an <see cref="IGitClient"/> clone
/// fails. Centralised so all three git-based PoC sources record an
/// identically-shaped diagnostic event — see GAP-053.
/// </summary>
internal static class GitPocDiagnostics
{
    public const int StderrTruncateBytes = 2048;
    public const int StderrErrorPreviewBytes = 512;

    /// <summary>
    /// UTF-8 byte-bounded substring of <paramref name="s"/> capped at
    /// <paramref name="maxBytes"/>. Avoids splitting a multi-byte rune.
    /// Returns the original string if it already fits.
    /// </summary>
    public static string TruncateUtf8(string s, int maxBytes)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        var bytes = System.Text.Encoding.UTF8.GetBytes(s);
        if (bytes.Length <= maxBytes) return s;
        // Walk back from maxBytes to a UTF-8 boundary (top bits 10xxxxxx are continuation bytes).
        var cut = maxBytes;
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return System.Text.Encoding.UTF8.GetString(bytes, 0, cut);
    }

    public static int Utf8ByteSize(string s)
        => string.IsNullOrEmpty(s) ? 0 : System.Text.Encoding.UTF8.GetByteCount(s);

    public static string Sha256Hex(string s)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(s ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    /// <summary>
    /// Records both <c>poc.fetch.diagnostics</c> (full diagnostic surface,
    /// 2 KB stderr cap) and an enriched <c>poc.fetch.error</c> (existing
    /// event shape, with <c>exit_code</c> / <c>stderr_first_512_bytes</c> /
    /// <c>git_version</c> / <c>egress_ok</c> appended for at-a-glance
    /// triage). Caller must have just observed <c>!cloneResult.Success</c>.
    /// </summary>
    public static async Task RecordCloneFailureAsync(
        AuditLog? audit,
        string source,
        string cveId,
        string repoUrl,
        IGitClient git,
        GitCloneResult cloneResult,
        CancellationToken ct)
    {
        var egress = await git.ProbeEgressAsync(ct).ConfigureAwait(false);
        var stderrFullSize = Utf8ByteSize(cloneResult.Stderr);
        var stderrTruncated = TruncateUtf8(cloneResult.Stderr, StderrTruncateBytes);
        var stderrSha256 = stderrFullSize > StderrTruncateBytes ? Sha256Hex(cloneResult.Stderr) : null;
        var stderrPreview = TruncateUtf8(cloneResult.Stderr, StderrErrorPreviewBytes);

        audit?.Record("poc.fetch.diagnostics", new Dictionary<string, object?>
        {
            ["source"] = source,
            ["cve_id"] = cveId,
            ["repo_url"] = repoUrl,
            ["git_version"] = git.GitVersion,
            ["exit_code"] = cloneResult.ExitCode,
            ["stage"] = cloneResult.Stage,
            ["stderr"] = stderrTruncated,
            ["stderr_full_byte_size"] = stderrFullSize,
            ["stderr_truncated"] = stderrFullSize > StderrTruncateBytes,
            ["stderr_sha256"] = stderrSha256,
            ["egress_ok"] = egress.Ok,
            ["egress_exit_code"] = egress.ExitCode,
            ["egress_probe"] = egress.Probe,
            ["egress_stderr"] = TruncateUtf8(egress.Stderr, StderrTruncateBytes),
        });

        audit?.Record("poc.fetch.error", new Dictionary<string, object?>
        {
            ["source"] = source,
            ["cve_id"] = cveId,
            ["error"] = "git clone failed",
            ["exit_code"] = cloneResult.ExitCode,
            ["stage"] = cloneResult.Stage,
            ["stderr_first_512_bytes"] = stderrPreview,
            ["git_version"] = git.GitVersion,
            ["egress_ok"] = egress.Ok,
        });
    }
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
