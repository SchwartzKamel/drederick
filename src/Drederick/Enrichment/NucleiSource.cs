using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// Locates <c>nuclei-templates</c> matching a CVE id and (when caching is
/// enabled) primes the local PoC cache so <see cref="Drederick.Autopilot.ExploitationPlanner"/>
/// can emit band-500 / band-400 nuclei actions on subsequent runs.
///
/// Discovery uses <c>grep -rlnF</c> against a probed templates root
/// (<c>~/nuclei-templates</c>, <c>~/.config/nuclei/templates</c>,
/// <c>$DREDERICK_NUCLEI_TEMPLATES</c>, …). Each hit is copied verbatim into
/// <c>out/poc_cache/nuclei/&lt;external_id&gt;/&lt;file&gt;</c> with
/// SHA-256 recorded via <see cref="Reporting.SqliteReport.UpsertPocSource"/>
/// and a <c>poc.fetch</c> audit event emitted. <see cref="PocRef.LocalPath"/>
/// then points at the cached copy so the planner's <c>_pocCacheRoot</c>
/// scanners hit. <b>Invariant:</b> read-and-mirror only — we never execute,
/// never rewrite, never neutralise template bytes.
/// </summary>
public sealed class NucleiSource : IPocSource
{
    public const string SourceName = "nuclei";
    private const int TimeoutSeconds = 30;
    private const long DefaultMaxArtifactBytes = 5L * 1024 * 1024;       // 5 MB
    private const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024;   // 2 GB

    // CVE-id whitelist regex — defends grep argv against injection. Matches
    // only the canonical CVE-YYYY-NNNN[N…] shape we accept everywhere.
    private static readonly Regex CveShape = new(@"^CVE-\d{4}-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IProcessRunner _runner;
    private readonly Func<string?> _templatesDirProbe;
    private readonly long _maxArtifactBytes;
    private readonly long _maxTotalBytes;

    public NucleiSource(
        IProcessRunner? runner = null,
        Func<string?>? templatesDirProbe = null,
        long? maxArtifactBytes = null,
        long? maxTotalBytes = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
        _templatesDirProbe = templatesDirProbe ?? DefaultProbe;
        _maxArtifactBytes = maxArtifactBytes ?? DefaultMaxArtifactBytes;
        _maxTotalBytes = maxTotalBytes ?? DefaultMaxTotalBytes;
    }

    public string Name => SourceName;

    public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        IReadOnlyList<PocRef> empty = Array.Empty<PocRef>();
        if (!CveShape.IsMatch(cveId)) return Task.FromResult(empty);

        var dir = _templatesDirProbe();
        if (string.IsNullOrWhiteSpace(dir)) return Task.FromResult(empty);

        (int code, string stdout, string _) res;
        try
        {
            // -F: fixed-string match (CVE ids carry no regex meta).
            // The CVE id is whitelisted by CveShape and the dir is from a
            // controlled probe — argv is safe.
            res = _runner.Run("grep",
                $"-rlnF -- {ShellArg(cveId)} {ShellArg(dir)}",
                TimeoutSeconds);
        }
        catch (Win32Exception) { return Task.FromResult(empty); }
        catch (InvalidOperationException) { return Task.FromResult(empty); }
        catch (TimeoutException) { return Task.FromResult(empty); }

        // grep exits 1 when no matches; that's not a failure.
        if (res.code != 0 && res.code != 1) return Task.FromResult(empty);

        var refs = new List<PocRef>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long totalCached = 0;
        foreach (var line in res.stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var path = line.Trim();
            if (path.Length == 0) continue;
            if (!seen.Add(path)) continue;
            var templateId = Path.GetFileNameWithoutExtension(path);
            string? cachedPath = null;
            if (ctx.FetchPoc)
            {
                cachedPath = TryCache(cveId, templateId, path, ctx, ref totalCached);
            }
            // When caching ran successfully, point LocalPath at the cached
            // copy so ExploitationPlanner.FindNucleiTemplatesForCve hits the
            // poc_cache tree. Otherwise fall back to the original location.
            refs.Add(new PocRef(Name, Url: null, ExternalId: templateId, LocalPath: cachedPath ?? path));
        }
        return Task.FromResult<IReadOnlyList<PocRef>>(refs);
    }

    private string? TryCache(string cveId, string templateId, string sourcePath, PocQueryContext ctx, ref long totalCached)
    {
        try
        {
            var info = new FileInfo(sourcePath);
            if (!info.Exists) return null;
            if (info.Length > _maxArtifactBytes) return null;
            if (totalCached + info.Length > _maxTotalBytes) return null;

            var safeId = SafeId(string.IsNullOrWhiteSpace(templateId) ? cveId : templateId);
            var dir = Path.Combine(ctx.CacheRoot, Name, safeId);
            Directory.CreateDirectory(dir);
            var dest = Path.Combine(dir, Path.GetFileName(sourcePath));

            // Verbatim copy.
            var bytes = File.ReadAllBytes(sourcePath);
            File.WriteAllBytes(dest, bytes);
            totalCached += info.Length;

            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var fetchedAt = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            var sourceUrl = $"https://github.com/projectdiscovery/nuclei-templates/blob/main/{templateId}.yaml";

            ctx.Report.UpsertPocSource(
                source: Name,
                externalId: safeId,
                sha256: sha,
                path: dest,
                fetchedAt: fetchedAt,
                sourceUrl: sourceUrl);

            ctx.Audit?.Record("poc.fetch", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve"] = cveId,
                ["external_id"] = safeId,
                ["url"] = sourceUrl,
                ["local_path"] = dest,
                ["sha256"] = sha,
                ["bytes"] = info.Length,
            });

            return dest;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static string SafeId(string id)
    {
        var sb = new System.Text.StringBuilder(id.Length);
        foreach (var c in id)
        {
            sb.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_');
        }
        return sb.Length == 0 ? "_" : sb.ToString();
    }

    private static string? DefaultProbe()
    {
        var env = Environment.GetEnvironmentVariable("DREDERICK_NUCLEI_TEMPLATES");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env)) return env;

        var home = Environment.GetEnvironmentVariable("HOME")
                   ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home)) return null;
        string[] candidates =
        {
            Path.Combine(home, "nuclei-templates"),
            Path.Combine(home, ".config", "nuclei", "templates"),
            Path.Combine(home, ".config", "nuclei-templates"),
        };
        foreach (var c in candidates)
        {
            if (Directory.Exists(c)) return c;
        }
        return null;
    }

    private static string ShellArg(string s) => "'" + s.Replace("'", "'\\''") + "'";
}
