using System.IO.Compression;
using System.Text.Json;

namespace Drederick.Enrichment;

/// <summary>
/// Manages a local on-disk copy of the NVD JSON 2.0 CVE data feed. The cache
/// directory holds one or more <c>nvdcve-2.0-*.json.gz</c> files which are
/// loaded lazily into flat <see cref="NvdEntry"/> records.
///
/// The cache supports fully offline operation: if a network refresh is
/// requested but fails (or an <see cref="IHttpFetcher"/> throws), any
/// pre-existing files are still used.
/// </summary>
public sealed class NvdCache
{
    public const string DefaultBaseUrl = "https://nvd.nist.gov/feeds/json/cve/2.0/";
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromHours(24);
    private const int RecentYearCount = 5;

    private readonly string _cacheDir;
    private readonly IHttpFetcher _fetcher;
    private readonly TimeSpan _refreshInterval;
    private readonly string _baseUrl;
    private readonly Func<DateTimeOffset> _now;

    private List<NvdEntry>? _loaded;

    public NvdCache(
        string? cacheDir = null,
        IHttpFetcher? fetcher = null,
        TimeSpan? refreshInterval = null,
        string? baseUrl = null,
        Func<DateTimeOffset>? now = null)
    {
        _cacheDir = cacheDir ?? DefaultCacheDir();
        _fetcher = fetcher ?? new HttpClientFetcher();
        _refreshInterval = refreshInterval ?? DefaultRefreshInterval;
        _baseUrl = baseUrl ?? DefaultBaseUrl;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public string CacheDir => _cacheDir;

    public static string DefaultCacheDir()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".drederick", "nvd");
    }

    /// <summary>
    /// Ensure the cache is populated — download fresh feed files if stale or
    /// missing, then return all known CVE entries. Safe to call repeatedly:
    /// the in-memory entries are cached until <see cref="Invalidate"/>.
    /// </summary>
    public async Task<IReadOnlyList<NvdEntry>> LoadAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(_cacheDir);
        await EnsureFreshAsync(ct).ConfigureAwait(false);
        return _loaded ??= ParseCacheDir();
    }

    public void Invalidate() => _loaded = null;

    private async Task EnsureFreshAsync(CancellationToken ct)
    {
        var existing = Directory.EnumerateFiles(_cacheDir, "*.json.gz").ToList();
        var newest = existing.Count == 0
            ? DateTimeOffset.MinValue
            : existing.Max(f => new DateTimeOffset(File.GetLastWriteTimeUtc(f), TimeSpan.Zero));

        // If the cache is fresh we do nothing. If it exists but is stale we
        // still try to refresh but tolerate any failure (offline mode).
        if (existing.Count > 0 && _now() - newest < _refreshInterval)
        {
            return;
        }

        var currentYear = _now().Year;
        var urls = new List<string>();
        for (int y = currentYear - RecentYearCount + 1; y <= currentYear; y++)
        {
            urls.Add($"{_baseUrl}nvdcve-2.0-{y}.json.gz");
        }
        urls.Add($"{_baseUrl}nvdcve-2.0-modified.json.gz");

        bool anySuccess = false;
        foreach (var url in urls)
        {
            try
            {
                var bytes = await _fetcher.FetchAsync(url, ct).ConfigureAwait(false);
                if (bytes is null) continue;
                var fileName = url[(url.LastIndexOf('/') + 1)..];
                var path = Path.Combine(_cacheDir, fileName);
                await File.WriteAllBytesAsync(path, bytes, ct).ConfigureAwait(false);
                anySuccess = true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Offline or transient failure — fall through. If we already
                // have any cached file we'll still be able to load.
            }
        }

        if (!anySuccess && existing.Count == 0)
        {
            throw new InvalidOperationException(
                $"NvdCache: no feed files in '{_cacheDir}' and refresh failed. " +
                "Drop an NVD 2.0 .json.gz into the cache dir or ensure network access.");
        }
    }

    private List<NvdEntry> ParseCacheDir()
    {
        var result = new List<NvdEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(_cacheDir, "*.json.gz"))
        {
            foreach (var entry in ParseFile(file))
            {
                if (seen.Add(entry.CveId))
                {
                    result.Add(entry);
                }
            }
        }
        return result;
    }

    internal static IEnumerable<NvdEntry> ParseFile(string path)
    {
        using var fs = File.OpenRead(path);
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var doc = JsonDocument.Parse(gz);
        return ParseDocument(doc).ToList();
    }

    internal static IEnumerable<NvdEntry> ParseDocument(JsonDocument doc)
    {
        if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns) ||
            vulns.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }
        foreach (var v in vulns.EnumerateArray())
        {
            if (!v.TryGetProperty("cve", out var cve)) continue;
            var parsed = ParseCve(cve);
            if (parsed is not null) yield return parsed;
        }
    }

    private static NvdEntry? ParseCve(JsonElement cve)
    {
        if (!cve.TryGetProperty("id", out var idEl) || idEl.ValueKind != JsonValueKind.String) return null;
        var id = idEl.GetString()!;

        string? summary = null;
        if (cve.TryGetProperty("descriptions", out var descs) && descs.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in descs.EnumerateArray())
            {
                if (d.TryGetProperty("lang", out var lang) &&
                    string.Equals(lang.GetString(), "en", StringComparison.OrdinalIgnoreCase) &&
                    d.TryGetProperty("value", out var val))
                {
                    summary = val.GetString();
                    break;
                }
            }
        }

        string? published = null;
        if (cve.TryGetProperty("published", out var pub) && pub.ValueKind == JsonValueKind.String)
        {
            published = pub.GetString();
        }

        double? cvss = ExtractCvss(cve);

        var matches = new List<NvdCpeMatch>();
        if (cve.TryGetProperty("configurations", out var configs) && configs.ValueKind == JsonValueKind.Array)
        {
            foreach (var cfg in configs.EnumerateArray())
            {
                if (!cfg.TryGetProperty("nodes", out var nodes)) continue;
                foreach (var node in nodes.EnumerateArray())
                {
                    CollectCpeMatches(node, matches);
                }
            }
        }

        return new NvdEntry
        {
            CveId = id,
            Summary = summary,
            Published = published,
            Cvss = cvss,
            CpeMatches = matches,
        };
    }

    private static double? ExtractCvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics)) return null;
        // Preference order: v3.1 > v3.0 > v2.0.
        foreach (var key in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (metrics.TryGetProperty(key, out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var m in arr.EnumerateArray())
                {
                    if (m.TryGetProperty("cvssData", out var data) &&
                        data.TryGetProperty("baseScore", out var score) &&
                        score.ValueKind == JsonValueKind.Number)
                    {
                        return score.GetDouble();
                    }
                }
            }
        }
        return null;
    }

    private static void CollectCpeMatches(JsonElement node, List<NvdCpeMatch> acc)
    {
        if (node.TryGetProperty("cpeMatch", out var cpes) && cpes.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in cpes.EnumerateArray())
            {
                var criteria = c.TryGetProperty("criteria", out var crEl) ? crEl.GetString() : null;
                if (string.IsNullOrEmpty(criteria)) continue;
                var (vendor, product, version) = ParseCpe(criteria!);
                acc.Add(new NvdCpeMatch
                {
                    Criteria = criteria!,
                    Vendor = vendor,
                    Product = product,
                    Version = version,
                    Vulnerable = !c.TryGetProperty("vulnerable", out var vuln) || vuln.GetBoolean(),
                    VersionStartIncluding = OptString(c, "versionStartIncluding"),
                    VersionStartExcluding = OptString(c, "versionStartExcluding"),
                    VersionEndIncluding = OptString(c, "versionEndIncluding"),
                    VersionEndExcluding = OptString(c, "versionEndExcluding"),
                });
            }
        }
        if (node.TryGetProperty("children", out var children) && children.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in children.EnumerateArray()) CollectCpeMatches(child, acc);
        }
    }

    private static string? OptString(JsonElement obj, string name)
    {
        return obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;
    }

    /// <summary>
    /// Parse "cpe:2.3:a:vendor:product:version:..." into (vendor, product, version).
    /// Returns nulls for missing/wildcard parts.
    /// </summary>
    internal static (string? vendor, string? product, string? version) ParseCpe(string criteria)
    {
        // cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:...
        var parts = criteria.Split(':');
        if (parts.Length < 6) return (null, null, null);
        var vendor = parts[3];
        var product = parts[4];
        var version = parts[5];
        return (vendor, product, version);
    }
}
