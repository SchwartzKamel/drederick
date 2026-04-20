using System.Text;
using System.Text.Json;

namespace Drederick.Enrichment;

/// <summary>
/// Queries the public GitHub Security Advisories REST endpoint for advisories
/// tagged with a given CVE id. Only records references — never clones repo
/// contents (that would require forking git and materially expanding the
/// attack surface). When <c>--fetch-poc</c> is on and an advisory contains a
/// GitHub reference whose path looks like <c>/poc*</c> or <c>/exploit*</c>,
/// the URL is still recorded verbatim so the practitioner can fetch it out of
/// band; no automated clone is performed.
/// </summary>
public sealed class GhsaSource : IPocSource
{
    public const string SourceName = "ghsa";
    private const string ApiBase = "https://api.github.com/advisories";

    private readonly IHttpFetcher _fetcher;

    public GhsaSource(IHttpFetcher? fetcher = null)
    {
        _fetcher = fetcher ?? new HttpClientFetcher();
    }

    public string Name => SourceName;

    public async Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        var url = $"{ApiBase}?cve_id={Uri.EscapeDataString(cveId)}";
        byte[]? body;
        try { body = await _fetcher.FetchAsync(url, ct).ConfigureAwait(false); }
        catch (HttpRequestException) { return Array.Empty<PocRef>(); }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return Array.Empty<PocRef>(); }

        if (body is null || body.Length == 0) return Array.Empty<PocRef>();

        List<PocRef> refs;
        try { refs = Parse(Encoding.UTF8.GetString(body)); }
        catch (JsonException) { return Array.Empty<PocRef>(); }

        // Caching is intentionally not implemented: GHSA entries are URL
        // references. The spec explicitly allows skipping git sparse-checkout
        // and simply recording the URL, which is what we do.
        return refs;
    }

    internal static List<PocRef> Parse(string json)
    {
        var refs = new List<PocRef>();
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return refs;

        foreach (var adv in doc.RootElement.EnumerateArray())
        {
            if (adv.ValueKind != JsonValueKind.Object) continue;
            var ghsaId = GetString(adv, "ghsa_id");
            var htmlUrl = GetString(adv, "html_url");
            if (!string.IsNullOrWhiteSpace(htmlUrl) && !string.IsNullOrWhiteSpace(ghsaId))
            {
                refs.Add(new PocRef(SourceName, Url: htmlUrl, ExternalId: ghsaId));
            }

            if (adv.TryGetProperty("references", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                int refIdx = 0;
                foreach (var r in arr.EnumerateArray())
                {
                    string? refUrl = r.ValueKind switch
                    {
                        JsonValueKind.String => r.GetString(),
                        JsonValueKind.Object => GetString(r, "url"),
                        _ => null,
                    };
                    if (string.IsNullOrWhiteSpace(refUrl)) continue;
                    var ext = ghsaId is null ? $"ref-{refIdx}" : $"{ghsaId}-ref-{refIdx}";
                    refs.Add(new PocRef(SourceName, Url: refUrl, ExternalId: ext));
                    refIdx++;
                }
            }
        }
        return refs;
    }

    /// <summary>
    /// Returns true if the URL is a GitHub repo URL whose path contains a
    /// segment starting with <c>poc</c> or <c>exploit</c>. Surfaced for tests
    /// — the live aggregator only records URLs, but this classifier is how a
    /// future sparse-checkout hook would gate itself.
    /// </summary>
    public static bool LooksLikePocRepoPath(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (!string.Equals(u.Host, "github.com", StringComparison.OrdinalIgnoreCase)) return false;
        var segments = u.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var seg in segments)
        {
            if (seg.StartsWith("poc", StringComparison.OrdinalIgnoreCase)) return true;
            if (seg.StartsWith("exploit", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string? GetString(JsonElement el, string prop)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(prop, out var v)) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }
}
