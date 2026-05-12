using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Http;

/// <summary>
/// SPA catch-all baseline probe (GAP-055). Single-page applications
/// frequently serve the app shell with HTTP 200 for any unknown route,
/// which poisons wordlist content discovery with thousands of false
/// positives. This detector fires two randomized 404-bait requests
/// against a base URL and decides whether the target is a SPA catch-all,
/// returning a <see cref="SpaBaseline"/> the main content-discovery loop
/// can use to tag wordlist hits as <c>match_kind=spa_catch_all</c>.
/// </summary>
/// <remarks>
/// Scope is re-checked inside <see cref="ProbeAsync"/> — the host of the
/// supplied <c>baseUrl</c> must be in scope. Out-of-scope inputs throw
/// <see cref="ScopeException"/>.
/// </remarks>
public sealed class SpaCatchAllDetector
{
    /// <summary>Structural HTML markers that strongly suggest an SPA shell.</summary>
    internal static readonly string[] SpaMarkers =
    {
        "<div id=\"root\">",
        "<div id='root'>",
        "<div id=\"app\">",
        "<div id='app'>",
        "<script src=\"/static/",
        "<script src='/static/",
        "__INITIAL_STATE__",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public SpaCatchAllDetector(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public async Task<SpaBaseline> ProbeAsync(
        string baseUrl,
        HttpClient httpClient,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        }
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            throw new ArgumentException(
                $"baseUrl '{baseUrl}' is not an absolute URL.", nameof(baseUrl));
        }
        if (httpClient is null)
        {
            throw new ArgumentNullException(nameof(httpClient));
        }

        _scope.Require(baseUri.Host);

        var authority = baseUri.GetLeftPart(UriPartial.Authority);

        var probe1 = await FetchAsync(httpClient, authority, ct).ConfigureAwait(false);
        var probe2 = await FetchAsync(httpClient, authority, ct).ConfigureAwait(false);

        bool sameStatus200 = probe1.Status == 200 && probe2.Status == 200;
        long lenMin = Math.Min(probe1.Length, probe2.Length);
        long lenMax = Math.Max(probe1.Length, probe2.Length);

        bool identicalSha =
            sameStatus200
            && probe1.Sha256 is not null
            && probe2.Sha256 is not null
            && string.Equals(probe1.Sha256, probe2.Sha256, StringComparison.Ordinal);

        bool looseSpa = false;
        if (sameStatus200 && !identicalSha && lenMax > 0)
        {
            double drift = (lenMax - lenMin) / (double)lenMax;
            if (drift <= 0.05
                && BodyContainsSpaMarker(probe1.BodyText)
                && BodyContainsSpaMarker(probe2.BodyText))
            {
                looseSpa = true;
            }
        }

        bool isLikelySpa = identicalSha || looseSpa;

        var redirectChainSha = ComputeRedirectChainSha(probe1, probe2);

        var baseline = new SpaBaseline
        {
            BaseUrl = authority,
            PrimaryStatus = probe1.Status,
            PrimaryContentLength = probe1.Length,
            PrimaryContentType = probe1.ContentType,
            BodySha256 = probe1.Sha256,
            SecondaryBodySha256 = probe2.Sha256,
            ContentLengthRange = (lenMin, lenMax),
            RedirectChainSha256 = redirectChainSha,
            IsLikelySpaCatchAll = isLikelySpa,
            DetectionReason = isLikelySpa
                ? (identicalSha ? "identical_sha" : "loose_structure_match")
                : "no_match",
        };

        _audit.Record("spa_catch_all.baseline", new Dictionary<string, object?>
        {
            ["base_url"] = authority,
            ["probe1_status"] = probe1.Status,
            ["probe2_status"] = probe2.Status,
            ["content_length_min"] = lenMin,
            ["content_length_max"] = lenMax,
            ["sha256"] = baseline.BodySha256,
            ["secondary_sha256"] = baseline.SecondaryBodySha256,
            ["redirect_chain_sha256"] = redirectChainSha,
            ["is_spa"] = isLikelySpa,
            ["reason"] = baseline.DetectionReason,
        });

        return baseline;
    }

    /// <summary>
    /// Returns true when a wordlist hit's body should be tagged as a SPA
    /// catch-all match against the supplied baseline. Two-tier check:
    /// exact SHA-256 match, or content-length within 2% of the baseline
    /// range AND body contains a SPA structural marker.
    /// </summary>
    public static bool IsBodySpaCatchAllMatch(
        byte[] body,
        string? bodySha256,
        SpaBaseline baseline)
    {
        if (baseline is null) return false;
        if (!baseline.IsLikelySpaCatchAll) return false;
        if (body is null) return false;

        if (bodySha256 is not null)
        {
            if (string.Equals(bodySha256, baseline.BodySha256, StringComparison.Ordinal)
                || string.Equals(bodySha256, baseline.SecondaryBodySha256, StringComparison.Ordinal))
            {
                return true;
            }
        }

        long size = body.LongLength;
        long lenMax = baseline.ContentLengthRange.Max;
        long lenMin = baseline.ContentLengthRange.Min;
        if (lenMax <= 0) return false;

        long allowedDrift = (long)Math.Ceiling(lenMax * 0.02);
        bool lengthInRange = size >= (lenMin - allowedDrift) && size <= (lenMax + allowedDrift);
        if (!lengthInRange) return false;

        string text;
        try { text = Encoding.UTF8.GetString(body); }
        catch { return false; }

        return BodyContainsSpaMarker(text);
    }

    internal static bool BodyContainsSpaMarker(string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        foreach (var marker in SpaMarkers)
        {
            if (body.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    private static string ComputeRedirectChainSha(ProbeResponse a, ProbeResponse b)
    {
        var sb = new StringBuilder();
        sb.Append(a.Status).Append('|').Append(a.LocationHeader ?? "").Append('\n');
        sb.Append(b.Status).Append('|').Append(b.LocationHeader ?? "");
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    private static async Task<ProbeResponse> FetchAsync(
        HttpClient httpClient, string authority, CancellationToken ct)
    {
        var rand = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var path = "/__drederick_404_" + rand;
        var url = authority + path;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var resp = await httpClient.SendAsync(
                req, HttpCompletionOption.ResponseContentRead, cts.Token).ConfigureAwait(false);

            var bytes = await resp.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            string? text = null;
            try { text = Encoding.UTF8.GetString(bytes); }
            catch { /* binary body, leave null */ }

            return new ProbeResponse
            {
                Path = path,
                Status = (int)resp.StatusCode,
                Length = bytes.LongLength,
                ContentType = resp.Content.Headers.ContentType?.MediaType,
                Sha256 = sha,
                BodyText = text,
                LocationHeader = resp.Headers.Location?.ToString(),
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new ProbeResponse
            {
                Path = path,
                Status = 0,
                Length = 0,
                ContentType = null,
                Sha256 = null,
                BodyText = null,
                LocationHeader = null,
            };
        }
    }

    private sealed class ProbeResponse
    {
        public string Path { get; set; } = "";
        public int Status { get; set; }
        public long Length { get; set; }
        public string? ContentType { get; set; }
        public string? Sha256 { get; set; }
        public string? BodyText { get; set; }
        public string? LocationHeader { get; set; }
    }
}

/// <summary>
/// Baseline emitted by <see cref="SpaCatchAllDetector.ProbeAsync"/>.
/// Captures enough state for the content-discovery main loop to tag
/// wordlist hits that look like the SPA shell rather than real content.
/// </summary>
public sealed class SpaBaseline
{
    public string BaseUrl { get; set; } = "";
    public int PrimaryStatus { get; set; }
    public long PrimaryContentLength { get; set; }
    public string? PrimaryContentType { get; set; }
    public string? BodySha256 { get; set; }
    public string? SecondaryBodySha256 { get; set; }
    public (long Min, long Max) ContentLengthRange { get; set; }
    public string? RedirectChainSha256 { get; set; }
    public bool IsLikelySpaCatchAll { get; set; }
    public string DetectionReason { get; set; } = "no_match";
}
