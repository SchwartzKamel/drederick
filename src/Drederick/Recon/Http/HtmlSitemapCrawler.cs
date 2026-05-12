// --- htb-content-discovery-crawl --- (GAP-022)
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Http;

/// <summary>
/// GAP-022 HTML / sitemap.xml / robots.txt content-discovery crawler.
/// Complements <see cref="Drederick.Recon.HttpContentDiscoveryTool"/>
/// (wordlist-based) by extracting <c>&lt;a href&gt;</c>, <c>&lt;form
/// action&gt;</c>, <c>&lt;iframe&gt;</c>, <c>&lt;img src&gt;</c>,
/// <c>&lt;script src&gt;</c>, <c>&lt;link href&gt;</c>, PWA
/// <c>manifest.json</c>, and sitemap.xml URL sets from a target's HTML
/// surface, then HEAD-probing each discovered URL for status,
/// content-type, and content-length.
///
/// Scope-first: <c>_scope.Require</c> is the first statement of every
/// public entry point, and is re-checked against every same-origin
/// candidate URL and every <c>Location</c> redirect host.
///
/// <para>
/// <b>Robots policy.</b> By default the crawler treats
/// <c>Disallow:</c> paths in <c>/robots.txt</c> as <b>high-signal
/// seeds</b> — operators in an authorized engagement want to know
/// exactly what the site is trying to hide. Pass
/// <c>respectRobots: true</c> (CLI: <c>--respect-robots</c>) to honour
/// disallow rules as crawl boundaries instead. <c>Sitemap:</c> entries
/// in robots.txt are always followed (within scope).
/// </para>
///
/// Body content is NEVER logged; audit records URL + status + content
/// length only.
/// </summary>
public sealed partial class HtmlSitemapCrawler : IReconTool, IDisposable
{
    public string Name => "html-sitemap-crawler";

    public string Description =>
        "GAP-022 HTML+sitemap+robots content-discovery crawler. Fetches /robots.txt and " +
        "/sitemap.xml, parses HTML anchors, forms, iframes, script/img/link src, and PWA " +
        "manifest references, then HEAD-probes each same-origin URL for status, content-type, " +
        "and content-length up to a depth and URL cap. By default Disallow: rules in robots.txt " +
        "are treated as HIGH-SIGNAL seeds (operator pass --respect-robots to honour them as " +
        "boundaries). Same-origin only; Location redirects are scope-revalidated.";

    public const int DefaultDepth = 2;
    public const int DefaultMaxUrls = 500;
    public const int DefaultRatePerSecond = 10;
    public const int DefaultSitemapIndexDepth = 3;
    private const int MaxRobotsBytes = 256 * 1024;
    private const int MaxSitemapBytes = 8 * 1024 * 1024;
    private const string UserAgent = "drederick-crawl/1.0";
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromSeconds(15);

    [GeneratedRegex(@"<a\b[^>]*\bhref\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AnchorRegex();

    [GeneratedRegex(@"<form\b[^>]*\baction\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex(@"<iframe\b[^>]*\bsrc\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IframeRegex();

    [GeneratedRegex(@"<img\b[^>]*\bsrc\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ImgRegex();

    [GeneratedRegex(@"<script\b[^>]*\bsrc\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScriptRegex();

    [GeneratedRegex(@"<link\b[^>]*\bhref\s*=\s*['""]([^'""]+)['""][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LinkRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public HtmlSitemapCrawler(Scope.Scope scope, AuditLog audit, HttpClient? httpClient = null)
    {
        _scope = scope;
        _audit = audit;
        if (httpClient is null)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            };
            _http = new HttpClient(handler) { Timeout = ResponseTimeout };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }

    /// <summary>
    /// Crawl <paramref name="baseUrl"/>: fetch robots.txt, sitemap.xml,
    /// and the base HTML; extract same-origin URLs; HEAD-probe each up
    /// to <paramref name="maxDepth"/> hops and <paramref name="maxUrls"/>
    /// total. Returns a typed <see cref="HtmlSitemapResult"/>.
    /// </summary>
    public async Task<HtmlSitemapResult> CrawlAsync(
        string baseUrl,
        int maxDepth = DefaultDepth,
        int maxUrls = DefaultMaxUrls,
        int ratePerSecond = DefaultRatePerSecond,
        bool respectRobots = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        if (ArgvValidator.ContainsShellMetachars(baseUrl))
            throw new ArgumentException(
                $"Invalid baseUrl '{baseUrl}': contains shell metacharacters.", nameof(baseUrl));
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException(
                $"baseUrl '{baseUrl}' must be an absolute http(s) URL.", nameof(baseUrl));
        }

        _scope.Require(baseUri.Host);

        if (maxDepth < 0) maxDepth = 0;
        if (maxUrls < 1) maxUrls = 1;
        if (ratePerSecond < 1) ratePerSecond = 1;
        if (ratePerSecond > 1000) ratePerSecond = 1000;

        var result = new HtmlSitemapResult();
        var sw = Stopwatch.StartNew();
        _audit.Record("crawl.start", new Dictionary<string, object?>
        {
            ["base"] = baseUri.GetLeftPart(UriPartial.Authority),
            ["max_depth"] = maxDepth,
            ["max_urls"] = maxUrls,
            ["rate_rps"] = ratePerSecond,
            ["respect_robots"] = respectRobots,
        });

        var minIntervalMs = 1000.0 / ratePerSecond;
        var nextSlot = DateTimeOffset.UtcNow;
        async Task ThrottleAsync()
        {
            var now = DateTimeOffset.UtcNow;
            if (now < nextSlot)
            {
                var wait = nextSlot - now;
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
            }
            nextSlot = DateTimeOffset.UtcNow.AddMilliseconds(minIntervalMs);
        }

        try
        {
            // ---- 1. robots.txt ----
            var robotsUri = new Uri(baseUri, "/robots.txt");
            var sitemapSeeds = new List<string>();
            try
            {
                await ThrottleAsync().ConfigureAwait(false);
                var (robotsBody, _, _) = await GetTextAsync(robotsUri, MaxRobotsBytes, ct).ConfigureAwait(false);
                if (robotsBody is not null)
                {
                    ParseRobots(robotsBody, result.RobotsDisallow, result.RobotsAllow, sitemapSeeds);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _audit.Record("crawl.error", new Dictionary<string, object?>
                {
                    ["stage"] = "robots",
                    ["url"] = robotsUri.ToString(),
                    ["message"] = ex.GetType().Name,
                });
            }

            // ---- 2. seed URLs ----
            // De-dup queue of (absoluteUrl, depth, source).
            var queue = new Queue<(Uri Url, int Depth, string Source)>();
            var enqueued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Enqueue(Uri u, int depth, string source)
            {
                if (depth > maxDepth) return;
                if (!IsSameOrigin(baseUri, u)) return;
                // Strip fragment; normalize.
                var clean = StripFragment(u);
                var key = clean.AbsoluteUri;
                if (!enqueued.Add(key)) return;
                queue.Enqueue((clean, depth, source));
            }

            // Always crawl the base.
            Enqueue(baseUri, 0, "base");

            // Robots Disallow paths: by default these are HIGH-SIGNAL seeds.
            // When --respect-robots, they become boundaries (not seeded, and
            // filtered out of later crawls).
            var disallowedPrefixes = new List<string>();
            if (respectRobots)
            {
                disallowedPrefixes.AddRange(result.RobotsDisallow);
            }
            else
            {
                foreach (var path in result.RobotsDisallow)
                {
                    if (string.IsNullOrEmpty(path)) continue;
                    if (Uri.TryCreate(baseUri, path, out var seedUri))
                        Enqueue(seedUri, 1, "robots-disallow");
                }
            }

            // Robots Allow paths are always seeded (intel either way).
            foreach (var path in result.RobotsAllow)
            {
                if (string.IsNullOrEmpty(path)) continue;
                if (Uri.TryCreate(baseUri, path, out var seedUri))
                    Enqueue(seedUri, 1, "robots-allow");
            }

            // ---- 3. sitemap discovery ----
            // Always try /sitemap.xml in addition to robots-declared sitemaps.
            var sitemapsToFetch = new Queue<(Uri Url, int IndexDepth)>();
            sitemapsToFetch.Enqueue((new Uri(baseUri, "/sitemap.xml"), 0));
            foreach (var s in sitemapSeeds)
            {
                if (Uri.TryCreate(s, UriKind.Absolute, out var su) && IsSameOrigin(baseUri, su))
                    sitemapsToFetch.Enqueue((su, 0));
            }

            var visitedSitemaps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (sitemapsToFetch.Count > 0)
            {
                var (smUri, indexDepth) = sitemapsToFetch.Dequeue();
                if (!visitedSitemaps.Add(smUri.AbsoluteUri)) continue;
                if (indexDepth > DefaultSitemapIndexDepth) continue;
                try
                {
                    await ThrottleAsync().ConfigureAwait(false);
                    var (smBody, _, _) = await GetTextAsync(smUri, MaxSitemapBytes, ct).ConfigureAwait(false);
                    if (smBody is null) continue;
                    result.SitemapUrls.Add(smUri.AbsoluteUri);
                    ParseSitemap(smBody, out var locs, out var indexLocs);
                    foreach (var loc in locs)
                    {
                        if (Uri.TryCreate(loc, UriKind.Absolute, out var lu))
                            Enqueue(lu, 1, "sitemap");
                    }
                    foreach (var idx in indexLocs)
                    {
                        if (Uri.TryCreate(idx, UriKind.Absolute, out var iu) && IsSameOrigin(baseUri, iu))
                            sitemapsToFetch.Enqueue((iu, indexDepth + 1));
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (XmlException)
                {
                    _audit.Record("crawl.error", new Dictionary<string, object?>
                    {
                        ["stage"] = "sitemap",
                        ["url"] = smUri.ToString(),
                        ["message"] = "MalformedSitemap",
                    });
                }
                catch (Exception ex)
                {
                    _audit.Record("crawl.error", new Dictionary<string, object?>
                    {
                        ["stage"] = "sitemap",
                        ["url"] = smUri.ToString(),
                        ["message"] = ex.GetType().Name,
                    });
                }
            }

            // ---- 4. fetch base HTML, extract URLs ----
            try
            {
                await ThrottleAsync().ConfigureAwait(false);
                var (html, _, _) = await GetTextAsync(baseUri, 4 * 1024 * 1024, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(html))
                {
                    foreach (var (link, source) in ExtractLinks(html))
                    {
                        if (Uri.TryCreate(baseUri, link, out var abs))
                        {
                            Enqueue(abs, 1, source);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _audit.Record("crawl.error", new Dictionary<string, object?>
                {
                    ["stage"] = "html",
                    ["url"] = baseUri.ToString(),
                    ["message"] = ex.GetType().Name,
                });
            }

            // ---- 5. HEAD-probe each URL ----
            while (queue.Count > 0 && result.CrawledUrls.Count < maxUrls)
            {
                ct.ThrowIfCancellationRequested();
                var (url, depth, source) = queue.Dequeue();

                // Re-validate scope on every URL.
                try { _scope.Require(url.Host); }
                catch (ScopeException) { continue; }

                if (respectRobots && IsDisallowed(url, disallowedPrefixes)) continue;

                await ThrottleAsync().ConfigureAwait(false);
                CrawledUrl entry;
                try
                {
                    entry = await HeadAsync(url, depth, source, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    _audit.Record("crawl.error", new Dictionary<string, object?>
                    {
                        ["stage"] = "head",
                        ["url"] = url.ToString(),
                        ["message"] = ex.GetType().Name,
                    });
                    continue;
                }
                result.CrawledUrls.Add(entry);

                // Recurse on same-origin links found via HTML body of 2xx
                // text/html responses? Per spec we HEAD only, so we do not
                // re-parse the body. Depth-2 expansion happens through the
                // initial HTML + sitemap seed phase.
            }
        }
        catch (OperationCanceledException)
        {
            result.Error = "cancelled";
        }
        finally
        {
            _audit.Record("crawl.finish", new Dictionary<string, object?>
            {
                ["base"] = baseUri.GetLeftPart(UriPartial.Authority),
                ["crawl_count"] = result.CrawledUrls.Count,
                ["sitemap_count"] = result.SitemapUrls.Count,
                ["robots_rule_count"] = result.RobotsDisallow.Count + result.RobotsAllow.Count,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
        }

        return result;
    }

    // ---------- HTTP helpers ----------

    private async Task<(string? Body, string? ContentType, long ContentLength)> GetTextAsync(
        Uri url, int maxBytes, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(ResponseTimeout);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
        if ((int)resp.StatusCode >= 400) return (null, null, 0);
        var ctHeader = resp.Content.Headers.ContentType?.ToString();
        var len = resp.Content.Headers.ContentLength ?? 0;
        await using var s = await resp.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
        var buf = new byte[Math.Min(maxBytes, 64 * 1024)];
        using var ms = new MemoryStream();
        int total = 0;
        int read;
        while ((read = await s.ReadAsync(buf, linked.Token).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > maxBytes) break;
            ms.Write(buf, 0, read);
        }
        return (Encoding.UTF8.GetString(ms.ToArray()), ctHeader, len);
    }

    private async Task<CrawledUrl> HeadAsync(Uri url, int depth, string source, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(ResponseTimeout);
        using var req = new HttpRequestMessage(HttpMethod.Head, url);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);

        int status = (int)resp.StatusCode;
        string? ctHeader = resp.Content.Headers.ContentType?.ToString();
        long len = resp.Content.Headers.ContentLength ?? 0;

        // Inspect Location header for off-scope redirects; the redirect
        // target is NOT auto-followed (handler disables auto-redirect).
        // We surface the status as-is but if the Location host is off
        // scope, do not enqueue it (caller's enqueue already gated, but
        // we double-check here defensively).
        if (resp.Headers.Location is { } loc)
        {
            try
            {
                var locAbs = loc.IsAbsoluteUri ? loc : new Uri(url, loc);
                if (IsSameOrigin(url, locAbs))
                {
                    try { _scope.Require(locAbs.Host); }
                    catch (ScopeException) { /* swallow */ }
                }
                // Off-origin / off-scope redirects are noted by status
                // only; not enqueued.
            }
            catch { /* ignore malformed Location */ }
        }

        _audit.Record("crawl.head", new Dictionary<string, object?>
        {
            ["url"] = url.AbsoluteUri,
            ["status"] = status,
            ["content_type"] = ctHeader,
            ["content_length"] = len,
            ["depth"] = depth,
            ["source"] = source,
        });

        return new CrawledUrl
        {
            Url = url.AbsoluteUri,
            Status = status,
            ContentType = ctHeader,
            ContentLength = len,
            Depth = depth,
            Source = source,
        };
    }

    // ---------- Parsers ----------

    internal static void ParseRobots(
        string body,
        List<string> disallow,
        List<string> allow,
        List<string> sitemaps)
    {
        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var key = line[..colon].Trim().ToLowerInvariant();
            var value = line[(colon + 1)..].Trim();
            if (value.Length == 0) continue;
            switch (key)
            {
                case "disallow": disallow.Add(value); break;
                case "allow": allow.Add(value); break;
                case "sitemap": sitemaps.Add(value); break;
            }
        }
    }

    internal static void ParseSitemap(string xml, out List<string> locs, out List<string> indexLocs)
    {
        locs = new List<string>();
        indexLocs = new List<string>();
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            IgnoreProcessingInstructions = true,
        };
        using var sr = new StringReader(xml);
        using var rdr = XmlReader.Create(sr, settings);
        // Track whether we're inside a <sitemap> (index) or <url> (urlset).
        var stack = new Stack<string>();
        while (rdr.Read())
        {
            if (rdr.NodeType == XmlNodeType.Element)
            {
                stack.Push(rdr.LocalName);
                if (rdr.IsEmptyElement) stack.Pop();
            }
            else if (rdr.NodeType == XmlNodeType.EndElement)
            {
                if (stack.Count > 0) stack.Pop();
            }
            else if (rdr.NodeType == XmlNodeType.Text)
            {
                if (stack.Count >= 2 && stack.Peek() == "loc")
                {
                    var parents = stack.ToArray(); // top-of-stack first
                    var parent = parents.Length >= 2 ? parents[1] : "";
                    var value = rdr.Value.Trim();
                    if (string.Equals(parent, "url", StringComparison.OrdinalIgnoreCase))
                        locs.Add(value);
                    else if (string.Equals(parent, "sitemap", StringComparison.OrdinalIgnoreCase))
                        indexLocs.Add(value);
                }
            }
        }
    }

    internal static IEnumerable<(string Url, string Source)> ExtractLinks(string html)
    {
        if (string.IsNullOrEmpty(html)) yield break;
        foreach (Match m in AnchorRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "html-anchor");
        foreach (Match m in FormActionRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "form-action");
        foreach (Match m in IframeRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "iframe");
        foreach (Match m in ImgRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "img-src");
        foreach (Match m in ScriptRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "script-src");
        foreach (Match m in LinkRegex().Matches(html))
            yield return (WebUtility.HtmlDecode(m.Groups[1].Value), "link-href");
    }

    // ---------- Origin / robots helpers ----------

    internal static bool IsSameOrigin(Uri a, Uri b)
    {
        if (!string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)) return false;
        return a.Port == b.Port;
    }

    internal static Uri StripFragment(Uri u)
    {
        if (string.IsNullOrEmpty(u.Fragment)) return u;
        var b = new UriBuilder(u) { Fragment = "" };
        return b.Uri;
    }

    internal static bool IsDisallowed(Uri url, List<string> disallowedPrefixes)
    {
        var path = url.AbsolutePath;
        foreach (var p in disallowedPrefixes)
        {
            if (string.IsNullOrEmpty(p)) continue;
            if (p == "/") return true;
            if (path.StartsWith(p, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}

/// <summary>GAP-022 result shape.</summary>
public sealed class HtmlSitemapResult
{
    [System.Text.Json.Serialization.JsonPropertyName("robots_disallow_paths")]
    public List<string> RobotsDisallow { get; set; } = new();
    [System.Text.Json.Serialization.JsonPropertyName("robots_allow_paths")]
    public List<string> RobotsAllow { get; set; } = new();
    [System.Text.Json.Serialization.JsonPropertyName("sitemap_urls")]
    public List<string> SitemapUrls { get; set; } = new();
    [System.Text.Json.Serialization.JsonPropertyName("crawled_urls")]
    public List<CrawledUrl> CrawledUrls { get; set; } = new();
    [System.Text.Json.Serialization.JsonPropertyName("error")]
    public string? Error { get; set; }
}

public sealed class CrawledUrl
{
    [System.Text.Json.Serialization.JsonPropertyName("url")]
    public string Url { get; set; } = "";
    [System.Text.Json.Serialization.JsonPropertyName("status")]
    public int Status { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("content_type")]
    public string? ContentType { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("content_length")]
    public long ContentLength { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("depth")]
    public int Depth { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("source")]
    public string Source { get; set; } = "";
}
// --- end htb-content-discovery-crawl ---
