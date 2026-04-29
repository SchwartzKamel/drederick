using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Pure C# HttpClient-based HTTP header fuzzing tool. Probes for HTTP-layer
/// header attacks: request smuggling (CL.TE, TE.CL, TE.TE), Host header
/// injection, CRLF injection, and cache poisoning. All probes are DETECTION-
/// ONLY — timing-based or reflection-based markers, no actual exploitation.
/// </summary>
public sealed class HeaderFuzzTool : IFuzzTool, IDisposable
{
    public string Name => "header-fuzz";

    public string Description =>
        "Probes for HTTP header attacks: request smuggling (timing-based), " +
        "Host header injection, CRLF injection, and cache poisoning markers. " +
        "Pure C# HttpClient-based, DETECTION-ONLY.";

    public FuzzCategory Category => FuzzCategory.Web;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly HeaderFuzzCanary _canary;

    public HeaderFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        HttpClient? httpClient = null,
        HeaderFuzzCanary? canary = null)
    {
        _scope = scope;
        _audit = audit;

        if (httpClient is null)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+fuzz-header)");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }

        _canary = canary ?? HeaderFuzzCanary.GenerateRandom();
    }

    public async Task<HeaderFuzzResult> ProbeAsync(
        string baseUrl,
        HeaderFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        }
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"baseUrl '{baseUrl}' is not an absolute URL.", nameof(baseUrl));
        }
        if (uri.Scheme != "http" && uri.Scheme != "https")
        {
            throw new ArgumentException($"baseUrl must be http or https, got {uri.Scheme}", nameof(baseUrl));
        }

        // Scope gate on the host (first statement)
        _scope.Require(uri.Host);

        var opts = options ?? new HeaderFuzzOptions();
        var findings = new List<HeaderFinding>();
        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        _audit.Record("header-fuzz.start", new Dictionary<string, object?>
        {
            ["url"] = baseUrl,
            ["probes_enabled"] = new
            {
                smuggling = opts.ProbeSmuggling,
                host_injection = opts.ProbeHostInjection,
                crlf = opts.ProbeCrlf,
                cache_poisoning = opts.ProbeCachePoisoning,
            },
        });

        try
        {
            // Rate limiter: simple token bucket via delay
            var delayMs = opts.RateLimitRps > 0 ? 1000 / opts.RateLimitRps : 0;

            if (opts.ProbeSmuggling)
            {
                var smugglingFindings = await ProbeSmuggling(uri, opts.SmuggleSamples, delayMs, ct);
                findings.AddRange(smugglingFindings);
            }

            if (opts.ProbeHostInjection)
            {
                var hostFindings = await ProbeHostInjection(uri, delayMs, ct);
                findings.AddRange(hostFindings);
            }

            if (opts.ProbeCrlf)
            {
                var crlfFindings = await ProbeCrlfInjection(uri, delayMs, ct);
                findings.AddRange(crlfFindings);
            }

            if (opts.ProbeCachePoisoning)
            {
                var cacheFindings = await ProbeCachePoisoning(uri, delayMs, ct);
                findings.AddRange(cacheFindings);
            }

            sw.Stop();
            _audit.Record("header-fuzz.finish", new Dictionary<string, object?>
            {
                ["finding_count"] = findings.Count,
                ["duration_ms"] = sw.ElapsedMilliseconds,
            });

            return new HeaderFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = sw.Elapsed,
                Findings = findings,
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            _audit.Record("header-fuzz.finish", new Dictionary<string, object?>
            {
                ["finding_count"] = findings.Count,
                ["duration_ms"] = sw.ElapsedMilliseconds,
                ["error"] = ex.Message,
            });

            return new HeaderFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = sw.Elapsed,
                Findings = findings,
                Error = ex.Message,
            };
        }
    }

    private async Task<List<HeaderFinding>> ProbeSmuggling(
        Uri uri,
        int samples,
        int delayMs,
        CancellationToken ct)
    {
        var findings = new List<HeaderFinding>();

        // Baseline RTT measurements (samples GETs)
        var baselines = new List<long>();
        for (int i = 0; i < samples; i++)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            var sw = Stopwatch.StartNew();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch
            {
                // ignore baseline failures
            }
            sw.Stop();
            baselines.Add(sw.ElapsedMilliseconds);
        }

        if (baselines.Count == 0 || baselines.All(b => b == 0))
        {
            return findings; // Cannot measure baseline
        }

        var baselineMedian = baselines.OrderBy(x => x).ElementAt(baselines.Count / 2);

        // CL.TE probe: send request with conflicting Content-Length and Transfer-Encoding
        // This is a DETECTION-ONLY probe (timing-based)
        var clTeTimings = new List<long>();
        for (int i = 0; i < samples; i++)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            var sw = Stopwatch.StartNew();
            try
            {
                // We use SocketsHttpHandler to craft low-level request
                // But HttpClient abstracts this, so we'll use a custom approach
                // For now, we'll send a POST with both headers and measure timing
                using var req = new HttpRequestMessage(HttpMethod.Post, uri);

                // Try to set conflicting headers (HttpClient may sanitize these)
                // We'll set Content-Length and Transfer-Encoding
                req.Content = new StringContent("0\r\n\r\nGET /404 HTTP/1.1\r\nHost: localhost\r\n\r\n");

                // Manually try to add Transfer-Encoding (HttpClient will handle chunked automatically)
                // This is a simplified probe - in real smuggling, we'd need raw socket control
                req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");
                req.Content.Headers.ContentLength = 4; // Conflicting with actual body

                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch
            {
                // ignore probe failures
            }
            sw.Stop();
            clTeTimings.Add(sw.ElapsedMilliseconds);
        }

        if (clTeTimings.Count > 0 && clTeTimings.Any(t => t > 0))
        {
            var smuggleMedian = clTeTimings.OrderBy(x => x).ElementAt(clTeTimings.Count / 2);
            // Threshold: 5x baseline AND at least 1000ms
            if (smuggleMedian > baselineMedian * 5 && smuggleMedian > 1000)
            {
                findings.Add(new HeaderFinding(
                    HeaderIssue.RequestSmuggling,
                    "Content-Length + Transfer-Encoding",
                    $"Timing delta detected: baseline {baselineMedian}ms, probe {smuggleMedian}ms (ratio {smuggleMedian / (double)baselineMedian:F2}x)"));
            }
        }

        // TE.CL probe (reverse)
        var teClTimings = new List<long>();
        for (int i = 0; i < samples; i++)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            var sw = Stopwatch.StartNew();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, uri);
                req.Content = new StringContent("GPOST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n0\r\n\r\n");
                req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");

                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch
            {
                // ignore
            }
            sw.Stop();
            teClTimings.Add(sw.ElapsedMilliseconds);
        }

        if (teClTimings.Count > 0 && teClTimings.Any(t => t > 0))
        {
            var smuggleMedian = teClTimings.OrderBy(x => x).ElementAt(teClTimings.Count / 2);
            if (smuggleMedian > baselineMedian * 5 && smuggleMedian > 1000)
            {
                findings.Add(new HeaderFinding(
                    HeaderIssue.RequestSmuggling,
                    "Transfer-Encoding + Content-Length",
                    $"TE.CL timing delta detected: baseline {baselineMedian}ms, probe {smuggleMedian}ms (ratio {smuggleMedian / (double)baselineMedian:F2}x)"));
            }
        }

        // TE.TE obfuscation probe
        var teTeTimings = new List<long>();
        for (int i = 0; i < samples; i++)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            var sw = Stopwatch.StartNew();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, uri);
                req.Content = new StringContent("0\r\n\r\n");
                req.Headers.TryAddWithoutValidation("Transfer-Encoding", "xchunked"); // obfuscated
                req.Content.Headers.ContentLength = 4;

                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch
            {
                // ignore
            }
            sw.Stop();
            teTeTimings.Add(sw.ElapsedMilliseconds);
        }

        if (teTeTimings.Count > 0 && teTeTimings.Any(t => t > 0))
        {
            var smuggleMedian = teTeTimings.OrderBy(x => x).ElementAt(teTeTimings.Count / 2);
            if (smuggleMedian > baselineMedian * 5 && smuggleMedian > 1000)
            {
                findings.Add(new HeaderFinding(
                    HeaderIssue.RequestSmuggling,
                    "Transfer-Encoding obfuscation",
                    $"TE.TE timing delta detected: baseline {baselineMedian}ms, probe {smuggleMedian}ms (ratio {smuggleMedian / (double)baselineMedian:F2}x)"));
            }
        }

        return findings;
    }

    private async Task<List<HeaderFinding>> ProbeHostInjection(
        Uri uri,
        int delayMs,
        CancellationToken ct)
    {
        var findings = new List<HeaderFinding>();

        var hostHeaders = new[]
        {
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "Forwarded",
        };

        foreach (var header in hostHeaders)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);

                if (header == "Forwarded")
                {
                    req.Headers.TryAddWithoutValidation(header, $"host={_canary.Hostname}");
                }
                else
                {
                    req.Headers.TryAddWithoutValidation(header, _canary.Hostname);
                }

                using var resp = await _http.SendAsync(req, ct);

                // Check response body for canary reflection
                var body = await resp.Content.ReadAsStringAsync(ct);
                if (body.Contains(_canary.Hostname, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new HeaderFinding(
                        HeaderIssue.HostHeaderInjection,
                        header,
                        $"Canary '{_canary.Hostname}' reflected in response body"));
                }

                // Check response headers (Location, Set-Cookie, Link, etc.)
                if (resp.Headers.Location?.ToString().Contains(_canary.Hostname, StringComparison.OrdinalIgnoreCase) == true)
                {
                    findings.Add(new HeaderFinding(
                        HeaderIssue.HostHeaderInjection,
                        header,
                        $"Canary '{_canary.Hostname}' reflected in Location header: {resp.Headers.Location}"));
                }

                if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        if (cookie.Contains(_canary.Hostname, StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(new HeaderFinding(
                                HeaderIssue.HostHeaderInjection,
                                header,
                                $"Canary '{_canary.Hostname}' reflected in Set-Cookie header"));
                            break;
                        }
                    }
                }

                if (resp.Headers.TryGetValues("Link", out var links))
                {
                    foreach (var link in links)
                    {
                        if (link.Contains(_canary.Hostname, StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(new HeaderFinding(
                                HeaderIssue.HostHeaderInjection,
                                header,
                                $"Canary '{_canary.Hostname}' reflected in Link header"));
                            break;
                        }
                    }
                }
            }
            catch
            {
                // ignore failures
            }
        }

        return findings;
    }

    private async Task<List<HeaderFinding>> ProbeCrlfInjection(
        Uri uri,
        int delayMs,
        CancellationToken ct)
    {
        var findings = new List<HeaderFinding>();

        // Headers to test for CRLF injection
        var testHeaders = new[]
        {
            "User-Agent",
            "Referer",
            "Cookie",
        };

        var injectedHeaderName = _canary.MarkerHeader;
        var injectedHeaderValue = _canary.MarkerValue;

        foreach (var header in testHeaders)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            try
            {
                // Try to inject a header via CRLF
                // Note: HttpClient may sanitize these, so we use TryAddWithoutValidation
                var crlfPayload = $"normal-value\r\n{injectedHeaderName}: {injectedHeaderValue}";

                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                req.Headers.TryAddWithoutValidation(header, crlfPayload);

                using var resp = await _http.SendAsync(req, ct);

                // Check if our injected header appears in the response
                var body = await resp.Content.ReadAsStringAsync(ct);

                // Look for the injected header in response body or echoed headers
                if (body.Contains(injectedHeaderName, StringComparison.OrdinalIgnoreCase) &&
                    body.Contains(injectedHeaderValue, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new HeaderFinding(
                        HeaderIssue.CrlfInjection,
                        header,
                        $"CRLF injection successful: injected header '{injectedHeaderName}' with value '{injectedHeaderValue}' reflected in response"));
                }

                // Also check if server echoes the injected header in response headers
                if (resp.Headers.TryGetValues(injectedHeaderName, out var values))
                {
                    if (values.Any(v => v.Contains(injectedHeaderValue, StringComparison.OrdinalIgnoreCase)))
                    {
                        findings.Add(new HeaderFinding(
                            HeaderIssue.CrlfInjection,
                            header,
                            $"CRLF injection successful: injected response header '{injectedHeaderName}: {injectedHeaderValue}'"));
                    }
                }
            }
            catch
            {
                // ignore failures
            }
        }

        return findings;
    }

    private async Task<List<HeaderFinding>> ProbeCachePoisoning(
        Uri uri,
        int delayMs,
        CancellationToken ct)
    {
        var findings = new List<HeaderFinding>();

        // Headers that might affect cache keys
        var cacheHeaders = new Dictionary<string, string>
        {
            ["X-Forwarded-Scheme"] = "https",
            ["X-Forwarded-Proto"] = "https",
            ["X-Original-URL"] = "/admin",
            ["X-Rewrite-URL"] = "/admin",
        };

        // First, get a baseline response
        HttpResponseMessage? baselineResp = null;
        string? baselineBody = null;
        long baselineSize = 0;

        try
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            baselineResp = await _http.SendAsync(req, ct);
            baselineBody = await baselineResp.Content.ReadAsStringAsync(ct);
            baselineSize = baselineBody.Length;
        }
        catch
        {
            // Cannot establish baseline
            return findings;
        }

        // Now test each cache-related header
        foreach (var (header, value) in cacheHeaders)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                req.Headers.TryAddWithoutValidation(header, value);

                using var resp = await _http.SendAsync(req, ct);
                var body = await resp.Content.ReadAsStringAsync(ct);
                var size = body.Length;

                // Check for cache-related headers in response
                var hasCacheHeader = resp.Headers.TryGetValues("Age", out _) ||
                                   resp.Headers.TryGetValues("X-Cache", out _) ||
                                   resp.Headers.TryGetValues("CF-Cache-Status", out _) ||
                                   resp.Headers.TryGetValues("X-Cache-Status", out _);

                // If response diverges significantly AND cache headers present, flag it
                var sizeDelta = Math.Abs(size - baselineSize);
                var statusDivergent = resp.StatusCode != baselineResp.StatusCode;

                if (hasCacheHeader && (sizeDelta > 0 || statusDivergent))
                {
                    findings.Add(new HeaderFinding(
                        HeaderIssue.CachePoisoning,
                        header,
                        $"Cache key confusion detected: header '{header}: {value}' caused divergent cached response " +
                        $"(status {resp.StatusCode} vs baseline {baselineResp.StatusCode}, size {size} vs {baselineSize})"));
                }
            }
            catch
            {
                // ignore failures
            }
        }

        baselineResp?.Dispose();

        return findings;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}

/// <summary>
/// Canary values for header fuzzing detection. Each tool instance generates
/// a random marker by default to avoid cross-contamination.
/// </summary>
public sealed class HeaderFuzzCanary
{
    public string Hostname { get; init; } = "drederick-canary.example";
    public string MarkerHeader { get; init; } = "X-Drederick-Probe";
    public string MarkerValue { get; init; } = "";

    public static HeaderFuzzCanary GenerateRandom()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(16);
        var hex = Convert.ToHexString(randomBytes).ToLowerInvariant();

        return new HeaderFuzzCanary
        {
            Hostname = $"{hex}.drederick-canary.example",
            MarkerHeader = "X-Drederick-Probe",
            MarkerValue = hex,
        };
    }
}

/// <summary>
/// Options for header fuzzing probes.
/// </summary>
public sealed class HeaderFuzzOptions
{
    public bool ProbeSmuggling { get; init; } = true;
    public bool ProbeHostInjection { get; init; } = true;
    public bool ProbeCrlf { get; init; } = true;
    public bool ProbeCachePoisoning { get; init; } = true;
    public int RateLimitRps { get; init; } = 10;
    public int SmuggleSamples { get; init; } = 3;
}
