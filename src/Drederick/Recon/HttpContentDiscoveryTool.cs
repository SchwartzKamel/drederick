using System.Diagnostics;
using System.Net.Http;
using System.Security.Authentication;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Path-only HTTP content discovery. For each word in a bounded, sanitized
/// wordlist, GETs <c>&lt;baseUrl&gt;/&lt;word&gt;</c> and records the response
/// status and size when the status is in a small set of "interesting" codes
/// (skipping 404s). Strictly path-only — NO query parameter fuzzing, NO POST
/// bodies, NO header injection, NO auth probing. Off-by-default behavior is
/// enforced at the CLI layer; this tool just performs the probe when invoked.
/// </summary>
public sealed class HttpContentDiscoveryTool : IReconTool, IDisposable
{
    public string Name => "http-content-discovery";

    public string Description =>
        "GET a bounded list of common paths under a base URL and return the statuses and sizes " +
        "for interesting responses (200/201/204/301/302/307/401/403). Path-only, rate limited, " +
        "no parameter or credential brute-forcing.";

    /// <summary>
    /// Statuses considered "interesting" enough to record. 404 is intentionally
    /// omitted so noisy output stays clean.
    /// </summary>
    private static readonly HashSet<int> InterestingStatuses = new()
    {
        200, 201, 204, 301, 302, 307, 401, 403,
    };

    /// <summary>Safety valve — never probe more than this many paths regardless of input size.</summary>
    public const int MaxWordlistEntries = 2000;

    /// <summary>
    /// Hand-curated default wordlist (~100 highest-signal paths). Operators can
    /// override by passing their own <c>wordlist</c> to the constructor.
    /// All entries here are guaranteed to pass <see cref="IsSafePath"/>.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultWordlist = new[]
    {
        "robots.txt", "sitemap.xml", "humans.txt", "favicon.ico", "crossdomain.xml",
        "security.txt", ".well-known/security.txt", ".well-known/change-password",
        "admin", "admin/", "administrator", "administrator/", "admin.php", "admin.html",
        "admin/login", "admin/index.php", "wp-admin", "wp-admin/", "wp-login.php",
        "wp-config.php", "wp-content", "wp-content/", "wp-includes", "wp-json",
        "login", "login.php", "login.html", "signin", "signup", "register",
        "logout", "dashboard", "account", "profile", "users", "user",
        "api", "api/", "api/v1", "api/v2", "api/v1/users", "api/users",
        "graphql", "swagger", "swagger-ui", "swagger.json", "openapi.json",
        "docs", "documentation", "redoc",
        "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
        "phpmyadmin", "phpmyadmin/", "pma", "adminer.php", "adminer",
        ".git", ".git/", ".git/HEAD", ".git/config", ".git/index",
        ".svn", ".svn/entries", ".hg", ".bzr", ".env", ".env.local",
        ".env.production", ".env.development", ".htaccess", ".htpasswd",
        ".DS_Store", "Thumbs.db", "web.config", "composer.json", "composer.lock",
        "package.json", "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock",
        "backup", "backup/", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
        "dump.sql", "database.sql", "old", "old/", "new", "new/", "tmp", "tmp/",
        "temp", "temp/", "test", "test/", "tests", "dev", "staging",
        "server-status", "server-info", "status", "health", "healthz", "ping",
        "metrics", "debug", "console", "actuator", "actuator/health", "actuator/env",
        "config", "config.php", "config.json", "config.yml", "settings",
        "uploads", "uploads/", "files", "files/", "images", "img", "static",
        "assets", "public", "private", "hidden",
        "cgi-bin", "cgi-bin/", "cgi-bin/test.cgi",
        "manager/html", "host-manager/html", "jmx-console", "web-console",
        "_vti_bin", "_vti_pvt", "solr", "solr/admin",
        "robots", "LICENSE", "README", "README.md", "CHANGELOG", "CHANGELOG.md",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly IReadOnlyList<string> _wordlist;
    private readonly int _rateLimitRps;

    public HttpContentDiscoveryTool(
        Scope.Scope scope,
        AuditLog audit,
        HttpClient? httpClient = null,
        IEnumerable<string>? wordlist = null,
        int rateLimitRps = 10)
    {
        _scope = scope;
        _audit = audit;

        if (rateLimitRps <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(rateLimitRps), rateLimitRps, "rateLimitRps must be positive.");
        }
        _rateLimitRps = rateLimitRps;

        if (httpClient is null)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }

        var source = wordlist ?? DefaultWordlist;
        _wordlist = SanitizeAndCap(source);
    }

    /// <summary>
    /// Returns true if <paramref name="path"/> contains only URL-safe path
    /// characters: alphanumerics, <c>-</c>, <c>_</c>, <c>.</c>, <c>/</c>, and
    /// the single allowed percent escape <c>%2F</c> (case-insensitive). Any
    /// other character — including <c>&lt; &gt; ? &amp; = ;</c>, whitespace,
    /// newlines, or stray <c>%</c> — causes rejection.
    /// </summary>
    public static bool IsSafePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        for (int i = 0; i < path.Length; i++)
        {
            char c = path[i];
            if (c == '%')
            {
                if (i + 2 >= path.Length) return false;
                char a = path[i + 1];
                char b = path[i + 2];
                bool is2F = (a == '2') && (b == 'F' || b == 'f');
                if (!is2F) return false;
                i += 2;
                continue;
            }
            bool ok = (c >= 'a' && c <= 'z')
                   || (c >= 'A' && c <= 'Z')
                   || (c >= '0' && c <= '9')
                   || c == '-' || c == '_' || c == '.' || c == '/';
            if (!ok) return false;
        }
        return true;
    }

    internal static IReadOnlyList<string> SanitizeAndCap(IEnumerable<string> source)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var kept = new List<string>();
        foreach (var raw in source)
        {
            if (raw is null) continue;
            var trimmed = raw.Trim().TrimStart('/');
            if (trimmed.Length == 0) continue;
            if (!IsSafePath(trimmed)) continue;
            if (!seen.Add(trimmed)) continue;
            kept.Add(trimmed);
            if (kept.Count >= MaxWordlistEntries) break;
        }
        return kept;
    }

    /// <summary>The effective, sanitized, capped wordlist in use.</summary>
    public IReadOnlyList<string> EffectiveWordlist => _wordlist;

    public async Task<HttpContentDiscoveryResult> ProbeAsync(
        string baseUrl,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        }
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            throw new ArgumentException($"baseUrl '{baseUrl}' is not an absolute URL.", nameof(baseUrl));
        }

        // Scope gate on the host. Scope only understands IP literals, which is
        // exactly what we want here — a hostname cannot be meaningfully
        // scope-checked in advance, and HTTP content discovery must land on an
        // authorized IP.
        var host = baseUri.Host;
        _scope.Require(host);

        var normalizedBase = baseUri.GetLeftPart(UriPartial.Authority);

        _audit.Record("http-content-discovery.start", new Dictionary<string, object?>
        {
            ["base_url"] = normalizedBase,
            ["word_count"] = _wordlist.Count,
            ["rate_limit_rps"] = _rateLimitRps,
        });

        var result = new HttpContentDiscoveryResult { BaseUrl = normalizedBase };

        var minIntervalTicks = Stopwatch.Frequency / _rateLimitRps;
        long nextAllowedTick = Stopwatch.GetTimestamp();

        foreach (var word in _wordlist)
        {
            ct.ThrowIfCancellationRequested();

            // Leaky-bucket style pacing: wait until the next slot opens.
            var now = Stopwatch.GetTimestamp();
            if (now < nextAllowedTick)
            {
                var deltaMs = (long)((nextAllowedTick - now) * 1000.0 / Stopwatch.Frequency);
                if (deltaMs > 0)
                {
                    await Task.Delay((int)deltaMs, ct).ConfigureAwait(false);
                }
            }
            nextAllowedTick = Stopwatch.GetTimestamp() + minIntervalTicks;

            var url = normalizedBase + "/" + word;
            var entry = new HttpContentDiscoveryEntry { Path = "/" + word };

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                reqCts.CancelAfter(TimeSpan.FromSeconds(5));
                using var resp = await _http.SendAsync(
                    req, HttpCompletionOption.ResponseHeadersRead, reqCts.Token).ConfigureAwait(false);

                int status = (int)resp.StatusCode;
                if (!InterestingStatuses.Contains(status))
                {
                    continue;
                }

                long size;
                if (resp.Content.Headers.ContentLength.HasValue)
                {
                    size = resp.Content.Headers.ContentLength.Value;
                }
                else
                {
                    var bytes = await resp.Content.ReadAsByteArrayAsync(reqCts.Token)
                        .ConfigureAwait(false);
                    size = bytes.LongLength;
                }

                entry.Status = status;
                entry.Size = size;
                result.Entries.Add(entry);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _audit.Record("http-content-discovery.error", new Dictionary<string, object?>
                {
                    ["base_url"] = normalizedBase,
                    ["path"] = entry.Path,
                    ["error"] = ex.Message,
                });
                // Per-path failures do not abort the probe.
                continue;
            }
        }

        _audit.Record("http-content-discovery.finish", new Dictionary<string, object?>
        {
            ["base_url"] = normalizedBase,
            ["entries_recorded"] = result.Entries.Count,
            ["word_count"] = _wordlist.Count,
        });

        return result;
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }
}
