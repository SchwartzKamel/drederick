using System.Diagnostics;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using Drederick.Audit;
using Drederick.Recon.Http;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Path-only HTTP content discovery with SPA catch-all baseline detection,
/// optional wordlist profile selection (raft-small/medium/large from
/// SecLists), and optional extension fanout. For each word in a bounded,
/// sanitized wordlist GETs &lt;baseUrl&gt;/&lt;word&gt; and records status +
/// size + body sha256 (for 200s). Strictly path-only — NO query parameter
/// fuzzing, NO POST bodies, NO header injection, NO auth probing.
/// Closes GAP-055 (SPA catch-all detection) and provides the
/// <see cref="HttpContentDiscoveryAutoRouter"/> helper for GAP-057
/// (vhost-detection auto-routing).
/// </summary>
public sealed class HttpContentDiscoveryTool : IReconTool, IDisposable
{
    public string Name => "http-content-discovery";

    public string Description =>
        "GET a bounded list of common paths under a base URL and return the statuses and sizes " +
        "for interesting responses (200/201/204/301/302/307/401/403). Detects SPA catch-all 200s " +
        "via baseline-sha256 comparison. Path-only, rate limited, no parameter or credential brute-forcing.";

    private static readonly HashSet<int> InterestingStatuses = new()
    {
        200, 201, 204, 301, 302, 307, 401, 403,
    };

    public const int MaxWordlistEntries = 2000;

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
        "config.php", "configuration.php", "settings.php", "config.json", "config.yaml",
        "backup", "backup/", "backups", "backup.sql", "dump.sql", "db.sql",
        "uploads", "uploads/", "files", "files/", "media", "media/", "static", "static/",
        "tmp", "tmp/", "temp", "temp/", "cache", "cache/",
        "test", "tests", "testing", "dev", "development", "staging",
        "old", "new", "v1", "v2", "v3",
        "console", "manager", "manager/html", "actuator", "actuator/health", "actuator/env",
        "metrics", "health", "status", "ping", "version",
        "server-status", "server-info", "server-status/",
    };

    public static readonly IReadOnlyList<string> KnownProfiles = new[]
    {
        "default", "raft-small", "raft-medium", "raft-large",
    };

    private static readonly IReadOnlyList<string> SeclistsSearchDirs = new[]
    {
        "/usr/share/seclists/Discovery/Web-Content/",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly IReadOnlyList<string> _wordlist;
    private readonly IReadOnlyList<string> _extensions;
    private readonly string _profileName;
    private readonly int _rateLimitRps;
    // --- htb-socks-proxy-scanning ---
    // GAP-049: optional pivot proxy + audit hook. Wired into the
    // self-owned HttpClient's handler when caller didn't pass one.
    private readonly Drederick.Ops.SocksProxyConfig? _socksConfig;
    private readonly Drederick.Ops.SocksProxyResolver? _socksResolver;
    /// <summary>GAP-049 — per-dispatch breadcrumb. Callers invoke this
    /// from the top of public discovery methods so the audit log
    /// reflects which dispatches routed through the pivot.</summary>
    public void RecordProxyApplied()
        => _socksResolver?.RecordApplied("http-content-discovery", _socksConfig);
    // --- end htb-socks-proxy-scanning ---

    public HttpContentDiscoveryTool(
        Scope.Scope scope,
        AuditLog audit,
        HttpClient? httpClient = null,
        IEnumerable<string>? wordlist = null,
        int rateLimitRps = 10,
        IEnumerable<string>? extensions = null,
        string? wordlistProfile = null,
        // --- htb-socks-proxy-scanning ---
        Drederick.Ops.SocksProxyConfig? socksConfig = null,
        Drederick.Ops.SocksProxyResolver? socksResolver = null
        // --- end htb-socks-proxy-scanning ---
        )
    {
        _scope = scope;
        _audit = audit;

        if (rateLimitRps <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(rateLimitRps), rateLimitRps, "rateLimitRps must be positive.");
        }
        _rateLimitRps = rateLimitRps;
        // --- htb-socks-proxy-scanning ---
        _socksConfig = socksConfig;
        _socksResolver = socksResolver;
        // --- end htb-socks-proxy-scanning ---

        if (httpClient is null)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            // --- htb-socks-proxy-scanning ---
            if (_socksConfig is not null)
            {
                var webProxy = new System.Net.WebProxy(new Uri(_socksConfig.ToRedactedUri()));
                if (!string.IsNullOrEmpty(_socksConfig.Username))
                {
                    webProxy.Credentials = new System.Net.NetworkCredential(
                        _socksConfig.Username, _socksConfig.Password ?? string.Empty);
                }
                handler.Proxy = webProxy;
                handler.UseProxy = true;
            }
            // --- end htb-socks-proxy-scanning ---
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }

        _extensions = NormalizeExtensions(extensions);

        IEnumerable<string> source;
        if (wordlist is not null)
        {
            source = wordlist;
            _profileName = wordlistProfile ?? "custom";
        }
        else if (!string.IsNullOrWhiteSpace(wordlistProfile))
        {
            _profileName = wordlistProfile.Trim().ToLowerInvariant();
            source = ResolveWordlistProfile(_profileName, _audit);
        }
        else
        {
            source = DefaultWordlist;
            _profileName = "default";
        }

        var expanded = ExpandExtensions(source, _extensions);
        _wordlist = SanitizeAndCap(expanded);
    }

    public IReadOnlyList<string> EffectiveExtensions => _extensions;
    public string WordlistProfile => _profileName;

    private static IReadOnlyList<string> NormalizeExtensions(IEnumerable<string>? extensions)
    {
        if (extensions is null) return Array.Empty<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var kept = new List<string>();
        foreach (var raw in extensions)
        {
            if (raw is null) continue;
            var ext = raw.Trim().TrimStart('.');
            if (ext.Length == 0) continue;
            bool ok = true;
            foreach (var c in ext)
            {
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
                { ok = false; break; }
            }
            if (!ok) continue;
            if (!seen.Add(ext)) continue;
            kept.Add(ext);
        }
        return kept;
    }

    internal static IEnumerable<string> ExpandExtensions(
        IEnumerable<string> words,
        IReadOnlyList<string> extensions)
    {
        foreach (var w in words)
        {
            if (w is null) continue;
            yield return w;
            if (extensions.Count == 0) continue;
            var trimmed = w.TrimEnd();
            if (trimmed.EndsWith('/')) continue;
            foreach (var ext in extensions)
            {
                yield return trimmed + "." + ext;
            }
        }
    }

    public static IEnumerable<string> ResolveWordlistProfile(string name, AuditLog? audit = null)
    {
        var profile = (name ?? "default").Trim().ToLowerInvariant();
        if (profile == "default" || profile.Length == 0)
        {
            return DefaultWordlist;
        }
        if (profile is "raft-small" or "raft-medium" or "raft-large")
        {
            var fileName = profile + "-words.txt";
            foreach (var dir in SeclistsSearchDirs)
            {
                string path;
                try { path = Path.Combine(dir, fileName); }
                catch { continue; }
                if (File.Exists(path))
                {
                    try
                    {
                        var lines = File.ReadAllLines(path);
                        audit?.Record("http-content-discovery.wordlist_profile.loaded",
                            new Dictionary<string, object?>
                            {
                                ["profile"] = profile,
                                ["path"] = path,
                                ["lines"] = lines.Length,
                            });
                        return lines;
                    }
                    catch (Exception ex)
                    {
                        audit?.Record("http-content-discovery.wordlist_profile.read_error",
                            new Dictionary<string, object?>
                            {
                                ["profile"] = profile,
                                ["path"] = path,
                                ["error"] = ex.Message,
                            });
                    }
                }
            }
            audit?.Record("http-content-discovery.wordlist_profile.fallback",
                new Dictionary<string, object?>
                {
                    ["profile"] = profile,
                    ["reason"] = "seclists_not_found",
                    ["fallback"] = "default",
                });
            return DefaultWordlist;
        }
        audit?.Record("http-content-discovery.wordlist_profile.unknown",
            new Dictionary<string, object?>
            {
                ["profile"] = profile,
                ["fallback"] = "default",
            });
        return DefaultWordlist;
    }

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

        var host = baseUri.Host;
        _scope.Require(host);

        var normalizedBase = baseUri.GetLeftPart(UriPartial.Authority);

        _audit.Record("http-content-discovery.start", new Dictionary<string, object?>
        {
            ["base_url"] = normalizedBase,
            ["word_count"] = _wordlist.Count,
            ["rate_limit_rps"] = _rateLimitRps,
            ["profile"] = _profileName,
            ["extensions"] = _extensions,
        });

        var result = new HttpContentDiscoveryResult { BaseUrl = normalizedBase };

        // --- htb-spa-catchall-detection ---
        // GAP-055: delegate SPA catch-all baseline probing to
        // SpaCatchAllDetector (two randomized 404-bait requests +
        // SHA / length / structural-marker fusion).
        SpaBaseline? spaBaseline = null;
        try
        {
            var detector = new SpaCatchAllDetector(_scope, _audit);
            spaBaseline = await detector.ProbeAsync(normalizedBase, _http, ct).ConfigureAwait(false);
            result.BaselineStatus = spaBaseline.PrimaryStatus;
            result.BaselineContentLength = spaBaseline.PrimaryContentLength;
            result.BaselineContentType = spaBaseline.PrimaryContentType;
            result.BaselineSha256 = spaBaseline.BodySha256;
            result.SpaCatchAllDetected = spaBaseline.IsLikelySpaCatchAll;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (ScopeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _audit.Record("http-content-discovery.baseline_error", new Dictionary<string, object?>
            {
                ["base_url"] = normalizedBase,
                ["error"] = ex.Message,
            });
        }
        // --- end htb-spa-catchall-detection ---

        var minIntervalTicks = Stopwatch.Frequency / _rateLimitRps;
        long nextAllowedTick = Stopwatch.GetTimestamp();

        foreach (var word in _wordlist)
        {
            ct.ThrowIfCancellationRequested();

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
                if (status == 200)
                {
                    var bytes = await resp.Content.ReadAsByteArrayAsync(reqCts.Token)
                        .ConfigureAwait(false);
                    size = bytes.LongLength;
                    var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                    entry.BodySha256 = sha;
                    // --- htb-spa-catchall-detection ---
                    if (spaBaseline is not null
                        && SpaCatchAllDetector.IsBodySpaCatchAllMatch(bytes, sha, spaBaseline))
                    {
                        entry.MatchKind = "spa_catch_all";
                    }
                    // --- end htb-spa-catchall-detection ---
                }
                else if (resp.Content.Headers.ContentLength.HasValue)
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
                continue;
            }
        }

        _audit.Record("http-content-discovery.finish", new Dictionary<string, object?>
        {
            ["base_url"] = normalizedBase,
            ["entries_recorded"] = result.Entries.Count,
            ["word_count"] = _wordlist.Count,
            ["spa_catch_all_detected"] = result.SpaCatchAllDetected,
        });

        return result;
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }

    // --- htb-content-discovery-vhost-aware ---
    /// <summary>
    /// GAP-057: build a vhost-keyed base URL for content discovery
    /// re-probe. Used by
    /// <see cref="Http.VhostContentDiscoveryScheduler"/> to convert a
    /// detected vhost into a deterministic URL the existing
    /// <see cref="ProbeAsync"/> entrypoint can consume. Default ports
    /// (80 for http, 443 for https) are elided to match the canonical
    /// shape emitted by <see cref="HttpContentDiscoveryAutoRouter"/>.
    /// </summary>
    public static string BuildVhostBaseUrl(string vhost, int port, bool useTls)
    {
        if (string.IsNullOrWhiteSpace(vhost))
            throw new ArgumentException("vhost must not be empty.", nameof(vhost));
        var trimmed = vhost.Trim().Trim('.').ToLowerInvariant();
        var scheme = useTls ? "https" : "http";
        var isDefaultPort = (useTls && port == 443) || (!useTls && port == 80);
        var authority = isDefaultPort
            ? trimmed
            : trimmed + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return scheme + "://" + authority + "/";
    }
    // --- end htb-content-discovery-vhost-aware ---
}

/// <summary>
/// Bridge from <c>http.vhost.detected</c> events (emitted by
/// <see cref="HttpProbeTool"/>) to a queue of base URLs that
/// <see cref="HttpContentDiscoveryTool"/> should be re-fired against.
/// Closes GAP-057. Thread-safe.
/// </summary>
public sealed class HttpContentDiscoveryAutoRouter
{
    private readonly object _lock = new();
    private readonly List<string> _queued = new();
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> QueuedBaseUrls
    {
        get { lock (_lock) { return _queued.ToArray(); } }
    }

    public void OnVhostDetected(string vhost, int port = 80, bool useTls = false)
    {
        if (string.IsNullOrWhiteSpace(vhost)) return;
        var trimmed = vhost.Trim();
        var scheme = useTls ? "https" : "http";
        var isDefaultPort = (useTls && port == 443) || (!useTls && port == 80);
        var authority = isDefaultPort
            ? trimmed
            : trimmed + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var url = scheme + "://" + authority + "/";
        lock (_lock)
        {
            if (_seen.Add(url)) _queued.Add(url);
        }
    }

    public IReadOnlyList<string> Drain()
    {
        lock (_lock)
        {
            var copy = _queued.ToArray();
            _queued.Clear();
            return copy;
        }
    }
}
