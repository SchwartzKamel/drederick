// --- htb-content-discovery-crawl --- (GAP-022)
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Recon.Http;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Http;

/// <summary>
/// GAP-022 HTML+sitemap+robots crawler tests. Uses HttpListener on
/// 127.0.0.1:0; scope is 127.0.0.0/8 throughout.
/// </summary>
public class HtmlSitemapCrawlerTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-crawl-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private sealed class ScriptedListener : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _runner;
        public int Port { get; }
        public string BaseUrl => $"http://127.0.0.1:{Port}";
        public Func<HttpListenerContext, Task>? Handler { get; set; }
        public int RequestCount;
        public List<string> RequestPaths { get; } = new();
        public List<string> RequestMethods { get; } = new();
        private readonly object _lock = new();

        public ScriptedListener()
        {
            Port = GetFreePort();
            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            _listener.Start();
            _runner = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    HttpListenerContext ctx;
                    try { ctx = await _listener.GetContextAsync(); }
                    catch { return; }
                    Interlocked.Increment(ref RequestCount);
                    lock (_lock)
                    {
                        RequestPaths.Add(ctx.Request.Url?.AbsolutePath ?? "");
                        RequestMethods.Add(ctx.Request.HttpMethod);
                    }
                    try
                    {
                        if (Handler is not null) await Handler(ctx);
                        else { ctx.Response.StatusCode = 200; ctx.Response.Close(); }
                    }
                    catch
                    {
                        try { ctx.Response.Abort(); } catch { }
                    }
                }
            });
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _runner.Wait(TimeSpan.FromSeconds(2)); } catch { }
            _listener.Close();
        }
    }

    private static async Task WriteAsync(HttpListenerContext ctx, int status, string body, string ct = "text/html")
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = ct;
        if (ctx.Request.HttpMethod == "HEAD")
        {
            ctx.Response.ContentLength64 = Encoding.UTF8.GetByteCount(body);
            ctx.Response.Close();
            return;
        }
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static HtmlSitemapCrawler NewCrawler(out AuditLog audit, out string auditPath,
        string scopeSpec = "127.0.0.0/8")
    {
        var scope = ScopeLoader.Parse(scopeSpec);
        audit = NewAudit(out auditPath);
        var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        return new HtmlSitemapCrawler(scope, audit, http);
    }

    private static Func<HttpListenerContext, Task> RouteHandler(Dictionary<string, (int, string, string)> routes,
        (int, string, string) fallback = default)
    {
        return async ctx =>
        {
            var path = ctx.Request.Url!.AbsolutePath;
            if (routes.TryGetValue(path, out var r))
                await WriteAsync(ctx, r.Item1, r.Item2, r.Item3);
            else
            {
                var fb = fallback == default ? (404, "not found", "text/plain") : fallback;
                await WriteAsync(ctx, fb.Item1, fb.Item2, fb.Item3);
            }
        };
    }

    // ---- Unit-level parser tests ----

    [Fact]
    public void Parses_RobotsTxt_Disallows()
    {
        var dis = new List<string>();
        var allow = new List<string>();
        var sm = new List<string>();
        var body = """
            User-agent: *
            Disallow: /admin
            Disallow: /secret/
            Allow: /public
            # comment
            Sitemap: http://example/sitemap.xml
            """;
        HtmlSitemapCrawler.ParseRobots(body, dis, allow, sm);
        Assert.Contains("/admin", dis);
        Assert.Contains("/secret/", dis);
        Assert.Contains("/public", allow);
        Assert.Contains("http://example/sitemap.xml", sm);
    }

    [Fact]
    public void Parses_Sitemap_Xml()
    {
        var xml = """
            <?xml version="1.0"?>
            <urlset>
              <url><loc>http://a/x</loc></url>
              <url><loc>http://a/y</loc></url>
            </urlset>
            """;
        HtmlSitemapCrawler.ParseSitemap(xml, out var locs, out var idx);
        Assert.Equal(new[] { "http://a/x", "http://a/y" }, locs);
        Assert.Empty(idx);
    }

    [Fact]
    public void Parses_SitemapIndex_Xml()
    {
        var xml = """
            <?xml version="1.0"?>
            <sitemapindex>
              <sitemap><loc>http://a/s1.xml</loc></sitemap>
              <sitemap><loc>http://a/s2.xml</loc></sitemap>
            </sitemapindex>
            """;
        HtmlSitemapCrawler.ParseSitemap(xml, out var locs, out var idx);
        Assert.Equal(new[] { "http://a/s1.xml", "http://a/s2.xml" }, idx);
    }

    [Fact]
    public void MalformedSitemap_GracefulError()
    {
        // The static parser surfaces XmlException; the public CrawlAsync
        // path swallows it into the audit. Test the public path below;
        // here verify the parser throws as expected.
        Assert.Throws<System.Xml.XmlException>(() =>
            HtmlSitemapCrawler.ParseSitemap("<not valid xml<<<", out _, out _));
    }

    // ---- Integration tests ----

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var crawler = NewCrawler(out var audit, out _, scopeSpec: "10.0.0.0/8");
        try
        {
            await Assert.ThrowsAsync<ScopeException>(() =>
                crawler.CrawlAsync("http://127.0.0.1:8080/"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Crawls_Anchors_From_Html()
    {
        using var server = new ScriptedListener();
        var html = "<html><body>" +
                   "<a href=\"/about\">a</a>" +
                   "<a href=\"/contact\">c</a>" +
                   "</body></html>";
        server.Handler = RouteHandler(new()
        {
            ["/"] = (200, html, "text/html"),
            ["/about"] = (200, "ok", "text/html"),
            ["/contact"] = (200, "ok", "text/html"),
        });
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", maxDepth: 2, maxUrls: 50, ratePerSecond: 100);
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/about") && c.Source == "html-anchor");
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/contact") && c.Source == "html-anchor");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Resolves_Relative_Urls()
    {
        using var server = new ScriptedListener();
        var html = "<html><body><a href=\"sub/page\">x</a></body></html>";
        server.Handler = RouteHandler(new()
        {
            ["/"] = (200, html, "text/html"),
            ["/sub/page"] = (200, "ok", "text/html"),
        });
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", maxDepth: 2, ratePerSecond: 100);
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/sub/page"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectsDepthLimit()
    {
        using var server = new ScriptedListener();
        // base has anchor to /a; if /a had anchors they'd be depth 2.
        var html = "<html><a href=\"/a\">a</a></html>";
        server.Handler = RouteHandler(new()
        {
            ["/"] = (200, html, "text/html"),
            ["/a"] = (200, "ok", "text/html"),
        });
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", maxDepth: 0, ratePerSecond: 100);
            // depth 0 means only base (depth 0); /a is depth 1 and should be filtered.
            Assert.DoesNotContain(r.CrawledUrls, c => c.Url.EndsWith("/a"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectsMaxUrlsCap()
    {
        using var server = new ScriptedListener();
        var sb = new StringBuilder("<html><body>");
        for (int i = 0; i < 50; i++) sb.Append($"<a href=\"/p{i}\">x</a>");
        sb.Append("</body></html>");
        server.Handler = ctx =>
        {
            var path = ctx.Request.Url!.AbsolutePath;
            if (path == "/") return WriteAsync(ctx, 200, sb.ToString(), "text/html");
            return WriteAsync(ctx, 200, "ok", "text/html");
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", maxDepth: 2, maxUrls: 5, ratePerSecond: 200);
            Assert.True(r.CrawledUrls.Count <= 5, $"expected <=5, got {r.CrawledUrls.Count}");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task SameOrigin_Enforced_RejectsExternal()
    {
        using var server = new ScriptedListener();
        var html = "<html><a href=\"http://evil.example.com/x\">e</a><a href=\"/local\">l</a></html>";
        server.Handler = RouteHandler(new()
        {
            ["/"] = (200, html, "text/html"),
            ["/local"] = (200, "ok", "text/html"),
        });
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/local"));
            Assert.DoesNotContain(r.CrawledUrls, c => c.Url.Contains("evil.example.com"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectsRedirect_OnlyInScope()
    {
        using var server = new ScriptedListener();
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            if (p == "/")
                return WriteAsync(ctx, 200, "<a href=\"/r\">r</a>", "text/html");
            if (p == "/r")
            {
                // 302 with off-scope Location header (192.168.x must be off-scope under 127.0.0.0/8)
                ctx.Response.StatusCode = 302;
                ctx.Response.Headers["Location"] = "http://192.168.99.99/elsewhere";
                ctx.Response.Close();
                return Task.CompletedTask;
            }
            return WriteAsync(ctx, 404, "nf", "text/plain");
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
            // /r is in-scope; off-scope redirect target must NOT appear.
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/r"));
            Assert.DoesNotContain(r.CrawledUrls, c => c.Url.Contains("192.168.99.99"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RobotsDisallow_AsHighSignalSeeds_NotBoundaries()
    {
        using var server = new ScriptedListener();
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            return p switch
            {
                "/robots.txt" => WriteAsync(ctx, 200,
                    "User-agent: *\nDisallow: /secret-admin\n", "text/plain"),
                "/" => WriteAsync(ctx, 200, "<html>hi</html>", "text/html"),
                "/secret-admin" => WriteAsync(ctx, 200, "ok", "text/html"),
                _ => WriteAsync(ctx, 404, "nf", "text/plain"),
            };
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100, respectRobots: false);
            Assert.Contains("/secret-admin", r.RobotsDisallow);
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/secret-admin") && c.Source == "robots-disallow");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectRobots_Flag_HonorsDisallows()
    {
        using var server = new ScriptedListener();
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            return p switch
            {
                "/robots.txt" => WriteAsync(ctx, 200,
                    "User-agent: *\nDisallow: /secret-admin\n", "text/plain"),
                "/" => WriteAsync(ctx, 200,
                    "<a href=\"/secret-admin\">x</a>", "text/html"),
                _ => WriteAsync(ctx, 200, "ok", "text/html"),
            };
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100, respectRobots: true);
            // robots Disallow honoured -> /secret-admin must NOT appear in crawled set.
            Assert.DoesNotContain(r.CrawledUrls, c => c.Url.EndsWith("/secret-admin"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Parses_Sitemap_Xml_Integration()
    {
        using var server = new ScriptedListener();
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            return p switch
            {
                "/sitemap.xml" => WriteAsync(ctx, 200,
                    $"<?xml version=\"1.0\"?><urlset><url><loc>{server.BaseUrl}/from-sitemap</loc></url></urlset>",
                    "application/xml"),
                "/" => WriteAsync(ctx, 200, "<html>hi</html>", "text/html"),
                "/from-sitemap" => WriteAsync(ctx, 200, "ok", "text/html"),
                _ => WriteAsync(ctx, 404, "nf", "text/plain"),
            };
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
            Assert.Contains(r.SitemapUrls, s => s.EndsWith("/sitemap.xml"));
            Assert.Contains(r.CrawledUrls, c => c.Url.EndsWith("/from-sitemap") && c.Source == "sitemap");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RateLimit_Honored()
    {
        using var server = new ScriptedListener();
        var sb = new StringBuilder("<html>");
        for (int i = 0; i < 8; i++) sb.Append($"<a href=\"/p{i}\">x</a>");
        sb.Append("</html>");
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            if (p == "/") return WriteAsync(ctx, 200, sb.ToString(), "text/html");
            return WriteAsync(ctx, 200, "ok", "text/html");
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var sw = Stopwatch.StartNew();
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", maxDepth: 2, maxUrls: 50, ratePerSecond: 5);
            sw.Stop();
            // 5 rps => 200ms/req; we expect at least ~6 requests => >=1s elapsed.
            // Be lenient to avoid flake: assert >= 600ms when >= 5 requests were made.
            if (r.CrawledUrls.Count >= 5)
            {
                Assert.True(sw.ElapsedMilliseconds >= 600,
                    $"rate-limit not honoured: {sw.ElapsedMilliseconds}ms for {r.CrawledUrls.Count} requests");
            }
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Audit_NeverLogsBody()
    {
        using var server = new ScriptedListener();
        const string canary = "DREDERICK_BODY_CANARY_ABCDEF";
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            return p switch
            {
                "/" => WriteAsync(ctx, 200, $"<html>{canary}<a href=\"/x\">x</a></html>", "text/html"),
                "/x" => WriteAsync(ctx, 200, canary, "text/html"),
                _ => WriteAsync(ctx, 404, "nf", "text/plain"),
            };
        };
        var crawler = NewCrawler(out var audit, out var auditPath);
        try
        {
            await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
        }
        finally { audit.Dispose(); }
        var contents = File.ReadAllText(auditPath);
        Assert.DoesNotContain(canary, contents);
    }

    [Fact]
    public async Task MalformedSitemap_GracefulError_Integration()
    {
        using var server = new ScriptedListener();
        server.Handler = ctx =>
        {
            var p = ctx.Request.Url!.AbsolutePath;
            return p switch
            {
                "/sitemap.xml" => WriteAsync(ctx, 200, "<not-valid<<<", "application/xml"),
                "/" => WriteAsync(ctx, 200, "<html>hi</html>", "text/html"),
                _ => WriteAsync(ctx, 404, "nf", "text/plain"),
            };
        };
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            var r = await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
            // Should not throw; sitemap_urls may include the URL only after
            // a successful fetch. The crawler logs an audit error and
            // continues.
            Assert.NotNull(r);
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Uses_HEAD_For_Probes()
    {
        using var server = new ScriptedListener();
        server.Handler = RouteHandler(new()
        {
            ["/"] = (200, "<a href=\"/probe\">x</a>", "text/html"),
            ["/probe"] = (200, "should not be GETted", "text/html"),
        });
        var crawler = NewCrawler(out var audit, out _);
        try
        {
            await crawler.CrawlAsync(server.BaseUrl + "/", ratePerSecond: 100);
        }
        finally { audit.Dispose(); }
        // The /probe URL should have been HEAD'd, not GET'd. The base
        // and /robots.txt and /sitemap.xml are GET (text fetch); discovered
        // links are HEAD.
        var headed = server.RequestPaths
            .Zip(server.RequestMethods, (p, m) => (p, m))
            .Where(t => t.p == "/probe")
            .ToList();
        Assert.NotEmpty(headed);
        Assert.All(headed, t => Assert.Equal("HEAD", t.m));
    }
}
// --- end htb-content-discovery-crawl ---
