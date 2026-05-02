using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

public class CmsFingerprintToolTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-cms-fp-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static AuditLog NewAudit() => NewAudit(out _);

    private sealed class CannedHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage>? Responder { get; set; }
        public List<HttpRequestMessage> Requests { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(Responder?.Invoke(request) ?? new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private static HttpResponseMessage Html(string body, IEnumerable<string>? setCookies = null,
        IEnumerable<KeyValuePair<string, string>>? extraHeaders = null,
        HttpStatusCode status = HttpStatusCode.OK)
    {
        var r = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/html"),
        };
        if (setCookies is not null)
        {
            foreach (var c in setCookies)
                r.Headers.TryAddWithoutValidation("Set-Cookie", c);
        }
        if (extraHeaders is not null)
        {
            foreach (var kv in extraHeaders)
                r.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }
        return r;
    }

    private static CmsFingerprintTool Build(
        Scope.Scope scope,
        AuditLog audit,
        CannedHandler handler,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        return new CmsFingerprintTool(
            scope, audit, resolver, _ => handler, corpus: null,
            timeout: TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task CameleonCMS_CookieAndMetaGenerator_TopMatchWithVersion()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var body = """<html><head><meta name="generator" content="Camaleon CMS 2.9.0"></head><body>hi</body></html>""";
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/"
                ? Html(body, setCookies: new[] { "_camaleon_cms_session=abc123; Path=/" })
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        Assert.NotEmpty(f.Matches);
        Assert.Equal("CameleonCMS", f.Matches[0].Name);
        Assert.Equal("2.9.0", f.Matches[0].Version);
        Assert.True(f.Matches[0].Confidence >= 2);
    }

    [Fact]
    public async Task WordPress_MetaGenerator_AndWpLoginProbe()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var rootBody = """<html><head><meta name="generator" content="WordPress 6.4.1"></head><body><link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css"/>blog</body></html>""";
        var handler = new CannedHandler
        {
            Responder = req =>
            {
                var p = req.RequestUri!.AbsolutePath;
                if (p == "/") return Html(rootBody);
                if (p == "/wp-login.php") return Html("<html>WordPress login</html>");
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            },
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        var wp = f.Matches.FirstOrDefault(m => m.Name == "WordPress");
        Assert.NotNull(wp);
        Assert.Equal("6.4.1", wp!.Version);
        Assert.True(wp.Confidence >= 2);
    }

    [Fact]
    public async Task Drupal_XGeneratorHeader_AndChangelog()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            Responder = req =>
            {
                var p = req.RequestUri!.AbsolutePath;
                if (p == "/")
                {
                    return Html("<html><body>Welcome to <script>Drupal.settings={};</script></body></html>",
                        extraHeaders: new[] { new KeyValuePair<string, string>("X-Generator", "Drupal 9.5.11 (https://www.drupal.org)") });
                }
                if (p == "/CHANGELOG.txt") return Html("Drupal 9.5.11, ..");
                if (p == "/user/login") return Html("Login | Drupal");
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            },
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        var d = f.Matches.FirstOrDefault(m => m.Name == "Drupal");
        Assert.NotNull(d);
        Assert.True(d!.Confidence >= 2);
    }

    [Fact]
    public async Task GenericSite_NoMatch_NoError()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            Responder = _ => Html("<html><body><h1>plain</h1></body></html>"),
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        Assert.Null(f.Error);
        Assert.Empty(f.Matches);
    }

    [Fact]
    public async Task SingleSignal_LowConfidence_Included()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        // Only an html_pattern hit on Drupal — no meta, no headers, no cookies, probes will not run.
        var body = "<html><body><script>Drupal.settings.foo=1;</script></body></html>";
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/"
                ? Html(body)
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        var d = f.Matches.FirstOrDefault(m => m.Name == "Drupal");
        Assert.NotNull(d);
        Assert.Equal(1, d!.Confidence);
    }

    [Fact]
    public async Task OutOfScopeIp_Throws_NoRequests()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler();
        var tool = Build(scope, audit, handler);

        await Assert.ThrowsAsync<ScopeException>(() => tool.FingerprintAsync("8.8.8.8", 80));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Hostname_ResolvesInScope_RequestUsesHostname()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var body = """<html><head><meta name="generator" content="Camaleon CMS 2.9.0"></head></html>""";
        var handler = new CannedHandler
        {
            Responder = _ => Html(body, setCookies: new[] { "_camaleon_cms_session=x" }),
        };
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, __) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.42") });
        var tool = Build(scope, audit, handler, resolver);

        var f = await tool.FingerprintAsync("facts.htb", 80);

        Assert.NotEmpty(handler.Requests);
        Assert.Equal("facts.htb", handler.Requests[0].RequestUri!.Host);
        Assert.NotEmpty(f.Matches);
        Assert.Equal("CameleonCMS", f.Matches[0].Name);
    }

    [Fact]
    public async Task Hostname_ResolvesOutOfScope_Throws_NoRequests()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler();
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, __) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
        var tool = Build(scope, audit, handler, resolver);

        await Assert.ThrowsAsync<ScopeException>(() => tool.FingerprintAsync("evil.htb", 80));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task PathProbes_OnlyRunWhenConfidenceReached_BoundsRequestCount()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            // Plain HTML — no signals match anywhere. No fingerprint reaches confidence_required.
            Responder = _ => Html("<html><body>plain</body></html>"),
        };
        var tool = Build(scope, audit, handler);

        var _ = await tool.FingerprintAsync("10.0.0.5", 80);

        // Exactly one request: GET /. No path-probe blow-up across 12 CMSes.
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task AuditEvents_StartMatchFinish_Emitted()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var audit = NewAudit(out var auditPath);
        var body = """<html><head><meta name="generator" content="Camaleon CMS 2.9.0"></head></html>""";
        var handler = new CannedHandler
        {
            Responder = _ => Html(body, setCookies: new[] { "_camaleon_cms_session=x" }),
        };
        var tool = Build(scope, audit, handler);

        await tool.FingerprintAsync("10.0.0.5", 80);
        audit.Dispose();

        var lines = await File.ReadAllLinesAsync(auditPath);
        Assert.Contains(lines, l => l.Contains("\"event\":\"cms-fingerprint.start\""));
        Assert.Contains(lines, l => l.Contains("\"event\":\"cms-fingerprint.match\"") && l.Contains("CameleonCMS"));
        Assert.Contains(lines, l => l.Contains("\"event\":\"cms-fingerprint.finish\"") && l.Contains("matches_count"));
    }

    [Fact]
    public async Task VersionRegex_StripsLeadingV()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        // Body contains "Camaleon CMS v2.9.0" — version capture group must yield "2.9.0", not "v2.9.0".
        var body = """<html><head><meta name="generator" content="Camaleon CMS"></head><body>Powered by Camaleon CMS v2.9.0</body></html>""";
        var handler = new CannedHandler
        {
            Responder = _ => Html(body, setCookies: new[] { "_camaleon_cms_session=x" }),
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        var cam = f.Matches.First(m => m.Name == "CameleonCMS");
        Assert.Equal("2.9.0", cam.Version);
    }

    [Fact]
    public async Task LargeBody_TruncatedTo512KB_StillMatchesEarlySignal()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        // Place the meta-generator early, then pad to ~1 MB. Signal must still match.
        var head = """<html><head><meta name="generator" content="Camaleon CMS 2.9.0"></head><body>""";
        var pad = new string('A', 1024 * 1024);
        var body = head + pad + "</body></html>";
        var handler = new CannedHandler
        {
            Responder = _ => Html(body, setCookies: new[] { "_camaleon_cms_session=x" }),
        };
        var tool = Build(scope, audit, handler);

        var f = await tool.FingerprintAsync("10.0.0.5", 80);

        var cam = f.Matches.First(m => m.Name == "CameleonCMS");
        Assert.Equal("2.9.0", cam.Version);
    }

    [Fact]
    public void EmbeddedCorpus_Loads_AndContainsCameleonCms()
    {
        var corpus = CmsFingerprintTool.LoadEmbeddedCorpus();
        Assert.NotEmpty(corpus);
        Assert.Contains(corpus, e => e.Name == "CameleonCMS");
        Assert.Contains(corpus, e => e.Name == "WordPress");
    }
}
