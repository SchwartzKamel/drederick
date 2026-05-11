using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class HttpContentDiscoveryToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-hcd-{Guid.NewGuid():N}.jsonl"));

    /// <summary>Programmable HttpMessageHandler. Dispatches by the request path (not the full URL).</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage>? Responder { get; set; }
        public List<string> Paths { get; } = new();
        public int CallCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            lock (Paths) Paths.Add(request.RequestUri!.AbsolutePath);
            var resp = Responder!(request);
            return Task.FromResult(resp);
        }
    }

    private static HttpResponseMessage Status(int code, string? body = null)
    {
        var msg = new HttpResponseMessage((HttpStatusCode)code);
        if (body is not null)
        {
            msg.Content = new StringContent(body, Encoding.UTF8, "text/plain");
        }
        else
        {
            msg.Content = new ByteArrayContent(Array.Empty<byte>());
        }
        return msg;
    }

    [Fact]
    public async Task OutOfScope_Throws_ScopeException_And_Does_Not_Connect()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler { Responder = _ => Status(200) };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http, wordlist: new[] { "admin" }, rateLimitRps: 100);

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("http://192.168.1.1/"));
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public void WordlistSanitization_Filters_Malicious_Entries()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();

        var dirty = new[]
        {
            "admin",              // keep
            "login.php",          // keep
            "a<b",                // drop: '<'
            "a>b",                // drop: '>'
            "x?y=1",              // drop: '?' and '='
            "a&b",                // drop: '&'
            "a;b",                // drop: ';'
            "line\nbreak",        // drop: newline
            "%00null",            // drop: bad percent escape
            "%20space",           // drop: %20 not allowed
            "ok%2Fslash",         // keep: %2F is the one allowed escape
            "",                   // drop: empty
            "   ",                // drop: whitespace only
            "../etc/passwd",      // drop: '..' path segments actually parse OK char-wise,
                                  //        BUT '../' contains '/' and '.' which are allowed.
                                  //        We intentionally DO accept this char set; the
                                  //        important malicious-payload filter is punctuation.
        };

        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null, wordlist: dirty, rateLimitRps: 100);

        var effective = tool.EffectiveWordlist;
        Assert.Contains("admin", effective);
        Assert.Contains("login.php", effective);
        Assert.Contains("ok%2Fslash", effective);
        Assert.DoesNotContain("a<b", effective);
        Assert.DoesNotContain("a>b", effective);
        Assert.DoesNotContain("x?y=1", effective);
        Assert.DoesNotContain("a&b", effective);
        Assert.DoesNotContain("a;b", effective);
        Assert.DoesNotContain("line\nbreak", effective);
        Assert.DoesNotContain("%00null", effective);
        Assert.DoesNotContain("%20space", effective);
        Assert.DoesNotContain("", effective);
    }

    [Fact]
    public void IsSafePath_DirectChecks()
    {
        Assert.True(HttpContentDiscoveryTool.IsSafePath("admin"));
        Assert.True(HttpContentDiscoveryTool.IsSafePath("a/b/c.txt"));
        Assert.True(HttpContentDiscoveryTool.IsSafePath(".git/HEAD"));
        Assert.True(HttpContentDiscoveryTool.IsSafePath("foo%2Fbar"));
        Assert.True(HttpContentDiscoveryTool.IsSafePath("foo%2fbar"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath(""));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a b"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a%"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a%2"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a%41"));     // %41 == 'A' still forbidden
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a?b"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a=b"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a&b"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a;b"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("a\nb"));
        Assert.False(HttpContentDiscoveryTool.IsSafePath("<script>"));
    }

    [Fact]
    public async Task StatusFiltering_Skips_404_Records_200_301_403()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath switch
            {
                "/found" => Status(200, "hello"),
                "/moved" => Status(301),
                "/forbidden" => Status(403),
                "/missing" => Status(404, "nope"),
                "/teapot" => Status(418),
                _ => Status(500),
            },
        };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http,
            wordlist: new[] { "found", "moved", "forbidden", "missing", "teapot" },
            rateLimitRps: 1000);

        var result = await tool.ProbeAsync("http://10.10.10.5:8080/");

        Assert.Equal("http://10.10.10.5:8080", result.BaseUrl);
        Assert.Equal(3, result.Entries.Count);
        Assert.Contains(result.Entries, e => e.Path == "/found" && e.Status == 200 && e.Size == 5);
        Assert.Contains(result.Entries, e => e.Path == "/moved" && e.Status == 301);
        Assert.Contains(result.Entries, e => e.Path == "/forbidden" && e.Status == 403);
        Assert.DoesNotContain(result.Entries, e => e.Status == 404);
        Assert.DoesNotContain(result.Entries, e => e.Status == 418);
        // 5 wordlist requests + 1 SPA-baseline 404 probe = 6 total handler calls.
        Assert.Equal(6, handler.CallCount);
    }

    [Fact]
    public async Task RateLimit_Enforces_Minimum_Duration()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler { Responder = _ => Status(200) };
        using var http = new HttpClient(handler);
        // All paths return 200 so all 10 requests go through the pacing logic.
        var words = Enumerable.Range(0, 10).Select(i => $"p{i}").ToArray();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http, wordlist: words, rateLimitRps: 5);

        var sw = Stopwatch.StartNew();
        var result = await tool.ProbeAsync("http://10.10.10.5/");
        sw.Stop();

        Assert.Equal(10, result.Entries.Count);
        // 10 requests at 5 rps → at least 9 intervals of 200ms ≈ 1.8s. Use a
        // generous lower bound (1500ms) to avoid CI flake from coarse timers.
        Assert.True(sw.ElapsedMilliseconds >= 1500,
            $"expected >=1500ms, got {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Cap_Honored_At_2000()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var many = Enumerable.Range(0, 3000).Select(i => $"p{i}").ToArray();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null, wordlist: many, rateLimitRps: 100);

        Assert.Equal(HttpContentDiscoveryTool.MaxWordlistEntries, tool.EffectiveWordlist.Count);
        Assert.Equal(2000, tool.EffectiveWordlist.Count);
    }

    [Fact]
    public async Task PerPath_Error_Does_Not_Abort_Probe()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler
        {
            Responder = req =>
            {
                if (req.RequestUri!.AbsolutePath == "/boom")
                {
                    throw new HttpRequestException("synthetic failure");
                }
                return Status(200, "ok");
            },
        };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http,
            wordlist: new[] { "ok1", "boom", "ok2" },
            rateLimitRps: 1000);

        var result = await tool.ProbeAsync("http://10.10.10.5/");

        Assert.Equal(2, result.Entries.Count);
        Assert.Contains(result.Entries, e => e.Path == "/ok1" && e.Status == 200);
        Assert.Contains(result.Entries, e => e.Path == "/ok2" && e.Status == 200);
        Assert.DoesNotContain(result.Entries, e => e.Path == "/boom");
        // 3 wordlist requests + 1 SPA-baseline 404 probe = 4 total handler calls.
        Assert.Equal(4, handler.CallCount);
    }

    [Fact]
    public async Task DefaultWordlist_IsSafe_And_NonEmpty()
    {
        Assert.NotEmpty(HttpContentDiscoveryTool.DefaultWordlist);
        foreach (var p in HttpContentDiscoveryTool.DefaultWordlist)
        {
            Assert.True(HttpContentDiscoveryTool.IsSafePath(p.TrimStart('/')),
                $"default wordlist entry not URL-safe: '{p}'");
        }
        await Task.CompletedTask;
    }
}
