using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Hardening tests for <see cref="HttpContentDiscoveryTool"/> covering
/// GAP-055 (SPA catch-all detection) and GAP-057 (vhost auto-routing) plus
/// the wordlist-profile / extension-fanout machinery added alongside.
/// Lives in a separate namespace from the legacy
/// <c>tests/Drederick.Tests/HttpContentDiscoveryToolTests.cs</c> to avoid
/// class-name collisions while keeping the new behaviour close to its
/// owner directory.
/// </summary>
public class HttpContentDiscoveryToolHardeningTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-hcdh-{Guid.NewGuid():N}.jsonl"));

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
            return Task.FromResult(Responder!(request));
        }
    }

    private static HttpResponseMessage MakeResponse(int code, string? body, string mediaType = "text/html")
    {
        var msg = new HttpResponseMessage((HttpStatusCode)code);
        msg.Content = body is null
            ? new ByteArrayContent(Array.Empty<byte>())
            : new StringContent(body, Encoding.UTF8, mediaType);
        return msg;
    }

    private static bool IsBaselinePath(string p) =>
        p.StartsWith("/__drederick_baseline_404_", StringComparison.Ordinal);

    // --- (1) SPA catch-all detection ----------------------------------------

    [Fact]
    public async Task SpaCatchAll_All_Unknown_Paths_Tagged_When_Baseline_Returns_200_Shell()
    {
        const string ReactShell = "<!doctype html><html><body><div id=\"root\"></div></body></html>";

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler
        {
            // Pterodactyl-style: every route returns the same React shell.
            Responder = _ => MakeResponse(200, ReactShell),
        };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http,
            wordlist: new[] { ".git/config", "panel.env", "laravel.log" },
            rateLimitRps: 1000);

        var result = await tool.ProbeAsync("http://10.10.10.5/");

        Assert.True(result.SpaCatchAllDetected);
        Assert.Equal(200, result.BaselineStatus);
        Assert.False(string.IsNullOrEmpty(result.BaselineSha256));
        Assert.Equal(3, result.Entries.Count);
        Assert.All(result.Entries, e => Assert.Equal("spa_catch_all", e.MatchKind));
        Assert.All(result.Entries, e => Assert.Equal(result.BaselineSha256, e.BodySha256));
    }

    [Fact]
    public async Task SpaCatchAll_RealHit_Not_Tagged_When_Body_Differs()
    {
        const string ReactShell = "<!doctype html><html><body><div id=\"root\"></div></body></html>";
        const string AdminPage  = "<html><h1>Admin Panel — please log in</h1></html>";

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath switch
            {
                "/admin" => MakeResponse(200, AdminPage),
                _        => MakeResponse(200, ReactShell),
            },
        };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http,
            wordlist: new[] { "admin", "robots.txt", "favicon.ico" },
            rateLimitRps: 1000);

        var result = await tool.ProbeAsync("http://10.10.10.5/");

        Assert.True(result.SpaCatchAllDetected);
        var admin = Assert.Single(result.Entries, e => e.Path == "/admin");
        Assert.Null(admin.MatchKind);
        Assert.NotEqual(result.BaselineSha256, admin.BodySha256);

        var robots = Assert.Single(result.Entries, e => e.Path == "/robots.txt");
        Assert.Equal("spa_catch_all", robots.MatchKind);
        Assert.Equal(result.BaselineSha256, robots.BodySha256);
    }

    [Fact]
    public async Task SpaCatchAll_Not_Detected_When_Baseline_Is_404()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var handler = new StubHandler
        {
            Responder = req =>
            {
                if (IsBaselinePath(req.RequestUri!.AbsolutePath))
                    return MakeResponse(404, "Not found");
                return MakeResponse(200, "real content");
            },
        };
        using var http = new HttpClient(handler);
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, http, wordlist: new[] { "found" }, rateLimitRps: 1000);

        var result = await tool.ProbeAsync("http://10.10.10.5/");

        Assert.False(result.SpaCatchAllDetected);
        Assert.Equal(404, result.BaselineStatus);
        Assert.All(result.Entries, e => Assert.Null(e.MatchKind));
    }

    // --- (2) raft-medium wordlist profile -----------------------------------

    [Fact]
    public void RaftMedium_Falls_Back_To_Default_With_Warning_When_Seclists_Absent()
    {
        // CI typically has no seclists installed under either canonical
        // path. Whether or not it does, the loader must not throw, must
        // return a usable wordlist, and must emit either the
        // ".loaded" or ".fallback" marker — GAP-055 calls explicitly for
        // a recorded warning when we fall back.
        using var audit = NewAudit();
        var list = HttpContentDiscoveryTool.ResolveWordlistProfile("raft-medium", audit).ToArray();

        Assert.NotEmpty(list);

        var seclistsPresent =
            File.Exists("/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt") ||
            File.Exists("/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt");

        // Read the audit jsonl back to verify the warning wired through.
        var auditPath = audit.Path;
        audit.Dispose();
        var contents = File.ReadAllText(auditPath);
        if (seclistsPresent)
        {
            Assert.Contains("\"http-content-discovery.wordlist_profile.loaded\"", contents);
        }
        else
        {
            Assert.Contains("\"http-content-discovery.wordlist_profile.fallback\"", contents);
            // Fallback list must equal the curated default so the probe
            // still has signal to chase.
            Assert.Equal(HttpContentDiscoveryTool.DefaultWordlist, list);
        }
    }

    [Fact]
    public void Profile_Constructor_Accepts_Default()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null, wordlist: null, rateLimitRps: 100,
            extensions: null, wordlistProfile: "default");

        Assert.Equal("default", tool.WordlistProfile);
        Assert.NotEmpty(tool.EffectiveWordlist);
    }

    // --- (3) Extension fanout -----------------------------------------------

    [Fact]
    public void ExtensionFanout_Cross_Product_Is_Correct()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null,
            wordlist: new[] { "admin", "config" },
            rateLimitRps: 100,
            extensions: new[] { "php", ".html", "txt" });

        var w = tool.EffectiveWordlist;
        Assert.Contains("admin", w);
        Assert.Contains("admin.php", w);
        Assert.Contains("admin.html", w);
        Assert.Contains("admin.txt", w);
        Assert.Contains("config", w);
        Assert.Contains("config.php", w);
        Assert.Contains("config.html", w);
        Assert.Contains("config.txt", w);
        Assert.Equal(8, w.Count);

        Assert.Equal(new[] { "php", "html", "txt" }, tool.EffectiveExtensions);
    }

    [Fact]
    public void ExtensionFanout_Skips_Directory_Entries()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null,
            wordlist: new[] { "admin/", "login" },
            rateLimitRps: 100,
            extensions: new[] { "php" });

        var w = tool.EffectiveWordlist;
        Assert.Contains("admin/", w);
        Assert.DoesNotContain("admin/.php", w);
        Assert.Contains("login", w);
        Assert.Contains("login.php", w);
    }

    [Fact]
    public void ExtensionFanout_Drops_Non_Alnum_Extensions()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        using var tool = new HttpContentDiscoveryTool(
            scope, audit, httpClient: null,
            wordlist: new[] { "admin" },
            rateLimitRps: 100,
            extensions: new[] { "php", "ph?", "ph p", "" });

        Assert.Equal(new[] { "php" }, tool.EffectiveExtensions);
    }

    // --- (4) Vhost auto-routing ---------------------------------------------

    [Fact]
    public void AutoRouter_Queues_Vhost_Bases_With_Default_Ports()
    {
        var router = new HttpContentDiscoveryAutoRouter();

        router.OnVhostDetected("pterodactyl.htb");
        router.OnVhostDetected("10.10.10.5", port: 80);
        router.OnVhostDetected("admin.example.com", port: 8443, useTls: true);
        router.OnVhostDetected("secure.example.com", port: 443, useTls: true);

        var queued = router.QueuedBaseUrls;
        Assert.Contains("http://pterodactyl.htb/", queued);
        Assert.Contains("http://10.10.10.5/", queued);
        Assert.Contains("https://admin.example.com:8443/", queued);
        Assert.Contains("https://secure.example.com/", queued);
        Assert.Equal(4, queued.Count);
    }

    [Fact]
    public void AutoRouter_Deduplicates_And_Drains()
    {
        var router = new HttpContentDiscoveryAutoRouter();
        router.OnVhostDetected("a.htb");
        router.OnVhostDetected("a.htb"); // dup
        router.OnVhostDetected("A.HTB"); // case-insensitive dup
        router.OnVhostDetected("b.htb");

        Assert.Equal(2, router.QueuedBaseUrls.Count);
        var drained = router.Drain();
        Assert.Equal(2, drained.Count);
        Assert.Empty(router.QueuedBaseUrls);

        // Re-detection of an already-drained vhost is suppressed (we already
        // dispatched work for it once this run).
        router.OnVhostDetected("a.htb");
        Assert.Empty(router.QueuedBaseUrls);
    }

    [Fact]
    public async Task AutoRouter_Wired_Into_Probe_Hits_Vhost_Authority()
    {
        // End-to-end-ish: detect a vhost, drain the queue, run the tool
        // against the resulting base URL. Verifies that the auto-router's
        // URL shape is one the tool actually accepts.
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();

        var seenAuthority = "";
        var handler = new StubHandler
        {
            Responder = req =>
            {
                seenAuthority = req.RequestUri!.Authority;
                return MakeResponse(200, "ok");
            },
        };
        using var http = new HttpClient(handler);

        var router = new HttpContentDiscoveryAutoRouter();
        router.OnVhostDetected("10.10.10.5", port: 80);

        // Scope only knows about the IP, so we reroute via the Host header
        // by addressing the IP and overriding the request authority — in
        // production AdaptiveRunner does the equivalent via /etc/hosts. For
        // this test we just confirm the URL string the router produces
        // round-trips through Uri parsing cleanly.
        var url = router.Drain().Single();
        Assert.Equal("http://10.10.10.5/", url);

        var uri = new Uri(url);
        Assert.Equal("10.10.10.5", uri.Host);
        Assert.Equal(80, uri.Port);
        Assert.Equal("/", uri.AbsolutePath);

        // Sanity-check the tool itself still works (scope is by host string).
        var inScope = ScopeLoader.Parse("10.10.10.5");
        using var tool = new HttpContentDiscoveryTool(
            inScope, audit, http, wordlist: new[] { "ok1" }, rateLimitRps: 1000);
        var result = await tool.ProbeAsync(url);
        Assert.Equal("10.10.10.5", seenAuthority);
        Assert.Single(result.Entries);
    }

    // --- helpers ------------------------------------------------------------

}
