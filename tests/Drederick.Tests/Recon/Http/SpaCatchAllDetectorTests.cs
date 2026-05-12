using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Http;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Http;

/// <summary>
/// Tests for <see cref="SpaCatchAllDetector"/> (GAP-055): two-probe SPA
/// catch-all baseline, structural-marker fusion, scope enforcement,
/// audit emission, and end-to-end integration with
/// <see cref="HttpContentDiscoveryTool"/> via a live loopback
/// <see cref="HttpListener"/>.
/// </summary>
public class SpaCatchAllDetectorTests
{
    private const string ReactShell =
        "<!doctype html><html><head><title>X</title></head><body>" +
        "<div id=\"root\"></div><script src=\"/static/js/main.abc123.js\"></script>" +
        "</body></html>";

    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-spa-{Guid.NewGuid():N}.jsonl"));

    private static string AuditPath(AuditLog log) => log.Path;

    private sealed class StubHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage>? Responder { get; set; }
        public List<string> Paths { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
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

    // (1) Strictest form: every random 404 path returns 200 with byte-identical body.
    [Fact]
    public async Task Detects_React_Style_Spa_With_Identical_Body_Sha()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var stub = new StubHandler
        {
            Responder = _ => MakeResponse(200, ReactShell),
        };
        using var http = new HttpClient(stub);

        var detector = new SpaCatchAllDetector(scope, audit);
        var baseline = await detector.ProbeAsync("http://10.10.10.5/", http, CancellationToken.None);

        Assert.True(baseline.IsLikelySpaCatchAll);
        Assert.Equal("identical_sha", baseline.DetectionReason);
        Assert.Equal(baseline.BodySha256, baseline.SecondaryBodySha256);
        Assert.True(baseline.ContentLengthRange.Min > 0);
        Assert.Equal(baseline.ContentLengthRange.Min, baseline.ContentLengthRange.Max);
        // Two probes fired.
        Assert.Equal(2, stub.Paths.Count);
        Assert.All(stub.Paths, p =>
            Assert.StartsWith("/__drederick_404_", p, StringComparison.Ordinal));
    }

    // (2) Loose form: body bytes differ (random nonce in the body) but
    // structural markers + length-within-5% still identify SPA.
    [Fact]
    public async Task Detects_Loose_Spa_Where_Bodies_Differ_But_Structure_Matches()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        int n = 0;
        var stub = new StubHandler
        {
            Responder = _ =>
            {
                // Append a tiny per-request nonce so SHA differs but
                // length drift is well under 5%.
                var body = ReactShell + "<!-- nonce:" + (n++).ToString("D2") + " -->";
                return MakeResponse(200, body);
            },
        };
        using var http = new HttpClient(stub);

        var detector = new SpaCatchAllDetector(scope, audit);
        var baseline = await detector.ProbeAsync("http://10.10.10.5/", http, CancellationToken.None);

        Assert.True(baseline.IsLikelySpaCatchAll);
        Assert.Equal("loose_structure_match", baseline.DetectionReason);
        Assert.NotEqual(baseline.BodySha256, baseline.SecondaryBodySha256);
    }

    // (3) Real 404s — no SPA, IsLikelySpaCatchAll=false but hashes captured.
    [Fact]
    public async Task Returns_False_On_Real_404_Responses()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        int n = 0;
        var stub = new StubHandler
        {
            Responder = _ => MakeResponse(404, "<html><body>not found " + (n++) + "</body></html>"),
        };
        using var http = new HttpClient(stub);

        var detector = new SpaCatchAllDetector(scope, audit);
        var baseline = await detector.ProbeAsync("http://10.10.10.5/", http, CancellationToken.None);

        Assert.False(baseline.IsLikelySpaCatchAll);
        Assert.Equal("no_match", baseline.DetectionReason);
        Assert.Equal(404, baseline.PrimaryStatus);
        Assert.False(string.IsNullOrEmpty(baseline.BodySha256));
        Assert.NotEqual(baseline.BodySha256, baseline.SecondaryBodySha256);
    }

    // (4) Scope enforcement.
    [Fact]
    public async Task Throws_ScopeException_For_Out_Of_Scope_Base_Url()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var stub = new StubHandler { Responder = _ => MakeResponse(200, ReactShell) };
        using var http = new HttpClient(stub);

        var detector = new SpaCatchAllDetector(scope, audit);
        await Assert.ThrowsAsync<ScopeException>(() =>
            detector.ProbeAsync("http://192.0.2.7/", http, CancellationToken.None));
        Assert.Empty(stub.Paths);
    }

    // (5) Audit event recorded.
    [Fact]
    public async Task Records_Spa_Catch_All_Baseline_Audit_Event()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var audit = NewAudit();
        var path = AuditPath(audit);
        try
        {
            var stub = new StubHandler { Responder = _ => MakeResponse(200, ReactShell) };
            using var http = new HttpClient(stub);

            var detector = new SpaCatchAllDetector(scope, audit);
            await detector.ProbeAsync("http://10.10.10.5/", http, CancellationToken.None);
        }
        finally
        {
            audit.Dispose();
        }

        var text = File.ReadAllText(path);
        Assert.Contains("spa_catch_all.baseline", text);
        Assert.Contains("\"is_spa\":true", text);
        Assert.Contains("\"reason\":\"identical_sha\"", text);
    }

    // (6) Integration: HttpListener on 127.0.0.1:0. Three wordlist hits
    // — two are catch-all (200 with shell), one is a real distinct asset.
    [Fact]
    public async Task Integration_Only_Real_Hit_Is_Untagged_When_Spa_Catch_All_Active()
    {
        if (!HttpListener.IsSupported)
        {
            return;
        }

        var listener = new HttpListener();
        int port = 0;
        for (int attempt = 0; attempt < 10; attempt++)
        {
            port = GetFreeTcpPort();
            try
            {
                listener.Prefixes.Clear();
                listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                listener.Start();
                break;
            }
            catch (HttpListenerException)
            {
                listener = new HttpListener();
            }
        }
        if (!listener.IsListening)
        {
            return; // environment refuses to bind; do not fail the suite.
        }

        const string RealAsset = "User-agent: *\nDisallow: /private/\n";

        using var listenerCts = new CancellationTokenSource();
        var serverTask = Task.Run(async () =>
        {
            try
            {
                while (!listenerCts.IsCancellationRequested)
                {
                    var ctx = await listener.GetContextAsync();
                    var p = ctx.Request.Url!.AbsolutePath;
                    byte[] body;
                    string ct = "text/html";
                    if (p == "/robots.txt")
                    {
                        body = Encoding.UTF8.GetBytes(RealAsset);
                        ct = "text/plain";
                    }
                    else
                    {
                        body = Encoding.UTF8.GetBytes(ReactShell);
                    }
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = ct;
                    ctx.Response.ContentLength64 = body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.Close();
                }
            }
            catch { /* shutdown */ }
        });

        try
        {
            // Scope 127.0.0.0/8 so both detector and tool will accept loopback.
            var scope = ScopeLoader.Parse("127.0.0.0/8");
            using var audit = NewAudit();

            using var tool = new HttpContentDiscoveryTool(
                scope, audit,
                httpClient: null,
                wordlist: new[] { "robots.txt", "admin", "login" },
                rateLimitRps: 100);

            var result = await tool.ProbeAsync(
                $"http://127.0.0.1:{port}/", CancellationToken.None);

            Assert.True(result.SpaCatchAllDetected);

            var byPath = result.Entries.ToDictionary(e => e.Path, e => e);
            Assert.True(byPath.ContainsKey("/robots.txt"));
            Assert.True(byPath.ContainsKey("/admin"));
            Assert.True(byPath.ContainsKey("/login"));

            // Real hit must NOT be tagged spa_catch_all.
            Assert.Null(byPath["/robots.txt"].MatchKind);

            // Catch-all hits must be tagged.
            Assert.Equal("spa_catch_all", byPath["/admin"].MatchKind);
            Assert.Equal("spa_catch_all", byPath["/login"].MatchKind);

            // Downstream pursuit list = entries whose match_kind is not spa_catch_all.
            var pursuit = result.Entries
                .Where(e => e.MatchKind != "spa_catch_all")
                .Select(e => e.Path)
                .ToList();
            Assert.Single(pursuit);
            Assert.Equal("/robots.txt", pursuit[0]);
        }
        finally
        {
            listenerCts.Cancel();
            try { listener.Stop(); } catch { }
            try { listener.Close(); } catch { }
            try { await serverTask; } catch { }
        }
    }

    private static int GetFreeTcpPort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        int port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
