using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon.Http;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Http;

/// <summary>
/// GAP-035 / CVE-2025-49132-shape locale-parameter LFI probe tests. Uses
/// HttpListener on 127.0.0.1:0 to drive the tool against scripted server
/// responses; scope is set to 127.0.0.0/8 throughout.
/// </summary>
public class LocaleLfiProbeTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-locale-lfi-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
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
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static LocaleLfiProbe NewProbe(out AuditLog audit, out string auditPath)
    {
        var scope = ScopeLoader.Parse("127.0.0.0/8");
        audit = NewAudit(out auditPath);
        // Reuse a short-timeout HttpClient so listener disposal doesn't hang the test.
        var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        return new LocaleLfiProbe(scope, audit, http);
    }

    [Fact]
    public async Task DetectsPasswdMarker_OnLfi()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx =>
        {
            var q = ctx.Request.QueryString["lang"] ?? "";
            if (q.Contains("etc/passwd") || q.Contains("etc%2fpasswd"))
                await WriteAsync(ctx, 200, "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/sbin/nologin\n");
            else
                await WriteAsync(ctx, 200, "<html><body>hello world</body></html>");
        };

        var probe = NewProbe(out var audit, out _);
        try
        {
            var html = "<a href=\"/index.php?lang=en\">en</a>";
            var r = await probe.ProbeAsync(server.BaseUrl, discoveryHtml: html, maxProbes: 50);

            Assert.Contains(r.Findings, f => f.Evidence == "passwd_marker");
            var hit = r.Findings.First(f => f.Evidence == "passwd_marker");
            Assert.Equal("lang", hit.Parameter);
            Assert.True(hit.Confidence > 0.9);
            Assert.False(string.IsNullOrEmpty(hit.BodySampleSha256));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task DetectsWinIniMarker()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx =>
        {
            var q = ctx.Request.QueryString["page"] ?? "";
            if (q.Contains("win.ini") || q.Contains("windows%2fwin.ini"))
                await WriteAsync(ctx, 200, "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[boot loader]\n");
            else
                await WriteAsync(ctx, 200, "<html>hi</html>");
        };
        var probe = NewProbe(out var audit, out _);
        try
        {
            var html = "<a href=\"/render.php?page=home\">home</a>";
            var r = await probe.ProbeAsync(server.BaseUrl, discoveryHtml: html, maxProbes: 50);
            Assert.Contains(r.Findings, f => f.Evidence == "win_ini_marker");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task DetectsPhpFilterBase64()
    {
        // Generate a base64 blob > 200 chars in length.
        var blob = Convert.ToBase64String(new byte[256]);
        using var server = new ScriptedListener();
        server.Handler = async ctx =>
        {
            var q = ctx.Request.QueryString["file"] ?? "";
            if (q.Contains("php://filter") || q.Contains("php%3a%2f%2ffilter"))
                await WriteAsync(ctx, 200, blob, "text/plain");
            else
                await WriteAsync(ctx, 200, "<html>regular</html>");
        };
        var probe = NewProbe(out var audit, out _);
        try
        {
            var candidates = new[] { ($"{server.BaseUrl}/index.php", "file") };
            var r = await probe.ProbeAsync(server.BaseUrl, candidates: candidates, maxProbes: 30);
            Assert.Contains(r.Findings, f => f.Evidence == "base64_blob");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task LengthAnomaly_FlaggedAsLowConfidence()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx =>
        {
            var q = ctx.Request.QueryString["lang"] ?? "";
            // Baseline returns a short stable body; one payload returns a
            // very long body but no marker — that's the "length anomaly"
            // shape we want to flag low-confidence.
            if (q.Contains("etc/passwd") && !q.Contains("win.ini"))
                await WriteAsync(ctx, 200, new string('x', 50_000));
            else
                await WriteAsync(ctx, 200, "ok");
        };
        var probe = NewProbe(out var audit, out _);
        try
        {
            var candidates = new[] { ($"{server.BaseUrl}/index.php", "lang") };
            var r = await probe.ProbeAsync(server.BaseUrl, candidates: candidates, maxProbes: 30);
            var lowConf = r.Findings.FirstOrDefault(f => f.Evidence == "length_anomaly");
            Assert.NotNull(lowConf);
            Assert.True(lowConf!.Confidence < 0.6);
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task BaselineRequest_NoFalsePositive()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx => await WriteAsync(ctx, 200, "<html>same body for everyone</html>");
        var probe = NewProbe(out var audit, out _);
        try
        {
            var html = "<a href=\"/index.php?lang=en\">en</a>";
            var r = await probe.ProbeAsync(server.BaseUrl, discoveryHtml: html, maxProbes: 30);
            Assert.Empty(r.Findings);
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectsRateLimit()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx => await WriteAsync(ctx, 200, "ok");
        var probe = NewProbe(out var audit, out _);
        try
        {
            // 2 (url, param) candidates × (1 baseline + 8 payloads) = 18 probes
            // capped at 20; at 10 rps we expect ≥ ~1.8 s elapsed.
            var candidates = new[]
            {
                ($"{server.BaseUrl}/a", "lang"),
                ($"{server.BaseUrl}/b", "page"),
            };
            var sw = Stopwatch.StartNew();
            await probe.ProbeAsync(server.BaseUrl, candidates: candidates, maxProbes: 20, ratePerSecond: 10);
            sw.Stop();
            Assert.True(sw.Elapsed >= TimeSpan.FromSeconds(1.4),
                $"expected rate-limited run ≥ 1.4s, got {sw.Elapsed.TotalSeconds:F2}s");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RespectsMaxProbes()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx => await WriteAsync(ctx, 200, "ok");
        var probe = NewProbe(out var audit, out _);
        try
        {
            var candidates = new[]
            {
                ($"{server.BaseUrl}/a", "lang"),
                ($"{server.BaseUrl}/b", "page"),
                ($"{server.BaseUrl}/c", "file"),
                ($"{server.BaseUrl}/d", "template"),
            };
            var r = await probe.ProbeAsync(server.BaseUrl, candidates: candidates,
                maxProbes: 5, ratePerSecond: 1000);
            Assert.True(r.ProbedUrls.Count <= 5,
                $"expected at most 5 probes, got {r.ProbedUrls.Count}");
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var audit = NewAudit(out _);
        try
        {
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var probe = new LocaleLfiProbe(scope, audit, http);
            await Assert.ThrowsAsync<ScopeException>(
                () => probe.ProbeAsync("http://127.0.0.1:1234/", candidates: new[] { ("http://127.0.0.1:1234/", "lang") }));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Argv_Injection_Rejected()
    {
        var probe = NewProbe(out var audit, out _);
        try
        {
            await Assert.ThrowsAsync<ArgumentException>(
                () => probe.ProbeAsync("http://127.0.0.1:80/;rm -rf /"));
            await Assert.ThrowsAsync<ArgumentException>(
                () => probe.ProbeAsync("http://127.0.0.1:80/`whoami`"));
            await Assert.ThrowsAsync<ArgumentException>(
                () => probe.ProbeAsync("ftp://127.0.0.1/"));
        }
        finally { audit.Dispose(); }
    }

    [Fact]
    public async Task Audit_NeverLogsBody()
    {
        const string canary = "CANARY-LFI-XYZZY-77293-secret-payload-must-not-leak";
        using var server = new ScriptedListener();
        server.Handler = async ctx => await WriteAsync(ctx, 200, canary + "\nroot:x:0:0:root:/root:/bin/sh\n");
        var probe = NewProbe(out var audit, out var auditPath);
        try
        {
            var candidates = new[] { ($"{server.BaseUrl}/index.php", "lang") };
            await probe.ProbeAsync(server.BaseUrl, candidates: candidates, maxProbes: 30);
        }
        finally { audit.Dispose(); }

        var text = File.ReadAllText(auditPath);
        Assert.DoesNotContain(canary, text);
    }

    [Fact]
    public async Task RedirectToOffScope_Rejected()
    {
        using var server = new ScriptedListener();
        server.Handler = async ctx =>
        {
            // Issue a redirect to an off-scope public IP — the tool must
            // not record this as a finding and must audit a rejection.
            ctx.Response.StatusCode = 302;
            ctx.Response.Headers["Location"] = "http://8.8.8.8/evil";
            ctx.Response.Close();
            await Task.CompletedTask;
        };
        var probe = NewProbe(out var audit, out var auditPath);
        try
        {
            var candidates = new[] { ($"{server.BaseUrl}/index.php", "lang") };
            var r = await probe.ProbeAsync(server.BaseUrl, candidates: candidates, maxProbes: 30);
            Assert.Empty(r.Findings);
        }
        finally { audit.Dispose(); }

        var text = File.ReadAllText(auditPath);
        Assert.Contains("redirect_rejected", text);
        Assert.Contains("\"redirect_rejected\":true", text);
    }

    [Fact]
    public void DiscoversLocaleParamsFromHtml()
    {
        string? path = null;
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", "locale-lfi", "form-and-link.html");
            if (File.Exists(candidate)) { path = candidate; break; }
            dir = Path.GetDirectoryName(dir);
        }
        Assert.NotNull(path);
        var html = File.ReadAllText(path!);

        var cands = LocaleLfiProbe.ExtractCandidates("http://127.0.0.1:8080/", html);

        Assert.Contains(cands, c => c.Parameter == "lang");
        Assert.Contains(cands, c => c.Parameter == "locale");
        Assert.Contains(cands, c => c.Parameter == "page");
        Assert.Contains(cands, c => c.Parameter == "view");
        Assert.Contains(cands, c => c.Parameter == "template");
        Assert.Contains(cands, c => c.Parameter == "region");
        // Non-locale params must not appear.
        Assert.DoesNotContain(cands, c => c.Parameter == "q");
        Assert.DoesNotContain(cands, c => c.Parameter == "color");
        Assert.DoesNotContain(cands, c => c.Parameter == "username");
    }
}
