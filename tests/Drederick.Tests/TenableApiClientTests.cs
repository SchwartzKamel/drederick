using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Ops.Tenable;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// Tests for <see cref="TenableApiClient"/> and <see cref="TenableApiPuller"/>.
/// All HTTP traffic is intercepted via a fake <see cref="HttpMessageHandler"/>
/// — no real network is touched.
/// </summary>
public class TenableApiClientTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.NotFound);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            // Materialize content (for header echo + Body inspection).
            Requests.Add(request);
            return Task.FromResult(Responder(request));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Fact]
    public void Ctor_Throws_OnMissingCredentials()
    {
        Assert.Throws<ArgumentException>(() => new TenableApiClient("https://x", "", "y"));
        Assert.Throws<ArgumentException>(() => new TenableApiClient("https://x", "y", ""));
        Assert.Throws<ArgumentException>(() => new TenableApiClient("", "a", "b"));
    }

    [Fact]
    public void Ctor_Sets_X_ApiKeys_Header()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://cloud.tenable.com", "AAAA", "BBBB", http);
        Assert.True(http.DefaultRequestHeaders.Contains("X-ApiKeys"));
        var hdr = string.Join(",", http.DefaultRequestHeaders.GetValues("X-ApiKeys"));
        Assert.Contains("accessKey=AAAA", hdr);
        Assert.Contains("secretKey=BBBB", hdr);
    }

    [Fact]
    public void AccessKeyDigest_IsStable_ButNotPlaintext()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var c1 = new TenableApiClient("https://x", "secret123", "y", http);
        using var c2 = new TenableApiClient("https://x", "secret123", "y", http);
        Assert.Equal(c1.AccessKeyDigest, c2.AccessKeyDigest);
        Assert.DoesNotContain("secret123", c1.AccessKeyDigest);
        Assert.Equal(12, c1.AccessKeyDigest.Length); // 6 bytes * 2 hex chars
    }

    [Fact]
    public async Task ListScansAsync_ParsesScanArray()
    {
        var handler = new FakeHandler
        {
            Responder = req =>
            {
                Assert.EndsWith("/scans", req.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK,
                    """{"scans":[{"id":42,"name":"Daily","status":"completed","last_modification_date":1700000000}]}""");
            }
        };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://cloud.tenable.com", "a", "b", http);
        var scans = await client.ListScansAsync();
        Assert.Single(scans);
        Assert.Equal(42, scans[0].Id);
        Assert.Equal("Daily", scans[0].Name);
    }

    [Fact]
    public async Task ListScansAsync_ReturnsEmpty_WhenNoScansKey()
    {
        var handler = new FakeHandler { Responder = _ => Json(HttpStatusCode.OK, "{}") };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var scans = await client.ListScansAsync();
        Assert.Empty(scans);
    }

    [Fact]
    public async Task ListScansAsync_Throws_OnHttpError()
    {
        var handler = new FakeHandler { Responder = _ => Json(HttpStatusCode.Forbidden, """{"error":"forbidden"}""") };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var ex = await Assert.ThrowsAsync<TenableApiException>(async () => await client.ListScansAsync());
        Assert.Contains("403", ex.Message);
    }

    [Fact]
    public async Task RequestExportAsync_ReturnsFileId()
    {
        var handler = new FakeHandler
        {
            Responder = req =>
            {
                Assert.Equal(HttpMethod.Post, req.Method);
                Assert.EndsWith("/scans/42/export", req.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK, """{"file":99}""");
            }
        };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var fileId = await client.RequestExportAsync(42, "nessus");
        Assert.Equal(99, fileId);
    }

    [Fact]
    public async Task RequestExportAsync_AcceptsStringFileId()
    {
        var handler = new FakeHandler { Responder = _ => Json(HttpStatusCode.OK, """{"file":"100"}""") };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var fileId = await client.RequestExportAsync(1, "nessus");
        Assert.Equal(100, fileId);
    }

    [Fact]
    public async Task RequestExportAsync_Throws_WhenFileIdMissing()
    {
        var handler = new FakeHandler { Responder = _ => Json(HttpStatusCode.OK, "{}") };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        await Assert.ThrowsAsync<TenableApiException>(async () => await client.RequestExportAsync(1, "nessus"));
    }

    [Fact]
    public async Task GetExportStatusAsync_ReturnsStatusString()
    {
        var handler = new FakeHandler
        {
            Responder = req =>
            {
                Assert.EndsWith("/scans/42/export/99/status", req.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK, """{"status":"ready"}""");
            }
        };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var status = await client.GetExportStatusAsync(42, 99);
        Assert.Equal("ready", status);
    }

    [Fact]
    public async Task DownloadExportAsync_ReturnsBytes()
    {
        var payload = "<NessusClientData_v2></NessusClientData_v2>";
        var handler = new FakeHandler
        {
            Responder = req =>
            {
                Assert.EndsWith("/scans/42/export/99/download", req.RequestUri!.AbsolutePath);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes(payload)),
                };
            }
        };
        using var http = new HttpClient(handler);
        using var client = new TenableApiClient("https://x", "a", "b", http);
        var bytes = await client.DownloadExportAsync(42, 99);
        Assert.Equal(payload, Encoding.UTF8.GetString(bytes));
    }
}

public class TenableApiPullerTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.NotFound);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(Responder(request));
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString());
        public TempDir() { Directory.CreateDirectory(Path); }
        public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
    }

    private static (TenableApiClient client, FakeHandler handler) MakeClient()
    {
        var handler = new FakeHandler();
        var http = new HttpClient(handler);
        var client = new TenableApiClient("https://cloud.tenable.com", "AAAA", "BBBB", http);
        return (client, handler);
    }

    private static AuditLog MakeAudit(TempDir dir) => new(System.IO.Path.Combine(dir.Path, "audit.jsonl"));

    [Fact]
    public void Selector_Validate_RequiresExactlyOne()
    {
        Assert.False(new TenableScanSelector().Validate(out _));
        Assert.False(new TenableScanSelector { ScanId = 1, Latest = true }.Validate(out _));
        Assert.False(new TenableScanSelector { ScanId = 1, ScanName = "x" }.Validate(out _));
        Assert.True(new TenableScanSelector { ScanId = 1 }.Validate(out _));
        Assert.True(new TenableScanSelector { ScanName = "x" }.Validate(out _));
        Assert.True(new TenableScanSelector { Latest = true }.Validate(out _));
    }

    [Fact]
    public async Task PullAsync_Latest_PicksMostRecentCompleted()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        "{\"scans\":[" +
                        "{\"id\":1,\"name\":\"Old\",\"status\":\"completed\",\"last_modification_date\":100}," +
                        "{\"id\":2,\"name\":\"New\",\"status\":\"completed\",\"last_modification_date\":200}," +
                        "{\"id\":3,\"name\":\"Running\",\"status\":\"running\",\"last_modification_date\":300}" +
                        "]}");
                if (path.Contains("/export") && path.EndsWith("/status"))
                    return Json(HttpStatusCode.OK, """{"status":"ready"}""");
                if (path.EndsWith("/export"))
                    return Json(HttpStatusCode.OK, """{"file":7}""");
                if (path.EndsWith("/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("payload")) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { Latest = true },
                new TenableApiPullOptions { CacheRoot = System.IO.Path.Combine(dir.Path, "cache") });

            Assert.Equal(2, result.ScanId);
            Assert.Equal("New", result.ScanName);
            Assert.False(result.FromCache);
            Assert.True(File.Exists(result.CachedPath));
            Assert.Equal("payload", File.ReadAllText(result.CachedPath));
        }
    }

    [Fact]
    public async Task PullAsync_ByScanId_FailsWhenNotVisible()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            handler.Responder = _ => Json(HttpStatusCode.OK, """{"scans":[]}""");
            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            await Assert.ThrowsAsync<TenableApiException>(() =>
                puller.PullAsync(
                    new TenableScanSelector { ScanId = 999 },
                    new TenableApiPullOptions { CacheRoot = dir.Path }));
        }
    }

    [Fact]
    public async Task PullAsync_ByName_PicksMostRecentMatch()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        "{\"scans\":[" +
                        "{\"id\":1,\"name\":\"Daily\",\"status\":\"completed\",\"last_modification_date\":100}," +
                        "{\"id\":2,\"name\":\"Daily\",\"status\":\"completed\",\"last_modification_date\":500}," +
                        "{\"id\":3,\"name\":\"Other\",\"status\":\"completed\",\"last_modification_date\":900}" +
                        "]}");
                if (path.EndsWith("/status")) return Json(HttpStatusCode.OK, """{"status":"ready"}""");
                if (path.EndsWith("/export")) return Json(HttpStatusCode.OK, """{"file":1}""");
                if (path.EndsWith("/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Array.Empty<byte>()) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };
            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { ScanName = "daily" }, // case-insensitive
                new TenableApiPullOptions { CacheRoot = dir.Path });
            Assert.Equal(2, result.ScanId);
        }
    }

    [Fact]
    public async Task PullAsync_UsesCache_WhenFileExists()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            // Pre-create the cache file at the deterministic path: <scan_id>-<last_mod>.<ext>
            var cacheDir = System.IO.Path.Combine(dir.Path, "cache");
            Directory.CreateDirectory(cacheDir);
            var cachedPath = System.IO.Path.Combine(cacheDir, "5-1234.nessus");
            File.WriteAllText(cachedPath, "cached-bytes");

            int exportCalls = 0;
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        """{"scans":[{"id":5,"name":"X","status":"completed","last_modification_date":1234}]}""");
                if (path.EndsWith("/export") || path.Contains("/export/")) { exportCalls++; }
                return Json(HttpStatusCode.OK, """{"file":1}""");
            };

            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { ScanId = 5 },
                new TenableApiPullOptions { CacheRoot = cacheDir });

            Assert.True(result.FromCache);
            Assert.Equal(cachedPath, result.CachedPath);
            Assert.Equal(0, exportCalls); // never called export endpoints
        }
    }

    [Fact]
    public async Task PullAsync_NoCache_ForcesFreshExport()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            var cacheDir = System.IO.Path.Combine(dir.Path, "cache");
            Directory.CreateDirectory(cacheDir);
            var cachedPath = System.IO.Path.Combine(cacheDir, "5-1234.nessus");
            File.WriteAllText(cachedPath, "stale");

            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        """{"scans":[{"id":5,"name":"X","status":"completed","last_modification_date":1234}]}""");
                if (path.EndsWith("/status")) return Json(HttpStatusCode.OK, """{"status":"ready"}""");
                if (path.EndsWith("/export")) return Json(HttpStatusCode.OK, """{"file":9}""");
                if (path.EndsWith("/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("fresh")) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { ScanId = 5 },
                new TenableApiPullOptions { CacheRoot = cacheDir, NoCache = true });

            Assert.False(result.FromCache);
            Assert.Equal("fresh", File.ReadAllText(result.CachedPath));
        }
    }

    [Fact]
    public async Task PullAsync_PollsUntilReady()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            int statusCalls = 0;
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        """{"scans":[{"id":1,"name":"X","status":"completed","last_modification_date":10}]}""");
                if (path.EndsWith("/export")) return Json(HttpStatusCode.OK, """{"file":1}""");
                if (path.EndsWith("/status"))
                {
                    statusCalls++;
                    var s = statusCalls < 3 ? "loading" : "ready";
                    return Json(HttpStatusCode.OK, "{\"status\":\"" + s + "\"}");
                }
                if (path.EndsWith("/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("ok")) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };
            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { ScanId = 1 },
                new TenableApiPullOptions { CacheRoot = System.IO.Path.Combine(dir.Path, "cache") });
            Assert.Equal(3, statusCalls);
            Assert.Equal("ok", File.ReadAllText(result.CachedPath));
        }
    }

    [Fact]
    public async Task PullAsync_Times_Out_When_Never_Ready()
    {
        using var dir = new TempDir();
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = MakeAudit(dir))
        {
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        """{"scans":[{"id":1,"name":"X","status":"completed","last_modification_date":10}]}""");
                if (path.EndsWith("/export")) return Json(HttpStatusCode.OK, """{"file":1}""");
                if (path.EndsWith("/status")) return Json(HttpStatusCode.OK, """{"status":"loading"}""");
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            // Synthetic clock that advances past the deadline on the first delay.
            var now = DateTimeOffset.UtcNow;
            var puller = new TenableApiPuller(
                client,
                audit,
                utcNow: () => now,
                delay: (_, __) => { now = now.AddMinutes(20); return Task.CompletedTask; });

            await Assert.ThrowsAsync<TenableApiException>(() =>
                puller.PullAsync(
                    new TenableScanSelector { ScanId = 1 },
                    new TenableApiPullOptions
                    {
                        CacheRoot = System.IO.Path.Combine(dir.Path, "cache"),
                        PollTimeout = TimeSpan.FromMinutes(1),
                    }));
        }
    }

    [Fact]
    public async Task PullAsync_AuditsKeyEvents()
    {
        using var dir = new TempDir();
        var auditPath = System.IO.Path.Combine(dir.Path, "audit.jsonl");
        var (client, handler) = MakeClient();
        using (client)
        using (var audit = new AuditLog(auditPath))
        {
            handler.Responder = req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (path.EndsWith("/scans"))
                    return Json(HttpStatusCode.OK,
                        """{"scans":[{"id":1,"name":"X","status":"completed","last_modification_date":10}]}""");
                if (path.EndsWith("/export")) return Json(HttpStatusCode.OK, """{"file":1}""");
                if (path.EndsWith("/status")) return Json(HttpStatusCode.OK, """{"status":"ready"}""");
                if (path.EndsWith("/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("z")) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            await puller.PullAsync(
                new TenableScanSelector { Latest = true },
                new TenableApiPullOptions { CacheRoot = System.IO.Path.Combine(dir.Path, "cache") });
        }

        var lines = File.ReadAllLines(auditPath);
        Assert.Contains(lines, l => l.Contains("\"tenable.api.list\""));
        Assert.Contains(lines, l => l.Contains("\"tenable.api.select\""));
        Assert.Contains(lines, l => l.Contains("\"tenable.api.export.request\""));
        Assert.Contains(lines, l => l.Contains("\"tenable.api.export.ready\""));
        Assert.Contains(lines, l => l.Contains("\"tenable.api.download\""));
        // Plaintext key never appears in audit.
        foreach (var line in lines) Assert.DoesNotContain("AAAA", line);
    }
}
