using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Ops.Tenable;
using Xunit;

namespace Drederick.Tests;

public class TenableScClientTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.NotFound);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(Responder(request));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Fact]
    public void WithApiKey_RequiresKeys()
    {
        Assert.Throws<ArgumentException>(() => TenableScClient.WithApiKey("https://sc", "", "y"));
        Assert.Throws<ArgumentException>(() => TenableScClient.WithApiKey("https://sc", "x", ""));
    }

    [Fact]
    public void WithUserPass_RequiresCreds()
    {
        Assert.Throws<ArgumentException>(() => TenableScClient.WithUserPass("https://sc", "", "p"));
        Assert.Throws<ArgumentException>(() => TenableScClient.WithUserPass("https://sc", "u", ""));
    }

    [Fact]
    public void BackendName_IsTenableSc()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "AAAA", "BBBB", httpClient: http);
        Assert.Equal("tenable.sc", client.BackendName);
    }

    [Fact]
    public void ApiKey_Auth_SetsXApiKeyHeader()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "AAAA", "BBBB", httpClient: http);
        Assert.True(http.DefaultRequestHeaders.Contains("X-ApiKey"));
        var hdr = string.Join(",", http.DefaultRequestHeaders.GetValues("X-ApiKey"));
        Assert.Contains("accesskey=AAAA", hdr);
        Assert.Contains("secretkey=BBBB", hdr);
    }

    [Fact]
    public async Task UserPass_Auth_PostsTokenAndSetsXSecurityCenter()
    {
        var handler = new FakeHandler();
        bool tokenPosted = false;
        handler.Responder = req =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("/rest/token") && req.Method == HttpMethod.Post)
            {
                tokenPosted = true;
                return Json(HttpStatusCode.OK, """{"response":{"token":12345}}""");
            }
            if (req.RequestUri.AbsolutePath.StartsWith("/rest/scanResult"))
                return Json(HttpStatusCode.OK, """{"response":{"usable":[]}}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        };
        using var http = new HttpClient(handler);
        using (var client = TenableScClient.WithUserPass("https://sc", "alice", "pw", httpClient: http))
        {
            await client.ListScansAsync();
        }
        Assert.True(tokenPosted);
        // After the first call, X-SecurityCenter header is set.
        Assert.True(http.DefaultRequestHeaders.Contains("X-SecurityCenter"));
        Assert.Equal("12345", string.Join(",", http.DefaultRequestHeaders.GetValues("X-SecurityCenter")));
    }

    [Fact]
    public async Task UserPass_Failure_OnLogin_Throws()
    {
        var handler = new FakeHandler();
        handler.Responder = _ => Json(HttpStatusCode.Unauthorized, """{"error":"bad creds"}""");
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithUserPass("https://sc", "u", "p", httpClient: http);
        await Assert.ThrowsAsync<TenableApiException>(async () => await client.ListScansAsync());
    }

    [Fact]
    public void ParseScanResultList_HandlesUsableShape()
    {
        var json = """
        {"response":{"usable":[
          {"id":"7","name":"weekly","status":"Completed","finishTime":"1700000000","startTime":"1699990000","uuid":"abc"},
          {"id":"8","name":"daily","status":"Running","finishTime":"0","startTime":"1700001000"}
        ]}}
        """;
        var scans = TenableScClient.ParseScanResultList(json);
        Assert.Equal(2, scans.Count);
        Assert.Equal(7, scans[0].Id);
        Assert.Equal("weekly", scans[0].Name);
        Assert.Equal("Completed", scans[0].Status);
        Assert.Equal(1700000000, scans[0].LastModificationDate);
        Assert.Equal("abc", scans[0].Uuid);
        Assert.Equal(8, scans[1].Id);
    }

    [Fact]
    public void ParseScanResultList_HandlesArrayShape()
    {
        var json = """
        {"response":[
          {"id":42,"name":"x","status":"Completed","finishTime":100}
        ]}
        """;
        var scans = TenableScClient.ParseScanResultList(json);
        Assert.Single(scans);
        Assert.Equal(42, scans[0].Id);
    }

    [Fact]
    public void ParseScanResultList_HandlesManageableFallback()
    {
        var json = """
        {"response":{"manageable":[
          {"id":1,"name":"m","status":"Completed","finishTime":50}
        ]}}
        """;
        var scans = TenableScClient.ParseScanResultList(json);
        Assert.Single(scans);
        Assert.Equal(1, scans[0].Id);
    }

    [Fact]
    public void ParseScanResultList_EmptyOnMissingResponse()
    {
        Assert.Empty(TenableScClient.ParseScanResultList("{}"));
        Assert.Empty(TenableScClient.ParseScanResultList("""{"response":null}"""));
    }

    [Fact]
    public async Task RequestExportAsync_RejectsNonNessusFormat()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "a", "b", httpClient: http);
        await Assert.ThrowsAsync<TenableApiException>(async () => await client.RequestExportAsync(1, "csv"));
    }

    [Fact]
    public async Task RequestExportAsync_ReturnsScanIdAsFileId()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "a", "b", httpClient: http);
        var fid = await client.RequestExportAsync(99, "nessus");
        Assert.Equal(99, fid);
    }

    [Fact]
    public async Task GetExportStatusAsync_AlwaysReady()
    {
        var handler = new FakeHandler();
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "a", "b", httpClient: http);
        Assert.Equal("ready", await client.GetExportStatusAsync(1, 1));
    }

    [Fact]
    public async Task DownloadExportAsync_UnzipsNessusEntry()
    {
        // Build a ZIP containing one .nessus entry on the fly.
        byte[] zipBytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = zip.CreateEntry("scan-99.nessus");
                using var stream = entry.Open();
                var data = Encoding.UTF8.GetBytes("<NessusClientData_v2/>");
                stream.Write(data, 0, data.Length);
            }
            zipBytes = ms.ToArray();
        }

        var handler = new FakeHandler
        {
            Responder = req =>
            {
                Assert.EndsWith("/rest/scanResult/99/download", req.RequestUri!.AbsolutePath);
                Assert.Equal(HttpMethod.Post, req.Method);
                return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(zipBytes) };
            }
        };
        using var http = new HttpClient(handler);
        using var client = TenableScClient.WithApiKey("https://sc", "a", "b", httpClient: http);
        var bytes = await client.DownloadExportAsync(99, 99);
        Assert.Equal("<NessusClientData_v2/>", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void UnzipFirstNessus_PassesThroughRawXml()
    {
        var raw = Encoding.UTF8.GetBytes("<NessusClientData_v2/>");
        var bytes = TenableScClient.UnzipFirstNessus(raw, 1);
        Assert.Equal(raw, bytes);
    }

    [Fact]
    public void UnzipFirstNessus_FallsBackToFirstEntry_IfNoNessusExtension()
    {
        byte[] zipBytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = zip.CreateEntry("scan.xml");
                using var stream = entry.Open();
                var data = Encoding.UTF8.GetBytes("payload");
                stream.Write(data, 0, data.Length);
            }
            zipBytes = ms.ToArray();
        }
        var bytes = TenableScClient.UnzipFirstNessus(zipBytes, 1);
        Assert.Equal("payload", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void UnzipFirstNessus_ThrowsOnEmptyZip()
    {
        byte[] zipBytes;
        using (var ms = new MemoryStream())
        {
            using (var _ = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true)) { }
            zipBytes = ms.ToArray();
        }
        Assert.Throws<TenableApiException>(() => TenableScClient.UnzipFirstNessus(zipBytes, 7));
    }

    [Fact]
    public async Task PullAsync_ViaScBackend_EndToEnd()
    {
        // Smoke-test the puller against a SC backend: list → select → request → status → download.
        byte[] zipBytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var e = zip.CreateEntry("x.nessus");
                using var s = e.Open();
                var d = Encoding.UTF8.GetBytes("body");
                s.Write(d, 0, d.Length);
            }
            zipBytes = ms.ToArray();
        }

        var handler = new FakeHandler
        {
            Responder = req =>
            {
                var p = req.RequestUri!.AbsolutePath;
                if (p.EndsWith("/rest/scanResult"))
                    return Json(HttpStatusCode.OK,
                        """{"response":{"usable":[{"id":5,"name":"X","status":"Completed","finishTime":"1234"}]}}""");
                if (p.EndsWith("/rest/scanResult/5/download"))
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(zipBytes) };
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        };
        using var http = new HttpClient(handler);

        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            using var audit = new AuditLog(Path.Combine(tmpDir, "audit.jsonl"));
            using var client = TenableScClient.WithApiKey("https://sc", "a", "b", httpClient: http);
            var puller = new TenableApiPuller(client, audit, delay: (_, __) => Task.CompletedTask);
            var result = await puller.PullAsync(
                new TenableScanSelector { Latest = true },
                new TenableApiPullOptions { CacheRoot = Path.Combine(tmpDir, "cache") });
            Assert.Equal(5, result.ScanId);
            Assert.Equal("body", File.ReadAllText(result.CachedPath));
            // Audit must include the backend name now.
            var auditText = File.ReadAllText(Path.Combine(tmpDir, "audit.jsonl"));
            Assert.Contains("\"backend\":\"tenable.sc\"", auditText);
        }
        finally
        {
            try { Directory.Delete(tmpDir, true); } catch { }
        }
    }
}
