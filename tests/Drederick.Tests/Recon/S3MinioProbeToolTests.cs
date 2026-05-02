using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

public class S3MinioProbeToolTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-s3-probe-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }
    private static AuditLog NewAudit() => NewAudit(out _);

    private sealed class CannedHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage>? Responder { get; set; }
        public List<HttpRequestMessage> Requests { get; } = new();
        public TimeSpan? PerRequestDelay { get; set; }
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (PerRequestDelay is { } d)
            {
                await Task.Delay(d, cancellationToken).ConfigureAwait(false);
            }
            return Responder?.Invoke(request) ?? new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private sealed class StubLister : IS3BucketLister
    {
        public IReadOnlyList<S3BucketEntry> Result { get; set; } = Array.Empty<S3BucketEntry>();
        public List<S3Endpoint> Calls { get; } = new();
        public Task<IReadOnlyList<S3BucketEntry>> ListAsync(
            S3Endpoint endpoint, S3Credential credential, CancellationToken ct)
        {
            Calls.Add(endpoint);
            return Task.FromResult(Result);
        }
    }

    private static HttpResponseMessage Xml(HttpStatusCode code, string body, string? server = null)
    {
        var r = new HttpResponseMessage(code)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/xml"),
        };
        if (server is not null)
        {
            r.Headers.TryAddWithoutValidation("Server", server);
        }
        return r;
    }

    private static S3MinioProbeTool Build(
        Scope.Scope scope,
        AuditLog audit,
        CannedHandler handler,
        IS3BucketLister? lister = null,
        CredentialStore? creds = null,
        TimeSpan? timeout = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        return new S3MinioProbeTool(
            scope, audit, creds, resolver,
            _ => handler, lister,
            timeout ?? TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task MinioHealth_Live_200_DetectsMinio()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/minio/health/live"
                ? new HttpResponseMessage(HttpStatusCode.OK)
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var tool = Build(scope, audit, handler);
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.True(f.IsMinio);
        Assert.True(f.IsS3);
    }

    [Fact]
    public async Task AnonListAllMyBuckets_Parses()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        const string xml = """
<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>internal</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>
    <Bucket><Name>backups</Name><CreationDate>2024-01-02T00:00:00.000Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>
""";
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/" && string.IsNullOrEmpty(req.RequestUri!.Query)
                ? Xml(HttpStatusCode.OK, xml)
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var tool = Build(scope, audit, handler);
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.True(f.IsS3);
        Assert.True(f.AnonymousListAllowed);
        Assert.Equal(new[] { "internal", "backups" }, f.AnonymousBuckets);
    }

    [Fact]
    public async Task AccessDenied_Detects_S3_AuthRequired()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        const string xml = """
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message><HostId>abc</HostId></Error>
""";
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/" && string.IsNullOrEmpty(req.RequestUri!.Query)
                ? Xml(HttpStatusCode.Forbidden, xml)
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var tool = Build(scope, audit, handler);
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.True(f.IsS3);
        Assert.False(f.AnonymousListAllowed);
    }

    [Fact]
    public async Task NotS3_GenericNginx404()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            Responder = _ =>
            {
                var r = new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent("<html><body>404 Not Found</body></html>"),
                };
                r.Headers.TryAddWithoutValidation("Server", "nginx/1.18.0");
                return r;
            },
        };
        var tool = Build(scope, audit, handler);
        var f = await tool.ProbeAsync("10.0.0.5", 80);
        Assert.False(f.IsS3);
        Assert.False(f.IsMinio);
    }

    [Fact]
    public async Task OutOfScope_Throws_NoRequests()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler();
        var tool = Build(scope, audit, handler);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8", 9000));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Hostname_ResolvedIp_ScopeValidated()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler { Responder = _ => new HttpResponseMessage(HttpStatusCode.OK) };
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, __) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.42") });
        var tool = Build(scope, audit, handler, resolver: resolver);
        var f = await tool.ProbeAsync("minio.htb", 9000);
        Assert.True(f.IsMinio);
        Assert.NotEmpty(handler.Requests);
        Assert.Equal("minio.htb", handler.Requests[0].RequestUri!.Host);
    }

    [Fact]
    public async Task Hostname_ResolvesOutOfScope_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler();
        Func<string, CancellationToken, Task<IPAddress[]>> resolver =
            (_, __) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
        var tool = Build(scope, audit, handler, resolver: resolver);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("evil.htb", 9000));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Authenticated_BucketList_ViaStubLister_EmitsAuditEvents()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var audit = NewAudit(out var auditPath);
        var handler = new CannedHandler
        {
            Responder = req => req.RequestUri!.AbsolutePath == "/minio/health/live"
                ? new HttpResponseMessage(HttpStatusCode.OK)
                : new HttpResponseMessage(HttpStatusCode.NotFound),
        };
        var creds = new CredentialStore(audit);
        creds.Add("AKIAFAKEACCESSKEY", "FakeSecretKeyMaterial", realm: "s3", source: "test");
        var lister = new StubLister
        {
            Result = new[]
            {
                new S3BucketEntry { Name = "internal", ObjectCount = 1, Objects = new[] { new S3ObjectEntry { Key = "id_ed25519", Size = 432 } } },
                new S3BucketEntry { Name = "public", ObjectCount = 0, Objects = Array.Empty<S3ObjectEntry>() },
            },
        };
        var tool = Build(scope, audit, handler, lister, creds);
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.True(f.IsMinio);
        Assert.Equal(2, f.AuthenticatedBuckets.Count);
        Assert.Single(lister.Calls);

        audit.Dispose();
        var lines = await File.ReadAllLinesAsync(auditPath);
        Assert.Contains(lines, l => l.Contains("\"event\":\"s3.bucket.listed\"") && l.Contains("\"bucket\":\"internal\""));
        Assert.Contains(lines, l => l.Contains("\"event\":\"s3.object.found\"") && l.Contains("\"key\":\"id_ed25519\""));
        Assert.DoesNotContain(lines, l => l.Contains("FakeSecretKeyMaterial"));
    }

    [Fact]
    public async Task AuditShapes_StartAndFinish_Recorded()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var audit = NewAudit(out var auditPath);
        var handler = new CannedHandler { Responder = _ => new HttpResponseMessage(HttpStatusCode.NotFound) };
        var tool = Build(scope, audit, handler);
        await tool.ProbeAsync("10.0.0.5", 9000);
        audit.Dispose();
        var lines = await File.ReadAllLinesAsync(auditPath);
        Assert.Contains(lines, l => l.Contains("\"event\":\"s3.probe.start\"") && l.Contains("\"port\":9000"));
        Assert.Contains(lines, l => l.Contains("\"event\":\"s3.probe.finish\""));
    }

    [Fact]
    public async Task Timeout_ReturnsErrorTimeout_NoThrow()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            PerRequestDelay = TimeSpan.FromSeconds(5),
            Responder = _ => new HttpResponseMessage(HttpStatusCode.OK),
        };
        var tool = Build(scope, audit, handler, timeout: TimeSpan.FromMilliseconds(150));
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.False(f.IsMinio);
    }

    [Fact]
    public async Task MinioVersion_ParsedFromServerHeader()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit();
        var handler = new CannedHandler
        {
            Responder = req =>
            {
                if (req.RequestUri!.AbsolutePath == "/minio/health/live")
                {
                    var r = new HttpResponseMessage(HttpStatusCode.OK);
                    r.Headers.TryAddWithoutValidation("Server", "MinIO/RELEASE.2024-01-01T00-00-00Z");
                    return r;
                }
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            },
        };
        var tool = Build(scope, audit, handler);
        var f = await tool.ProbeAsync("10.0.0.5", 9000);
        Assert.True(f.IsMinio);
        Assert.Equal("MinIO/RELEASE.2024-01-01T00-00-00Z", f.Server);
        Assert.Equal("RELEASE.2024-01-01T00-00-00Z", f.MinioVersion);
    }
}
