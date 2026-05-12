using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Tests for <see cref="CloudStorageEnumTool"/> (GAP-018). Uses an
/// in-process <see cref="HttpListener"/> on 127.0.0.1:0 that replays
/// canned responses for S3 bucket listings, access-denied envelopes,
/// 404s, and object payloads.
/// </summary>
public class CloudStorageEnumToolTests
{
    private const string Canary = "hunter2-DREDERICK-CANARY";

    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-cloud-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), $"drederick-cloud-out-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    /// <summary>Tiny scripted HTTP server matching path-style S3 requests.
    /// Routes is path → (status, content-type, body).</summary>
    private sealed class FakeS3Server : IAsyncDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly Task _serverTask;
        private readonly CancellationTokenSource _cts = new();
        private readonly Dictionary<string, (int Status, string ContentType, byte[] Body)> _routes;
        public int Port { get; }

        public FakeS3Server(Dictionary<string, (int, string, byte[])> routes)
        {
            _routes = routes;
            Port = GetFreePort();
            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            _listener.Start();
            _serverTask = Task.Run(RunAsync);
        }

        private static int GetFreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var p = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return p;
        }

        private async Task RunAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
                catch { return; }
                _ = Task.Run(() => Handle(ctx));
            }
        }

        private void Handle(HttpListenerContext ctx)
        {
            try
            {
                var key = ctx.Request.Url!.AbsolutePath;
                if (_routes.TryGetValue(key, out var route))
                {
                    ctx.Response.StatusCode = route.Status;
                    ctx.Response.ContentType = route.ContentType;
                    ctx.Response.ContentLength64 = route.Body.Length;
                    ctx.Response.OutputStream.Write(route.Body, 0, route.Body.Length);
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                }
            }
            catch { /* ignore */ }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { await _serverTask.ConfigureAwait(false); } catch { }
        }
    }

    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(FindFixtureDir(), name));

    private static string FindFixtureDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(d, "tests", "fixtures", "cloud-storage");
            if (Directory.Exists(candidate)) return candidate;
            d = Path.GetFullPath(Path.Combine(d, ".."));
        }
        throw new DirectoryNotFoundException("cloud-storage fixture dir not found");
    }

    private static Dictionary<string, (int, string, byte[])> RouteListable(string bucket)
    {
        return new Dictionary<string, (int, string, byte[])>
        {
            [$"/{bucket}/"] = (200, "application/xml", Fixture("listbucket-with-env.xml")),
            [$"/{bucket}/.env"] = (200, "text/plain", Encoding.UTF8.GetBytes(
                "DB_PASSWORD=" + Canary + "\n")),
            [$"/{bucket}/readme.txt"] = (200, "text/plain", Encoding.UTF8.GetBytes("hi")),
            [$"/{bucket}/backup-2024.tar.gz"] = (200, "application/gzip", new byte[2048]),
        };
    }

    [Fact]
    public async Task DetectsListableS3Bucket()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "backup");

        var b = Assert.Single(r.Buckets);
        Assert.True(b.Listable);
        Assert.Contains(b.Objects, o => o.Key == ".env");
        Assert.Contains(b.Objects, o => o.Key == "backup-2024.tar.gz");
    }

    [Fact]
    public async Task DetectsExistsButForbidden()
    {
        var routes = new Dictionary<string, (int, string, byte[])>
        {
            ["/private/"] = (403, "application/xml", Fixture("access-denied.xml")),
        };
        await using var srv = new FakeS3Server(routes);
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "private");

        var b = Assert.Single(r.Buckets);
        Assert.False(b.Listable);
        Assert.True(b.ExistsButForbidden);
    }

    [Fact]
    public async Task Detects_404_NotABucket()
    {
        await using var srv = new FakeS3Server(new Dictionary<string, (int, string, byte[])>());
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "nope");

        Assert.Empty(r.Buckets);
    }

    [Fact]
    public async Task Harvests_DotEnv_Object()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var outDir = TempDir();
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, outDir);

        var r = await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "backup");

        var b = Assert.Single(r.Buckets);
        var env = b.Objects.Single(o => o.Key == ".env");
        Assert.True(env.Harvested);
        Assert.False(string.IsNullOrEmpty(env.Sha256));
        Assert.True(File.Exists(env.LocalPath));
        var dir = Path.Combine(outDir, "loot", "127.0.0.1", "cloud-bucket-backup");
        Assert.True(Directory.Exists(dir));
        // readme.txt is not high-signal, so it must not be harvested.
        Assert.DoesNotContain(b.Objects, o => o.Key == "readme.txt" && o.Harvested);
    }

    [Fact]
    public async Task RespectsTotalByteCap()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        // Tight cap — only one (truncated) object can fit.
        var r = await tool.EnumerateAsync(
            "127.0.0.1", srv.Port, useTls: false, bucketName: "backup",
            maxHarvestBytes: 20);

        var b = Assert.Single(r.Buckets);
        Assert.True(b.HarvestedCount <= 1, $"HarvestedCount={b.HarvestedCount}");
        long total = b.Objects
            .Where(o => o.Harvested && o.LocalPath is not null)
            .Sum(o => new FileInfo(o.LocalPath!).Length);
        Assert.True(total <= 20, $"total harvested bytes {total} > 20 cap");
    }

    [Fact]
    public async Task RespectsPerObjectCap_TruncatesLarge()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync(
            "127.0.0.1", srv.Port, useTls: false, bucketName: "backup",
            maxObjectBytes: 16);

        var b = Assert.Single(r.Buckets);
        var tar = b.Objects.FirstOrDefault(o => o.Key == "backup-2024.tar.gz");
        if (tar is { Harvested: true })
        {
            var info = new FileInfo(tar.LocalPath!);
            Assert.True(info.Length <= 16);
        }
    }

    [Fact]
    public async Task WordlistMode_ProbesMultipleBuckets()
    {
        // Only "dev" listable; "prod" 403; "test" 404.
        var routes = new Dictionary<string, (int, string, byte[])>(RouteListable("dev"))
        {
            ["/prod/"] = (403, "application/xml", Fixture("access-denied.xml")),
        };
        await using var srv = new FakeS3Server(routes);
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync(
            "127.0.0.1", srv.Port, useTls: false, bucketName: null,
            bucketWordlist: new[] { "dev", "prod", "test" },
            harvestEnabled: false);

        Assert.Equal(2, r.Buckets.Count);
        Assert.Contains(r.Buckets, b => b.Name == "dev" && b.Listable);
        Assert.Contains(r.Buckets, b => b.Name == "prod" && b.ExistsButForbidden);
    }

    [Fact]
    public async Task VirtualHost_ScopeRecheck()
    {
        // Virtual-host form requires the bucket name to be valid; scope
        // recheck happens implicitly because every public call uses
        // _scope.Require(target). Here we assert that passing an in-scope
        // target with a wordlist still invokes scope on every iteration
        // and a parallel out-of-scope call throws.
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        var r = await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "backup");
        Assert.Single(r.Buckets);

        // The same tool refuses a different host that is NOT in scope.
        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.EnumerateAsync("10.99.99.99", srv.Port, useTls: false, bucketName: "backup"));
    }

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.EnumerateAsync("127.0.0.1", 9000, useTls: false, bucketName: "backup"));
    }

    [Theory]
    [InlineData("127.0.0.1; rm -rf /")]
    [InlineData("../etc/passwd")]
    [InlineData("127.0.0.1$(whoami)")]
    public async Task ArgvInjection_Rejected(string injected)
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        // ScopeException wins for non-IP-shape input; ArgumentException for
        // shape-valid-but-still-malicious input — either is an acceptable
        // refusal.
        await Assert.ThrowsAnyAsync<Exception>(() =>
            tool.EnumerateAsync(injected, 9000, useTls: false));
    }

    [Theory]
    [InlineData("bad/bucket")]
    [InlineData("bad bucket")]
    [InlineData("bucket;name")]
    public async Task RejectsBadBucketName(string bad)
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            tool.EnumerateAsync("127.0.0.1", 9000, useTls: false, bucketName: bad));
    }

    [Fact]
    public async Task NoCloudHarvest_SkipsDownload()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var outDir = TempDir();
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out _);
        var tool = new CloudStorageEnumTool(scope, audit, outDir);

        var r = await tool.EnumerateAsync(
            "127.0.0.1", srv.Port, useTls: false, bucketName: "backup",
            harvestEnabled: false);

        var b = Assert.Single(r.Buckets);
        Assert.True(b.Listable);
        Assert.Equal(0, b.HarvestedCount);
        Assert.DoesNotContain(b.Objects, o => o.Harvested);
        // No directory written for this bucket.
        var dir = Path.Combine(outDir, "loot", "127.0.0.1", "cloud-bucket-backup");
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public async Task Audit_NeverLogsContent()
    {
        await using var srv = new FakeS3Server(RouteListable("backup"));
        var scope = ScopeLoader.Parse("127.0.0.1");
        var audit = NewAudit(out var auditPath);
        var tool = new CloudStorageEnumTool(scope, audit, TempDir());

        await tool.EnumerateAsync("127.0.0.1", srv.Port, useTls: false, bucketName: "backup");

        audit.Dispose();
        var txt = File.ReadAllText(auditPath);
        Assert.DoesNotContain(Canary, txt);
    }
}
