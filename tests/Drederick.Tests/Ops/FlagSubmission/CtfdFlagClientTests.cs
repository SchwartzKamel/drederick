using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Ops.FlagSubmission;
using Xunit;

namespace Drederick.Tests.Ops.FlagSubmission;

public class CtfdFlagClientTests
{
    private const string Token = "ctfd_test_token_canary_aaaaaaaaaa";
    private const string CanaryFlag = "flag{ctfd_plaintext_canary_xyz}";

    private static TimeSpan[] FastRetries => new[]
    {
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
    };

    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(AppContext.BaseDirectory,
            $"ctfd-flag-audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private sealed class FakeServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        public string BaseUrl { get; }
        public List<HttpListenerRequest> Requests { get; } = new();
        public List<string> RequestBodies { get; } = new();
        public List<string?> AuthHeaders { get; } = new();
        public Func<int, HttpListenerRequest, string, (int code, string body)>? Responder;

        public FakeServer()
        {
            _listener = new HttpListener();
            var port = GetEphemeralPort();
            BaseUrl = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(BaseUrl + "/");
            _listener.Start();
            _ = Task.Run(LoopAsync);
        }

        private static int GetEphemeralPort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var p = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return p;
        }

        private async Task LoopAsync()
        {
            int n = 0;
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { break; }
                var req = ctx.Request;
                Requests.Add(req);
                AuthHeaders.Add(req.Headers["Authorization"]);
                string body;
                using (var sr = new StreamReader(req.InputStream, req.ContentEncoding))
                    body = await sr.ReadToEndAsync();
                RequestBodies.Add(body);

                var (code, respBody) = Responder?.Invoke(n++, req, body)
                    ?? (200, "{\"data\":{\"status\":\"correct\"}}");
                ctx.Response.StatusCode = code;
                var buf = Encoding.UTF8.GetBytes(respBody);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = buf.Length;
                await ctx.Response.OutputStream.WriteAsync(buf, 0, buf.Length);
                ctx.Response.OutputStream.Close();
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }
    }

    private static CtfdFlagClient NewClient(FakeServer srv, AuditLog audit, TimeSpan? minInterval = null)
        => new(
            baseUrl: srv.BaseUrl,
            token: Token,
            audit: audit,
            http: new HttpClient(),
            allowedScheme: "http",
            minInterval: minInterval ?? TimeSpan.FromMilliseconds(1),
            retryDelays: FastRetries);

    [Fact]
    public async Task Ctfd_Submit_Success()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, r, _) =>
        {
            Assert.EndsWith("/api/v1/challenges/attempt", r.Url!.AbsolutePath);
            return (200, "{\"data\":{\"status\":\"correct\",\"message\":\"Correct\"}}");
        };
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitFlagAsync(11, "flag{abc}");
        Assert.True(result.Success);
        Assert.Equal("ctfd", result.Platform);
        Assert.Equal(11, result.TargetId);
        var body = JsonDocument.Parse(srv.RequestBodies[0]).RootElement;
        Assert.Equal(11, body.GetProperty("challenge_id").GetInt32());
        Assert.Equal("flag{abc}", body.GetProperty("submission").GetString());
        Assert.StartsWith("Token ", srv.AuthHeaders[0]);

        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task Ctfd_ListChallenges_Returns_Parsed_Catalog()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) =>
            (200, "{\"data\":[" +
                  "{\"id\":1,\"name\":\"baby-rsa\",\"category\":\"crypto\",\"value\":50}," +
                  "{\"id\":2,\"name\":\"sql-101\",\"category\":\"web\",\"value\":100}" +
                  "]}");
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var list = await client.ListChallengesAsync();
        Assert.Equal(2, list.Count);
        Assert.Equal(1, list[0].Id);
        Assert.Equal("baby-rsa", list[0].Name);
        Assert.Equal("crypto", list[0].Category);
        Assert.Equal(50, list[0].Value);

        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task RetryOn_429_With_Backoff()
    {
        using var srv = new FakeServer();
        srv.Responder = (n, _, _) => n switch
        {
            0 => (429, "{\"data\":{\"status\":\"ratelimit\"}}"),
            _ => (200, "{\"data\":{\"status\":\"correct\"}}"),
        };
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitFlagAsync(5, "flag{x}");
        Assert.True(result.Success);
        Assert.True(srv.Requests.Count >= 2);
        var auditText = File.ReadAllText(path);
        Assert.Contains("flag.submit.backoff", auditText);
        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task Audit_NeverLogs_PlaintextFlag()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (200, "{\"data\":{\"status\":\"correct\"}}");
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        await client.SubmitFlagAsync(1, CanaryFlag);
        audit.Dispose();

        var auditText = File.ReadAllText(path);
        Assert.DoesNotContain(CanaryFlag, auditText);
        Assert.DoesNotContain("ctfd_plaintext_canary_xyz", auditText);
        Assert.Contains(FlagSubmissionResult.Sha256Hex(CanaryFlag), auditText);
        File.Delete(path);
    }

    [Fact]
    public void Refuses_Non_Https_In_Production_Mode()
    {
        using var audit = NewAudit(out var path);
        try
        {
            Assert.Throws<InvalidOperationException>(() =>
                new CtfdFlagClient(baseUrl: "http://ctf.example", token: Token, audit: audit));
        }
        finally
        {
            audit.Dispose();
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
