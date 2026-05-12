using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Ops.FlagSubmission;
using Xunit;

namespace Drederick.Tests.Ops.FlagSubmission;

public class HtbFlagClientTests
{
    private const string Token = "htb_test_token_canary_aaaaaaaaaaaaa";
    private const string CanaryFlag = "HTB{plaintext_canary_must_never_appear}";

    private static TimeSpan[] FastRetries => new[]
    {
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
    };

    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(AppContext.BaseDirectory,
            $"htb-flag-audit-{Guid.NewGuid():N}.jsonl");
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
            // Bind to ephemeral port via a HttpListener quirk: pick port at random.
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
                    ?? (200, "{\"message\":\"OK\"}");
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

    private static HtbFlagClient NewClient(FakeServer srv, AuditLog audit, TimeSpan? minInterval = null)
        => new(
            token: Token,
            audit: audit,
            http: new HttpClient(),
            baseUrl: srv.BaseUrl,
            allowedScheme: "http",
            minInterval: minInterval ?? TimeSpan.FromMilliseconds(1),
            retryDelays: FastRetries);

    [Fact]
    public async Task Htb_Machine_Submission_Success()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, r, _) =>
        {
            Assert.EndsWith("/api/v4/machine/own", r.Url!.AbsolutePath);
            Assert.Equal("POST", r.HttpMethod);
            return (200, "{\"message\":\"Hack The Box | Owned!\"}");
        };
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitMachineFlagAsync(42, "HTB{test_flag_v1}", 30);

        Assert.True(result.Success);
        Assert.Equal(200, result.ResponseCode);
        Assert.Equal("htb", result.Platform);
        Assert.Equal(42, result.TargetId);
        Assert.Equal("machine", result.Kind);
        Assert.NotEmpty(result.FlagSha256);
        // Payload was JSON with flag/id/difficulty
        var body = JsonDocument.Parse(srv.RequestBodies[0]).RootElement;
        Assert.Equal(42, body.GetProperty("id").GetInt32());
        Assert.Equal(30, body.GetProperty("difficulty").GetInt32());
        Assert.Equal("HTB{test_flag_v1}", body.GetProperty("flag").GetString());

        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task Htb_Challenge_Submission_Success()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, r, _) =>
        {
            Assert.EndsWith("/api/v4/challenge/own", r.Url!.AbsolutePath);
            return (200, "{\"message\":\"Correct\"}");
        };
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitChallengeFlagAsync(7, "HTB{challenge_flag}");
        Assert.True(result.Success);
        Assert.Equal("challenge", result.Kind);
        Assert.Equal(7, result.TargetId);

        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task RateLimit_Honored_BetweenSubmissions()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (200, "{\"message\":\"OK\"}");
        using var audit = NewAudit(out var path);
        var minInterval = TimeSpan.FromMilliseconds(200);
        using var client = new HtbFlagClient(
            token: Token, audit: audit, http: new HttpClient(),
            baseUrl: srv.BaseUrl, allowedScheme: "http",
            minInterval: minInterval, retryDelays: FastRetries);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await client.SubmitMachineFlagAsync(1, "HTB{a}", 50);
        await client.SubmitMachineFlagAsync(2, "HTB{b}", 50);
        sw.Stop();

        Assert.True(sw.Elapsed >= minInterval,
            $"expected >= {minInterval}, got {sw.Elapsed}");

        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task RetryOn_429_With_Backoff()
    {
        using var srv = new FakeServer();
        srv.Responder = (n, _, _) => n switch
        {
            0 => (429, "{\"message\":\"slow down\"}"),
            1 => (429, "{\"message\":\"slow down\"}"),
            _ => (200, "{\"message\":\"OK\"}"),
        };
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitMachineFlagAsync(99, "HTB{retry}", 50);

        Assert.True(result.Success);
        Assert.True(srv.Requests.Count >= 3, $"expected ≥3 attempts, got {srv.Requests.Count}");
        // Audit must contain at least one backoff record.
        var auditText = File.ReadAllText(path);
        Assert.Contains("flag.submit.backoff", auditText);
        audit.Dispose();
        File.Delete(path);
    }

    [Fact]
    public async Task Audit_NeverLogs_PlaintextFlag()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (200, "{\"message\":\"OK\"}");
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        await client.SubmitMachineFlagAsync(1, CanaryFlag, 50);
        audit.Dispose();

        var auditText = File.ReadAllText(path);
        Assert.DoesNotContain(CanaryFlag, auditText);
        Assert.DoesNotContain("plaintext_canary_must_never_appear", auditText);
        // Hash must be present.
        Assert.Contains(FlagSubmissionResult.Sha256Hex(CanaryFlag), auditText);

        File.Delete(path);
    }

    [Fact]
    public async Task Audit_NeverLogs_AuthorizationHeader()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (200, "{\"message\":\"OK\"}");
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        await client.SubmitMachineFlagAsync(1, "HTB{x}", 50);
        audit.Dispose();

        var auditText = File.ReadAllText(path);
        Assert.DoesNotContain(Token, auditText);
        Assert.DoesNotContain("Bearer", auditText);
        File.Delete(path);

        // And confirm the server actually got the bearer (test integrity).
        Assert.NotNull(srv.AuthHeaders[0]);
        Assert.StartsWith("Bearer ", srv.AuthHeaders[0]);
    }

    [Fact]
    public void Refuses_Non_Https_In_Production_Mode()
    {
        using var audit = NewAudit(out var path);
        try
        {
            Assert.Throws<InvalidOperationException>(() =>
                new HtbFlagClient(token: Token, audit: audit, baseUrl: "http://www.hackthebox.com"));
        }
        finally
        {
            audit.Dispose();
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task Persists_Submission_Result_To_SqliteAndJson()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (200, "{\"message\":\"OK\"}");
        using var audit = NewAudit(out var auditPath);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitMachineFlagAsync(123, "HTB{persist}", 50);

        var dir = Path.Combine(AppContext.BaseDirectory, $"flag-persist-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var jsonPath = Path.Combine(dir, "flag-submissions.json");
        var dbPath = Path.Combine(dir, "findings.db");
        FlagSubmissionResult.AppendToJson(jsonPath, result);
        FlagSubmissionResult.PersistToSqlite(dbPath, result);
        // Idempotent re-insert:
        FlagSubmissionResult.PersistToSqlite(dbPath, result);

        Assert.True(File.Exists(jsonPath));
        var loaded = JsonSerializer.Deserialize<List<FlagSubmissionResult>>(File.ReadAllText(jsonPath))!;
        Assert.Single(loaded);
        Assert.Equal(result.FlagSha256, loaded[0].FlagSha256);

        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={dbPath}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM flag_submissions";
            var n = Convert.ToInt32(cmd.ExecuteScalar());
            Assert.Equal(1, n); // unique constraint enforced
        }

        audit.Dispose();
        File.Delete(auditPath);
        Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void FlagSubmissionResult_Json_Roundtrip()
    {
        var r = new FlagSubmissionResult
        {
            Platform = "htb",
            Success = true,
            ResponseCode = 200,
            Message = "Owned",
            FlagSha256 = FlagSubmissionResult.Sha256Hex("HTB{rt}"),
            SubmittedAt = DateTimeOffset.UtcNow,
            TargetId = 5,
            Kind = "machine",
        };
        var json = JsonSerializer.Serialize(r);
        var back = JsonSerializer.Deserialize<FlagSubmissionResult>(json)!;
        Assert.Equal(r.Platform, back.Platform);
        Assert.Equal(r.Success, back.Success);
        Assert.Equal(r.ResponseCode, back.ResponseCode);
        Assert.Equal(r.Message, back.Message);
        Assert.Equal(r.FlagSha256, back.FlagSha256);
        Assert.Equal(r.TargetId, back.TargetId);
        Assert.Equal(r.Kind, back.Kind);
    }

    [Fact]
    public async Task ResponseError_4xx_RecordedAsFailure()
    {
        using var srv = new FakeServer();
        srv.Responder = (_, _, _) => (400, "{\"message\":\"Invalid flag\"}");
        using var audit = NewAudit(out var path);
        using var client = NewClient(srv, audit);

        var result = await client.SubmitMachineFlagAsync(1, "HTB{bad}", 50);
        Assert.False(result.Success);
        Assert.Equal(400, result.ResponseCode);
        Assert.Equal("Invalid flag", result.Message);

        audit.Dispose();
        File.Delete(path);
    }
}
