using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Ctfd;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Jeopardy.Ctfd;

public class CtfdClientTests
{
    private const string Token = "ctfd_dummy_token_0123456789abcdef";

    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(
            AppContext.BaseDirectory,
            $"ctfd-audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static Scope.Scope InScope() => ScopeLoader.Parse("10.10.10.5");

    private static TimeSpan[] FastRetries => new[]
    {
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
        TimeSpan.FromMilliseconds(1),
    };

    private static string FixturePath(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(
                dir, "tests", "Drederick.Tests", "Jeopardy", "Fixtures", name);
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"Fixture not found: {name}");
    }

    private static string LoadFixture(string name) => File.ReadAllText(FixturePath(name));

    private static HttpResponseMessage Json(int code, string body) =>
        new((HttpStatusCode)code)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

    private sealed class StubHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } = _ => Json(200, "{}");
        public List<HttpRequestMessage> Requests { get; } = new();
        public int CallCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            lock (Requests) Requests.Add(request);
            return Task.FromResult(Responder(request));
        }
    }

    private static CtfdClient NewClient(StubHandler handler, Scope.Scope? scope = null)
    {
        var http = new HttpClient(handler);
        var audit = NewAudit(out _);
        return new CtfdClient(
            new Uri("http://10.10.10.5:8000/"),
            Token,
            scope ?? InScope(),
            audit,
            http,
            maxConcurrency: 4,
            retryDelays: FastRetries);
    }

    [Fact]
    public void Constructor_OutOfScope_Throws_ScopeException()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var audit = NewAudit(out _);
        var handler = new StubHandler();
        using var http = new HttpClient(handler);
        Assert.Throws<ScopeException>(() =>
            new CtfdClient(
                new Uri("http://192.168.99.1/"),
                Token, scope, audit, http, retryDelays: FastRetries));
        audit.Dispose();
    }

    [Fact]
    public async Task ListChallengesAsync_ParsesFixture()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_list.json")),
        };
        using var client = NewClient(handler);
        var list = await client.ListChallengesAsync(CancellationToken.None);

        Assert.Equal(2, list.Count);
        Assert.Equal("Pwn Me", list[0].Name);
        Assert.Equal("pwn", list[0].Category);
        Assert.Equal(200, list[0].Value);
        Assert.False(list[0].Solved);
        Assert.Contains("beginner", list[0].Tags);
        Assert.Equal("crypto", list[1].Category);
        Assert.True(list[1].Solved);
        Assert.Contains("rsa", list[1].Tags);
    }

    [Fact]
    public async Task GetChallengeAsync_ParsesFilesTagsConnection()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_chal_42.json")),
        };
        using var client = NewClient(handler);
        var chal = await client.GetChallengeAsync(42, CancellationToken.None);

        Assert.Equal(42, chal.Id);
        Assert.Equal("pwn", chal.Category);
        Assert.Equal("nc ctf.example.com 1337", chal.ConnectionInfo);
        Assert.Equal(2, chal.Files.Count);
        Assert.Equal("chall.bin", chal.Files[0].Name);
        Assert.Equal("libc.so.6", chal.Files[1].Name);
        Assert.Equal(2048, chal.Files[1].SizeBytes);
        Assert.Contains("format-string", chal.Tags);
        // HTML stripped, but <pre>/<code> body preserved.
        Assert.Contains("find the flag", chal.Description);
        Assert.Contains("printf(user_input);", chal.Description);
        Assert.DoesNotContain("<b>", chal.Description);
        Assert.DoesNotContain("<pre>", chal.Description);
    }

    [Fact]
    public async Task SubmitFlagAsync_Correct()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_submit_correct.json")),
        };
        using var client = NewClient(handler);
        var result = await client.SubmitFlagAsync(1, "flag{real}", CancellationToken.None);
        Assert.True(result.Correct);
        Assert.False(result.AlreadySolved);
        Assert.Equal("Correct", result.Message);
    }

    [Fact]
    public async Task SubmitFlagAsync_Incorrect()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_submit_incorrect.json")),
        };
        using var client = NewClient(handler);
        var result = await client.SubmitFlagAsync(1, "flag{wrong}", CancellationToken.None);
        Assert.False(result.Correct);
        Assert.False(result.AlreadySolved);
        Assert.Equal("Nope, try again.", result.Message);
    }

    [Fact]
    public async Task SubmitFlagAsync_AlreadySolved()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_submit_already.json")),
        };
        using var client = NewClient(handler);
        var result = await client.SubmitFlagAsync(1, "flag{dup}", CancellationToken.None);
        Assert.True(result.AlreadySolved);
    }

    [Fact]
    public async Task SubmitFlagAsync_Duplicate_ShortCircuits()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_submit_correct.json")),
        };
        using var client = NewClient(handler);
        var r1 = await client.SubmitFlagAsync(7, "flag{dedupe}", CancellationToken.None);
        var callsAfterFirst = handler.CallCount;
        var r2 = await client.SubmitFlagAsync(7, "flag{dedupe}", CancellationToken.None);
        Assert.True(r1.Correct);
        Assert.True(r2.AlreadySolved);
        Assert.Equal(callsAfterFirst, handler.CallCount); // no second HTTP call
    }

    [Fact]
    public async Task Retries_429_Then_Succeeds()
    {
        int n = 0;
        var handler = new StubHandler
        {
            Responder = _ =>
            {
                n++;
                return n < 2
                    ? Json(429, "{\"error\":\"rate\"}")
                    : Json(200, LoadFixture("ctfd_list.json"));
            },
        };
        using var client = NewClient(handler);
        var list = await client.ListChallengesAsync(CancellationToken.None);
        Assert.Equal(2, list.Count);
        Assert.True(handler.CallCount >= 2);
    }

    [Fact]
    public async Task Persistent_5xx_Throws_After_Retries()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(503, "{\"error\":\"down\"}"),
        };
        using var client = NewClient(handler);
        await Assert.ThrowsAsync<CtfdException>(
            () => client.ListChallengesAsync(CancellationToken.None));
        Assert.Equal(3, handler.CallCount);
    }

    [Fact]
    public async Task TokenRedaction_HidesTokenInException()
    {
        var handler = new StubHandler
        {
            // Return a 400 body containing the token; the client constructs
            // the error message from its own path/status and must redact.
            Responder = _ => Json(400, $"{{\"token\":\"{Token}\"}}"),
        };
        // Build client with our probe handler that surfaces the token via
        // an HttpRequestException path to verify redact wraps it.
        var scope = InScope();
        var auditPath = Path.Combine(
            AppContext.BaseDirectory, $"ctfd-audit-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(auditPath);

        var raising = new StubHandler
        {
            Responder = _ => throw new HttpRequestException(
                $"boom contacting server with Token {Token}"),
        };
        using var http = new HttpClient(raising);
        using var client = new CtfdClient(
            new Uri("http://10.10.10.5:8000/"), Token, scope, audit, http,
            retryDelays: FastRetries);
        var ex = await Assert.ThrowsAsync<CtfdException>(
            () => client.ListChallengesAsync(CancellationToken.None));
        Assert.DoesNotContain(Token, ex.Message);
        audit.Dispose();
        // Audit file must not contain the raw token either (redacted).
        var content = File.ReadAllText(auditPath);
        Assert.DoesNotContain(Token, content);
        Assert.Contains("[REDACTED]", content);
    }

    [Fact]
    public async Task SubmitFlag_Canary_NotInAudit()
    {
        const string canary = "flag{canary_ctfd_tok}";
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_submit_incorrect.json")),
        };
        var scope = InScope();
        var auditPath = Path.Combine(
            AppContext.BaseDirectory, $"ctfd-canary-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(auditPath);
        using var http = new HttpClient(handler);
        using (var client = new CtfdClient(
            new Uri("http://10.10.10.5:8000/"), Token, scope, audit, http,
            retryDelays: FastRetries))
        {
            await client.SubmitFlagAsync(9, canary, CancellationToken.None);
        }
        audit.Dispose();

        var content = File.ReadAllText(auditPath);
        Assert.DoesNotContain(canary, content);
        // SHA-256 of canary must be recorded instead.
        using var sha = System.Security.Cryptography.SHA256.Create();
        var digest = Convert.ToHexString(
            sha.ComputeHash(Encoding.UTF8.GetBytes(canary))).ToLowerInvariant();
        Assert.Contains(digest, content);
    }

    [Fact]
    public async Task Attachment_Exceeds_Cap_Throws()
    {
        // Stream a body whose declared Content-Length exceeds the cap,
        // with content that would also exceed if streamed.
        var bigContent = new StreamContent(new InfiniteZeroStream(
            (long)(CtfdClient.MaxAttachmentBytes + 1024)));
        bigContent.Headers.ContentLength = CtfdClient.MaxAttachmentBytes + 1024;
        var handler = new StubHandler
        {
            Responder = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = bigContent },
        };
        using var client = NewClient(handler);
        var file = new CtfdAttachment("big.bin", "/files/big.bin", null);
        await Assert.ThrowsAsync<CtfdException>(
            () => client.DownloadAttachmentAsync(file, CancellationToken.None));
    }

    [Fact]
    public async Task Attachment_StreamOverflow_Throws_When_ContentLength_Unknown()
    {
        // No declared Content-Length; client must still abort while streaming.
        var handler = new StubHandler
        {
            Responder = _ =>
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StreamContent(new InfiniteZeroStream(
                        CtfdClient.MaxAttachmentBytes + 4096)),
                };
                resp.Content.Headers.ContentLength = null;
                return resp;
            },
        };
        using var client = NewClient(handler);
        var file = new CtfdAttachment("bigger.bin", "/files/bigger.bin", null);
        await Assert.ThrowsAsync<CtfdException>(
            () => client.DownloadAttachmentAsync(file, CancellationToken.None));
    }

    [Fact]
    public async Task Scoreboard_Parses_Fixture()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_scoreboard.json")),
        };
        using var client = NewClient(handler);
        var board = await client.GetScoreboardAsync(CancellationToken.None);
        Assert.Equal(5, board.Count);
        Assert.Equal(1, board[0].Rank);
        Assert.Equal("team-alpha", board[0].Name);
        Assert.Equal(4200, board[0].Score);
        Assert.Equal(10, board[0].TeamId);
    }

    [Fact]
    public async Task AuthorizationHeader_UsesTokenScheme()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, LoadFixture("ctfd_list.json")),
        };
        using var client = NewClient(handler);
        _ = await client.ListChallengesAsync(CancellationToken.None);
        var auth = handler.Requests[0].Headers.GetValues("Authorization").Single();
        Assert.StartsWith("Token ", auth);
        Assert.DoesNotContain("Bearer", auth);
        Assert.EndsWith(Token, auth);
    }

    [Fact]
    public async Task Attachment_AbsoluteExternalUrl_OutOfScope_Throws()
    {
        var handler = new StubHandler
        {
            Responder = _ => Json(200, "ignored"),
        };
        using var client = NewClient(handler);
        // Attachment hosted on an out-of-scope S3-style domain resolves to a
        // different host that must fail scope validation.
        var file = new CtfdAttachment(
            "leaked.zip", "http://203.0.113.7/bucket/leaked.zip", null);
        await Assert.ThrowsAsync<ScopeException>(
            () => client.DownloadAttachmentAsync(file, CancellationToken.None));
        Assert.Equal(0, handler.CallCount);
    }

    private sealed class InfiniteZeroStream : Stream
    {
        private long _remaining;
        public InfiniteZeroStream(long length) { _remaining = length; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _remaining;
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0) return 0;
            int n = (int)Math.Min(count, _remaining);
            Array.Clear(buffer, offset, n);
            _remaining -= n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
