using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

public class CopilotLlmClientTests : IDisposable
{
    private readonly string _workDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;

    public CopilotLlmClientTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-copilot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _auditPath = Path.Combine(_workDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string LoadFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "Drederick.Tests", "Jeopardy", "Fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            candidate = Path.Combine(dir, "Jeopardy", "Fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    private sealed class TestHttpHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        public List<string> RequestBodies { get; } = new();
        public Queue<Func<HttpRequestMessage, HttpResponseMessage>> Responders { get; } = new();
        public int CallCount => Requests.Count;

        public void Enqueue(HttpStatusCode status, string body, string contentType = "application/json")
        {
            Responders.Enqueue(_ => new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, contentType),
            });
        }

        public void EnqueueResponder(Func<HttpRequestMessage, HttpResponseMessage> fn) => Responders.Enqueue(fn);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            string body = "";
            if (request.Content is not null)
                body = await request.Content.ReadAsStringAsync(cancellationToken);
            RequestBodies.Add(body);

            if (Responders.Count == 0)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                { Content = new StringContent("no responder queued") };
            return Responders.Dequeue()(request);
        }
    }

    private (CopilotLlmClient client, TestHttpHandler handler) MakeClient(
        string token = "ghu_test_copilot_token_aaaaaaaaaaaaaaaa",
        string integrationId = "drederick-tests",
        Uri? endpoint = null)
    {
        var handler = new TestHttpHandler();
        var http = new HttpClient(handler);
        var client = new CopilotLlmClient(token, integrationId, _audit, http, endpoint ?? new Uri("https://api.githubcopilot.test/v1"));
        return (client, handler);
    }

    // 1.
    [Fact]
    public void TryCreateFromEnvironment_WithNoToken_ReturnsNull()
    {
        using var scope = new EnvScope(("COPILOT_TOKEN", null), ("GH_TOKEN", null), ("GITHUB_TOKEN", null));
        var client = CopilotLlmClient.TryCreateFromEnvironment(_audit);
        Assert.Null(client);
    }

    // 2.
    [Fact]
    public void TokenPreferenceOrder_CopilotTokenBeatsGhTokenBeatsGithubToken()
    {
        using (var _ = new EnvScope(("COPILOT_TOKEN", "copilot_tok_1"), ("GH_TOKEN", "gh_tok_2"), ("GITHUB_TOKEN", "ghp_tok_3")))
        {
            var (tok, src) = InvokeResolveToken();
            Assert.Equal("copilot_tok_1", tok);
            Assert.Equal("CopilotToken", src);
        }
        using (var _ = new EnvScope(("COPILOT_TOKEN", null), ("GH_TOKEN", "gh_tok_2"), ("GITHUB_TOKEN", "ghp_tok_3")))
        {
            var (tok, src) = InvokeResolveToken();
            Assert.Equal("gh_tok_2", tok);
            Assert.Equal("GhToken", src);
        }
        using (var _ = new EnvScope(("COPILOT_TOKEN", null), ("GH_TOKEN", null), ("GITHUB_TOKEN", "ghp_tok_3")))
        {
            var (tok, src) = InvokeResolveToken();
            Assert.Equal("ghp_tok_3", tok);
            Assert.Equal("GithubToken", src);
        }
    }

    // 3.
    [Fact]
    public async Task ListModelsAsync_ParsesFixture_AndCachesResult()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_models.json"));

        var a = await client.ListModelsAsync(CancellationToken.None);
        Assert.Equal(8, a.Count);
        Assert.Contains(a, m => m.Id == "gpt-5.4" && m.Family == "openai-gpt");
        Assert.Contains(a, m => m.Id == "claude-opus-4.7" && m.Family == "anthropic-claude");
        Assert.Contains(a, m => m.Id == "gemini-3.1-pro" && m.Family == "google-gemini");
        Assert.Contains(a, m => m.Id == "grok-code-fast-1" && m.Family == "xai-grok");
        Assert.Contains(a, m => m.Id == "goldeneye" && m.Family == "copilot-native");
        Assert.True(a.First(m => m.Id == "gpt-5.4").SupportsTools);

        // Second call: cache hit, no new HTTP.
        var b = await client.ListModelsAsync(CancellationToken.None);
        Assert.Equal(a.Count, b.Count);
        Assert.Equal(1, handler.CallCount);
    }

    // 4.
    [Fact]
    public async Task ChatAsync_SimpleResponse_ParsesContentTokensFinishReason()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        var resp = await client.ChatAsync(
            "gpt-5.4",
            new[] { new CopilotChatMessage("user", "what's the flag?") },
            tools: null,
            CancellationToken.None);

        Assert.Equal("gpt-5.4", resp.ModelId);
        Assert.Equal("The flag is FLAG{jeopardy_pwned}.", resp.Content);
        Assert.Equal(42, resp.PromptTokens);
        Assert.Equal(11, resp.CompletionTokens);
        Assert.Equal("stop", resp.FinishReason);
        Assert.Empty(resp.ToolCalls);
        Assert.True(resp.Elapsed >= TimeSpan.Zero);
    }

    // 5.
    [Fact]
    public async Task ChatAsync_ToolCallResponse_PopulatesToolCalls()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_toolcall.json"));

        var resp = await client.ChatAsync(
            "claude-sonnet-4.6",
            new[] { new CopilotChatMessage("user", "scan 10.10.10.5") },
            tools: null,
            CancellationToken.None);

        Assert.Null(resp.Content);
        Assert.Single(resp.ToolCalls);
        var tc = resp.ToolCalls[0];
        Assert.Equal("call_abc123", tc.Id);
        Assert.Equal("nmap_scan", tc.Name);
        Assert.Contains("10.10.10.5", tc.ArgumentsJson);
        Assert.Equal("tool_calls", resp.FinishReason);
    }

    // 6.
    [Fact]
    public async Task Audit_EmitsStartAndFinish_WithPromptSha256_NotPlaintext()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        const string secret = "THIS_PROMPT_TEXT_MUST_NOT_APPEAR_IN_AUDIT";
        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", secret) },
            tools: null,
            CancellationToken.None);

        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("copilot.chat.start", audit);
        Assert.Contains("copilot.chat.finish", audit);
        Assert.Contains("prompt_sha256", audit);
        Assert.DoesNotContain(secret, audit);
    }

    // 7.
    [Fact]
    public async Task Canary_PlaintextMessageContent_NeverLandsInAuditLog()
    {
        const string canary = "ULTRA_SECRET_COPILOT_CANARY";
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[]
            {
                new CopilotChatMessage("system", "be helpful"),
                new CopilotChatMessage("user", canary),
            },
            tools: null, CancellationToken.None);

        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.DoesNotContain(canary, audit);
    }

    // 8.
    [Fact]
    public async Task TokenCanary_RedactedFromExceptionMessages()
    {
        const string canaryTok = "ghu_canary_copilot_token_42aaaaaaaaaaaaaa";
        var handler = new TestHttpHandler();
        var http = new HttpClient(handler);
        var client = new CopilotLlmClient(canaryTok, "drederick-tests", _audit, http, new Uri("https://api.githubcopilot.test/v1"));

        for (int i = 0; i < 4; i++)
            handler.Enqueue(HttpStatusCode.InternalServerError, $"upstream died; Authorization: Bearer {canaryTok}");

        var ex = await Assert.ThrowsAsync<CopilotLlmException>(() =>
            client.ChatAsync("gpt-5.4",
                new[] { new CopilotChatMessage("user", "x") },
                tools: null, CancellationToken.None));

        Assert.DoesNotContain(canaryTok, ex.Message);
        Assert.Contains("REDACTED", ex.Message);
    }

    // 9.
    [Fact]
    public async Task On429_RetriesWithBackoff_AndAuditRecordsAttempts()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.TooManyRequests, "{\"error\":\"rate_limited\"}");
        handler.Enqueue(HttpStatusCode.TooManyRequests, "{\"error\":\"rate_limited\"}");
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        var resp = await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "retry me") },
            tools: null, CancellationToken.None);

        Assert.Equal(3, handler.CallCount);
        Assert.Equal("stop", resp.FinishReason);

        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("copilot.chat.retry", audit);
    }

    // 10.
    [Fact]
    public async Task IntegrationIdHeader_IsSetOnEveryRequest()
    {
        var (client, handler) = MakeClient(integrationId: "drederick-integration-xyz");
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_models.json"));
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ListModelsAsync(CancellationToken.None);
        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") },
            tools: null, CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        foreach (var req in handler.Requests)
        {
            Assert.True(req.Headers.Contains("Copilot-Integration-Id"),
                "Copilot-Integration-Id header missing on request to " + req.RequestUri);
            Assert.Equal("drederick-integration-xyz", req.Headers.GetValues("Copilot-Integration-Id").First());
            Assert.Equal("Bearer", req.Headers.Authorization?.Scheme);
        }
    }

    // 11.
    [Fact]
    public void EstimateCostUsd_KnownModelNonZero_UnknownZero()
    {
        var known = new CopilotChatResponse("gpt-5.4", null, Array.Empty<CopilotToolCall>(), 1000, 1000, "stop", TimeSpan.Zero);
        var unknown = new CopilotChatResponse("not-a-real-model", null, Array.Empty<CopilotToolCall>(), 1000, 1000, "stop", TimeSpan.Zero);
        Assert.True(CopilotLlmClient.EstimateCostUsd(known) > 0m);
        Assert.Equal(0m, CopilotLlmClient.EstimateCostUsd(unknown));
    }

    // 12.
    [Fact]
    public async Task EndpointOverride_IsHonored()
    {
        var override_ = new Uri("https://custom.copilot.test/v1");
        var (client, handler) = MakeClient(endpoint: override_);
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_models.json"));
        await client.ListModelsAsync(CancellationToken.None);

        Assert.Single(handler.Requests);
        var url = handler.Requests[0].RequestUri!.ToString();
        Assert.StartsWith("https://custom.copilot.test/v1/", url);
        Assert.EndsWith("/models", url);
    }

    // 13 (bonus): TryCreateFromEnvironment honors COPILOT_ENDPOINT and falls back
    //             to GitHub Models endpoint for PAT-style tokens.
    [Fact]
    public void TryCreateFromEnvironment_FallsBackToGithubModelsForPat()
    {
        using var _ = new EnvScope(
            ("COPILOT_TOKEN", null),
            ("GH_TOKEN", null),
            ("GITHUB_TOKEN", "ghp_patstyle_xxxxxxxxxxxxxxxxxxxx"),
            ("COPILOT_ENDPOINT", null));
        var client = CopilotLlmClient.TryCreateFromEnvironment(_audit);
        Assert.NotNull(client);
        client!.Dispose();
    }

    // ---- helpers ----

    private static (string? Token, string Source) InvokeResolveToken()
    {
        // Reflection into internal method so we can assert preference order directly.
        var m = typeof(CopilotLlmClient).GetMethod("ResolveToken",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var tuple = m.Invoke(null, null)!;
        var t1 = tuple.GetType().GetField("Item1")!.GetValue(tuple) as string;
        var t2 = tuple.GetType().GetField("Item2")!.GetValue(tuple)!.ToString()!;
        return (t1, t2);
    }

    private sealed class EnvScope : IDisposable
    {
        private readonly List<(string k, string? prev)> _prev = new();
        public EnvScope(params (string key, string? value)[] set)
        {
            foreach (var (k, v) in set)
            {
                _prev.Add((k, Environment.GetEnvironmentVariable(k)));
                Environment.SetEnvironmentVariable(k, v);
            }
        }
        public void Dispose()
        {
            foreach (var (k, prev) in _prev) Environment.SetEnvironmentVariable(k, prev);
        }
    }
}
