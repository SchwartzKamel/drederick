using System.Net;
using System.Net.Sockets;
using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

public class LlamaCppLlmClientTests : IDisposable
{
    private readonly string _workDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;

    public LlamaCppLlmClientTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-llamacpp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _auditPath = Path.Combine(_workDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private const string SimpleChatResponse = """
    {
      "id": "chatcmpl-llamacpp-1",
      "object": "chat.completion",
      "model": "qwen2.5-coder-32b",
      "choices": [
        { "index": 0, "message": { "role": "assistant", "content": "The answer is 42." }, "finish_reason": "stop" }
      ],
      "usage": { "prompt_tokens": 17, "completion_tokens": 5, "total_tokens": 22 }
    }
    """;

    private const string ChatResponseNoUsage = """
    {
      "id": "chatcmpl-llamacpp-2",
      "object": "chat.completion",
      "model": "tinyllama",
      "choices": [
        { "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }
      ]
    }
    """;

    private const string ModelsResponse = """
    {
      "object": "list",
      "data": [
        { "id": "qwen2.5-coder-32b", "object": "model" },
        { "id": "deepseek-coder-v2", "object": "model" }
      ]
    }
    """;

    private sealed class TestHttpHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        public List<string> RequestBodies { get; } = new();
        public Queue<Func<HttpRequestMessage, HttpResponseMessage>> Responders { get; } = new();
        public Func<HttpRequestMessage, Exception>? Thrower { get; set; }

        public void Enqueue(HttpStatusCode status, string body)
        {
            Responders.Enqueue(_ => new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            string body = "";
            if (request.Content is not null)
                body = await request.Content.ReadAsStringAsync(cancellationToken);
            RequestBodies.Add(body);

            if (Thrower is not null) throw Thrower(request);
            if (Responders.Count == 0)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("no responder") };
            return Responders.Dequeue()(request);
        }
    }

    private (LlamaCppLlmClient client, TestHttpHandler handler) MakeClient(
        IReadOnlyList<LlamaCppModelConfig>? models = null,
        string? bearerToken = null,
        Uri? baseUrl = null)
    {
        var handler = new TestHttpHandler();
        var http = new HttpClient(handler);
        var client = new LlamaCppLlmClient(
            baseUrl ?? new Uri("http://127.0.0.1:8080"),
            _audit,
            models,
            bearerToken,
            http);
        return (client, handler);
    }

    // 1.
    [Fact]
    public async Task ChatAsync_PostsToCorrectUrl_AndParsesResponse()
    {
        var (client, handler) = MakeClient(
            models: new[] { new LlamaCppModelConfig("qwen2.5-coder-32b", SupportsTools: false, ContextWindow: 32768) });
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        var resp = await client.ChatAsync(
            "qwen2.5-coder-32b",
            new[] { new CopilotChatMessage("user", "ping?") },
            tools: null,
            CancellationToken.None);

        Assert.Single(handler.Requests);
        var url = handler.Requests[0].RequestUri!.ToString();
        Assert.Equal("http://127.0.0.1:8080/v1/chat/completions", url);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("The answer is 42.", resp.Content);
        Assert.Equal("stop", resp.FinishReason);
        Assert.Equal(17, resp.PromptTokens);
        Assert.Equal(5, resp.CompletionTokens);
    }

    // 2.
    [Fact]
    public async Task NoBearerToken_MeansNoAuthorizationHeader()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        await client.ChatAsync("qwen2.5-coder-32b",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        Assert.Null(handler.Requests[0].Headers.Authorization);
    }

    // 3.
    [Fact]
    public async Task BearerToken_SetsAuthorizationHeader()
    {
        var (client, handler) = MakeClient(bearerToken: "secret-proxy-tok");
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        await client.ChatAsync("qwen2.5-coder-32b",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        var auth = handler.Requests[0].Headers.Authorization;
        Assert.NotNull(auth);
        Assert.Equal("Bearer", auth!.Scheme);
        Assert.Equal("secret-proxy-tok", auth.Parameter);
    }

    // 4.
    [Fact]
    public async Task ToolsStripped_WhenModelSupportsToolsFalse()
    {
        var tool = Microsoft.Extensions.AI.AIFunctionFactory.Create(
            (string target) => "ok", name: "nmap_scan", description: "scan a host");
        var (client, handler) = MakeClient(
            models: new[] { new LlamaCppModelConfig("notools-model", SupportsTools: false, ContextWindow: null) });
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        await client.ChatAsync("notools-model",
            new[] { new CopilotChatMessage("user", "scan") },
            tools: new[] { tool },
            CancellationToken.None);

        var body = handler.RequestBodies[0];
        Assert.DoesNotContain("\"tools\"", body);
        Assert.DoesNotContain("nmap_scan", body);
    }

    // 5.
    [Fact]
    public async Task ToolsForwarded_WhenModelSupportsToolsTrue()
    {
        var tool = Microsoft.Extensions.AI.AIFunctionFactory.Create(
            (string target) => "ok", name: "nmap_scan", description: "scan a host");
        var (client, handler) = MakeClient(
            models: new[] { new LlamaCppModelConfig("tools-model", SupportsTools: true, ContextWindow: null) });
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        await client.ChatAsync("tools-model",
            new[] { new CopilotChatMessage("user", "scan") },
            tools: new[] { tool },
            CancellationToken.None);

        var body = handler.RequestBodies[0];
        Assert.Contains("\"tools\"", body);
        Assert.Contains("nmap_scan", body);
    }

    // 6.
    [Fact]
    public async Task ListModelsAsync_ReturnsConfiguredModels_WithoutNetworkCall()
    {
        var (client, handler) = MakeClient(models: new[]
        {
            new LlamaCppModelConfig("qwen2.5-coder-32b", SupportsTools: true, ContextWindow: 32768),
            new LlamaCppModelConfig("tinyllama", SupportsTools: false, ContextWindow: 2048),
        });

        var models = await client.ListModelsAsync(CancellationToken.None);
        Assert.Equal(2, models.Count);
        Assert.Empty(handler.Requests);
        Assert.All(models, m => Assert.Equal("llamacpp-local", m.Family));
        Assert.True(models.First(m => m.Id == "qwen2.5-coder-32b").SupportsTools);
        Assert.False(models.First(m => m.Id == "tinyllama").SupportsTools);
    }

    // 7.
    [Fact]
    public async Task ListModelsAsync_DiscoversViaV1Models_WhenNotConfigured()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, ModelsResponse);

        var models = await client.ListModelsAsync(CancellationToken.None);
        Assert.Single(handler.Requests);
        Assert.EndsWith("/v1/models", handler.Requests[0].RequestUri!.ToString());
        Assert.Equal(2, models.Count);
        Assert.All(models, m =>
        {
            Assert.Equal("llamacpp-local", m.Family);
            Assert.False(m.SupportsTools);
            Assert.Null(m.ContextWindow);
        });
    }

    // 8.
    [Fact]
    public async Task ListModelsAsync_ReturnsEmpty_On404_DoesNotThrow()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.NotFound, "{\"error\":\"not found\"}");

        var models = await client.ListModelsAsync(CancellationToken.None);
        Assert.Empty(models);
    }

    // 9.
    [Fact]
    public async Task ConnectionRefused_SurfacesActionableError()
    {
        var (client, handler) = MakeClient();
        handler.Thrower = _ => new HttpRequestException(
            "conn refused",
            new SocketException((int)SocketError.ConnectionRefused));

        var ex = await Assert.ThrowsAsync<CopilotLlmException>(() =>
            client.ChatAsync("qwen2.5-coder-32b",
                new[] { new CopilotChatMessage("user", "x") }, tools: null, CancellationToken.None));

        Assert.Contains("llama-server unreachable", ex.Message);
        Assert.Contains("127.0.0.1:8080", ex.Message);
        Assert.Contains("is `llama-server` running", ex.Message);
    }

    // 10.
    [Fact]
    public async Task Audit_NeverContainsPlaintextCanary()
    {
        const string canary = "flag{canary_llamacpp_xyz}";
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, SimpleChatResponse);

        await client.ChatAsync("qwen2.5-coder-32b",
            new[]
            {
                new CopilotChatMessage("system", "you are helpful"),
                new CopilotChatMessage("user", canary),
            },
            tools: null, CancellationToken.None);

        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("llamacpp.chat.start", audit);
        Assert.Contains("llamacpp.chat.finish", audit);
        Assert.Contains("prompt_sha256", audit);
        Assert.DoesNotContain(canary, audit);
    }

    // 11.
    [Fact]
    public async Task UsageTokens_GracefullyZero_WhenServerOmits()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, ChatResponseNoUsage);

        var resp = await client.ChatAsync("tinyllama",
            new[] { new CopilotChatMessage("user", "hi") },
            tools: null, CancellationToken.None);

        Assert.Equal(0, resp.PromptTokens);
        Assert.Equal(0, resp.CompletionTokens);
        Assert.Equal("hi", resp.Content);
    }

    // 12.
    [Fact]
    public void TryCreateFromEnvironment_WithOnlyUrl_ReturnsWorkingClient()
    {
        using var _ = new EnvScope(
            ("LLAMACPP_URL", "http://localhost:9999"),
            ("LLAMACPP_BEARER_TOKEN", null),
            ("LLAMACPP_MODELS", null));

        var client = LlamaCppLlmClient.TryCreateFromEnvironment(_audit);
        Assert.NotNull(client);
        client!.Dispose();
    }

    // 13.
    [Fact]
    public void TryCreateFromEnvironment_ReturnsNull_OnUnparseableUrl()
    {
        using var _ = new EnvScope(
            ("LLAMACPP_URL", "not a url at all"),
            ("LLAMACPP_BEARER_TOKEN", null),
            ("LLAMACPP_MODELS", null));

        var client = LlamaCppLlmClient.TryCreateFromEnvironment(_audit);
        Assert.Null(client);
    }

    // 14.
    [Fact]
    public void TryCreateFromEnvironment_WithNoEnv_ReturnsDefaultLocalhost()
    {
        using var _ = new EnvScope(
            ("LLAMACPP_URL", null),
            ("LLAMACPP_BEARER_TOKEN", null),
            ("LLAMACPP_MODELS", null));

        var client = LlamaCppLlmClient.TryCreateFromEnvironment(_audit);
        Assert.NotNull(client);
        client!.Dispose();
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
