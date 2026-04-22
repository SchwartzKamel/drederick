using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

public class AzureOpenAiLlmClientTests : IDisposable
{
    private readonly string _workDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;

    public AzureOpenAiLlmClientTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-azure-" + Guid.NewGuid().ToString("N"));
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

    private const string Endpoint = "https://my-resource.openai.azure.test";

    private (AzureOpenAiLlmClient client, TestHttpHandler handler) MakeClient(
        AzureOpenAiAuth? auth = null,
        IReadOnlyDictionary<string, string>? deploymentMap = null,
        string apiVersion = AzureOpenAiLlmClient.DefaultApiVersion)
    {
        var handler = new TestHttpHandler();
        var http = new HttpClient(handler);
        var client = new AzureOpenAiLlmClient(
            Endpoint,
            auth ?? new AzureOpenAiAuth.ApiKey("sk-azure-key-zzzzzzzzzzzzzzzzzzzz"),
            _audit,
            deploymentMap,
            apiVersion,
            http);
        return (client, handler);
    }

    // 1. Happy path URL shape
    [Fact]
    public async Task ChatAsync_BuildsCorrectAzureUrl_WithDeploymentAndApiVersion()
    {
        var (client, handler) = MakeClient(
            deploymentMap: new Dictionary<string, string> { ["gpt-5.4"] = "my-gpt54-prod" });
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        var resp = await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        Assert.Single(handler.Requests);
        var url = handler.Requests[0].RequestUri!.ToString();
        Assert.Equal(
            $"{Endpoint}/openai/deployments/my-gpt54-prod/chat/completions?api-version={AzureOpenAiLlmClient.DefaultApiVersion}",
            url);
        Assert.Equal("The flag is FLAG{jeopardy_pwned}.", resp.Content);
    }

    // 2. api-key header set (not Authorization)
    [Fact]
    public async Task ApiKeyAuth_SetsApiKeyHeader_NotAuthorization()
    {
        var (client, handler) = MakeClient(auth: new AzureOpenAiAuth.ApiKey("test-api-key-123"));
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        var req = handler.Requests[0];
        Assert.True(req.Headers.Contains("api-key"));
        Assert.Equal("test-api-key-123", req.Headers.GetValues("api-key").First());
        Assert.Null(req.Headers.Authorization);
    }

    // 3. Bearer sets Authorization (not api-key)
    [Fact]
    public async Task BearerAuth_SetsAuthorizationHeader_NotApiKey()
    {
        var (client, handler) = MakeClient(auth: new AzureOpenAiAuth.Bearer("ey.fake.bearer.token"));
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        var req = handler.Requests[0];
        Assert.False(req.Headers.Contains("api-key"));
        Assert.Equal("Bearer", req.Headers.Authorization?.Scheme);
        Assert.Equal("ey.fake.bearer.token", req.Headers.Authorization?.Parameter);
    }

    // 4. Deployment remap honored
    [Fact]
    public async Task DeploymentMap_RemapsLogicalToAzureDeployment()
    {
        var (client, handler) = MakeClient(deploymentMap: new Dictionary<string, string>
        {
            ["gpt-5.4"] = "my-gpt54-prod",
            ["gpt-4o"] = "four-o-dep",
        });
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        Assert.Contains("/deployments/my-gpt54-prod/", handler.Requests[0].RequestUri!.ToString());
    }

    // 5. Missing mapping falls through to modelId as deployment
    [Fact]
    public async Task MissingDeploymentMapping_FallsThroughToModelId()
    {
        var (client, handler) = MakeClient(deploymentMap: new Dictionary<string, string>
        {
            ["gpt-5.4"] = "remapped",
        });
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-4o-mini",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        Assert.Contains("/deployments/gpt-4o-mini/", handler.Requests[0].RequestUri!.ToString());
    }

    // 6. Body does NOT contain "model" key
    [Fact]
    public async Task RequestBody_OmitsModelKey_ForAzureRouting()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        var body = handler.RequestBodies[0];
        using var doc = System.Text.Json.JsonDocument.Parse(body);
        Assert.False(doc.RootElement.TryGetProperty("model", out _));
        Assert.True(doc.RootElement.TryGetProperty("messages", out _));
    }

    // 7. Tool calls surface correctly
    [Fact]
    public async Task ToolCalls_AreSurfacedFromResponse()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_toolcall.json"));

        var resp = await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "scan") }, tools: null, CancellationToken.None);

        Assert.Single(resp.ToolCalls);
        Assert.Equal("nmap_scan", resp.ToolCalls[0].Name);
        Assert.Contains("10.10.10.5", resp.ToolCalls[0].ArgumentsJson);
        Assert.Equal("tool_calls", resp.FinishReason);
    }

    // 8. Usage tokens parsed
    [Fact]
    public async Task UsageTokens_Extracted()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        var resp = await client.ChatAsync("gpt-5.4",
            new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None);

        Assert.Equal(42, resp.PromptTokens);
        Assert.Equal(11, resp.CompletionTokens);
    }

    // 9. 401 → actionable exception
    [Fact]
    public async Task On401_SurfacesActionableAuthMessage()
    {
        var (client, handler) = MakeClient();
        handler.Enqueue(HttpStatusCode.Unauthorized, "{\"error\":{\"code\":\"401\",\"message\":\"bad key\"}}");

        var ex = await Assert.ThrowsAsync<CopilotLlmException>(() =>
            client.ChatAsync("gpt-5.4",
                new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        Assert.Contains("AZURE_OPENAI_API_KEY", ex.Message);
    }

    // 10. 429 → CopilotLlmException with status (after retries exhausted)
    [Fact]
    public async Task On429_AfterRetries_SurfacesStatus()
    {
        var (client, handler) = MakeClient();
        for (int i = 0; i < 4; i++)
            handler.Enqueue(HttpStatusCode.TooManyRequests, "{\"error\":\"rate_limited\"}");

        var ex = await Assert.ThrowsAsync<CopilotLlmException>(() =>
            client.ChatAsync("gpt-5.4",
                new[] { new CopilotChatMessage("user", "hi") }, tools: null, CancellationToken.None));

        Assert.Equal(HttpStatusCode.TooManyRequests, ex.StatusCode);
    }

    // 11. Canary: plaintext never in audit log
    [Fact]
    public async Task Canary_PlaintextMessageAndKey_NeverInAuditLog()
    {
        const string canary = "flag{canary_azure_xyz}";
        const string keyCanary = "sk-azure-canary-CANARYKEY-zzz";
        var (client, handler) = MakeClient(auth: new AzureOpenAiAuth.ApiKey(keyCanary));
        handler.Enqueue(HttpStatusCode.OK, LoadFixture("copilot_chat_simple.json"));

        await client.ChatAsync("gpt-5.4",
            new[]
            {
                new CopilotChatMessage("system", "be helpful"),
                new CopilotChatMessage("user", canary),
            }, tools: null, CancellationToken.None);

        _audit.Dispose();
        var audit = File.ReadAllText(_auditPath);
        Assert.Contains("azure_openai.chat.start", audit);
        Assert.Contains("azure_openai.chat.finish", audit);
        Assert.DoesNotContain(canary, audit);
        Assert.DoesNotContain(keyCanary, audit);
    }

    // 12. ListModelsAsync returns deployment map keys
    [Fact]
    public async Task ListModelsAsync_ReturnsDeploymentMapKeys()
    {
        var (client, _) = MakeClient(deploymentMap: new Dictionary<string, string>
        {
            ["gpt-5.4"] = "prod-54",
            ["gpt-4o"] = "prod-4o",
        });

        var models = await client.ListModelsAsync(CancellationToken.None);
        Assert.Equal(2, models.Count);
        Assert.Contains(models, m => m.Id == "gpt-5.4");
        Assert.Contains(models, m => m.Id == "gpt-4o");
    }

    // 12b. Empty deployment map → empty list (no throw)
    [Fact]
    public async Task ListModelsAsync_EmptyMap_ReturnsEmptyList()
    {
        var (client, _) = MakeClient();
        var models = await client.ListModelsAsync(CancellationToken.None);
        Assert.Empty(models);
    }

    // 13. TryCreateFromEnvironment returns null when unset
    [Fact]
    public void TryCreateFromEnvironment_WithoutCreds_ReturnsNull()
    {
        using var _ = new EnvScope(
            ("AZURE_OPENAI_ENDPOINT", "https://my-resource.openai.azure.com"),
            ("AZURE_OPENAI_API_KEY", null),
            ("AZURE_OPENAI_BEARER_TOKEN", null));
        var client = AzureOpenAiLlmClient.TryCreateFromEnvironment(_audit);
        Assert.Null(client);
    }

    // 13b. TryCreateFromEnvironment returns null when endpoint missing
    [Fact]
    public void TryCreateFromEnvironment_WithoutEndpoint_ReturnsNull()
    {
        using var _ = new EnvScope(
            ("AZURE_OPENAI_ENDPOINT", null),
            ("AZURE_OPENAI_API_KEY", "some-key"),
            ("AZURE_OPENAI_BEARER_TOKEN", null));
        var client = AzureOpenAiLlmClient.TryCreateFromEnvironment(_audit);
        Assert.Null(client);
    }

    // 14. Deployment map parser
    [Fact]
    public void ParseDeploymentMap_HandlesCommaSeparatedPairs()
    {
        var map = AzureOpenAiLlmClient.ParseDeploymentMap("gpt-5.4=prod-54, gpt-4o=prod-4o");
        Assert.Equal(2, map.Count);
        Assert.Equal("prod-54", map["gpt-5.4"]);
        Assert.Equal("prod-4o", map["gpt-4o"]);
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
