using System.Net;
using System.Text;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Microsoft.Extensions.AI;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// Tests for <see cref="CopilotChatClient"/> and <see cref="AzureOpenAiChatClient"/>
/// — the new <see cref="IChatClient"/> implementations that enable Copilot SDK
/// and Azure OpenAI for the <c>--agent</c> recon/exploit runner.
/// </summary>
public class ProviderChatClientTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-provider-{Guid.NewGuid():N}.jsonl");

    // ---- CopilotChatClient request serialization ----

    [Fact]
    public void CopilotChatClient_BuildRequestBody_IncludesModelAndMessages()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new CopilotChatClient("test-token", "test-integration", audit, "gpt-4o-mini",
                endpoint: new Uri("https://test.example.com/v1"));

            var messages = new List<ChatMessage>
            {
                new(ChatRole.System, "You are a test assistant."),
                new(ChatRole.User, "Hello!"),
            };

            var body = client.BuildRequestBody(messages, null);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            Assert.Equal("gpt-4o-mini", root.GetProperty("model").GetString());
            var msgs = root.GetProperty("messages");
            Assert.Equal(2, msgs.GetArrayLength());
            Assert.Equal("system", msgs[0].GetProperty("role").GetString());
            Assert.Equal("You are a test assistant.", msgs[0].GetProperty("content").GetString());
            Assert.Equal("user", msgs[1].GetProperty("role").GetString());
            Assert.Equal("Hello!", msgs[1].GetProperty("content").GetString());
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void CopilotChatClient_BuildRequestBody_SerializesToolCallMessages()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new CopilotChatClient("test-token", "test-integration", audit, "gpt-4o-mini",
                endpoint: new Uri("https://test.example.com/v1"));

            // Simulate an assistant message with a tool call
            var assistantMsg = new ChatMessage(ChatRole.Assistant, (string?)null);
            assistantMsg.Contents.Add(new FunctionCallContent("call_123", "nmap_scan",
                new Dictionary<string, object?> { ["target"] = "10.10.10.5" }));

            // And a tool result message
            var toolResultMsg = new ChatMessage(ChatRole.Tool, (string?)null);
            toolResultMsg.Contents.Add(new FunctionResultContent("call_123", "{\"ports\": [22, 80]}"));

            var messages = new List<ChatMessage> { assistantMsg, toolResultMsg };
            var body = client.BuildRequestBody(messages, null);
            using var doc = JsonDocument.Parse(body);
            var msgs = doc.RootElement.GetProperty("messages");

            // First message: assistant with tool_calls
            var m0 = msgs[0];
            Assert.Equal("assistant", m0.GetProperty("role").GetString());
            var toolCalls = m0.GetProperty("tool_calls");
            Assert.Equal(1, toolCalls.GetArrayLength());
            Assert.Equal("call_123", toolCalls[0].GetProperty("id").GetString());
            Assert.Equal("nmap_scan", toolCalls[0].GetProperty("function").GetProperty("name").GetString());

            // Second message: tool result
            var m1 = msgs[1];
            Assert.Equal("tool", m1.GetProperty("role").GetString());
            Assert.Equal("call_123", m1.GetProperty("tool_call_id").GetString());
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    // ---- CopilotChatClient response parsing ----

    [Fact]
    public void CopilotChatClient_ParseResponse_TextResponse()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new CopilotChatClient("test-token", "test-integration", audit, "gpt-4o-mini",
                endpoint: new Uri("https://test.example.com/v1"));

            var json = """
            {
              "model": "gpt-4o-mini",
              "choices": [{
                "finish_reason": "stop",
                "message": {
                  "role": "assistant",
                  "content": "Hello, world!"
                }
              }],
              "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5
              }
            }
            """;

            var response = client.ParseResponse(json, TimeSpan.FromMilliseconds(100));

            Assert.Equal("gpt-4o-mini", response.ModelId);
            Assert.Equal(ChatFinishReason.Stop, response.FinishReason);
            Assert.Equal(10, response.Usage?.InputTokenCount);
            Assert.Equal(5, response.Usage?.OutputTokenCount);
            Assert.Single(response.Messages);
            Assert.Contains(response.Messages[0].Contents, c => c is TextContent tc && tc.Text == "Hello, world!");
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void CopilotChatClient_ParseResponse_ToolCallResponse()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new CopilotChatClient("test-token", "test-integration", audit, "gpt-4o-mini",
                endpoint: new Uri("https://test.example.com/v1"));

            var json = """
            {
              "model": "gpt-4o-mini",
              "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                  "role": "assistant",
                  "content": null,
                  "tool_calls": [{
                    "id": "call_abc",
                    "type": "function",
                    "function": {
                      "name": "nmap_scan",
                      "arguments": "{\"target\":\"10.10.10.5\"}"
                    }
                  }]
                }
              }],
              "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 15
              }
            }
            """;

            var response = client.ParseResponse(json, TimeSpan.FromMilliseconds(50));

            Assert.Equal(ChatFinishReason.ToolCalls, response.FinishReason);
            var msg = response.Messages[0];
            var fc = msg.Contents.OfType<FunctionCallContent>().Single();
            Assert.Equal("call_abc", fc.CallId);
            Assert.Equal("nmap_scan", fc.Name);
            Assert.NotNull(fc.Arguments);
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void CopilotChatClient_ParseResponse_MultipleToolCalls()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new CopilotChatClient("test-token", "test-integration", audit, "gpt-4o-mini",
                endpoint: new Uri("https://test.example.com/v1"));

            var json = """
            {
              "model": "gpt-4o-mini",
              "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                  "role": "assistant",
                  "content": "Let me scan both.",
                  "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "nmap_scan", "arguments": "{\"target\":\"10.10.10.5\"}"}},
                    {"id": "c2", "type": "function", "function": {"name": "http_probe", "arguments": "{\"target\":\"10.10.10.5\"}"}}
                  ]
                }
              }],
              "usage": {"prompt_tokens": 30, "completion_tokens": 25}
            }
            """;

            var response = client.ParseResponse(json, TimeSpan.FromMilliseconds(50));
            var msg = response.Messages[0];

            // Should have text + 2 tool calls
            var text = msg.Contents.OfType<TextContent>().Single();
            Assert.Equal("Let me scan both.", text.Text);
            var calls = msg.Contents.OfType<FunctionCallContent>().ToList();
            Assert.Equal(2, calls.Count);
            Assert.Equal("c1", calls[0].CallId);
            Assert.Equal("c2", calls[1].CallId);
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    // ---- AzureOpenAiChatClient ----

    [Fact]
    public void AzureOpenAiChatClient_BuildRequestBody_OmitsModelByDefault()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new AzureOpenAiChatClient(
                "https://test.openai.azure.com", new AzureOpenAiAuth.ApiKey("test-key"),
                audit, "gpt-4o", http: new HttpClient());

            var messages = new List<ChatMessage>
            {
                new(ChatRole.User, "Hello!"),
            };

            // Azure: includeModel defaults to true, but the GetResponseAsync path
            // calls with includeModel: false
            var body = client.BuildRequestBody(messages, null, includeModel: false);
            using var doc = JsonDocument.Parse(body);
            Assert.False(doc.RootElement.TryGetProperty("model", out _));
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void AzureOpenAiChatClient_BuildChatUrl_IncludesDeploymentAndApiVersion()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var deploymentMap = new Dictionary<string, string> { ["gpt-4o"] = "my-gpt4-deployment" };
            var client = new AzureOpenAiChatClient(
                "https://test.openai.azure.com", new AzureOpenAiAuth.ApiKey("test-key"),
                audit, "gpt-4o", deploymentMap, http: new HttpClient());

            var deployment = client.ResolveDeployment("gpt-4o");
            Assert.Equal("my-gpt4-deployment", deployment);

            var url = client.BuildChatUrl(deployment);
            Assert.Contains("deployments/my-gpt4-deployment", url.ToString());
            Assert.Contains("api-version=", url.ToString());
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void AzureOpenAiChatClient_ResolveDeployment_FallsThrough()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new AzureOpenAiChatClient(
                "https://test.openai.azure.com", new AzureOpenAiAuth.ApiKey("test-key"),
                audit, "gpt-4o", http: new HttpClient());

            // No deployment map entry → falls through to model id as deployment name
            Assert.Equal("gpt-4o", client.ResolveDeployment("gpt-4o"));
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void AzureOpenAiChatClient_ParseResponse_ParsesToolCalls()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var client = new AzureOpenAiChatClient(
                "https://test.openai.azure.com", new AzureOpenAiAuth.ApiKey("test-key"),
                audit, "gpt-4o", http: new HttpClient());

            var json = """
            {
              "model": "gpt-4o",
              "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                  "role": "assistant",
                  "content": null,
                  "tool_calls": [{
                    "id": "call_xyz",
                    "type": "function",
                    "function": {
                      "name": "smb_probe",
                      "arguments": "{\"target\":\"10.10.10.5\"}"
                    }
                  }]
                }
              }],
              "usage": {"prompt_tokens": 50, "completion_tokens": 30}
            }
            """;

            var response = client.ParseResponse(json, TimeSpan.FromMilliseconds(100));
            Assert.Equal(ChatFinishReason.ToolCalls, response.FinishReason);
            var fc = response.Messages[0].Contents.OfType<FunctionCallContent>().Single();
            Assert.Equal("call_xyz", fc.CallId);
            Assert.Equal("smb_probe", fc.Name);
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    // ---- MicrosoftAgentRunner factory ----

    [Fact]
    public void TryCreateFromProvider_LlamaCpp_ReturnsNull()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var result = MicrosoftAgentRunner.TryCreateFromProvider(LlmProvider.LlamaCpp, null, audit);
            Assert.Null(result);
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void TryCreateFromProvider_Copilot_ReturnsNull_WithoutToken()
    {
        var auditPath = NewAuditPath();
        try
        {
            // Ensure no Copilot tokens are set (they shouldn't be in CI)
            var savedCopilot = Environment.GetEnvironmentVariable("COPILOT_TOKEN");
            var savedGh = Environment.GetEnvironmentVariable("GH_TOKEN");
            var savedGithub = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
            try
            {
                Environment.SetEnvironmentVariable("COPILOT_TOKEN", null);
                Environment.SetEnvironmentVariable("GH_TOKEN", null);
                Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);

                var audit = new AuditLog(auditPath);
                var result = MicrosoftAgentRunner.TryCreateFromProvider(LlmProvider.Copilot, null, audit);
                Assert.Null(result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("COPILOT_TOKEN", savedCopilot);
                Environment.SetEnvironmentVariable("GH_TOKEN", savedGh);
                Environment.SetEnvironmentVariable("GITHUB_TOKEN", savedGithub);
            }
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    [Fact]
    public void TryCreateFromProvider_Azure_ReturnsNull_WithoutEndpoint()
    {
        var auditPath = NewAuditPath();
        try
        {
            var savedEndpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
            try
            {
                Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", null);

                var audit = new AuditLog(auditPath);
                var result = MicrosoftAgentRunner.TryCreateFromProvider(LlmProvider.Azure, null, audit);
                Assert.Null(result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", savedEndpoint);
            }
        }
        finally
        {
            TryDelete(auditPath);
        }
    }

    // ---- CLI options: --llm-provider accepted with --agent ----

    [Fact]
    public void CliOptions_LlmProvider_AcceptedWithAgent()
    {
        var opts = Drederick.Cli.CommandLineOptions.Parse(new[]
        {
            "--scope", "scope.yaml",
            "--target", "10.10.10.5",
            "--agent",
            "--llm-provider=azure",
            "--out", "out/"
        });

        Assert.True(opts.UseAgent);
        Assert.Equal(LlmProvider.Azure, opts.LlmProvider);
    }

    [Fact]
    public void CliOptions_LlmProvider_AcceptedWithHybridAgent()
    {
        var opts = Drederick.Cli.CommandLineOptions.Parse(new[]
        {
            "--scope", "scope.yaml",
            "--target", "10.10.10.5",
            "--agent=hybrid",
            "--llm-provider=copilot",
            "--out", "out/"
        });

        Assert.True(opts.UseHybridAgent);
        Assert.Equal(LlmProvider.Copilot, opts.LlmProvider);
    }

    [Fact]
    public void CliOptions_AzureDeployment_AcceptedWithAgent()
    {
        var opts = Drederick.Cli.CommandLineOptions.Parse(new[]
        {
            "--scope", "scope.yaml",
            "--target", "10.10.10.5",
            "--agent",
            "--llm-provider=azure",
            "--azure-deployment=gpt-4o=my-deployment",
            "--out", "out/"
        });

        Assert.True(opts.UseAgent);
        Assert.Equal("my-deployment", opts.AzureDeploymentMap["gpt-4o"]);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* ignore */ }
    }
}
