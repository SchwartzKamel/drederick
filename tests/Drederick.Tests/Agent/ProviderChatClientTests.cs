using System.Net;
using System.Text;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using GitHub.Copilot.SDK;
using Microsoft.Extensions.AI;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// Tests for the provider implementations that enable Copilot SDK and Azure
/// OpenAI for the <c>--agent</c> recon/exploit runner.
/// </summary>
public class ProviderChatClientTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-provider-{Guid.NewGuid():N}.jsonl");

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
                var result = MicrosoftAgentRunner.TryCreateFromProvider(
                    LlmProvider.Copilot,
                    null,
                    audit,
                    allowGitHubCliAuth: false);
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
    public void TryCreateFromProvider_Copilot_UsesAuthenticatedGitHubCliTokenAndOfficialSdkRunner()
    {
        var auditPath = NewAuditPath();
        var ghDir = Path.Combine(AppContext.BaseDirectory, "drederick-gh-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ghDir);
        var gh = Path.Combine(ghDir, OperatingSystem.IsWindows() ? "gh.cmd" : "gh");
        File.WriteAllText(gh, OperatingSystem.IsWindows()
            ? "@echo off\r\nif \"%1 %2\"==\"auth token\" (echo gho_from_cli& exit /b 0)\r\nexit /b 1\r\n"
            : "#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then printf 'gho_from_cli\\n'; exit 0; fi\nexit 1\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(gh, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var savedCopilot = Environment.GetEnvironmentVariable("COPILOT_TOKEN");
        var savedGh = Environment.GetEnvironmentVariable("GH_TOKEN");
        var savedGithub = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        var savedModel = Environment.GetEnvironmentVariable("DREDERICK_MODEL");
        var savedPath = Environment.GetEnvironmentVariable("PATH");
        try
        {
            Environment.SetEnvironmentVariable("COPILOT_TOKEN", null);
            Environment.SetEnvironmentVariable("GH_TOKEN", null);
            Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
            Environment.SetEnvironmentVariable("DREDERICK_MODEL", "gpt-4o-mini");
            Environment.SetEnvironmentVariable("PATH", ghDir + Path.PathSeparator + savedPath);

            var audit = new AuditLog(auditPath);
            var result = MicrosoftAgentRunner.TryCreateFromProvider(LlmProvider.Copilot, null, audit);
            var sdkRunner = Assert.IsType<CopilotSdkAgentRunner>(result);
            Assert.Equal("gpt-4o-mini", sdkRunner.ModelId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("COPILOT_TOKEN", savedCopilot);
            Environment.SetEnvironmentVariable("GH_TOKEN", savedGh);
            Environment.SetEnvironmentVariable("GITHUB_TOKEN", savedGithub);
            Environment.SetEnvironmentVariable("DREDERICK_MODEL", savedModel);
            Environment.SetEnvironmentVariable("PATH", savedPath);
            TryDelete(auditPath);
            try { Directory.Delete(ghDir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void CopilotModelCompliance_SelectsHaikuFirst_WhenModelIsImplicit()
    {
        var models = new[]
        {
            Model("gpt-4o-mini"),
            Model("claude-haiku-4.5"),
            Model("claude-sonnet-4.5"),
        };

        var decision = CopilotModelCompliance.SelectModel(models, requestedModelId: null, explicitModel: false);

        Assert.True(decision.Compliant);
        Assert.Equal("claude-haiku-4.5", decision.SelectedModelId);
        Assert.Equal("preferred:claude-haiku-4.5", decision.Reason);
    }

    [Fact]
    public void CopilotModelCompliance_ExplicitUnavailableModel_Fails()
    {
        var models = new[]
        {
            Model("claude-haiku-4.5"),
        };

        var decision = CopilotModelCompliance.SelectModel(models, "not-real", explicitModel: true);

        Assert.False(decision.Compliant);
        Assert.Equal("model_unavailable", decision.Reason);
        Assert.Null(decision.SelectedModelId);
        Assert.Contains("not-real", CopilotModelCompliance.BuildFailureMessage(decision));
    }

    [Fact]
    public void CopilotModelCompliance_ExplicitNonToolModel_Fails()
    {
        var models = new[]
        {
            Model("text-embedding-3-small"),
            Model("claude-haiku-4.5"),
        };

        var decision = CopilotModelCompliance.SelectModel(models, "text-embedding-3-small", explicitModel: true);

        Assert.False(decision.Compliant);
        Assert.Equal("missing_tool_support_metadata", decision.Reason);
        Assert.Null(decision.SelectedModelId);
    }

    [Fact]
    public void CopilotModelCompliance_DisabledPolicy_FailsEvenForKnownToolModel()
    {
        var models = new[]
        {
            Model("claude-haiku-4.5", policyState: "disabled"),
        };

        var decision = CopilotModelCompliance.SelectModel(models, "claude-haiku-4.5", explicitModel: true);

        Assert.False(decision.Compliant);
        Assert.Equal("model_policy_not_enabled", decision.Reason);
    }

    [Fact]
    public async Task CopilotModelCompliance_CachesModelList_PerToken()
    {
        CopilotModelCompliance.ClearCacheForTests();
        try
        {
            var calls = 0;
            Task<IList<ModelInfo>> Fetch(CancellationToken _)
            {
                calls++;
                return Task.FromResult<IList<ModelInfo>>(new List<ModelInfo> { Model("claude-haiku-4.5") });
            }

            var first = await CopilotModelCompliance.GetModelsAsync("gho_token_a", Fetch, CancellationToken.None);
            var second = await CopilotModelCompliance.GetModelsAsync("gho_token_a", Fetch, CancellationToken.None);
            var third = await CopilotModelCompliance.GetModelsAsync("gho_token_b", Fetch, CancellationToken.None);

            Assert.False(first.FromCache);
            Assert.True(second.FromCache);
            Assert.False(third.FromCache);
            Assert.Equal(2, calls);
        }
        finally
        {
            CopilotModelCompliance.ClearCacheForTests();
        }
    }

    [Fact]
    public async Task CopilotModelCompliance_GetModelsAsync_HonorsCancellationBeforeFetch()
    {
        CopilotModelCompliance.ClearCacheForTests();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var calls = 0;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CopilotModelCompliance.GetModelsAsync(
                "gho_token_cancel",
                _ =>
                {
                    calls++;
                    return Task.FromResult<IList<ModelInfo>>(new List<ModelInfo>());
                },
                cts.Token));
        Assert.Equal(0, calls);
    }

    [Fact]
    public void CopilotSdkAgentRunner_Config_UsesOfficialSdkAndOnlyProvidedTools()
    {
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var runner = new CopilotSdkAgentRunner(audit, "gho_test", "claude-haiku-4.5");
            var function = AIFunctionFactory.Create((string value) => value, name: "echo_test");

            var options = runner.CreateClientOptions();
            Assert.Equal("gho_test", options.GitHubToken);
            Assert.False(options.UseLoggedInUser);

            var config = runner.CreateSessionConfig(new List<AIFunction> { function });
            Assert.Equal("claude-haiku-4.5", config.Model);
            Assert.Single(config.Tools!);
            Assert.Equal("echo_test", Assert.Single(config.AvailableTools!));
            Assert.NotNull(config.OnPermissionRequest);
            Assert.Equal(SystemMessageMode.Append, config.SystemMessage!.Mode);
            Assert.Contains("Drederick", config.SystemMessage.Content);
            Assert.False(config.Streaming);
            Assert.False(config.InfiniteSessions!.Enabled);
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

    private static ModelInfo Model(string id, string? policyState = "enabled") => new()
    {
        Id = id,
        Name = id,
        Capabilities = new ModelCapabilities
        {
            Supports = new ModelSupports(),
        },
        Policy = new ModelPolicy
        {
            State = policyState ?? "",
        },
    };
}
