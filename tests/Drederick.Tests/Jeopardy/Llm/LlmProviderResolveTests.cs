using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

/// <summary>
/// Tests for <see cref="LlmProviderFactory.Resolve"/>: autodetect order is
/// Copilot → Azure → OpenAI. Explicit (non-Auto) requests pass through
/// unchanged. Tests mutate process-wide environment variables and must run
/// serialized — share a single xUnit collection so two of these never race.
/// </summary>
[Collection(nameof(LlmProviderResolveCollection))]
public class LlmProviderResolveTests : IDisposable
{
    private static readonly string[] EnvVars =
    {
        "COPILOT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
        "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_BEARER_TOKEN", "AZURE_OPENAI_USE_ENTRA",
        "OPENAI_API_KEY",
    };

    private readonly Dictionary<string, string?> _saved = new();
    private readonly string _auditPath;
    private readonly AuditLog _audit;

    public LlmProviderResolveTests()
    {
        foreach (var v in EnvVars)
        {
            _saved[v] = Environment.GetEnvironmentVariable(v);
            Environment.SetEnvironmentVariable(v, null);
        }
        _auditPath = Path.Combine(AppContext.BaseDirectory, $"resolve-audit-{Guid.NewGuid():N}.jsonl");
        _audit = new AuditLog(_auditPath);
    }

    public void Dispose()
    {
        foreach (var kv in _saved)
            Environment.SetEnvironmentVariable(kv.Key, kv.Value);
        try { File.Delete(_auditPath); } catch { /* ignore */ }
    }

    private List<JsonElement> ReadAuditEvents(string eventName)
    {
        var events = new List<JsonElement>();
        if (!File.Exists(_auditPath)) return events;
        foreach (var line in File.ReadAllLines(_auditPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("event", out var t)
                && t.GetString() == eventName)
            {
                events.Add(doc.RootElement.Clone());
            }
        }
        return events;
    }

    // 1
    [Fact]
    public void Resolve_Auto_CopilotPresent_PicksCopilot()
    {
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", "ghu_test_copilot_token");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        Assert.Equal(LlmProvider.Copilot, picked);
        var ev = Assert.Single(ReadAuditEvents("llm.provider.autodetect"));
        Assert.Equal("copilot", ev.GetProperty("selected").GetString());
        Assert.Equal("CopilotToken", ev.GetProperty("source").GetString());
        var attempted = ev.GetProperty("attempted").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Equal(new[] { "copilot" }, attempted);
    }

    // 2
    [Fact]
    public void Resolve_Auto_OnlyAzureSet_PicksAzure()
    {
        Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "sk-azure-test");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        Assert.Equal(LlmProvider.Azure, picked);
        var ev = Assert.Single(ReadAuditEvents("llm.provider.autodetect"));
        Assert.Equal("azure", ev.GetProperty("selected").GetString());
        Assert.Equal("env:api_key", ev.GetProperty("source").GetString());
        var attempted = ev.GetProperty("attempted").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Equal(new[] { "copilot", "azure" }, attempted);
    }

    // 3
    [Fact]
    public void Resolve_Auto_OnlyOpenAiSet_PicksOpenAi()
    {
        Environment.SetEnvironmentVariable("OPENAI_API_KEY", "sk-openai-test");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        Assert.Equal(LlmProvider.OpenAi, picked);
        var ev = Assert.Single(ReadAuditEvents("llm.provider.autodetect"));
        Assert.Equal("openai", ev.GetProperty("selected").GetString());
        var attempted = ev.GetProperty("attempted").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Equal(new[] { "copilot", "azure", "openai" }, attempted);
    }

    // 4
    [Fact]
    public void Resolve_Auto_NothingSet_ReturnsAutoSentinel()
    {
        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        Assert.Equal(LlmProvider.Auto, picked);
        var ev = Assert.Single(ReadAuditEvents("llm.provider.autodetect"));
        Assert.Equal("none", ev.GetProperty("selected").GetString());

        // TryCreateChatClient also returns null on Auto sentinel.
        var built = Drederick.Agent.MicrosoftAgentRunner.TryCreateChatClient(
            LlmProvider.Auto, null, _audit, allowGitHubCliAuth: false);
        Assert.Null(built);
    }

    // 5
    [Fact]
    public void Resolve_Explicit_Copilot_NoProbing()
    {
        // Set Azure env so it would win autodetect — but request is explicit
        // Copilot, so resolve must pass through unchanged and emit no audit.
        Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "sk-azure");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Copilot, _audit, allowGitHubCliAuth: false);

        Assert.Equal(LlmProvider.Copilot, picked);
        Assert.Empty(ReadAuditEvents("llm.provider.autodetect"));
    }

    // 6
    [Fact]
    public void Resolve_Explicit_Azure_NotConfigured_ReturnsAzure()
    {
        // Operator was explicit — no Azure env, no autodetect. Resolve passes
        // Azure through; the factory will then return null. The error message
        // is the caller's responsibility — but it must NOT be misleading.
        var picked = LlmProviderFactory.Resolve(LlmProvider.Azure, _audit, allowGitHubCliAuth: false);
        Assert.Equal(LlmProvider.Azure, picked);

        var built = Drederick.Agent.MicrosoftAgentRunner.TryCreateChatClient(
            LlmProvider.Azure, null, _audit, allowGitHubCliAuth: false);
        Assert.Null(built);
    }

    // 7
    [Fact]
    public void Resolve_PrioritizesCopilot_OverAzure_WhenBothConfigured()
    {
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", "ghu_x");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "sk-azure");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);
        Assert.Equal(LlmProvider.Copilot, picked);
    }

    // 8 + 9
    [Theory]
    [InlineData("auto")]
    [InlineData("AUTO")]
    [InlineData("Auto")]
    [InlineData("autodetect")]
    public void Parse_Auto_AnyCase_ReturnsAuto(string raw)
    {
        Assert.Equal(LlmProvider.Auto, LlmProviderFactory.Parse(raw));
    }

    // 10
    [Fact]
    public void CommandLineOptions_Default_LlmProvider_IsAuto()
    {
        var opts = new Drederick.Cli.CommandLineOptions();
        Assert.Equal(LlmProvider.Auto, opts.LlmProvider);
    }

    // 11
    [Fact]
    public void Audit_Autodetect_Emitted_OnlyOnAutoPath()
    {
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", "ghu_x");

        // Explicit copilot — no autodetect event.
        _ = LlmProviderFactory.Resolve(LlmProvider.Copilot, _audit, allowGitHubCliAuth: false);
        Assert.Empty(ReadAuditEvents("llm.provider.autodetect"));

        // Auto — exactly one autodetect event.
        _ = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);
        Assert.Single(ReadAuditEvents("llm.provider.autodetect"));
    }

    // 12
    [Fact]
    public void TryCreateFromProvider_Auto_NothingConfigured_ReturnsNull()
    {
        var result = Drederick.Agent.MicrosoftAgentRunner.TryCreateFromProvider(
            LlmProvider.Auto, null, _audit, allowGitHubCliAuth: false);
        Assert.Null(result);
    }

    // 13
    [Fact]
    public void TryCreateChatClient_Auto_CopilotConfigured_ReturnsCopilotClient()
    {
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", "ghu_test_token");

        var built = Drederick.Agent.MicrosoftAgentRunner.TryCreateChatClient(
            LlmProvider.Auto, null, _audit, allowGitHubCliAuth: false);

        Assert.NotNull(built);
        Assert.IsType<Drederick.Agent.AzureOpenAiChatClient>(built.Value.Client);
    }

    // 14
    [Fact]
    public void Resolve_Auto_AzureUseEntra_NoBearer_DoesNotPickAzure()
    {
        // USE_ENTRA=1 alone (no bearer) is NOT enough — matches doctor +
        // factory semantics. Resolve must skip Azure here.
        Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_USE_ENTRA", "1");
        Environment.SetEnvironmentVariable("OPENAI_API_KEY", "sk-test");

        var picked = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        // Should fall through to OpenAI, not pick Azure.
        Assert.Equal(LlmProvider.OpenAi, picked);
    }

    // 15: Auto with no providers configured should NOT throw, and
    //     ICopilotLlmClient factory should print actionable guidance.
    [Fact]
    public void LlmProviderFactory_Create_Auto_NothingConfigured_PrintsGuidance()
    {
        var err = new StringWriter();
        var opts = new Drederick.Cli.CommandLineOptions { CtfSolveSubcommand = true };
        var client = LlmProviderFactory.Create(LlmProvider.Auto, opts, _audit, err, allowGitHubCliAuth: false);
        Assert.Null(client);
        var msg = err.ToString();
        Assert.Contains("auto", msg, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gh auth login", msg, StringComparison.OrdinalIgnoreCase);
    }

    // Bonus: Resolve never logs a token value — only source name.
    [Fact]
    public void Resolve_Auto_DoesNotLogSecretValues()
    {
        var canary = "ghu_canary_secret_value_DO_NOT_LEAK";
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", canary);

        _ = LlmProviderFactory.Resolve(LlmProvider.Auto, _audit, allowGitHubCliAuth: false);

        var raw = File.ReadAllText(_auditPath);
        Assert.DoesNotContain(canary, raw);
    }
}

[CollectionDefinition(nameof(LlmProviderResolveCollection), DisableParallelization = true)]
public sealed class LlmProviderResolveCollection { }
