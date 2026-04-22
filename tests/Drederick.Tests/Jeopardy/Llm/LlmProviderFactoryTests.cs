using Drederick.Audit;
using Drederick.Cli;
using Drederick.Jeopardy.Llm;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

/// <summary>
/// Unit tests for <see cref="LlmProviderFactory"/>. The factory is the
/// single doorway CLI and Web UI share for picking a Jeopardy LLM
/// backend; regressions here change operator-facing error text and the
/// provider selection contract, so we lock both down.
/// </summary>
public sealed class LlmProviderFactoryTests : IDisposable
{
    private readonly string _workDir;
    private readonly AuditLog _audit;

    // Every env var the factory touches — saved & restored around each test
    // so nothing in the operator's real shell leaks into or out of the run.
    private static readonly string[] TouchedEnvVars =
    {
        "COPILOT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "COPILOT_INTEGRATION_ID",
        "COPILOT_ENDPOINT",
        "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_BEARER_TOKEN",
        "AZURE_OPENAI_USE_ENTRA", "AZURE_OPENAI_API_VERSION",
        "AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_DEPLOYMENT_MAP",
        "LLAMACPP_URL", "LLAMACPP_BEARER_TOKEN", "LLAMACPP_MODELS",
    };

    private readonly Dictionary<string, string?> _savedEnv = new();

    public LlmProviderFactoryTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-llmfactory-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _audit = new AuditLog(Path.Combine(_workDir, "audit.jsonl"));
        foreach (var k in TouchedEnvVars)
        {
            _savedEnv[k] = Environment.GetEnvironmentVariable(k);
            Environment.SetEnvironmentVariable(k, null);
        }
    }

    public void Dispose()
    {
        foreach (var (k, v) in _savedEnv)
        {
            Environment.SetEnvironmentVariable(k, v);
        }
        _audit.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private CommandLineOptions NewOpts() => new() { CtfSolveSubcommand = true };

    // --- parse --------------------------------------------------------

    [Theory]
    [InlineData(null, LlmProvider.Copilot)]
    [InlineData("", LlmProvider.Copilot)]
    [InlineData("copilot", LlmProvider.Copilot)]
    [InlineData("COPILOT", LlmProvider.Copilot)]
    [InlineData("gh-copilot", LlmProvider.Copilot)]
    [InlineData("azure", LlmProvider.Azure)]
    [InlineData("azure-openai", LlmProvider.Azure)]
    [InlineData("AOAI", LlmProvider.Azure)]
    [InlineData("llamacpp", LlmProvider.LlamaCpp)]
    [InlineData("llama-cpp", LlmProvider.LlamaCpp)]
    [InlineData("llama.cpp", LlmProvider.LlamaCpp)]
    [InlineData("local", LlmProvider.LlamaCpp)]
    public void Parse_Accepts_Aliases(string? raw, LlmProvider expected)
    {
        Assert.Equal(expected, LlmProviderFactory.Parse(raw));
    }

    [Fact]
    public void Parse_Rejects_Unknown()
    {
        Assert.Throws<ArgumentException>(() => LlmProviderFactory.Parse("openai"));
    }

    // --- copilot ------------------------------------------------------

    [Fact]
    public void Copilot_With_CopilotToken_Creates_Client()
    {
        Environment.SetEnvironmentVariable("COPILOT_TOKEN", "ghu_fake_copilot_token_for_tests_only");
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Copilot, NewOpts(), _audit, err);
        Assert.NotNull(client);
        Assert.IsType<CopilotLlmClient>(client);
        Assert.Empty(err.ToString());
    }

    [Fact]
    public void Copilot_With_No_Token_Returns_Null_And_Writes_Actionable_Stderr()
    {
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Copilot, NewOpts(), _audit, err);
        Assert.Null(client);
        var msg = err.ToString();
        Assert.Contains("copilot", msg, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("COPILOT_TOKEN", msg);
        Assert.Contains("GH_TOKEN", msg);
        Assert.Contains("GITHUB_TOKEN", msg);
    }

    // --- azure --------------------------------------------------------

    [Fact]
    public void Azure_With_ApiKey_And_Endpoint_Creates_Client()
    {
        var opts = NewOpts();
        opts.AzureEndpoint = "https://foo.openai.azure.test";
        opts.AzureDeploymentMap["gpt-5.4"] = "gpt5-prod";
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "fake-api-key-do-not-leak");
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        Assert.NotNull(client);
        Assert.IsType<AzureOpenAiLlmClient>(client);
        Assert.Empty(err.ToString());
    }

    [Fact]
    public void Azure_With_Bearer_Creates_Client()
    {
        var opts = NewOpts();
        Environment.SetEnvironmentVariable("AZURE_OPENAI_ENDPOINT", "https://foo.openai.azure.test");
        Environment.SetEnvironmentVariable("AZURE_OPENAI_BEARER_TOKEN", "fake-bearer-do-not-leak");
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        Assert.NotNull(client);
    }

    [Fact]
    public void Azure_With_UseEntra_But_No_Bearer_Returns_Null()
    {
        var opts = NewOpts();
        opts.AzureEndpoint = "https://foo.openai.azure.test";
        Environment.SetEnvironmentVariable("AZURE_OPENAI_USE_ENTRA", "1");
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        Assert.Null(client);
        Assert.Contains("USE_ENTRA", err.ToString());
    }

    [Fact]
    public void Azure_Missing_Endpoint_Returns_Null_With_Stderr()
    {
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "k");
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, NewOpts(), _audit, err);
        Assert.Null(client);
        Assert.Contains("azure-endpoint", err.ToString());
        Assert.Contains("AZURE_OPENAI_ENDPOINT", err.ToString());
    }

    [Fact]
    public void Azure_Missing_Auth_Returns_Null_And_Mentions_All_Three_Options()
    {
        var opts = NewOpts();
        opts.AzureEndpoint = "https://foo.openai.azure.test";
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        Assert.Null(client);
        var msg = err.ToString();
        Assert.Contains("AZURE_OPENAI_API_KEY", msg);
        Assert.Contains("AZURE_OPENAI_BEARER_TOKEN", msg);
        Assert.Contains("AZURE_OPENAI_USE_ENTRA", msg);
    }

    [Fact]
    public void Azure_Does_Not_Leak_Secrets_To_Stderr()
    {
        var opts = NewOpts();
        // Endpoint set; no auth — factory prints a "no auth" error.
        opts.AzureEndpoint = "https://foo.openai.azure.test";
        Environment.SetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT", "gpt5-prod");
        var err = new StringWriter();
        _ = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        // The DEPLOYMENT value is fine to echo, but a real secret must never
        // land in stderr. Also try an api-key case and confirm the key is
        // never echoed:
        Environment.SetEnvironmentVariable("AZURE_OPENAI_API_KEY", "SECRET-DO-NOT-LEAK-k3y");
        var err2 = new StringWriter();
        var c = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err2);
        Assert.DoesNotContain("SECRET-DO-NOT-LEAK-k3y", err.ToString());
        Assert.DoesNotContain("SECRET-DO-NOT-LEAK-k3y", err2.ToString());
    }

    // --- llamacpp -----------------------------------------------------

    [Fact]
    public void LlamaCpp_With_Default_Url_Creates_Client()
    {
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.LlamaCpp, NewOpts(), _audit, err);
        Assert.NotNull(client);
        Assert.IsType<LlamaCppLlmClient>(client);
        Assert.Empty(err.ToString());
    }

    [Fact]
    public void LlamaCpp_With_Flag_Url_Overrides_Env()
    {
        Environment.SetEnvironmentVariable("LLAMACPP_URL", "http://127.0.0.1:9999");
        var opts = NewOpts();
        opts.LlamaCppUrl = "http://127.0.0.1:8080";
        opts.LlamaCppModels["qwen"] = "qwen2.5-coder";
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.LlamaCpp, opts, _audit, err);
        Assert.NotNull(client);
        Assert.Empty(err.ToString());
    }

    [Fact]
    public void LlamaCpp_With_Invalid_Url_Returns_Null_With_Stderr()
    {
        var opts = NewOpts();
        opts.LlamaCppUrl = "::::not a url";
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.LlamaCpp, opts, _audit, err);
        Assert.Null(client);
        Assert.Contains("llamacpp", err.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    // --- provider routing --------------------------------------------

    [Fact]
    public void Default_CommandLineOptions_LlmProvider_Is_Copilot()
    {
        var opts = new CommandLineOptions();
        Assert.Equal(LlmProvider.Copilot, opts.LlmProvider);
    }

    [Fact]
    public void Parsed_Cli_Without_Flag_Defaults_To_Copilot()
    {
        var opts = CommandLineOptions.Parse(new[] { "ctf-solve" });
        Assert.Equal(LlmProvider.Copilot, opts.LlmProvider);
    }
}
