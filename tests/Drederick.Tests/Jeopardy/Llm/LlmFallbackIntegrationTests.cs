using Drederick.Agent;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Jeopardy.Llm;
using Drederick.Memory;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Jeopardy.Llm;

/// <summary>
/// Integration between <see cref="LlmProviderFactory"/> and
/// <see cref="HybridAgentRunner"/>: when no LLM credentials are available
/// the factory returns <c>null</c>, the hybrid runner receives a null
/// inner runner, and the deterministic runner is invoked with a clear
/// <c>hybrid.llm_unavailable</c> audit event. Guards
/// <c>@invariant-id:llm-cannot-escape-scope</c> — no live network, no
/// SDK shenanigans, no silent crash when the LLM path is unconfigured.
/// </summary>
public sealed class LlmFallbackIntegrationTests : IDisposable
{
    private readonly string _workDir;
    private readonly string _auditPath;
    private readonly AuditLog _audit;

    // Every env var the factory touches — saved and cleared so tests don't
    // inherit operator shell state.
    private static readonly string[] TouchedEnvVars =
    {
        "COPILOT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "COPILOT_INTEGRATION_ID",
        "COPILOT_ENDPOINT",
        "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_BEARER_TOKEN",
        "AZURE_OPENAI_USE_ENTRA", "AZURE_OPENAI_API_VERSION",
        "AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_DEPLOYMENT_MAP",
        "LLAMACPP_URL", "LLAMACPP_BEARER_TOKEN", "LLAMACPP_MODELS",
        "OPENAI_API_KEY", "DREDERICK_MODEL",
    };
    private readonly Dictionary<string, string?> _savedEnv = new();

    public LlmFallbackIntegrationTests()
    {
        _workDir = Path.Combine(AppContext.BaseDirectory,
            "drederick-llmfallback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _auditPath = Path.Combine(_workDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        foreach (var k in TouchedEnvVars)
        {
            _savedEnv[k] = Environment.GetEnvironmentVariable(k);
            Environment.SetEnvironmentVariable(k, null);
        }
    }

    public void Dispose()
    {
        foreach (var (k, v) in _savedEnv) Environment.SetEnvironmentVariable(k, v);
        _audit.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private sealed class StubDeterministicRunner : IReconAgentRunner
    {
        public int Calls;
        public Task RunAsync(
            IReadOnlyList<string> targets,
            ReconToolbox tools,
            KnowledgeBase priorKnowledge,
            CancellationToken ct)
        {
            Calls++;
            return Task.CompletedTask;
        }
    }

    [Fact]
    public void Copilot_Factory_With_No_Token_Returns_Null()
    {
        var opts = new CommandLineOptions { CtfSolveSubcommand = true };
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Copilot, opts, _audit, err);
        Assert.Null(client);
        // Message must be actionable — operator should know what to set.
        var msg = err.ToString();
        Assert.Contains("COPILOT_TOKEN", msg);
        Assert.Contains("GITHUB_TOKEN", msg);
    }

    [Fact]
    public void Azure_Factory_With_No_Endpoint_Returns_Null()
    {
        var opts = new CommandLineOptions { CtfSolveSubcommand = true };
        var err = new StringWriter();
        var client = LlmProviderFactory.Create(LlmProvider.Azure, opts, _audit, err);
        Assert.Null(client);
        Assert.Contains("AZURE_OPENAI_ENDPOINT", err.ToString());
    }

    [Fact]
    public void MicrosoftAgentRunner_TryCreate_Returns_Null_When_OPENAI_API_KEY_Missing()
    {
        // Env is already cleared by the constructor — nothing to do.
        var r = MicrosoftAgentRunner.TryCreateFromEnvironment(_audit);
        Assert.Null(r);
    }

    [Fact]
    public async Task Hybrid_With_Null_Llm_From_Factory_Falls_Through_To_Deterministic()
    {
        // Simulate the full "no LLM credentials" operator path:
        //   1. MicrosoftAgentRunner.TryCreateFromEnvironment → null
        //   2. HybridAgentRunner wrapped around null + deterministic
        //   3. Deterministic gets the run; hybrid.llm_unavailable audited.
        var llmRunner = MicrosoftAgentRunner.TryCreateFromEnvironment(_audit);
        Assert.Null(llmRunner);

        var det = new StubDeterministicRunner();
        var hybrid = new HybridAgentRunner(llmRunner, det, _audit);
        await hybrid.RunAsync(
            new[] { "10.0.0.1" },
            tools: null!,
            priorKnowledge: new KnowledgeBase(),
            ct: CancellationToken.None);

        Assert.Equal(1, det.Calls);
        _audit.Dispose();
        var lines = File.ReadAllLines(_auditPath);
        Assert.Contains(lines, l => l.Contains("\"hybrid.llm_unavailable\""));
        Assert.Contains(lines, l => l.Contains("\"hybrid.finish\"") && l.Contains("\"deterministic\""));
        // We should *not* see an llm_fallback event — there was no LLM
        // exception to fall back from; the path is explicit.
        Assert.DoesNotContain(lines, l => l.Contains("\"hybrid.llm_fallback\""));
    }
}
