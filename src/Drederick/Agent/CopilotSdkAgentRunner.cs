using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Drederick.Memory;
using Drederick.Recon;
using GitHub.Copilot.SDK;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

/// <summary>
/// Official GitHub Copilot SDK-backed recon/exploit runner. This is the
/// Copilot provider implementation for <c>--agent</c>; Azure and raw OpenAI
/// continue to use <see cref="MicrosoftAgentRunner"/>'s <see cref="IChatClient"/>
/// path.
/// </summary>
public sealed class CopilotSdkAgentRunner : IReconAgentRunner
{
    internal const string DefaultModelId = "claude-sonnet-4.6";

    private readonly AuditLog _audit;
    private readonly string _githubToken;
    private readonly string _modelId;
    private readonly bool _modelWasExplicit;
    private readonly LlmExploitTools? _exploitTools;

    public string ModelId => _modelId;

    public CopilotSdkAgentRunner(
        AuditLog audit,
        string githubToken,
        string modelId,
        LlmExploitTools? exploitTools = null,
        bool modelWasExplicit = true)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentException.ThrowIfNullOrWhiteSpace(githubToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);

        _audit = audit;
        _githubToken = githubToken;
        _modelId = modelId;
        _modelWasExplicit = modelWasExplicit;
        _exploitTools = exploitTools;
    }

    public CopilotSdkAgentRunner WithExploitTools(LlmExploitTools exploitTools) =>
        new(_audit, _githubToken, _modelId, exploitTools, _modelWasExplicit);

    public static CopilotSdkAgentRunner? TryCreateFromEnvironment(
        AuditLog audit,
        string? modelId = null,
        LlmExploitTools? exploitTools = null,
        bool allowGitHubCliAuth = true)
    {
        ArgumentNullException.ThrowIfNull(audit);

        var (token, source) = CopilotAuthTokenResolver.ResolveToken(allowGitHubCliAuth, audit);
        if (string.IsNullOrWhiteSpace(token)) return null;

        audit.Record("copilot.sdk.auth.ready", new Dictionary<string, object?>
        {
            ["source"] = source.ToString(),
        });

        var explicitModel = !string.IsNullOrWhiteSpace(modelId);
        modelId = explicitModel ? modelId!.Trim() : DefaultModelId;
        return new CopilotSdkAgentRunner(audit, token, modelId, exploitTools, explicitModel);
    }

    public async Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase prior,
        CancellationToken ct)
    {
        var aiTools = LlmToolCatalog.BuildAiFunctions(tools, _exploitTools);

        await using var client = CreateClient();
        try
        {
            await client.StartAsync(ct).ConfigureAwait(false);

            var modelSnapshot = await CopilotModelCompliance.GetModelsAsync(
                _githubToken,
                client.ListModelsAsync,
                ct).ConfigureAwait(false);
            var modelDecision = CopilotModelCompliance.SelectModel(
                modelSnapshot.Models,
                _modelId,
                _modelWasExplicit);
            AuditModelDecision(modelDecision, modelSnapshot);
            if (!modelDecision.Compliant || string.IsNullOrWhiteSpace(modelDecision.SelectedModelId))
            {
                throw new CopilotModelComplianceException(CopilotModelCompliance.BuildFailureMessage(modelDecision));
            }

            _audit.Record("runner.start", new Dictionary<string, object?>
            {
                ["runner"] = nameof(CopilotSdkAgentRunner),
                ["model"] = modelDecision.SelectedModelId,
                ["requested_model"] = _modelId,
                ["model_explicit"] = _modelWasExplicit,
                ["targets"] = targets,
                ["sdk"] = "GitHub.Copilot.SDK",
                ["tool_count"] = aiTools.Count,
            });

            await using var session = await client.CreateSessionAsync(
                CreateSessionConfig(aiTools, modelDecision.SelectedModelId),
                ct).ConfigureAwait(false);

            var prompt = MicrosoftAgentRunner.BuildUserMessage(targets, prior);
            _audit.Record("copilot.sdk.sending", new Dictionary<string, object?>
            {
                ["prompt_len"] = prompt.Length,
                ["model"] = modelDecision.SelectedModelId,
                ["streaming"] = true,
                ["idle_timeout_s"] = 600,
            });

            var response = await session.SendAndWaitAsync(
                new MessageOptions { Prompt = prompt },
                timeout: TimeSpan.FromMinutes(15),
                ct).ConfigureAwait(false);

            var text = response?.Data?.Content;
            _audit.Record("runner.agent_response", new Dictionary<string, object?>
            {
                ["text_len"] = text?.Length ?? 0,
                ["finish_reason"] = "sdk_session_idle",
            });

            if (!string.IsNullOrEmpty(text))
            {
                Console.WriteLine();
                Console.WriteLine("--- agent summary ---");
                Console.WriteLine(text);
                Console.WriteLine("---------------------");
            }
        }
        catch (Exception ex)
        {
            _audit.Record("runner.agent_error", new Dictionary<string, object?>
            {
                ["runner"] = nameof(CopilotSdkAgentRunner),
                ["error"] = ex.Message,
            });
            throw;
        }

        tools.Finalize(targets);
        _audit.Record("runner.finish", new Dictionary<string, object?>
        {
            ["tool_calls"] = tools.ToolCallsTotal,
        });
    }

    internal CopilotClient CreateClient() => new(CreateClientOptions());

    internal CopilotClientOptions CreateClientOptions() => new()
    {
        GitHubToken = _githubToken,
        UseLoggedInUser = false,
        LogLevel = "warning",
        Cwd = Directory.GetCurrentDirectory(),
    };

    internal SessionConfig CreateSessionConfig(ICollection<AIFunction> aiTools) =>
        CreateSessionConfig(aiTools, _modelId);

    internal SessionConfig CreateSessionConfig(ICollection<AIFunction> aiTools, string modelId) => new()
    {
        ClientName = "drederick",
        Model = modelId,
        Tools = aiTools,
        AvailableTools = aiTools.Select(t => t.Name).ToArray(),
        OnPermissionRequest = PermissionHandler.ApproveAll,
        WorkingDirectory = Directory.GetCurrentDirectory(),
        Streaming = true,
        InfiniteSessions = new InfiniteSessionConfig { Enabled = false },
        GitHubToken = _githubToken,
        SystemMessage = new SystemMessageConfig
        {
            Mode = SystemMessageMode.Append,
            Content = MicrosoftAgentRunner.BuildSystemPrompt(),
        },
    };

    private void AuditModelDecision(CopilotModelDecision decision, CopilotModelListSnapshot snapshot)
    {
        _audit.Record(
            decision.Compliant ? "copilot.sdk.model.selected" : "copilot.sdk.model.refused",
            new Dictionary<string, object?>
            {
                ["runner"] = nameof(CopilotSdkAgentRunner),
                ["requested_model"] = decision.RequestedModelId,
                ["model_explicit"] = decision.ExplicitModel,
                ["selected_model"] = decision.SelectedModelId,
                ["compliant"] = decision.Compliant,
                ["reason"] = decision.Reason,
                ["available_model_count"] = snapshot.Models.Count,
                ["compliant_model_count"] = decision.CompliantModelIds.Count,
                ["model_cache"] = snapshot.FromCache ? "hit" : "miss",
            });
    }
}
