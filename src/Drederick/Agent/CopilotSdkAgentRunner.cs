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
    internal const string DefaultModelId = "claude-haiku-4.5";

    private readonly AuditLog _audit;
    private readonly string _githubToken;
    private readonly string _modelId;
    private readonly LlmExploitTools? _exploitTools;

    public string ModelId => _modelId;

    public CopilotSdkAgentRunner(
        AuditLog audit,
        string githubToken,
        string modelId,
        LlmExploitTools? exploitTools = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentException.ThrowIfNullOrWhiteSpace(githubToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);

        _audit = audit;
        _githubToken = githubToken;
        _modelId = modelId;
        _exploitTools = exploitTools;
    }

    public CopilotSdkAgentRunner WithExploitTools(LlmExploitTools exploitTools) =>
        new(_audit, _githubToken, _modelId, exploitTools);

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

        modelId = string.IsNullOrWhiteSpace(modelId) ? DefaultModelId : modelId;
        return new CopilotSdkAgentRunner(audit, token, modelId, exploitTools);
    }

    public async Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase prior,
        CancellationToken ct)
    {
        var aiTools = LlmToolCatalog.BuildAiFunctions(tools, _exploitTools);

        _audit.Record("runner.start", new Dictionary<string, object?>
        {
            ["runner"] = nameof(CopilotSdkAgentRunner),
            ["model"] = _modelId,
            ["targets"] = targets,
            ["sdk"] = "GitHub.Copilot.SDK",
            ["tool_count"] = aiTools.Count,
        });

        await using var client = CreateClient();
        try
        {
            await client.StartAsync(ct).ConfigureAwait(false);

            await using var session = await client.CreateSessionAsync(
                CreateSessionConfig(aiTools),
                ct).ConfigureAwait(false);

            var response = await session.SendAndWaitAsync(
                new MessageOptions { Prompt = MicrosoftAgentRunner.BuildUserMessage(targets, prior) },
                timeout: null,
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
        LogLevel = "warn",
        Cwd = Directory.GetCurrentDirectory(),
    };

    internal SessionConfig CreateSessionConfig(ICollection<AIFunction> aiTools) => new()
    {
        ClientName = "drederick",
        Model = _modelId,
        Tools = aiTools,
        AvailableTools = aiTools.Select(t => t.Name).ToArray(),
        OnPermissionRequest = PermissionHandler.ApproveAll,
        WorkingDirectory = Directory.GetCurrentDirectory(),
        Streaming = false,
        InfiniteSessions = new InfiniteSessionConfig { Enabled = false },
        GitHubToken = _githubToken,
        SystemMessage = new SystemMessageConfig
        {
            Mode = SystemMessageMode.Append,
            Content = MicrosoftAgentRunner.BuildSystemPrompt(),
        },
    };
}
