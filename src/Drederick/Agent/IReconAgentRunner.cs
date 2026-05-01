using Drederick.Memory;
using Drederick.Recon;

namespace Drederick.Agent;

/// <summary>
/// Contract for the component that drives the recon session. Two implementations
/// ship: <see cref="AdaptiveRunner"/> (deterministic, no LLM; always available),
/// <see cref="MicrosoftAgentRunner"/> (Microsoft Agent Framework + OpenAI/Azure),
/// and <see cref="CopilotSdkAgentRunner"/> (official GitHub Copilot SDK).
/// </summary>
public interface IReconAgentRunner
{
    Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase priorKnowledge,
        CancellationToken ct);
}
