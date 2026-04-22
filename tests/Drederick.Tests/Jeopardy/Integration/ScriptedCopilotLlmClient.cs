using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Jeopardy.Llm;
using Microsoft.Extensions.AI;

namespace Drederick.Tests.Jeopardy.Integration;

/// <summary>
/// Script-driven <see cref="ICopilotLlmClient"/> keyed by model id. Unlike
/// the per-solver <c>FakeCopilotLlmClient</c>, this one honors the
/// <paramref name="modelId"/> argument passed into <see cref="ChatAsync"/>
/// so a single instance can drive a multi-model swarm with a different
/// transcript per model.
///
/// <para>Also records every prompt fed to the model so tests can assert
/// that operator hints / peer insights made it into the context window.
/// Intentionally NOT thread-safe on a single model queue — each model gets
/// its own lock-free queue and calls for the same model should not
/// interleave. Multiple models in parallel IS supported.</para>
/// </summary>
internal sealed class ScriptedCopilotLlmClient : ICopilotLlmClient
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<object>> _queues =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _callCounts = new(StringComparer.Ordinal);

    /// <summary>Every prompt seen by every model, in call order, appended under the model id.</summary>
    public ConcurrentDictionary<string, List<IReadOnlyList<CopilotChatMessage>>> Prompts { get; }
        = new(StringComparer.Ordinal);

    public int TotalCallCount => SumCalls();

    private int SumCalls()
    {
        int sum = 0;
        foreach (var kv in _callCounts) sum += kv.Value;
        return sum;
    }

    public int CallsFor(string modelId) =>
        _callCounts.TryGetValue(modelId, out var n) ? n : 0;

    public ScriptedCopilotLlmClient EnqueueContent(string modelId, string content,
        int promptTokens = 100, int completionTokens = 50)
    {
        Q(modelId).Enqueue(new CopilotChatResponse(
            ModelId: modelId,
            Content: content,
            ToolCalls: Array.Empty<CopilotToolCall>(),
            PromptTokens: promptTokens,
            CompletionTokens: completionTokens,
            FinishReason: "stop",
            Elapsed: TimeSpan.FromMilliseconds(5)));
        return this;
    }

    public ScriptedCopilotLlmClient EnqueueToolCall(string modelId, string toolName, string argsJson,
        int promptTokens = 100, int completionTokens = 50, string callId = "call-1")
    {
        Q(modelId).Enqueue(new CopilotChatResponse(
            ModelId: modelId,
            Content: null,
            ToolCalls: new[] { new CopilotToolCall(callId, toolName, argsJson) },
            PromptTokens: promptTokens,
            CompletionTokens: completionTokens,
            FinishReason: "tool_calls",
            Elapsed: TimeSpan.FromMilliseconds(5)));
        return this;
    }

    public ScriptedCopilotLlmClient EnqueueDelay(string modelId, TimeSpan delay)
    {
        Q(modelId).Enqueue(delay);
        return this;
    }

    public ScriptedCopilotLlmClient EnqueueException(string modelId, HttpStatusCode? status, string? msg = null)
    {
        Q(modelId).Enqueue(new CopilotLlmException(status, modelId, msg ?? "scripted"));
        return this;
    }

    private ConcurrentQueue<object> Q(string modelId) =>
        _queues.GetOrAdd(modelId, _ => new ConcurrentQueue<object>());

    public async Task<CopilotChatResponse> ChatAsync(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools,
        CancellationToken ct)
    {
        _callCounts.AddOrUpdate(modelId, 1, (_, n) => n + 1);
        Prompts.AddOrUpdate(modelId,
            _ => new List<IReadOnlyList<CopilotChatMessage>> { messages },
            (_, existing) =>
            {
                lock (existing) existing.Add(messages);
                return existing;
            });

        var q = Q(modelId);
        while (true)
        {
            if (!q.TryDequeue(out var next))
            {
                throw new InvalidOperationException(
                    $"ScriptedCopilotLlmClient ran out of scripted responses for model '{modelId}' " +
                    $"after {_callCounts[modelId]} call(s).");
            }

            if (next is TimeSpan delay)
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
                continue;
            }
            if (next is Exception ex) throw ex;
            return (CopilotChatResponse)next;
        }
    }

    public Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyList<CopilotModel>>(Array.Empty<CopilotModel>());
}
