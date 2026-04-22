using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Jeopardy.Llm;
using Microsoft.Extensions.AI;

namespace Drederick.Tests.Jeopardy.Solver.Fakes;

/// <summary>
/// Deterministic, script-driven fake for <see cref="ICopilotLlmClient"/>. Each
/// <see cref="Enqueue"/> pushes one response OR one exception onto an internal
/// queue, and each <c>ChatAsync</c> call dequeues the next entry. Running out
/// of scripted responses throws so tests fail loudly on over-iteration.
/// </summary>
internal sealed class FakeCopilotLlmClient : ICopilotLlmClient
{
    private readonly Queue<object> _queue = new();
    public List<int> MessageCounts { get; } = new();
    public int CallCount { get; private set; }

    public FakeCopilotLlmClient EnqueueContent(string content, int promptTokens = 100, int completionTokens = 50)
    {
        _queue.Enqueue(new CopilotChatResponse(
            ModelId: "fake-model",
            Content: content,
            ToolCalls: Array.Empty<CopilotToolCall>(),
            PromptTokens: promptTokens,
            CompletionTokens: completionTokens,
            FinishReason: "stop",
            Elapsed: TimeSpan.FromMilliseconds(5)));
        return this;
    }

    public FakeCopilotLlmClient EnqueueToolCall(
        string toolName, string argumentsJson, int promptTokens = 100, int completionTokens = 50,
        string? content = null, string callId = "call-1")
    {
        _queue.Enqueue(new CopilotChatResponse(
            ModelId: "fake-model",
            Content: content,
            ToolCalls: new[] { new CopilotToolCall(callId, toolName, argumentsJson) },
            PromptTokens: promptTokens,
            CompletionTokens: completionTokens,
            FinishReason: "tool_calls",
            Elapsed: TimeSpan.FromMilliseconds(5)));
        return this;
    }

    public FakeCopilotLlmClient EnqueueToolCalls(
        params (string Name, string Args)[] calls)
    {
        var list = new List<CopilotToolCall>();
        int i = 0;
        foreach (var c in calls) list.Add(new CopilotToolCall($"call-{i++}", c.Name, c.Args));
        _queue.Enqueue(new CopilotChatResponse(
            ModelId: "fake-model",
            Content: null,
            ToolCalls: list,
            PromptTokens: 100,
            CompletionTokens: 50,
            FinishReason: "tool_calls",
            Elapsed: TimeSpan.FromMilliseconds(5)));
        return this;
    }

    public FakeCopilotLlmClient EnqueueException(HttpStatusCode? status, string? message = null)
    {
        _queue.Enqueue(new CopilotLlmException(status, "fake-model", message ?? "scripted"));
        return this;
    }

    public FakeCopilotLlmClient EnqueueDelay(TimeSpan delay)
    {
        _queue.Enqueue(delay);
        return this;
    }

    public int Remaining => _queue.Count;

    public async Task<CopilotChatResponse> ChatAsync(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools,
        CancellationToken ct)
    {
        CallCount++;
        MessageCounts.Add(messages.Count);

        if (_queue.Count == 0)
        {
            throw new InvalidOperationException(
                $"FakeCopilotLlmClient ran out of scripted responses at call #{CallCount}");
        }
        var next = _queue.Dequeue();
        while (next is TimeSpan delay)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            if (_queue.Count == 0)
            {
                throw new InvalidOperationException(
                    $"FakeCopilotLlmClient ran out of scripted responses after delay at call #{CallCount}");
            }
            next = _queue.Dequeue();
        }
        if (next is Exception ex) throw ex;
        return (CopilotChatResponse)next;
    }

    public Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyList<CopilotModel>>(Array.Empty<CopilotModel>());
}
