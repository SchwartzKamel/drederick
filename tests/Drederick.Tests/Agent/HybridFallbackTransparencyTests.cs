using System.Net.Http;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-055 — tests for structured <c>hybrid.fallback</c> audit events
/// emitted on every LLM → deterministic fallback inside
/// <see cref="HybridAgentRunner"/>.
/// </summary>
public class HybridFallbackTransparencyTests
{
    private const string Canary = "CANARY-SECRET-prompt-fragment-1234567890";

    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-hybrid-fb-{Guid.NewGuid():N}.jsonl");

    private sealed class StubRunner : IReconAgentRunner
    {
        public int Calls;
        public Exception? Throw;
        public Task RunAsync(
            IReadOnlyList<string> targets,
            ReconToolbox tools,
            KnowledgeBase priorKnowledge,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Calls++;
            if (Throw is not null) throw Throw;
            return Task.CompletedTask;
        }
    }

    private static (KnowledgeBase kb, AuditLog audit, string auditPath) Build()
    {
        var auditPath = NewAuditPath();
        return (new KnowledgeBase(), new AuditLog(auditPath), auditPath);
    }

    private static IReadOnlyList<JsonElement> ReadFallbackEvents(string path)
    {
        var result = new List<JsonElement>();
        foreach (var line in File.ReadAllLines(path))
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("event", out var ev)
                && ev.GetString() == HybridFallbackEvent.EventName)
            {
                result.Add(doc.RootElement.Clone());
            }
        }
        return result;
    }

    [Fact]
    public async Task NoApiKey_NullLlm_EmitsStructuredFallbackEvent()
    {
        var (kb, audit, path) = Build();
        try
        {
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(null, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            Assert.Equal(1, det.Calls);
            audit.Dispose();
            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            Assert.Equal(HybridFallbackEvent.Stages.Init, ev.GetProperty("stage").GetString());
            Assert.Equal(HybridFallbackEvent.Reasons.NoApiKey, ev.GetProperty("reason").GetString());
            Assert.Equal(HybridFallbackEvent.FellBack.DeterministicRunner, ev.GetProperty("fell_back_to").GetString());
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task NetworkError_HttpRequestException_EmitsNetworkReason()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new HttpRequestException("connection refused " + Canary) };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            Assert.Equal(1, det.Calls);
            audit.Dispose();
            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            Assert.Equal(HybridFallbackEvent.Stages.Network, ev.GetProperty("stage").GetString());
            Assert.Equal(HybridFallbackEvent.Reasons.NetworkError, ev.GetProperty("reason").GetString());
            Assert.Contains("HttpRequestException", ev.GetProperty("exception_type").GetString());
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task ParseError_JsonException_EmitsParseReason()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new JsonException("unexpected token near " + Canary) };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            audit.Dispose();
            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            Assert.Equal(HybridFallbackEvent.Stages.ResponseParse, ev.GetProperty("stage").GetString());
            Assert.Equal(HybridFallbackEvent.Reasons.ParseError, ev.GetProperty("reason").GetString());
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task RateLimit_DetectedFromMessage_EmitsRateLimitReason()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new InvalidOperationException("429 Too Many Requests, retry after 17 seconds (" + Canary + ")") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            audit.Dispose();
            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            Assert.Equal(HybridFallbackEvent.Reasons.RateLimit, ev.GetProperty("reason").GetString());
            Assert.Equal(17, ev.GetProperty("retry_hint_seconds").GetInt32());
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task ScopeException_Propagates_NoFallbackEventEmitted()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new ScopeException("Target '8.8.8.8' is not in scope.") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await Assert.ThrowsAsync<ScopeException>(() =>
                hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None));

            Assert.Equal(0, det.Calls);
            audit.Dispose();
            var events = ReadFallbackEvents(path);
            Assert.Empty(events);
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Cancellation_Propagates_NoFallbackEventEmitted()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new OperationCanceledException() };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None));

            Assert.Equal(0, det.Calls);
            audit.Dispose();
            var events = ReadFallbackEvents(path);
            Assert.Empty(events);
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task CanaryStringInExceptionMessage_NotPresentInAudit()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new InvalidOperationException(Canary) };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            audit.Dispose();
            var rawAudit = File.ReadAllText(path);
            Assert.DoesNotContain(Canary, rawAudit);

            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            // A hash IS present and is non-empty.
            var hash = ev.GetProperty("message_sha256").GetString();
            Assert.False(string.IsNullOrEmpty(hash));
            Assert.DoesNotContain(Canary, hash!);
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task AuthError_DetectedFromMessage_EmitsAuthReason()
    {
        var (kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new InvalidOperationException("401 Unauthorized: invalid api key") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, null!, kb, CancellationToken.None);

            audit.Dispose();
            var events = ReadFallbackEvents(path);
            var ev = Assert.Single(events);
            Assert.Equal(HybridFallbackEvent.Reasons.AuthError, ev.GetProperty("reason").GetString());
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }
}
