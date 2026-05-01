using Drederick.Agent;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// Tests for <see cref="HybridAgentRunner"/>. Stubbed inner runners avoid
/// any dependency on the OpenAI SDK or recon binaries.
/// </summary>
public class HybridAgentRunnerTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-hybrid-{Guid.NewGuid():N}.jsonl");

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
            Calls++;
            if (Throw is not null) throw Throw;
            return Task.CompletedTask;
        }
    }

    private static (ReconToolbox? tools, KnowledgeBase kb, AuditLog audit, string auditPath) Build()
    {
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);
        // StubRunner ignores the toolbox; pass null! to avoid spinning up
        // real recon tools just for this orchestration test.
        return (null, new KnowledgeBase(), audit, auditPath);
    }

    [Fact]
    public async Task LlmSucceeds_DeterministicNotCalled()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner();
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None);

            Assert.Equal(1, llm.Calls);
            Assert.Equal(0, det.Calls);
            audit.Dispose();
            var lines = File.ReadAllLines(path);
            Assert.Contains(lines, l => l.Contains("\"hybrid.start\""));
            Assert.Contains(lines, l => l.Contains("\"hybrid.finish\"") && l.Contains("\"llm\""));
            Assert.DoesNotContain(lines, l => l.Contains("\"hybrid.llm_fallback\""));
        }
        finally { audit.Dispose(); File.Delete(path); }
    }

    [Fact]
    public async Task LlmThrowsGeneric_DeterministicCalled_FallbackAudited()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new InvalidOperationException("rate limit exceeded") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None);

            Assert.Equal(1, llm.Calls);
            Assert.Equal(1, det.Calls);
            audit.Dispose();
            var lines = File.ReadAllLines(path);
            Assert.Contains(lines, l => l.Contains("\"hybrid.llm_fallback\"")
                                        && l.Contains("InvalidOperationException")
                                        && l.Contains("message_sha256"));
            // Plaintext error message must NOT be logged verbatim.
            Assert.DoesNotContain(lines, l => l.Contains("rate limit exceeded"));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task LlmThrowsScope_Propagates_DeterministicNotCalled()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new ScopeException("Target '8.8.8.8' is not in scope.") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await Assert.ThrowsAsync<ScopeException>(() =>
                hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None));

            Assert.Equal(1, llm.Calls);
            Assert.Equal(0, det.Calls);
            audit.Dispose();
            var lines = File.ReadAllLines(path);
            Assert.DoesNotContain(lines, l => l.Contains("\"hybrid.llm_fallback\""));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task LlmThrowsModelCompliance_Propagates_DeterministicNotCalled()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new CopilotModelComplianceException("model lacks tool support") };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await Assert.ThrowsAsync<CopilotModelComplianceException>(() =>
                hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None));

            Assert.Equal(1, llm.Calls);
            Assert.Equal(0, det.Calls);
            audit.Dispose();
            var lines = File.ReadAllLines(path);
            Assert.DoesNotContain(lines, l => l.Contains("\"hybrid.llm_fallback\""));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task NullLlmInner_DeterministicCalledDirectly()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(null, det, audit);

            await hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None);

            Assert.Equal(1, det.Calls);
            audit.Dispose();
            var lines = File.ReadAllLines(path);
            Assert.Contains(lines, l => l.Contains("\"hybrid.llm_unavailable\""));
            Assert.Contains(lines, l => l.Contains("\"hybrid.finish\"") && l.Contains("\"deterministic\""));
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task LlmThrowsCancellation_Propagates_DeterministicNotCalled()
    {
        var (tools, kb, audit, path) = Build();
        try
        {
            var llm = new StubRunner { Throw = new OperationCanceledException() };
            var det = new StubRunner();
            var hybrid = new HybridAgentRunner(llm, det, audit);

            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                hybrid.RunAsync(new[] { "10.0.0.1" }, tools!, kb, CancellationToken.None));

            Assert.Equal(1, llm.Calls);
            Assert.Equal(0, det.Calls);
        }
        finally { audit.Dispose(); if (File.Exists(path)) File.Delete(path); }
    }
}
