using Drederick.Audit;
using Drederick.Autopilot.ChainReasoner;
using Drederick.Memory;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Autopilot.ChainReasoner;

public class ChainReasonerTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"chain-{Guid.NewGuid():N}.jsonl");

    private static KnowledgeBase KbWithSmbAnon()
    {
        var kb = new KnowledgeBase();
        kb.Hosts["10.0.0.5"] = new HostFinding
        {
            Target = "10.0.0.5",
            Smb = new List<SmbResult>
            {
                new() { Port = 445, SigningRequired = false, Shares = new List<string> { "public", "IT$" } },
            },
            Nmap = new NmapResult
            {
                OpenPorts = new List<NmapPort> { new() { Port = 445, Service = "smb" } },
            },
        };
        return kb;
    }

    [Fact]
    public void Templates_All_Load()
    {
        Assert.True(BuiltInChainTemplates.All.Count >= 8,
            $"Expected at least 8 built-in templates, got {BuiltInChainTemplates.All.Count}.");
        var ids = BuiltInChainTemplates.All.Select(t => t.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(BuiltInChainTemplates.All, t =>
        {
            Assert.False(string.IsNullOrEmpty(t.Id));
            Assert.NotEmpty(t.Steps);
        });
    }

    [Fact]
    public void Ranking_Is_Deterministic_For_Same_Inputs()
    {
        using var audit = new AuditLog(NewAuditPath());
        var reasoner = new global::Drederick.Autopilot.ChainReasoner.ChainReasoner(audit);
        var kb = KbWithSmbAnon();

        var first = reasoner.Reason(kb, creds: null, sessions: null, top: 5);
        var second = reasoner.Reason(kb, creds: null, sessions: null, top: 5);

        Assert.Equal(first.Count, second.Count);
        for (int i = 0; i < first.Count; i++)
        {
            Assert.Equal(first[i].Id, second[i].Id);
            Assert.Equal(first[i].Score, second[i].Score);
        }
    }

    [Fact]
    public void Missing_Precondition_Prunes_Chain()
    {
        using var audit = new AuditLog(NewAuditPath());
        var reasoner = new global::Drederick.Autopilot.ChainReasoner.ChainReasoner(audit);
        // Empty KB: no SMB, no kerberos, no http, etc.
        var kb = new KnowledgeBase();

        var chains = reasoner.Reason(kb, creds: null, sessions: null, top: 10);

        Assert.DoesNotContain(chains, c => c.Id == "anon-smb-loot");
        Assert.DoesNotContain(chains, c => c.Id == "kerberoast-bloodhound");
    }

    [Fact]
    public void Smb_Anon_Chain_Selected_When_Predicates_Match()
    {
        using var audit = new AuditLog(NewAuditPath());
        var reasoner = new global::Drederick.Autopilot.ChainReasoner.ChainReasoner(audit);
        var kb = KbWithSmbAnon();

        var chains = reasoner.Reason(kb, creds: null, sessions: null, top: 10);

        Assert.Contains(chains, c => c.Id == "anon-smb-loot");
        var picked = chains.First(c => c.Id == "anon-smb-loot");
        Assert.Equal("rule", picked.Source);
        Assert.Contains("smb.anon-read=true", picked.Reason);
        Assert.True(picked.Likelihood > 0);
    }

    [Fact]
    public async Task Llm_Augmenter_Adds_Synthetic_Chain()
    {
        using var audit = new AuditLog(NewAuditPath());
        var reasoner = new global::Drederick.Autopilot.ChainReasoner.ChainReasoner(audit);
        var kb = KbWithSmbAnon();

        var fake = new FakeAugmenter(new AttackChain
        {
            Id = "synthetic-llm-chain",
            Name = "LLM-suggested chain",
            Steps = new[] { new AttackStep { Name = "step1", Tool = "x", Confidence = 0.9, Cost = 10 } },
            Likelihood = 0.9,
            Impact = 0.9,
            Cost = 10,
            Score = 0.81,
            Reason = "LLM-derived",
        });

        var chains = await reasoner.ReasonAsync(kb, creds: null, sessions: null, top: 20, augmenter: fake);

        Assert.Contains(chains, c => c.Id == "synthetic-llm-chain" && c.Source == "llm");
    }

    [Fact]
    public async Task Augmenter_Exception_Falls_Back_Cleanly()
    {
        using var audit = new AuditLog(NewAuditPath());
        var reasoner = new global::Drederick.Autopilot.ChainReasoner.ChainReasoner(audit);
        var kb = KbWithSmbAnon();

        var thrower = new ThrowingAugmenter();
        var chains = await reasoner.ReasonAsync(kb, creds: null, sessions: null, top: 5, augmenter: thrower);

        // Rule-based output still produced.
        Assert.NotEmpty(chains);
    }

    private sealed class FakeAugmenter : IChainAugmenter
    {
        private readonly AttackChain _chain;
        public FakeAugmenter(AttackChain c) { _chain = c; }
        public Task<IReadOnlyList<AttackChain>> AugmentAsync(ChainFacts f, IReadOnlyList<AttackChain> b, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<AttackChain>>(new[] { _chain });
    }

    private sealed class ThrowingAugmenter : IChainAugmenter
    {
        public Task<IReadOnlyList<AttackChain>> AugmentAsync(ChainFacts f, IReadOnlyList<AttackChain> b, CancellationToken ct)
            => throw new InvalidOperationException("simulated LLM outage");
    }
}
